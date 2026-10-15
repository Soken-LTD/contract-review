"""Sandboxed runs of the Sui and Aptos CLIs (plan v4 07 section 4; 09 4.2).

Every compiler and linter run goes through `sandbox.profile.docker_argv`: uid 10001, read-only
root, no network for build and analyze, the family egress network for deps only. Mount layout:

  <work>/src   -> /work/src   read-only (the pinned source, never writable after the pin)
  <work>/out   -> /work/out   read-write, empty at start (artifacts only)
  <work>/move  -> /work/move  MOVE_HOME: written by deps (egress), read-only in build/analyze
  <work>/host  never mounted: supervisor files (logs, hashes, provenance)

Container output is read back with lstat checks only (no symlink, regular files, inside out/).
"""

from __future__ import annotations

import logging
import os
import secrets
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

logger = logging.getLogger(__name__)

BUILD_LIMITS = StepLimits(cpus=4, memory="8g", pids=512, max_file=256 * 1024 * 1024)
DEPS_LIMITS = StepLimits(cpus=2, memory="2g", pids=256, max_file=256 * 1024 * 1024)

_LIMITS_YAML = Path(__file__).resolve().parents[4] / "contract" / "ops" / "limits.yaml"


def _load_wall_s(yaml_key_path: tuple[str, ...], default: int, env_var: str) -> int:
    """Load a wall_s value from limits.yaml; env override is accepted only if LOWER.

    contract/ops/limits.yaml is the authoritative source (09 UV9-8).  An env var may
    tighten the limit for local testing but never loosen it — so a bug in config cannot
    be masked by bumping the env var above the yaml cap.
    """
    try:
        import yaml  # PyYAML; always available in the worker venv

        data = yaml.safe_load(_LIMITS_YAML.read_text())
        node: dict = data
        for key in yaml_key_path:
            node = node[key]
        yaml_val = int(node)
    except (OSError, KeyError, TypeError, ValueError):
        yaml_val = default
    env_raw = os.environ.get(env_var)
    if env_raw is not None:
        try:
            env_val = int(env_raw)
            return min(yaml_val, env_val)  # env can only tighten the limit
        except ValueError:
            pass
    return yaml_val


# Per-step wall clocks loaded from contract/ops/limits.yaml (env vars tighten only).
BUILD_WALL_S: int = _load_wall_s(("build", "move", "wall_s"), 900, "SOKEN_MOVE_BUILD_WALL_S")
# Per-container analyze limit; step-level cap is analyze.move.wall_s (see move_steps.py).
ANALYZE_WALL_S: int = _load_wall_s(
    ("analyze", "move", "per_container_wall_s"), 180, "SOKEN_MOVE_ANALYZE_WALL_S"
)
ANALYZE_STEP_WALL_S: int = _load_wall_s(("analyze", "move", "wall_s"), 600, "SOKEN_MOVE_ANALYZE_STEP_WALL_S")
DEPS_WALL_S = 300
EGRESS_NETWORK = os.environ.get("SOKEN_MOVE_NETWORK", "soken-move-egress")
IMAGES = {"sui": "sui-build", "aptos": "aptos-build"}
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_ARTIFACTS = 4000


class SandboxUnavailable(RuntimeError):
    """docker missing or the image is not pinned: the step is not run (fail closed)."""


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def image_for(chain: str) -> str:
    """Pinned image (images.lock.json) or the `SOKEN_IMAGE_SUI_BUILD` / `_APTOS_BUILD` override."""
    image = locked_image(IMAGES[chain])
    if image is None:
        raise SandboxUnavailable(f"image {IMAGES[chain]} not pinned")
    if not shutil.which("docker"):
        raise SandboxUnavailable("docker not found")
    return image


def prepare_dirs(work: Path) -> dict[str, Path]:
    """Fresh layout under work. src is written by the caller, then never mounted writable."""
    work.mkdir(parents=True, exist_ok=True)
    dirs = {"src": work / "src", "host": work / "host"}
    for d in dirs.values():
        d.mkdir(exist_ok=True)
    dirs["out"] = sandbox_writable_dir(work / "out")
    dirs["move"] = sandbox_writable_dir(work / "move")
    return dirs


def run(
    chain: str,
    step: str,
    dirs: dict[str, Path],
    command: list[str],
    *,
    timeout: int,
    workdir: str = "/work/src",
    extra_env: dict[str, str] | None = None,
) -> RunResult:
    """One CLI run. step = deps (egress, MOVE_HOME writable) | build | analyze (no network)."""
    image = image_for(chain)
    if any(".." in tok.split("/") for tok in command):
        raise ValueError("path token with ..")
    deps = step == "deps"
    mounts = [
        (dirs["src"].resolve(), "/work/src", True),          # source: read-only after the pin
        (dirs["out"].resolve(), "/work/out", deps),           # artifacts: written by build/analyze only
        (dirs["move"].resolve(), "/work/move", not deps),     # MOVE_HOME: written by deps only
    ]
    if "scratch" in dirs:
        # Analyzer scratch copy of the source (the CLI writes next to the package); the host never
        # reads anything back from it except the process output.
        mounts.append((dirs["scratch"].resolve(), "/work/scratch", False))
    env = {"HOME": "/tmp", "MOVE_HOME": "/work/move", "SUI_SKIP_UPDATE_CHECK": "1", "APTOS_DISABLE_TELEMETRY": "true",
           **(extra_env or {})}
    # Named container: killing the docker CLI process does NOT stop the container;
    # on timeout we call `docker rm -f <name>` to kill and remove it (same pattern as
    # soken_review.sandbox.repo_fetch.materialize_repo).
    container_name = f"soken-move-{step}-{secrets.token_hex(6)}"
    argv = docker_argv(
        step=step, image=image, work_dir=dirs["src"], cache_dir=None,
        limits=DEPS_LIMITS if step == "deps" else BUILD_LIMITS, env=env, command=command,
        family_network=EGRESS_NETWORK if step == "deps" else None,
        runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"), workdir=workdir, mounts=mounts,
        name=container_name,
    )
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        # Kill the container before returning — just killing the docker CLI leaves it running.
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True, check=False, timeout=60,
        )
        return RunResult(-1, _text(exc.stdout), _text(exc.stderr), timed_out=True)
    return RunResult(proc.returncode, _text(proc.stdout), _text(proc.stderr))


def _text(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    return raw.decode(errors="replace") if isinstance(raw, bytes) else raw


def read_artifacts(root: Path, suffix: str = ".mv") -> dict[str, bytes]:
    """Regular files with `suffix` under root, keyed by root-relative posix path (09 3.5).

    Never follows a symlink (lstat on every entry, directories walked without following), skips
    anything outside root, caps count and size. Container-owned dirs are only read here."""
    out: dict[str, bytes] = {}
    base = root.resolve()
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            return out
    except OSError:
        return out
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            try:
                st = os.lstat(e.path)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                logger.warning("symlink in build output ignored: %s", e.path)
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append(Path(e.path))
                continue
            if not stat.S_ISREG(st.st_mode) or not e.name.endswith(suffix) or st.st_size > MAX_ARTIFACT_BYTES:
                continue
            p = Path(e.path)
            if not p.resolve().is_relative_to(base):
                continue
            fd = os.open(e.path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with os.fdopen(fd, "rb") as fh:
                    out[p.relative_to(root).as_posix()] = fh.read(MAX_ARTIFACT_BYTES + 1)
            except OSError:
                continue
            if len(out) >= MAX_ARTIFACTS:
                return out
    return out


def scratch_copy(dirs: dict[str, Path], name: str) -> dict[str, Path]:
    """Fresh host-made copy of the read-only source tree for one analyzer run."""
    import tempfile

    base = Path(tempfile.mkdtemp(prefix=f"scratch-{name}-", dir=dirs["host"].parent))
    shutil.copytree(dirs["src"], base / "src", symlinks=False)
    for root, dnames, fnames in os.walk(base):
        for n in dnames:
            os.chmod(os.path.join(root, n), 0o777)
        for n in fnames:
            os.chmod(os.path.join(root, n), 0o666)
    os.chmod(base, 0o777)
    return dirs | {"scratch": base}


def write_host(path: Path, data: bytes | str) -> None:
    """Supervisor-only write (O_NOFOLLOW) into the never-mounted host dir."""
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data.encode() if isinstance(data, str) else data
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)
