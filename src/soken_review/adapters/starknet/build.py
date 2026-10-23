"""Starknet deps and build steps in the sandbox (07 4, 8.2; 09 3.5, 4.2).

build(candidate, work_dir, cairo_version) -> BuildResult

Layout under work_dir:
  tree/         source tree written by the supervisor; container-writable (Scarb writes Scarb.lock).
                Never read back for review: the reviewed text is the pin store copy.
  scarb-cache/  SCARB_CACHE filled by deps (registry and git packages, corelib)
  cargo-home/   CARGO_HOME filled by deps (crates of Cairo procedural macros)
  output/       SCARB_TARGET_DIR, empty before build; the only place artifacts are read from
  host/         supervisor only, never mounted: build log, artifact copies, class hashes, trust scan,
                deps_verify.json (the fetched cache checked against the pinned Scarb.lock)

Gates before a container runs: the host must honour _BUILD_LIMITS (sandbox.profile admission,
reason `host_capacity`), and the fetched scarb-cache must match the pinned lock (deps_integrity,
reason `deps_integrity`) before any offline step reads it.

Containers write artifacts only; class hashes, selector sets and dep.match are computed here, in
the supervisor, from artifact bytes (provenance.decide_dep_match).
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.starknet.deps_integrity import discard_regenerable, verify_cargo_home, verify_scarb_cache
from soken_review.adapters.starknet.fetch import STARKNET_EGRESS_NETWORK
from soken_review.adapters.starknet.sierra import class_hash, hex_felt, selector_set
from soken_review.adapters.starknet.trust_scan import lock_path, package_name, scan_files
from soken_review.adapters.starknet.units import count_nsloc_cairo, in_scope_paths
from soken_review.sandbox.profile import (
    SANDBOX_UID,
    HostCapacityError,
    StepLimits,
    docker_argv,
    host_capacity,
    sandbox_writable_dir,
)

logger = logging.getLogger(__name__)

_IMAGE_MAP = Path(__file__).parent / "data" / "image_map.json"
# Floor 4g: the OZ workspace build was OOM-killed at ~2.8 GiB RSS on a 3.9 GiB host (2026-10-23);
# a host below the floor refuses the step with the numbers instead of letting the kernel decide.
_BUILD_LIMITS = StepLimits(cpus=4, memory="8g", pids=1024, max_file=512 * 1024 * 1024, min_memory="4g")
_DEPS_LIMITS = StepLimits(cpus=2, memory="2g", pids=256, max_file=256 * 1024 * 1024)
# `scarb --version` only. No cache is mounted, so the 1 MiB file cap cannot reach Scarb state.
_PROBE_LIMITS = StepLimits(cpus=1, memory="512m", pids=64, max_file=1024 * 1024)
# `scarb metadata` resolves the workspace against the fetched cache: the deps work class without the
# network. It must never run under _PROBE_LIMITS. Scarb keeps the registry index in a redb file
# (`registry/cache/<source>.v1.redb`, 3.5 MiB for one registry) that every run reopens read-write;
# under a 1 MiB fsize cap redb cannot write its clean-shutdown state and leaves the file marked
# "recovery required", and the next Scarb process (the build) aborts the repair, deletes and
# recreates the index. Offline resolution then has no cached record for any registry package and
# fails with "cannot access the network in offline mode" (stand, oz-account-v3, 2026-10-22).
_METADATA_LIMITS = _DEPS_LIMITS
_DEPS_WALL_S = 300
_DEPS_MAX_BYTES = 4 * 1024**3        # limits.yaml deps.starknet once measured (P0-DEPS)
_BUILD_WALL_S = 1500                 # 07 U-12: Scarb cold release build; 09 sets the wall
_MAX_ARTIFACT = 32 * 1024 * 1024
_MAX_ARTIFACTS = 200
_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_]{1,200}\.contract_class\.json$")
_PROFILE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_CAIRO_LINE_RE = re.compile(r"^cairo:\s*(\d+\.\d+\.\d+)", re.MULTILINE)


# --------------------------------------------------------------------------------------------
# Toolchain image (07 3.1, 8.2 step 1)
# --------------------------------------------------------------------------------------------

def image_for(cairo_version: str) -> str | None:
    """Image whose bundled Cairo is `cairo_version`: per-version override, then images map."""
    if not _VERSION_RE.match(cairo_version or ""):
        return None
    override = os.environ.get("SOKEN_IMAGE_STARKNET_BUILD_" + cairo_version.replace(".", "_"))
    if override:
        return override
    try:
        entry = json.loads(_IMAGE_MAP.read_text())["images"].get(cairo_version)
    except (OSError, ValueError, KeyError):
        return None
    if not entry or set(entry["digest"].removeprefix("sha256:")) <= {"0"}:
        return None
    return f"{entry['repository']}@{entry['digest']}"


def probe_cairo_version(image: str, work_dir: Path) -> str | None:
    """`scarb --version` inside the image (offline): the image's bundled Cairo, or None (U-10)."""
    argv = docker_argv(step="build", image=image, work_dir=work_dir, cache_dir=None, limits=_PROBE_LIMITS,
                       env={"HOME": "/tmp"}, command=["scarb", "--version"],
                       mounts=[(sandbox_writable_dir(work_dir / "probe"), "/work/probe", True)])
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=120, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    m = _CAIRO_LINE_RE.search(proc.stdout.decode(errors="replace"))
    return m.group(1) if proc.returncode == 0 and m else None


# --------------------------------------------------------------------------------------------
# Tree and output handling
# --------------------------------------------------------------------------------------------

def _give_to_sandbox(path: Path) -> None:
    """Make a supervisor-written file or dir writable by uid 10001 (chown, or dev chmod)."""
    uid, gid = (int(x) for x in SANDBOX_UID.split(":"))
    try:
        os.chown(path, uid, gid, follow_symlinks=False)
    except PermissionError:
        if os.environ.get("SOKEN_SANDBOX_DEV_PERMS") != "1":
            raise
        path.chmod(0o777 if path.is_dir() else 0o666)


def write_tree(files: dict[str, str], tree: Path) -> list[str]:
    """Write the candidate into `tree`; blocked toolchain files are not written. Returns skipped paths."""
    from soken_review.adapters.evm.units import safe_store_path

    skipped: list[str] = []
    sandbox_writable_dir(tree)
    base = tree.resolve()
    for raw, content in files.items():
        rel = safe_store_path(raw)
        if rel is None or re.search(r"(?:^|/)(?:rust-toolchain(?:\.toml)?|\.cargo/config(?:\.toml)?)$", rel):
            skipped.append(raw)
            continue
        dest = (tree / rel).resolve()
        if not dest.is_relative_to(base):
            skipped.append(raw)
            continue
        parent = dest.parent
        missing = []
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        parent_made = sorted(missing, key=lambda p: len(p.parts))
        dest.parent.mkdir(parents=True, exist_ok=True)
        for d in parent_made:
            _give_to_sandbox(d)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        _give_to_sandbox(dest)
    return skipped


def _write_host(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def lock_changed(tree: Path, files: dict[str, str], package_dir: str) -> str | None:
    """Scarb 2.13 has no `--locked`: after a container ran, read the tree's Scarb.lock back
    (O_NOFOLLOW, regular file only) and compare it byte for byte with the pinned copy.
    Returns a reason when it differs or cannot be read, None when unchanged."""
    rel = lock_path(files, package_dir)
    pinned = files.get(rel)
    if pinned is None:
        return "lock_missing"
    target = tree / rel
    try:
        st = target.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > 16 * 1024 * 1024:
            return "lock_not_regular_file"
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return "lock_unreadable"
    try:
        data = b""
        while chunk := os.read(fd, 1 << 20):
            data += chunk
    finally:
        os.close(fd)
    return None if data == pinned.encode("utf-8") else "lock_changed_by_resolution"


def _dir_bytes(path: Path) -> int | None:
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False, onerror=lambda _e: None):
        for entry in (*dirs, *files):
            try:
                total += os.lstat(os.path.join(root, entry)).st_blocks * 512
            except OSError:
                return None
    return total


def read_artifacts(output_dir: Path, profile: str, host_dir: Path) -> list[dict[str, Any]]:
    """Read `<output>/<profile>/*.contract_class.json` with lstat checks; hash in the supervisor.

    Symlinks, non-regular files, unexpected names and oversize files are skipped. Each accepted
    artifact is copied to host/artifacts/ and its class hash and selector sets computed here.
    """
    prof = output_dir / profile
    try:
        if not stat.S_ISDIR(prof.lstat().st_mode):
            return []
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    for entry in sorted(prof.iterdir(), key=lambda p: p.name):
        if len(rows) >= _MAX_ARTIFACTS:
            break
        if not _ARTIFACT_RE.match(entry.name):
            continue
        try:
            st = entry.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_ARTIFACT:
            continue
        fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            data = b""
            while chunk := os.read(fd, 1 << 20):
                data += chunk
                if len(data) > _MAX_ARTIFACT:
                    break
        finally:
            os.close(fd)
        if len(data) > _MAX_ARTIFACT:
            continue
        try:
            cls = json.loads(data)
            h = class_hash(cls)
            sels = selector_set(cls)
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("artifact %s unreadable: %s", entry.name, exc)
            continue
        _write_host(host_dir / "artifacts" / entry.name, data)
        rows.append({
            "contract": entry.name.removesuffix(".contract_class.json"),
            "file": f"artifacts/{entry.name}",
            "class_hash": hex_felt(h),
            "selectors": {k: sorted(hex(s) for s in v) for k, v in sels.items()},
        })
    return rows


# --------------------------------------------------------------------------------------------
# Container runs
# --------------------------------------------------------------------------------------------

def _mounts(work_dir: Path) -> list[tuple[Path, str, bool]]:
    return [
        (work_dir / "tree", "/work/tree", False),
        (work_dir / "scarb-cache", "/work/scarb-cache", False),
        (work_dir / "cargo-home", "/work/cargo-home", False),
    ]


def _env() -> dict[str, str]:
    return {"HOME": "/tmp", "SCARB_CACHE": "/work/scarb-cache", "CARGO_HOME": "/work/cargo-home",
            "SCARB_TARGET_DIR": "/work/output", "CARGO_TERM_COLOR": "never", "NO_COLOR": "1"}


def _offline_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Env of a no-network Scarb run. `SCARB_OFFLINE` (Scarb's env form of `--offline`) also reaches
    every nested `scarb` a tool starts without the flag (caracal runs `scarb clean` and
    `scarb build --workspace`), so it resolves from the fetched cache instead of trying the
    registry on a network that does not exist."""
    return {**_env(), "SCARB_OFFLINE": "true", **(overrides or {})}


def _container_workdir(package_dir: str) -> str | None:
    if not package_dir:
        return "/work/tree"
    parts = PurePosixPath(package_dir).parts
    if any(p in ("..", ".") or not re.match(r"^[A-Za-z0-9_.-]+$", p) or p.startswith("-") for p in parts):
        return None
    return "/work/tree/" + "/".join(parts)


def run_deps(image: str, work_dir: Path, workdir: str) -> str | None:
    """`scarb fetch` with the family egress network; wall and byte budget enforced. None = ok."""
    name = f"soken-stk-deps-{secrets.token_hex(6)}"
    argv = docker_argv(step="deps", image=image, work_dir=work_dir, cache_dir=None, limits=_DEPS_LIMITS,
                       env=_env(), command=["scarb", "fetch"], family_network=STARKNET_EGRESS_NETWORK,
                       workdir=workdir, mounts=_mounts(work_dir), name=name)
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + _DEPS_WALL_S
    try:
        while proc.poll() is None:
            if time.monotonic() > deadline:
                return "deps_timeout"
            used = [_dir_bytes(work_dir / d) for d in ("scarb-cache", "cargo-home")]
            if any(u is None for u in used) or sum(u or 0 for u in used) > _DEPS_MAX_BYTES:
                return "deps_budget_exceeded"
            time.sleep(1)
    finally:
        if proc.poll() is None:
            _remove_container(name)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
    out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
    if proc.returncode != 0:
        return "\n".join([f"exit {proc.returncode}", *out.splitlines()[-20:]])
    return None


def run_offline(image: str, work_dir: Path, workdir: str, command: list[str], wall_s: int,
                limits: StepLimits = _BUILD_LIMITS, env: dict[str, str] | None = None) -> tuple[int, str]:
    """Run a Scarb command with no network; output dir mounted read-write. Returns (rc, log).

    `env` overrides single variables of the offline environment (a tool that needs its own
    `SCARB_TARGET_DIR`); the cache, home and offline variables stay.
    """
    mounts = [*_mounts(work_dir), (work_dir / "output", "/work/output", False)]
    name = f"soken-stk-run-{secrets.token_hex(6)}"
    argv = docker_argv(step="build", image=image, work_dir=work_dir, cache_dir=None, limits=limits,
                       env=_offline_env(env), command=command, workdir=workdir, mounts=mounts, name=name)
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=wall_s, check=False)
    except subprocess.TimeoutExpired:
        _remove_container(name)   # killing the `docker run` client alone leaves the container running
        return 124, "build_timeout"
    return proc.returncode, proc.stdout.decode(errors="replace")


def _remove_container(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)


def run_metadata(image: str, work_dir: Path, workdir: str) -> tuple[int, str]:
    """Run `scarb metadata --format-version 1 --offline` in the sandbox; return (rc, stdout JSON).

    No network; only the tree and the already-fetched scarb-cache are mounted. stdout is the
    metadata JSON; stderr carries scarb diagnostics (discarded by the supervisor). The build
    container never writes to host/, so this output cannot be spoofed after the fact. Runs under
    _METADATA_LIMITS: the registry index in scarb-cache must stay writable (see the constant).
    """
    name = f"soken-stk-meta-{secrets.token_hex(6)}"
    argv = docker_argv(step="build", image=image, work_dir=work_dir, cache_dir=None,
                       limits=_METADATA_LIMITS, env=_offline_env(),
                       command=["scarb", "--offline", "metadata", "--format-version", "1"],
                       workdir=workdir, mounts=_mounts(work_dir), name=name)
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=120, check=False)
    except subprocess.TimeoutExpired as exc:
        _remove_container(name)
        return 1, str(exc)
    except FileNotFoundError as exc:
        return 1, str(exc)
    return proc.returncode, proc.stdout.decode(errors="replace")


# --------------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------------

def plugin_cargo_locks(files: dict[str, str]) -> dict[str, str | None]:
    """Pinned `Cargo.lock` text of every in-tree `[cairo-plugin]` package dir (None when the dir has
    none): the oracle for CARGO_HOME. Only plugin dirs count; a Cargo.lock elsewhere is not one
    Scarb's cargo run reads."""
    import tomllib

    out: dict[str, str | None] = {}
    for path, text in files.items():
        if PurePosixPath(path).name != "Scarb.toml":
            continue
        try:
            manifest = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            continue
        if "cairo-plugin" not in manifest:
            continue
        d = str(PurePosixPath(path).parent) if "/" in path else ""
        out[d] = files.get(f"{d}/Cargo.lock" if d else "Cargo.lock")
    return out


def _mark_untrusted(candidate: Candidate, host: Path, reasons: list[str]) -> None:
    """Add `reasons` to host/trust_scan.json and flag the inputs untrusted (blocks tier A, not the build)."""
    candidate.untrusted_inputs = True
    path = host / "trust_scan.json"
    data = json.loads(path.read_text()) if path.exists() else {"untrusted": True, "reasons": []}
    data["untrusted"] = True
    data["reasons"] = sorted(set(data["reasons"]) | set(reasons))
    _write_host(path, json.dumps(data).encode())


def _mark_lock(candidate: Candidate, host: Path, work_dir: Path, package_dir: str, stage: str) -> None:
    """A lockfile that resolution changed makes the inputs untrusted (blocks tier A, not the build)."""
    reason = lock_changed(work_dir / "tree", candidate.files, package_dir)
    if reason is None:
        return
    _mark_untrusted(candidate, host, [f"{reason}:{stage}"])


def build(candidate: Candidate, work_dir: Path, cairo_version: str | None) -> BuildResult:
    """Deps then offline build; artifacts hashed in the supervisor (host/artifacts.json)."""
    work_dir.mkdir(parents=True, exist_ok=True)
    host = work_dir / "host"
    host.mkdir(exist_ok=True)
    settings = candidate.settings or {}
    package_dir = str(settings.get("package_dir") or "")
    profile = str(settings.get("profile") or "release")

    def failed(reason: str, head: str | None) -> BuildResult:
        _write_host(host / "build_status.json", json.dumps({"status": "failed", "reason": reason}).encode())
        return BuildResult(candidate=candidate, status="failed", reason=reason, stderr_head=head)

    untrusted, reasons = scan_files(candidate.files, package_dir)
    candidate.untrusted_inputs = untrusted
    _write_host(host / "trust_scan.json", json.dumps({"untrusted": untrusted, "reasons": reasons}).encode())

    # Write build context and pinned lock for the plugin-scope check (supervisor only; never mounted).
    pkg = package_name(candidate.files, package_dir)
    lock_rel = lock_path(candidate.files, package_dir)
    lock_content = candidate.files.get(lock_rel) or ""
    _write_host(host / "build_context.json", json.dumps({"package_name": pkg, "lock_path": lock_rel}).encode())
    _write_host(host / "Scarb.lock.pinned", lock_content.encode())

    if not _PROFILE_RE.match(profile):
        return failed("build_failed", "profile_rejected")
    workdir = _container_workdir(package_dir)
    if workdir is None:
        return failed("build_failed", "unsafe_package_dir")
    if not cairo_version:
        return failed("toolchain_unavailable", "cairo_version_unknown")
    image = image_for(cairo_version)
    if image is None:
        return failed("toolchain_unavailable", f"no_image_for_cairo_{cairo_version}")
    if not shutil.which("docker"):
        return failed("build_failed", "sandbox_unavailable")
    # Admission before any container: the step's largest limit (_BUILD_LIMITS) must fit this host,
    # or the job fails now with the numbers (E_HOST_CAPACITY) instead of fetching for nothing and
    # ending under the global OOM killer. docker_argv repeats the check for every run as a backstop.
    try:
        host_capacity().check(_BUILD_LIMITS, "build")
    except HostCapacityError as exc:
        _write_host(host / "build_status.json", json.dumps({"status": "failed", "reason": "host_capacity",
                                                            "detail": exc.detail()}).encode())
        return BuildResult(candidate=candidate, status="failed", reason="host_capacity", stderr_head=exc.reason,
                           build_notes={"host_capacity": exc.detail()})
    bundled = probe_cairo_version(image, work_dir)
    if bundled != cairo_version:
        return failed("toolchain_unavailable", f"image_cairo_{bundled}_not_{cairo_version}")

    write_tree(candidate.files, work_dir / "tree")
    for d in ("scarb-cache", "cargo-home"):
        sandbox_writable_dir(work_dir / d)
    out = work_dir / "output"
    if out.exists():
        return failed("build_failed", "output_dir_not_empty")
    sandbox_writable_dir(out)

    deps_err = run_deps(image, work_dir, workdir)
    if deps_err is not None:
        return failed("deps_unreachable", deps_err)
    _mark_lock(candidate, host, work_dir, package_dir, "after_deps")

    # The fetched cache is checked against the pinned lock (never the tree copy, which the deps
    # container may rewrite) before the first offline step reads it. A mismatch or an unlisted
    # package closes the build; rows the lock cannot vouch for are flagged, not trusted.
    scarb_v = verify_scarb_cache(lock_content if lock_rel in candidate.files else None, work_dir / "scarb-cache")
    cargo_v = verify_cargo_home(plugin_cargo_locks(candidate.files), work_dir / "cargo-home")
    verify: dict[str, Any] = {"scarb_cache": scarb_v.as_dict(), "cargo_home": cargo_v.as_dict()}
    failures = [*scarb_v.failures, *[f"cargo-home/{f}" for f in cargo_v.failures]]
    if not failures:
        # Scarb and cargo compile an already-extracted tree as is (`.scarb-ok` / `.cargo-ok` skip the
        # untar) and Scarb reuses an unpacked corelib the same way, so the verified bytes vouch for
        # the build only once those trees are gone and the offline run re-extracts them. Removed
        # through directory descriptors: a symlink planted there is refused, never followed.
        discarded: list[str] = []
        for root, rels in ((work_dir / "scarb-cache", scarb_v.regenerate), (work_dir / "cargo-home", cargo_v.regenerate)):
            for rel in rels:
                removed, reason = discard_regenerable(root, rel)
                if reason is not None:
                    failures.append(f"{root.name}/{reason}")
                elif removed:
                    discarded.append(f"{root.name}/{rel}")
        verify["discarded"] = discarded
    failures = sorted(set(failures))
    verify["failures"] = failures
    _write_host(host / "deps_verify.json", json.dumps(verify, indent=1).encode())
    if failures:
        return failed("deps_integrity", "\n".join(failures[:20]))
    deps_unverified = list(scarb_v.unverified)
    if deps_unverified:
        _mark_untrusted(candidate, host, [f"deps_unverified:{label}" for label in deps_unverified])

    # Supervisor reads scarb metadata offline (after fetch, before build); host/ is never
    # mounted into containers so this file cannot be modified by the build step.
    meta_rc, meta_out = run_metadata(image, work_dir, workdir)
    if meta_rc == 0 and meta_out.strip():
        _write_host(host / "scarb_metadata.json", meta_out.encode())
    else:
        logger.warning("scarb metadata failed (rc=%d); plugin-scope check will be skipped", meta_rc)
    # The metadata probe is the first resolution from the fetched index with no network: Scarb
    # checks every resolved record against the lock (`ops/resolve.rs` `check_checksums`) and
    # rewrites Scarb.lock from the result. A tree lock that is not the pinned one byte for byte
    # means the index did not reproduce the pinned resolution; nothing has compiled yet, so close.
    drift = lock_changed(work_dir / "tree", candidate.files, package_dir)
    if drift is not None:
        return failed("deps_integrity", f"index_resolution_differs_from_lock:{drift}")

    t0 = time.monotonic()
    # --package: only the scanned package is compiled (a workspace build would compile every member).
    pkg = package_name(candidate.files, package_dir)
    cmd = ["scarb", "--offline", "--profile", profile, "build"] + (["--package", pkg] if pkg else [])
    rc, log = run_offline(image, work_dir, workdir, cmd, _BUILD_WALL_S)
    _write_host(host / "build.log", log.encode())
    if rc != 0:
        return failed("build_failed", "\n".join([f"exit {rc}", *log.splitlines()[-20:]]))

    _mark_lock(candidate, host, work_dir, package_dir, "after_build")
    artifacts = read_artifacts(out, profile, host)
    _write_host(host / "artifacts.json", json.dumps(artifacts, indent=1).encode())
    _write_host(host / "build_status.json", json.dumps({
        "status": "ok", "image": image, "cairo": bundled, "profile": profile,
        "build_s": round(time.monotonic() - t0, 1), "artifacts": len(artifacts)}).encode())
    scope = in_scope_paths(candidate.files, package_dir)
    nsloc = sum(count_nsloc_cairo(candidate.files[p]) for p in scope)
    return BuildResult(candidate=candidate, status="ok", nsloc=nsloc, work_dir=str(work_dir),
                       stderr_head="\n".join(log.splitlines()[-5:]) or None,
                       build_notes={"deps_unverified": deps_unverified})
