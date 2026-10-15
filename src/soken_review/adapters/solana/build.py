"""Solana build step: cargo-build-sbf inside the sandbox (06 sections 3.3.2, 3.3.3).

build(candidate) -> BuildResult

Security rules (RULES.md §untrusted-data, 09 3.5, 06 3.3):
  - Trust scan runs before writing the tree; fail closed on any untrusted pattern.
  - Never write .cargo/config*, rust-toolchain* from the fetched tree.
  - Source tree mounted read-only in the build container; container writes only to output_dir.
  - Supervisor writes (logs, hashes, provenance) go to host_dir, NEVER mounted in any container.
  - Reading container output: lstat every entry; reject symlinks and non-regular-files;
    open with explicit path (no follow); copy to host_dir before use.
  - cargo fetch (deps) runs in a network-enabled container (runsc-egress family network).
  - cargo build-sbf runs in an offline container (runsc-none) via sandbox.profile.docker_argv.
  - Image per Solana version line (images.build_image): the derived solana-verifiable-build image of
    the version solana-verify would pick; source at its WorkingDir, crates under its CARGO_HOME, the
    same cargo build-sbf command, so the hash is comparable with the deployed program (U-S1).
  - Fail closed when docker is unavailable.
  - Host execution only behind SOKEN_SOLANA_DIRECT=1 (dev only, never in tests).
  - Command is an argv list, never a shell string.
  - Build exit code is respected: non-zero = status failed.
  - HOME = the image home holding platform-tools, readable not writable (root fs read-only, 09 4.2).
  - Build hash: SHA-256 of .so bytes with trailing zeros stripped (F5).
  - Overflow checks: extracted from verbose rustc log (04 8.5, U-S5).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.solana import images as solana_images
from soken_review.sandbox.profile import StepLimits, docker_argv, sandbox_writable_dir

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SBX_ROOT = _REPO_ROOT / ".sbx"

# Dev-only bypass: never set in CI or tests
_DIRECT_BUILD = os.environ.get("SOKEN_SOLANA_DIRECT", "0") == "1"

# Sandbox resource limits (06 3.3.1; Solana builds are heavier than EVM)
_BUILD_LIMITS = StepLimits(cpus=4, memory="8g", pids=512, max_file=512 * 1024 * 1024)
_DEPS_LIMITS = StepLimits(cpus=2, memory="4g", pids=256, max_file=256 * 1024 * 1024)

# Solana family egress network (for cargo fetch)
_SOLANA_EGRESS_NETWORK = os.environ.get("SOKEN_SOLANA_NETWORK", "soken-egress-solana")

# Allowlisted cargo args (06 3.3.3)
_ALLOWED_CARGO_ARGS = frozenset({
    "--features", "--no-default-features", "--locked", "--frozen", "--offline",
    "-p", "--package", "--lib",
    # --manifest-path intentionally excluded: path injection risk; not accepted from candidates
})
# --arch: exactly these values accepted (cargo-build-sbf 2.1.x)
_ALLOWED_ARCH_VALUES = frozenset({"sbfv1", "sbfv2", "sbfv3"})
# Each feature token must match this; no spaces, no leading dash (shell-injection guard)
_FEATURE_TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)?$')
_PKG_NAME_RE = re.compile(r'^[A-Za-z0-9_-]+$')
# Container path component: must not start with '-' and must be safe
_CONTAINER_PATH_RE = re.compile(r'^[A-Za-z0-9_./-]+$')

_OVERFLOW_RE = re.compile(r'-C\s+overflow-checks=(on|off)')

# Files never written from the fetched tree (06 3.3.4)
_BLOCKED_PATH_RES = [
    re.compile(r'(?:^|/)\.cargo/config(?:\.toml)?$', re.IGNORECASE),
    re.compile(r'(?:^|/)rust-toolchain(?:\.toml)?$', re.IGNORECASE),
]


def _path_is_blocked(path: str) -> bool:
    return any(pat.search(path) for pat in _BLOCKED_PATH_RES)


# ---------------------------------------------------------------------------
# Image and verify-args helpers (06 3.3.1, 3.3.3)
# ---------------------------------------------------------------------------

_LIB_NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_VERIFY_FLAGS_WITH_VALUE = frozenset({"--library-name", "--mount-path", "--base-image", "--arch"})


class VerifyArgs(dict):
    """Parsed `solana-verify build` args of an owner-linked verify PDA (06 3.3.3)."""


def parse_verify_args(args: list[str] | None) -> tuple[VerifyArgs | None, str | None]:
    """Split verify PDA args into flags we honour and cargo args. (None, reason) when not allowlisted.

    Supported: --library-name, --mount-path, --base-image, --arch, --bpf, and cargo args after "--"
    through _validate_args. Anything else (e.g. --cargo-build-sbf-args, --workspace-path,
    `--config ...` cargo args) is untrusted_args: nothing built.
    """
    out = VerifyArgs(library_name=None, mount_path="", base_image=None, arch=None, bpf=False, cargo_args=[])
    items = list(args or [])
    i = 0
    while i < len(items):
        arg = items[i]
        if arg == "--":
            cargo, ok = _validate_args(items[i + 1:])
            if not ok:
                return None, "untrusted_args"
            out["cargo_args"] = cargo
            break
        name, eq, inline = arg.partition("=")
        if name in _VERIFY_FLAGS_WITH_VALUE:
            if eq:
                value = inline
                i += 1
            elif i + 1 < len(items):
                value = items[i + 1]
                i += 2
            else:
                return None, "untrusted_args"
            key = name[2:].replace("-", "_")
            out[key] = value
            continue
        if arg == "--bpf":
            out["bpf"] = True
            i += 1
            continue
        return None, "untrusted_args"
    if out["library_name"] is not None and not _LIB_NAME_RE.match(out["library_name"]):
        return None, "untrusted_args"
    if out["mount_path"]:
        from soken_review.adapters.solana.units import safe_store_path
        norm = safe_store_path(out["mount_path"].strip("/"))
        if norm is None or not _CONTAINER_PATH_RE.match(norm):
            return None, "untrusted_args"
        out["mount_path"] = norm
    return out, None


def _toml(content: str) -> dict[str, Any] | None:
    import tomllib
    try:
        return tomllib.loads(content)
    except (tomllib.TOMLDecodeError, TypeError):
        return None


def _manifests_under(files: dict[str, str], root: str) -> dict[str, dict[str, Any]]:
    """Parsed Cargo.toml files under root, keyed by path relative to root ("" = root itself)."""
    prefix = f"{root}/" if root else ""
    out: dict[str, dict[str, Any]] = {}
    for path, content in files.items():
        if not path.startswith(prefix) or PurePosixPath(path).name != "Cargo.toml" or not isinstance(content, str):
            continue
        parsed = _toml(content)
        if parsed is not None:
            rel = PurePosixPath(path[len(prefix):]).parent.as_posix()
            out["" if rel == "." else rel] = parsed
    return out


def _lib_name(manifest: dict[str, Any]) -> str | None:
    lib = manifest.get("lib") if isinstance(manifest.get("lib"), dict) else {}
    if lib.get("name"):
        return str(lib["name"])
    pkg = manifest.get("package") if isinstance(manifest.get("package"), dict) else {}
    return str(pkg["name"]).replace("-", "_") if pkg.get("name") else None


def _library_dir(manifests: dict[str, dict[str, Any]], library_name: str) -> str | None:
    """Dir (relative to the mount) of the Cargo.toml whose [lib] name is library_name, as solana-verify
    find_relative_manifest_path_and_build_path; shortest path first for a stable choice."""
    hits = sorted((d for d, m in manifests.items() if _lib_name(m) == library_name), key=lambda d: (d.count("/"), d))
    return hits[0] if hits else None


def _workspace_dir(manifests: dict[str, dict[str, Any]], crate_dir: str) -> str:
    """Nearest ancestor (or the dir itself) whose Cargo.toml has [workspace]: where target/ goes."""
    parts = [p for p in crate_dir.split("/") if p]
    for n in range(len(parts), -1, -1):
        d = "/".join(parts[:n])
        if isinstance(manifests.get(d, {}).get("workspace"), dict):
            return d
    return crate_dir


def _version_from_metadata(manifests: dict[str, dict[str, Any]], ws_dir: str) -> str | None:
    """`[workspace.metadata.cli] solana` of the workspace root manifest (solana-verify first choice)."""
    ws = (manifests.get(ws_dir) or {}).get("workspace") or {}
    meta = ws.get("metadata") if isinstance(ws, dict) else None
    cli = meta.get("cli") if isinstance(meta, dict) else None
    value = cli.get("solana") if isinstance(cli, dict) else None
    return str(value) if isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value) else None


_DEPS_WALL_S = 300                 # 09 3.2 Solana deps wall
_DEPS_MAX_BYTES = 6 * 1024**3      # 09 3.2 Solana deps budget (limits.yaml deps.solana once measured)


def _dir_bytes(path: Path) -> int | None:
    """Disk usage in bytes (allocated blocks, so sparse files count as written).

    None when any entry cannot be read: the container (uid 10001) can create unreadable dirs,
    and an unmeasurable tree is treated as over budget (fail closed).
    """
    total = 0
    failed = False

    def _err(_exc: OSError) -> None:
        nonlocal failed
        failed = True

    for root, dirs, files in os.walk(path, onerror=_err, followlinks=False):
        for entry in (*dirs, *files):
            try:
                st = os.lstat(os.path.join(root, entry))
            except OSError:
                return None
            total += st.st_blocks * 512
        if failed:
            return None
    return None if failed else total


def _fetch_deps(
    image: str, cargo_home: Path, mounts: list[tuple[Path, str, bool]], workdir: str,
    env: dict[str, str], command: list[str], image_paths: tuple[str, ...],
) -> str | None:
    """Run one `cargo fetch --locked` in the sandbox with the family egress network. None = ok.

    The wall and the byte budget are enforced while it runs: the container is named and killed
    when CARGO_HOME grows past the budget (a hostile lockfile cannot fill the host disk).
    """
    import secrets
    import time

    from soken_review.adapters.solana.fetch import _SOLANA_EGRESS_NETWORK

    name = f"soken-deps-{secrets.token_hex(6)}"
    argv = docker_argv(
        step="deps",
        image=image,
        work_dir=cargo_home.parent,
        cache_dir=None,
        limits=_DEPS_LIMITS,
        env=env,
        command=command,
        family_network=_SOLANA_EGRESS_NETWORK,
        runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
        workdir=workdir,
        mounts=mounts,
        name=name,
        image_paths=image_paths,
    )
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + _DEPS_WALL_S
    try:
        while proc.poll() is None:
            used = _dir_bytes(cargo_home)
            if time.monotonic() > deadline:
                return "deps_timeout"
            if used is None or used > _DEPS_MAX_BYTES:
                return "deps_budget_exceeded"
            time.sleep(1)
    finally:
        # Always remove the container, whatever happened above (kill on budget, crash, interrupt).
        if proc.poll() is None:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
    stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
    if proc.returncode != 0:
        return "\n".join(stderr.splitlines()[-20:])
    return None


# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def _detect_version_from_lock(cargo_lock_content: str) -> str | None:
    """Solana line from Cargo.lock (06 3.3.1): solana-program / solana-sdk, else the modular
    entrypoint crates that replaced them (solana-program-entrypoint, solana-account-info)."""
    for crate in ("solana-program", "solana-sdk", "solana-program-entrypoint", "solana-account-info"):
        m = re.search(rf'^name = "{crate}"\s*\nversion = "([^"]+)"', cargo_lock_content, re.MULTILINE)
        if m:
            return m.group(1)
    return None


def _detect_version_from_workspace(files: dict[str, str]) -> str | None:
    for path, content in files.items():
        if PurePosixPath(path).name == "Cargo.toml" and isinstance(content, str):
            m = re.search(
                r'\[workspace\.metadata\.cli\][^\[]*solana\s*=\s*"([^"]+)"',
                content, re.DOTALL
            )
            if m:
                return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Hash and overflow checks
# ---------------------------------------------------------------------------

def _so_hash(so_bytes: bytes) -> str:
    """SHA-256 of program bytes with trailing zeros stripped (F5)."""
    return hashlib.sha256(so_bytes.rstrip(b"\x00")).hexdigest()


def _extract_overflow_checks(log: str) -> str:
    for m in _OVERFLOW_RE.finditer(log):
        return m.group(1)
    return "unknown"


# ---------------------------------------------------------------------------
# Arg validation (06 3.3.3)
# ---------------------------------------------------------------------------

def _validate_features(features_str: str) -> tuple[list[str], bool]:
    """Split and validate feature tokens; each must match _FEATURE_TOKEN_RE.

    Returns (token_list, ok). Never passes a comma-separated string to cargo;
    each token becomes a separate argv element via --features token ... repeated.
    """
    tokens = [t.strip() for t in features_str.replace(",", " ").split()]
    for tok in tokens:
        if not tok:
            continue
        if tok.startswith("-"):
            return [], False
        if not _FEATURE_TOKEN_RE.match(tok):
            return [], False
    return [t for t in tokens if t], True


def _validate_args(args: list[str]) -> tuple[list[str], bool]:
    """Validate and expand cargo args; features are split into per-token argv items.

    Unknown args = rejected (reason build_args_rejected). No shell expansion; every
    value is an argv token, never part of a shell string.
    """
    validated: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _ALLOWED_CARGO_ARGS:
            validated.append(arg)
            if arg in ("--features", "-p", "--package"):
                if i + 1 >= len(args):
                    return [], False
                val = args[i + 1]
                if arg == "--features":
                    tokens, ok = _validate_features(val)
                    if not ok:
                        return [], False
                    # Remove the --features we appended, add per-token form
                    validated.pop()
                    for tok in tokens:
                        validated += ["--features", tok]
                    i += 2
                    continue
                if arg in ("-p", "--package") and not _PKG_NAME_RE.match(val):
                    return [], False
                validated.append(val)
                i += 2
                continue
        elif arg == "--arch":
            # --arch only allowed with exact values
            if i + 1 >= len(args):
                return [], False
            val = args[i + 1]
            if val not in _ALLOWED_ARCH_VALUES:
                return [], False
            validated += ["--arch", val]
            i += 2
            continue
        elif arg.startswith("-"):
            # Any other flag = rejected
            return [], False
        i += 1
    return validated, True


# ---------------------------------------------------------------------------
# Safe file writing (src tree — blocked files excluded)
# ---------------------------------------------------------------------------

def _write_host_file(path: Path, data: bytes) -> None:
    """Write data to a host-only file using O_NOFOLLOW to prevent symlink attacks."""
    import os as _os
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = _os.open(
        str(path),
        _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC | _os.O_NOFOLLOW,
        0o600,
    )
    try:
        _os.write(fd, data)
    finally:
        _os.close(fd)


def _write_source_tree(files: dict[str, str], src_dir: Path) -> list[str]:
    """Write source files to src_dir, skipping blocked and unsafe paths.

    Normalizes each path with safe_store_path first; checks blocked patterns on the
    normalized path (not raw) to prevent bypass via path normalization tricks.
    src_dir must NOT be mounted in any container after this point (read-only mount only).
    """
    from soken_review.adapters.solana.units import safe_store_path

    src_base = src_dir.resolve()
    skipped: list[str] = []

    for raw_path, content in files.items():
        # Normalize first; reject if unsafe
        norm = safe_store_path(raw_path)
        if norm is None:
            skipped.append(f"unsafe_path:{raw_path}")
            continue
        # Check blocked patterns on normalized path
        if _path_is_blocked(norm):
            skipped.append(f"blocked:{raw_path}->norm:{norm}")
            continue
        dest = (src_dir / norm).resolve()
        if not dest.is_relative_to(src_base):
            skipped.append(f"traversal:{raw_path}")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            dest.write_bytes(content)
        else:
            dest.write_text(content, encoding="utf-8")

    return skipped


# ---------------------------------------------------------------------------
# Safe output reading (09 3.5, RULES.md §untrusted-data)
# ---------------------------------------------------------------------------

_SO_MAX_BYTES = 64 * 1024 * 1024
_SO_MAX_FILES = 64


def _safe_read_so(output_dir: Path, host_dir: Path, want: str | None = None) -> tuple[bytes | None, str | None]:
    """Read the deployable .so from the container's output_dir/deploy into host_dir.

    want: the exact file name (`<library_name>.so`, as solana-verify finds it); None = first .so.
    The read goes through sandbox.output (09 3.5): the deploy dir and every entry are opened without
    following links; a symlink, special file or oversize file anywhere there rejects the whole read.
    The bytes read are the bytes written to host_dir and hashed; nothing is copied by path.
    """
    from soken_review.sandbox.output import UnsafeOutput, read_output_files

    try:
        found = read_output_files(output_dir / "deploy", want or "*.so", _SO_MAX_FILES, _SO_MAX_BYTES)
    except (FileNotFoundError, UnsafeOutput) as exc:
        logger.warning("build output rejected: %s", exc)
        return None, None
    names = sorted(n for n in found if "/" not in n and n.endswith(".so"))
    if not names:
        return None, None
    name = names[0]
    data = found[name]
    dest = (host_dir / name).resolve()
    if not dest.is_relative_to(host_dir.resolve()):
        return None, None
    _write_host_file(dest, data)
    return data, name


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build(candidate: Candidate, work_dir: Path | None = None) -> BuildResult:
    """Build a Solana candidate and return a BuildResult (trust scan first)."""
    _SBX_ROOT.mkdir(exist_ok=True)
    if work_dir is None:
        tmp_path = Path(tempfile.mkdtemp(dir=_SBX_ROOT))
        return _do_build(candidate, tmp_path)
    work_dir.mkdir(parents=True, exist_ok=True)
    return _do_build(candidate, work_dir)


def _fail(candidate: Candidate, reason: str, head: str) -> BuildResult:
    return BuildResult(candidate=candidate, status="failed", reason=reason, stderr_head=head)


def _do_build(candidate: Candidate, work_dir: Path) -> BuildResult:
    work_dir.mkdir(parents=True, exist_ok=True)

    # host_dir: NEVER mounted in any container (supervisor writes only)
    host_dir = work_dir / "host"
    host_dir.mkdir(exist_ok=True)
    settings = candidate.settings or {}

    # Step 1: Trust scan (06 3.3.4). It decides tier A only: an untrusted candidate is still built
    # and analyzed in the sandbox, and resolve_provenance answers not_checkable BUILD_INPUT_UNTRUSTED.
    from soken_review.adapters.solana.trust_scan import scan_candidate_files
    untrusted, reasons = scan_candidate_files(candidate.files, settings.get("unread_paths") or ())
    if untrusted:
        candidate.untrusted_inputs = True
        _write_host_file(host_dir / "untrusted_inputs.txt", "\n".join(reasons).encode())

    # Step 2: verify args of the owner-linked PDA (06 3.3.3); anything off the allowlist builds nothing
    vargs, bad = parse_verify_args(settings.get("verify_args"))
    if vargs is None:
        return _fail(candidate, bad or "untrusted_args", "verify_args_failed_allowlist")
    if vargs["bpf"]:
        return _fail(candidate, "unsupported_toolchain", "bpf_line_not_proven")
    mount = vargs["mount_path"] or (getattr(candidate, "mount_path", None) or "").strip("/")
    manifests = _manifests_under(candidate.files, mount)
    library = vargs["library_name"]
    crate_rel = ""
    if library:
        found = _library_dir(manifests, library)
        if found is None:
            return _fail(candidate, "failed", f"library_not_found:{library}")
        crate_rel = found
    ws_rel = _workspace_dir(manifests, crate_rel)

    # Step 3: Cargo.lock of the workspace (solana-verify refuses without it, F29)
    lock_key = "/".join(p for p in (mount, ws_rel, "Cargo.lock") if p)
    lock_content = candidate.files.get(lock_key) if isinstance(candidate.files.get(lock_key), str) else None
    if lock_content is None:
        lock_content = next((c for p, c in candidate.files.items()
                             if PurePosixPath(p).name == "Cargo.lock" and isinstance(c, str)), None)

    # Step 4: Version, as solana-verify picks it: --base-image, [workspace.metadata.cli], Cargo.lock
    version: str | None = None
    if vargs["base_image"]:
        version = solana_images.version_from_base_image(vargs["base_image"])
        if version is None:
            return _fail(candidate, "untrusted_base_image", "base_image_not_in_image_map")
    if version is None:
        version = _version_from_metadata(manifests, "") or _version_from_metadata(manifests, ws_rel)
    if version is None and lock_content:
        version = _detect_version_from_lock(lock_content)
    if version is None:
        version = _detect_version_from_workspace(candidate.files)
    if version is None and _DIRECT_BUILD:
        try:
            res = subprocess.run(  # noqa: PLW1510
                ["cargo-build-sbf", "--version"], capture_output=True, text=True, timeout=10
            )
            m = re.search(r'solana-cargo-build-sbf\s+(\S+)', res.stdout + res.stderr)
            if m:
                version = m.group(1)
        except Exception:  # noqa: BLE001,S110
            pass
    if version is None:
        return _fail(candidate, "unsupported_toolchain", "solana_version_unknown")

    # Step 5: Image of that exact version (06 3.3.1); no image = nothing built
    image = solana_images.build_image(version) if not _DIRECT_BUILD else None
    if not _DIRECT_BUILD and image is None:
        return _fail(candidate, "unsupported_toolchain", f"no_image_for_version_{version}")
    if vargs["arch"] and (image is None or vargs["arch"] not in image.arch_values):
        return _fail(candidate, "untrusted_args", "arch_not_listed_for_image")

    # Step 6: Args (user args and verify cargo args, one allowlist)
    build_args: list[str] = list(getattr(candidate, "build_args", None) or [])
    if build_args:
        build_args, valid = _validate_args(build_args)
        if not valid:
            return _fail(candidate, "untrusted_args", "declared_args_failed_allowlist")
    build_args += vargs["cargo_args"]

    # Step 7: Lock requirement (with address = required)
    if lock_content is None and getattr(candidate, "program_id", None) is not None:
        return _fail(candidate, "lock_missing", "Cargo.lock required")

    # Step 8: Write source tree (blocked files excluded)
    src_dir = work_dir / "src"
    src_dir.mkdir(exist_ok=True)
    _write_source_tree(candidate.files, src_dir)

    # output_dir: mounted into container (empty, receives target/ of the build)
    output_dir = work_dir / "output"
    sandbox_writable_dir(output_dir)

    if _DIRECT_BUILD:
        crate_dir = src_dir / mount / crate_rel if (mount or crate_rel) else src_dir
        return _build_direct(candidate, crate_dir, output_dir, host_dir, work_dir, build_args)

    assert image is not None
    meta = {
        "version": version, "line": image.line, "u_s1": image.u_s1, "image": image.ref,
        "upstream": image.upstream, "working_dir": image.working_dir, "cargo_home": image.cargo_home,
        "home": image.home, "active_toolchain": image.active_toolchain, "mount": mount,
        "crate_rel": crate_rel, "ws_rel": ws_rel, "library_name": library, "cargo_args": build_args,
        "arch": vargs["arch"],
    }
    _write_host_file(host_dir / "build_meta.json", json.dumps(meta, indent=2).encode())
    return _build_docker(candidate, src_dir, output_dir, host_dir, work_dir, image, meta)


# ---------------------------------------------------------------------------
# Direct build (dev-only, SOKEN_SOLANA_DIRECT=1)
# ---------------------------------------------------------------------------

def _build_direct(
    candidate: Candidate,
    crate_dir: Path,
    output_dir: Path,
    host_dir: Path,
    work_dir: Path,
    extra_args: list[str],
) -> BuildResult:
    """Direct cargo-build-sbf; log goes to host_dir (never mounted)."""
    log_parts: list[str] = []

    for attempt_offline in (True, False):
        cmd: list[str] = ["cargo-build-sbf", "--"]
        cmd += ["--locked", "--offline", "-v"] if attempt_offline else ["--locked", "-v"]
        cmd.extend(extra_args)

        try:
            proc = subprocess.run(
                cmd, cwd=str(crate_dir), capture_output=True, timeout=600, check=False
            )
        except subprocess.TimeoutExpired:
            return BuildResult(
                candidate=candidate, status="failed",
                reason="budget_exceeded", stderr_head="build_timeout",
            )
        except Exception as exc:  # noqa: BLE001
            return BuildResult(
                candidate=candidate, status="failed",
                reason="failed", stderr_head=str(exc)[:200],
            )

        stdout = proc.stdout.decode(errors="replace")
        stderr = proc.stderr.decode(errors="replace")
        log_parts.append(
            f"--- attempt offline={attempt_offline} rc={proc.returncode} ---\n{stdout}\n{stderr}"
        )

        # Check exit code
        if proc.returncode == 0:
            break
        if not attempt_offline:
            log = "\n".join(log_parts)
            (host_dir / "build.log").write_text(log, encoding="utf-8")
            return BuildResult(
                candidate=candidate, status="failed",
                reason="failed",
                stderr_head="\n".join(stderr.splitlines()[:20]),
            )

    full_log = "\n".join(log_parts)
    _write_host_file(host_dir / "build.log", full_log.encode())

    # Copy .so from target/deploy/ to output_dir first, then safe-read into host_dir
    deploy_dir = crate_dir / "target" / "deploy"
    if deploy_dir.is_dir():
        for so in sorted(deploy_dir.glob("*.so")):
            if not so.is_symlink() and so.stat().st_size > 0:
                dest = output_dir / "target" / "deploy"
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(so), str(dest / so.name))

    so_bytes, so_name = _safe_read_so(output_dir, host_dir)
    if so_bytes is None:
        deploy = output_dir / "deploy"
        try:
            real_dir = stat.S_ISDIR(deploy.lstat().st_mode)  # never list through a planted symlink
        except OSError:
            real_dir = False
        listing = sorted(p.name for p in deploy.iterdir())[:20] if real_dir else ["<no deploy dir>"]
        return BuildResult(
            candidate=candidate, status="failed",
            reason="artifact_missing",
            stderr_head="\n".join([f"deploy: {listing}", *stderr.splitlines()[-20:]]),
        )

    program_hash = _so_hash(so_bytes)
    overflow = _extract_overflow_checks(full_log)

    # Write supervisor metadata to host_dir only (O_NOFOLLOW)
    _write_host_file(host_dir / "overflow_checks.txt", overflow.encode())
    _write_host_file(host_dir / "program_hash.txt", program_hash.encode())
    _write_host_file(host_dir / "so_name.txt", so_name.encode())

    from soken_review.adapters.solana.units import count_nsloc_rust, is_in_scope_rust
    nsloc = sum(
        count_nsloc_rust(c)
        for p, c in candidate.files.items()
        if is_in_scope_rust(p) and isinstance(c, str)
    )

    return BuildResult(
        candidate=candidate, status="ok",
        nsloc=nsloc, work_dir=str(work_dir),
        stderr_head="\n".join(stderr.splitlines()[:20]) or None,
    )


# ---------------------------------------------------------------------------
# Docker sandbox build
# ---------------------------------------------------------------------------

def _safe_container_workdir(src_dir: Path, crate_dir: Path, root: str = "/work/src") -> str | None:
    """Compute <root>/<rel_crate> safely; returns None if unsafe.

    root is /work/src or the image WorkingDir (06 3.3.2); docker_argv checks it again.
    """
    try:
        rel = crate_dir.resolve().relative_to(src_dir.resolve())
    except ValueError:
        return None  # crate_dir not under src_dir

    rel_posix = rel.as_posix()
    if rel_posix == ".":
        return root
    # Validate every component
    for part in rel.parts:
        if not _CONTAINER_PATH_RE.match(part) or part.startswith("-") or part == "..":
            return None
    return f"{root}/{rel_posix}"


def sandbox_layout(work_dir: Path) -> dict[str, Any] | None:
    """Mount layout of a finished docker build, from the supervisor's host/build_meta.json (never a
    container file). The analysis step reuses it to run clippy in the same image and paths."""
    try:
        meta = json.loads((work_dir / "host" / "build_meta.json").read_text())
    except (OSError, ValueError):
        return None
    return meta if isinstance(meta, dict) else None


def _build_docker(
    candidate: Candidate,
    src_dir: Path,
    output_dir: Path,
    host_dir: Path,
    work_dir: Path,
    image: Any,
    meta: dict[str, Any],
) -> BuildResult:
    """Build inside Docker exactly where `solana-verify build` builds (06 3.3.2, U-S1).

    Mounts (09 4.2; host_dir is NEVER mounted):
      src/<mount>           -> W (image WorkingDir), read-only
      output/               -> W/<workspace>/target, read-write, empty: receives deploy/<lib>.so
      cargo-home/           -> CH (image CARGO_HOME), read-write: crates fetched by deps
    Commands (argv lists, no shell):
      deps   sbf-cargo fetch --locked (the platform-tools cargo, so the registry dir is the one the
             build reads), then cargo fetch --locked with RUSTUP_TOOLCHAIN (host cargo, for clippy)
      build  RUSTUP_TOOLCHAIN=<active> cargo build-sbf [--arch V] -- --config sparse
             --locked --offline -v [--manifest-path W/<lib dir>/Cargo.toml] [cargo args]
    The .so is copied Python-side by _safe_read_so after the container exits; the supervisor hashes it.
    """
    if not shutil.which("docker"):
        return _fail(candidate, "failed", "sandbox_unavailable")

    w, ch = image.working_dir, image.cargo_home
    mount, crate_rel, ws_rel = meta["mount"], meta["crate_rel"], meta["ws_rel"]
    src_root = src_dir / mount if mount else src_dir
    if not src_root.resolve().is_relative_to(src_dir.resolve()) or not src_root.is_dir():
        return _fail(candidate, "untrusted_args", "unsafe_mount_path")
    workdir = _safe_container_workdir(src_root, src_root / crate_rel if crate_rel else src_root, root=w)
    target = _safe_container_workdir(src_root, src_root / ws_rel if ws_rel else src_root, root=w)
    if workdir is None or target is None:
        return _fail(candidate, "untrusted_args", "unsafe_mount_path")
    target += "/target"
    # Mount point for the target dir inside the read-only source mount (the walker skips target/).
    (src_root / ws_rel / "target" if ws_rel else src_root / "target").mkdir(parents=True, exist_ok=True)

    line_major, line_minor = (int(x) for x in image.line.split("."))
    if (line_major, line_minor) < (1, 17):
        lock_args = ["--frozen", "--locked"]                   # F29, below 1.17
    else:
        lock_args = ["--config", 'registries.crates-io.protocol="sparse"', "--locked"]
    manifest_args = ["--manifest-path", f"{workdir}/Cargo.toml"] if meta.get("library_name") else []
    image_paths = (w, ch)

    # deps (06 3.3, 09 3.1): the only step with egress, into a per-candidate CARGO_HOME.
    cargo_home = sandbox_writable_dir(work_dir / "cargo-home")
    deps_mounts = [(src_root, w, True), (cargo_home, ch, False)]
    base_env = {"HOME": image.home, "CARGO_HOME": ch}
    host_env = {**base_env, "RUSTUP_TOOLCHAIN": image.active_toolchain}
    sparse = lock_args[:2] if lock_args[0] == "--config" else []
    fetch_args = ["fetch", "--locked", *sparse, *manifest_args]
    # deps (06 3.3, 09 3.1): sbf-cargo first (platform-tools cargo, fills the registry the build reads),
    # then host cargo with RUSTUP_TOOLCHAIN (fills the same registry for clippy's toolchain).
    # Both must succeed with --locked; any failure, including "needs to be updated but --locked was
    # passed" (Cargo.lock format mismatch), is deps_failed.  The source mount is read-only throughout:
    # no cargo is ever allowed to regenerate Cargo.lock (security: a repo cannot force re-resolution
    # by crafting a lock format mismatch, which would change the dependency set that gets built).
    for cmd, env in ((["sbf-cargo", *fetch_args], base_env), (["cargo", *fetch_args], host_env)):
        deps_failure = _fetch_deps(image.ref, cargo_home, deps_mounts, workdir, env, cmd, image_paths)
        if deps_failure is not None:
            return _fail(candidate, "deps_failed", deps_failure)

    cmd = ["cargo", "build-sbf"]
    if meta.get("arch"):
        cmd += ["--arch", meta["arch"]]
    # Do NOT pass --config build.rustc-wrapper=""/build.rustc-workspace-wrapper="": cargo-build-sbf
    # sets up its own build environment (RUSTFLAGS, target spec) and these overrides may interfere
    # with that setup, causing a different binary than solana-verify produces.  Security is maintained
    # by the trust scan blocking .cargo/config* files in the source tree (06 3.3.4, _BLOCKED_PATH_RES).
    # Use -vv to log each rustc invocation for U-S1 diagnosis (reference vs sandbox comparison).
    cmd += ["--", *lock_args, "--offline", "-vv", *manifest_args, *meta.get("cargo_args", [])]

    try:
        argv = docker_argv(
            step="build",
            image=image.ref,
            work_dir=work_dir,
            cache_dir=None,
            limits=_BUILD_LIMITS,
            env=host_env,
            command=cmd,
            runtime=os.environ.get("SOKEN_SANDBOX_RUNTIME"),
            workdir=workdir,
            mounts=[(src_root, w, True), (output_dir, target, False), (cargo_home, ch, False)],
            image_paths=image_paths,
        )
    except ValueError as exc:
        return _fail(candidate, "untrusted_args", str(exc)[:200])

    try:
        proc = subprocess.run(argv, capture_output=True, timeout=900, check=False)
    except subprocess.TimeoutExpired:
        return _fail(candidate, "budget_exceeded", "build_timeout_docker")
    except Exception as exc:  # noqa: BLE001
        return _fail(candidate, "failed", f"docker_error:{str(exc)[:200]}")

    stdout = proc.stdout.decode(errors="replace")
    stderr = proc.stderr.decode(errors="replace")
    # Write log to host_dir ONLY (never mounted, O_NOFOLLOW)
    _write_host_file(host_dir / "build.log", (stdout + "\n" + stderr).encode())

    if proc.returncode != 0:
        # The cause of a failed cargo build is at the end of the log; keep the last 20 lines.
        return _fail(candidate, "failed", "\n".join([f"exit {proc.returncode}", *stderr.splitlines()[-20:]]))

    lib = meta.get("library_name")
    so_bytes, so_name = _safe_read_so(output_dir, host_dir, want=f"{lib}.so" if lib else None)
    if so_bytes is None:
        deploy = output_dir / "deploy"
        try:
            real_dir = stat.S_ISDIR(deploy.lstat().st_mode)  # never list through a planted symlink
        except OSError:
            real_dir = False
        listing = sorted(p.name for p in deploy.iterdir())[:20] if real_dir else ["<no deploy dir>"]
        return _fail(candidate, "artifact_missing", "\n".join([f"deploy: {listing}", *stderr.splitlines()[-20:]]))

    program_hash = _so_hash(so_bytes)
    overflow = _extract_overflow_checks(stdout + "\n" + stderr)

    # Supervisor-only writes with O_NOFOLLOW
    _write_host_file(host_dir / "overflow_checks.txt", overflow.encode())
    _write_host_file(host_dir / "program_hash.txt", program_hash.encode())
    _write_host_file(host_dir / "so_name.txt", so_name.encode())

    from soken_review.adapters.solana.units import count_nsloc_rust, is_in_scope_rust
    nsloc = sum(
        count_nsloc_rust(c)
        for p, c in candidate.files.items()
        if is_in_scope_rust(p) and isinstance(c, str)
    )

    return BuildResult(
        candidate=candidate, status="ok",
        nsloc=nsloc, work_dir=str(work_dir),
        stderr_head="\n".join(stderr.splitlines()[:20]) or None,
    )


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def compute_so_hash(so_path: Path) -> str:
    """Public helper: compute the F5 hash of a .so file."""
    return _so_hash(so_path.read_bytes())
