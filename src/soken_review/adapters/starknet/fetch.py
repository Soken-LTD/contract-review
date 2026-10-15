"""Starknet chain_state and fetch (07 4, 8.1).

chain_state (supervisor, fixed hosts): pin a block, read the class hash at the address and the
class at that block, decode the Sierra and compiler versions. A class with no Sierra program is
Cairo 0 (job state insufficient_source, detail cairo0_class).

fetch (runsc-egress): the user repo at the commit, cloned by the git-fetch image on the Starknet
family network. Source by address is not on chain (07 8.1 step 4): no explorer source is read.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.evm.units import safe_store_path
from soken_review.adapters.starknet.felt import normalize_address
from soken_review.adapters.starknet.rpc import CONTRACT_NOT_FOUND, StarknetRpc, StarknetRpcError
from soken_review.adapters.starknet.sierra import class_hash as compute_class_hash
from soken_review.adapters.starknet.sierra import decode_versions, entry_points, is_cairo0
from soken_review.sandbox import egress as _egress
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

logger = logging.getLogger(__name__)

STARKNET_EGRESS_NETWORK = os.environ.get("SOKEN_STARKNET_NETWORK", _egress.network_name("starknet"))
_FETCH_LIMITS = StepLimits(cpus=1.0, memory="1g", pids=64, max_file=256 * 1024 * 1024)

_REPO_URL_RE = re.compile(r"^https://(?:github\.com|gitlab\.com|codeberg\.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?:\.git)?$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_KEEP_SUFFIXES = {".cairo", ".toml", ".lock", ".rs", ".md", ".txt"}   # sources, manifests, proc-macro crates, docs
# Files a manifest may name (`readme`, `license-file`); Scarb refuses a manifest whose file is missing.
_KEEP_NAMES = re.compile(r"^(README|LICEN[SC]E|COPYING|NOTICE)([._-][A-Za-z0-9._-]*)?$", re.IGNORECASE)
_SKIP_DIRS = {".git", "target", "node_modules", ".snfoundry_cache"}
_MAX_FILE = 512 * 1024
_MAX_FILES = 5000
_MAX_TOTAL = 128 * 1024 * 1024


class Cairo0Class(Exception):
    """07 8.1 step 3."""


# --------------------------------------------------------------------------------------------
# chain_state
# --------------------------------------------------------------------------------------------

async def read_chain_state(address: str, rpc: StarknetRpc | None = None) -> dict[str, Any]:
    """Pinned read of the deployed class (07 8.1). Returns a JSON-able dict; `class` holds the class.

    Raises ValueError for an invalid address (E_ADDRESS_INVALID), LookupError when no contract is
    deployed at the address.
    """
    addr = normalize_address(address)
    if addr is None:
        raise ValueError("E_ADDRESS_INVALID")
    probe = rpc or StarknetRpc()
    block = await probe.block_number()
    pinned = StarknetRpc(probe.url, block=block, check_licence=False)
    try:
        class_hash = await pinned.class_hash_at(addr)
    except StarknetRpcError as exc:
        if exc.code == CONTRACT_NOT_FOUND:
            raise LookupError("no contract at address") from exc
        raise
    contract_class = await pinned.get_class(class_hash)
    return verified_state(addr, block, pinned.url, probe.licence_warning, class_hash, contract_class)


def verified_state(addr: str, block: int, url: str, licence_warning: str | None, class_hash: str,
                   contract_class: dict[str, Any]) -> dict[str, Any]:
    """Check the served class body against the class hash at the address (keyless public RPC: the
    body is untrusted until its hash is recomputed here). A Sierra body that does not hash to the
    reported class hash, or does not parse, is dropped: `class` is None, class_verified False, and
    every fact and selector derived from it is absent (dep.match not_checkable, facts unknown).
    Cairo 0 bodies are not hashed here; they only end the job (07 8.1 step 3).
    """
    cairo0 = is_cairo0(contract_class)
    verified = False
    error = None
    if not cairo0:
        try:
            verified = compute_class_hash(contract_class) == int(class_hash, 16)
            error = None if verified else "class_body_hash_mismatch"
        except (ValueError, KeyError, TypeError) as exc:
            error = f"class_body_unparsable: {type(exc).__name__}"
    if not cairo0 and not verified:
        logger.warning("starknet chain_state: %s for %s", error, class_hash)
        contract_class = {}
    versions = decode_versions(contract_class["sierra_program"]) if verified else None
    eps = {k: len(v) for k, v in (contract_class.get("entry_points_by_type") or {}).items()}
    return {
        "chain": "starknet",
        "address": addr,
        "block": block,
        "read_mode": "rpc_pinned_block",
        "rpc_host": url.split("/")[2],
        "licence_warning": licence_warning,
        "class_verified": verified,
        "class_error": error,
        "class_hash": hex(int(class_hash, 16)),
        "cairo0": cairo0,
        "sierra_version": versions.sierra if versions else None,
        "cairo_version": versions.cairo if versions else None,
        "contract_class_version": contract_class.get("contract_class_version"),
        "entry_point_counts": eps,
        "selectors": {k: [hex(s) for s, _ in v] for k, v in entry_points(contract_class).items()} if verified else None,
        "class": contract_class if verified else None,
    }


# --------------------------------------------------------------------------------------------
# fetch: sandboxed git clone (09 5.2)
# --------------------------------------------------------------------------------------------

def safe_repo_url(url: str) -> str | None:
    u = (url or "").strip()
    return u if _REPO_URL_RE.match(u) else None


def _git_image() -> str | None:
    return locked_image("git-fetch") or os.environ.get("SOKEN_GIT_FETCH_IMAGE") or None


def _run_git(image: str, clone_dir: Path, command: list[str], timeout: int) -> tuple[bool, str]:
    argv = docker_argv(
        step="fetch", image=image, work_dir=clone_dir.parent, cache_dir=None, limits=_FETCH_LIMITS,
        env={}, command=command, family_network=STARKNET_EGRESS_NETWORK,
        mounts=[(clone_dir, "/work/clone", False)],
    )
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)
    return proc.returncode == 0, proc.stderr.decode(errors="replace")[-2000:]


def clone_repo(repo_url: str, commit: str, work_dir: Path) -> dict[str, str] | None:
    """Fetch exactly `commit` inside the git-fetch sandbox; None on any failure (fail closed)."""
    url = safe_repo_url(repo_url)
    if url is None or not _COMMIT_RE.match(commit or ""):
        logger.warning("starknet fetch: unsafe repo url or commit not a full sha")
        return None
    image = _git_image()
    if image is None:
        logger.warning("git-fetch image not configured; failing closed")
        return None
    clone_dir = sandbox_writable_dir(work_dir / "clone")
    flags = ["-c", "protocol.file.allow=never", "-c", "core.hooksPath=/dev/null", "-c", "safe.directory=/work/clone"]
    steps = [
        (["git", *flags, "init", "-q", "/work/clone"], 30),
        (["git", *flags, "-C", "/work/clone", "remote", "add", "origin", url], 10),
        (["git", *flags, "-C", "/work/clone", "fetch", "-q", "--depth=1", "--no-recurse-submodules", "origin", commit], 240),
        (["git", *flags, "-C", "/work/clone", "checkout", "-q", "FETCH_HEAD"], 60),
    ]
    for cmd, timeout in steps:
        ok, err = _run_git(image, clone_dir, cmd, timeout)
        if not ok:
            logger.warning("sandboxed git step %s failed: %s", cmd[len(flags) + 1:len(flags) + 3], err[-500:])
            return None
    return walk_source_files(clone_dir)


def walk_source_files(root: Path) -> dict[str, str]:
    """{store path: text} for Cairo build inputs; no symlink is followed, limits enforced."""
    files: dict[str, str] = {}
    total = 0
    base = root.resolve()
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            full = Path(dirpath) / name
            keep = full.suffix.lower() in _KEEP_SUFFIXES or _KEEP_NAMES.match(name)
            if not keep or full.is_symlink() or not full.is_file():
                continue
            size = full.lstat().st_size
            if size > _MAX_FILE:
                continue
            total += size
            if total > _MAX_TOTAL or len(files) >= _MAX_FILES:
                logger.warning("starknet fetch: size limits reached at %s", root)
                return files
            rel = safe_store_path(full.relative_to(base).as_posix())
            if rel is None:
                continue
            try:
                files[rel] = full.read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
    return files


def candidate_sha256(files: dict[str, str]) -> str:
    parts = [f"{p}:{hashlib.sha256(files[p].encode()).hexdigest()}" for p in sorted(files)]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def make_candidate(
    files: dict[str, str],
    *,
    provider: str,
    repo_url: str | None,
    commit: str | None,
    subdir: str | None,
    cairo_version: str | None,
) -> Candidate:
    """Candidate for the build step. The compiler version comes from the class (07 8.1), never the repo."""
    package_dir = (subdir or "").strip("/")
    if package_dir and safe_store_path(package_dir) is None:
        package_dir = ""
    return Candidate(
        provider=provider,  # type: ignore[arg-type]
        files=files,
        sha256=candidate_sha256(files),
        language="cairo",
        compiler=Compiler(version=cairo_version, version_pinned_by="sierra_program") if cairo_version else None,
        settings={"package_dir": package_dir, "profile": "release"},
        std_json_input=None,
        entry_contract=None,
        source_url=repo_url,
        fetched_at=datetime.now(UTC).isoformat(),
    )


def manifest_dirs(files: dict[str, str]) -> list[str]:
    """Directories (store paths) that hold a Scarb.toml."""
    return sorted(str(PurePosixPath(p).parent) if "/" in p else "" for p in files if PurePosixPath(p).name == "Scarb.toml")
