"""Solana fetch step: source discovery + candidates assembly (06 section 3.2).

fetch_source(job, cs) -> list[SourceBundle]

Discovery pipeline (06 3.2):
  1. Input detection: program_id (base58 32-byte) from job.address / job.repo_url
  2. security.txt (on-chain): source_code, source_revision, source_release fields
  3. OtterSec verify API: verify.osec.io/status-all/<programId>
     - Each item has signer + seeds [b"otter_verify", signer, program_id]
     - Owner-linked = signer == upgrade_authority (from chain state)
  4. Repo clone (git): shallow clone, resolve to commit, walk source files
  5. Candidate assembly: tier A (linked PDA) / tier B (other PDA) / tier C (security.txt only)

Path safety: every path from untrusted sources goes through safe_store_path().
Network is disabled in build/analyze containers; fetch runs in host or egress sandbox.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import UTC
from pathlib import Path, PurePosixPath
from typing import Any

from soken_review.sandbox.profile import sandbox_writable_dir

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_SBX_ROOT = _REPO_ROOT / ".sbx"

# Family egress network (09 4.3): internal, the solana smokescreen is the only way out
_SOLANA_EGRESS_NETWORK = os.environ.get("SOKEN_SOLANA_FETCH_NETWORK", "soken-egress-solana")

# OtterSec verify endpoint (06 §3.2.2, F12-F17)
_OSEC_VERIFY_URL = "https://verify.osec.io/status-all/{program_id}"
_OSEC_TIMEOUT = 10  # seconds

# security.txt program (06 §3.2.1, F7-F11)
_SECURITY_TXT_PROGRAM = "SECURITY_TXT_PROGRAM_ID"  # resolved at runtime via PDA lookup
_SECURITY_TXT_MAGIC = b"=======BEGIN SECURITY.TXT V1======="

# Source content limits
_MAX_FILE_SIZE = 512 * 1024  # 512 KB per file
_MAX_FILES = 2000
_MAX_REPO_SIZE = 128 * 1024 * 1024  # 128 MB total

# Allowed repo schemes
_ALLOWED_REPO_SCHEMES = frozenset({"https"})
_REPO_URL_RE = re.compile(
    r'^https://(?:github|gitlab)\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?$'
)
# Allowed commit hash
_COMMIT_RE = re.compile(r'^[0-9a-f]{40}$', re.IGNORECASE)
# Allowed tag/version ref (for display only, not used in git checkout)
_TAG_RE = re.compile(r'^[A-Za-z0-9._/-]{1,80}$')



def _resolve_subdir(root: Path, subdir: str | None) -> Path | None:
    """The clone root, or `root/subdir` when subdir is a safe relative path to a real directory
    inside the clone (no `..`, absolute paths, backslashes or symlinked components). None when an
    unsafe or missing subdir was requested: the fetch then fails instead of walking another tree."""
    if not subdir:
        return root
    from .units import safe_store_path

    rel = safe_store_path(subdir.strip("/"))
    if rel is None:
        logger.warning("fetch: unsafe subdir %r refused", subdir[:80])
        return None
    base = root.resolve()
    cur = root
    for part in rel.split("/"):
        cur = cur / part
        if cur.is_symlink():
            logger.warning("fetch: subdir %r goes through a symlink; refused", subdir[:80])
            return None
    if not cur.is_dir() or not cur.resolve().is_relative_to(base):
        logger.warning("fetch: subdir %r not found in the clone", subdir[:80])
        return None
    return cur

def _sha256_candidate(files: dict[str, str]) -> str:
    """Canonical SHA-256 over sorted (path, content_sha256) pairs."""
    parts = []
    for path in sorted(files):
        content = files[path]
        if isinstance(content, str):
            content_bytes = content.encode()
        else:
            content_bytes = content
        parts.append(f"{path}:{hashlib.sha256(content_bytes).hexdigest()}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


# ---------------------------------------------------------------------------
# OtterSec verify API (06 §3.2.2, F12-F17)
# ---------------------------------------------------------------------------

def _fetch_osec_verify(program_id: str) -> list[dict[str, Any]]:
    """Fetch verify PDA list from OtterSec API. Returns [] on any error."""
    try:
        import urllib.request
        url = _OSEC_VERIFY_URL.format(program_id=program_id)
        req = urllib.request.Request(url, headers={"User-Agent": "soken-review/1"})
        with urllib.request.urlopen(req, timeout=_OSEC_TIMEOUT) as resp:
            if resp.status != 200:
                logger.debug("osec verify %s: HTTP %s", program_id, resp.status)
                return []
            data = json.loads(resp.read().decode())
    except Exception as exc:  # noqa: BLE001
        logger.debug("osec verify fetch failed for %s: %s", program_id, exc)
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "status" in data:
        # API may return {"status": [...]} or top-level list
        inner = data.get("status") or data.get("results") or []
        return inner if isinstance(inner, list) else []
    return []


def _is_owner_linked(verify_item: dict[str, Any], upgrade_authority: str | None) -> bool:
    """Return True if the verify PDA signer == upgrade authority (owner-linked, F16)."""
    if upgrade_authority is None:
        return False
    signer = verify_item.get("signer") or verify_item.get("verifier")
    if not signer:
        return False
    return str(signer).strip() == str(upgrade_authority).strip()


# ---------------------------------------------------------------------------
# security.txt parsing (06 §3.2.1, F7-F11)
# ---------------------------------------------------------------------------

def _parse_security_txt(account_data: bytes) -> dict[str, str]:
    """Parse security.txt fields from on-chain account data."""
    fields: dict[str, str] = {}
    try:
        start = account_data.find(_SECURITY_TXT_MAGIC)
        if start == -1:
            return {}
        end_marker = b"=======END SECURITY.TXT V1======="
        end = account_data.find(end_marker, start)
        if end == -1:
            return {}
        content = account_data[start + len(_SECURITY_TXT_MAGIC):end].decode("utf-8", errors="replace")
        for line in content.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                fields[key.strip().lower()] = val.strip()
    except Exception as exc:  # noqa: BLE001
        logger.debug("security.txt parse error: %s", exc)
    return fields


# ---------------------------------------------------------------------------
# Git repo cloning (06 §3.2.3)
# ---------------------------------------------------------------------------

def _safe_repo_url(url: str) -> str | None:
    """Validate repo URL; returns the URL or None if unsafe."""
    if not _REPO_URL_RE.match(url.strip()):
        return None
    return url.strip()


def _clone_repo(repo_url: str, commit: str | None, work_dir: Path,
                subdir: str | None = None) -> dict[str, str] | None:
    """Materialize a repo commit in the sandbox and return source files as {path: content}.

    Production (SOKEN_SOLANA_DIRECT not set): soken-fetch (09 5.2) in the git-fetch image on the
    solana egress network; any failure = fetch failed (None), never a direct clone.
    Dev (SOKEN_SOLANA_DIRECT=1): direct git clone on the host.

    With a subdir the result's `.workspace` is the walk of the clone root: the subdir is the
    reviewed scope, but a Cargo workspace needs the root manifest, Cargo.lock, every member manifest
    and path dependencies to build.
    """
    src_url = _safe_repo_url(repo_url)
    if src_url is None:
        logger.warning("unsafe repo url rejected: %s", repo_url)
        return None

    if os.environ.get("SOKEN_SOLANA_DIRECT") == "1":
        clone_dir = work_dir / "clone"
        sandbox_writable_dir(clone_dir)
        files = _clone_direct(src_url, commit, clone_dir, subdir=subdir)
    else:
        files = _clone_in_sandbox(src_url, commit, work_dir, subdir=subdir)
        if files is None:
            logger.warning("sandboxed fetch failed for %s; failing closed (no direct fallback)", src_url)
    return files


def _walk_scope(root: Path, subdir: str | None) -> dict[str, str] | None:
    """Walk of the subdir; with a subdir, the walk of the clone root rides along as `.workspace`."""
    src_root = _resolve_subdir(root, subdir)
    if src_root is None:
        return None
    files = _walk_source_files(src_root)
    if src_root != root and isinstance(files, SourceFiles):
        files.workspace = _walk_source_files(root)
    return files


def _clone_in_sandbox(src_url: str, commit: str | None, work_dir: Path,
                      subdir: str | None = None) -> dict[str, str] | None:
    """soken-fetch of the pinned commit (or the remote HEAD when none is known) into work_dir/src.

    No checkout, no hooks, depth 1 with a 5 MiB blob filter, submodules by our own policy
    (09 5.2). Returns the file dict, or None on any refusal (exit code logged, 09 3.6)."""
    from soken_review.sandbox.repo_fetch import materialize_repo

    pinned = commit if commit and _COMMIT_RE.match(commit) else None
    res = materialize_repo(src_url, work_dir, "solana", commit=pinned, ref=None if pinned else "HEAD",
                           image=os.environ.get("SOKEN_GIT_FETCH_IMAGE") or None)
    if not res.ok:
        logger.warning("soken-fetch exit %d (%s): %s", res.exit_code, res.error_code,
                       str((res.manifest or {}).get("error"))[:300])
        return None
    return _walk_scope(Path(res.src_dir), subdir)


def _clone_direct(src_url: str, commit: str | None, clone_dir: Path,
                  subdir: str | None = None) -> dict[str, str] | None:
    """Direct git clone on host (dev/fallback only; NOT for production)."""
    try:
        if commit and _COMMIT_RE.match(commit):
            subprocess.run(
                [
                    "git", "clone",
                    "-c", "protocol.file.allow=never",
                    "-c", "core.hooksPath=/dev/null",
                    "--no-recurse-submodules",
                    "--quiet", "--depth=100",
                    src_url, str(clone_dir),
                ],
                capture_output=True, timeout=120, check=True,
            )
            subprocess.run(
                [
                    "git", "-C", str(clone_dir),
                    "-c", "core.hooksPath=/dev/null",
                    "checkout", "--quiet", commit,
                ],
                capture_output=True, timeout=30, check=True,
            )
        else:
            subprocess.run(
                [
                    "git", "clone",
                    "-c", "protocol.file.allow=never",
                    "-c", "core.hooksPath=/dev/null",
                    "--no-recurse-submodules",
                    "--quiet", "--depth=1",
                    src_url, str(clone_dir),
                ],
                capture_output=True, timeout=120, check=True,
            )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.warning("git clone failed for %s: %s", src_url, exc)
        return None

    return _walk_scope(clone_dir, subdir)


class SourceFiles(dict):
    """{path: content} of the read source files, plus `unread_paths`: files the walker did not read
    (binary extension, hidden or heavy dir) that the trust scan must still see (06 3.3.4)."""

    unread_paths: list[str]
    workspace: dict[str, str] | None   # walk of the clone root when a subdir was fetched

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.unread_paths = []
        self.workspace = None


_TRUST_ARTIFACT_EXTS = frozenset({".o", ".a", ".so", ".elf"})
_CARGO_CONFIG_NAME_RE = re.compile(r'^config(?:\.toml)?$', re.IGNORECASE)


def _trust_relevant_unread(path: Path, rel_parts: tuple[str, ...]) -> bool:
    """A file the walker skips but the trust scan rules on: committed objects or ELF anywhere,
    `.cargo/config*` (06 3.3.4). Skipping it silently would make the scan fail open."""
    if path.suffix.lower() in _TRUST_ARTIFACT_EXTS:
        return True
    if len(rel_parts) >= 2 and rel_parts[-2] == ".cargo" and _CARGO_CONFIG_NAME_RE.match(rel_parts[-1]):
        return True
    try:
        with path.open("rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return True  # unreadable: fail closed


def _walk_source_files(root: Path) -> dict[str, str]:
    """Walk directory and return {relative_path: content} for source files.

    Enforces _MAX_FILES, _MAX_FILE_SIZE, _MAX_REPO_SIZE limits.
    Skips .git/, target/, node_modules/, .cargo/, hidden dirs. Skipped files the trust scan rules
    on (objects, ELF, .cargo/config*) are listed in the result's `unread_paths`.
    """
    from soken_review.adapters.solana.units import safe_store_path

    files = SourceFiles()
    total_bytes = 0
    root_resolved = root.resolve()

    skip_dirs = {".git", "target", "node_modules", ".cargo", ".idea"}

    for path in sorted(root_resolved.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel_parts = path.relative_to(root_resolved).parts
        if rel_parts[0] == ".git":
            continue
        # Skip hidden dirs, known heavy dirs and non-source extensions; record what the trust scan needs
        ext = path.suffix.lower()
        if any(p.startswith(".") or p in skip_dirs for p in rel_parts) \
                or ext not in {".rs", ".toml", ".lock", ".json", ".yaml", ".yml", ".md", ".txt"}:
            if _trust_relevant_unread(path, rel_parts):
                files.unread_paths.append("/".join(rel_parts))
            continue
        if len(files) >= _MAX_FILES:
            logger.warning("file limit reached at %s", root)
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_SIZE:
            continue
        total_bytes += size
        if total_bytes > _MAX_REPO_SIZE:
            logger.warning("repo size limit reached at %s", root)
            break
        rel_path = str(path.relative_to(root_resolved))
        safe = safe_store_path(rel_path)
        if safe is None:
            continue
        try:
            files[safe] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

    return files


# ---------------------------------------------------------------------------
# Candidate assembly
# ---------------------------------------------------------------------------

def _make_candidate(
    files: dict[str, str],
    provider: str,
    repo_url: str | None = None,
    commit: str | None = None,
    framework: str | None = None,
) -> Candidate:  # noqa: F821
    """Build a Candidate dataclass from source files."""
    from soken_review.adapters.base import Candidate, Compiler
    from soken_review.adapters.solana.build import _detect_version_from_lock, _detect_version_from_workspace
    from soken_review.adapters.solana.detect import detect_framework_from_files

    if framework is None:
        framework = detect_framework_from_files(files) or "native"

    # Try to get Solana version from Cargo.lock
    version_str = "unknown"
    try:
        lock_content = next(
            (v for k, v in files.items() if PurePosixPath(k).name == "Cargo.lock"),
            None,
        )
        if lock_content:
            version_str = _detect_version_from_lock(lock_content) or "unknown"
        if version_str == "unknown":
            version_str = _detect_version_from_workspace(files) or "unknown"
    except Exception:  # noqa: BLE001,S110
        pass

    compiler = Compiler(version=version_str, version_pinned_by="lock" if version_str != "unknown" else "user")

    return Candidate(
        provider=provider,  # type: ignore[arg-type]
        files=files,
        sha256=_sha256_candidate(files),
        language="rust",
        compiler=compiler,
        settings={"framework": framework, "unread_paths": list(getattr(files, "unread_paths", []))},
        std_json_input=None,
        entry_contract=None,
        source_url=repo_url,
        fetched_at=_utc_now(),
    )


def _utc_now() -> str:
    from datetime import datetime
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# resolve_provenance (06 §2.4)
# ---------------------------------------------------------------------------

def resolve_provenance(
    program_id: str,
    program_hash: str | None,
    verify_items: list[dict[str, Any]],
    upgrade_authority: str | None,
    untrusted_inputs: bool = False,
    deployed_hash: str | None = None,
    version_line_passed: bool = False,
    build_declared: bool = False,
    commit: str | None = None,
) -> dict[str, Any]:
    """Provenance of one built candidate (06 2.4, 2.5).

    program_hash: F5 hash the supervisor computed over the built .so (host/program_hash.txt).
    deployed_hash: F5 hash the supervisor computed over the deployed program (onchain.py), never a
      registry value: a verified flag or an OtterSec hash never yields exact (F3).
    version_line_passed: the U-S1 row of the build image's line passed (images.line_passed).

    Tier A (`exact`, MATCH_REBUILD) only when: trusted inputs, both hashes ours and equal, line passed.
    Unproven line, whatever the hashes: B, SOURCE_NOT_REBUILT why unsupported_toolchain (never A or C).
    Untrusted inputs: B, BUILD_INPUT_UNTRUSTED whatever the hashes say (never A or C).
    Differing hashes: B third_party_verified_only when an owner-linked OtterSec entry reports
    is_verified for the same commit; C mismatch when the build was declared (verify args); else B
    REBUILD_DIFFERS_UNDECLARED.
    """
    base: dict[str, Any] = {"program_id": program_id, "hash": program_hash, "deployed_hash": deployed_hash,
                            "hash_equal": bool(program_hash and deployed_hash and program_hash == deployed_hash),
                            "version_line_passed": version_line_passed}
    if untrusted_inputs:
        # 06 2.4 / 3.3.4: a build from untrusted inputs proves nothing about the deployment.
        return {**base, "tier": "B", "match": "not_checkable", "reason": "BUILD_INPUT_UNTRUSTED"}
    if not program_hash:
        return {**base, "tier": "D", "match": None, "reason": "NO_CHECKABLE_SOURCE"}
    if not deployed_hash:
        return {**base, "tier": "B", "match": "not_checkable", "reason": "DEPLOYMENT_NOT_HASHABLE"}
    if not version_line_passed:
        # An unproven line (U-S1 row not passed) never yields A or C, equal hashes or not.
        return {**base, "tier": "B", "match": "not_checkable", "reason": "SOURCE_NOT_REBUILT",
                "why": "unsupported_toolchain"}
    if base["hash_equal"]:
        return {**base, "tier": "A", "match": "exact", "reason": "MATCH_REBUILD"}
    linked_verified = [
        i for i in verify_items
        if _is_owner_linked(i, upgrade_authority) and i.get("is_verified") is True
        and (commit is None or str(i.get("commit") or "") == commit)
    ]
    if linked_verified:
        return {**base, "tier": "B", "match": "third_party_verified_only", "reason": "SOURCE_NOT_REBUILT",
                "why": "rebuild_differs", "signer": linked_verified[0].get("signer")}
    if build_declared:
        return {**base, "tier": "C", "match": "mismatch", "reason": "MISMATCH_DECLARED_BUILD"}
    return {**base, "tier": "B", "match": "not_checkable", "reason": "REBUILD_DIFFERS_UNDECLARED"}


# ---------------------------------------------------------------------------
# Public API: fetch_source
# ---------------------------------------------------------------------------

def fetch_source(job: Any, cs: dict[str, Any]) -> list[Any]:
    """Fetch source bundles for a Solana program (06 §3.1, 3.2).

    job may be a dict (from supervisor) or an object with attributes.
    cs (chain state) is the raw chain_state dict and may contain upgrade_authority.
    """
    from soken_review.adapters.base import SourceBundle, Target
    from soken_review.adapters.solana.detect import detect_framework_from_files
    from soken_review.adapters.solana.units import is_solana_address, make_unit_label

    # Normalise: accept both plain dicts (supervisor path) and objects with attributes
    # (direct adapter calls). Same pattern as the Aptos and Sui adapters.
    j: dict[str, Any] = job if isinstance(job, dict) else vars(job)

    program_id: str | None = None
    repo_url: str | None = None
    commit: str | None = None
    subdir: str | None = None

    raw_addr = j.get("address") or ""
    if raw_addr:
        raw_addr = str(raw_addr).strip()
        if is_solana_address(raw_addr):
            program_id = raw_addr
    raw_repo = j.get("repo_url") or ""
    if raw_repo:
        repo_url = str(raw_repo).strip()
    raw_commit = j.get("commit") or ""
    if raw_commit:
        raw_commit = str(raw_commit).strip()
        if _COMMIT_RE.match(raw_commit):
            commit = raw_commit
    raw_subdir = j.get("subdir") or j.get("package_dir") or ""
    if raw_subdir:
        subdir = str(raw_subdir).strip("/") or None

    if program_id is None and repo_url is None:
        logger.warning("fetch_source: no program_id and no repo_url")
        return []

    upgrade_authority: str | None = None
    if cs:
        ua_val = cs.get("upgrade_authority")
        if ua_val and hasattr(ua_val, "value"):
            upgrade_authority = str(ua_val.value) if ua_val.value else None
        elif isinstance(ua_val, str):
            upgrade_authority = ua_val  # noqa: F841

    # Fetch OtterSec verify items
    verify_items: list[dict[str, Any]] = []
    if program_id:
        verify_items = _fetch_osec_verify(program_id)
        logger.info("osec verify: %d items for %s", len(verify_items), program_id)

    # Determine repo_url from verify items if not provided
    if repo_url is None and verify_items:
        for item in verify_items:
            candidate_url = item.get("repo_url") or item.get("repository")
            if candidate_url and _safe_repo_url(str(candidate_url)):
                repo_url = str(candidate_url)
                # Commit from verify item
                cmt = item.get("commit") or item.get("source_revision")
                if cmt and _COMMIT_RE.match(str(cmt)):
                    commit = str(cmt)
                break

    # security.txt embedded in the deployed program (06 3.2.1): source_code names the repository,
    # source_revision the commit. Read by the supervisor at chain_state (onchain.security_txt_fields);
    # the URL goes through the same allowlist as a user repo URL.
    if repo_url is None and cs:
        sec = cs.get("security_txt")
        sec = sec.value if hasattr(sec, "value") else sec
        if isinstance(sec, dict):
            source_code = str(sec.get("source_code") or "").strip().removesuffix("/")
            if source_code and _safe_repo_url(source_code):
                repo_url = source_code
                rev = str(sec.get("source_revision") or "").strip()
                if _COMMIT_RE.match(rev):
                    commit = rev
                logger.info("fetch_source: repo from security.txt for %s", program_id)

    if repo_url is None:
        logger.info("fetch_source: no repo_url available for %s", program_id)
        return []

    # Clone repo
    _SBX_ROOT.mkdir(exist_ok=True)
    # The sandboxed clone is written by the sandbox user (uid 10001). A root worker (the stand) removes it;
    # a non-root worker (CI, a developer host) cannot, and the cleanup PermissionError used to fail the whole
    # fetch step after the clone had succeeded (client-path e2e 2026-10-27, E_INTERNAL unexpected_exception).
    # The leftover directory is reported and left to the retention sweep. TemporaryDirectory is not used:
    # even with ignore_cleanup_errors its onexc handler chmods the parent and raises again
    # (`Operation not permitted: .../hooks`, run 40507334257).
    work_dir = Path(tempfile.mkdtemp(dir=_SBX_ROOT))
    try:
        files = _clone_repo(repo_url, commit, work_dir, subdir=subdir)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        if work_dir.exists():
            logger.warning("fetch_source: clone dir %s left behind (written by the sandbox user, worker is not root)",
                           work_dir)
    workspace = getattr(files, "workspace", None)

    if not files:
        logger.warning("fetch_source: empty file set from repo %s", repo_url)
        return []

    framework = detect_framework_from_files(files) or "native"
    candidate = _make_candidate(files, "repo", repo_url=repo_url, commit=commit, framework=framework)
    if subdir and workspace:
        attach_build_workspace(candidate, subdir, workspace)

    # Unit label
    unit_label = make_unit_label(
        name=_name_from_url(repo_url),
        program_id=program_id or "",
        store_path=None,
    ) if program_id else _name_from_url(repo_url)

    target = Target(
        address=None,
        display_address=program_id,
        unit_label=unit_label,
        repo_url=repo_url,
        commit=commit,
        files=list(files.keys()),
        discovered_by="input",
    )

    return [SourceBundle(target=target, candidates=[candidate])]


def attach_build_workspace(candidate: Any, subdir: str, workspace: dict[str, str]) -> None:
    """Keep the repo tree around a subdir candidate for the build (runtime only, never pinned).

    `candidate.files` stays the subdir (the reviewed scope, the pin). The build needs the Cargo
    workspace the subdir belongs to: `settings.subdir` places the scope in it and
    `settings.library_name` is the subdir crate's `[lib] name` (solana-verify --library-name), so
    the build is `--manifest-path <subdir>/Cargo.toml` inside the workspace. The workspace's own
    unread paths (committed objects, .cargo/config*) join the trust scan.
    """
    from soken_review.adapters.solana.build import _lib_name, _toml

    manifest = _toml(candidate.files.get("Cargo.toml") or "")
    candidate.settings["subdir"] = subdir
    lib = _lib_name(manifest) if manifest else None
    if lib:
        candidate.settings["library_name"] = lib
    candidate.settings["workspace_unread_paths"] = list(getattr(workspace, "unread_paths", []))
    candidate._full_tree = dict(workspace)
    if candidate.compiler is not None and candidate.compiler.version == "unknown":
        # the subdir has no Cargo.lock of its own: the workspace lock pins the Solana version
        from soken_review.adapters.base import Compiler
        from soken_review.adapters.solana.build import _detect_version_from_lock

        lock = workspace.get("Cargo.lock")
        version = _detect_version_from_lock(lock) if isinstance(lock, str) else None
        if version:
            candidate.compiler = Compiler(version=version, version_pinned_by="lock")


def _name_from_url(repo_url: str) -> str:
    """Extract a safe name from repo URL, e.g. github.com/foo/bar -> bar."""
    parts = repo_url.rstrip("/").split("/")
    name = parts[-1].removesuffix(".git") if parts else "unknown"
    # Keep only safe chars
    name = re.sub(r"[^A-Za-z0-9_-]", "_", name)[:40]
    return name or "unknown"
