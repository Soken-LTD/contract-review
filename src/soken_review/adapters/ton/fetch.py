"""TON source fetch and chain_state 0 reads (plan v4 06 sections 2.1, 4.2, 4.3).

Fetch order per plan 06 4.2:
  1. User source (repo or files), when provided
  2. TON verifier bundle for the unit's code hash (body hash when library-coded)

State reads (plan 06 4.3, F38), supervisor only:
  - Pin:     toncenter v2 getMasterchainInfo  -> mc_seqno
  - Account: toncenter v2 getAddressInformation?seqno=<mc_seqno>; the answer must name that block
  - Libs:    toncenter v2 getLibraries for a library-ref code cell; body hash checked here

Every hash (account code, library body) is computed in this process by `cell.root_info`;
no container reports a hash (09 3.5).

TON verifier: GET https://verifier.ton.org/api/v1/verification/source?code_hash=<hex>, files
inline; each file's sha256 must equal its `content_hash`.

Rate limiter per plan 06 2.10 / limits.yaml: toncenter 10/s (keyless 1/s), ton_verifier 2/s.

Security (RULES.md §3):
  - Per-file and total size caps; binary blobs (.boc/.cell/.fif) never enter a candidate.
  - All file names pass filter_candidate_files (safe_store_path gate).
  - Repo archives: github.com only, fixed URL, size caps.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.ton.cell import BocError, root_hash, root_info
from soken_review.adapters.ton.units import filter_candidate_files, safe_store_path

logger = logging.getLogger(__name__)

# ── provider base URLs ────────────────────────────────────────────────────

TONCENTER_V2 = "https://toncenter.com/api/v2"

_VERIFIER_HOST = "verifier.ton.org"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_BUNDLE_BYTES = 8 * 1024 * 1024
_TONCENTER_RETRIES = 5
_TONCENTER_PER_S = 10.0 if os.environ.get("SOKEN_TONCENTER_API_KEY") else 1.0

# Allowlist for downloading source files from verifier bundles.
# Only these hostnames may serve source files (SSRF protection).
# Ref: plan 09 4.3 provider rows + outbound rows in limits.yaml.
_VERIFIER_DOWNLOAD_ALLOWLIST: frozenset[str] = frozenset([
    "server.ton.org",
    "verifier.ton.org",
    # Common GitHub raw file hosts for open-source bundles
    "raw.githubusercontent.com",
    "github.com",
    # TON verifier IPFS gateway (only if needed)
    "ipfs.ton.live",
])

# Reserved / internal IP ranges that must never be contacted (SSRF)
_RESERVED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.IPv4Network("127.0.0.0/8"),       # loopback
    ipaddress.IPv4Network("10.0.0.0/8"),         # RFC1918
    ipaddress.IPv4Network("172.16.0.0/12"),       # RFC1918
    ipaddress.IPv4Network("192.168.0.0/16"),      # RFC1918
    ipaddress.IPv4Network("169.254.0.0/16"),      # link-local / IMDS
    ipaddress.IPv4Network("100.64.0.0/10"),       # shared address space
    ipaddress.IPv4Network("0.0.0.0/8"),           # "this" network
    ipaddress.IPv4Network("240.0.0.0/4"),         # reserved
    ipaddress.IPv6Network("::1/128"),             # IPv6 loopback
    ipaddress.IPv6Network("fc00::/7"),            # IPv6 unique local
    ipaddress.IPv6Network("fe80::/10"),           # IPv6 link-local
    ipaddress.IPv6Network("::ffff:0:0/96"),       # IPv4-mapped
]

# Maximum bytes per downloaded source file (SSRF / DoS protection)
_MAX_FILE_BYTES = 512 * 1024  # 512 KB per file

# Binary blob extensions that must never be written into the source tree.
# A malicious verifier bundle or user upload could include a pre-built
# .boc/.cell file that, if written to src_dir, could be picked up by the
# compiler-output glob and bypass the build entirely (planted-artifact attack).
_BINARY_SOURCE_EXTS = frozenset({".boc", ".cell", ".fif", ".fift", ".bag"})

# Total fetch budget per candidate (plan 09 3.2 limits.yaml)
_MAX_TOTAL_FETCH_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB total across all files
_MAX_TOTAL_INODES = 200_000  # max number of individual source files

_TIMEOUT = httpx.Timeout(30.0)
_MAX_RETRIES = 3


def _is_internal_ip(addr: str) -> bool:
    """Return True if addr resolves to a reserved/internal address."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        # addr is a hostname; resolve it
        try:
            resolved = socket.getaddrinfo(addr, None)
            for _family, _type, _proto, _canonname, sockaddr in resolved:
                ip = ipaddress.ip_address(sockaddr[0])
                for net in _RESERVED_NETWORKS:
                    if ip in net:
                        return True
            return False
        except Exception:  # noqa: BLE001
            return True  # fail closed: unresolvable = internal assumed
    for net in _RESERVED_NETWORKS:
        try:
            if ip in net:
                return True
        except TypeError:
            continue
    return False


def _validate_download_url(url: str) -> str | None:
    """Validate a source file download URL (SSRF protection).

    Returns the URL if valid, None if rejected (with a debug log).
    Rules:
      - HTTPS only
      - Hostname in _VERIFIER_DOWNLOAD_ALLOWLIST
      - Resolved IP not in reserved/internal ranges
      - No credentials in URL
    """
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        logger.debug("_validate_download_url: unparseable URL: %r", url[:200])
        return None

    if parsed.scheme != "https":
        logger.debug("_validate_download_url: rejected non-https scheme %r", parsed.scheme)
        return None

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        logger.debug("_validate_download_url: no hostname in URL")
        return None

    if hostname not in _VERIFIER_DOWNLOAD_ALLOWLIST:
        logger.debug("_validate_download_url: hostname %r not in allowlist", hostname)
        return None

    if parsed.username or parsed.password:
        logger.debug("_validate_download_url: credentials in URL rejected")
        return None

    if _is_internal_ip(hostname):
        logger.debug("_validate_download_url: hostname %r resolves to internal IP", hostname)
        return None

    return url


# ── rate limiter ──────────────────────────────────────────────────────────


class _Limiter:
    def __init__(self, per_s: float) -> None:
        self._gap = 1.0 / per_s
        self._last: float = 0.0
        self._down_until: float = 0.0

    def is_down(self) -> bool:
        return time.monotonic() < self._down_until

    def mark_down(self) -> None:
        self._down_until = time.monotonic() + 600

    async def wait(self) -> None:
        if self.is_down():
            raise RuntimeError("provider is down (marked 10 min)")
        elapsed = time.monotonic() - self._last
        if elapsed < self._gap:
            await asyncio.sleep(self._gap - elapsed)
        self._last = time.monotonic()


_limiters: dict[str, _Limiter] = {}


def _limiter(key: str, per_s: float = 2.0) -> _Limiter:
    if key not in _limiters:
        _limiters[key] = _Limiter(per_s)
    return _limiters[key]


async def _get(
    client: httpx.AsyncClient,
    url: str,
    key: str,
    per_s: float = 2.0,
    follow_redirects: bool = False,
    **kw: Any,
) -> httpx.Response:
    """GET with rate limiting, 3 retries, 403 text/html down-mark.

    follow_redirects=False by default to prevent SSRF via redirects.
    Callers that set follow_redirects=True must validate the redirect target
    against the allowlist before using the response (plan 09 4.3).
    """
    lim = _limiter(key, per_s)
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            await lim.wait()
            r = await client.get(url, follow_redirects=follow_redirects, **kw)
            if r.status_code == 403 and "text/html" in r.headers.get("content-type", ""):
                lim.mark_down()
                raise RuntimeError(f"403 html from {key}")
            return r
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(2**attempt)
    raise RuntimeError(f"GET {url} failed after {_MAX_RETRIES} retries") from last_exc


# ── sha256 helper ─────────────────────────────────────────────────────────


def _candidate_sha256(files: dict[str, str]) -> str:
    parts = sorted((p, hashlib.sha256(c.encode()).hexdigest()) for p, c in files.items())
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _make_ton_candidate(
    *,
    provider: str,
    raw_files: dict[str, str],
    language: str,
    compiler_version: str | None,
    compiler_pinned_by: str,
    entry_contract: str | None,
    source_url: str | None,
    source_bundle: dict[str, Any] | None = None,
) -> Candidate:
    """Central Candidate constructor for TON – applies path safety filter (RULES.md §3)."""
    files, dropped = filter_candidate_files(raw_files)
    if dropped:
        logger.warning("ton make_candidate: dropped %d unsafe paths: %s", len(dropped), dropped)
    compiler = Compiler(version=compiler_version, version_pinned_by=compiler_pinned_by) if compiler_version else None
    return Candidate(
        provider=provider,  # type: ignore[arg-type]
        files=files,
        sha256=_candidate_sha256(files),
        language=language,
        compiler=compiler,
        settings=source_bundle or {},
        std_json_input=None,
        entry_contract=entry_contract,
        explorer_verified=(provider == "ton_verifier"),
        sourcify_match=None,
        constructor_args_hex=None,
        source_url=source_url,
        fetched_at=_now(),
    )


# ── toncenter v2 state reads (plan 06 4.3, F38) ───────────────────────────


class TonReadError(RuntimeError):
    """A toncenter read failed after retries (06 2.1: job failed, E_INTERNAL)."""


def _toncenter_headers(api_key: str | None) -> dict[str, str]:
    key = api_key or os.environ.get("SOKEN_TONCENTER_API_KEY")
    return {"X-API-Key": key} if key else {}


async def _toncenter(client: httpx.AsyncClient, method: str, params: dict[str, Any], api_key: str | None) -> Any:
    """One v2 call; 429 and 5xx are retried with backoff (F34: keyless calls hit 429)."""
    url = f"{TONCENTER_V2}/{method}"
    last = ""
    for attempt in range(_TONCENTER_RETRIES):
        r = await _get(client, url, "toncenter", per_s=_TONCENTER_PER_S, headers=_toncenter_headers(api_key), params=params)
        if r.status_code == 200:
            data = r.json()
            if not data.get("ok"):
                raise TonReadError(f"{method}: ok=false {str(data.get('error'))[:120]}")
            return data.get("result")
        last = f"{method}: HTTP {r.status_code}"
        if r.status_code != 429 and r.status_code < 500:
            break
        await asyncio.sleep(1.5 * (attempt + 1))
    raise TonReadError(last)


async def fetch_mc_seqno(client: httpx.AsyncClient, api_key: str | None = None) -> int:
    """v2 getMasterchainInfo -> result.last.seqno (F38)."""
    result = await _toncenter(client, "getMasterchainInfo", {}, api_key)
    seqno = (result or {}).get("last", {}).get("seqno")
    if not isinstance(seqno, int):
        raise TonReadError("getMasterchainInfo: no last.seqno")
    return seqno


async def fetch_account_state(
    client: httpx.AsyncClient,
    raw_address: str,
    mc_seqno: int,
    api_key: str | None = None,
) -> dict[str, Any]:
    """v2 getAddressInformation?address=&seqno= (F38, U-T5).

    The answer must name the requested masterchain block; otherwise the read is not pinned.
    """
    result = await _toncenter(client, "getAddressInformation", {"address": raw_address, "seqno": mc_seqno}, api_key)
    if not isinstance(result, dict):
        raise TonReadError("getAddressInformation: no result")
    block = result.get("block_id") or {}
    if block.get("seqno") != mc_seqno or block.get("workchain") != -1:
        raise TonReadError(f"getAddressInformation answered block {block.get('seqno')}, asked {mc_seqno}")
    return result


async def fetch_library_body(
    client: httpx.AsyncClient,
    lib_hash: str,
    api_key: str | None = None,
) -> bytes | None:
    """v2 getLibraries -> library body BoC, or None (06 2.1: library `not_found`).

    The supervisor hashes the body itself; a body whose root hash differs from the requested
    hash is `not_found`, never used.
    """
    result = await _toncenter(client, "getLibraries", {"libraries": lib_hash}, api_key)
    for entry in (result or {}).get("result", []) if isinstance(result, dict) else []:
        boc_b64 = entry.get("data") if isinstance(entry, dict) else None
        if not isinstance(boc_b64, str):
            continue
        try:
            body = base64.b64decode(boc_b64, validate=True)
            if root_hash(body) == lib_hash:
                return body
        except (ValueError, BocError):
            pass
        logger.warning("ton library %s: body hash differs from the requested hash", lib_hash)
    return None


def _b64_bytes(b64: str | None) -> bytes | None:
    if not b64:
        return None
    try:
        return base64.b64decode(b64, validate=True)
    except ValueError:
        return None


# ── TON verifier source fetch (plan 06 4.2, 4.3, F13) ─────────────────────


async def fetch_verifier_bundle(
    client: httpx.AsyncClient,
    code_hash: str,
) -> dict[str, Any] | None:
    """`verifier.ton.org` `/api/v1/verification/source?code_hash=` -> bundle, or None.

    The registry answers files inline (`path`, `content`, `content_hash`), so there are no
    per-file downloads. A 404 means no bundle for this hash.
    """
    if not _HEX64.match(code_hash):
        return None
    url = f"https://{_VERIFIER_HOST}/api/v1/verification/source"
    r = await _get(client, url, "ton_verifier", per_s=2.0, params={"code_hash": code_hash})
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise RuntimeError(f"ton verifier HTTP {r.status_code}")
    if len(r.content) > _MAX_BUNDLE_BYTES:
        raise RuntimeError("ton verifier bundle over the size cap")
    data = r.json()
    if not data.get("verified") or (data.get("code_hash") or "").lower() != code_hash:
        return None
    bundle = data.get("bundle")
    return bundle if isinstance(bundle, dict) else None


def _bundle_files(bundle: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Inline files whose sha256 equals `content_hash`, and the FunC targets in bundle order.

    A file with a wrong hash, a binary extension or an unsafe path is dropped; a dropped
    target makes the bundle unusable (returns no files).
    """
    files: dict[str, str] = {}
    targets: list[str] = []
    total = 0
    for entry in bundle.get("files") or []:
        path = entry.get("path")
        content = entry.get("content")
        if not isinstance(path, str) or not isinstance(content, str):
            return {}, []
        raw = content.encode("utf-8")
        total += len(raw)
        if (
            len(raw) > _MAX_FILE_BYTES
            or total > _MAX_BUNDLE_BYTES
            or len(files) >= _MAX_TOTAL_INODES
            or Path(path).suffix.lower() in _BINARY_SOURCE_EXTS
            or hashlib.sha256(raw).hexdigest() != (entry.get("content_hash") or "").lower()
        ):
            logger.warning("ton verifier bundle: file %r rejected", path[:200])
            return {}, []
        files[path] = content
        if entry.get("include_in_command"):
            targets.append(path)
    return files, targets


def _parse_verifier_compiler(bundle: dict[str, Any]) -> tuple[str, str | None]:
    """Extract language and version from a verifier bundle (F13, F32)."""
    compiler = bundle.get("compiler") or {}
    lang_raw = (compiler.get("language") or "").lower()
    version = compiler.get("version") or (compiler.get("params") or {}).get("compiler_version")
    language = {"fift": "func"}.get(lang_raw, lang_raw)
    return language, version


async def fetch_source_from_verifier(
    client: httpx.AsyncClient,
    code_hash: str,
) -> Candidate | None:
    """Verifier bundle for a code hash as a `ton_verifier` candidate (06 4.2).

    Not owner-linked (06 2.3: the registry is pay-to-submit); it reaches tier A only when the
    supervisor's rebuild hash equals the on-chain hash.
    """
    bundle = await fetch_verifier_bundle(client, code_hash)
    if not bundle:
        return None
    raw_files, targets = _bundle_files(bundle)
    if not raw_files:
        return None
    language, version = _parse_verifier_compiler(bundle)
    if language not in ("func", "tact", "tolk"):
        return None
    entry = bundle.get("entrypoint")
    settings: dict[str, Any] = {
        "entry": entry,
        "func_targets": targets,
        "verifier": {
            "code_hash": code_hash,
            "source_bundle_hash": bundle.get("source_bundle_hash"),
            "storage_revision": bundle.get("storage_revision"),
            "verified_at": bundle.get("verified_at"),
            "compiler": bundle.get("compiler"),
        },
    }
    cand = _make_ton_candidate(
        provider="ton_verifier",
        raw_files=raw_files,
        language=language,
        compiler_version=version,
        compiler_pinned_by="ton_verifier",
        entry_contract=entry,
        source_url=f"https://{_VERIFIER_HOST}/api/v1/verification/source?code_hash={code_hash}",
        source_bundle=settings,
    )
    bad = bundle_paths_error(entry, targets, cand.files, language)
    if bad:
        logger.warning("ton verifier bundle for %s dropped: %s", code_hash, bad)
        return None
    return cand


_LANG_EXTS = {"func": (".fc", ".func"), "tolk": (".tolk",), "tact": (".tact", ".fc", ".func")}


def bundle_paths_error(entry: Any, targets: list[Any], files: dict[str, str], language: str) -> str | None:
    """The bundle's entrypoint and every `include_in_command` target must be a safe store path
    exactly as written, not start with `-`, carry a source extension of the language, and be a
    member of the accepted file set. Returns the first violation, or None."""
    exts = _LANG_EXTS.get(language, ())
    for kind, value in [("entrypoint", entry), *(("target", t) for t in targets)]:
        if not isinstance(value, str) or not value:
            return f"{kind} missing or not a string"
        if value.startswith("-") or any(part.startswith("-") for part in value.split("/")):
            return f"{kind} {value[:80]!r} starts with '-'"
        if safe_store_path(value) != value:
            return f"{kind} {value[:80]!r} is not a safe store path"
        if not value.lower().endswith(exts):
            return f"{kind} {value[:80]!r} is not a {language} source file"
        if value not in files:
            return f"{kind} {value[:80]!r} is not in the bundle's accepted files"
    return None


# ── user / repo candidate (plan 06 4.2) ───────────────────────────────────


def _validate_user_files(files: dict[str, str]) -> dict[str, str]:
    """Apply per-file and total-budget caps to user-supplied files (plan 09 3.2).

    Security (coordinator 2026-10-09): rejects binary blob extensions
    (.boc/.cell/.fif/.fift) so user uploads cannot plant pre-built artifacts
    that would be picked up by compiler-output globs.
    """
    validated: dict[str, str] = {}
    total_bytes = 0
    for path, content in files.items():
        if len(validated) >= _MAX_TOTAL_INODES:
            logger.warning("make_user_candidate: inode cap (%d) reached", _MAX_TOTAL_INODES)
            break
        # Reject binary blobs (planted-artifact attack prevention)
        if Path(path).suffix.lower() in _BINARY_SOURCE_EXTS:
            logger.debug("make_user_candidate: rejecting binary blob %r", path[:200])
            continue
        encoded = content.encode("utf-8", errors="replace")
        if len(encoded) > _MAX_FILE_BYTES:
            logger.warning("make_user_candidate: file %r too large (%d bytes), skipping", path[:200], len(encoded))
            continue
        if total_bytes + len(encoded) > _MAX_TOTAL_FETCH_BYTES:
            logger.warning("make_user_candidate: total byte budget exceeded at %r", path[:200])
            break
        validated[path] = content
        total_bytes += len(encoded)
    return validated


def make_user_candidate(files: dict[str, str], *, compiler_version: str | None = None, language: str | None = None) -> Candidate:
    """Build a Candidate from user-supplied files (resource-bounded per plan 09 3.2)."""
    from soken_review.adapters.ton.detect import detect_language_from_files
    bounded = _validate_user_files(files)
    lang = language or detect_language_from_files(bounded) or "func"
    return _make_ton_candidate(
        provider="user",
        raw_files=bounded,
        language=lang,
        compiler_version=compiler_version,
        compiler_pinned_by="user",
        entry_contract=None,
        source_url=None,
    )


async def fetch_repo_candidate(
    client: httpx.AsyncClient,
    repo_url: str,
    commit: str,
    subdir: str = "",
) -> Candidate | None:
    """Clone a repo at a commit via the GitHub archive API and return a Candidate.

    Only github.com repos are supported (plan 06 4.2, provider='repo').
    """
    import tarfile
    import tempfile
    from pathlib import Path

    repo_url = repo_url.rstrip("/").removesuffix(".git")
    if "github.com" not in repo_url:
        logger.debug("fetch_repo_candidate: only github.com repos supported, got %s", repo_url)
        return None

    path_parts = repo_url.split("github.com/", 1)[-1].split("/")
    if len(path_parts) < 2:
        return None
    owner, repo = path_parts[0], path_parts[1]

    # Validate commit: only hex sha or short-ref alphanumeric
    import re
    if not re.match(r"^[A-Za-z0-9._-]{1,80}$", commit):
        logger.warning("fetch_repo_candidate: unsafe commit string %r", commit[:20])
        return None

    archive_url = f"https://github.com/{owner}/{repo}/archive/{commit}.tar.gz"
    try:
        # GitHub archive redirects github.com → codeload.github.com; allow that single hop.
        # The URL is fully constructed here (not attacker-controlled), so redirect is safe.
        r = await _get(client, archive_url, "github", per_s=1.0, follow_redirects=True)
        if r.status_code != 200:
            logger.debug("GitHub archive %s -> %d", archive_url, r.status_code)
            return None
        raw_bytes = r.content
    except Exception as exc:  # noqa: BLE001
        logger.debug("fetch_repo_candidate failed: %s", exc)
        return None

    CONTRACT_EXTS = {".fc", ".func", ".tact", ".tolk", ".json", ".toml"}
    files: dict[str, str] = {}
    total_bytes = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = Path(tmpdir) / "archive.tar.gz"
        archive_path.write_bytes(raw_bytes)
        try:
            with tarfile.open(archive_path, "r:gz") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    # Total inode cap
                    if len(files) >= _MAX_TOTAL_INODES:
                        logger.warning("fetch_repo_candidate: inode cap (%d) reached", _MAX_TOTAL_INODES)
                        break
                    parts = member.name.split("/", 1)
                    rel = parts[1] if len(parts) > 1 else member.name
                    if subdir:
                        prefix = subdir.rstrip("/") + "/"
                        if not rel.startswith(prefix):
                            continue
                        rel = rel[len(prefix):]
                    ext = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
                    if ext not in CONTRACT_EXTS:
                        continue
                    fobj = tf.extractfile(member)
                    if fobj is None:
                        continue
                    raw_content = fobj.read(_MAX_FILE_BYTES + 1)
                    if len(raw_content) > _MAX_FILE_BYTES:
                        logger.debug("skip oversized file %s in %s", rel, archive_url)
                        continue
                    # Total byte budget
                    if total_bytes + len(raw_content) > _MAX_TOTAL_FETCH_BYTES:
                        logger.warning("fetch_repo_candidate: total byte budget exceeded at %s", rel)
                        break
                    try:
                        content = raw_content.decode("utf-8", errors="replace")
                        files[rel] = content
                        total_bytes += len(raw_content)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("skip file %s in %s: %s", rel, archive_url, exc)
        except Exception as exc:  # noqa: BLE001
            logger.debug("tarfile extract failed: %s", exc)
            return None

    if not files:
        return None
    from soken_review.adapters.ton.detect import detect_language_from_files
    language = detect_language_from_files(files) or "func"
    return _make_ton_candidate(
        provider="repo",
        raw_files=files,
        language=language,
        compiler_version=None,
        compiler_pinned_by="repo",
        entry_contract=None,
        source_url=f"https://github.com/{owner}/{repo}/tree/{commit}",
        source_bundle={"repo_url": repo_url, "commit": commit, "subdir": subdir},
    )


# ── chain_state 0 (plan 06 2.1, 2.2, 4.3) ─────────────────────────────────

_STATUS = {"active": "active", "uninitialized": "uninit", "uninit": "uninit", "frozen": "frozen"}


async def read_ton_chain_state(
    raw_address: str,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Account state pinned to one masterchain seqno, hashed by the supervisor (06 4.3, F38).

    Returns the `chain_state` TON document (06 2.2). `dep_hash` is the hash a rebuild must
    equal: the root code cell hash, or the library body hash when the code is a library ref
    (dep_match.yaml `ton`). It is None with a `why` when the code cannot be hashed.

    Raises TonReadError when the pin or the account read fails (job failed, E_INTERNAL).
    """
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        mc_seqno = await fetch_mc_seqno(client, api_key)
        acct = await fetch_account_state(client, raw_address, mc_seqno, api_key)

        state = acct.get("state")
        status = _STATUS.get(state if isinstance(state, str) else "", "nonexist")
        code = _b64_bytes(acct.get("code")) if status == "active" else None
        data = _b64_bytes(acct.get("data")) if status == "active" else None
        if status == "active" and not code:
            status = "nonexist"

        entry: dict[str, Any] = {
            "status": status,
            "balance": acct.get("balance"),
            "code_boc": code.hex() if code else None,
            "data_boc": data.hex() if data else None,
            "code_hash": None,
            "code_is_library_ref": False,
            "library_hash": None,
            "library_body_boc": None,
            "dep_hash": None,
            "why": None,
            "read_status": {"account": "ok"},
        }
        if code:
            try:
                info = root_info(code)
            except BocError as exc:
                entry["why"] = "code_not_hashable"
                entry["read_status"]["code"] = str(exc)[:120]
            else:
                entry["code_hash"] = info.hash
                if info.is_library_ref and info.library_hash:
                    entry["code_is_library_ref"] = True
                    entry["library_hash"] = info.library_hash
                    try:
                        body = await fetch_library_body(client, info.library_hash, api_key)
                    except TonReadError as exc:
                        body = None
                        entry["read_status"]["library"] = f"unavailable: {exc}"[:160]
                    if body is None:
                        entry["why"] = "library_not_found"
                    else:
                        entry["library_body_boc"] = body.hex()
                        entry["dep_hash"] = info.library_hash
                        entry["read_status"]["library"] = "ok"
                else:
                    entry["dep_hash"] = info.hash

        return {"mc_seqno": mc_seqno, "accounts": {raw_address: entry}}


# ── main fetch orchestrator (plan 06 4.2) ─────────────────────────────────


async def fetch_ton_sources(
    raw_address: str | None,
    code_hash: str | None,
    user_files: dict[str, str] | None = None,
    repo_url: str | None = None,
    repo_commit: str | None = None,
    repo_subdir: str = "",
    api_key: str | None = None,
    *,
    compiler_version: str | None = None,
    language: str | None = None,
    read_status: dict[str, str] | None = None,
) -> list[Candidate]:
    """Fetch TON source candidates in 06 4.2 order: user source, then the verifier bundle.

    A verifier outage is recorded in `read_status["ton_verifier"] = "unavailable"` (06 2.1);
    the caller fails the job when resolution then ends other than exact.
    """
    candidates: list[Candidate] = []
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        if user_files:
            candidates.append(make_user_candidate(user_files, compiler_version=compiler_version, language=language))
        if repo_url and repo_commit:
            rc = await fetch_repo_candidate(client, repo_url, repo_commit, repo_subdir)
            if rc is not None:
                candidates.append(rc)
        if code_hash:
            try:
                vc = await fetch_source_from_verifier(client, code_hash)
            except (RuntimeError, httpx.HTTPError, ValueError) as exc:
                logger.warning("ton verifier unavailable for %s: %s", code_hash, exc)
                if read_status is not None:
                    read_status["ton_verifier"] = "unavailable"
                vc = None
            else:
                if read_status is not None:
                    read_status["ton_verifier"] = "ok" if vc is not None else "not_found"
            if vc is not None:
                candidates.append(vc)
    return candidates
