"""TON source fetch and chain_state 0 reads (plan v4 06 sections 2.1, 4.2, 4.3).

Fetch order per plan 06 4.2:
  1. User source (repo or files), when provided
  2. TON verifier bundle for the unit's code hash, via on-chain registry (primary)
     or legacy HTTP API (fallback).

State reads (plan 06 4.3, F38), supervisor only:
  - Pin:     toncenter v2 getMasterchainInfo  -> mc_seqno
  - Account: toncenter v2 getAddressInformation?seqno=<mc_seqno>; the answer must name that block
  - Libs:    toncenter v2 getLibraries for a library-ref code cell; body hash checked here

Every hash (account code, library body) is computed in this process by `cell.root_info`;
no container reports a hash (09 3.5).

TON verifier (on-chain registry, primary path — replaces broken /api/v1/verification/source):
  Two-step TonCenter v2 runGetMethod lookup:
  1. POST toncenter.com/api/v2/runGetMethod
       address : SOURCES_REGISTRY (EQD-BJSVUJviud_Qv7Ymfd3qzXdrmV525e3YDzWQoHIAiInL)
       method  : get_source_item_address
       stack   : [["num", sha256_int(verifier_id)], ["num", code_hash_int]]
     Returns addr_std cell → source item address.
  2. POST toncenter.com/api/v2/runGetMethod
       address : source_item_address
       method  : get_source_item_data
       stack   : []
     Returns stack[3] cell → version_byte(1) + ipfs_url string.
  3. Fetch IPFS manifest JSON from gateway (files.orbs.network, gateway.pinata.cloud, ipfs.ton.live).
  4. For each source entry in the manifest: fetch file text from IPFS (same gateway chain).
  5. Verify: base64.decode(manifest["hash"]) must equal bytes.fromhex(code_hash).
  Verifiers tried in order: "orbs.com", "verifier.ton.org".

TON verifier (legacy HTTP API, fallback):
  GET https://verifier.ton.org/api/v1/verification/source?code_hash=<hex>
  Files inline; each file's sha256 must equal its `content_hash`.
  This endpoint returns 404 for many verified contracts (2026-10-25 incident); the on-chain
  registry path is authoritative.

Rate limiter per plan 06 2.10 / limits.yaml: toncenter 10/s (keyless 1/s), ton_verifier 2/s,
ipfs 2/s.

Security (RULES.md §3):
  - Per-file and total size caps; binary blobs (.boc/.cell/.fif) never enter a candidate.
  - All file names pass filter_candidate_files (safe_store_path gate).
  - Repo archives: github.com only, fixed URL, size caps.
  - IPFS gateways: only hosts in _VERIFIER_DOWNLOAD_ALLOWLIST (SSRF protection).
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

# ── on-chain registry (primary verified-source path) ─────────────────────

# Mainnet sources registry contract (ton-community/contract-verifier-sdk, SOURCES_REGISTRY).
_SOURCES_REGISTRY_MAINNET = "EQD-BJSVUJviud_Qv7Ymfd3qzXdrmV525e3YDzWQoHIAiInL"

# Verifier IDs tried in priority order.  The on-chain registry is keyed by
# sha256(verifier_id) as a 256-bit integer. "orbs.com" is the primary submitter
# (all contracts verified via verifier.ton.org UI are registered under orbs.com first).
_REGISTRY_VERIFIER_IDS: tuple[str, ...] = ("orbs.com", "verifier.ton.org")

# IPFS gateway base URLs, tried in order until one responds.
# Rate-limited under the "ipfs" bucket (limits.yaml outbound.ipfs 2/s).
_IPFS_GATEWAYS: tuple[str, ...] = (
    "https://files.orbs.network/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
    "https://ipfs.ton.live/ipfs/",
)

_MAX_MANIFEST_BYTES = 1 * 1024 * 1024    # 1 MiB for the sources JSON manifest
_IPFS_PER_S = 2.0                         # matches outbound.ipfs in limits.yaml

# Source file extensions from the IPFS manifest that are kept in the Candidate.
# ABI (.abi), package (.pkg) and binary blob extensions are excluded.
_REGISTRY_SOURCE_EXTS = frozenset({".tact", ".fc", ".func", ".tolk", ".json", ".toml"})

# Allowlist for downloading source files from verifier bundles.
# Only these hostnames may serve source files (SSRF protection).
# Ref: plan 09 4.3 provider rows + outbound rows in limits.yaml.
_VERIFIER_DOWNLOAD_ALLOWLIST: frozenset[str] = frozenset([
    "server.ton.org",
    "verifier.ton.org",
    # Common GitHub raw file hosts for open-source bundles
    "raw.githubusercontent.com",
    "github.com",
    # IPFS gateways for on-chain registry source fetch (2026-10-25)
    "files.orbs.network",
    "gateway.pinata.cloud",
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

# Maximum size for compilerSettings.parameters JSON string (size-capped before parse).
_MAX_PARAMS_JSON = 4096


def _normalise_verifier_compiler(
    name: Any,
    version: Any,
    params_raw: Any,
) -> dict[str, Any]:
    """Return a normalised compiler dict: {"name": str, "version": str|None, "params": dict|None}.

    Both fetch paths (on-chain registry and legacy HTTP) store `settings["verifier"]["compiler"]`
    as this shape so that build.py and trust_scan.scan_params always receive a dict, never a bare
    string.  `params_raw` is the compilerSettings.parameters field from the registry manifest
    (a JSON string) or the legacy bundle's compiler.params dict.  Invalid JSON and oversized
    strings produce an `__invalid__` marker that scan_params rejects (untrusted_args).
    """
    # Fail closed: params that are present but cannot become a dict are kept as a marker that
    # trust_scan.scan_params rejects ("outside the allowlist"), never dropped as "no params".
    params: dict[str, Any] | None = None
    if params_raw is None or params_raw == "":
        params = None
    elif isinstance(params_raw, dict):
        params = params_raw
    elif isinstance(params_raw, str) and len(params_raw) <= _MAX_PARAMS_JSON:
        try:
            parsed = json.loads(params_raw)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        params = parsed if isinstance(parsed, dict) else {"__invalid__": "params are not a JSON object"}
    else:
        params = {"__invalid__": "params are oversized or of an unexpected type"}
    return {
        "name": (name or "").lower() if isinstance(name, str) else "",
        "version": version if isinstance(version, str) and version else None,
        "params": params,
    }


# ── on-chain registry helpers ─────────────────────────────────────────────


def _crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM used in TON user-friendly address encoding."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def _ton_address_b64(workchain: int, hash_bytes: bytes) -> str:
    """Encode a (workchain, 32-byte hash) pair as a bounceable TON address (base64url)."""
    tag = 0x11  # bounceable addr_std
    msg = bytes([tag, workchain & 0xFF]) + hash_bytes
    crc = _crc16_xmodem(msg)
    full = msg + bytes([crc >> 8, crc & 0xFF])
    return base64.urlsafe_b64encode(full).decode()


def _parse_addr_std_cell(obj: dict[str, Any]) -> tuple[int, bytes] | None:
    """Parse a TonCenter cell object as an addr_std, returning (workchain, hash_bytes).

    TonCenter runGetMethod returns cells as::

        {"bytes": "<boc_b64>", "object": {"data": {"b64": "<bits_b64>", "len": <n_bits>}}}

    addr_std TL-B: addr_std$10 anycast:(Maybe Anycast) workchain_id:int8 address:bits256
    = 267 bits (no anycast).
    """
    try:
        cell_data = obj.get("object", {}).get("data", {})
        b64 = cell_data.get("b64")
        num_bits = cell_data.get("len")
        if not isinstance(b64, str) or not isinstance(num_bits, int) or num_bits < 267:
            return None
        raw = base64.b64decode(b64)
        # bits are MSB-first; strip trailing padding bits
        total_bits = len(raw) * 8
        value = int.from_bytes(raw, "big") >> (total_bits - num_bits)
        # addr_std$10 = top two bits == 0b10
        if (value >> (num_bits - 2)) & 0b11 != 0b10:
            return None
        # anycast bit must be 0 (no anycast support)
        if (value >> (num_bits - 3)) & 1:
            return None
        # workchain = bits 3-10 (int8)
        wc = (value >> (num_bits - 11)) & 0xFF
        if wc >= 128:
            wc -= 256
        # address = bottom 256 bits
        addr_int = value & ((1 << 256) - 1)
        return wc, addr_int.to_bytes(32, "big")
    except Exception:  # noqa: BLE001
        return None


def _parse_string_cell(obj: dict[str, Any]) -> str | None:
    """Parse a TonCenter cell object as a snake-encoded string (version_byte + UTF-8).

    Used by get_source_item_data stack[3] which encodes an ipfs:// URL as:
      0x01 <utf-8 bytes>  (version = 1, rest is the string).
    The cell data must be byte-aligned (len % 8 == 0).
    """
    try:
        cell_data = obj.get("object", {}).get("data", {})
        b64 = cell_data.get("b64")
        num_bits = cell_data.get("len")
        if not isinstance(b64, str) or not isinstance(num_bits, int):
            return None
        if num_bits % 8 != 0:
            return None
        raw = base64.b64decode(b64)[: num_bits // 8]
        if not raw or raw[0] != 1:  # version byte must be 1
            return None
        return raw[1:].decode("utf-8")
    except Exception:  # noqa: BLE001
        return None


def _registry_verifier_sha256_int(verifier_id: str) -> int:
    """SHA-256 of verifier_id string as a big-endian 256-bit integer (registry key format)."""
    return int.from_bytes(hashlib.sha256(verifier_id.encode()).digest(), "big")


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


# ── on-chain registry source fetch (primary path, replaces broken HTTP API) ──


async def _run_get_method(
    client: httpx.AsyncClient,
    address: str,
    method: str,
    stack: list[list[Any]],
) -> list[Any] | None:
    """Call TonCenter v2 runGetMethod; return the result stack list or None.

    Uses the "toncenter" rate-limiter bucket (same as other v2 calls).
    Raises RuntimeError on persistent HTTP errors so callers can mark unavailable.
    """
    url = f"{TONCENTER_V2}/runGetMethod"
    payload = {"address": address, "method": method, "stack": stack}
    for attempt in range(_MAX_RETRIES):
        try:
            await _limiter("toncenter", _TONCENTER_PER_S).wait()
            r = await client.post(url, json=payload, headers=_toncenter_headers(None))
            if r.status_code == 200:
                data = r.json()
                if not data.get("ok"):
                    logger.debug("runGetMethod %s.%s ok=false: %s", address[:12], method, str(data.get("error"))[:80])
                    return None
                result = data.get("result") or {}
                if result.get("exit_code", -1) != 0:
                    logger.debug("runGetMethod %s.%s exit_code=%s", address[:12], method, result.get("exit_code"))
                    return None
                return result.get("stack") or []
            if r.status_code not in (429, 500, 502, 503, 504):
                return None  # permanent client error
        except Exception as exc:  # noqa: BLE001
            logger.debug("runGetMethod attempt %d failed: %s", attempt, exc)
        if attempt < _MAX_RETRIES - 1:
            await asyncio.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"runGetMethod {method} on {address[:20]} failed after {_MAX_RETRIES} retries")


async def _registry_get_source_item_address(
    client: httpx.AsyncClient,
    code_hash: str,
    verifier_id: str,
) -> str | None:
    """Step 1: call get_source_item_address on the sources registry.

    Exact request::

        POST https://toncenter.com/api/v2/runGetMethod
        {"address": "<SOURCES_REGISTRY>",
         "method": "get_source_item_address",
         "stack": [["num", "<sha256(verifier_id) as int>"],
                   ["num", "<code_hash_hex as int>"]]}

    Returns the source item address in bounceable base64url form, or None.
    """
    verifier_int = _registry_verifier_sha256_int(verifier_id)
    code_hash_int = int(code_hash, 16)
    stack = await _run_get_method(
        client,
        _SOURCES_REGISTRY_MAINNET,
        "get_source_item_address",
        [["num", str(verifier_int)], ["num", str(code_hash_int)]],
    )
    if not stack:
        return None
    # stack[0] is an addr_std cell
    item_type, item_val = stack[0][0], stack[0][1] if len(stack[0]) > 1 else {}
    if item_type != "cell":
        return None
    parsed = _parse_addr_std_cell(item_val if isinstance(item_val, dict) else {})
    if parsed is None:
        return None
    wc, hash_bytes = parsed
    return _ton_address_b64(wc, hash_bytes)


async def _registry_get_ipfs_link(
    client: httpx.AsyncClient,
    source_item_address: str,
) -> str | None:
    """Step 2: call get_source_item_data on the source item contract.

    Exact request::

        POST https://toncenter.com/api/v2/runGetMethod
        {"address": "<source_item_address>",
         "method": "get_source_item_data",
         "stack": []}

    Returns the ipfs:// URL from stack[3], or None.
    Stack layout (from contract-verifier-sdk):
      [0] verifier_id hash (num)
      [1] code_hash (num)
      [2] verifier address (cell)
      [3] ipfs link cell: 0x01 <utf-8 ipfs:// URL>
    """
    stack = await _run_get_method(client, source_item_address, "get_source_item_data", [])
    if not stack or len(stack) < 4:
        return None
    item_type, item_val = stack[3][0], stack[3][1] if len(stack[3]) > 1 else {}
    if item_type != "cell":
        return None
    return _parse_string_cell(item_val if isinstance(item_val, dict) else {})


async def _ipfs_fetch_bytes(
    client: httpx.AsyncClient,
    cid: str,
    max_bytes: int,
) -> bytes | None:
    """Fetch raw bytes for an IPFS CID, trying each gateway in turn.

    Uses the "ipfs" rate-limiter bucket (limits.yaml outbound.ipfs 2/s).
    Only hostnames in _VERIFIER_DOWNLOAD_ALLOWLIST are contacted (SSRF protection).
    """
    for gateway in _IPFS_GATEWAYS:
        url = gateway + cid
        if _validate_download_url(url) is None:
            continue
        try:
            await _limiter("ipfs", _IPFS_PER_S).wait()
            r = await client.get(url, follow_redirects=False)
            if r.status_code == 200:
                if len(r.content) > max_bytes:
                    logger.warning("_ipfs_fetch_bytes: %s over cap (%d > %d)", cid[:20], len(r.content), max_bytes)
                    return None
                return r.content
        except Exception as exc:  # noqa: BLE001
            logger.debug("_ipfs_fetch_bytes gateway %s cid %s: %s", gateway, cid[:20], exc)
    return None


async def _ipfs_fetch_manifest(
    client: httpx.AsyncClient,
    ipfs_url: str,
    code_hash: str,
) -> dict[str, Any] | None:
    """Fetch the IPFS sources JSON manifest and verify it matches code_hash.

    The manifest "hash" field is base64 of the 32-byte code cell hash.
    Returns the parsed manifest dict, or None on failure.
    """
    if not ipfs_url.startswith("ipfs://"):
        return None
    cid = ipfs_url[len("ipfs://"):]
    raw = await _ipfs_fetch_bytes(client, cid, _MAX_MANIFEST_BYTES)
    if raw is None:
        return None
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    # Verify the manifest hash matches the requested code hash.
    hash_b64 = manifest.get("hash")
    if not isinstance(hash_b64, str):
        logger.debug("_ipfs_fetch_manifest: missing hash field for %s", code_hash[:12])
        return None
    try:
        declared_hash = base64.b64decode(hash_b64 + "==").hex()  # tolerate missing padding
    except Exception:  # noqa: BLE001
        return None
    if declared_hash != code_hash:
        logger.warning(
            "_ipfs_fetch_manifest: hash mismatch for %s: manifest declares %s",
            code_hash[:12], declared_hash[:12],
        )
        return None
    return manifest


def _registry_find_entrypoint(manifest: dict[str, Any], source_filenames: list[str]) -> str | None:
    """Resolve the entrypoint from compilerSettings.parameters within the IPFS filenames.

    parameters JSON: {"entrypoint": "contracts/ft_master.tact", ...}
    IPFS filenames may include a directory prefix (e.g. "contract/contracts/ft_master.tact").
    Returns the IPFS filename that ends with "/<entrypoint>" or equals it exactly.
    """
    params_raw = (manifest.get("compilerSettings") or {}).get("parameters")
    if not isinstance(params_raw, str):
        return None
    try:
        params = json.loads(params_raw)
    except (json.JSONDecodeError, TypeError):
        return None
    entry = params.get("entrypoint")
    if not isinstance(entry, str) or not entry:
        return None
    for fn in source_filenames:
        if fn == entry or fn.endswith("/" + entry):
            return fn
    return None


async def _registry_download_files(
    client: httpx.AsyncClient,
    manifest: dict[str, Any],
) -> dict[str, str]:
    """Download source files referenced in the IPFS manifest.

    Only files with extensions in _REGISTRY_SOURCE_EXTS are fetched (skips .abi, .pkg).
    Binary blob extensions are never written (planted-artifact protection).
    Returns a {filename: content} mapping for the accepted files.
    """
    from pathlib import Path as _Path
    result: dict[str, str] = {}
    total_bytes = 0
    sources = manifest.get("sources") or []
    for entry in sources:
        filename = entry.get("filename") if isinstance(entry, dict) else None
        ipfs_url = entry.get("url") if isinstance(entry, dict) else None
        if not isinstance(filename, str) or not isinstance(ipfs_url, str):
            continue
        ext = _Path(filename).suffix.lower()
        if ext not in _REGISTRY_SOURCE_EXTS:
            continue
        if ext in _BINARY_SOURCE_EXTS:
            continue
        if len(result) >= _MAX_TOTAL_INODES:
            logger.warning("_registry_download_files: inode cap reached")
            break
        if not ipfs_url.startswith("ipfs://"):
            continue
        cid = ipfs_url[len("ipfs://"):]
        raw = await _ipfs_fetch_bytes(client, cid, _MAX_FILE_BYTES)
        if raw is None:
            logger.debug("_registry_download_files: failed to fetch %s", filename)
            continue
        if total_bytes + len(raw) > _MAX_TOTAL_FETCH_BYTES:
            logger.warning("_registry_download_files: total byte budget exceeded at %s", filename)
            break
        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            logger.debug("_registry_download_files: decode failed for %s: %s", filename, exc)
            continue
        result[filename] = content
        total_bytes += len(raw)
    return result


async def fetch_source_from_registry(
    client: httpx.AsyncClient,
    code_hash: str,
) -> Candidate | None:
    """Fetch verified sources via the TON on-chain sources registry (primary path).

    Replaces the broken ``GET /api/v1/verification/source`` endpoint (2026-10-25 incident).
    Tries each verifier ID in _REGISTRY_VERIFIER_IDS until one resolves a source item.

    The fetched manifest's ``hash`` field is verified against ``code_hash`` before use.
    Individual source files are downloaded from IPFS with size caps; the build step
    recompiles and checks the output hash against the on-chain dep_hash (tier logic).

    Returns a ``ton_verifier`` Candidate, or None if no verified source is found or
    a network error prevents resolution.
    """
    if not _HEX64.match(code_hash):
        return None
    for verifier_id in _REGISTRY_VERIFIER_IDS:
        try:
            source_item_addr = await _registry_get_source_item_address(client, code_hash, verifier_id)
        except RuntimeError as exc:
            logger.warning("registry get_source_item_address failed (%s): %s", verifier_id, exc)
            raise  # propagate to mark the whole verifier call as unavailable
        if source_item_addr is None:
            logger.debug("registry: no source item for %s / %s", code_hash[:12], verifier_id)
            continue
        try:
            ipfs_url = await _registry_get_ipfs_link(client, source_item_addr)
        except RuntimeError as exc:
            logger.warning("registry get_source_item_data failed (%s/%s): %s", code_hash[:12], verifier_id, exc)
            continue
        if not ipfs_url:
            logger.debug("registry: empty ipfs link for %s / %s", code_hash[:12], verifier_id)
            continue
        manifest = await _ipfs_fetch_manifest(client, ipfs_url, code_hash)
        if manifest is None:
            logger.debug("registry: manifest fetch/verify failed for %s / %s", code_hash[:12], verifier_id)
            continue
        raw_files = await _registry_download_files(client, manifest)
        if not raw_files:
            logger.warning("registry: no source files downloaded for %s / %s", code_hash[:12], verifier_id)
            continue
        language_raw = (manifest.get("compiler") or "").lower()
        language = {"fift": "func"}.get(language_raw, language_raw)
        if language not in ("func", "tact", "tolk"):
            logger.debug("registry: unsupported compiler %r for %s", language_raw, code_hash[:12])
            continue
        compiler_settings = manifest.get("compilerSettings") or {}
        version = compiler_settings.get("tactVersion") or compiler_settings.get("compilerVersion")
        entry = _registry_find_entrypoint(manifest, list(raw_files))
        if entry is None and language == "tact":
            logger.debug("registry: no entrypoint found for tact contract %s", code_hash[:12])
            # still proceed; build may work without an explicit entry if there is only one .tact file
        # Normalise into the documented compiler shape so build.py/trust_scan always get a dict.
        # parameters is a JSON string in the registry manifest; parse it safely (size-capped).
        _compiler_norm = _normalise_verifier_compiler(
            name=manifest.get("compiler"),
            version=version,
            params_raw=compiler_settings.get("parameters"),
        )
        settings: dict[str, Any] = {
            "entry": entry,
            "verifier": {
                "verifier_id": verifier_id,
                "code_hash": code_hash,
                "ipfs_manifest_url": ipfs_url,
                "compiler": _compiler_norm,
                "compiler_settings": compiler_settings,
                "verification_date": manifest.get("verificationDate"),
                "source_item_address": source_item_addr,
            },
        }
        cand = _make_ton_candidate(
            provider="ton_verifier",
            raw_files=raw_files,
            language=language,
            compiler_version=version,
            compiler_pinned_by="ton_verifier",
            entry_contract=entry,
            source_url=f"https://verifier.ton.org/{code_hash}",
            source_bundle=settings,
        )
        bad = bundle_paths_error(entry, [], cand.files, language)
        if bad and entry is not None:
            logger.warning("registry: bundle paths error for %s: %s", code_hash[:12], bad)
            # entry path check failed but files are present; clear entry and continue
            cand = _make_ton_candidate(
                provider="ton_verifier",
                raw_files=raw_files,
                language=language,
                compiler_version=version,
                compiler_pinned_by="ton_verifier",
                entry_contract=None,
                source_url=f"https://verifier.ton.org/{code_hash}",
                source_bundle={**settings, "entry": None},
            )
        logger.info("registry: found verified source for %s via %s (%d files)", code_hash[:12], verifier_id, len(cand.files))
        return cand
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
    """Verified source for a code hash as a ``ton_verifier`` Candidate (06 4.2).

    Primary path: on-chain registry via ``fetch_source_from_registry()``.
    The GET /api/v1/verification/source endpoint was removed/broken (2026-10-25 incident;
    returns 404 for verified contracts).  The registry is now authoritative.

    Fallback: legacy HTTP API bundle (kept for resilience in case the registry
    lookup fails due to a transient TonCenter outage).

    Not owner-linked (06 2.3: the registry is pay-to-submit); reaches tier A only when
    the supervisor's rebuild hash equals the on-chain hash.
    """
    # Primary: on-chain registry
    try:
        cand = await fetch_source_from_registry(client, code_hash)
        if cand is not None:
            return cand
    except (RuntimeError, httpx.HTTPError, ValueError) as exc:
        logger.warning("ton registry lookup failed for %s: %s; trying legacy API", code_hash[:12], exc)

    # Fallback: legacy HTTP bundle API
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
    # Normalise into the documented compiler shape (same as the registry path above).
    _raw_compiler = bundle.get("compiler") or {}
    _legacy_params = _raw_compiler.get("params") if isinstance(_raw_compiler, dict) else None
    _compiler_norm = _normalise_verifier_compiler(
        name=language,
        version=version,
        params_raw=_legacy_params,
    )
    settings: dict[str, Any] = {
        "entry": entry,
        "func_targets": targets,
        "verifier": {
            "code_hash": code_hash,
            "source_bundle_hash": bundle.get("source_bundle_hash"),
            "storage_revision": bundle.get("storage_revision"),
            "verified_at": bundle.get("verified_at"),
            "compiler": _compiler_norm,
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
