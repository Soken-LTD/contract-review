"""EVM source fetch (05 section 4.2, steps 1, 2, 4, 6).

Fetch order (D-ESC, SCOPE section 8):
  Step 1: Sourcify v2 ?fields=all + all-chains lookup (F8, F46)
  Step 2: eth-bytecode-db sources:search with deployed bytecode only (F45)
  Step 3: Sourcify similarity verify — PUBLIC WRITE, behind flag=False (F44, R5)
  Step 4: IPFS metadata via CBOR CID (Filebase, Lighthouse, Pinata, 4everland)
  Step 5: Etherscan getsourcecode — behind etherscan_licence flag (F1)
  Step 6: user/repo candidate

Rules:
  R1  Sourcify exact_match or match (no user/repo candidate) → stop.
  R3  Provider cache key (chain_id, address, runtime_code_hash).
  R4  Per-provider rate limiter, 3 retries, 10-min down on 403 text/html.
  R5  Similarity verify is a public write; never call in tests or by default.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.evm.units import filter_candidate_files

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Provider URLs (no Etherscan / Routescan hosts per D-ESC)
# ---------------------------------------------------------------------------

SOURCIFY_BASE = "https://sourcify.dev/server"
ETH_BYTECODE_DB_BASE = "https://eth.blockscout.com/api/v2/bytecodes"
IPFS_GATEWAYS = [
    "https://ipfs.filebase.io/ipfs/{cid}",
    "https://gateway.lighthouse.storage/ipfs/{cid}",
    "https://gateway.pinata.cloud/ipfs/{cid}",
    "https://4everland.io/ipfs/{cid}",
]

_TIMEOUT = httpx.Timeout(30.0)
_MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Simple per-provider rate limiter + down-marker (R4)
# ---------------------------------------------------------------------------


class ProviderLimiter:
    """Token-bucket rate limiter with a 10-minute down-mark on 403 text/html (R4)."""

    def __init__(self, per_s: float = 2.0) -> None:
        self._per_s = per_s
        self._last: float = 0.0
        self._down_until: float = 0.0

    def is_down(self) -> bool:
        return time.monotonic() < self._down_until

    def mark_down(self) -> None:
        self._down_until = time.monotonic() + 600  # 10 minutes

    async def wait(self) -> None:
        if self.is_down():
            raise RuntimeError("provider is down (403 text/html mark)")
        now = time.monotonic()
        elapsed = now - self._last
        gap = 1.0 / self._per_s
        if elapsed < gap:
            await asyncio.sleep(gap - elapsed)
        self._last = time.monotonic()


# One limiter instance per logical provider (shared across calls in a process)
_limiters: dict[str, ProviderLimiter] = {}


def _limiter(key: str, per_s: float = 2.0) -> ProviderLimiter:
    if key not in _limiters:
        _limiters[key] = ProviderLimiter(per_s)
    return _limiters[key]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


async def _get(client: httpx.AsyncClient, url: str, limiter_key: str, **kwargs: Any) -> httpx.Response:
    """GET with rate limiting, 3 retries, 403 text/html down-mark (R4)."""
    lim = _limiter(limiter_key)
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            await lim.wait()
            resp = await client.get(url, **kwargs)
            if resp.status_code == 403 and "text/html" in resp.headers.get("content-type", ""):
                lim.mark_down()
                raise RuntimeError(f"403 text/html from {limiter_key}; marked down 10 min")
            return resp
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(2**attempt)
    raise RuntimeError(f"GET {url} failed after {_MAX_RETRIES} retries") from last_exc


async def _post(client: httpx.AsyncClient, url: str, limiter_key: str, **kwargs: Any) -> httpx.Response:
    """POST with rate limiting, 3 retries, 403 text/html down-mark (R4)."""
    lim = _limiter(limiter_key)
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            await lim.wait()
            resp = await client.post(url, **kwargs)
            if resp.status_code == 403 and "text/html" in resp.headers.get("content-type", ""):
                lim.mark_down()
                raise RuntimeError(f"403 text/html from {limiter_key}; marked down 10 min")
            return resp
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(2**attempt)
    raise RuntimeError(f"POST {url} failed after {_MAX_RETRIES} retries") from last_exc


# ---------------------------------------------------------------------------
# Candidate sha256 helper (base.py Candidate.sha256 field)
# ---------------------------------------------------------------------------


def _candidate_sha256(files: dict[str, str]) -> str:
    """sha256 over sorted (path, content_sha256) pairs (05 3.3)."""
    parts = sorted((path, hashlib.sha256(content.encode()).hexdigest()) for path, content in files.items())
    digest = hashlib.sha256(json.dumps(parts).encode()).hexdigest()
    return digest


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def make_candidate(
    *,
    provider: str,
    raw_files: dict[str, str],
    language: str,
    compiler: Compiler | None,
    settings: dict[str, Any],
    std_json_input: dict[str, Any] | None,
    entry_contract: str | None,
    explorer_verified: bool = False,
    sourcify_match: str | None = None,
    constructor_args_hex: str | None = None,
    source_url: str | None = None,
    fetched_at: str | None = None,
    _caller_context: str = "",
) -> Candidate:
    """Central Candidate constructor — ALWAYS applies the path safety filter (security gate).

    raw_files: provider-supplied mapping of path -> content (attacker-controlled).
    All paths go through filter_candidate_files before being stored.
    Dropped paths are logged as warnings; callers must not bypass this by passing
    pre-validated dicts directly to Candidate().
    """
    files, dropped = filter_candidate_files(raw_files)
    if dropped:
        ctx = f" [{_caller_context}]" if _caller_context else ""
        logger.warning("make_candidate%s: dropped %d unsafe paths: %s", ctx, len(dropped), dropped)
    return Candidate(
        provider=provider,  # type: ignore[arg-type]
        files=files,
        sha256=_candidate_sha256(files),
        language=language,
        compiler=compiler,
        settings=settings,
        std_json_input=std_json_input,
        entry_contract=entry_contract,
        explorer_verified=explorer_verified,
        sourcify_match=sourcify_match,
        constructor_args_hex=constructor_args_hex,
        source_url=source_url,
        fetched_at=fetched_at or _now_iso(),
    )


# ---------------------------------------------------------------------------
# CBOR metadata hash extraction (05 step 4, F47)
# ---------------------------------------------------------------------------


def extract_cbor_cid(runtime_hex: str) -> str | None:
    """Extract IPFS CID from the CBOR auxdata appended to Solidity runtime bytecode.

    Solidity appends CBOR-encoded metadata to the end of runtime bytecode.
    The last 2 bytes are the length of the CBOR data.
    Returns the base58-encoded CIDv0 (Qm...) or None.
    """
    raw = runtime_hex.removeprefix("0x")
    if len(raw) < 4:
        return None
    try:
        cbor_len = int(raw[-4:], 16)
        if cbor_len < 2 or cbor_len * 2 + 4 > len(raw):
            return None
        cbor_hex = raw[-(cbor_len * 2 + 4) : -4]
        cbor_bytes = bytes.fromhex(cbor_hex)
        # CBOR map: look for key 0x69706673 ("ipfs") or key bytes[4] == 0x04 (ipfs multihash)
        # Minimal CBOR parsing: find 0xa2 or 0xa1 map marker + "ipfs" key (0x64 "ipfs" = 0x646970667300)
        # Solidity emits: {ipfs: <34 bytes CIDv0 multihash>, solc: <version>}
        # CIDv0 multihash: 0x1220 + 32-byte sha256
        idx = cbor_bytes.find(b"\x64ipfs")
        if idx == -1:
            # Try legacy key 0x0004 (bytes4 key)
            idx = cbor_bytes.find(b"\x04ipfs")
        if idx == -1:
            return None
        # After the key, expect bytes[34]: 0x58 0x22 + 34 bytes
        key_end = idx + 5  # len('ipfs') + 1 byte for cbor key prefix
        if key_end + 2 > len(cbor_bytes):
            return None
        # CBOR bytes(34) = 0x58 0x22 <34 bytes>
        if cbor_bytes[key_end] == 0x58 and cbor_bytes[key_end + 1] == 0x22:
            multihash = cbor_bytes[key_end + 2 : key_end + 36]
        # CBOR bytes(34) as direct bytes value
        elif cbor_bytes[key_end] == 0x98 or cbor_bytes[key_end] == 0x42:
            multihash = cbor_bytes[key_end + 1 : key_end + 35]
        else:
            # Direct 34-byte value
            multihash = cbor_bytes[key_end : key_end + 34]
        if len(multihash) == 34 and multihash[:2] == b"\x12\x20":
            return _b58encode(multihash)
    except Exception as exc:  # noqa: BLE001
        logger.debug("CBOR CID extraction failed: %s", exc)
    return None


_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    """Base58 encode (for IPFS CIDv0 QmXxx)."""
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r : r + 1])
    # leading zeros
    for byte in data:
        if byte == 0:
            result.append(b"1")
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


# ---------------------------------------------------------------------------
# Sourcify v2 helpers (step 1, F8, F46)
# ---------------------------------------------------------------------------


def _sourcify_to_candidate(data: dict[str, Any], chain_id: int, address: str) -> Candidate | None:
    """Convert a Sourcify v2 ?fields=all response to a Candidate (05 3.3, F8)."""
    if not data:
        return None

    match_type = data.get("match")  # "exact_match" | "match" | None
    if not match_type:
        return None

    compilation = data.get("compilation", {})
    std_json = data.get("stdJsonInput")
    compiler_ver: str | None = None
    settings: dict[str, Any] = {}
    language = "solidity"

    raw_files: dict[str, str] = {}
    if std_json:
        language = std_json.get("language", "Solidity").lower()
        settings = std_json.get("settings", {})
        sources_map = std_json.get("sources", {})
        for path, src_obj in sources_map.items():
            content = src_obj.get("content", "")
            if content:
                raw_files[path] = content
        compiler_ver = settings.get("compilationTarget", {})

    if compilation:
        language = compilation.get("language", language).lower()
        compiler_ver = compilation.get("compilerVersion") or compiler_ver
        if not settings:
            settings = compilation.get("settings", {})

    compiler_obj: Compiler | None = None
    if compiler_ver:
        compiler_obj = Compiler(version=str(compiler_ver), version_pinned_by="sourcify")

    chain_str = str(chain_id)
    addr_lower = address.lower()

    # make_candidate() is the single enforcement point for path safety (security gate)
    return make_candidate(
        provider="sourcify",
        raw_files=raw_files,
        language=language,
        compiler=compiler_obj,
        settings=settings,
        std_json_input=std_json,
        entry_contract=(compilation or {}).get("fullyQualifiedName"),  # "path:Name" (05 3.3)
        explorer_verified=True,
        sourcify_match=match_type,
        constructor_args_hex=data.get("deployment", {}).get("constructorArguments"),
        source_url=f"{SOURCIFY_BASE}/v2/contract/{chain_str}/{addr_lower}",
        fetched_at=_now_iso(),
        _caller_context=f"sourcify {chain_id}/{address}",
    )


async def fetch_sourcify(
    client: httpx.AsyncClient,
    chain_id: int,
    address: str,
) -> Candidate | None:
    """Step 1a: Sourcify v2 GET ?fields=all (F8)."""
    url = f"{SOURCIFY_BASE}/v2/contract/{chain_id}/{address}?fields=all"
    try:
        resp = await _get(client, url, "sourcify")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            logger.debug("Sourcify %s returned %d", url, resp.status_code)
            return None
        data = resp.json()
        return _sourcify_to_candidate(data, chain_id, address)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Sourcify step 1a failed for %s/%s: %s", chain_id, address, exc)
        return None


def _unverified(candidate: Candidate) -> Candidate:
    """A record of the same address on another chain is a candidate only (05 4.2 step 1, F46):
    the code there can differ (deterministic deployers, address squatting), so it carries no
    verification or match; the 13.1 rebuild against this chain's runtime decides (R2)."""
    candidate.explorer_verified = False
    candidate.sourcify_match = None
    return candidate


async def fetch_sourcify_all_chains(
    client: httpx.AsyncClient,
    address: str,
) -> list[Candidate]:
    """Step 1b: Sourcify all-chains lookup (F46)."""
    url = f"{SOURCIFY_BASE}/v2/contract/all-chains/{address}?fields=all"
    try:
        resp = await _get(client, url, "sourcify")
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            return []
        data = resp.json()
        # Response is a list of per-chain records
        results = []
        if isinstance(data, list):
            for rec in data:
                cid = rec.get("chainId", 0)
                candidate = _sourcify_to_candidate(rec, int(cid), address)
                if candidate is not None:
                    results.append(_unverified(candidate))
        elif isinstance(data, dict):
            for chain_key, rec in data.items():
                try:
                    cid = int(chain_key)
                except ValueError:
                    continue
                candidate = _sourcify_to_candidate(rec, cid, address)
                if candidate is not None:
                    results.append(_unverified(candidate))
        return results
    except Exception as exc:  # noqa: BLE001
        logger.debug("Sourcify all-chains failed for %s: %s", address, exc)
        return []


# ---------------------------------------------------------------------------
# eth-bytecode-db sources:search (step 2, F45)
# NOTE: never use sources:search-all with chain+address (F45, SCOPE X18)
# ---------------------------------------------------------------------------


async def fetch_eth_bytecode_db(
    client: httpx.AsyncClient,
    runtime_bytecode: str,
) -> Candidate | None:
    """Step 2: eth-bytecode-db sources:search with deployed bytecode only (F45).

    No chain or address is passed — this avoids triggering the Etherscan import
    path (F45, SCOPE X18). Only 'sources:search' (bytecode-only) is called.
    """
    url = f"{ETH_BYTECODE_DB_BASE}/sources:search"
    body = {"deployedBytecode": runtime_bytecode}
    try:
        resp = await _post(client, url, "eth_bytecode_db", json=body)
        if resp.status_code not in (200, 201):
            return None
        data = resp.json()
        sources = (
            data.get("ethBytecodeDbSources")
            or data.get("allianceSources")
            or data.get("sourcifySources")
            or []
        )
        if not sources:
            return None
        src = sources[0]
        raw_files_map = src.get("sourceFiles", {})
        compiler_ver = src.get("compilerVersion", "")
        settings = src.get("compilationArtifacts", {}) or {}
        compiler_obj = Compiler(version=compiler_ver, version_pinned_by="eth_bytecode_db") if compiler_ver else None
        raw_files = {k: v.get("content", "") for k, v in raw_files_map.items()} if isinstance(raw_files_map, dict) else {}
        # make_candidate() is the single enforcement point for path safety (security gate)
        return make_candidate(
            provider="eth_bytecode_db",
            raw_files=raw_files,
            language=src.get("language", "solidity").lower(),
            compiler=compiler_obj,
            settings=settings,
            std_json_input=None,
            entry_contract=src.get("contractName"),
            explorer_verified=False,  # bytecode similarity, not a verification of this address
            sourcify_match=None,
            source_url=url,
            fetched_at=_now_iso(),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("eth-bytecode-db failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Step 3: Sourcify similarity verify — PUBLIC WRITE, OFF BY DEFAULT (R5, F44)
# ---------------------------------------------------------------------------


async def fetch_sourcify_similarity(
    client: httpx.AsyncClient,
    chain_id: int,
    address: str,
    *,
    similarity_verify: bool = False,
) -> Candidate | None:
    """Step 3: Sourcify similarity verify (F44).

    NEVER called in tests. Only enabled with similarity_verify=True (R5).
    This is a public write: Sourcify pushes the verification to Routescan and
    attempts Etherscan (research/05 F44, research/06 section "Important side effect").
    """
    if not similarity_verify:
        return None
    url = f"{SOURCIFY_BASE}/v2/verify/similarity/{chain_id}/{address}"
    try:
        resp = await _post(client, url, "sourcify")
        if resp.status_code not in (200, 201):
            return None
        data = resp.json()
        return _sourcify_to_candidate(data, chain_id, address)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Sourcify similarity failed for %s/%s: %s", chain_id, address, exc)
        return None


# ---------------------------------------------------------------------------
# Step 4: IPFS metadata (F47)
# ---------------------------------------------------------------------------


async def fetch_ipfs_metadata(
    client: httpx.AsyncClient,
    runtime_bytecode: str,
) -> Candidate | None:
    """Step 4: Fetch Sourcify metadata.json from IPFS using the CBOR CID (F47).

    Tries gateways in order: Filebase, Lighthouse, Pinata, 4everland.
    """
    cid = extract_cbor_cid(runtime_bytecode)
    if not cid:
        return None

    for gateway_template in IPFS_GATEWAYS:
        url = gateway_template.format(cid=cid)
        host = url.split("/")[2]
        limiter_key = f"ipfs:{host}"
        try:
            resp = await _get(client, url, limiter_key, follow_redirects=True)
            if resp.status_code != 200:
                continue
            metadata = resp.json()
            # metadata.json contains sources and compiler info
            compiler_info = metadata.get("compiler", {})
            settings = metadata.get("settings", {})
            language = metadata.get("language", "Solidity").lower()
            compiler_ver = compiler_info.get("version", "")
            # Sources may be embedded or referenced by hash
            raw_sources: dict[str, str] = {}
            for path, src_obj in metadata.get("sources", {}).items():
                if "content" in src_obj:
                    raw_sources[path] = src_obj["content"]
            compiler_obj = Compiler(version=compiler_ver, version_pinned_by="ipfs") if compiler_ver else None
            # make_candidate() is the single enforcement point for path safety (security gate)
            return make_candidate(
                provider="ipfs",
                raw_files=raw_sources,
                language=language,
                compiler=compiler_obj,
                settings=settings,
                std_json_input=None,
                entry_contract=None,
                explorer_verified=False,
                sourcify_match=None,
                source_url=url,
                fetched_at=_now_iso(),
                _caller_context=f"ipfs:{cid}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("IPFS gateway %s failed for CID %s: %s", host, cid, exc)
            continue
    return None


# ---------------------------------------------------------------------------
# Main fetch orchestrator (05 4.2)
# ---------------------------------------------------------------------------


async def fetch_source(
    chain_id: int,
    address: str,
    runtime_bytecode: str,
    *,
    user_candidate: Candidate | None = None,
    similarity_verify: bool = False,
    etherscan_licence: bool = False,
) -> list[Candidate]:
    """Fetch EVM source candidates in order (05 4.2 steps 1, 2, 4, 6).

    R1: Stop after Sourcify exact/match if no user_candidate.
    R3: Callers should check cache keyed on (chain_id, address, runtime_code_hash).
    R4: Per-provider rate limiter, 3 retries, 10-min down on 403 text/html.
    R5: Similarity verify (step 3) is off unless similarity_verify=True.
    """
    candidates: list[Candidate] = []
    address_lower = address.lower()
    if not address_lower.startswith("0x"):
        address_lower = "0x" + address_lower

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # Step 1a: Sourcify v2 for the specific chain
        sourcify_candidate = await fetch_sourcify(client, chain_id, address_lower)
        if sourcify_candidate is not None:
            candidates.append(sourcify_candidate)
            # R1: Stop here if exact/match and no user candidate
            if user_candidate is None and sourcify_candidate.sourcify_match in ("exact_match", "match"):
                if user_candidate is not None:
                    candidates.append(user_candidate)
                return candidates

        # Step 1b: all-chains lookup (F46) — yields additional candidates from other chains
        # (used for cross-chain deployed contracts; we add unique candidates not already found)
        all_chain_candidates = await fetch_sourcify_all_chains(client, address_lower)
        existing_shas = {c.sha256 for c in candidates}
        for ac in all_chain_candidates:
            if ac.sha256 not in existing_shas:
                candidates.append(ac)
                existing_shas.add(ac.sha256)

        # Step 2: eth-bytecode-db sources:search (bytecode-only, no chain/address, F45)
        if runtime_bytecode and runtime_bytecode not in ("0x", "0x0"):
            bytecode_candidate = await fetch_eth_bytecode_db(client, runtime_bytecode)
            if bytecode_candidate is not None and bytecode_candidate.sha256 not in existing_shas:
                candidates.append(bytecode_candidate)
                existing_shas.add(bytecode_candidate.sha256)

        # Step 3: Sourcify similarity verify — public write, OFF by default (R5, F44)
        if similarity_verify:
            sim_candidate = await fetch_sourcify_similarity(
                client, chain_id, address_lower, similarity_verify=similarity_verify
            )
            if sim_candidate is not None and sim_candidate.sha256 not in existing_shas:
                candidates.append(sim_candidate)
                existing_shas.add(sim_candidate.sha256)
                # After similarity, try step 1 again per the plan table
                new_sourcify = await fetch_sourcify(client, chain_id, address_lower)
                if new_sourcify is not None and new_sourcify.sha256 not in existing_shas:
                    candidates.append(new_sourcify)
                    existing_shas.add(new_sourcify.sha256)

        # Step 4: IPFS metadata
        if runtime_bytecode and runtime_bytecode not in ("0x", "0x0"):
            ipfs_candidate = await fetch_ipfs_metadata(client, runtime_bytecode)
            if ipfs_candidate is not None and ipfs_candidate.sha256 not in existing_shas:
                candidates.append(ipfs_candidate)
                existing_shas.add(ipfs_candidate.sha256)

        # Step 5: Etherscan — stub; only behind etherscan_licence flag (F1, SCOPE X18)
        if etherscan_licence:
            # TODO: implement when Etherscan Advanced licence is acquired (F1)
            logger.debug("Etherscan step 5 not yet implemented (etherscan_licence=True)")

    # Step 6: user/repo candidate
    if user_candidate is not None and user_candidate.sha256 not in existing_shas:
        candidates.append(user_candidate)

    return candidates
