"""TRON source fetch (05 section 4.2 TRON column, 4.3).

Fetch order (SCOPE 8, D-ESC):
  Step 1: TronScan contract/info (key, after ToS confirmation) (F24)
  Step 2: Sourcify 728126428 lookup (reuses EVM fetch_sourcify) (F9)
  Step 3-5: not applicable for TRON
  Step 6: user or repo candidate

Runtime: TronGrid getcontractinfo (runtimecode), cross-checked with eth_getCode (F25, F26)
Creation: TronGrid getcontract (bytecode) + TronScan constructor_params (F24, F25)

TronScan API key: TRON_API_KEY env var; keyless endpoint attempted first (4.3, UV5-02).
Rate limiting: outbound.tronscan 2 req/s (R4, limits.yaml).

Sourcify chain_id for TRON: 728126428 (F9).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time
from typing import Any

import httpx

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.evm.fetch import (
    _now_iso,
    fetch_sourcify,
    make_candidate,
)
from soken_review.adapters.tron.address import TronAddressError, b58_to_hex, hex_to_b58

logger = logging.getLogger(__name__)

TRON_CHAIN_ID = 728126428  # Sourcify chain_id for TRON (F9)
TRONSCAN_BASE = "https://apilist.tronscanapi.com"

_TIMEOUT = httpx.Timeout(30.0)
_MAX_RETRIES = 3
_RATE_PER_S = 2.0  # outbound.tronscan (R4, limits.yaml)

# Optional API key (4.3, UV5-02)
_TRON_API_KEY = os.environ.get("TRON_API_KEY", "")


class _TronScanLimiter:
    def __init__(self) -> None:
        self._last: float = 0.0

    async def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        gap = 1.0 / _RATE_PER_S
        if elapsed < gap:
            await asyncio.sleep(gap - elapsed)
        self._last = time.monotonic()


_limiter = _TronScanLimiter()


def _tronscan_headers() -> dict[str, str]:
    h: dict[str, str] = {"Accept": "application/json"}
    if _TRON_API_KEY:
        h["TRON-PRO-API-KEY"] = _TRON_API_KEY
    return h


async def _tronscan_get(client: httpx.AsyncClient, url: str, **kwargs: Any) -> httpx.Response:
    """GET with rate-limiting and 3 retries (R4)."""
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            await _limiter.wait()
            resp = await client.get(url, headers=_tronscan_headers(), **kwargs)
            if resp.status_code == 403 and "text/html" in resp.headers.get("content-type", ""):
                raise RuntimeError("403 text/html from tronscan; marked down")
            return resp
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(2**attempt)
    raise RuntimeError(f"TronScan GET {url} failed after {_MAX_RETRIES} retries") from last_exc


async def _tronscan_post(client: httpx.AsyncClient, url: str, **kwargs: Any) -> httpx.Response:
    """POST with rate-limiting and 3 retries (R4)."""
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            await _limiter.wait()
            resp = await client.post(url, headers=_tronscan_headers(), **kwargs)
            return resp
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(2**attempt)
    raise RuntimeError(f"TronScan POST {url} failed after {_MAX_RETRIES} retries") from last_exc


# ---------------------------------------------------------------------------
# Step 1: TronScan contract/info (F24)
# ---------------------------------------------------------------------------


def _decode_contract_code(contract_code: list[Any] | dict) -> dict[str, str]:
    """Decode TronScan's base64 contract_code[] to {filename: content} dict.

    TronScan returns contract_code as a list of base64-encoded source objects or
    as a dict with name/content entries.

    SECURITY: All keys here are attacker-controlled. This dict MUST be passed to
    make_candidate() (not Candidate() directly) which applies filter_candidate_files /
    safe_store_path to every key.  Unsafe keys (../x.sol, /etc/passwd, backslash paths)
    are dropped by make_candidate with a warning and never reach the file system.
    """
    files: dict[str, str] = {}
    if isinstance(contract_code, list):
        for i, entry in enumerate(contract_code):
            if isinstance(entry, str):
                # Pure base64-encoded source
                try:
                    content = base64.b64decode(entry).decode("utf-8", errors="replace")
                    files[f"contract_{i}.sol"] = content
                except Exception as exc:  # noqa: BLE001
                    logger.debug("base64 decode failed for entry %d: %s", i, exc)
            elif isinstance(entry, dict):
                name = entry.get("name") or entry.get("filename") or f"contract_{i}.sol"
                content_b64 = entry.get("content") or entry.get("code") or ""
                if content_b64:
                    try:
                        content = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        content = content_b64
                else:
                    content = ""
                files[str(name)] = content
    elif isinstance(contract_code, dict):
        for name, val in contract_code.items():
            if isinstance(val, str):
                try:
                    content = base64.b64decode(val).decode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    content = val
                files[name] = content
    return files


async def fetch_tronscan(
    client: httpx.AsyncClient,
    display_address: str,
) -> Candidate | None:
    """Step 1: TronScan contract/info (F24).

    Posts to apilist.tronscanapi.com/api/solidity/contract/info.
    Returns Candidate or None if the contract is unverified or the request fails.
    """
    # First check verify_status via GET /api/contract (F24)
    verify_url = f"{TRONSCAN_BASE}/api/contract"
    try:
        resp = await _tronscan_get(client, verify_url, params={"contract": display_address})
        if resp.status_code == 200:
            rows = resp.json().get("data") or [{}]  # GET /api/contract answers {"data": [{...}]}
            verify_status = (rows[0] or {}).get("verify_status", 0)
            # Meaning of verify_status: UV5-06 (to be settled); 1 = verified is the common interpretation
            if not verify_status:
                return None  # not verified
    except Exception as exc:  # noqa: BLE001
        logger.debug("TronScan verify_status check failed for %s: %s", display_address, exc)
        # Continue to attempt source fetch anyway

    # Fetch full source
    info_url = f"{TRONSCAN_BASE}/api/solidity/contract/info"
    try:
        resp = await _tronscan_post(
            client, info_url, json={"contractAddress": display_address}
        )
        if resp.status_code != 200:
            logger.debug("TronScan contract/info HTTP %d for %s", resp.status_code, display_address)
            return None
        data = resp.json().get("data") or {}  # {"code": 200, "data": {...}}
    except Exception as exc:  # noqa: BLE001
        logger.debug("TronScan contract/info failed for %s: %s", display_address, exc)
        return None

    # Extract source code
    contract_code = data.get("contract_code") or data.get("sourceCode") or data.get("source_code")
    if not contract_code:
        return None

    raw_files = _decode_contract_code(contract_code)
    if not raw_files:
        return None

    # Compiler info
    compiler_str = data.get("compiler") or data.get("compiler_version") or ""
    # TronScan returns "tron-0.8.18" or "0.8.18" style
    if compiler_str:
        compiler_obj = Compiler(version=str(compiler_str), version_pinned_by="tronscan")
    else:
        compiler_obj = None

    # Settings from TronScan
    optimizer_enabled = bool(data.get("optimizer", False))
    optimizer_runs = int(data.get("optimizer_runs", 200) or 200)
    evm_version = str(data.get("evm_version", "") or "")
    if evm_version == "default":  # TronScan placeholder, not a solc value
        evm_version = ""
    via_ir = bool(data.get("via_ir", False))

    settings: dict[str, Any] = {
        "optimizer": {"enabled": optimizer_enabled, "runs": optimizer_runs},
    }
    if evm_version:
        settings["evmVersion"] = evm_version
    if via_ir:
        settings["viaIR"] = True

    constructor_args = data.get("constructor_params") or data.get("constructor_arguments")
    if constructor_args and isinstance(constructor_args, str):
        # Normalize to hex
        if not constructor_args.startswith("0x"):
            constructor_args = "0x" + constructor_args
    else:
        constructor_args = None

    return make_candidate(
        provider="tronscan",
        raw_files=raw_files,
        language="solidity",
        compiler=compiler_obj,
        settings=settings,
        std_json_input=None,
        entry_contract=_entry_contract(raw_files, data.get("contract_name") or data.get("name")),
        explorer_verified=True,
        sourcify_match=None,
        constructor_args_hex=constructor_args,
        source_url=f"{TRONSCAN_BASE}/api/solidity/contract/info",
        fetched_at=_now_iso(),
        _caller_context=f"tronscan {display_address}",
    )


def _entry_contract(files: dict[str, str], name: str | None) -> str | None:
    """"path:Name" (05 3.3) for the file that declares `contract <name>`; None if not exactly one."""
    if not name:
        return None
    pattern = re.compile(rf"\bcontract\s+{re.escape(name)}\b")
    hits = [path for path, text in files.items() if pattern.search(text)]
    return f"{hits[0]}:{name}" if len(hits) == 1 else None


# ---------------------------------------------------------------------------
# Step 2: Sourcify 728126428 lookup (F9)
# ---------------------------------------------------------------------------


async def fetch_sourcify_tron(
    client: httpx.AsyncClient,
    internal_hex: str,
) -> Candidate | None:
    """Step 2: Sourcify lookup for TRON chain_id 728126428 (F9).

    Reuses the EVM Sourcify fetch with TRON chain_id and the 20-byte internal hex address.
    NOTE: '0x' prefix is added for the Sourcify API call (standard EVM hex format).
    """
    address_with_prefix = "0x" + internal_hex.lower()
    return await fetch_sourcify(client, TRON_CHAIN_ID, address_with_prefix)


# ---------------------------------------------------------------------------
# Runtime and creation bytecode fetch (F25, F26)
# ---------------------------------------------------------------------------


async def fetch_tron_runtime(
    display_address: str,
    internal_hex: str,
) -> tuple[str | None, str | None]:
    """Fetch runtime and creation bytecode for a TRON contract.

    Returns: (runtime_hex, creation_hex)
    runtime:  TronGrid getcontractinfo.runtimecode (F25), cross-checked with eth_getCode (F26)
    creation: TronGrid getcontract.bytecode (F25)

    Both may be None on failure.
    """
    from soken_review.adapters.tron.rpc import TronGridClient

    client = TronGridClient()
    runtime_hex: str | None = None
    creation_hex: str | None = None

    try:
        info = await client.get_contract_info(internal_hex)
        rc = info.get("runtimecode") or info.get("runtime_code") or ""
        if rc:
            runtime_hex = rc if rc.startswith("0x") else ("0x" + rc)
    except Exception as exc:  # noqa: BLE001
        logger.debug("TronGrid getcontractinfo failed for %s: %s", display_address, exc)

    # Cross-check with eth_getCode (F26)
    try:
        eth_code = await client.eth_get_code("0x" + internal_hex)
        if eth_code and eth_code != "0x" and runtime_hex:
            # Normalize both (strip 0x, lower)
            rt_norm = runtime_hex.removeprefix("0x").lower()
            eth_norm = eth_code.removeprefix("0x").lower()
            if rt_norm != eth_norm:
                logger.info(
                    "TRON runtime mismatch: TronGrid len=%d, eth_getCode len=%d (using TronGrid)",
                    len(rt_norm),
                    len(eth_norm),
                )
        elif eth_code and eth_code != "0x" and not runtime_hex:
            runtime_hex = eth_code
    except Exception as exc:  # noqa: BLE001
        logger.debug("TronGrid eth_getCode failed for %s: %s", display_address, exc)

    try:
        contract_data = await client.get_contract(internal_hex)
        bc = contract_data.get("bytecode") or contract_data.get("code") or ""
        if bc:
            creation_hex = bc if bc.startswith("0x") else ("0x" + bc)
    except Exception as exc:  # noqa: BLE001
        logger.debug("TronGrid getcontract failed for %s: %s", display_address, exc)

    return runtime_hex, creation_hex


# ---------------------------------------------------------------------------
# Main TRON fetch orchestrator (05 4.2 TRON)
# ---------------------------------------------------------------------------


async def fetch_source_tron(
    display_address: str,
    *,
    user_candidate: Candidate | None = None,
) -> tuple[list[Candidate], str | None, str | None]:
    """Fetch TRON source candidates in order (05 4.2 steps 1, 2, 6).

    Args:
        display_address: TRON base58check address (T...), or 20-byte internal hex.
        user_candidate: user-supplied candidate (step 6).

    Returns:
        (candidates, runtime_hex, creation_hex)
    """
    # Normalize address
    if display_address.startswith("T"):
        try:
            internal_hex = b58_to_hex(display_address)
        except TronAddressError as exc:
            logger.warning("Invalid TRON address %r: %s", display_address, exc)
            return [], None, None
        disp = display_address
    else:
        # Assume 20-byte internal hex (with or without 0x41 prefix)
        raw = display_address.lower().lstrip("0x")
        if len(raw) == 42 and raw.startswith("41"):
            raw = raw[2:]
        if len(raw) != 40:
            logger.warning("Invalid TRON address hex %r", display_address)
            return [], None, None
        internal_hex = raw
        disp = hex_to_b58(internal_hex)

    candidates: list[Candidate] = []
    existing_shas: set[str] = set()

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        # Step 1: TronScan contract/info (F24)
        ts_candidate = await fetch_tronscan(client, disp)
        if ts_candidate is not None:
            candidates.append(ts_candidate)
            existing_shas.add(ts_candidate.sha256)

        # Step 2: Sourcify 728126428 (F9)
        src_candidate = await fetch_sourcify_tron(client, internal_hex)
        if src_candidate is not None and src_candidate.sha256 not in existing_shas:
            candidates.append(src_candidate)
            existing_shas.add(src_candidate.sha256)

    # Step 6: user or repo candidate
    if user_candidate is not None and user_candidate.sha256 not in existing_shas:
        candidates.append(user_candidate)

    # Fetch runtime and creation bytecode
    runtime_hex, creation_hex = await fetch_tron_runtime(disp, internal_hex)

    return candidates, runtime_hex, creation_hex
