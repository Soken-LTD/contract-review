"""Lightweight source-verification check for related contract addresses (feat/context-related-state).

Uses the same egress path as the fetch step (Sourcify v2 via the rate-limited _get helper).
Only ``?fields=compilation`` is requested — no source files are downloaded — so the check is
much lighter than a full ``fetch_sourcify`` call.

Results are cached per ``(chain_id, address_lower)`` for the lifetime of the process so a job
with many related contracts does not hammer Sourcify.

Graceful degradation: any network or parse error returns ``(None, None)`` (unknown), never
raises.  The caller must not infer anything from ``None`` beyond "we could not determine
verification status".
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from ..adapters.evm.fetch import SOURCIFY_BASE, _get  # private helper, same egress path

logger = logging.getLogger(__name__)

# Process-local cache: (chain_id, address_lower) -> (verified, name)
_VERIFY_CACHE: dict[tuple[int, str], tuple[bool | None, str | None]] = {}


def _cache_key(chain_id: int, address: str) -> tuple[int, str]:
    return (chain_id, address.lower())


async def check_sourcify_verified(
    chain_id: int,
    address: str,
    *,
    _http_client: httpx.AsyncClient | None = None,
) -> tuple[bool | None, str | None]:
    """Check Sourcify for verified source of ``address`` on ``chain_id``.

    Returns ``(verified, name)`` where:
    - ``(True, "<ContractName>")``  – Sourcify has an exact_match or match
    - ``(False, None)``             – Sourcify returned 404 (not verified)
    - ``(None, None)``              – unknown (network error or unexpected response)

    Caches per ``(chain_id, address_lower)`` for the process lifetime.

    Args:
        chain_id:     EVM chain ID (e.g. 8453 for Base).
        address:      Contract address (0x-prefixed hex, any case).
        _http_client: Injected client for tests; a fresh client is used when None.
    """
    key = _cache_key(chain_id, address)
    if key in _VERIFY_CACHE:
        return _VERIFY_CACHE[key]

    result = await _do_check(chain_id, address.lower(), _http_client)
    _VERIFY_CACHE[key] = result
    return result


async def _do_check(
    chain_id: int,
    address_lower: str,
    client: httpx.AsyncClient | None,
) -> tuple[bool | None, str | None]:
    """Perform the actual Sourcify query (not cached)."""
    url = f"{SOURCIFY_BASE}/v2/contract/{chain_id}/{address_lower}?fields=compilation"
    try:
        if client is not None:
            resp = await _get(client, url, "sourcify")
        else:
            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await _get(c, url, "sourcify")
    except Exception as exc:  # noqa: BLE001
        logger.debug("verify: Sourcify check failed for %s/%s: %s", chain_id, address_lower, type(exc).__name__)
        return None, None

    if resp.status_code == 404:
        return False, None
    if resp.status_code != 200:
        logger.debug("verify: Sourcify returned %d for %s/%s", resp.status_code, chain_id, address_lower)
        return None, None

    try:
        data: dict[str, Any] = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.debug("verify: JSON parse error for %s/%s: %s", chain_id, address_lower, exc)
        return None, None

    match_type = data.get("match")
    if not match_type:
        return False, None

    # Extract the contract name from compilation.fullyQualifiedName ("path:Name") or contractName
    # The name is third-party data shown to the model and printed in the report: accept only a
    # Solidity identifier, anything else is dropped (the verified status still stands).
    compilation = data.get("compilation") if isinstance(data.get("compilation"), dict) else {}
    fqn = compilation.get("fullyQualifiedName")
    name = fqn.rpartition(":")[2] if isinstance(fqn, str) else None
    if not name:
        name = compilation.get("contractName") if isinstance(compilation.get("contractName"), str) else None
    if name is not None and not _IDENT_RE.fullmatch(name):
        name = None

    return True, name


_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]{0,63}")


def clear_verify_cache() -> None:
    """Clear the process-local verification cache (for tests)."""
    _VERIFY_CACHE.clear()
