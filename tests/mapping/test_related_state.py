"""Tests for related contract classification and state-parameter probing (feat/context-related-state).

All tests use in-process AsyncMocks; no live network access.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock


def _probe(rpc):
    """Give a test double the capped probe the code requires: delegate to its eth_call stub,
    None on error or on fewer than 32 bytes of return data (RpcClient.eth_call_probe rules)."""
    async def eth_call_probe(address, data, block=None, **_limits):
        try:
            raw = await rpc.eth_call(address, data, block=block)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) - 2 < 64:
            return None
        return raw
    rpc.eth_call_probe = eth_call_probe


import pytest

from soken_review.mapping.related import (
    MAX_STATE_PROBES,
    _decode_address_array,
    _decode_uint,
    _getter_names_to_probe,
    _role_label_from_key,
    classify_related_contracts,
    load_related_contracts,
    state_parameter_facts,
    write_related_contracts,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OWNER = "0x" + "ab" * 20
GOVERNANCE = "0x" + "cd" * 20
SAFE_SINGLETON = "0x" + "11" * 20

# Facts list as returned by onchain_facts() with owner and governance set
def _facts(owner: str = OWNER, governance: str | None = None) -> list[dict]:
    out = [
        {"key": "onchain.owner", "value": owner},
        {"key": "onchain.balance", "value": "1000"},  # not an address - should be skipped
    ]
    if governance:
        out.append({"key": "onchain.governance", "value": governance})
    return out


def _map(*names: str) -> dict:
    """Build a minimal map doc with named entry functions."""
    spans = [{"id": f"s{i}", "name": n} for i, n in enumerate(names)]
    return {
        "spans": spans,
        "semantic": {
            "functions": [{"span": s["id"], "is_entry": True} for s in spans],
            "state_vars": [],
        },
    }


# ---------------------------------------------------------------------------
# related_contract_facts: address extraction
# ---------------------------------------------------------------------------

def test_role_label_from_key():
    assert _role_label_from_key("onchain.owner") == "owner"
    assert _role_label_from_key("onchain.governance") == "governance"
    assert _role_label_from_key("onchain.eip1967.admin") == "eip1967"
    assert _role_label_from_key("onchain.pending_owner") == "pending_owner"


@pytest.mark.asyncio
async def test_classify_eoa():
    """get_code returns empty → kind = eoa."""
    rpc = AsyncMock(spec=["get_code"])
    rpc.get_code = AsyncMock(return_value="0x")
    facts = _facts(owner=OWNER)
    results = await classify_related_contracts(rpc, 100, facts)
    assert len(results) == 1
    assert results[0]["address"] == OWNER.lower()
    assert results[0]["kind"] == "eoa"
    assert results[0]["role"] == "owner"


@pytest.mark.asyncio
async def test_classify_generic_contract():
    """Non-Safe bytecode → kind = contract."""
    rpc = AsyncMock(spec=["get_code", "eth_call", "eth_call_probe"])
    rpc.get_code = AsyncMock(return_value="0x6080604052")  # standard EVM init bytecode
    rpc.eth_call = AsyncMock(return_value="0x" + "0" * 64)  # getMinDelay returns 0 → no entry
    _probe(rpc)
    facts = _facts(owner=OWNER)
    results = await classify_related_contracts(rpc, 100, facts)
    assert results[0]["kind"] == "contract"


@pytest.mark.asyncio
async def test_classify_contract_with_min_delay():
    """Contract whose getMinDelay() returns non-zero: min_delay_s is set."""
    delay = 86400  # 1 day
    rpc = AsyncMock(spec=["get_code", "eth_call", "eth_call_probe"])
    rpc.get_code = AsyncMock(return_value="0x6080604052")
    # eth_call returns non-zero delay only for the getMinDelay selector
    async def _call(address, data, block=None):
        if data == "0xf27a0c92":
            return "0x" + format(delay, "064x")
        return "0x" + "0" * 64
    rpc.eth_call = AsyncMock(side_effect=_call)
    _probe(rpc)
    results = await classify_related_contracts(rpc, 100, _facts(owner=OWNER))
    assert results[0]["kind"] == "contract"
    assert results[0].get("min_delay_s") == delay


@pytest.mark.asyncio
async def test_classify_get_code_failure_returns_eoa():
    """A failed eth_getCode leaves the entry at the eoa default, never raises."""
    rpc = AsyncMock(spec=["get_code"])
    rpc.get_code = AsyncMock(side_effect=RuntimeError("rpc down"))
    results = await classify_related_contracts(rpc, 100, _facts(owner=OWNER))
    assert results[0]["kind"] == "eoa"   # graceful fallback


@pytest.mark.asyncio
async def test_classify_zero_address_skipped():
    """Zero address in facts must not appear in related_contracts."""
    facts = [{"key": "onchain.owner", "value": "0x" + "0" * 40}]
    rpc = AsyncMock()
    results = await classify_related_contracts(rpc, 100, facts)
    assert results == []


@pytest.mark.asyncio
async def test_classify_deduplicates_addresses():
    """Same address from two different fact keys → one entry."""
    facts = [
        {"key": "onchain.owner", "value": OWNER},
        {"key": "onchain.governance", "value": OWNER},  # same address
    ]
    rpc = AsyncMock(spec=["get_code", "eth_call", "eth_call_probe"])
    rpc.get_code = AsyncMock(return_value="0x")
    rpc.eth_call = AsyncMock(return_value="0x" + "0" * 64)
    _probe(rpc)
    results = await classify_related_contracts(rpc, 100, facts)
    # Deduplication: only one entry, first role wins
    assert len(results) == 1
    assert results[0]["role"] == "owner"


@pytest.mark.asyncio
async def test_classify_safe_multisig_reads_owners_and_threshold():
    """Safe proxy code → multisig; owners and threshold are read."""
    from soken_review.mapping.facts import _safe_proxy_prefix, _safe_singletons

    prefix, _ = _safe_proxy_prefix()
    # Construct minimal Safe proxy bytecode: prefix + 0xFE + singleton address
    safe_code = "0x" + prefix.hex() + "fe" + "00" * 10
    # singleton address (a known Safe singleton)
    singletons = list(_safe_singletons())
    if not singletons:
        pytest.skip("no safe singletons loaded")
    singleton_addr = singletons[0]  # e.g. "0x41675c099f32341bf84bfc5382af534df5c7461a"
    singleton_padded = "0x" + singleton_addr[2:].zfill(64)

    owners_abi = _encode_address_array([GOVERNANCE])  # one owner

    async def _call(address, data, block=None):
        if data == "0xa0e67e2b":  # getOwners
            return "0x" + owners_abi.hex()
        if data == "0xe75235b8":  # getThreshold
            return "0x" + format(1, "064x")
        return "0x" + "0" * 64

    rpc = AsyncMock(spec=["get_code", "get_storage_at", "eth_call", "eth_call_probe"])
    rpc.get_code = AsyncMock(return_value=safe_code)
    rpc.get_storage_at = AsyncMock(return_value=singleton_padded)
    rpc.eth_call = AsyncMock(side_effect=_call)
    _probe(rpc)

    results = await classify_related_contracts(rpc, 100, _facts(owner=OWNER))
    entry = results[0]
    assert entry["kind"] == "multisig", entry
    assert entry.get("threshold") == 1
    assert entry.get("owners_count") == 1
    assert GOVERNANCE.lower() in [o.lower() for o in (entry.get("owners") or [])]


def _encode_address_array(addresses: list[str]) -> bytes:
    """Manually encode a Solidity address[] for ABI testing."""
    count = len(addresses)
    # offset to array data (32 bytes offset, pointing to position 32)
    result = (32).to_bytes(32, "big")
    result += count.to_bytes(32, "big")
    for addr in addresses:
        padded = int(addr, 16).to_bytes(20, "big")
        result += b"\x00" * 12 + padded
    return result


# ---------------------------------------------------------------------------
# State parameter facts
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_state_parameter_facts_reads_new_getter():
    """A getter not in HOLDER_GETTERS is probed and recorded as state.<snake>."""
    rpc = AsyncMock(spec=["eth_call", "eth_call_probe"])
    fee_value = 500  # 500 bps
    rpc.eth_call = AsyncMock(return_value="0x" + format(fee_value, "064x"))
    _probe(rpc)

    map_doc = _map("assetListingDelay", "oracleTimeout")
    facts = await state_parameter_facts(rpc, "0x" + "a" * 40, 100, map_doc, None)
    keys = {f["key"] for f in facts}
    assert "state.asset_listing_delay" in keys
    assert "state.oracle_timeout" in keys


@pytest.mark.asyncio
async def test_state_parameter_facts_skips_already_read_getters():
    """owner, totalSupply, decimals and all HOLDER_GETTERS must not be re-probed."""
    from soken_review.mapping.related import _ALREADY_READ
    rpc = AsyncMock(spec=["eth_call", "eth_call_probe"])
    rpc.eth_call = AsyncMock(return_value="0x" + "0" * 64)
    _probe(rpc)

    already = list(_ALREADY_READ)[:5]
    map_doc = _map(*already)
    await state_parameter_facts(rpc, "0x" + "a" * 40, 100, map_doc, None)
    # All-zero return → None decode → no facts, AND they should have been skipped anyway
    assert rpc.eth_call.await_count == 0


@pytest.mark.asyncio
async def test_state_parameter_facts_zero_return_skipped():
    """A getter returning all-zero (the Solidity default) produces no fact."""
    rpc = AsyncMock(spec=["eth_call", "eth_call_probe"])
    rpc.eth_call = AsyncMock(return_value="0x" + "0" * 64)
    _probe(rpc)
    map_doc = _map("sellCooldown")
    facts = await state_parameter_facts(rpc, "0x" + "a" * 40, 100, map_doc, None)
    assert not facts


@pytest.mark.asyncio
async def test_state_parameter_facts_address_like_value_decoded():
    """A return value that looks like an address is decoded as an address."""
    addr_value = "0x" + "0" * 24 + "ab" * 20  # top 12 bytes zero, bottom 20 non-zero
    rpc = AsyncMock(spec=["eth_call", "eth_call_probe"])
    rpc.eth_call = AsyncMock(return_value=addr_value)
    _probe(rpc)
    map_doc = _map("fillAgent")
    facts = await state_parameter_facts(rpc, "0x" + "a" * 40, 100, map_doc, None)
    f = next((f for f in facts if f["key"] == "state.fill_agent"), None)
    assert f is not None, facts
    assert f["value"].startswith("0x"), f["value"]
    assert len(f["value"]) == 42  # 0x + 40 hex chars


@pytest.mark.asyncio
async def test_state_parameter_facts_bool_naming_convention():
    """is*/paused returns 'true'/'false' for bool-like values."""
    rpc = AsyncMock(spec=["eth_call", "eth_call_probe"])
    rpc.eth_call = AsyncMock(return_value="0x" + "0" * 63 + "1")  # value = 1
    _probe(rpc)
    map_doc = _map("paused", "isActive")
    facts = await state_parameter_facts(rpc, "0x" + "a" * 40, 100, map_doc, None)
    for f in facts:
        assert f["value"] in ("true", "false"), f["value"]


@pytest.mark.asyncio
async def test_state_parameter_facts_rpc_failure_is_graceful():
    """A failed eth_call for a getter produces no fact, never raises."""
    rpc = AsyncMock(spec=["eth_call", "eth_call_probe"])
    rpc.eth_call = AsyncMock(side_effect=RuntimeError("rpc down"))
    _probe(rpc)
    map_doc = _map("assetListingDelay")
    facts = await state_parameter_facts(rpc, "0x" + "a" * 40, 100, map_doc, None)
    assert facts == []


@pytest.mark.asyncio
async def test_state_parameter_facts_capped_at_max():
    """No more than MAX_STATE_PROBES eth_call calls are made."""
    rpc = AsyncMock(spec=["eth_call", "eth_call_probe"])
    rpc.eth_call = AsyncMock(return_value="0x" + format(1, "064x"))
    _probe(rpc)
    # Many names to probe
    names = [f"getter{i}" for i in range(MAX_STATE_PROBES + 20)]
    map_doc = _map(*names)
    await state_parameter_facts(rpc, "0x" + "a" * 40, 100, map_doc, None)
    assert rpc.eth_call.await_count <= MAX_STATE_PROBES


# ---------------------------------------------------------------------------
# _getter_names_to_probe
# ---------------------------------------------------------------------------

def test_getter_names_to_probe_excludes_already_read():
    map_doc = _map("owner", "governance", "sellCooldown", "assetListingDelay")
    names = _getter_names_to_probe(map_doc, None)
    # 'owner' is in _ALREADY_READ, 'governance' is in HOLDER_GETTERS → both excluded
    assert "owner" not in names
    assert "governance" not in names
    # sellCooldown and assetListingDelay are new
    assert "sellCooldown" in names or "assetListingDelay" in names


def test_getter_names_from_state_vars():
    spans = []
    state_vars = [{"id": "p:T.fee", "name": "fee"}, {"id": "p:T.maxDeposit", "name": "maxDeposit"}]
    map_doc = {"spans": spans, "semantic": {"functions": [], "state_vars": state_vars}}
    names = _getter_names_to_probe(map_doc, None)
    assert "fee" in names
    assert "maxDeposit" in names


# ---------------------------------------------------------------------------
# ABI helpers
# ---------------------------------------------------------------------------

def test_decode_uint():
    assert _decode_uint("0x" + format(7200, "064x")) == 7200
    assert _decode_uint("0x" + "0" * 64) == 0
    assert _decode_uint(None) is None
    assert _decode_uint("bad") is None


def test_decode_address_array_empty():
    assert _decode_address_array(b"", 0) == []


def test_decode_address_array_one():
    data = _encode_address_array_bytes([OWNER])
    result = _decode_address_array(data, 0)
    assert len(result) == 1
    assert result[0].lower() == OWNER.lower()


def _encode_address_array_bytes(addresses: list[str]) -> bytes:
    count = len(addresses)
    result = (32).to_bytes(32, "big")
    result += count.to_bytes(32, "big")
    for addr in addresses:
        n = int(addr, 16)
        result += n.to_bytes(32, "big")
    return result


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_write_load_related_contracts_roundtrip(tmp_path: Path):
    job_id = "job_REL0000000000000000000000"
    contracts = [{"address": OWNER, "kind": "eoa", "role": "owner"}]
    write_related_contracts(tmp_path, job_id, contracts)
    loaded = load_related_contracts(tmp_path, job_id)
    assert loaded == contracts


def test_load_related_contracts_missing_returns_empty(tmp_path: Path):
    assert load_related_contracts(tmp_path, "job_ABSENT0000000000000000000") == []


# ---------------------------------------------------------------------------
# review_status detailed response
# ---------------------------------------------------------------------------

def test_review_status_detailed_includes_related_contracts(tmp_path: Path):
    """_build_status_response with response_format=detailed reads related_contracts.json."""
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.read import set_context
    from soken_review.tools.start_status import _build_status_response

    job_id = "job_DETL0000000000000000000"
    ctx = MemoryJobContext(tmp_path)
    ctx.set_state(job_id, "ready")
    set_context(ctx)

    contracts = [{"address": OWNER, "kind": "eoa", "role": "owner", "verified": None}]
    write_related_contracts(tmp_path, job_id, contracts)

    job = {
        "job_id": job_id,
        "state": "ready",
        "requester_role": "third_party_public_code",
        "ownership_proven": False,
        "context_items": [],
        "error_code": None,
        "error_detail": None,
        "map_status": "partial",
        "analyzer_degraded": False,
        "tier": None,
        "upload_id": None,
    }
    out = _build_status_response(job, "detailed")
    assert "related_contracts" in out, out.keys()
    assert out["related_contracts"] == contracts


def test_review_status_concise_does_not_include_related_contracts(tmp_path: Path):
    """concise response_format must not include related_contracts."""
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.read import set_context
    from soken_review.tools.start_status import _build_status_response

    job_id = "job_DETL0000000000000000001"
    ctx = MemoryJobContext(tmp_path)
    ctx.set_state(job_id, "ready")
    set_context(ctx)

    contracts = [{"address": OWNER, "kind": "eoa", "role": "owner"}]
    write_related_contracts(tmp_path, job_id, contracts)

    job = {
        "job_id": job_id,
        "state": "ready",
        "requester_role": "third_party_public_code",
        "ownership_proven": False,
        "context_items": [],
        "error_code": None,
        "error_detail": None,
        "map_status": "partial",
        "analyzer_degraded": False,
        "tier": None,
        "upload_id": None,
    }
    out = _build_status_response(job, "concise")
    assert "related_contracts" not in out


def test_review_status_detailed_includes_suggested_context(tmp_path: Path):
    """detailed response includes server-discovered project URLs."""
    from soken_review.mapping.project_url import write_suggested_context
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.read import set_context
    from soken_review.tools.start_status import _build_status_response

    job_id = "job_DETL0000000000000000002"
    ctx = MemoryJobContext(tmp_path)
    ctx.set_state(job_id, "ready")
    set_context(ctx)

    suggested = [{"url": "https://example-protocol.com/", "kind": "website", "source_hint": "Token.sol"}]
    write_suggested_context(tmp_path, job_id, suggested)

    job = {
        "job_id": job_id,
        "state": "ready",
        "requester_role": "third_party_public_code",
        "ownership_proven": False,
        "context_items": [],
        "error_code": None,
        "error_detail": None,
        "map_status": "partial",
        "analyzer_degraded": False,
        "tier": None,
        "upload_id": None,
    }
    out = _build_status_response(job, "detailed")
    assert "suggested_context_items" in out
    assert out["suggested_context_items"] == suggested


@pytest.mark.asyncio
async def test_pool_probe_is_capped_and_fails_over(monkeypatch):
    """Production passes an RpcClientPool: it must expose the capped probe and try each endpoint once."""
    from soken_review.adapters.evm import rpc as R

    seen: list[tuple[str, dict]] = []

    async def fake_probe(self, to, data, block=None, **limits):
        seen.append((self._url, limits))
        return None if self._url.endswith("a") else "0x" + "0" * 63 + "1"

    monkeypatch.setattr(R.RpcClient, "eth_call_probe", fake_probe)
    pool = R.RpcClientPool(["https://rpc.example/a", "https://rpc.example/b"])
    out = await pool.eth_call_probe("0x" + "1" * 40, "0x12345678", 100, gas=2_000_000, timeout_s=5.0)
    assert out.endswith("1") and [u for u, _ in seen] == ["https://rpc.example/a", "https://rpc.example/b"]
    assert all(lim["gas"] == 2_000_000 for _, lim in seen)


def test_strict_owner_decode_unknown_on_truncation():
    from soken_review.mapping.related import _decode_address_array_strict

    word = lambda n: n.to_bytes(32, "big")
    owner = b"\x00" * 12 + b"\x11" * 20
    full = word(32) + word(2) + owner + owner
    assert _decode_address_array_strict(full) == ["0x" + "11" * 20] * 2
    assert _decode_address_array_strict(word(32) + word(3) + owner + owner) is None   # declared 3, got 2
    assert _decode_address_array_strict(b"") is None
