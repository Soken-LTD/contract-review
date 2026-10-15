"""Unit tests for EVM proxy detection (05 section 5)."""

from __future__ import annotations

import json
from pathlib import Path

from soken_review.adapters.evm import proxy as proxy_module
from soken_review.adapters.evm.proxy import (
    DIAMOND_CUT_SELECTOR,
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPL_SLOT,
    FACETS_SELECTOR,
    OWNER_SELECTOR,
    SAFE_GET_MODULES_PAGINATED,
    SAFE_GET_OWNERS,
    SAFE_GET_THRESHOLD,
    SAFE_RUNTIMES,
    SAFE_SINGLETON_SLOT,
    ZOS_ADMIN_SLOT,
    ZOS_IMPL_SLOT,
    decode_facets,
    detect_proxy,
    has_delegatecall,
    read_proxy_authority,
    read_proxy_calls,
)

_FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "evm"


def _zero_slots() -> dict[str, str]:
    return {
        EIP1967_IMPL_SLOT: "0x" + "0" * 64,
        EIP1967_ADMIN_SLOT: "0x" + "0" * 64,
        EIP1967_BEACON_SLOT: "0x" + "0" * 64,
        "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7": "0x" + "0" * 64,
        ZOS_IMPL_SLOT: "0x" + "0" * 64,
        ZOS_ADMIN_SLOT: "0x" + "0" * 64,
    }


def test_not_a_proxy_for_regular_contract():
    code = "0x6080604052"  # typical Solidity contract header
    result = detect_proxy(code, _zero_slots())
    assert result.pattern is None
    assert result.pattern_name == "not_a_proxy"


def test_eip1167_minimal_proxy_detection():
    # Construct a minimal proxy bytecode
    impl = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # 20 bytes = 40 hex chars
    code = "0x363d3d373d3d3d363d73" + impl + "5af43d82803e903d91602b57fd5bf3"
    result = detect_proxy(code, _zero_slots())
    assert result.pattern == 1
    assert result.pattern_name == "eip1167_minimal_proxy"
    assert result.implementation == "0x" + impl


def test_eip7702_delegated_eoa():
    impl = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"  # 20 bytes
    code = "0xef0100" + impl
    result = detect_proxy(code, _zero_slots())
    assert result.pattern == 0
    assert result.pattern_name == "eip7702_delegated_eoa"
    assert result.implementation == "0x" + impl


def test_eip1967_transparent_proxy():
    impl_addr = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    admin_addr = "0xcafecafecafecafecafecafecafecafecafecafe"
    slots = _zero_slots()
    slots[EIP1967_IMPL_SLOT] = "0x" + "0" * 24 + impl_addr[2:]
    slots[EIP1967_ADMIN_SLOT] = "0x" + "0" * 24 + admin_addr[2:]
    result = detect_proxy("0x6080604052", slots)
    assert result.pattern == 2
    assert result.pattern_name == "eip1967_transparent"
    assert result.implementation == impl_addr
    assert result.admin == admin_addr


def test_eip1967_uups_proxy():
    impl_addr = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    slots = _zero_slots()
    slots[EIP1967_IMPL_SLOT] = "0x" + "0" * 24 + impl_addr[2:]
    # UUPS code contains upgradeTo selector 3659cfe6
    code = "0x6080604052" + "3659cfe6" + "4f1ef286"
    result = detect_proxy(code, slots)
    assert result.pattern == 2
    assert result.pattern_name == "eip1967_uups"
    assert result.implementation == impl_addr


def test_eip1967_beacon_proxy():
    beacon_addr = "0xbeaconbeaconbeaconbeaconbeaconbeaconbeac"
    slots = _zero_slots()
    slots[EIP1967_BEACON_SLOT] = "0x" + "0" * 24 + beacon_addr[2:]
    result = detect_proxy("0x6080604052", slots)
    assert result.pattern == 3
    assert result.pattern_name == "eip1967_beacon"
    assert result.beacon == beacon_addr
    # implementation deferred to chain_state 1 (beacon.implementation() call)
    assert result.implementation is None


def test_zeppelinos_proxy():
    """USDC uses ZeppelinOS proxy pattern (F11)."""
    usdc_slots = json.loads((_FIXTURE_DIR / "proxy_slots_usdc.json").read_text())
    storage = usdc_slots["slots"]
    # USDC runtime bytecode is a ZeppelinOS proxy, not EIP-1967
    code = "0x6080604052"  # placeholder (not minimal proxy)
    result = detect_proxy(code, storage)
    assert result.pattern == 5
    assert result.pattern_name == "zeppelinos"
    # Implementation: keccak256("org.zeppelinos.proxy.implementation") slot
    assert result.implementation is not None
    assert result.implementation.startswith("0x")
    # Admin: 0x807a96288A1A408dBC13DE2b1d087d10356395d2 (F39)
    assert result.admin is not None
    assert "807a96288" in result.admin.lower()


def test_empty_code_is_not_proxy():
    result = detect_proxy("0x", _zero_slots())
    assert result.pattern is None


# ---------------------------------------------------------------------------
# Patterns 6 (Safe) and 7 (EIP-2535 diamond): bytes captured from Ethereum mainnet
# ---------------------------------------------------------------------------

_LIVE = json.loads((_FIXTURE_DIR / "proxy_patterns_6_7.json").read_text())


def _with_slot0(value: str) -> dict[str, str]:
    slots = _zero_slots()
    slots[SAFE_SINGLETON_SLOT] = value
    return slots


def test_safe_proxies_all_versions_detected():
    """UV5-07: Safe 1.1.1, 1.3.0 and 1.4.1 proxies from mainnet are pattern 6, singleton = slot 0."""
    seen = set()
    for safe in _LIVE["safes"]:
        result = detect_proxy(safe["runtime"], _with_slot0(safe["slot0"]))
        assert result.pattern == 6, safe["address"]
        assert result.pattern_name == "safe"
        assert result.extra["safe_version"] == safe["version"]
        assert result.implementation == "0x" + safe["slot0"][-40:]
        seen.add(safe["version"])
    assert seen == {"1.1.1", "1.3.0", "1.4.1"}


def test_safe_runtime_with_one_byte_changed_is_not_a_safe():
    """The list is exact bytes: a lookalike runtime is never pattern 6."""
    safe = _LIVE["safes"][1]
    code = safe["runtime"][:-2] + ("00" if not safe["runtime"].endswith("00") else "01")
    result = detect_proxy(code, _with_slot0(safe["slot0"]))
    assert result.pattern != 6


def test_safe_list_rows_match_examples():
    """Every row of data/safe_proxy_runtimes.json carries a source, a date and live examples."""
    data = json.loads(
        (Path(proxy_module.__file__).parent / "data" / "safe_proxy_runtimes.json").read_text()
    )
    for row in data["runtimes"]:
        assert row["source_url"].startswith("https://") and row["checked_at"]
        assert row["examples"] and all(e["address"] != e["address"].lower() for e in row["examples"])
    assert set(SAFE_RUNTIMES.values()) == {"1.1.1", "1.3.0", "1.4.1"}


def test_diamond_lifi_detected_with_facets():
    d = _LIVE["diamond"]
    result = detect_proxy(d["runtime"], _zero_slots(), {FACETS_SELECTOR: d["facets_return"]})
    assert result.pattern == 7
    assert result.pattern_name == "eip2535_diamond"
    facets = result.extra["facets"]
    assert len(facets) > 10
    assert all(f["address"].startswith("0x") and len(f["address"]) == 42 for f in facets)
    assert result.extra["diamond_cut_present"] is True
    assert result.implementation is None


def test_diamond_without_facets_call_is_not_a_proxy():
    d = _LIVE["diamond"]
    assert detect_proxy(d["runtime"], _zero_slots()).pattern is None
    assert detect_proxy(d["runtime"], _zero_slots(), {}).pattern is None


def _facets_return(facets: list[tuple[str, list[str]]]) -> str:
    """ABI-encode (address,bytes4[])[] the way solc does."""
    def w(n: int) -> str:
        return format(n, "064x")

    tuples = []
    for addr, sels in facets:
        body = w(int(addr, 16)) + w(64) + w(len(sels)) + "".join(s[2:].ljust(64, "0") for s in sels)
        tuples.append(body)
    offsets, pos = [], 32 * len(tuples)
    for t in tuples:
        offsets.append(w(pos))
        pos += len(t) // 2
    return "0x" + w(32) + w(len(tuples)) + "".join(offsets) + "".join(tuples)


def test_decode_facets_roundtrip_and_rejections():
    good = _facets_return([("0x" + "11" * 20, [FACETS_SELECTOR, DIAMOND_CUT_SELECTOR])])
    assert decode_facets(good) == [{"address": "0x" + "11" * 20, "selectors": [FACETS_SELECTOR, DIAMOND_CUT_SELECTOR]}]
    # empty list, zero address, no selector, loupe missing, truncated, garbage: not a diamond
    assert decode_facets(_facets_return([])) is None
    assert decode_facets(_facets_return([("0x" + "00" * 20, [FACETS_SELECTOR])])) is None
    assert decode_facets(_facets_return([("0x" + "11" * 20, [])])) is None
    assert decode_facets(_facets_return([("0x" + "11" * 20, ["0xdeadbeef"])])) is None
    assert decode_facets(good[:-64]) is None
    assert decode_facets("0x") is None
    assert decode_facets("0x" + "ff" * 64) is None
    assert decode_facets("0xzz") is None


def test_fallback_returning_bytes_is_not_a_diamond():
    """A contract whose fallback echoes 32 bytes for any selector (common) is not pattern 7."""
    assert detect_proxy("0x6080604052", _zero_slots(), {FACETS_SELECTOR: "0x" + "00" * 31 + "01"}).pattern is None


class _FakeRpc:
    def __init__(self, answers: dict[str, str]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    async def eth_call(self, to: str, data: str) -> str:
        self.calls.append(data)
        for prefix, ret in self.answers.items():
            if data.startswith(prefix):
                return ret
        raise RuntimeError("execution reverted")


def _abi_addr_array(addrs: list[str], tail_word: str | None = None) -> str:
    w = lambda n: format(n, "064x")
    head = w(64 if tail_word is not None else 32) + (tail_word or "")
    return "0x" + head + w(len(addrs)) + "".join(a[2:].rjust(64, "0") for a in addrs)


def test_safe_authority_reads_owners_threshold_modules():
    import asyncio

    owners = ["0x" + "aa" * 20, "0x" + "bb" * 20]
    module = "0x" + "cc" * 20
    rpc = _FakeRpc({
        SAFE_GET_OWNERS: _abi_addr_array(owners),
        SAFE_GET_THRESHOLD: "0x" + format(2, "064x"),
        SAFE_GET_MODULES_PAGINATED: _abi_addr_array([module], tail_word="0" * 63 + "1"),
    })
    result = detect_proxy(_LIVE["safes"][2]["runtime"], _with_slot0(_LIVE["safes"][2]["slot0"]))
    auth = asyncio.run(read_proxy_authority(rpc, "0x" + "dd" * 20, result))
    assert auth == {"owners": owners, "threshold": 2, "initialized": True, "modules": [module]}


def test_diamond_authority_owner_and_unreadable_owner():
    import asyncio

    d = _LIVE["diamond"]
    result = detect_proxy(d["runtime"], _zero_slots(), {FACETS_SELECTOR: d["facets_return"]})
    owner = "0x" + "ee" * 20
    auth = asyncio.run(read_proxy_authority(_FakeRpc({OWNER_SELECTOR: "0x" + owner[2:].rjust(64, "0")}), owner, result))
    assert auth == {"owner": owner, "diamond_cut_present": True}
    auth = asyncio.run(read_proxy_authority(_FakeRpc({}), owner, result))
    assert auth["owner"] is None and auth["errors"]


def test_read_proxy_calls_revert_means_no_facets():
    import asyncio

    assert asyncio.run(read_proxy_calls(_FakeRpc({}), "0x" + "dd" * 20)) == {}
    ret = asyncio.run(read_proxy_calls(_FakeRpc({FACETS_SELECTOR: "0x01"}), "0x" + "dd" * 20))
    assert ret == {FACETS_SELECTOR: "0x01"}


# --- pattern 7 needs structural evidence: DELEGATECALL outside PUSH data and CBOR metadata ---


def _fake_facets() -> str:
    return _facets_return([("0x" + "11" * 20, [FACETS_SELECTOR, DIAMOND_CUT_SELECTOR])])


def test_fake_facets_without_delegatecall_is_not_a_diamond():
    # a contract that just returns a well-formed facets() answer: PUSH/MSTORE/RETURN, no DELEGATECALL
    code = "0x6080604052" + "60206000f3"
    assert detect_proxy(code, _zero_slots(), {FACETS_SELECTOR: _fake_facets()}).pattern is None


def test_delegatecall_byte_in_push_data_or_metadata_is_not_evidence():
    in_push = "0x" + "63f4f4f4f4" + "00"                      # PUSH4 0xf4f4f4f4, STOP
    assert not has_delegatecall(in_push)
    meta = "a2646970667358221220" + "f4" * 32 + "64736f6c6343000814" + "0033"  # CBOR tail holds 0xf4
    assert not has_delegatecall("0x6080604052" + "00" + meta)
    assert detect_proxy("0x6080604052" + "00" + meta, _zero_slots(), {FACETS_SELECTOR: _fake_facets()}).pattern is None


def test_real_delegatecall_with_facets_is_a_diamond_marked_self_reported():
    code = "0x" + "366000803760008036600073" + "11" * 20 + "5af4" + "00"  # ... GAS DELEGATECALL STOP
    assert has_delegatecall(code)
    r = detect_proxy(code, _zero_slots(), {FACETS_SELECTOR: _fake_facets()})
    assert r.pattern == 7
    assert r.extra["facets_source"] == "self_reported_loupe"
    assert r.extra["diamond_unit"] is True and r.extra["coverage_note"]


def test_lifi_runtime_has_delegatecall():
    assert has_delegatecall(_LIVE["diamond"]["runtime"])
