"""One job for a proxy and for related contracts (matrix run 2026-10-31: Venus, Magnum).

A proxy job reviews the implementation source, keeps the proxy as the address whose state is read,
and pins the proxy's own source as related `proxy`. Related contracts named at review_start are
pinned under `_related/<name>/`, in scope, kept out of the main build.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.evm import proxy as proxy_mod
from soken_review.adapters.evm import related_sources as rel
from soken_review.mapping.facts import static_facts
from soken_review.pinning.store import PinnedSource
from soken_review.tools.start_status import _proxy_related_status
from tests.worker.test_supervisor import FakeStore, _make_supervisor

PROXY = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
IMPL = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
ADMIN = "0x807a96288a1a408dbc13de2b1d087d10356395d2"
BEACON = "0x" + "be" * 20
PROXY_CODE = "0x6080604052" + "11" * 40
IMPL_CODE = "0x6080604052" + "22" * 80
ZERO = "0x" + "0" * 64


def _word(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


class FakeRpc:
    """eth_getCode / eth_getStorageAt / eth_call at a pinned block, from dicts."""

    def __init__(self, code: dict[str, str], slots: dict[str, str] | None = None,
                 calls: dict[tuple[str, str], str] | None = None, fail: bool = False) -> None:
        self.code = {k.lower(): v for k, v in code.items()}
        self.slots = slots or {}
        self.calls = calls or {}
        self.fail = fail
        self.answered_by = "rpc.test"

    async def get_code(self, address: str, block=None) -> str:
        if self.fail:
            raise RuntimeError("down")
        return self.code.get(address.lower(), "0x")

    async def get_storage_at(self, address: str, slot: str, block=None) -> str:
        if self.fail:
            raise RuntimeError("down")
        return self.slots.get(slot, ZERO)

    async def eth_call(self, to: str, data: str, block=None, state_override=None) -> str:
        key = (to.lower(), data)
        if key not in self.calls:
            raise RuntimeError("execution reverted")
        return self.calls[key]


# ---------------------------------------------------------------------------- resolve_proxy


@pytest.mark.asyncio
async def test_transparent_proxy_follows_the_implementation():
    rpc = FakeRpc({PROXY: PROXY_CODE, IMPL: IMPL_CODE},
                  {proxy_mod.EIP1967_IMPL_SLOT: _word(IMPL), proxy_mod.EIP1967_ADMIN_SLOT: _word(ADMIN)})
    rec = await proxy_mod.resolve_proxy(rpc, PROXY, PROXY_CODE)
    assert rec["pattern_name"] == "eip1967_transparent"
    assert rec["proxy"] == PROXY and rec["implementation"] == IMPL and rec["admin"] == ADMIN
    assert rec["proxy_bytecode"] == PROXY_CODE and rec["implementation_bytecode"] == IMPL_CODE
    assert proxy_mod.proxy_summary(rec) == {"pattern_name": "eip1967_transparent", "proxy": PROXY,
                                           "implementation": IMPL, "admin": ADMIN}


@pytest.mark.asyncio
async def test_uups_proxy_is_named_uups():
    code = "0x60806040" + "3659cfe6" + "33" * 10
    rpc = FakeRpc({PROXY: code, IMPL: IMPL_CODE}, {proxy_mod.EIP1967_IMPL_SLOT: _word(IMPL)})
    rec = await proxy_mod.resolve_proxy(rpc, PROXY, code)
    assert rec["pattern_name"] == "eip1967_uups" and rec["admin"] is None


@pytest.mark.asyncio
async def test_beacon_proxy_reads_the_beacon_implementation():
    rpc = FakeRpc({PROXY: PROXY_CODE, IMPL: IMPL_CODE}, {proxy_mod.EIP1967_BEACON_SLOT: _word(BEACON)},
                  {(BEACON, proxy_mod.BEACON_IMPLEMENTATION_SELECTOR): _word(IMPL)})
    rec = await proxy_mod.resolve_proxy(rpc, PROXY, PROXY_CODE)
    assert rec["pattern_name"] == "eip1967_beacon" and rec["implementation"] == IMPL and rec["beacon"] == BEACON


@pytest.mark.asyncio
async def test_minimal_proxy_clone_is_followed():
    code = "0x363d3d373d3d3d363d73" + IMPL[2:] + "5af43d82803e903d91602b57fd5bf3"
    rec = await proxy_mod.resolve_proxy(FakeRpc({PROXY: code, IMPL: IMPL_CODE}), PROXY, code)
    assert rec["pattern_name"] == "eip1167_minimal_proxy" and rec["implementation"] == IMPL


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["not_a_proxy", "impl_without_code", "rpc_down", "beacon_reverts"])
async def test_no_follow_reviews_the_address_as_before(case):
    slots = {proxy_mod.EIP1967_IMPL_SLOT: _word(IMPL)}
    code = {PROXY: PROXY_CODE, IMPL: IMPL_CODE}
    kw: dict = {}
    if case == "not_a_proxy":
        slots = {}
    elif case == "impl_without_code":
        code = {PROXY: PROXY_CODE}
    elif case == "rpc_down":
        kw["fail"] = True
    elif case == "beacon_reverts":
        slots = {proxy_mod.EIP1967_BEACON_SLOT: _word(BEACON)}
    assert await proxy_mod.resolve_proxy(FakeRpc(code, slots, **kw), PROXY, PROXY_CODE) is None


# ---------------------------------------------------------------------------- parse_related

PF = "0x7366388273111e035bbc555cd0f44a5bb3067c32"
NFT = "0xe063710f0de555894342325d42b921f9fc225590"
MAIN = "0x48a2728Db6854f2844c2F77423Ad75876d7c60F7"


def test_related_from_the_schema_field_and_from_old_scope_include():
    src = {"kind": "deployed", "related": [{"address": PF, "name": "PriceFeed"}]}
    scope = {"include": [f"related:NFT={NFT}", "contracts/Main.sol", f"related:{PF.upper().replace('0X', '0x')}"]}
    related, rest = rel.parse_related(src, scope, MAIN)
    assert related == [{"address": PF, "name": "PriceFeed"}, {"address": NFT, "name": "NFT"}]
    assert rest == ["contracts/Main.sol"]


def test_related_default_name_and_reserved_proxy_name():
    related, _ = rel.parse_related({"related": [{"address": PF}, {"address": NFT, "name": "proxy"}]}, None, MAIN)
    assert related[0]["name"] == "c_" + PF[2:12]
    assert related[1]["name"] == "proxy_" + NFT[2:8]


@pytest.mark.parametrize("src,scope,field", [
    ({"related": [{"address": "0x1234"}]}, None, "source.related[0]"),
    ({}, {"include": ["related:Bad Name=" + PF]}, "scope.include[0]"),
    ({"related": [{"address": MAIN.lower()}]}, None, "source.related[0]"),
    ({"related": [{"address": "0x" + f"{i:040x}"} for i in range(1, 7)]}, None, "source.related"),
])
def test_related_rejections_name_the_field(src, scope, field):
    with pytest.raises(rel.RelatedError) as exc:
        rel.parse_related(src, scope, MAIN)
    assert exc.value.field == field


# ---------------------------------------------------------------------------- fetch_related


def _cand(files: dict[str, str], provider: str = "sourcify", entry: str = "contracts/PriceFeed.sol:PriceFeed"):
    return Candidate(provider=provider, files=files, sha256="a" * 64, language="solidity",
                     compiler=Compiler("0.8.28", "sourcify"), settings={}, std_json_input=None,
                     entry_contract=entry, explorer_verified=False, sourcify_match="exact_match")


@pytest.mark.asyncio
async def test_fetch_related_pins_verified_sources_and_fails_soft():
    missing = "0x" + "12" * 20
    unverified = "0x" + "34" * 20
    broken = "0x" + "56" * 20
    rpc = FakeRpc({PF: "0x6080", unverified: "0x6080", broken: "0x6080"})

    async def fake_fetch(chain_id, address, runtime_bytecode):
        if address == broken:
            raise RuntimeError("sourcify 502")
        if address == unverified:
            return [_cand({"x.sol": "x"}, provider="user")]
        return [_cand({"contracts/PriceFeed.sol": "contract PriceFeed {}\n"})]

    entries = [{"name": "PriceFeed", "address": PF}, {"name": "Gone", "address": missing},
               {"name": "Plain", "address": unverified}, {"name": "Broken", "address": broken}]
    with patch.object(rel, "fetch_source", new=fake_fetch):
        files, langs, records = await rel.fetch_related(56, entries, rpc)
    assert files == {"_related/PriceFeed/contracts/PriceFeed.sol": "contract PriceFeed {}\n"}
    assert langs == {"_related/PriceFeed/contracts/PriceFeed.sol": "solidity"}
    by = {r["name"]: r for r in records}
    assert by["PriceFeed"]["status"] == "pinned" and by["PriceFeed"]["path"] == "_related/PriceFeed"
    assert by["Gone"]["status"] == "no_code" and "No contract code" in by["Gone"]["note"]
    assert by["Plain"]["status"] == "no_verified_source" and "verified source" in by["Plain"]["note"]
    assert by["Broken"]["status"] == "fetch_failed"
    assert all("—" not in r.get("note", "") for r in records)   # no em dashes in client text


# ---------------------------------------------------------------------------- facts and status


def test_static_facts_name_the_proxy_and_the_implementation():
    cs = {"block": 100, "address": PROXY, "bytecode": IMPL_CODE,
          "proxy": {"pattern_name": "eip1967_transparent", "proxy": PROXY, "implementation": IMPL,
                    "admin": ADMIN, "proxy_bytecode": PROXY_CODE}}
    facts = {f["key"]: f for f in static_facts(chain_id=1, address=PROXY, chain_state=cs, candidate=None,
                                               nsloc=None, pin_files=1, source_pin=None, analyzers={})}
    assert facts["deploy.address"]["value"] == PROXY
    assert facts["deploy.proxy.implementation"]["value"] == IMPL
    assert facts["deploy.proxy.admin"]["value"] == ADMIN
    assert facts["deploy.proxy.pattern"]["value"] == "eip1967_transparent"
    assert "of the implementation" in facts["deploy.code_hash"]["source"]
    assert facts["deploy.proxy.code_hash"]["value"].startswith("0x")


def test_status_carries_proxy_and_related_lines():
    steps = [
        {"step": "chain_state", "status": "done", "provenance": {"block": 1, "proxy": {"proxy": PROXY, "implementation": IMPL}}},
        {"step": "chain_state", "status": "done", "provenance": {"onchain_facts": 3}},
        {"step": "fetch", "status": "done", "provenance": {"provider": "sourcify", "related": [
            {"name": "PriceFeed", "address": PF, "status": "pinned", "provider": "sourcify", "path": "_related/PriceFeed",
             "files": 1, "entry_contract": "x"}]}},
    ]
    proxy, related = _proxy_related_status(steps)
    assert proxy == {"proxy": PROXY, "implementation": IMPL}
    assert related == [{"name": "PriceFeed", "address": PF, "status": "pinned", "provider": "sourcify",
                        "path": "_related/PriceFeed", "files": 1}]
    assert _proxy_related_status([]) == (None, [])


# ---------------------------------------------------------------------------- worker steps


def _conn_mock():
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    return conn


@pytest.mark.asyncio
async def test_chain_state_0_follows_the_proxy(tmp_path: Path) -> None:
    store = FakeStore()
    store.add_job("job_PROXYCS1", chain_id=1, address=PROXY)
    step = store.add_step("job_PROXYCS1", "chain_state", container=False, units=0, ram_mb=0, max_attempts=3)
    sup = _make_supervisor(store, tmp_path / "pins")
    rpc = FakeRpc({PROXY: PROXY_CODE, IMPL: IMPL_CODE},
                  {proxy_mod.EIP1967_IMPL_SLOT: _word(IMPL), proxy_mod.EIP1967_ADMIN_SLOT: _word(ADMIN)})

    class Pool:
        answered_by = "rpc.test"

        def __init__(self, *_a, **_k):
            pass

        async def block_number(self):
            return 101

        def with_block(self, _b):
            return rpc

    job = {"job_id": "job_PROXYCS1", "chain": "evm", "chain_id": 1, "address": PROXY}
    with patch("soken_review.worker.supervisor.RpcClientPool", Pool), \
         patch("soken_review.worker.supervisor._rpc_urls", return_value=["https://rpc.test"]), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job)), \
         patch.object(sup, "_mark_step", new=AsyncMock()) as mark, \
         patch.object(sup, "_after_chain_state", new=AsyncMock()):
        await sup._run_chain_state_0(step.as_dict())
    cs = json.loads((tmp_path / "work" / "job_PROXYCS1" / "chain_state.json").read_text())
    assert cs["address"] == PROXY and cs["block"] == 100
    assert cs["bytecode"] == IMPL_CODE and cs["self_address"] == IMPL
    assert cs["proxy"]["implementation"] == IMPL and cs["proxy"]["proxy_bytecode"] == PROXY_CODE
    prov = mark.await_args.kwargs["provenance"]
    assert prov["proxy"]["implementation"] == IMPL and "proxy_bytecode" not in prov["proxy"]


@pytest.mark.asyncio
async def test_fetch_reviews_the_implementation_and_pins_related(tmp_path: Path) -> None:
    store = FakeStore()
    jid = "job_PROXYFE1"
    store.add_job(jid, chain_id=1, address=PROXY)
    step = store.add_step(jid, "fetch", container=False, units=0, ram_mb=0, max_attempts=3)
    pin_root = tmp_path / "pins"
    sup = _make_supervisor(store, pin_root)
    out_dir = tmp_path / "work" / jid
    out_dir.mkdir(parents=True)
    (out_dir / "chain_state.json").write_text(json.dumps({
        "chain_id": 1, "address": PROXY, "bytecode": IMPL_CODE, "block": 100, "self_address": IMPL,
        "proxy": {"pattern_name": "eip1967_transparent", "proxy": PROXY, "implementation": IMPL,
                  "proxy_bytecode": PROXY_CODE}}))
    impl_cand = _cand({"contracts/FiatToken.sol": "contract FiatToken {}\n"}, entry="contracts/FiatToken.sol:FiatToken")
    seen: list[str] = []

    async def fake_main(chain_id, address, runtime_bytecode, **_k):
        seen.append(address)
        return [impl_cand]

    async def fake_related(chain_id, address, runtime_bytecode):
        name = "AdminUpgradeabilityProxy" if address == PROXY else "PriceFeed"
        return [_cand({f"contracts/{name}.sol": f"contract {name} {{}}\n"}, entry=f"contracts/{name}.sol:{name}")]

    job = {"job_id": jid, "chain": "evm", "chain_id": 1, "address": PROXY, "source_kind": "deployed",
           "source_args": {"kind": "deployed", "chain": "evm", "address": PROXY,
                           "related": [{"address": PF, "name": "PriceFeed"}]}, "state": "fetching"}
    rpc = FakeRpc({PROXY: PROXY_CODE, PF: "0x6080"})
    with patch("soken_review.worker.supervisor.JobRepo", return_value=AsyncMock()), \
         patch("soken_review.adapters.evm.fetch.fetch_source", new=fake_main), \
         patch.object(rel, "fetch_source", new=fake_related), \
         patch("soken_review.worker.supervisor.RpcClientPool", return_value=rpc), \
         patch("soken_review.worker.supervisor._rpc_urls", return_value=["https://rpc.test"]), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job)), \
         patch.object(sup, "_mark_step", new=AsyncMock()) as mark, \
         patch.object(sup, "_after_fetch", new=AsyncMock()):
        sup._pool.connection = MagicMock(return_value=_conn_mock())
        await sup._run_fetch(step.as_dict())
    assert seen == [IMPL]   # the implementation source is the code under review
    pin = PinnedSource.load(pin_root, jid)
    assert set(pin.entries) == {"contracts/FiatToken.sol", "_related/proxy/contracts/AdminUpgradeabilityProxy.sol",
                                "_related/PriceFeed/contracts/PriceFeed.sol"}
    assert all(e.in_scope for e in pin.entries.values())   # quotable as a location
    records = json.loads((out_dir / "related_sources.json").read_text())
    assert [(r["name"], r["status"], r.get("role")) for r in records] == [
        ("proxy", "pinned", "proxy"), ("PriceFeed", "pinned", None)]
    assert mark.await_args.kwargs["provenance"]["related"] == records

    from soken_review.worker.supervisor import _reviewed_files
    assert set(_reviewed_files(pin_root, jid)) == {"contracts/FiatToken.sol"}   # the build sees the main code only


@pytest.mark.asyncio
async def test_transparent_proxy_with_upgrade_selectors_and_admin_is_transparent():
    code = "0x60806040" + "3659cfe6" + "4f1ef286" + "33" * 10   # OZ TransparentUpgradeableProxy admin path
    rpc = FakeRpc({PROXY: code, IMPL: IMPL_CODE},
                  {proxy_mod.EIP1967_IMPL_SLOT: _word(IMPL), proxy_mod.EIP1967_ADMIN_SLOT: _word(ADMIN)})
    assert (await proxy_mod.resolve_proxy(rpc, PROXY, code))["pattern_name"] == "eip1967_transparent"
