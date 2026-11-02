"""TON start-of-job chain snapshot (blind round 5b, 2026-10-31).

chain_state was "none / no values" for the multisig v2 job: the snapshot read get_jetton_data,
get_owner and owner (none exist on a multisig) and wrote the balance as chain.native.balance.target,
outside the chain.target.* namespace review_status shows. The reviewer re-read get_multisig_data by
hand. Now the snapshot calls the standard-interface get methods the pinned source declares, decodes
the signer and proposer dictionaries, and writes everything under chain.target.*.

Answers: tests/fixtures/chain/ton_multisig_v2.json, toncenter v2 keyless, recorded 2026-10-31 at
masterchain block 102,481,952 (EQBabkaz2T0_ZoRDzaMqZheJIDeRCJgwxMlsQ1GigwsjQlP-).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from soken_review.chain import reads
from soken_review.chain import store as chain_store
from soken_review.chain.endpoints import Health
from soken_review.chain.proxy import ChainProxy
from soken_review.chain.ton_codec import dict_addresses, dict_entries
from tests.chain.replay import Replay

FIX = Path(__file__).resolve().parents[1] / "fixtures"
REC = FIX / "chain" / "ton_multisig_v2.json"
MSIG_SRC = FIX / "ton" / "multisig_v2" / "src"
ADDR = "EQBabkaz2T0_ZoRDzaMqZheJIDeRCJgwxMlsQ1GigwsjQlP-"
BLOCK = 102481952
SIGNERS = [
    "EQBrATsKZMtVKfwOwrHKNnqnL8gZcZS8tJXS77ZB7062taBl",
    "EQDomyrhsjysBwCzGnVqDTyVsQcB3AUMYT3p_Fj_LxGNE5Yt",
    "EQBQ_SeTuiiXWIrmrGr794r-hspHHoH3WiUzkv7ULqphPx2I",
    "EQDOFVMqXf4w0O6VfcDWk45cKsziFTvylQBtnsbUrvwb4O34",
    "EQAnmXA5Hw-2wVt8tom9uest_5xDTgkRkv-quvHnHE3f_g2o",
    "EQBh1n-zNJ9GHUZeLMaUmJIbROiOS3EaRSuL-lVDz-6qyvpA",
    "EQANLEvIiup9Sy4FV2Xd_-hN0QYxfupfENGRMrbMqX4k9xtb",
]


@pytest.fixture(autouse=True)
def _clean_state():
    Health.reset()
    chain_store._MEM.clear()
    yield
    Health.reset()
    chain_store._MEM.clear()


def _msig_stack() -> list:
    rows = json.loads(REC.read_text())
    key = next(k for k in rows if '"get_multisig_data"' in k)
    return rows[key]["result"]["stack"]


def _files() -> dict[str, str]:
    return {p.relative_to(MSIG_SRC).as_posix(): p.read_text() for p in MSIG_SRC.rglob("*") if p.is_file()}


# ── dictionary decoding ───────────────────────────────────────────────────


def test_signers_dictionary_decodes_to_seven_addresses():
    stack = _msig_stack()
    signers = stack[2]["cell"]["bytes"]
    rows = dict_addresses(signers, 8)
    assert rows is not None and [k for k, _a in rows] == list(range(7))   # dense keys 0..n-1
    assert [a for _k, a in rows] == SIGNERS
    assert stack[3]["@type"] == "tvm.stackEntryList"                     # no proposers: an empty list


def test_malformed_or_foreign_cells_are_not_dictionaries():
    signers = _msig_stack()[2]["cell"]["bytes"]
    # the right key width matters: read as 16-bit keys the labels run out of bits
    assert dict_addresses(signers, 16) is None
    assert dict_addresses("not base64!", 8) is None
    with pytest.raises(ValueError):
        dict_entries(base64.b64encode(b"\x00\x01").decode(), 8)


# ── which get methods ─────────────────────────────────────────────────────


def test_declared_getters_of_the_multisig_source():
    # get_order_estimate(order, expiration) and get_order_address(seqno) take arguments: not called
    assert reads.ton_declared_getters(_files()) == ["get_multisig_data"]
    tact = {"a.tact": "contract C { get fun totalSupply(): Int { return 1; } get fun balanceOf(a: Address): Int {} }"}
    assert reads.ton_declared_getters(tact) == ["total_supply"]
    tolk = {"a.tolk": "get fun seqno(): int { return 1; }\nget get_owner() { }\n"}
    assert reads.ton_declared_getters(tolk) == ["seqno", "get_owner"]


def test_methods_follow_the_source_and_are_capped():
    assert reads.ton_auto_methods(["get_multisig_data"]) == ["get_multisig_data"]
    assert reads.ton_auto_methods(["get_counter", "get_jetton_data"]) == ["get_jetton_data", "get_counter"]
    std = reads.ton_auto_methods(None)
    assert std[0] == "get_multisig_data" and len(std) == reads.TON_AUTO_MAX_METHODS
    assert reads.ton_auto_methods([]) == std                    # nothing recognised: the standard list
    many = [f"get_x{i}" for i in range(20)]
    assert len(reads.ton_auto_methods(many)) == reads.TON_AUTO_MAX_METHODS


# ── the snapshot itself, replayed ────────────────────────────────────────


async def _snapshot(declared: list[str] | None) -> tuple[reads.Out, dict, Replay]:
    replay = Replay(REC)
    cj = reads.ChainJob(job_id="job_TONAUTO", family="ton", chain_id=None, network="TON mainnet",
                        pinned_block=None, address=ADDR)
    async with ChainProxy(transport=replay, pace=False) as px:
        at = await reads.ton_resolve(px, cj, None)
        out = reads.Out(job=cj, at=at)
        res = await reads.ton_auto_state(px, out, ADDR, "target", declared)
        await reads.ton_balances(px, out, "native", "target", [{"alias": "native", "address": ADDR}])
    return out, res, replay


@pytest.mark.asyncio
async def test_multisig_state_lands_under_the_target_alias():
    out, res, replay = await _snapshot(reads.ton_declared_getters(_files()))
    facts = {f["key"]: f for f in out.facts}
    assert res["interfaces"] == ["multisig_v2"] and replay.missing == []
    assert facts["chain.target.threshold"]["value"] == "2"
    assert facts["chain.target.next_order_seqno"]["value"] == "-1"
    assert facts["chain.target.allow_arbitrary_order_seqno"]["value"] == "true"
    assert facts["chain.target.signers.count"]["value"] == "7"
    assert [facts[f"chain.target.signers.{i}"]["value"] for i in range(7)] == SIGNERS
    assert facts["chain.target.proposers.count"]["value"] == "0"
    assert facts["chain.target.interface"]["value"] == "multisig_v2"
    assert facts["chain.target.balance.native"]["value"] == "75975802681"
    assert all(f["block"] == BLOCK and f["family"] == "ton" for f in out.facts)
    # one get method only: the source declares no other zero-argument getter
    assert sum('runGetMethodStd' in k for k in replay.seen) == 1


@pytest.mark.asyncio
async def test_without_a_source_the_standard_list_finds_the_multisig():
    out, res, replay = await _snapshot(None)
    keys = {f["key"] for f in out.facts}
    assert res["interfaces"] == ["multisig_v2"] and replay.missing == []
    assert "chain.target.threshold" in keys
    # the jetton, NFT and wallet methods answered with TVM exit 11 and recorded nothing
    assert not any(k.startswith(("chain.target.total_supply", "chain.target.seqno", "chain.target.owner"))
                   for k in keys)


# ── security review PR #105: a declared getter cannot spoof a standard fact ─────────────────

SPOOF_SRC = {
    "multisig.fc": (
        "(int, int, cell, cell) get_multisig_data() method_id { return (0, 2, null(), null()); }\n"
        ";; contract-chosen names equal to standard fields and reserved keys\n"
        "int threshold() method_id { return 1; }\n"
        "int interface() method_id { return 1; }\n"
        "int allow_arbitrary_order_seqno() method_id { return 0; }\n"
        "int balance() method_id { return 1; }\n"
    ),
}


def _spoof_rows() -> dict:
    rows = json.loads(REC.read_text())
    msig_key = next(k for k in rows if '"get_multisig_data"' in k)
    answer = {"@extra": "x", "ok": True, "result": {
        "@type": "smc.runResult", "exit_code": 0, "gas_used": 100,
        "stack": [{"@type": "tvm.stackEntryNumber", "number": {"@type": "tvm.numberDecimal", "number": "1"}}]}}
    for name in ("threshold", "interface", "allow_arbitrary_order_seqno", "balance"):
        rows[msig_key.replace('"get_multisig_data"', f'"{name}"')] = answer
    return rows


@pytest.mark.asyncio
async def test_colliding_declared_getter_does_not_change_the_standard_fact():
    declared = reads.ton_declared_getters(SPOOF_SRC)
    assert declared[0] == "get_multisig_data" and "threshold" in declared and "interface" in declared
    replay = Replay(_spoof_rows())
    cj = reads.ChainJob(job_id="job_TONSPOOF", family="ton", chain_id=None, network="TON mainnet",
                        pinned_block=None, address=ADDR)
    async with ChainProxy(transport=replay, pace=False) as px:
        out = reads.Out(job=cj, at=await reads.ton_resolve(px, cj, None))
        await reads.ton_auto_state(px, out, ADDR, "target", declared)
        await reads.ton_balances(px, out, "native", "target", [{"alias": "native", "address": ADDR}])
    assert replay.missing == []
    keys = [f["key"] for f in out.facts]
    assert len(keys) == len(set(keys))                     # one fact per key
    facts = {f["key"]: f for f in out.facts}
    # the standard facts come from get_multisig_data and are unchanged
    assert facts["chain.target.threshold"]["value"] == "2"
    assert facts["chain.target.threshold"]["method"] == "runGetMethod get_multisig_data"
    assert facts["chain.target.interface"]["value"] == "multisig_v2"
    assert facts["chain.target.allow_arbitrary_order_seqno"]["value"] == "true"
    assert facts["chain.target.balance.native"]["value"] == "75975802681"
    # the contract's own getters are kept apart under chain.target.getter.*
    for name in ("threshold", "interface", "allow_arbitrary_order_seqno", "balance"):
        assert facts[f"chain.target.getter.{name}"]["value"] == "1"
        assert facts[f"chain.target.getter.{name}"]["method"] == f"runGetMethod {name}"


def test_out_fact_first_write_wins():
    cj = reads.ChainJob(job_id="job_X", family="ton", chain_id=None, network="TON mainnet", pinned_block=None,
                        address=ADDR)
    out = reads.Out(job=cj, at=reads.At(block=1, head=1, block_time=None))
    out.fact("chain.target.threshold", "2", method="a", source="a")
    out.fact("chain.target.threshold", "1", method="b", source="b")
    assert [(f["key"], f["value"]) for f in out.facts] == [("chain.target.threshold", "2")]
