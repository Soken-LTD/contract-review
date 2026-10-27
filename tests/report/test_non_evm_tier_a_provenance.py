"""Tier A provenance for chains without EVM bytecode (TON seqno, Solana slot).

Matrix run 2026-10-26: the first tier A TON job (Forton, PR #68 rebuild hash match) finalized and
then failed at render with "tier A provenance requires deployment.json data". The TON pipeline
wrote provenance.json only, and the assembly read the on-chain code hash from an EVM-only
chain_state field. The cover now takes `code_hash` and the pin `unit` from deployment.json.
"""

from __future__ import annotations

import pytest

from soken_review.adapters.ton.provenance import deployment_doc
from soken_review.report.assemble import (
    AssemblyError,
    _build_verification_blocks,
    _deployment_method_detail,
    _network_label,
    _report_chain,
    provenance,
)

TON_HASH = "c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea"
TON_ADDRESS = "EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ"
TON_RAW = "0:2f26e1259f494ff1cd98319e2c286c1046dfe49b1982e3de2ff18e134c780e6a"
SEQNO = 101_445_617


def _ton_prov(reason: str = "MATCH_REBUILD", tier: str = "A", why: str | None = None) -> dict:
    return {"src": 0, "match": "exact" if reason == "MATCH_REBUILD" else None, "reason": reason, "tier": tier,
            "why": why, "dep_hash": TON_HASH, "build_hash": TON_HASH if reason == "MATCH_REBUILD" else None,
            "matched_target": "contract_FtMaster", "tried": [], "checks": [{"check": "tact_config", "value": {}}],
            "mc_seqno": SEQNO, "address": TON_RAW}


def _ton_cand() -> dict:
    return {"provider": "ton_verifier", "sha256": "49" * 32, "language": "tact",
            "compiler": {"version": "1.6.5", "version_pinned_by": "ton_verifier"}}


def _ton_chain_state() -> dict:
    # The 06 2.2 TON document: accounts keyed by raw address, no EVM `bytecode` field.
    return {"mc_seqno": SEQNO, "accounts": {TON_RAW: {"status": "active", "code_hash": TON_HASH,
                                                      "dep_hash": TON_HASH, "code_boc": "b5ee9c72"}}}


def _ton_job(tier: str = "A") -> dict:
    return {"tier": tier, "chain": "ton", "chain_id": None, "address": TON_ADDRESS,
            "source_pin": "b4cc916ccf88bed8f28f6c15752c424fe8ef881983807d4240895a129f9adf49",
            "resolved_commit": None, "source_args": {"kind": "deployed", "chain": "ton", "address": TON_ADDRESS},
            "ownership_proven": False, "requester_role": "third_party_public_code"}


class TestTonDeploymentDoc:
    def test_match_rebuild_is_tier_a_with_code_hash_and_seqno(self):
        doc = deployment_doc(_ton_prov(), _ton_cand(), TON_ADDRESS)
        assert doc["tier"] == "A"
        assert doc["dep"]["match"] == "exact" and doc["dep"]["reason"] == "match_rebuild"
        assert doc["dep"]["contract"] == "contract_FtMaster"
        assert doc["dep"]["comparison"] == {"outcome": "exact", "local_hash": TON_HASH, "onchain_hash": TON_HASH}
        assert doc["code_hash"] == TON_HASH
        assert doc["block"] == SEQNO and doc["unit"] == "seqno" and doc["chain"] == "ton"
        assert doc["address"] == TON_ADDRESS
        assert doc["candidate"] == {"provider": "ton_verifier", "sha256": "49" * 32, "compiler": "1.6.5",
                                    "version_pinned_by": "ton_verifier", "untrusted_inputs": False}
        assert doc["checks"] == [{"check": "tact_config", "value": {}}]

    def test_toolchain_gap_is_third_party_verified_with_the_reason_noted(self):
        doc = deployment_doc(_ton_prov("SOURCE_TOOLCHAIN_GAP", "B", why="rebuild not attempted: tact 1.6.5"),
                             _ton_cand(), TON_ADDRESS)
        assert doc["tier"] == "B"
        assert doc["dep"]["match"] == "third_party_verified_only"
        assert doc["dep"]["notes"] == ["rebuild not attempted: tact 1.6.5"]

    def test_no_deployment_has_no_dep_and_falls_back_to_the_build_hash(self):
        prov = {**_ton_prov("NO_DEPLOYMENT_GIVEN", "B"), "dep_hash": None, "build_hash": "ab" * 32,
                "address": None, "mc_seqno": None}
        doc = deployment_doc(prov, None, None)
        assert doc["dep"] is None and doc["candidate"] is None
        assert doc["code_hash"] == "ab" * 32 and doc["block"] is None


class TestTonTierAProvenance:
    def test_cover_takes_hash_and_seqno_from_deployment(self):
        dep = deployment_doc(_ton_prov(), _ton_cand(), TON_ADDRESS)
        prov = provenance(_ton_job(), [_ton_cand()], _ton_chain_state(), dep)
        assert prov["tier"] == "A" and prov["label_key"] == "tier_a"
        assert prov["code_hash"] == TON_HASH
        assert prov["address"] == TON_ADDRESS
        assert prov["as_of"]["block_or_slot"] == SEQNO
        assert f"seqno {SEQNO}" in prov["label"]
        assert "block" not in prov["label"]

    def test_tier_a_without_any_code_hash_names_the_defect(self):
        dep = {**deployment_doc(_ton_prov(), _ton_cand(), TON_ADDRESS), "code_hash": None}
        with pytest.raises(AssemblyError) as exc:
            provenance(_ton_job(), [_ton_cand()], _ton_chain_state(), dep)
        assert "deployed code hash" in str(exc.value)

    def test_verification_blocks_and_method_row_use_the_seqno_unit(self):
        dep = deployment_doc(_ton_prov(), _ton_cand(), TON_ADDRESS)
        blocks = _build_verification_blocks(dep, _ton_chain_state(), _ton_job())
        rows = blocks[0]["table"]["rows"]
        assert ["Masterchain seqno", SEQNO] in rows
        assert ["On-chain code hash", TON_HASH] in rows
        assert ["Chain / network", "TON mainnet"] in rows
        # the dep reason is an enum token and prints as the closing paragraph
        assert {"p": "match_rebuild"} in blocks
        detail = _deployment_method_detail(_ton_job(), dep)
        assert f"at seqno {SEQNO:,}" in detail and "byte for byte" in detail

    def test_solana_slot_unit(self):
        dep = {"tier": "A", "dep": {"match": "exact", "reason": "match_rebuild", "contract": "locker",
                                    "comparison": {"outcome": "exact"}, "notes": []},
               "candidate": None, "block": 461_620_751, "unit": "slot", "chain": "solana",
               "address": "Fvm8Z25vd1Yauj6GB4jsrW7jJyUdNYGeDCWYqcuTtDek", "code_hash": "sha256:" + "1c" * 32}
        job = {**_ton_job(), "chain": "solana", "address": dep["address"]}
        prov = provenance(job, [], {"kind": "program", "address": dep["address"], "slot": 461_620_751}, dep)
        assert "slot 461620751" in prov["label"] and prov["code_hash"] == "sha256:" + "1c" * 32


class TestReportChain:
    def test_non_evm_jobs_report_their_own_chain(self):
        assert _report_chain(_ton_job()) == "ton"
        assert _report_chain({"chain": "solana", "chain_id": None}) == "solana"
        assert _report_chain({"chain": "ethereum", "chain_id": 10}) == "evm"
        assert _report_chain({"chain": "tron", "chain_id": 728126428}) == "tron"

    def test_network_label(self):
        assert _network_label(_ton_job(), None, None) == "TON mainnet"
        assert _network_label({"chain": "ton", "address": None, "chain_id": None}, None, None) == "Not deployed"
        assert _network_label({"chain": "ethereum", "chain_id": 10, "address": "0x" + "1" * 40}, None, None).endswith("(10)")
