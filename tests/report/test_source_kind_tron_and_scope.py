"""Cover and scope facts observed wrong on the blind client path (matrix run 2026-10-26/27):

- Apyee (repo at commit): the provenance line said the source was supplied by the requester
  because `source_args` stores `repo_url`, not `repo`.
- TRON (deployed address, `chain: tron`, no chain id on the job row, no chain_state.json): the
  header printed chain `evm` and network `Not deployed`.
- The verification section printed the dep.match reason enum (`match_rebuild`) as a paragraph.
- Test and mock contracts excluded by the scope rules are listed as out of scope with the reason.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from psycopg.types.json import Jsonb

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.pinning.store import PinnedSource
from soken_review.report import kit
from soken_review.report.assemble import (
    NO_DEPLOYMENT_LABEL,
    _build_verification_blocks,
    _dep_reason_text,
    _job_chain_id,
    _network_label,
    _report_chain,
    assemble_report,
    provenance,
    scope_excluded_rows,
)
from soken_review.report.kit.build import kit_texts
from soken_review.tools import report as report_tool

ASYNC = pytest.mark.asyncio(loop_scope="session")
TRON_ADDRESS = "TRegosVaS1o3DHG85nnW8xYzczPm3xL76K"
TRON_ID = 728126428
PIN = "b4cc916ccf88bed8f28f6c15752c424fe8ef881983807d4240895a129f9adf49"
COMMIT = "ffc81631af65010c8afe66e1bee09f94d2d1ea79"
REPO = "https://github.com/apyee-finance/apyee-protocol"


def _job(**over) -> dict:
    base = {"tier": "B", "source_pin": PIN, "address": None, "chain": None, "chain_id": None,
            "resolved_commit": None, "source_args": {}, "source_kind": "files",
            "ownership_proven": False, "requester_role": "third_party_public_code"}
    base.update(over)
    return base


# ---------------------------------------------------------------- provenance: source kind

class TestProvenanceSourceKind:
    def test_repo_job_prints_the_commit_label_and_repo_fields(self):
        job = _job(source_kind="repo", resolved_commit=COMMIT,
                   source_args={"kind": "repo", "commit": COMMIT, "subdir": "contracts", "repo_url": REPO})
        prov = provenance(job, [{"provider": "repo"}], None)
        assert prov["label_key"] == "tier_b_commit"
        assert prov["label"] == kit_texts()["tier_labels"]["tier_b_commit"].format(commit=COMMIT[:12])
        assert prov["repo"] == REPO and prov["commit"] == COMMIT

    def test_source_args_stored_as_a_json_string_still_resolve(self):
        job = _job(source_kind="repo", resolved_commit=COMMIT,
                   source_args=json.dumps({"kind": "repo", "repo_url": REPO}))
        prov = provenance(job, [], None)
        assert prov["label_key"] == "tier_b_commit" and prov["repo"] == REPO

    def test_legacy_repo_key_still_accepted(self):
        job = _job(source_kind="repo", resolved_commit=COMMIT, source_args={"repo": REPO})
        assert provenance(job, [], None)["label_key"] == "tier_b_commit"

    def test_upload_job_keeps_the_requester_label(self):
        job = _job(source_kind="upload", source_args={"kind": "upload"})
        prov = provenance(job, [], None)
        assert prov["label_key"] == "tier_b_files" and "repo" not in prov

    def test_deployed_explorer_source_is_third_party(self):
        job = _job(source_kind="deployed", address=TRON_ADDRESS, chain="tron",
                   source_args={"kind": "deployed", "chain": "tron", "address": TRON_ADDRESS})
        prov = provenance(job, [{"provider": "tronscan", "explorer_verified": True}], None)
        assert prov["label_key"] == "tier_b_third_party" and prov["address"] == TRON_ADDRESS

    def test_deployed_without_explorer_source_is_not_checked(self):
        job = _job(source_kind="deployed", address=TRON_ADDRESS, chain="tron")
        assert provenance(job, [{"provider": "user"}], None)["label_key"] == "tier_b_not_checked"

    def test_tier_a_repo_job_carries_repo_and_commit(self):
        job = _job(tier="A", source_kind="repo", resolved_commit=COMMIT, address="0x" + "ab" * 20, chain_id=10,
                   source_args={"repo_url": REPO})
        dep = {"tier": "A", "dep": {"match": "exact", "reason": "match_rebuild", "contract": "V.sol:V",
                                    "comparison": {"outcome": "exact"}}, "block": 5, "code_hash": "sha256:" + "1c" * 32}
        prov = provenance(job, [], {"block": 5}, dep)
        assert prov["repo"] == REPO and prov["commit"] == COMMIT


# ---------------------------------------------------------------- TRON header

class TestTronHeader:
    def test_deployed_tron_job_without_chain_id_resolves_to_the_tron_mainnet(self):
        job = _job(source_kind="deployed", chain="tron", address=TRON_ADDRESS)
        assert _job_chain_id(job) == TRON_ID
        assert _report_chain(job) == "tron"
        assert _network_label(job, None, None) == f"TRON Mainnet ({TRON_ID})"

    def test_chain_state_chain_id_still_wins(self):
        job = _job(source_kind="deployed", chain="tron", address=TRON_ADDRESS)
        assert _network_label(job, {"chain_id": TRON_ID}, None) == f"TRON Mainnet ({TRON_ID})"

    def test_tron_repo_job_without_address_stays_not_deployed(self):
        job = _job(source_kind="repo", chain="tron", resolved_commit=COMMIT, source_args={"repo_url": REPO})
        assert _job_chain_id(job) is None
        assert _report_chain(job) == "tron" and _network_label(job, None, None) == NO_DEPLOYMENT_LABEL

    def test_evm_job_without_chain_id_is_unchanged(self):
        job = _job(source_kind="repo", chain="evm", resolved_commit=COMMIT, source_args={"repo_url": REPO})
        assert _report_chain(job) == "evm" and _network_label(job, None, None) == NO_DEPLOYMENT_LABEL

    def test_verification_table_names_the_tron_network(self):
        job = _job(tier="A", source_kind="deployed", chain="tron", address=TRON_ADDRESS)
        dep = {"tier": "A", "dep": {"match": "exact", "reason": "match_rebuild", "contract": "T.sol:T",
                                    "comparison": {"outcome": "exact"}}, "block": 70_000_000,
               "code_hash": "sha256:" + "2d" * 32}
        rows = _build_verification_blocks(dep, None, job)[0]["table"]["rows"]
        assert ["Chain / network", f"TRON Mainnet ({TRON_ID})"] in rows
        assert ["Address", {"addr": TRON_ADDRESS}] in rows


# ---------------------------------------------------------------- dep.match reason text

class TestDepReasonText:
    @pytest.mark.parametrize("code", ["match_rebuild", "MATCH_REBUILD", " match_rebuild "])
    def test_known_code_prints_the_kit_text_in_any_case(self, code):
        assert _dep_reason_text(code) == kit_texts()["dep_match_reasons"]["match_rebuild"]

    def test_unknown_code_prints_plain_words_never_the_enum(self):
        text = _dep_reason_text("some_new_outcome")
        assert text == "Comparison outcome recorded as some new outcome."
        assert "some_new_outcome" not in text

    @pytest.mark.parametrize("code", ["", None, "not an enum!", "A" * 80])
    def test_no_paragraph_for_empty_or_malformed_codes(self, code):
        assert _dep_reason_text(code) is None

    def test_paragraph_in_verification_blocks_is_the_kit_text(self):
        job = _job(tier="A", address="0x" + "ab" * 20, chain_id=10)
        dep = {"tier": "A", "dep": {"match": "exact", "reason": "match_rebuild", "contract": "V.sol:V",
                                    "comparison": {"outcome": "exact"}}, "block": 5}
        blocks = _build_verification_blocks(dep, {"chain_id": 10, "block": 5}, job)
        assert blocks[-1] == {"p": kit_texts()["dep_match_reasons"]["match_rebuild"]}

    def test_every_pipeline_reason_code_has_a_kit_text(self):
        from soken_review.adapters.ton import provenance as ton_prov

        labels = kit_texts()["dep_match_reasons"]
        codes = {ton_prov.MATCH_REBUILD, ton_prov.NO_DEPLOYMENT_GIVEN, ton_prov.NO_DEPLOYED_CODE,
                 ton_prov.NO_SOURCE_FOUND, ton_prov.NO_CHECKABLE_SOURCE, ton_prov.SOURCE_NOT_OWNER_LINKED,
                 ton_prov.SOURCE_TOOLCHAIN_GAP, "SOURCE_NOT_REBUILT", "rebuild_differs", "untrusted_inputs"}
        import yaml

        rub = yaml.safe_load((Path(kit.__file__).resolve().parents[4] / "contract" / "rubric" / "dep_match.yaml")
                             .read_text(encoding="utf-8"))
        codes |= set(rub["not_checkable"]["evm_reasons"])
        assert {c.lower() for c in codes} <= set(labels)


# ---------------------------------------------------------------- scope rows and kit gate

class TestScopeExcludedRows:
    def test_rows_use_the_kit_reason_and_are_server_rows(self):
        cands = [{"provider": "repo", "scope_excluded": [
            {"path": "contracts/mocks/MockUSDC.sol", "reason": "test_or_mock_dir"},
            {"path": "contracts/Vault.t.sol", "reason": "mock_name"},
            {"path": "contracts/Harness.sol", "reason": "test_harness"},
            {"path": "contracts/Odd.sol", "reason": "something_else"},
            {"reason": "test_or_mock_dir"},
            "garbage"]}]
        rows = scope_excluded_rows(cands)
        labels = kit_texts()["scope_reasons"]
        assert [r["path"] for r in rows] == ["contracts/mocks/MockUSDC.sol", "contracts/Vault.t.sol",
                                             "contracts/Harness.sol", "contracts/Odd.sol"]
        assert [r["reason"] for r in rows] == [labels["test_or_mock_dir"], labels["mock_name"],
                                               labels["test_harness"], labels["other"]]
        assert {r["by"] for r in rows} == {"server"}

    def test_no_candidate_or_no_field_gives_no_rows(self):
        assert scope_excluded_rows([]) == [] and scope_excluded_rows([{"provider": "repo"}]) == []

    def test_rows_over_the_budget_end_with_a_count_row_not_a_silent_cut(self):
        labels = kit_texts()["scope_reasons"]
        cands = [{"scope_excluded": [{"path": f"contracts/mocks/Mock{i}.sol", "reason": "test_or_mock_dir"}
                                      for i in range(57)]}]
        rows = scope_excluded_rows(cands, budget=40)
        assert len(rows) == 40 and rows[-1] == {"path": labels["more_path"], "by": "server",
                                               "reason": labels["more"].format(n=18)}
        assert [r["path"] for r in rows[:39]] == [f"contracts/mocks/Mock{i}.sol" for i in range(39)]
        assert len(scope_excluded_rows(cands, budget=57)) == 57
        tiny = scope_excluded_rows(cands, budget=1)
        assert len(tiny) == 1 and tiny[0]["reason"] == labels["more"].format(n=57)

    def test_more_row_passes_the_schema_and_the_kit_gate(self):
        from soken_review.report.kit import build as kb

        labels = kit_texts()["scope_reasons"]
        assert kb.gate_kit_text("more", labels["more"].format(n=18)) == []
        assert kb.gate_kit_text("more_path", labels["more_path"]) == []

    def test_new_kit_texts_pass_the_public_gate(self):
        from soken_review.report.kit import build as kb

        t = kit_texts()
        for key, text in (*t["dep_match_reasons"].items(), *t["scope_reasons"].items()):
            assert kb.gate_kit_text(key, text) == [], (key, text)
            assert "—" not in text


# ---------------------------------------------------------------- TRON job end to end (Postgres)

SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.6.2;
contract CRSToken {
    address public owner;
    mapping(address => uint256) private _rOwned;
    constructor() public { owner = msg.sender; }
    function excludeAccount(address a) external {
        require(msg.sender == owner, "owner");
        _rOwned[a] = 0;
    }
}
"""


async def _tron_job(db_pool, tmp_path: Path) -> tuple[str, Path]:
    """A deployed TRON job the way the stand stored job_JDSJ... on 2026-10-26: chain `tron`,
    chain_id NULL, address set, candidates.json from TronScan, deployment.json tier B with no
    comparison, no chain_state.json."""
    jid = new_job_id()
    pin_root = tmp_path / "pins"
    path = "CRSToken.sol"
    pin = PinnedSource.from_files({path: SOL.encode()}, langs={path: "solidity"})
    pin.persist(pin_root, jid)
    (pin_root / jid / "leads.json").write_text("[]")
    work = tmp_path / "work" / jid
    work.mkdir(parents=True)
    cand = {"provider": "tronscan", "sha256": "d7" * 32, "language": "solidity",
            "compiler": {"version": "tron_0.6.2_Plato_v4.2", "version_pinned_by": "tronscan"}, "settings": {},
            "entry_contract": "CRSToken.sol:CRSToken", "explorer_verified": True, "sourcify_match": None,
            "untrusted_inputs": False, "fetched_at": "2026-10-26T15:03:44+00:00", "scope_excluded": []}
    (work / "candidates.json").write_text(json.dumps([cand]))
    (work / "deployment.json").write_text(json.dumps({"tier": "B", "label_reason": None, "checks": [], "dep": None,
                                                      "candidate": {"provider": "tronscan"}, "block": None}))
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(job_id=jid, principal_key=report_tool.principal_of(jid), surface="plugin", state="queued",
                          requester_role="third_party_public_code", source_kind="deployed",
                          source_args={"kind": "deployed", "chain": "tron", "address": TRON_ADDRESS},
                          has_deployment=True, chain="tron", chain_id=None, address=TRON_ADDRESS)
        rid = hashlib.sha256(jid.encode()).hexdigest()
        rid = "".join("abcdefghijklmnopqrstuvwxyz234567"[int(c, 16) * 2] for c in rid[:26])
        await conn.execute("update jobs set state = 'finalized', tier = 'B', report_id = %s, source_pin = %s"
                           " where job_id = %s", (rid, pin.source_pin, jid))
        content = {"title": "Exclusion snapshot goes stale after excludeAccount runs",
                   "body": {"description": [{"p": "The `excludeAccount` function writes the snapshot once."}],
                            "impact": [{"p": "Holder balances drift from the reported supply."}],
                            "recommendation": [{"p": "Refresh the snapshot on every transfer."}]}}
        await conn.execute("""insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
            current_revision, severity, evidence_level, final_id) values (%s,'exclusion-snapshot-stale',1,'model','accepted',1,
            'Medium','reasoning_challenged','M-001')""", (jid,))
        await conn.execute("""insert into finding_revisions (job_id, draft_key, revision, content, content_hash,
            category, category_family, impact_class, computed_severity, severity_rule)
            values (%s,'exclusion-snapshot-stale',1,%s,'h','evm.accounting_logic','evm','theft_of_funds','Medium','S1')""",
                           (jid, Jsonb(content)))
        await conn.execute("insert into finding_quote_ranges values (%s,'exclusion-snapshot-stale',1,0,'location',%s,7,10)",
                           (jid, path))
    return jid, pin_root


@ASYNC
async def test_tron_deployed_job_renders_tron_mainnet_and_the_address(db_pool, tmp_path):
    jid, pin_root = await _tron_job(db_pool, tmp_path)
    async with db_pool.connection() as conn:
        report, _extras = await assemble_report(conn, jid, pin_root)
    meta = report["meta"]
    assert meta["chain"] == "tron"
    assert meta["network"] == f"TRON Mainnet ({TRON_ID})" and meta["chain_id"] == TRON_ID
    assert meta["addr_url"] == "https://tronscan.org/#/contract/{a}"
    prov = meta["provenance"]
    assert prov["tier"] == "B" and prov["label_key"] == "tier_b_third_party" and prov["address"] == TRON_ADDRESS
    # tier B without a deployed code hash: the cover prints the source pin, labelled as the sha256 it is
    # (2026-10-27: a pin under "Bytecode hash" or "Commit" is the E6 cover defect)
    assert meta["source_id_label"] == "Files sha256" and "code_hash" not in prov
    assert "verification" not in report
    assert any(a["area_id"].startswith("evm.") for a in report["review_coverage"]["areas"])
