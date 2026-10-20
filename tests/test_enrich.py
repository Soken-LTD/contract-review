"""Unit tests for deterministic self-enrichment (evals/enrich.py).

Pure functions only: no live DB, no docker. harvest() reads Postgres and is exercised by the
live stack, not here; gate/distill/record_to_case are covered with hand-built records.
"""

from __future__ import annotations

import yaml

from soken_review.evals.corpus import check_case
from soken_review.evals.enrich import (
    HarvestRecord,
    JobContext,
    distill,
    gate,
    is_analyzer_miss,
    record_to_case,
)


def _job(**over) -> JobContext:
    base: dict = {
        "job_id": "job_4G1P72GEA45HGYRWTFYH9S1XEK",
        "chain": "evm",
        "chain_id": 1,
        "family": "evm",
        "source_kind": "deployed",
        "source_pin": "90e22f845616250afc3f848c039e3c71911aabf325f351382567f68e659c993d",
        "commit": None,
        "tier": "B",
        "requester_role": "third_party_public_code",
        "consent_public": True,
    }
    base.update(over)
    return JobContext(**base)


def _record(**over) -> HarvestRecord:
    base: dict = {
        "job": _job(),
        "draft_key": "reentrancy-in-withdraw",
        "finding_no": 1,
        "draft_origin": "model",
        "severity": "High",
        "category": "evm.reentrancy",
        "category_family": "evm",
        "has_linked_lead": False,
        "locator": {"file": "Vault.sol", "start": 120, "end": 134},
    }
    base.update(over)
    return HarvestRecord(**base)


# --------------------------------------------------------------------------------------------
# gate: PUBLIC-only, fail-closed on unknown consent
# --------------------------------------------------------------------------------------------


def test_gate_passes_public_job():
    recs = [_record()]
    assert gate(recs, _job(consent_public=True)) == recs
    assert gate(recs, {"requester_role": "third_party_public_code"}) == recs
    assert gate(recs, {"consent_public": True}) == recs


def test_gate_fail_closed_on_unknown_consent():
    recs = [_record()]
    assert gate(recs, {}) == []  # unknown -> drop
    assert gate(recs, {"requester_role": "owner"}) == []  # private client input -> drop
    assert gate(recs, _job(consent_public=False)) == []
    # a falsey/ambiguous consent flag is not a positive signal
    assert gate(recs, {"consent_public": "yes"}) == []


# --------------------------------------------------------------------------------------------
# distill: keep only analyzer misses
# --------------------------------------------------------------------------------------------


def test_distill_keeps_analyzer_miss():
    out = distill([_record()])
    assert len(out) == 1
    assert out[0]["ground_truth"][0]["category"] == "evm.reentrancy"


def test_distill_drops_finding_with_linked_lead():
    # a model finding that DID have a linked analyzer lead in its category is not a miss
    assert distill([_record(has_linked_lead=True)]) == []
    assert is_analyzer_miss(_record(has_linked_lead=True)) is False


def test_distill_drops_non_model_and_low_severity_and_no_locator():
    assert distill([_record(draft_origin="server_needs_text")]) == []
    assert distill([_record(severity="Low")]) == []
    assert distill([_record(severity="Informational")]) == []
    assert distill([_record(locator=None)]) == []


def test_distill_mixed_batch_keeps_only_misses():
    recs = [
        _record(draft_key="a-miss", finding_no=1),  # kept
        _record(draft_key="b-has-lead", finding_no=2, has_linked_lead=True),
        _record(draft_key="c-low", finding_no=3, severity="Low"),
        _record(draft_key="d-another-miss", finding_no=4, severity="Medium"),
    ]
    out = distill(recs)
    assert {c["case_id"] for c in out} == {"evm-own_audit-0001", "evm-own_audit-0004"}


# --------------------------------------------------------------------------------------------
# distilled candidate conforms to the corpus case.v1 format (runnable by the recall harness)
# --------------------------------------------------------------------------------------------


def test_distilled_candidate_validates_against_corpus_format(tmp_path):
    case = record_to_case(_record())
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump(case))
    report = check_case(path)  # tree=None: structural + enum + rubric checks
    assert report.ok, report.errors


def test_distilled_candidate_deployed_uses_address_mode():
    case = record_to_case(_record(job=_job(source_kind="deployed")))
    assert case["input_mode"] == "address"
    assert case["source"]["commit"] is None


def test_distilled_candidate_repo_mode_carries_commit(tmp_path):
    commit = "4240445ed3b5145be1032cf1becc9c6866046bf7"
    case = record_to_case(_record(job=_job(source_kind="repo", commit=commit)))
    assert case["input_mode"] == "repo"
    assert case["source"]["commit"] == commit
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump(case))
    assert check_case(path).ok
