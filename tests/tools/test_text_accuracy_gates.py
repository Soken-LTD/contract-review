"""Write-time gates for the text defects of the matrix run 2026-10-27 (JUDGEMENT E4, E5):

* review_submit_finding rejects a half placeholder (`{fact:key}`) with the double-brace example, so a
  token the kit will not expand never reaches the report (Wallitelli L-001 and I-001);
* review_submit_finding and review_set_section reject a sentence that calls the owner the deployer
  when the facts record no deployer (APAD I-002 and the onlyOwner roles note).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.mapping.facts import write_facts

from .test_submit_finalize import _VALID_SUBMISSION, _create_ready_job_with_pin

ASYNC = pytest.mark.asyncio(loop_scope="session")
APAD_FACTS = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "matrix_2026_10_27" / "apad.facts.json")
                        .read_text(encoding="utf-8"))
OWNER = "0xa9e3e9afa056d200241b85aec824b039ffe17582"
WALLITELLI_L001 = ("The constructor mints the full supply of {fact:onchain.total_supply} token units to msg.sender, "
                   "the account that sent the deployment transaction.")
APAD_I002 = ("The current owner is the deployer account {{fact:onchain.owner}}, an externally owned account, "
             "which also received the whole initial supply.")


async def _job_with_apad_facts(db_pool):
    from soken_review.tools import set_section as section_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)
    section_mod.set_pool(db_pool)
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    write_facts(pin_root, job_id, APAD_FACTS)
    ctx = MemoryJobContext(pin_root)
    submit_mod.set_context(ctx)
    section_mod.set_context(ctx)
    return job_id


def _submission(job_id: str, description: str) -> dict:
    args = json.loads(json.dumps(_VALID_SUBMISSION))
    args["job_id"] = job_id
    args["body"]["description"] = [{"p": description}]
    return args


@ASYNC
async def test_submit_rejects_a_half_placeholder_with_the_double_brace_example(db_pool):
    from soken_review.tools import submit as submit_mod

    job_id = await _job_with_apad_facts(db_pool)
    res = await submit_mod.handle_review_submit_finding(_submission(job_id, WALLITELLI_L001))
    assert res["accepted"] is False
    errs = [e for e in res["errors"] if e["code"] == "E_PLACEHOLDER_SYNTAX"]
    assert len(errs) == 1 and errs[0]["field"] == "description"
    assert "{fact:onchain.total_supply}" in errs[0]["what"]
    assert "Write {{fact:onchain.total_supply}} (two braces on each side)" in errs[0]["fix"]


@ASYNC
async def test_submit_rejects_the_apad_owner_is_deployer_sentence_with_the_recorded_facts(db_pool):
    from soken_review.tools import submit as submit_mod

    job_id = await _job_with_apad_facts(db_pool)
    res = await submit_mod.handle_review_submit_finding(_submission(job_id, APAD_I002))
    assert res["accepted"] is False
    errs = [e for e in res["errors"] if e["code"] == "E_CLAIM_UNSUPPORTED"]
    assert len(errs) == 1 and errs[0]["field"] == "description"
    assert OWNER in errs[0]["what"] and "no deployer fact" in errs[0]["what"]
    assert "{{fact:onchain.owner}}" in errs[0]["fix"]
    # the same facts without the claim: the submission goes through
    ok = await submit_mod.handle_review_submit_finding(
        _submission(job_id, "The current owner is {{fact:onchain.owner}}, an externally owned account."))
    assert ok["accepted"] is True, ok


@ASYNC
async def test_set_section_rejects_the_apad_roles_note_held_by_the_deployer(db_pool):
    from soken_review.tools import set_section as section_mod

    job_id = await _job_with_apad_facts(db_pool)
    res = await section_mod.handle_review_set_section({
        "job_id": job_id, "section": "roles_notes",
        "roles_notes": {"rows": [{"role": "onlyOwner", "risk_note": "Held by the deployer account. Gates only "
                                                                    "renounceOwnership and transferOwnership."}]}})
    assert res["accepted"] is False, res
    errs = [e for e in res["errors"] if e["code"] == "E_CLAIM_UNSUPPORTED"]
    assert len(errs) == 1 and errs[0]["field"] == "roles_notes[0]" and OWNER in errs[0]["what"]
    ok = await section_mod.handle_review_set_section({
        "job_id": job_id, "section": "roles_notes",
        "roles_notes": {"rows": [{"role": "onlyOwner", "risk_note": "Held by {{fact:onchain.owner}}. Gates only "
                                                                    "renounceOwnership and transferOwnership."}]}})
    assert ok["accepted"] is True, ok

