"""never-worse (CEO direction 2026-10-27 section A, contract/rubric/gate_policy.yaml).

* every previously rejecting advisory rule now returns accepted plus a warning, and the stored text
  is the printed (rewritten) form;
* every blocking rule still rejects;
* a full flow with zero optional steps (start, submit, finalize) builds the report, with the coverage
  note for the steps that were not taken.
"""

from __future__ import annotations

import copy

import pytest

from tests.tools.test_submit_finalize import _VALID_SUBMISSION, ASYNC, _create_ready_job_with_pin


async def _wired(db_pool):
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    for mod in (submit_mod, fin_mod):
        mod.set_pool(db_pool)
        mod.set_context(MemoryJobContext(pin_root))
    return submit_mod, fin_mod, job_id, pin_root


def _args(job_id: str, key: str, **over) -> dict:
    a = copy.deepcopy(_VALID_SUBMISSION)
    a.update({"job_id": job_id, "draft_key": key})
    a.update(over)
    return a


# Prose that every one of these rules rejected before 2026-10-27 (blind runs r1 to r4).
ADVISORY_CASES = [
    ("T13", "E_TEXT_GATE", {"impact": "The price is too low after the swap and the pool pays out."}),
    ("T24", "E_ABSENCE_UNRESOLVED", {"description": "Anyone can call withdraw at any time."}),
    ("T31", "E_CODESPAN_NOT_IN_SOURCE", {"description": "The pool calls router.swap(amount) with the full balance."}),
    ("L7", "E_NUMBER_UNSOURCED", {"description": "The pair is priced from the Uniswap V3 pool."}),
    ("L9a", "E_NUMBER_FORMAT", {"impact": "The error is about half the depeg."}),
    ("T5", "E_TEXT_GATE", {"recommendation": "You should write the balance first."}),
    ("T12", "E_TEXT_GATE", {"description": "Who can call withdraw and when does the balance change?"}),
    ("T16", "E_TEXT_GATE", {"description": "Slither reports this withdraw path as reentrant."}),
    ("T23", "E_TEXT_GATE", {"description": " ".join(["word"] * 95)}),
]


@ASYNC
@pytest.mark.parametrize(("rule", "code", "prose"), ADVISORY_CASES, ids=[c[0] for c in ADVISORY_CASES])
async def test_previously_rejecting_advisory_rule_is_accepted_with_a_warning(db_pool, rule, code, prose):
    submit_mod, _, job_id, _ = await _wired(db_pool)
    args = _args(job_id, f"adv-{rule.lower()}")
    for field, text in prose.items():
        args["body"][field] = [{"p": text}]
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is True, res
    hits = [w for w in res["warnings"] if w["code"] == code and w.get("rule") == rule]
    assert hits and hits[0]["class"] == "advisory" and hits[0]["suggest"], res["warnings"]
    async with db_pool.connection() as conn, conn.cursor() as cur:
        await cur.execute("select count(*) from gate_warnings where job_id = %s and tool = 'review_submit_finding'",
                          (job_id,))
        assert (await cur.fetchone())[0] == 1
        await cur.execute("select rejected_count from finding_drafts where job_id = %s", (job_id,))
        assert (await cur.fetchone())[0] == 0


@ASYNC
async def test_dotted_identifier_title_is_advisory(db_pool):
    """Lambo run 2026-10-27: T21 read the dots of `VirtualToken.cashIn` as sentence breaks."""
    submit_mod, _, job_id, _ = await _wired(db_pool)
    res = await submit_mod.handle_review_submit_finding(
        _args(job_id, "adv-title", title="VirtualToken.cashIn mints msg.value instead of amount"))
    assert res["accepted"] is True, res
    assert any(w.get("rule") == "T21" and w["class"] == "advisory" for w in res["warnings"]), res["warnings"]


@ASYNC
async def test_publication_rewrites_are_stored_and_reported(db_pool):
    submit_mod, _, job_id, _ = await _wired(db_pool)
    args = _args(job_id, "adv-rewrite", title="Reentrant withdraw drains the vault before the balance update.")
    args["body"]["description"] = [{"p": "The withdraw path \u2014 audited earlier \u2014 sends value first."}]
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is True, res
    rules = {w["rule"] for w in res["warnings"] if w["class"] == "rewrite"}
    assert {"T1", "T15", "T21"} <= rules, res["warnings"]
    async with db_pool.connection() as conn, conn.cursor() as cur:
        await cur.execute("select content from finding_revisions where job_id = %s", (job_id,))
        content = (await cur.fetchone())[0]
    assert content["body"]["description"][0]["p"] == "The withdraw path, reviewed earlier, sends value first."
    assert content["title"] == "Reentrant withdraw drains the vault before the balance update"


@ASYNC
async def test_bad_lead_link_is_dropped_not_rejected(db_pool):
    submit_mod, _, job_id, _ = await _wired(db_pool)
    res = await submit_mod.handle_review_submit_finding(_args(job_id, "adv-lead", lead_ids=["LEAD-0999"]))
    assert res["accepted"] is True and res["evidence_level"] == "reasoning_only", res
    assert [w["code"] for w in res["warnings"]] == ["E_LEAD_NOT_FOUND"]


BLOCKING_CASES = [
    ("T14", {"impact": "After the fix the vault is fully secure."}),
    ("T17", {"recommendation": "Follow the guide at https://example.org/guide for the fix."}),
    ("T25", {"description": "Soken found this withdraw path."}),
    ("T10", {"description": "Seen in 890+ protocols with this withdraw path."}),
    ("T27", {"recommendation": "Book a call for a paid review of the vault."}),
    ("L8c", {"impact": "An attacker drains 7342 tokens per call."}),
    ("L8b", {"impact": "An attacker drains 40% of the vault per call."}),
    ("step0", {"description": "The withdraw path" + chr(0x202E) + " sends value first."}),
    ("L0", {"description": "The pool holds {fact:pool.balance} tokens."}),
]


@ASYNC
@pytest.mark.parametrize(("rule", "prose"), BLOCKING_CASES, ids=[c[0] for c in BLOCKING_CASES])
async def test_blocking_rule_still_rejects(db_pool, rule, prose):
    submit_mod, _, job_id, _ = await _wired(db_pool)
    args = _args(job_id, f"blk-{rule.lower()}")
    for field, text in prose.items():
        args["body"][field] = [{"p": text}]
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is False, res
    assert res["errors"] and res["retries_left"] == 5


@ASYNC
async def test_quote_mismatch_still_rejects(db_pool):
    submit_mod, _, job_id, _ = await _wired(db_pool)
    args = _args(job_id, "blk-quote")
    args["quotes"] = [{**args["quotes"][0], "text": "    function withdrawAll() external {"}]
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is False and res["errors"][0]["code"].startswith("E_QUOTE"), res


@ASYNC
async def test_literal_on_the_quoted_line_is_sourced_at_submit(db_pool):
    """Pump Science run 2026-10-27: a number held by the quoted code was rejected at submit because
    the number check got no quotes. Line 5 of the fixture declares `uint256 a`; 256 is on it."""
    submit_mod, _, job_id, _ = await _wired(db_pool)
    args = _args(job_id, "src-literal")
    args["body"]["impact"] = [{"p": "The amount is a full uint256 and lines 5 to 8 move it."}]
    res = await submit_mod.handle_review_submit_finding(args)
    assert res["accepted"] is True, res
    assert not [w for w in res.get("warnings", []) if w["code"] == "E_LINEREF_OUTSIDE"]


@ASYNC
async def test_zero_optional_steps_reach_the_report(db_pool, tmp_path):
    """start, submit (a High that needs a challenge, prose with advisory hits), finalize, report:
    no read, no challenge, no lead triage, no sections. Finalize is accepted, the coverage note lists
    the skipped challenge, and the kit builds the report HTML from the assembled job."""
    from soken_review.report.assemble import assemble_report
    from soken_review.report.kit.build import build

    submit_mod, fin_mod, job_id, pin_root = await _wired(db_pool)
    args = _args(job_id, "flow-001")
    args["body"]["impact"] = [{"p": "Anyone can drain the vault \u2014 a severe loss."}]
    sub = await submit_mod.handle_review_submit_finding(args)
    assert sub["accepted"] is True and sub["status"] == "needs_challenge", sub
    assert sub["next_tools"][0] == "review_finalize"

    fin = await fin_mod.handle_review_finalize({"job_id": job_id})
    assert fin["accepted"] is True, fin
    assert {g["check"] for g in fin["coverage_gaps"]} >= {"F3"}

    from soken_review.pinning.store import PinnedSource

    async with db_pool.connection() as conn:
        # the fixture job skips the fetch step (pin hash, deployment record); tier B prints without one
        await conn.execute("update jobs set source_pin = %s, tier = 'B' where job_id = %s",
                           (PinnedSource.load(pin_root, job_id).source_pin, job_id))
        report, _ = await assemble_report(conn, job_id, pin_root)
    assert {"kind": "challenge_not_answered", "count": 1} in report["review_coverage"]["not_taken"]
    finding = report["findings"][0]
    assert finding["severity"] in ("High", "Critical") and finding["evidence_level"] == "reasoning_only"
    res = build(report, tmp_path)
    html = res.html_path.read_text(encoding="utf-8")
    assert "did not take" in html and "disproof checklist" in html
    assert "\u2014" not in html.split("<body", 1)[-1]
