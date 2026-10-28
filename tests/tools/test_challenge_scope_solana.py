"""Solana challenge scopes resolve from the parsed map (scopes.yaml, 04 8.4).

Blind run 2026-10-26 (Lock & Loan, `solana.ata_owner_reassign`): the finding was located on the
`recipient_loan_token` field of `ClaimDefaultCtx`, a `#[derive(Accounts)]` struct. No function
span covers a struct field, so every checklist item shipped `scope.not_covered: true` with no
ranges; the reviewer could neither quote a disproof inside the scope nor lift the K10 cap, and
both ata_owner_reassign findings printed High whatever the evidence (JUDGEMENT.md D10, D17).

Now: a location inside an Accounts struct resolves to the instruction handlers that take the
struct, their callees (across modules) and the struct itself; a location inside a handler adds
the handler's struct; `account_struct` is the struct alone. The handler replay runs the F-01
shape against a Solana pin end to end: real ranges, an absent answer that covers them, and the
reviewer's severity printed without a scope cap.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mapping.test_semantic_solana import FILES, HANDLER, LIB

from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories
from soken_review.tools.challenge import _resolve_scope, compute_challenge_items

from .test_write_tools import ASYNC, _log_reads

CATS = list(family_categories("solana", "solana"))

LIB_LINES = LIB.splitlines()
HANDLER_LINES = HANDLER.splitlines()


def _line_of(lines: list[str], needle: str) -> int:
    return next(i for i, line in enumerate(lines, 1) if needle in line)


# `Withdraw` struct and the handlers around it (line numbers derived from the fixture text)
WITHDRAW_STRUCT_START = _line_of(LIB_LINES, "pub struct Withdraw<'info>") - 1   # the #[derive(Accounts)] line
WITHDRAW_STRUCT_END = next(i for i in range(WITHDRAW_STRUCT_START, len(LIB_LINES) + 1) if LIB_LINES[i - 1] == "}")
VAULT_TOKEN_LINE = _line_of(LIB_LINES, "pub vault_token: Account<'info, TokenAccount>")
WITHDRAW_FN_LINE = _line_of(LIB_LINES, "pub fn withdraw(ctx: Context<Withdraw>")
HANDLE_WITHDRAW_LINE = _line_of(HANDLER_LINES, "pub fn handle_withdraw")
TRANSFER_LINE = _line_of(HANDLER_LINES, "anchor_spl::token::transfer(")


def _map() -> dict[str, Any]:
    doc = build_map(FILES, None, CATS, build_ok=False, parsed_family="solana").doc
    doc["_status"] = "partial"
    return doc


def _span(doc: dict[str, Any], sid: str) -> dict[str, Any]:
    return next(sp for sp in doc["spans"] if sp["id"] == sid)


def _range(sp: dict[str, Any]) -> str:
    return f"{sp['file']}:{sp['start']}-{sp['end']}"


def _covering(ranges: list[str], path: str, line: int) -> bool:
    for r in ranges:
        p, span = r.rsplit(":", 1)
        s, e = (int(x) for x in span.split("-"))
        if p == path and s <= line <= e:
            return True
    return False


def test_fixture_has_the_struct_and_handlers_the_tests_rely_on():
    doc = _map()
    contexts = doc["semantic"]["chain_extras"]["solana"]["contexts"]
    assert contexts["Withdraw"]["file"] == "src/lib.rs"
    assert contexts["Withdraw"]["start"] == WITHDRAW_STRUCT_START + 1   # struct line; derive attribute precedes it
    assert contexts["Withdraw"]["end"] == WITHDRAW_STRUCT_END
    instructions = {i["name"]: i for i in doc["semantic"]["chain_extras"]["solana"]["instructions"]}
    assert instructions["withdraw"]["context"] == "Withdraw"


def test_location_in_an_accounts_struct_resolves_to_its_handlers_and_the_struct():
    doc = _map()
    loc = [{"file": "src/lib.rs", "start": VAULT_TOKEN_LINE - 1, "end": VAULT_TOKEN_LINE}]
    ranges, not_covered, source = _resolve_scope("entry_function", "solana", doc, loc)
    assert not not_covered and source == "semantic", (ranges, source)
    assert _covering(ranges, "src/lib.rs", VAULT_TOKEN_LINE), ranges                 # the struct
    assert _covering(ranges, "src/lib.rs", WITHDRAW_FN_LINE), ranges                 # the instruction
    assert _covering(ranges, "src/instructions/withdraw.rs", HANDLE_WITHDRAW_LINE), ranges   # its handler, another module
    assert not _covering(ranges, "src/lib.rs", _line_of(LIB_LINES, "pub fn poke")), ranges   # not every instruction


def test_location_in_a_handler_adds_its_accounts_struct():
    doc = _map()
    loc = [{"file": "src/lib.rs", "start": WITHDRAW_FN_LINE, "end": WITHDRAW_FN_LINE + 1}]
    ranges, not_covered, _ = _resolve_scope("entry_function", "solana", doc, loc)
    assert not not_covered
    assert _covering(ranges, "src/lib.rs", VAULT_TOKEN_LINE), ranges
    assert _covering(ranges, "src/instructions/withdraw.rs", TRANSFER_LINE), ranges


def test_account_struct_scope_is_the_struct_alone():
    doc = _map()
    for loc in ([{"file": "src/lib.rs", "start": VAULT_TOKEN_LINE, "end": VAULT_TOKEN_LINE}],
                [{"file": "src/instructions/withdraw.rs", "start": TRANSFER_LINE, "end": TRANSFER_LINE}]):
        ranges, not_covered, source = _resolve_scope("account_struct", "solana", doc, loc)
        assert not not_covered and source == "semantic", (loc, ranges)
        assert ranges == [f"src/lib.rs:{WITHDRAW_STRUCT_START + 1}-{WITHDRAW_STRUCT_END}"], ranges


def test_account_struct_without_a_struct_falls_back_to_the_handler():
    """A native program parses accounts in the handler body: that body is the parsing block."""
    doc = _map()
    doc["semantic"]["chain_extras"]["solana"]["contexts"] = {}
    loc = [{"file": "src/instructions/withdraw.rs", "start": TRANSFER_LINE, "end": TRANSFER_LINE}]
    ranges, not_covered, source = _resolve_scope("account_struct", "solana", doc, loc)
    assert not not_covered and source == "semantic"
    assert _covering(ranges, "src/instructions/withdraw.rs", HANDLE_WITHDRAW_LINE), ranges


def test_location_nowhere_in_the_map_is_not_covered_with_no_ranges():
    doc = _map()
    ranges, not_covered, source = _resolve_scope("entry_function", "solana", doc,
                                                 [{"file": "src/lib.rs", "start": 2, "end": 2}])
    assert (ranges, not_covered, source) == ([], True, "not_covered")


def test_every_ata_owner_reassign_item_ships_real_ranges_for_a_struct_location():
    doc = _map()
    matrix = {"impact_class": "permanent_freeze", "magnitude": "unbounded", "trigger": "permissionless_role",
              "precondition": "normal_operation", "reversibility": "irreversible"}
    items, _ = compute_challenge_items("solana", "solana.ata_owner_reassign", matrix, doc,
                                       [{"file": "src/lib.rs", "start": VAULT_TOKEN_LINE, "end": VAULT_TOKEN_LINE}],
                                       is_generic=False)
    assert {"W0", "W0b", "W1", "W3", "W2"} <= {i["id"] for i in items}
    for item in items:
        assert item["scope"]["ranges"], item
        assert not item["scope"].get("not_covered"), item


# ── handler replay against Postgres: the F-01 shape on a Solana pin ─────────────────────────

F01_MATRIX = {"impact_class": "permanent_freeze", "magnitude": "unbounded", "trigger": "permissionless_role",
              "precondition": "normal_operation", "reversibility": "irreversible"}
REASON = "The borrower needs a defaulted loan first and the lender keeps every other claim path."


async def _solana_job(db_pool) -> tuple[str, Path]:
    import tempfile

    from soken_review.db.job_repo import JobRepo, new_job_id
    from soken_review.pinning.store import PinnedSource
    from soken_review.tools.report import principal_of

    pin_root = Path(tempfile.mkdtemp()) / "pins"
    pin_root.mkdir(parents=True, exist_ok=True)
    jid = new_job_id()
    async with db_pool.connection() as conn, conn.transaction():
        await JobRepo(conn).create(job_id=jid, principal_key=principal_of(jid), surface="plugin", state="queued",
                                   requester_role="third_party_public_code", source_kind="deployed", source_args={},
                                   has_deployment=True, chain="solana")
        await conn.execute("update jobs set state = 'ready', tier = 'A' where job_id = %s", (jid,))
    PinnedSource.from_files({p: t.encode() for p, t in FILES.items()}).persist(pin_root, jid)
    map_dir = pin_root / jid / "map"
    map_dir.mkdir(parents=True, exist_ok=True)
    (map_dir / "map.json").write_text(json.dumps(build_map(FILES, None, CATS, build_ok=False,
                                                           parsed_family="solana").doc), encoding="utf-8")
    (map_dir / "status.json").write_text(json.dumps({"map_status": "partial"}), encoding="utf-8")
    return jid, pin_root


def _quote(path: str, lines: list[str], start: int, end: int) -> dict[str, Any]:
    return {"file": path, "start": start, "end": end, "text": "\n".join(lines[start - 1:end])}


@ASYNC
async def test_f01_shape_on_a_solana_pin_gets_real_scopes_and_the_reviewers_severity(db_pool):
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _solana_job(db_pool)
    ctx = MemoryJobContext(pin_root)
    for mod in (submit_mod, challenge_mod):
        mod.set_pool(db_pool)
        mod.set_context(ctx)

    location = {**_quote("src/lib.rs", LIB_LINES, VAULT_TOKEN_LINE - 1, VAULT_TOKEN_LINE), "role": "location"}
    sub = await submit_mod.handle_review_submit_finding({
        "job_id": job_id, "draft_key": "withdraw-blocked-by-ata-owner-reassign",
        "category": "solana.ata_owner_reassign", "quotes": [location], "matrix": F01_MATRIX, "lead_ids": [],
        "title": "User can block withdraw by reassigning the owner of the vault token account",
        "body": {"description": [{"p": "The vault token account is required with a fixed derived address."}],
                 "impact": [{"p": "The authority loses the withdraw path while the account owner differs."}],
                 "recommendation": [{"p": "Make the token account optional."}]},
        "attack_steps": [{"text": "The user reassigns the owner of the token account.", "ref": f"src/lib.rs:{VAULT_TOKEN_LINE}"}],
        "claimed_severity": "High", "severity_reason": REASON,
    })
    assert sub["accepted"] is True, sub
    assert sub["status"] == "needs_challenge" and sub["computed_severity"] == "High", sub

    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": sub["draft_key"]})
    assert ch["accepted"] is True, ch
    scope_ranges: set[str] = set()
    for item in ch["items"]:
        assert item["scope"]["ranges"] and not item["scope"].get("not_covered"), item
        scope_ranges.update(item["scope"]["ranges"])
    assert any(_covering([r], "src/lib.rs", VAULT_TOKEN_LINE) for r in scope_ranges), scope_ranges
    assert any(_covering([r], "src/instructions/withdraw.rs", TRANSFER_LINE) for r in scope_ranges), scope_ranges

    # the reviewer read every range the server listed (job_reads), then answers absent with those refs
    for r in scope_ranges:
        path, span = r.rsplit(":", 1)
        s, e = (int(x) for x in span.split("-"))
        await _log_reads(db_pool, job_id, path, s, e)
    refs = sorted(scope_ranges)
    answers = []
    for item in ch["items"]:
        if item["id"] == "MB0":
            answers.append({"item_id": "MB0", "value": "present", "note": "The blocked transfer is the withdraw.",
                            "quotes": [_quote("src/instructions/withdraw.rs", HANDLER_LINES, TRANSFER_LINE, TRANSFER_LINE)]})
        elif item["id"] == "MB1":
            answers.append({"item_id": "MB1", "value": "present", "note": "The frozen amount is the whole vault.",
                            "quotes": [_quote("src/lib.rs", LIB_LINES, VAULT_TOKEN_LINE, VAULT_TOKEN_LINE)]})
        else:
            answers.append({"item_id": item["id"], "value": "absent", "refs": refs,
                            "note": "Nothing in the instruction lets the parties finish without this account."})
    res = await challenge_mod.handle_review_answer_challenge(
        {"job_id": job_id, "draft_key": sub["draft_key"], "revision": sub["revision"], "answers": answers})
    assert res["accepted"] is True, res
    assert res["severity_after"] == "High" and res["verdict"] == "passed", res
    assert "K10" not in res["caps_applied"] and "K10" not in res["severity_rule"], res
    assert "basis=" not in res["severity_rule"], res


@ASYNC
async def test_absent_answer_that_skips_the_struct_range_is_rejected_by_name(db_pool):
    """The struct is in scope: an absent answer whose refs stop at the handler names it."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _solana_job(db_pool)
    ctx = MemoryJobContext(pin_root)
    for mod in (submit_mod, challenge_mod):
        mod.set_pool(db_pool)
        mod.set_context(ctx)
    location = {**_quote("src/lib.rs", LIB_LINES, VAULT_TOKEN_LINE - 1, VAULT_TOKEN_LINE), "role": "location"}
    sub = await submit_mod.handle_review_submit_finding({
        "job_id": job_id, "draft_key": "withdraw-blocked-partial-refs",
        "category": "solana.ata_owner_reassign", "quotes": [location], "matrix": F01_MATRIX, "lead_ids": [],
        "title": "User can block withdraw by reassigning the owner of the vault token account",
        "body": {"description": [{"p": "The vault token account is required with a fixed derived address."}],
                 "impact": [{"p": "The authority loses the withdraw path while the account owner differs."}],
                 "recommendation": [{"p": "Make the token account optional."}]},
        "claimed_severity": "High", "severity_reason": REASON,
    })
    if sub.get("status") != "needs_challenge":
        pytest.skip(f"submission did not reach needs_challenge: {sub}")
    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": sub["draft_key"]})
    handler_only = [r for i in ch["items"] for r in i["scope"]["ranges"] if r.startswith("src/instructions/")]
    for r in set(handler_only):
        path, span = r.rsplit(":", 1)
        s, e = (int(x) for x in span.split("-"))
        await _log_reads(db_pool, job_id, path, s, e)
    answers = [{"item_id": i["id"], "value": "absent", "refs": sorted(set(handler_only)), "note": "n"} for i in ch["items"]]
    res = await challenge_mod.handle_review_answer_challenge(
        {"job_id": job_id, "draft_key": sub["draft_key"], "revision": sub["revision"], "answers": answers})
    # never-worse: recorded as unverified with a warning that names the range
    assert res["accepted"] is True and res["complete"] is False, res
    scope_errors = [w for w in res["warnings"] if w["code"] == "E_CHALLENGE_SCOPE"]
    assert scope_errors, res
    assert any("src/lib.rs" in json.dumps(e) for e in scope_errors), scope_errors
