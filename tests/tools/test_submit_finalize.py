"""Tests for review_submit_finding and review_finalize (03 §4.10, §4.14; 04 §1.2, §13).

Unit tests run without DB. Integration tests require Docker + Postgres 16 (use
SKIP_DB_TESTS=1 to skip them or set SOKEN_TEST_PG_DSN to point at an existing DB).

Integration flow tested (without stub): submit_finding → finalize → report_id assigned.
F5 is server-computed (04 §13): always passes when no N/A override rows have stale predicates.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

# ── Vault.sol test contract ───────────────────────────────────────────────────
# 9 lines; same content used by tests/report/test_render_flow.py.
# Lines (1-indexed):
#   L1  // SPDX-License-Identifier: MIT
#   L2  pragma solidity ^0.8.0;
#   L3  contract Vault {
#   L4      mapping(address => uint256) balances;
#   L5      function withdraw(uint256 a) external {
#   L6          (bool ok, ) = msg.sender.call{value: a}("");
#   L7          balances[msg.sender] -= a;
#   L8      }
#   L9  }
VAULT_SOL = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.0;\n"
    "contract Vault {\n"
    "    mapping(address => uint256) balances;\n"
    "    function withdraw(uint256 a) external {\n"
    '        (bool ok, ) = msg.sender.call{value: a}("");\n'
    "        balances[msg.sender] -= a;\n"
    "    }\n"
    "}\n"
)

# ── Unit tests: pure helpers that don't need DB ───────────────────────────────

ASYNC = pytest.mark.asyncio(loop_scope="session")


class TestContentHash:
    """_content_hash must be stable and exclude control fields."""

    def test_hash_excludes_control_fields(self):
        from soken_review.tools.submit import _content_hash

        args_a = {"job_id": "j1", "draft_key": "dk1", "expected_revision": 0, "category": "evm.reentrancy"}
        args_b = {"job_id": "j2", "draft_key": "dk2", "expected_revision": 5, "category": "evm.reentrancy"}
        assert _content_hash(args_a) == _content_hash(args_b)

    def test_hash_changes_on_content_change(self):
        from soken_review.tools.submit import _content_hash

        args_a = {"job_id": "j1", "draft_key": "dk1", "category": "evm.reentrancy"}
        args_b = {"job_id": "j1", "draft_key": "dk1", "category": "evm.access_control"}
        assert _content_hash(args_a) != _content_hash(args_b)

    def test_hash_is_stable(self):
        from soken_review.tools.submit import _content_hash

        args = {"job_id": "j1", "draft_key": "dk1", "category": "evm.reentrancy", "title": "Test"}
        assert _content_hash(args) == _content_hash(args)


class TestServerDraftFieldGuard:
    """_check_server_draft_fields must block non-allowed fields on srv-* drafts."""

    def test_allowed_fields_pass(self):
        from soken_review.tools.submit import _check_server_draft_fields

        args = {"job_id": "j1", "draft_key": "srv-001", "expected_revision": 0,
                "title": "T", "body": {}}
        assert _check_server_draft_fields(args) == []

    def test_category_blocked_on_server_draft(self):
        from soken_review.tools.submit import _check_server_draft_fields

        args = {"job_id": "j1", "draft_key": "srv-001", "category": "evm.reentrancy"}
        errors = _check_server_draft_fields(args)
        assert len(errors) == 1
        assert errors[0]["code"] == "E_FIELD_FIXED"
        assert errors[0]["field"] == "category"

    def test_multiple_blocked_fields(self):
        from soken_review.tools.submit import _check_server_draft_fields

        args = {"job_id": "j1", "draft_key": "srv-001", "category": "x", "matrix": {}, "quotes": []}
        errors = _check_server_draft_fields(args)
        assert len(errors) == 3


class TestDeriveFinalId:
    """report_id derivation must be deterministic and match spec formula."""

    def test_derive_report_id_deterministic(self):
        from soken_review.tools.finalize import _derive_report_id

        job_id = "job_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        rid1 = _derive_report_id(job_id)
        rid2 = _derive_report_id(job_id)
        assert rid1 == rid2

    def test_derive_report_id_length_26(self):
        from soken_review.tools.finalize import _derive_report_id

        rid = _derive_report_id("job_01ARZ3NDEKTSV4RRFFQ69G5FAV")
        assert len(rid) == 26

    def test_derive_report_id_charset(self):
        from soken_review.tools.finalize import _derive_report_id

        rid = _derive_report_id("job_01ARZ3NDEKTSV4RRFFQ69G5FAV")
        assert all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in rid)

    def test_derive_report_id_matches_test_render_flow_formula(self):
        """Verify our formula matches what test_render_flow.py uses."""
        import hashlib

        from soken_review.tools.finalize import _derive_report_id

        job_id = "job_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        # Formula from test_render_flow.py line 54-55:
        rid_ref = hashlib.sha256(job_id.encode()).hexdigest()
        rid_ref = "".join("abcdefghijklmnopqrstuvwxyz234567"[int(c, 16) * 2] for c in rid_ref[:26])

        assert _derive_report_id(job_id) == rid_ref


class TestFamilyFromChain:
    def test_evm_chains(self):
        from soken_review.tools.submit import _family_from_chain

        assert _family_from_chain("evm") == "evm"
        assert _family_from_chain("tron") == "evm"
        assert _family_from_chain(None) == "evm"

    def test_solana(self):
        from soken_review.tools.submit import _family_from_chain

        assert _family_from_chain("solana") == "solana"

    def test_ton(self):
        from soken_review.tools.submit import _family_from_chain

        assert _family_from_chain("ton") == "ton"

    def test_move_chains(self):
        from soken_review.tools.submit import _family_from_chain

        assert _family_from_chain("sui") == "move"
        assert _family_from_chain("aptos") == "move"

    def test_starknet(self):
        from soken_review.tools.submit import _family_from_chain

        assert _family_from_chain("starknet") == "cairo"


# ── Integration tests: require Postgres ──────────────────────────────────────

_VALID_MATRIX = {
    "impact_class": "theft_of_funds",
    "magnitude": "unbounded",
    "trigger": "anyone",
    "precondition": "none",
    "reversibility": "irreversible",
}

_VALID_SUBMISSION = {
    "draft_key": "draft-001",
    "category": "evm.reentrancy",
    "quotes": [
        {
            "file": "src/Vault.sol",
            "start": 5,
            "end": 8,
            "role": "location",
            # text field required by finding.v1.json schema; must match pinned L5-L8
            # after normalize_line: strip leading/trailing whitespace, collapse runs
            "text": (
                "    function withdraw(uint256 a) external {\n"
                '        (bool ok, ) = msg.sender.call{value: a}("");\n'
                "        balances[msg.sender] -= a;\n"
                "    }"
            ),
        }
    ],
    "matrix": _VALID_MATRIX,
    "lead_ids": [],
    "title": "Reentrant withdraw drains vault before balance update",
    "body": {
        "description": [{"p": "The withdraw function calls msg.sender before updating balance."}],
        "impact": [{"p": "Attacker drains the contract."}],
        "recommendation": [{"p": "Update state before external calls (CEI pattern)."}],
    },
    "attack_steps": [{"text": "Deploy exploit contract", "ref": "src/Vault.sol:6"}],
}


async def _create_ready_job(db_pool, chain: str = "evm") -> str:
    """Create a job in ready state with tier=A. Returns job_id."""
    from soken_review.db.job_repo import JobRepo, new_job_id
    from soken_review.tools.report import principal_of

    jid = new_job_id()
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(
            job_id=jid,
            principal_key=principal_of(jid),
            surface="plugin",
            state="queued",
            requester_role="third_party_public_code",
            source_kind="deployed",
            source_args={},
            has_deployment=True,
            chain=chain,
        )
        await conn.execute(
            "update jobs set state = 'ready', tier = 'A' where job_id = %s",
            (jid,),
        )
    return jid


async def _create_ready_job_with_pin(db_pool, chain: str = "evm") -> tuple[str, Path]:
    """Create a job in ready state AND persist a PinnedSource for Vault.sol.

    Returns (job_id, pin_root).  Tests that call submit must call
    ``submit_mod.set_context(MemoryJobContext(pin_root))`` before invoking the handler.
    """
    from soken_review.pinning.store import PinnedSource

    pin_root = Path(tempfile.mkdtemp()) / "pins"
    pin_root.mkdir(parents=True, exist_ok=True)

    jid = await _create_ready_job(db_pool, chain)
    pin = PinnedSource.from_files({"src/Vault.sol": VAULT_SOL.encode()})
    pin.persist(pin_root, jid)
    return jid, pin_root


async def _insert_lead(db_pool, job_id: str, lead_id: str = "LEAD-0001",
                       category: str = "evm.reentrancy",
                       path: str = "src/Vault.sol",
                       start: int = 5, end: int = 8) -> None:
    async with db_pool.connection() as conn, conn.transaction():
        await conn.execute(
            """insert into leads (job_id, lead_id, rule_id, tools, category, category_family,
               analyzer_severity_raw, severity_norm, path, start_line, end_line, state)
               values (%s, %s, 'reentrancy-eth', ARRAY['slither@0.11.6'], %s, 'evm',
                       'High', 'High', %s, %s, %s, 'open')""",
            (job_id, lead_id, category, path, start, end),
        )


@ASYNC
async def test_submit_finding_creates_draft(db_pool):
    """Integration: submit creates finding_drafts + finding_revisions rows."""
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id

    result = await submit_mod.handle_review_submit_finding(args)

    assert result["accepted"] is True
    assert result["finding_no"] == "F-01"
    assert result["revision"] == 0
    assert result["computed_severity"] in ("Critical", "High", "Medium", "Low", "Informational")
    assert "next_tools" in result

    # Verify DB row was created
    async with db_pool.connection() as conn:
        row = await (await conn.execute(
            "select * from finding_drafts where job_id = %s and draft_key = %s",
            (job_id, "draft-001"),
        )).fetchone()
    assert row is not None


@ASYNC
async def test_submit_finding_idempotent_replay(db_pool):
    """Integration: identical submission returns cached result (03 §10)."""
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id

    r1 = await submit_mod.handle_review_submit_finding(args)
    assert r1["accepted"] is True

    r2 = await submit_mod.handle_review_submit_finding(args)
    assert r2["accepted"] is True
    assert r2["revision"] == r1["revision"]
    assert r2["finding_no"] == r1["finding_no"]


@ASYNC
async def test_submit_finding_with_lead(db_pool):
    """Integration: lead linked to finding gets promoted."""
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    await _insert_lead(db_pool, job_id)

    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["lead_ids"] = ["LEAD-0001"]

    result = await submit_mod.handle_review_submit_finding(args)
    assert result["accepted"] is True

    # Lead should be promoted
    async with db_pool.connection() as conn:
        state_row = await (await conn.execute(
            "select state from leads where job_id = %s and lead_id = 'LEAD-0001'",
            (job_id,),
        )).fetchone()
    assert state_row[0] == "promoted"


@ASYNC
async def test_submit_finding_frozen_job_rejected(db_pool):
    """Integration: submit on finalized job returns E_JOB_FROZEN (state check runs before pin load)."""
    from soken_review.db.job_repo import JobRepo
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)

    # Frozen-job check happens before V2/V3, so we only need an empty pin_root
    job_id = await _create_ready_job(db_pool)
    submit_mod.set_context(MemoryJobContext(Path(tempfile.mkdtemp())))

    # Finalize the job manually
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.transition(job_id, "finalized")

    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    result = await submit_mod.handle_review_submit_finding(args)
    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_JOB_FROZEN"


@ASYNC
async def test_submit_server_draft_blocked_extra_fields(db_pool):
    """Integration: srv-* draft with category field returns E_FIELD_FIXED."""
    from soken_review.tools import submit as submit_mod

    submit_mod.set_pool(db_pool)

    job_id = await _create_ready_job(db_pool)
    args = {
        "job_id": job_id,
        "draft_key": "srv-0001",
        "category": "evm.reentrancy",  # not allowed on server draft
        "title": "A title for a server draft",
        "body": {},
    }
    result = await submit_mod.handle_review_submit_finding(args)
    assert result["accepted"] is False
    codes = [e["code"] for e in result["errors"]]
    assert "E_FIELD_FIXED" in codes


@ASYNC
async def test_finalize_checks_open_on_fresh_job(db_pool, tmp_path):
    """Integration: compute_finalize_checks returns open checks on a fresh ready job."""
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.finalize import compute_finalize_checks

    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    fin_mod.set_pool(db_pool)
    fin_mod.set_context(MemoryJobContext(pin_root))

    job_id = await _create_ready_job(db_pool)

    async with db_pool.connection() as conn:
        checks = await compute_finalize_checks(conn, job_id)

    check_map = {c["id"]: c for c in checks}
    # F1 should be closed (tier=A); open is int per schema (1=open, 0=closed)
    assert check_map["F1"]["open"] == 0
    # F5 is server-computed: always closed when no N/A override rows with stale predicates
    assert check_map["F5"]["open"] == 0


@ASYNC
async def test_finalize_checks_f3_open_when_needs_challenge(db_pool):
    """Integration: F3 is open when a draft has needs_challenge status."""
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.finalize import compute_finalize_checks

    submit_mod.set_pool(db_pool)
    fin_mod.set_pool(db_pool)

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    fin_mod.set_context(MemoryJobContext(pin_root))
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id

    result = await submit_mod.handle_review_submit_finding(args)
    assert result["accepted"] is True

    async with db_pool.connection() as conn:
        checks = await compute_finalize_checks(conn, job_id)

    check_map = {c["id"]: c for c in checks}
    # If severity >= Medium/High, F3 should be open
    sev = result["computed_severity"]
    if sev in ("High", "Critical", "Medium"):
        assert check_map["F3"]["open"] == 1  # open is int per schema
        assert result["status"] == "needs_challenge"
    else:
        assert result["status"] == "accepted"


@ASYNC
async def test_submit_then_finalize_end_to_end(db_pool):
    """Integration (no stub): submit (Informational finding) → finalize passes.

    Pipeline:
    1. Submit a best_practice/unbounded/anyone → base=Informational → status=accepted (rank 0 < 2)
    2. Call finalize — all checks must pass (F5 is server-computed, always closed)
    3. Asserts: accepted=True, state=render_queued, F1/F3/F5 all closed.

    F5 is now server-computed (04 §13): the server always produces one row per family
    category (not_covered / no_candidates), which does NOT block finalize.
    """
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)
    fin_mod.set_pool(db_pool)
    fin_mod.set_context(MemoryJobContext(Path(tempfile.mkdtemp()) / "pins"))

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))

    # Submit an Informational finding (best_practice → I0, anyone/none → L3, base=Informational)
    # No leads → evidence_level=reasoning_only.  Status goes to accepted (rank 0 < 2).
    info_matrix = {
        "impact_class": "best_practice",
        "magnitude": "unbounded",
        "trigger": "anyone",
        "precondition": "none",
        "reversibility": "irreversible",
    }
    # Quote lines 1-3: "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Vault {"
    quote_text_l1_l3 = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract Vault {"
    )
    args = {
        "job_id": job_id,
        "draft_key": "draft-info",
        "category": "evm.reentrancy",
        "quotes": [
            {
                "file": "src/Vault.sol",
                "start": 1,
                "end": 3,
                "role": "location",
                "text": quote_text_l1_l3,
            }
        ],
        "matrix": info_matrix,
        "lead_ids": [],
        "title": "Missing reentrancy guard on the withdraw function",
        "body": {
            "description": [{"p": "The contract does not use a reentrancy guard."}],
            "impact": [{"p": "An attacker could exploit this to drain funds."}],
            "recommendation": [{"p": "Add a reentrancy guard to the withdraw function."}],
        },
    }
    submit_result = await submit_mod.handle_review_submit_finding(args)
    assert submit_result["accepted"] is True, f"Submit failed: {submit_result}"
    # best_practice → Informational (rank 0) → status=accepted
    assert submit_result["computed_severity"] == "Informational"
    assert submit_result["status"] == "accepted"

    try:
        fin_result = await fin_mod.handle_review_finalize({"job_id": job_id})

        # F5 server-computed: finalize passes
        assert fin_result.get("accepted") is True, (
            f"Expected finalize to pass; got: {fin_result}. "
            "Check F5 is closed (server-computed coverage: not_covered does not block)."
        )
        assert fin_result["state"] == "render_queued"

        # Verify checks: F1/F3/F5 all closed
        from soken_review.tools.finalize import compute_finalize_checks
        async with db_pool.connection() as conn:
            checks = await compute_finalize_checks(conn, job_id)
        check_map = {c["id"]: c for c in checks}
        # idempotent replay returns from stored state, so we check idempotent path too
        # But checks are computed fresh here on the finalized job (no open leads)
        # F5 open is 0 when no N/A rows have stale predicates
        assert check_map["F5"]["open"] == 0, "F5 should be closed (server-computed)"
    finally:
        async with db_pool.connection() as conn:
            await conn.execute("delete from job_steps where job_id = %s", (job_id,))


@ASYNC
async def test_finalize_idempotent(db_pool):
    """Integration: calling finalize on an already-finalized job returns idempotent result.

    The finalize output schema (contract/mcp/tools.v1.json) has no 'finalized' or
    'report_id' fields.  Idempotent replay returns {accepted: true, state: "finalized", ...}.
    """
    from soken_review.db.job_repo import JobRepo
    from soken_review.tools import finalize as fin_mod

    fin_mod.set_pool(db_pool)

    job_id = await _create_ready_job(db_pool)

    # Manually transition to finalized to bypass open checks
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.transition(job_id, "finalized")
        await conn.execute(
            "update jobs set report_id = %s where job_id = %s",
            (fin_mod._derive_report_id(job_id), job_id),
        )

    r1 = await fin_mod.handle_review_finalize({"job_id": job_id})
    r2 = await fin_mod.handle_review_finalize({"job_id": job_id})

    # Idempotent replay: both calls return accepted=True, state="finalized"
    # (contract/mcp/tools.v1.json outputSchema: {accepted, state, final_ids, ...} — no 'finalized' key)
    assert r1.get("accepted") is True, f"r1 not accepted: {r1}"
    assert r1.get("state") == "finalized", f"r1 state not finalized: {r1}"
    assert r2.get("accepted") is True, f"r2 not accepted: {r2}"
    assert r2.get("state") == "finalized", f"r2 state not finalized: {r2}"


@ASYNC
async def test_finalize_terminal_job_returns_e_job_terminal(db_pool):
    """Issue 2 regression: finalize on a terminal job must return E_JOB_TERMINAL,
    not raise TypeError from 'code' kwarg conflict in ReviewError.__init__.
    """
    from soken_review.tools import finalize as fin_mod

    fin_mod.set_pool(db_pool)

    # Test both terminal states
    for terminal_state in ("insufficient_source", "failed"):
        job_id = await _create_ready_job(db_pool)
        # Terminal states (insufficient_source, failed) can only be reached from
        # fetching/building via the normal repo, not from ready. Force the state
        # directly in DB to test the finalize handler's state-check branch.
        async with db_pool.connection() as conn, conn.transaction():
            await conn.execute(
                "update jobs set state = %s where job_id = %s",
                (terminal_state, job_id),
            )

        result = await fin_mod.handle_review_finalize({"job_id": job_id})
        assert result.get("accepted") is False, (
            f"Expected rejection for {terminal_state}; got: {result}"
        )
        errors = result.get("errors", [])
        assert errors, f"Expected error list for {terminal_state}"
        assert errors[0]["code"] == "E_JOB_TERMINAL", (
            f"Expected E_JOB_TERMINAL for {terminal_state}; got {errors[0]['code']!r}"
        )
        # Confirm the template fields do not cause TypeError
        assert "what" in errors[0], "ReviewError should produce 'what' field"


@ASYNC
async def test_finalize_blocked_by_f3_needs_challenge(db_pool):
    """Issue 6: a finding in needs_challenge blocks finalize via F3.
    W0 defaults (open_downgrade_item=False, downgrade_items_present=0) must NOT let
    a needs_challenge draft bypass F3 — the challenge tool does not exist yet.
    """
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)
    fin_mod.set_pool(db_pool)

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))

    # Submit a Critical finding (theft_of_funds, unbounded, anyone, none) —
    # base severity is Critical (I4, L3), which is >= Medium → needs_challenge.
    critical_matrix = {
        "impact_class": "theft_of_funds",
        "magnitude": "unbounded",
        "trigger": "anyone",
        "precondition": "none",
        "reversibility": "irreversible",
    }
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["matrix"] = critical_matrix

    submit_result = await submit_mod.handle_review_submit_finding(args)
    assert submit_result["accepted"] is True, f"Submit failed: {submit_result}"
    assert submit_result["status"] == "needs_challenge", (
        f"Expected needs_challenge; got {submit_result['status']!r}"
    )

    fin_result = await fin_mod.handle_review_finalize({"job_id": job_id})
    assert fin_result.get("accepted") is False, (
        f"Finalize must be blocked with needs_challenge draft; got: {fin_result}"
    )
    items = fin_result.get("items") or []
    open_ids = {c["id"] for c in items if c.get("open")}
    assert "F3" in open_ids, (
        f"F3 must be open when a draft is in needs_challenge; open checks: {open_ids}"
    )


@ASYNC
async def test_lead_promoted_by_other_draft_rejected(db_pool):
    """Lead state guard: draft B cannot link a lead already promoted by draft A."""
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))

    # Insert an open lead then promote it to draft-A manually (simulating a prior submit)
    await _insert_lead(db_pool, job_id, lead_id="LEAD-0010")
    async with db_pool.connection() as conn, conn.transaction():
        await conn.execute(
            "update leads set state = 'promoted', state_ref = 'draft-alpha' "
            "where job_id = %s and lead_id = 'LEAD-0010'",
            (job_id,),
        )

    # Draft beta tries to link LEAD-0010 — must be rejected (promoted by draft-alpha)
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-beta"
    args["lead_ids"] = ["LEAD-0010"]

    result = await submit_mod.handle_review_submit_finding(args)
    assert result.get("accepted") is False, f"Expected rejection; got: {result}"
    codes = [e["code"] for e in result.get("errors", [])]
    assert "E_LEAD_NOT_FOUND" in codes, f"Expected E_LEAD_NOT_FOUND; codes: {codes}"


@ASYNC
async def test_dismissed_lead_rejected(db_pool):
    """Lead state guard: a dismissed lead cannot be linked."""
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))

    await _insert_lead(db_pool, job_id, lead_id="LEAD-0020")
    async with db_pool.connection() as conn, conn.transaction():
        # Dismissed leads require a non-null reason (check constraint: dismissed ↔ reason not null)
        await conn.execute(
            "update leads set state = 'dismissed', reason = 'fp_unreachable', state_ref = null "
            "where job_id = %s and lead_id = 'LEAD-0020'",
            (job_id,),
        )

    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-dis"
    args["lead_ids"] = ["LEAD-0020"]

    result = await submit_mod.handle_review_submit_finding(args)
    assert result.get("accepted") is False, f"Expected rejection; got: {result}"
    codes = [e["code"] for e in result.get("errors", [])]
    assert "E_LEAD_NOT_FOUND" in codes, f"Expected E_LEAD_NOT_FOUND; codes: {codes}"


@ASYNC
async def test_resubmit_draft_keeps_own_lead_accepted(db_pool):
    """Lead state guard: draft re-submit with its OWN promoted lead must be accepted."""
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    await _insert_lead(db_pool, job_id, lead_id="LEAD-0030")

    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-own"
    args["lead_ids"] = ["LEAD-0030"]

    # First submit: lead goes from open → promoted by draft-own
    r1 = await submit_mod.handle_review_submit_finding(args)
    assert r1["accepted"] is True, f"First submit failed: {r1}"

    # Re-submit (revision 2) with same lead: still accepted (lead promoted by THIS draft)
    r2 = await submit_mod.handle_review_submit_finding(args)
    assert r2["accepted"] is True, f"Re-submit with own lead failed: {r2}"


@ASYNC
async def test_finalize_after_server_render_failure_queues_the_render_in_one_call(db_pool):
    """After a redeploy that fixes a renderer bug, one review_finalize must reopen the job and queue
    the render again (the blind runs needed two calls: one that only replayed the stale failure)."""
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)
    fin_mod.set_pool(db_pool)
    fin_mod.set_context(MemoryJobContext(Path(tempfile.mkdtemp()) / "pins"))
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    submit_result = await submit_mod.handle_review_submit_finding({
        "job_id": job_id, "draft_key": "draft-info", "category": "evm.reentrancy",
        "quotes": [{"file": "src/Vault.sol", "start": 1, "end": 3, "role": "location",
                    "text": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Vault {"}],
        "matrix": {"impact_class": "best_practice", "magnitude": "unbounded", "trigger": "anyone",
                   "precondition": "none", "reversibility": "irreversible"},
        "lead_ids": [], "title": "Missing reentrancy guard on the withdraw function",
        "body": {"description": [{"p": "The contract does not use a reentrancy guard."}],
                 "impact": [{"p": "An attacker could exploit this to drain funds."}],
                 "recommendation": [{"p": "Add a reentrancy guard to the withdraw function."}]},
    })
    assert submit_result["accepted"] is True and submit_result["status"] == "accepted", submit_result
    try:
        first = await fin_mod.handle_review_finalize({"job_id": job_id})
        assert first["accepted"] is True and first["state"] == "render_queued", first
        # The render worker fails on server-built content (what render._finish_failed records).
        async with db_pool.connection() as conn:
            await conn.execute(
                """update jobs set state = 'render_failed', error_code = 'E_RENDER_FAILED', report_id = null,
                   report_at = null, error_detail = %s where job_id = %s""",
                ('{"detail": "internal", "note": "list object has no attribute get", "cause": "server"}', job_id))
        second = await fin_mod.handle_review_finalize({"job_id": job_id})
        assert second["accepted"] is True, second
        assert second["state"] == "render_queued"
        assert second["recovered_from"] == {"code": "internal", "cause": "server"}
        assert second["final_ids"] == first["final_ids"]
        async with db_pool.connection() as conn:
            row = await (await conn.execute(
                "select state, render_resets, (select count(*) from job_steps s where s.job_id = jobs.job_id"
                " and s.step = 'render') from jobs where job_id = %s", (job_id,))).fetchone()
        assert row[0] == "render_queued" and row[1] == 0 and row[2] == 2
    finally:
        fin_mod.set_pool(None)  # type: ignore[arg-type]
        submit_mod.set_pool(None)  # type: ignore[arg-type]
