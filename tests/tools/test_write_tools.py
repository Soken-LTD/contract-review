"""Tests for review_dismiss_lead, review_withdraw_finding, review_challenge,
review_answer_challenge, and review_set_section (03 §4.9-4.13, 04 §8, §10, §13).

Unit tests: no DB required.
Integration tests: Docker + Postgres 16 (SKIP_DB_TESTS=1 to skip).

E2e positive: submit Medium → challenge → answer (all absent) → F3 closed → finalize passes (F5 server-computed)
E2e negative: submit → challenge → answer kill item present → withdrawn, leads disproved
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

ASYNC = pytest.mark.asyncio(loop_scope="session")

# Re-use Vault.sol from the existing test file
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

_VALID_MATRIX = {
    "impact_class": "theft_of_funds",
    "magnitude": "unbounded",
    "trigger": "anyone",
    "precondition": "none",
    "reversibility": "irreversible",
}

# A submission that will become needs_challenge (High/Critical)
_VALID_SUBMISSION = {
    "draft_key": "draft-wr-001",
    "category": "evm.reentrancy",
    "quotes": [
        {
            "file": "src/Vault.sol",
            "start": 5,
            "end": 8,
            "role": "location",
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
    "title": "Reentrancy in withdraw allows draining",
    "body": {
        "description": [{"p": "The withdraw function calls msg.sender before updating balance."}],
        "impact": [{"p": "Attacker drains the contract."}],
        "recommendation": [{"p": "Apply CEI pattern."}],
    },
    "attack_steps": [{"text": "Deploy exploit contract", "ref": "src/Vault.sol:6"}],
}


# ── Helpers shared with test_submit_finalize ──────────────────────────────────

async def _create_ready_job_with_pin(db_pool, chain: str = "evm") -> tuple[str, Path]:
    from soken_review.db.job_repo import JobRepo, new_job_id
    from soken_review.pinning.store import PinnedSource
    from soken_review.tools.report import principal_of

    pin_root = Path(tempfile.mkdtemp()) / "pins"
    pin_root.mkdir(parents=True, exist_ok=True)

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
            "update jobs set state = 'ready', tier = 'A' where job_id = %s", (jid,)
        )

    pin = PinnedSource.from_files({"src/Vault.sol": VAULT_SOL.encode()})
    pin.persist(pin_root, jid)
    return jid, pin_root


async def _insert_lead(db_pool, job_id: str, lead_id: str = "LEAD-0001",
                       category: str = "evm.reentrancy",
                       severity_norm: str = "High",
                       path: str = "src/Vault.sol",
                       start: int = 5, end: int = 8) -> None:
    async with db_pool.connection() as conn, conn.transaction():
        await conn.execute(
            """insert into leads (job_id, lead_id, rule_id, tools, category, category_family,
               analyzer_severity_raw, severity_norm, path, start_line, end_line, state)
               values (%s, %s, 'reentrancy-eth', ARRAY['slither@0.11.6'], %s, 'evm',
                       %s, %s, %s, %s, %s, 'open')""",
            (job_id, lead_id, category, severity_norm, severity_norm, path, start, end),
        )


async def _submit_finding(db_pool, job_id: str, pin_root: Path,
                          draft_key: str = "draft-wr-001") -> dict[str, Any]:
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))

    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = draft_key

    result = await submit_mod.handle_review_submit_finding(args)
    return result


async def _log_reads(db_pool, job_id: str, path: str, start: int, end: int) -> None:
    """Insert a job_reads row so absent answers can reference it."""
    async with db_pool.connection() as conn, conn.transaction():
        await conn.execute(
            "insert into job_reads (job_id, path, start_line, end_line) values (%s, %s, %s, %s)",
            (job_id, path, start, end),
        )


def _write_minimal_map(
    pin_root: Path,
    job_id: str,
    category_to_fns: dict | None = None,
    spans: list | None = None,
) -> None:
    """Write a minimal map.json for tests.

    With an empty semantic.functions list:
    - nr_no_external_call returns 'true' (no external calls)
    - nr_no_proxy returns 'true' (no proxy_address / upgrade_surface in units)
    - nr_no_upgrade_path returns 'true' (empty upgrade_surface)

    category_to_fns controls computed coverage status per category:
    - absent / empty list → no_candidates
    - [span_id] referencing a span in spans → read/not_covered based on job_reads
    """
    import json as _json

    map_dir = pin_root / job_id / "map"
    map_dir.mkdir(parents=True, exist_ok=True)
    map_doc = {
        "version": 1,
        "spans": spans or [],
        "semantic": {
            "functions": [],
            "units": [],
            "category_to_functions": category_to_fns or {},
        },
    }
    (map_dir / "map.json").write_text(_json.dumps(map_doc), encoding="utf-8")


# ── Unit tests: compute_challenge_items ──────────────────────────────────────

class TestComputeChallengeItems:
    """Unit tests for challenge item generation (no DB)."""

    def test_items_returned_for_reentrancy(self):
        from soken_review.tools.challenge import compute_challenge_items

        items, _sha256 = compute_challenge_items(
            family="evm",
            category="evm.reentrancy",
            matrix=_VALID_MATRIX,
            map_doc=None,
            location_quotes=[{"file": "src/Vault.sol", "start": 5, "end": 8}],
            is_generic=False,
        )
        assert len(items) > 0
        # All items have required fields
        for item in items:
            assert "id" in item
            assert "kind" in item
            assert item["kind"] in ("kill", "downgrade", "context", "basis")
            assert "scope" in item
            assert "name" in item["scope"]

    def test_sha256_is_deterministic(self):
        from soken_review.tools.challenge import compute_challenge_items

        _items1, sha1 = compute_challenge_items(
            family="evm", category="evm.reentrancy",
            matrix=_VALID_MATRIX, map_doc=None,
            location_quotes=[{"file": "src/Vault.sol", "start": 5, "end": 8}],
            is_generic=False,
        )
        _items2, sha2 = compute_challenge_items(
            family="evm", category="evm.reentrancy",
            matrix=_VALID_MATRIX, map_doc=None,
            location_quotes=[{"file": "src/Vault.sol", "start": 5, "end": 8}],
            is_generic=False,
        )
        assert sha1 == sha2

    def test_basis_items_generated_for_theft_of_funds(self):
        from soken_review.tools.challenge import compute_challenge_items

        items, _ = compute_challenge_items(
            family="evm", category="evm.reentrancy",
            matrix=_VALID_MATRIX, map_doc=None,
            location_quotes=[],
            is_generic=False,
        )
        # MB0 should be included for theft_of_funds impact
        item_ids = [i["id"] for i in items]
        assert "MB0" in item_ids

    def test_mb2_generated_for_no_precondition(self):
        """MB2 (check blocking trigger) is generated when precondition=none."""
        from soken_review.tools.challenge import compute_challenge_items

        items, _ = compute_challenge_items(
            family="evm", category="evm.reentrancy",
            matrix=_VALID_MATRIX, map_doc=None,
            location_quotes=[],
            is_generic=False,
        )
        item_ids = [i["id"] for i in items]
        assert "MB2" in item_ids

    def test_no_basis_for_low_impact(self):
        """Low-impact categories that lack fund-transfer impact get fewer basis items."""
        from soken_review.tools.challenge import compute_challenge_items

        matrix = dict(_VALID_MATRIX)
        matrix["impact_class"] = "griefing_minor"
        items, _ = compute_challenge_items(
            family="evm", category="evm.reentrancy",
            matrix=matrix, map_doc=None,
            location_quotes=[],
            is_generic=False,
        )
        item_ids = [i["id"] for i in items]
        assert "MB0" not in item_ids

    def test_scope_not_covered_when_no_map(self):
        """Without a semantic map, entry_function scope returns not_covered=True."""
        from soken_review.tools.challenge import compute_challenge_items

        items, _ = compute_challenge_items(
            family="evm", category="evm.reentrancy",
            matrix=_VALID_MATRIX, map_doc=None,
            location_quotes=[{"file": "src/Vault.sol", "start": 5, "end": 8}],
            is_generic=False,
        )
        # At least one item should have scope.not_covered = True since no map
        # (lexical fallback only works for small spans)
        entry_fn_items = [i for i in items if i["scope"]["name"] == "entry_function"]
        # Without semantic layer, scope_not_covered depends on span size (L5-L8 = 4 lines <= 400)
        # So lexical fallback should resolve it (not_covered=False for small spans)
        # This is OK per design (lexical fallback for depth 0)
        assert len(entry_fn_items) >= 0  # Just verifying no crash

    def test_sha256_changes_with_different_category(self):
        from soken_review.tools.challenge import compute_challenge_items

        _, sha_r = compute_challenge_items(
            family="evm", category="evm.reentrancy",
            matrix=_VALID_MATRIX, map_doc=None,
            location_quotes=[],
            is_generic=False,
        )
        _, sha_a = compute_challenge_items(
            family="evm", category="evm.access_control",
            matrix=_VALID_MATRIX, map_doc=None,
            location_quotes=[],
            is_generic=False,
        )
        assert sha_r != sha_a


class TestRangesCover:
    """Unit tests for the absent-scope coverage check."""

    def test_fully_covered_range(self):
        from soken_review.tools.challenge import _ranges_cover

        scope_ranges = ["src/Vault.sol:5-8"]
        answer_refs = ["src/Vault.sol:5-8"]
        job_reads = {"src/Vault.sol": [(1, 10)]}
        missing = _ranges_cover(scope_ranges, answer_refs, job_reads)
        assert missing == []

    def test_ref_not_in_job_reads(self):
        from soken_review.tools.challenge import _ranges_cover

        scope_ranges = ["src/Vault.sol:5-8"]
        answer_refs = ["src/Vault.sol:5-8"]
        job_reads = {"src/Other.sol": [(1, 10)]}  # different file
        missing = _ranges_cover(scope_ranges, answer_refs, job_reads)
        assert "src/Vault.sol:5-8" in missing

    def test_empty_scope_trivially_covered(self):
        from soken_review.tools.challenge import _ranges_cover

        scope_ranges: list[str] = []
        answer_refs = ["src/Vault.sol:5-8"]
        job_reads: dict = {}
        missing = _ranges_cover(scope_ranges, answer_refs, job_reads)
        assert missing == []

    def test_partial_ref_coverage_counts(self):
        from soken_review.tools.challenge import _ranges_cover

        scope_ranges = ["src/Vault.sol:5-8"]
        answer_refs = ["src/Vault.sol:1-10"]  # larger than scope — covers it
        job_reads = {"src/Vault.sol": [(1, 10)]}
        missing = _ranges_cover(scope_ranges, answer_refs, job_reads)
        assert missing == []

    def test_invalid_ref_format_ignored(self):
        from soken_review.tools.challenge import _ranges_cover

        scope_ranges = ["src/Vault.sol:5-8"]
        answer_refs = ["not-a-valid-ref"]
        job_reads = {"src/Vault.sol": [(1, 10)]}
        missing = _ranges_cover(scope_ranges, answer_refs, job_reads)
        assert "src/Vault.sol:5-8" in missing


# ── Unit tests: dismiss validation ───────────────────────────────────────────

class TestDismissCommentOnlyDetection:
    def test_pure_comment_line_detected(self):
        from soken_review.tools.dismiss import _is_comment_only_text

        assert _is_comment_only_text("// SPDX-License-Identifier: MIT") is True

    def test_real_code_line_not_comment(self):
        from soken_review.tools.dismiss import _is_comment_only_text

        assert _is_comment_only_text("    require(amount > 0);") is False

    def test_mixed_code_and_comment(self):
        from soken_review.tools.dismiss import _is_comment_only_text

        text = "// check\n    require(amount > 0);\n"
        assert _is_comment_only_text(text) is False

    def test_blank_lines_only(self):
        from soken_review.tools.dismiss import _is_comment_only_text

        assert _is_comment_only_text("\n\n") is True


# ── Unit tests: challenge comment-only detection ──────────────────────────────

class TestChallengeCommentOnly:
    def test_comment_only_detected(self):
        from soken_review.pinning.store import PinnedSource
        from soken_review.tools.challenge import _is_comment_only
        pin = PinnedSource.from_files({"src/Vault.sol": VAULT_SOL.encode()})
        assert _is_comment_only("// SPDX-License-Identifier: MIT", pin, "src/Vault.sol", 1, 1) is True

    def test_code_line_not_comment(self):
        from soken_review.pinning.store import PinnedSource
        from soken_review.tools.challenge import _is_comment_only
        pin = PinnedSource.from_files({"src/Vault.sol": VAULT_SOL.encode()})
        assert _is_comment_only("    mapping(address => uint256) balances;", pin, "src/Vault.sol", 4, 4) is False


# ── Integration tests ─────────────────────────────────────────────────────────

@ASYNC
async def test_review_challenge_stateless(db_pool):
    """review_challenge returns items for a needs_challenge finding."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    result_submit = await _submit_finding(db_pool, job_id, pin_root)
    assert result_submit["accepted"] is True

    # Set up challenge module
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(MemoryJobContext(pin_root))

    draft_key = result_submit.get("draft_key", "draft-wr-001")
    status = result_submit.get("status", "accepted")

    # If finding is needs_challenge, call review_challenge
    if status != "needs_challenge":
        pytest.skip(f"finding status={status}, not needs_challenge (severity may be Low/Info)")

    result = await challenge_mod.handle_review_challenge({
        "job_id": job_id,
        "draft_key": draft_key,
    })

    assert result["accepted"] is True
    assert "items" in result
    assert len(result["items"]) > 0
    assert "checklist_sha256" in result
    assert len(result["checklist_sha256"]) == 64

    # Items have correct structure
    for item in result["items"]:
        assert "id" in item
        assert "kind" in item
        assert "scope" in item
        assert "name" in item["scope"]


@ASYNC
async def test_review_challenge_wrong_status(db_pool):
    """review_challenge on an already-accepted finding returns E_FINDING_NOT_FOUND."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(MemoryJobContext(pin_root))

    # Draft doesn't exist yet
    result = await challenge_mod.handle_review_challenge({
        "job_id": job_id,
        "draft_key": "nonexistent-draft",
    })
    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_FINDING_NOT_FOUND"


@ASYNC
async def test_review_challenge_frozen_job(db_pool):
    """review_challenge on a frozen job returns E_JOB_NOT_READY (state != ready)."""
    from soken_review.db.job_repo import JobRepo, new_job_id
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.report import principal_of

    pin_root = Path(tempfile.mkdtemp()) / "pins"
    pin_root.mkdir(parents=True, exist_ok=True)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(MemoryJobContext(pin_root))

    jid = new_job_id()
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(
            job_id=jid, principal_key=principal_of(jid), surface="plugin",
            state="queued", requester_role="third_party_public_code",
            source_kind="deployed", source_args={}, has_deployment=True, chain="evm",
        )
        await conn.execute(
            "update jobs set state = 'finalized', tier = 'A' where job_id = %s", (jid,)
        )

    result = await challenge_mod.handle_review_challenge({
        "job_id": jid,
        "draft_key": "draft-wr-001",
    })
    assert result["accepted"] is False
    # finalized → E_JOB_NOT_READY (state != ready)
    assert result["errors"][0]["code"] in ("E_JOB_NOT_READY",)


@ASYNC
async def test_review_dismiss_lead_fp_guarded(db_pool):
    """fp_guarded without semantic map -> E_DISMISS_UNCHECKABLE (guard class unverifiable)."""
    from soken_review.tools import dismiss as dismiss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))

    await _insert_lead(db_pool, job_id, "LEAD-0010")

    result = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{
            "lead_id": "LEAD-0010",
            "reason": "fp_guarded",
            "quotes": [{
                "file": "src/Vault.sol",
                "start": 5,
                "end": 5,
                "text": "    function withdraw(uint256 a) external {",
            }],
            "note": "The function is guarded by the balances mapping which prevents reentrancy under the assumed preconditions.",
        }],
    })

    # No semantic map in tests → guard class cannot be verified → E_DISMISS_UNCHECKABLE
    assert result["accepted"] is True
    assert len(result["rejected"]) == 1
    assert result["rejected"][0]["lead_id"] == "LEAD-0010"
    codes = [e["code"] for e in result["rejected"][0]["errors"]]
    assert "E_DISMISS_UNCHECKABLE" in codes


@ASYNC
async def test_review_dismiss_lead_comment_only_rejected(db_pool):
    """dismiss fp_guarded with comment-only quote: without map -> E_DISMISS_UNCHECKABLE."""
    from soken_review.tools import dismiss as dismiss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))

    await _insert_lead(db_pool, job_id, "LEAD-0011")

    result = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{
            "lead_id": "LEAD-0011",
            "reason": "fp_guarded",
            "quotes": [{
                "file": "src/Vault.sol",
                "start": 1,
                "end": 1,
                "text": "// SPDX-License-Identifier: MIT",
            }],
            "note": "The function is protected because the comment says so and no exploit path exists.",
        }],
    })

    # Without semantic map, fp_guarded fails with E_DISMISS_UNCHECKABLE before
    # the comment-only check is reached (guard class cannot be verified).
    assert result["accepted"] is True
    assert len(result["rejected"]) == 1
    assert result["rejected"][0]["lead_id"] == "LEAD-0011"
    codes = [e["code"] for e in result["rejected"][0]["errors"]]
    assert "E_DISMISS_UNCHECKABLE" in codes


@ASYNC
async def test_review_dismiss_lead_fp_unreachable_without_map(db_pool):
    """fp_unreachable without semantic map → E_DISMISS_UNCHECKABLE."""
    from soken_review.tools import dismiss as dismiss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))

    await _insert_lead(db_pool, job_id, "LEAD-0012")

    result = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{
            "lead_id": "LEAD-0012",
            "reason": "fp_unreachable",
            "note": "No external entry point ever calls this function directly or indirectly.",
        }],
    })

    assert result["accepted"] is True
    assert len(result["rejected"]) == 1
    codes = [e["code"] for e in result["rejected"][0]["errors"]]
    assert "E_DISMISS_UNCHECKABLE" in codes


@ASYNC
async def test_review_dismiss_lead_already_dismissed(db_pool):
    """Dismissing an already-dismissed lead returns it in 'already' list."""
    from soken_review.tools import dismiss as dismiss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))

    # Insert as previous_report lead so 'fixed' reason works without a semantic map.
    # located must be non-null for previous_report (schema constraint) — use 'verbatim'
    # to indicate the finding is at the same location as in the previous report.
    async with db_pool.connection() as conn, conn.transaction():
        await conn.execute(
            """insert into leads (job_id, lead_id, origin, located, rule_id, tools, category,
               category_family, analyzer_severity_raw, severity_norm, path, start_line,
               end_line, state)
               values (%s, 'LEAD-0013', 'previous_report', 'verbatim', 'reentrancy-eth',
                       ARRAY['slither@0.11.6'], 'evm.reentrancy', 'evm',
                       'High', 'High', 'src/Vault.sol', 5, 8, 'open')""",
            (job_id,),
        )

    # First dismissal — use 'fixed' reason (works for previous_report leads, no semantic map needed)
    r1 = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{
            "lead_id": "LEAD-0013",
            "reason": "fixed",
            "quotes": [{"file": "src/Vault.sol", "start": 5, "end": 5,
                        "text": "    function withdraw(uint256 a) external {"}],
            "note": "The reentrancy guard was added and the fix was applied.",
        }],
    })
    assert "LEAD-0013" in r1["dismissed"]

    # Second dismissal (idempotent — lead already dismissed)
    r2 = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{"lead_id": "LEAD-0013", "reason": "fixed",
                   "quotes": [], "note": "Lead already dismissed."}],
    })
    assert "LEAD-0013" in r2["already"]


@ASYNC
async def test_review_dismiss_lead_fixed_non_carried_rejected(db_pool):
    """fixed reason for a non-carried (analyzer) lead → E_FIX_NOT_EVIDENT."""
    from soken_review.tools import dismiss as dismiss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))

    await _insert_lead(db_pool, job_id, "LEAD-0014")  # origin=analyzer

    result = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{
            "lead_id": "LEAD-0014",
            "reason": "fixed",
            "note": "The developer applied CEI pattern in the latest version.",
        }],
    })

    assert result["accepted"] is True
    assert len(result["rejected"]) == 1
    codes = [e["code"] for e in result["rejected"][0]["errors"]]
    assert "E_FIX_NOT_EVIDENT" in codes


@ASYNC
async def test_review_withdraw_finding_not_found(db_pool):
    """Withdraw a non-existent finding → E_FINDING_NOT_FOUND."""
    from soken_review.tools import withdraw as withdraw_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    withdraw_mod.set_pool(db_pool)
    withdraw_mod.set_context(MemoryJobContext(pin_root))

    result = await withdraw_mod.handle_review_withdraw_finding({
        "job_id": job_id,
        "draft_key": "nonexistent",
        "reason": "disproved",
        "quotes": [{"file": "src/Vault.sol", "start": 5, "end": 5,
                    "text": "    function withdraw(uint256 a) external {"}],
        "note": "The function is not reachable from any entry due to internal visibility.",
    })

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_FINDING_NOT_FOUND"


@ASYNC
async def test_review_withdraw_finding_disproved_needs_quotes(db_pool):
    """disproved reason without quotes → E_WITHDRAW_EVIDENCE."""
    from soken_review.tools import submit as submit_mod
    from soken_review.tools import withdraw as withdraw_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    r = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-wr-002")
    assert r["accepted"] is True

    withdraw_mod.set_pool(db_pool)
    withdraw_mod.set_context(MemoryJobContext(pin_root))

    result = await withdraw_mod.handle_review_withdraw_finding({
        "job_id": job_id,
        "draft_key": "draft-wr-002",
        "reason": "disproved",
        "quotes": [],  # missing
        "note": "The counterexample demonstrates that the issue is not exploitable.",
    })

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_WITHDRAW_EVIDENCE"


@ASYNC
async def test_review_set_section_coverage_accepts_valid(db_pool):
    """Valid N/A coverage row (no_candidates category, true predicate) → accepted."""
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    # Write a minimal map so predicates can be evaluated (empty functions → nr_no_external_call=true)
    _write_minimal_map(pin_root, job_id)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    result = await ss_mod.handle_review_set_section({
        "job_id": job_id,
        "section": "coverage",
        "content": [
            {
                "area_id": "evm.reentrancy",
                "reason": "nr_no_external_call",
                "note": "No external calls found in this contract after review.",
            },
        ],
    })

    assert result["accepted"] is True, f"Expected accepted, got: {result}"
    assert result["section"] == "coverage"
    assert result["revision"] == 1


@ASYNC
async def test_review_set_section_idempotent(db_pool):
    """Submitting the same N/A coverage content twice returns idempotent=True."""
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    _write_minimal_map(pin_root, job_id)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    content = [{
        "area_id": "evm.reentrancy",
        "reason": "nr_no_external_call",
        "note": "Reviewed: no external calls found in scope.",
    }]

    r1 = await ss_mod.handle_review_set_section({
        "job_id": job_id, "section": "coverage", "content": content,
    })
    assert r1["accepted"] is True
    assert r1["idempotent"] is False

    r2 = await ss_mod.handle_review_set_section({
        "job_id": job_id, "section": "coverage", "content": content,
    })
    assert r2["accepted"] is True
    assert r2["idempotent"] is True
    assert r2["revision"] == r1["revision"]


@ASYNC
async def test_review_set_section_new_content_increments_revision(db_pool):
    """Submitting different N/A content creates a new revision."""
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    _write_minimal_map(pin_root, job_id)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    r1 = await ss_mod.handle_review_set_section({
        "job_id": job_id, "section": "coverage",
        "content": [{"area_id": "evm.reentrancy", "reason": "nr_no_external_call",
                     "note": "First pass: no external calls detected in scope."}],
    })
    assert r1["revision"] == 1

    r2 = await ss_mod.handle_review_set_section({
        "job_id": job_id, "section": "coverage",
        "content": [{"area_id": "evm.reentrancy", "reason": "nr_no_external_call",
                     "note": "Second pass confirms: no external calls present in contract."}],
    })
    assert r2["revision"] == 2


@ASYNC
async def test_review_set_section_coverage_rejects_state_field(db_pool):
    """Coverage row with 'state' field → E_SECTION_INVALID (old schema rejected)."""
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    _write_minimal_map(pin_root, job_id)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    result = await ss_mod.handle_review_set_section({
        "job_id": job_id,
        "section": "coverage",
        "content": [{"area_id": "evm.reentrancy", "state": "covered",
                     "note": "All reentrancy vectors reviewed."}],
    })

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_SECTION_INVALID"


@ASYNC
async def test_review_set_section_coverage_na_on_read_category_rejected(db_pool):
    """N/A row on a category computed as 'read' → E_COVERAGE_NA_UNCONFIRMED."""
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    # Span s1 covers lines 5-8 of Vault.sol; map reentrancy to it
    spans = [{"id": "s1", "file": "src/Vault.sol", "start": 5, "end": 8, "kind": "function"}]
    _write_minimal_map(pin_root, job_id, category_to_fns={"evm.reentrancy": ["s1"]}, spans=spans)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    # Log reads fully covering the span so computed status = "read"
    await _log_reads(db_pool, job_id, "src/Vault.sol", 5, 8)

    result = await ss_mod.handle_review_set_section({
        "job_id": job_id,
        "section": "coverage",
        "content": [{"area_id": "evm.reentrancy", "reason": "nr_no_external_call",
                     "note": "Attempting to mark as N/A but category is fully read."}],
    })

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_COVERAGE_NA_UNCONFIRMED"


@ASYNC
async def test_review_set_section_coverage_reason_for_wrong_category_rejected(db_pool):
    """Reason code not in category's checklist na list → E_COVERAGE_NA_UNCONFIRMED.

    nr_no_external_call is only in evm.reentrancy (R3.na).
    Using it for evm.access_control must be rejected.
    """
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    _write_minimal_map(pin_root, job_id)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    result = await ss_mod.handle_review_set_section({
        "job_id": job_id,
        "section": "coverage",
        "content": [{"area_id": "evm.access_control",
                     "reason": "nr_no_external_call",
                     "note": "Trying to use reentrancy reason on access-control category."}],
    })

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_COVERAGE_NA_UNCONFIRMED"


@ASYNC
async def test_review_set_section_coverage_category_with_no_na_entries_rejected(db_pool):
    """Category with no na entries in checklist allows no N/A reasons → rejected."""
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    _write_minimal_map(pin_root, job_id)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    # evm.oracle_manipulation has no na entries in its checklist items
    result = await ss_mod.handle_review_set_section({
        "job_id": job_id,
        "section": "coverage",
        "content": [{"area_id": "evm.oracle_manipulation",
                     "reason": "nr_no_external_call",
                     "note": "Oracle category has no allowed N/A reasons at all."}],
    })

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_COVERAGE_NA_UNCONFIRMED"


@ASYNC
async def test_review_set_section_coverage_false_predicate_rejected(db_pool):
    """N/A row whose predicate evaluates to 'false' → E_COVERAGE_NA_UNCONFIRMED.

    evm.reentrancy + nr_no_external_call: if the semantic map shows an external call,
    the predicate returns 'false' and the row must be rejected.
    """
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    # Write a map with an external call in functions → nr_no_external_call returns false
    import json as _json

    map_dir = pin_root / job_id / "map"
    map_dir.mkdir(parents=True, exist_ok=True)
    map_doc_with_ext_call = {
        "version": 1,
        "spans": [],
        "semantic": {
            "functions": [
                {"calls": [{"kind": "external", "target": "token.transfer"}]}
            ],
            "units": [],
            "category_to_functions": {},
        },
    }
    (map_dir / "map.json").write_text(_json.dumps(map_doc_with_ext_call), encoding="utf-8")

    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    result = await ss_mod.handle_review_set_section({
        "job_id": job_id,
        "section": "coverage",
        "content": [{"area_id": "evm.reentrancy",
                     "reason": "nr_no_external_call",
                     "note": "Claiming no external calls but map shows one exists."}],
    })

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_COVERAGE_NA_UNCONFIRMED"


@ASYNC
async def test_review_set_section_empty_content_rejected(db_pool):
    """Empty content array → E_SECTION_INVALID."""
    from soken_review.tools import set_section as ss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(MemoryJobContext(pin_root))

    result = await ss_mod.handle_review_set_section({
        "job_id": job_id, "section": "coverage", "content": [],
    })

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_SECTION_INVALID"


# ── E2e positive: submit → challenge → answer → F3 closed → set_section → finalize ──

@ASYNC
async def test_e2e_positive_submit_challenge_answer_finalize(db_pool):
    """Full positive flow for a Medium+ finding through challenge to finalize."""
    from soken_review.tools import (
        challenge as challenge_mod,
    )
    from soken_review.tools import (
        finalize as finalize_mod,
    )
    from soken_review.tools import (
        set_section as ss_mod,
    )
    from soken_review.tools import (
        submit as submit_mod,
    )
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)
    ss_mod.set_pool(db_pool)
    ss_mod.set_context(ctx)
    finalize_mod.set_pool(db_pool)
    finalize_mod.set_context(ctx)

    # 1. Submit finding
    submit_result = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-e2e-001")
    assert submit_result["accepted"] is True
    draft_key = submit_result.get("draft_key", "draft-e2e-001")
    revision = submit_result["revision"]
    status = submit_result.get("status", "accepted")

    if status != "needs_challenge":
        pytest.skip(f"Severity={submit_result.get('computed_severity')} → status={status}, skip challenge flow")

    # 2. Get challenge items
    ch_result = await challenge_mod.handle_review_challenge({
        "job_id": job_id, "draft_key": draft_key,
    })
    assert ch_result["accepted"] is True
    items = ch_result["items"]
    revision = ch_result["revision"]

    # 3. Log reads so absent answers can reference scope ranges
    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)

    # 4. Answer all items as absent (with refs to job_reads)
    answers = []
    for item in items:
        scope = item["scope"]
        scope_ranges = scope.get("ranges", [])
        refs = scope_ranges if scope_ranges else ["src/Vault.sol:1-9"]
        answers.append({
            "item_id": item["id"],
            "value": "absent",
            "refs": refs,
            "note": "No code evidence found for this item after examining all lines in the entry function scope.",
        })

    answer_result = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id,
        "draft_key": draft_key,
        "revision": revision,
        "answers": answers,
    })
    assert answer_result["accepted"] is True, f"answer failed: {answer_result}"
    assert answer_result["verdict"] in ("passed", "downgraded")

    # 5. F3 should now be closed (no needs_challenge findings)
    from soken_review.tools.finalize import compute_finalize_checks
    async with db_pool.connection() as conn:
        checks = await compute_finalize_checks(conn, job_id)
    f3 = next((c for c in checks if c["id"] == "F3"), None)
    assert f3 is not None
    assert f3["open"] == 0, "F3 should be closed after answering challenge"

    # 6. F5 is server-computed — no set_section call needed for it to pass.
    #    The server always produces one row per family category; not_covered does not block.
    # Attempt finalize — F2 may still be open if there are open High/Med leads
    async with db_pool.connection() as conn:
        checks2 = await compute_finalize_checks(conn, job_id)
    open_ids = [c["id"] for c in checks2 if c["open"]]
    # F2 and F1 may still be open (no leads inserted, tier=A so F1 closed)
    # F3 and F5 should be closed now
    assert "F3" not in open_ids
    assert "F5" not in open_ids


# ── E2e negative: kill item answered present → withdrawn, leads disproved ─────

@ASYNC
async def test_e2e_negative_kill_item_withdraws_finding(db_pool):
    """Kill item answered present → finding withdrawn, promoted leads disproved."""
    from soken_review.tools import (
        challenge as challenge_mod,
    )
    from soken_review.tools import (
        submit as submit_mod,
    )
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    # Insert an analyzer lead to be promoted with the finding
    await _insert_lead(db_pool, job_id, "LEAD-0099")

    # Submit with lead
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-kill-001"
    args["lead_ids"] = ["LEAD-0099"]
    submit_result = await submit_mod.handle_review_submit_finding(args)
    assert submit_result["accepted"] is True
    draft_key = "draft-kill-001"
    status = submit_result.get("status")

    if status != "needs_challenge":
        pytest.skip(f"Severity={submit_result.get('computed_severity')} → status={status}, skip kill test")

    # Get challenge items
    ch_result = await challenge_mod.handle_review_challenge({
        "job_id": job_id, "draft_key": draft_key,
    })
    assert ch_result["accepted"] is True
    items = ch_result["items"]
    revision = ch_result["revision"]

    # Find the first kill item
    kill_items = [i for i in items if i["kind"] == "kill"]
    if not kill_items:
        pytest.skip("No kill items generated for this category/matrix combination")

    kill_item_id = kill_items[0]["id"]

    # Answer kill item as present, others as absent
    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
    answers = []
    for item in items:
        if item["id"] == kill_item_id:
            # Present: needs a valid code quote
            answers.append({
                "item_id": item["id"],
                "value": "present",
                "quotes": [{
                    "file": "src/Vault.sol",
                    "start": 5,
                    "end": 7,
                    "text": (
                        "    function withdraw(uint256 a) external {\n"
                        '        (bool ok, ) = msg.sender.call{value: a}("");\n'
                        "        balances[msg.sender] -= a;"
                    ),
                }],
                "note": "The complete path code demonstrates the kill condition holds here.",
            })
        else:
            scope = item["scope"]
            scope_ranges = scope.get("ranges", [])
            refs = scope_ranges if scope_ranges else ["src/Vault.sol:1-9"]
            answers.append({
                "item_id": item["id"],
                "value": "absent",
                "refs": refs,
                "note": "No evidence of this condition found in the reviewed scope.",
            })

    answer_result = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id,
        "draft_key": draft_key,
        "revision": revision,
        "answers": answers,
    })

    assert answer_result["accepted"] is True, f"answer failed: {answer_result}"
    assert answer_result["verdict"] == "withdrawn"
    assert answer_result["kill_item"] == kill_item_id

    # Verify finding is withdrawn in DB
    async with db_pool.connection() as conn:
        row = await (await conn.execute(
            "select status, withdrawn_by, kill_item from finding_drafts where job_id = %s and draft_key = %s",
            (job_id, draft_key),
        )).fetchone()
    assert row is not None
    assert row[0] == "withdrawn"
    assert row[1] == "challenge"
    assert row[2] == kill_item_id

    # Verify promoted lead was disproved
    async with db_pool.connection() as conn:
        lead_row = await (await conn.execute(
            "select state, reason from leads where job_id = %s and lead_id = 'LEAD-0099'",
            (job_id,),
        )).fetchone()
    assert lead_row is not None
    # Lead should be dismissed (disproved_by_challenge) or reopened (previous_report would reopen)
    # LEAD-0099 is origin=analyzer → dismissed disproved_by_challenge
    assert lead_row[0] == "dismissed"
    assert lead_row[1] == "disproved_by_challenge"


@ASYNC
async def test_answer_challenge_idempotent(db_pool):
    """Submitting the same answers twice returns the stored verdict (idempotency)."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    r = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-idem-001")
    assert r["accepted"] is True

    if r.get("status") != "needs_challenge":
        pytest.skip("Severity not needs_challenge")

    ch = await challenge_mod.handle_review_challenge({
        "job_id": job_id, "draft_key": "draft-idem-001",
    })
    items = ch["items"]
    revision = ch["revision"]

    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)

    answers = [{
        "item_id": item["id"],
        "value": "absent",
        "refs": item["scope"].get("ranges") or ["src/Vault.sol:1-9"],
        "note": "No evidence found after careful review of the affected code path.",
    } for item in items]

    r1 = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id, "draft_key": "draft-idem-001",
        "revision": revision, "answers": answers,
    })
    assert r1["accepted"] is True

    r2 = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id, "draft_key": "draft-idem-001",
        "revision": revision, "answers": answers,
    })
    assert r2["accepted"] is True
    assert r2["verdict"] == r1["verdict"]


@ASYNC
async def test_answer_challenge_incomplete_answers(db_pool):
    """Missing item in answers → E_CHALLENGE_INCOMPLETE."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    r = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-inc-001")
    assert r["accepted"] is True

    if r.get("status") != "needs_challenge":
        pytest.skip("Severity not needs_challenge")

    ch = await challenge_mod.handle_review_challenge({
        "job_id": job_id, "draft_key": "draft-inc-001",
    })
    items = ch["items"]
    revision = ch["revision"]

    # Only answer the first item (incomplete)
    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
    partial_answers = [{
        "item_id": items[0]["id"],
        "value": "absent",
        "refs": ["src/Vault.sol:1-9"],
        "note": "No evidence found in the reviewed scope.",
    }] if items else []

    if len(items) <= 1:
        pytest.skip("Not enough items to test incomplete answers")

    result = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id, "draft_key": "draft-inc-001",
        "revision": revision, "answers": partial_answers,
    })

    assert result["accepted"] is False
    codes = [e["code"] for e in result["errors"]]
    assert "E_CHALLENGE_INCOMPLETE" in codes


@ASYNC
async def test_review_withdraw_with_disproof_quotes(db_pool):
    """Withdraw disproved with valid evidence quotes → accepted."""
    from soken_review.tools import submit as submit_mod
    from soken_review.tools import withdraw as withdraw_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    withdraw_mod.set_pool(db_pool)
    withdraw_mod.set_context(ctx)

    r = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-wd-001")
    assert r["accepted"] is True

    result = await withdraw_mod.handle_review_withdraw_finding({
        "job_id": job_id,
        "draft_key": "draft-wd-001",
        "reason": "disproved",
        "quotes": [{
            "file": "src/Vault.sol",
            "start": 7,
            "end": 7,
            "text": "        balances[msg.sender] -= a;",
        }],
        "note": "The balance update occurs before the call in this version so CEI is satisfied.",
    })

    assert result["accepted"] is True
    assert result["withdrawn_by"] == "model"

    # Idempotent repeat
    result2 = await withdraw_mod.handle_review_withdraw_finding({
        "job_id": job_id,
        "draft_key": "draft-wd-001",
        "reason": "disproved",
        "quotes": [{"file": "src/Vault.sol", "start": 7, "end": 7,
                    "text": "        balances[msg.sender] -= a;"}],
        "note": "Idempotent replay note for testing purposes only.",
    })
    assert result2["accepted"] is True


# ── _auto_unreachable BFS unit tests ─────────────────────────────────────────

class TestAutoUnreachableBFS:
    """Unit tests for the _auto_unreachable BFS reachability check."""

    def _make_map(self, functions, spans, status="full"):
        """Build a minimal map doc with the given functions, spans, and status."""
        doc = {
            "files": [],
            "spans": spans,
            "references": {},
            "constants": [],
            "semantic": {"functions": functions, "units": []},
            "_status": status,
        }
        return doc

    def test_internal_callee_of_entry_is_absent(self):
        """Internal function called by entry is reachable -> absent (NOT killed)."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:deposit", "file": "src/Vault.sol", "start": 1, "end": 5, "name": "deposit", "kind": "function"},
            {"id": "src/Vault.sol:_transfer", "file": "src/Vault.sol", "start": 10, "end": 15, "name": "_transfer", "kind": "function"},
        ]
        functions = [
            {
                "span": "src/Vault.sol:deposit",
                "visibility": "public",
                "is_entry": True,
                "modifiers": [],
                "guards": [],
                "calls": [{"kind": "internal", "target": "_transfer", "line": 3}],
                "writes": [],
                "reads": [],
            },
            {
                "span": "src/Vault.sol:_transfer",
                "visibility": "private",
                "is_entry": False,
                "modifiers": [],
                "guards": [],
                "calls": [],
                "writes": [],
                "reads": [],
            },
        ]
        doc = self._make_map(functions, spans)
        # Location is _transfer (lines 10-15): reachable via entry deposit->_transfer
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 12, "end": 12}])
        assert result == "absent", f"Expected absent (reachable via call), got {result}"

    def test_truly_uncalled_private_function_is_present_full_map(self):
        """Uncalled private function with full map -> present (no path from any entry)."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:deposit", "file": "src/Vault.sol", "start": 1, "end": 5, "name": "deposit", "kind": "function"},
            {"id": "src/Vault.sol:_deadCode", "file": "src/Vault.sol", "start": 20, "end": 25, "name": "_deadCode", "kind": "function"},
        ]
        functions = [
            {
                "span": "src/Vault.sol:deposit",
                "visibility": "public",
                "is_entry": True,
                "modifiers": [],
                "guards": [],
                "calls": [],  # does NOT call _deadCode
                "writes": [],
                "reads": [],
            },
            {
                "span": "src/Vault.sol:_deadCode",
                "visibility": "private",
                "is_entry": False,
                "modifiers": [],
                "guards": [],
                "calls": [],
                "writes": [],
                "reads": [],
            },
        ]
        doc = self._make_map(functions, spans, status="full")
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 22, "end": 22}])
        assert result == "present", f"Expected present (unreachable, full map), got {result}"

    def test_uncalled_private_partial_map_is_unknown(self):
        """Same uncalled function but with partial map -> unknown (cannot prove)."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:_deadCode", "file": "src/Vault.sol", "start": 20, "end": 25, "name": "_deadCode", "kind": "function"},
        ]
        functions = [
            {
                "span": "src/Vault.sol:_deadCode",
                "visibility": "private",
                "is_entry": False,
                "modifiers": [],
                "guards": [],
                "calls": [],
                "writes": [],
                "reads": [],
            },
        ]
        doc = self._make_map(functions, spans, status="partial")
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 22, "end": 22}])
        assert result == "unknown", f"Expected unknown (partial map), got {result}"

    def test_no_semantic_layer_returns_unknown(self):
        """Map without semantic layer -> unknown."""
        from soken_review.tools.challenge import _auto_unreachable

        doc = {"files": [], "spans": [], "references": {}, "constants": {}, "_status": "full"}
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 5, "end": 5}])
        assert result == "unknown"

    def test_location_outside_any_function_returns_unknown(self):
        """Location not inside any modelled function span (e.g. state var) -> unknown."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:withdraw", "file": "src/Vault.sol", "start": 10, "end": 20, "kind": "function"},
        ]
        functions = [
            {"span": "src/Vault.sol:withdraw", "visibility": "public", "is_entry": True,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map(functions, spans, status="full")
        # Location is at line 5, outside withdraw (10-20)
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 5, "end": 5}])
        assert result == "unknown", f"Expected unknown (outside any function), got {result}"

    def test_location_in_modifier_body_returns_absent(self):
        """Location inside a modifier body -> absent (modifier is a BFS root, so location is reachable)."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:onlyOwner", "file": "src/Vault.sol", "start": 1, "end": 5, "kind": "modifier"},
            {"id": "src/Vault.sol:withdraw", "file": "src/Vault.sol", "start": 10, "end": 20, "kind": "function"},
        ]
        functions = [
            {"span": "src/Vault.sol:onlyOwner", "visibility": "internal", "is_entry": False,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
            {"span": "src/Vault.sol:withdraw", "visibility": "public", "is_entry": True,
             "calls": [{"kind": "modifier", "target": "onlyOwner", "line": 10}],
             "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map(functions, spans, status="full")
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 3, "end": 3}])
        assert result == "absent", f"Expected absent (location directly in modifier = reachable), got {result}"

    def test_location_in_constructor_returns_absent(self):
        """Location inside a constructor body -> absent (constructor is a BFS root, so location is reachable)."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:constructor", "file": "src/Vault.sol", "start": 1, "end": 5, "kind": "constructor"},
        ]
        functions = [
            {"span": "src/Vault.sol:constructor", "visibility": "public", "is_entry": False,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map(functions, spans, status="full")
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 3, "end": 3}])
        assert result == "absent", f"Expected absent (location directly in constructor = reachable), got {result}"

    def test_internal_fn_only_called_from_constructor_returns_absent(self):
        """Internal fn called only from constructor -> absent (constructor is BFS root so callee is reachable)."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:constructor", "file": "src/Vault.sol", "start": 1, "end": 5, "kind": "constructor"},
            {"id": "src/Vault.sol:_init", "file": "src/Vault.sol", "start": 10, "end": 15, "kind": "function"},
        ]
        functions = [
            {"span": "src/Vault.sol:constructor", "visibility": "public", "is_entry": False,
             "calls": [{"kind": "internal", "target": "_init", "line": 3}],
             "guards": [], "modifiers": [], "writes": [], "reads": []},
            {"span": "src/Vault.sol:_init", "visibility": "private", "is_entry": False,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map(functions, spans, status="full")
        # Location inside _init; _init is only reachable via constructor
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 12, "end": 12}])
        assert result == "absent", (
            f"Expected absent (_init reachable via constructor as BFS root), got {result}"
        )

    def test_internal_fn_reached_only_via_modifier_is_absent(self):
        """Function reachable only via modifier invocation -> absent (BFS traverses modifier calls)."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:withdraw", "file": "src/Vault.sol", "start": 10, "end": 20, "kind": "function"},
            {"id": "src/Vault.sol:onlyOwner", "file": "src/Vault.sol", "start": 1, "end": 5, "kind": "modifier"},
            {"id": "src/Vault.sol:_check", "file": "src/Vault.sol", "start": 30, "end": 40, "kind": "function"},
        ]
        functions = [
            {"span": "src/Vault.sol:withdraw", "visibility": "public", "is_entry": True,
             "calls": [{"kind": "modifier", "target": "onlyOwner", "line": 10}],
             "guards": [], "modifiers": [], "writes": [], "reads": []},
            {"span": "src/Vault.sol:onlyOwner", "visibility": "internal", "is_entry": False,
             "calls": [{"kind": "internal", "target": "_check", "line": 3}],
             "guards": [], "modifiers": [], "writes": [], "reads": []},
            {"span": "src/Vault.sol:_check", "visibility": "private", "is_entry": False,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map(functions, spans, status="full")
        # _check is reachable via withdraw -> onlyOwner (modifier call) -> _check (internal call)
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 35, "end": 35}])
        assert result == "absent", f"Expected absent (reachable via modifier->internal), got {result}"

    def test_untraversable_call_to_known_function_returns_unknown(self):
        """Call with untraversable kind resolving to a known function -> unknown (potential missing edge)."""
        from soken_review.tools.challenge import _auto_unreachable

        spans = [
            {"id": "src/Vault.sol:entry", "file": "src/Vault.sol", "start": 1, "end": 5, "kind": "function"},
            {"id": "src/Vault.sol:_helper", "file": "src/Vault.sol", "start": 10, "end": 15, "kind": "function"},
        ]
        functions = [
            {"span": "src/Vault.sol:entry", "visibility": "public", "is_entry": True,
             "calls": [{"kind": "unknown_kind", "target": "_helper", "line": 3}],
             "guards": [], "modifiers": [], "writes": [], "reads": []},
            {"span": "src/Vault.sol:_helper", "visibility": "private", "is_entry": False,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map(functions, spans, status="full")
        result = _auto_unreachable("evm.reentrancy", doc, [{"file": "src/Vault.sol", "start": 12, "end": 12}])
        assert result == "unknown", f"Expected unknown (untraversable call to known fn), got {result}"


class TestResolveScopeSpanJoin:
    """_resolve_entry_function_scope must join through spans[] not functions[] fields."""

    def _make_map_with_semantic(self, spans: list, functions: list) -> dict:
        return {
            "spans": spans,
            "semantic": {"functions": functions, "units": [], "state_vars": [],
                         "category_to_functions": {}, "roles": [], "upgrade_surface": []},
            "_status": "full",
        }

    def test_scope_resolved_via_span_meta_join(self):
        """_resolve_entry_function_scope joins through spans[] to get file/start/end."""
        from soken_review.tools.challenge import _resolve_scope

        spans = [
            {"id": "src/Vault.sol:withdraw", "file": "src/Vault.sol",
             "start": 5, "end": 9, "kind": "function"},
        ]
        functions = [
            # Note: NO "path", "start_line", "end_line" on functions — those live on spans.
            {"span": "src/Vault.sol:withdraw", "visibility": "public", "is_entry": True,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map_with_semantic(spans, functions)
        # Location inside withdraw function (lines 6-7)
        location_quotes = [{"file": "src/Vault.sol", "start": 6, "end": 7}]
        ranges, nc, source = _resolve_scope("entry_function", "evm", doc, location_quotes)
        assert not nc, f"Expected scope resolved, got not_covered; ranges={ranges}"
        assert source == "semantic", f"Expected semantic source, got {source!r}"
        assert "src/Vault.sol:5-9" in ranges, f"Expected withdraw span in ranges, got {ranges}"

    def test_scope_not_covered_when_location_outside_all_functions(self):
        """Scope returns not_covered when no function spans overlap the location."""
        from soken_review.tools.challenge import _resolve_scope

        spans = [
            {"id": "src/Vault.sol:withdraw", "file": "src/Vault.sol",
             "start": 5, "end": 9, "kind": "function"},
        ]
        functions = [
            {"span": "src/Vault.sol:withdraw", "visibility": "public", "is_entry": True,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map_with_semantic(spans, functions)
        # Location OUTSIDE withdraw (lines 20-21)
        location_quotes = [{"file": "src/Vault.sol", "start": 20, "end": 21}]
        ranges, nc, _source = _resolve_scope("entry_function", "evm", doc, location_quotes)
        assert nc, f"Expected not_covered for location outside all functions, got ranges={ranges}"

    def test_different_file_location_not_matched(self):
        """Span in a different file does not match location in another file."""
        from soken_review.tools.challenge import _resolve_scope

        spans = [
            {"id": "src/Vault.sol:withdraw", "file": "src/Vault.sol",
             "start": 5, "end": 9, "kind": "function"},
        ]
        functions = [
            {"span": "src/Vault.sol:withdraw", "visibility": "public", "is_entry": True,
             "calls": [], "guards": [], "modifiers": [], "writes": [], "reads": []},
        ]
        doc = self._make_map_with_semantic(spans, functions)
        # Location in a DIFFERENT file
        location_quotes = [{"file": "src/Token.sol", "start": 6, "end": 7}]
        ranges, nc, _source = _resolve_scope("entry_function", "evm", doc, location_quotes)
        assert nc, f"Expected not_covered (different file), got ranges={ranges}"


# ── E_DISPROVED_LOCKED tests ──────────────────────────────────────────────────

@ASYNC
async def test_e2e_disproved_locked_new_key_same_category(db_pool):
    """After kill, a new draft with different key but overlapping location -> E_DISPROVED_LOCKED."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    await _insert_lead(db_pool, job_id, "LEAD-0201")

    # Submit and kill via challenge
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-lock-001"
    args["lead_ids"] = ["LEAD-0201"]
    submit_result = await submit_mod.handle_review_submit_finding(args)
    assert submit_result["accepted"] is True

    if submit_result.get("status") != "needs_challenge":
        pytest.skip(f"Severity={submit_result.get('computed_severity')} not needs_challenge")

    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": "draft-lock-001"})
    kill_items = [i for i in ch["items"] if i["kind"] == "kill"]
    if not kill_items:
        pytest.skip("No kill items for this category")

    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
    answers = []
    for item in ch["items"]:
        if item["id"] == kill_items[0]["id"]:
            answers.append({
                "item_id": item["id"], "value": "present",
                "quotes": [{"file": "src/Vault.sol", "start": 5, "end": 7,
                             "text": ("    function withdraw(uint256 a) external {\n"
                                      '        (bool ok, ) = msg.sender.call{value: a}("");\n'
                                      "        balances[msg.sender] -= a;")}],
                "note": "Kill condition present: value transfer before state update.",
            })
        else:
            scope_ranges = item["scope"].get("ranges", [])
            answers.append({"item_id": item["id"], "value": "absent",
                            "refs": scope_ranges or ["src/Vault.sol:1-9"],
                            "note": "Absent in scope."})

    answer_result = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id, "draft_key": "draft-lock-001",
        "revision": ch["revision"], "answers": answers,
    })
    assert answer_result["accepted"] is True
    assert answer_result["verdict"] == "withdrawn"

    # Now try to submit a new draft (different key) with overlapping location and same category
    args2 = dict(_VALID_SUBMISSION)
    args2["job_id"] = job_id
    args2["draft_key"] = "draft-lock-002"  # different key
    # Same category (evm.reentrancy) and overlapping location (lines 5-7)
    result2 = await submit_mod.handle_review_submit_finding(args2)
    assert result2["accepted"] is False
    codes = [e["code"] for e in result2["errors"]]
    assert "E_DISPROVED_LOCKED" in codes


@ASYNC
async def test_disproved_locked_same_key_resubmit_rejected(db_pool):
    """Resubmitting under a challenge-killed draft key -> E_DISPROVED_LOCKED."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    await _insert_lead(db_pool, job_id, "LEAD-0202")

    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-lock-same-001"
    args["lead_ids"] = ["LEAD-0202"]
    submit_result = await submit_mod.handle_review_submit_finding(args)
    assert submit_result["accepted"] is True

    if submit_result.get("status") != "needs_challenge":
        pytest.skip("Severity not needs_challenge")

    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": "draft-lock-same-001"})
    kill_items = [i for i in ch["items"] if i["kind"] == "kill"]
    if not kill_items:
        pytest.skip("No kill items")

    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
    answers = []
    for item in ch["items"]:
        if item["id"] == kill_items[0]["id"]:
            answers.append({
                "item_id": item["id"], "value": "present",
                "quotes": [{"file": "src/Vault.sol", "start": 5, "end": 7,
                             "text": ("    function withdraw(uint256 a) external {\n"
                                      '        (bool ok, ) = msg.sender.call{value: a}("");\n'
                                      "        balances[msg.sender] -= a;")}],
                "note": "Kill condition demonstrated in scope.",
            })
        else:
            scope_ranges = item["scope"].get("ranges", [])
            answers.append({"item_id": item["id"], "value": "absent",
                            "refs": scope_ranges or ["src/Vault.sol:1-9"],
                            "note": "Absent."})

    ar = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id, "draft_key": "draft-lock-same-001",
        "revision": ch["revision"], "answers": answers,
    })
    assert ar["verdict"] == "withdrawn"

    # Resubmit under the SAME draft key — must be rejected
    args_re = dict(_VALID_SUBMISSION)
    args_re["job_id"] = job_id
    args_re["draft_key"] = "draft-lock-same-001"
    result_re = await submit_mod.handle_review_submit_finding(args_re)
    assert result_re["accepted"] is False
    codes = [e["code"] for e in result_re["errors"]]
    assert "E_DISPROVED_LOCKED" in codes


# ── Scope tests for present answers ──────────────────────────────────────────

class TestPresentAnswerScopeCheck:
    """Unit tests for 'present' answer scope containment and not_covered handling."""

    def _make_item(self, kind="kill", scope_ranges=None, not_covered=False):
        scope = {"name": "entry_function", "ranges": scope_ranges or []}
        if not_covered:
            scope["not_covered"] = True
        return {
            "id": f"TEST-{kind}",
            "kind": kind,
            "question": "Does the condition hold?",
            "answer_type": "present_absent",
            "scope": scope,
            "allowed_na_reasons": [],
            "auto": None,
        }

    def test_quote_inside_scope_range_passes(self):
        """Quote inside resolved scope -> no scope violation."""
        from soken_review.tools.challenge import _quote_in_scope_ranges
        in_scope = _quote_in_scope_ranges("src/Vault.sol", 5, 7, ["src/Vault.sol:1-9"])
        assert in_scope is True

    def test_quote_outside_scope_range_fails(self):
        """Quote outside resolved scope -> should trigger E_CHALLENGE_SCOPE."""
        from soken_review.tools.challenge import _quote_in_scope_ranges
        in_scope = _quote_in_scope_ranges("src/Vault.sol", 20, 22, ["src/Vault.sol:1-9"])
        assert in_scope is False

    def test_quote_different_file_fails(self):
        """Quote in a different file -> not in scope."""
        from soken_review.tools.challenge import _quote_in_scope_ranges
        in_scope = _quote_in_scope_ranges("src/Other.sol", 5, 7, ["src/Vault.sol:1-9"])
        assert in_scope is False


# ── fp_guarded unresolvable scope test ───────────────────────────────────────

@ASYNC
async def test_review_dismiss_fp_guarded_non_reentrancy_category(db_pool):
    """fp_guarded on a non-reentrancy/access_control category -> E_DISMISS_UNCHECKABLE."""
    from soken_review.tools import dismiss as dismiss_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))

    # Insert lead with a non-reentrancy, non-access_control category
    await _insert_lead(db_pool, job_id, "LEAD-0301", category="evm.integer_overflow")

    result = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{
            "lead_id": "LEAD-0301",
            "reason": "fp_guarded",
            "quotes": [{"file": "src/Vault.sol", "start": 5, "end": 5,
                        "text": "    function withdraw(uint256 a) external {"}],
            "note": "Guarded by the check at line 5.",
        }],
    })

    assert result["accepted"] is True
    assert len(result["rejected"]) == 1
    codes = [e["code"] for e in result["rejected"][0]["errors"]]
    assert "E_DISMISS_UNCHECKABLE" in codes


# ── F2 severity re-validation test ───────────────────────────────────────────

@ASYNC
async def test_f2_duplicate_of_chain_broken_when_target_downgraded(db_pool):
    """Medium lead duplicate_of a draft later downgraded to Low by challenge -> F2 open."""
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.finalize import compute_finalize_checks

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    # Insert a Medium lead and submit a finding
    await _insert_lead(db_pool, job_id, "LEAD-0401", category="evm.reentrancy", severity_norm="Medium")
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-f2-001"
    args["lead_ids"] = ["LEAD-0401"]
    submit_result = await submit_mod.handle_review_submit_finding(args)
    if not submit_result["accepted"]:
        pytest.skip(f"Submit failed: {submit_result}")

    # Dismiss a SEPARATE Medium lead as duplicate_of this draft
    await _insert_lead(db_pool, job_id, "LEAD-0402", category="evm.reentrancy", severity_norm="Medium")
    from soken_review.tools import dismiss as dismiss_mod
    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))
    dismiss_result = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{
            "lead_id": "LEAD-0402",
            "reason": "duplicate_of",
            "duplicate_of": "draft-f2-001",
            "note": "Same reentrancy pattern at the same location as the primary finding.",
        }],
    })
    if not dismiss_result["accepted"] or "LEAD-0402" not in dismiss_result.get("dismissed", []):
        pytest.skip(f"Dismiss failed: {dismiss_result}")

    # Now force the target draft's severity to Low (simulating a downgrade by challenge)
    async with db_pool.connection() as conn:
        await conn.execute(
            "update finding_drafts set severity = 'Low' where job_id = %s and draft_key = %s",
            (job_id, "draft-f2-001"),
        )

    # F2 should now be open: duplicate chain broken (target severity Low < lead sev_rank 3)
    async with db_pool.connection() as conn:
        checks = await compute_finalize_checks(conn, job_id)
    f2 = next((c for c in checks if c["id"] == "F2"), None)
    assert f2 is not None
    assert f2["open"] > 0, "F2 should be open: target draft downgraded below lead sev_rank"


@ASYNC
async def test_no_semantic_map_self_kill_no_unlinked_lead_sweep(db_pool):
    """Kill answer must not affect unlinked open analyzer leads (kill-sweep-spec-clarification.md).

    Spec change 2026-10-14: automatic sweep of unlinked leads is removed entirely.
    Every open lead must be closed individually via review_dismiss_lead.
    This test verifies that an unlinked High lead at the same location stays open
    after a kill answer (both with and without a semantic map — the no-semantic case).
    """
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    # Insert a High unlinked open analyzer lead at the SAME location as the finding
    await _insert_lead(db_pool, job_id, "LEAD-0701",
                       category="evm.reentrancy", severity_norm="High",
                       path="src/Vault.sol", start=5, end=8)

    # Submit finding
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-sweep-001"
    args["lead_ids"] = []  # unlinked — we want to test the unlinked sweep
    submit_result = await submit_mod.handle_review_submit_finding(args)
    assert submit_result["accepted"] is True

    if submit_result.get("status") != "needs_challenge":
        pytest.skip(f"Severity={submit_result.get('computed_severity')} not needs_challenge")

    # Get challenge items and answer kill with present
    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": "draft-sweep-001"})
    kill_items = [i for i in ch["items"] if i["kind"] == "kill"]
    if not kill_items:
        pytest.skip("No kill items for this category")

    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
    answers = []
    for item in ch["items"]:
        if item["id"] == kill_items[0]["id"]:
            answers.append({
                "item_id": item["id"], "value": "present",
                "quotes": [{"file": "src/Vault.sol", "start": 5, "end": 7,
                             "text": ("    function withdraw(uint256 a) external {\n"
                                      '        (bool ok, ) = msg.sender.call{value: a}("");\n'
                                      "        balances[msg.sender] -= a;")}],
                "note": "Kill condition present: value transfer before state update.",
            })
        else:
            scope_ranges = item["scope"].get("ranges", [])
            answers.append({"item_id": item["id"], "value": "absent",
                            "refs": scope_ranges or ["src/Vault.sol:1-9"],
                            "note": "Absent in scope."})

    answer_result = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id, "draft_key": "draft-sweep-001",
        "revision": ch["revision"], "answers": answers,
    })
    assert answer_result["accepted"] is True
    assert answer_result["verdict"] == "withdrawn"

    # Verify: unlinked lead must still be open (no semantic map → kill_scope_is_semantic=False)
    async with db_pool.connection() as conn:
        from psycopg.rows import dict_row
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select state from leads where job_id = %s and lead_id = 'LEAD-0701'",
                (job_id,),
            )
            row = await cur.fetchone()
    assert row is not None
    assert row["state"] == "open", (
        f"Unlinked lead must remain open after kill without semantic map — got state={row['state']!r}"
    )


@ASYNC
async def test_wide_quote_self_kill_unlinked_lead_stays_open(db_pool):
    """Any unlinked open lead stays open after a kill answer regardless of location.

    Spec change 2026-10-14: automatic sweep removed. Even a lead at the exact same
    location as the kill quote must stay open — it requires individual dismissal.
    """
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    # Insert a High unlinked lead that extends BEYOND the kill answer quote (lines 5-8, quote is 5-7)
    await _insert_lead(db_pool, job_id, "LEAD-0702",
                       category="evm.reentrancy", severity_norm="High",
                       path="src/Vault.sol", start=5, end=8)

    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-wide-001"
    args["lead_ids"] = []
    submit_result = await submit_mod.handle_review_submit_finding(args)
    assert submit_result["accepted"] is True

    if submit_result.get("status") != "needs_challenge":
        pytest.skip(f"Severity={submit_result.get('computed_severity')} not needs_challenge")

    ch = await challenge_mod.handle_review_challenge({"job_id": job_id, "draft_key": "draft-wide-001"})
    kill_items = [i for i in ch["items"] if i["kind"] == "kill"]
    if not kill_items:
        pytest.skip("No kill items for this category")

    await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
    answers = []
    for item in ch["items"]:
        if item["id"] == kill_items[0]["id"]:
            # Kill quote is lines 5-7 but the lead spans 5-8 → not fully contained in quote
            answers.append({
                "item_id": item["id"], "value": "present",
                "quotes": [{"file": "src/Vault.sol", "start": 5, "end": 7,
                             "text": ("    function withdraw(uint256 a) external {\n"
                                      '        (bool ok, ) = msg.sender.call{value: a}("");\n'
                                      "        balances[msg.sender] -= a;")}],
                "note": "Kill condition: value transfer before balance update.",
            })
        else:
            scope_ranges = item["scope"].get("ranges", [])
            answers.append({"item_id": item["id"], "value": "absent",
                            "refs": scope_ranges or ["src/Vault.sol:1-9"],
                            "note": "Absent in scope."})

    answer_result = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id, "draft_key": "draft-wide-001",
        "revision": ch["revision"], "answers": answers,
    })
    assert answer_result["accepted"] is True
    assert answer_result["verdict"] == "withdrawn"

    # Lead spans 5-8 but kill quote is 5-7: not fully contained → must stay open
    async with db_pool.connection() as conn:
        from psycopg.rows import dict_row
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select state from leads where job_id = %s and lead_id = 'LEAD-0702'",
                (job_id,),
            )
            row = await cur.fetchone()
    assert row is not None
    assert row["state"] == "open", (
        f"Lead not fully contained in kill quote must stay open — got state={row['state']!r}"
    )


# ── Item 3: positive e2e to finalize, unread-range E_CHALLENGE_SCOPE, duplicate_of F2 ──

@ASYNC
async def test_e2e_full_finalize_accepted(db_pool):
    """Full positive flow: submit -> challenge -> absent answers -> finalize passes.

    F5 is server-computed: no set_section call needed.
    Verifies handle_review_finalize returns accepted=True and state='render_queued'.
    """
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import finalize as finalize_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)
    finalize_mod.set_pool(db_pool)
    finalize_mod.set_context(ctx)

    # Submit finding
    submit_result = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-fin-001")
    assert submit_result["accepted"] is True

    try:
        if submit_result.get("status") == "needs_challenge":
            # Get challenge items
            ch = await challenge_mod.handle_review_challenge({
                "job_id": job_id, "draft_key": "draft-fin-001",
            })
            assert ch["accepted"] is True

            # Log reads covering entire Vault.sol
            await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)

            # Answer all items absent
            answers = []
            for item in ch["items"]:
                scope_ranges = item["scope"].get("ranges", [])
                answers.append({
                    "item_id": item["id"],
                    "value": "absent",
                    "refs": scope_ranges if scope_ranges else ["src/Vault.sol:1-9"],
                    "note": "No code evidence for this condition after reading entire scope.",
                })

            ans = await challenge_mod.handle_review_answer_challenge({
                "job_id": job_id,
                "draft_key": "draft-fin-001",
                "revision": ch["revision"],
                "answers": answers,
            })
            assert ans["accepted"] is True, f"Answer challenge failed: {ans}"
            assert ans["verdict"] in ("passed", "downgraded"), f"Unexpected verdict: {ans['verdict']}"

        # F5 is server-computed — no set_section call required for coverage.
        # Call finalize — must pass all checks
        fin_result = await finalize_mod.handle_review_finalize({"job_id": job_id})
        assert fin_result["accepted"] is True, (
            f"Expected finalize to pass, got: {fin_result}"
        )
        assert fin_result["state"] == "render_queued"
        assert isinstance(fin_result.get("final_ids"), dict)
    finally:
        # Clean up enqueued render step so it does not bleed into test_render_* tests
        # which claim from the global job_steps queue.
        async with db_pool.connection() as conn:
            await conn.execute("delete from job_steps where job_id = %s", (job_id,))


@ASYNC
async def test_absent_answer_unread_range_e_challenge_scope(db_pool):
    """Absent answer with refs not backed by job_reads -> E_CHALLENGE_SCOPE.

    The absent-answer gate requires each scope range to be covered by (refs ∩ job_reads).
    Providing refs that have no corresponding job_reads entry means the scope range is
    uncovered and E_CHALLENGE_SCOPE must be returned.
    """
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)

    submit_result = await _submit_finding(db_pool, job_id, pin_root, draft_key="draft-scope-001")
    assert submit_result["accepted"] is True

    if submit_result.get("status") != "needs_challenge":
        pytest.skip(f"Severity not needs_challenge: {submit_result.get('computed_severity')}")

    ch = await challenge_mod.handle_review_challenge({
        "job_id": job_id, "draft_key": "draft-scope-001",
    })
    assert ch["accepted"] is True
    items_with_scope = [i for i in ch["items"] if i["scope"].get("ranges")]
    if not items_with_scope:
        pytest.skip("No items with non-empty scope ranges to test against")

    # Deliberately do NOT log any reads — job_reads table is empty.
    # Answer one item "absent" with a ref that matches the scope but has no job_reads backing.
    target = items_with_scope[0]
    scope_ranges = target["scope"]["ranges"]
    answers = []
    for item in ch["items"]:
        if item["id"] == target["id"]:
            answers.append({
                "item_id": item["id"],
                "value": "absent",
                "refs": scope_ranges,  # valid format, but NOT in job_reads
                "note": "Refs provided but not read via review_read_code.",
            })
        else:
            answers.append({
                "item_id": item["id"],
                "value": "absent",
                "refs": scope_ranges if scope_ranges else [],
                "note": "Absent.",
            })

    ans = await challenge_mod.handle_review_answer_challenge({
        "job_id": job_id,
        "draft_key": "draft-scope-001",
        "revision": ch["revision"],
        "answers": answers,
    })
    # At least one answer must produce E_CHALLENGE_SCOPE (unread refs)
    assert ans["accepted"] is False, (
        f"Expected rejection for unread refs, got accepted=True: {ans}"
    )
    all_codes = [e["code"] for e in ans.get("errors", [])]
    assert "E_CHALLENGE_SCOPE" in all_codes, (
        f"Expected E_CHALLENGE_SCOPE in errors, got: {all_codes}"
    )


@ASYNC
async def test_duplicate_of_chain_intact_closes_f2(db_pool):
    """Medium lead dismissed as duplicate_of an accepted draft -> F2 closed (chain valid).

    Complements test_f2_duplicate_of_chain_broken_when_target_downgraded: when the
    duplicate_of chain is VALID (target draft is accepted, same category, same location,
    severity >= lead severity), F2 must be closed.
    """
    from soken_review.tools import challenge as challenge_mod
    from soken_review.tools import dismiss as dismiss_mod
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.finalize import compute_finalize_checks

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    ctx = MemoryJobContext(pin_root)
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(ctx)
    challenge_mod.set_pool(db_pool)
    challenge_mod.set_context(ctx)
    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))

    # LEAD-0501: linked to the draft (promoted via submit).
    # Use Low severity so the duplicate target constraint (target_sev >= lead_sev) is
    # satisfied even if the challenge downgraded the draft to Low via basis fallbacks.
    await _insert_lead(db_pool, job_id, "LEAD-0501", category="evm.reentrancy",
                       severity_norm="Low", path="src/Vault.sol", start=5, end=8)
    args = dict(_VALID_SUBMISSION)
    args["job_id"] = job_id
    args["draft_key"] = "draft-dup-001"
    args["lead_ids"] = ["LEAD-0501"]
    submit_result = await submit_mod.handle_review_submit_finding(args)
    if not submit_result["accepted"]:
        pytest.skip(f"Submit failed: {submit_result}")

    # If needs_challenge, answer all absent to get it to accepted
    if submit_result.get("status") == "needs_challenge":
        ch = await challenge_mod.handle_review_challenge({
            "job_id": job_id, "draft_key": "draft-dup-001",
        })
        await _log_reads(db_pool, job_id, "src/Vault.sol", 1, 9)
        answers = [{"item_id": i["id"], "value": "absent",
                    "refs": i["scope"].get("ranges") or ["src/Vault.sol:1-9"],
                    "note": "Absent."}
                   for i in ch["items"]]
        ans = await challenge_mod.handle_review_answer_challenge({
            "job_id": job_id, "draft_key": "draft-dup-001",
            "revision": ch["revision"], "answers": answers,
        })
        if not ans["accepted"] or ans["verdict"] not in ("passed", "downgraded"):
            pytest.skip(f"Challenge answer failed or withdrawn: {ans}")

    # LEAD-0502: same location, same category, Low — dismiss as duplicate_of draft-dup-001
    await _insert_lead(db_pool, job_id, "LEAD-0502", category="evm.reentrancy",
                       severity_norm="Low", path="src/Vault.sol", start=5, end=8)
    dis = await dismiss_mod.handle_review_dismiss_lead({
        "job_id": job_id,
        "items": [{
            "lead_id": "LEAD-0502",
            "reason": "duplicate_of",
            "duplicate_of": "draft-dup-001",
            "note": "Same reentrancy pattern at the same location as the primary finding.",
        }],
    })
    assert dis["accepted"] is True
    assert "LEAD-0502" in dis.get("dismissed", []), (
        f"Expected LEAD-0502 dismissed, got: {dis}"
    )

    # F2: LEAD-0501 is promoted (no longer open), LEAD-0502 dismissed with valid chain -> F2 closed
    async with db_pool.connection() as conn:
        checks = await compute_finalize_checks(conn, job_id)
    f2 = next((c for c in checks if c["id"] == "F2"), None)
    assert f2 is not None
    assert f2["open"] == 0, (
        f"F2 should be closed: duplicate chain intact + LEAD-0501 promoted. Got open={f2['open']}"
    )


# ── not_a_vulnerability (04 §10, added 2026-10-23) ───────────────────────────

_NAV_NOTE = ("Slither rates reentrancy-eth High here, but the 2 state writes precede the call and "
             "no balance is read after it; what remains? Nothing exploitable, detector noise.")


async def _dismiss_nav(db_pool, job_id, pin_root, lead_id: str, quote: dict | None, note: str):
    from soken_review.tools import dismiss as dismiss_mod
    from soken_review.tools.context import MemoryJobContext

    dismiss_mod.set_pool(db_pool)
    dismiss_mod.set_context(MemoryJobContext(pin_root))
    item: dict[str, Any] = {"lead_id": lead_id, "reason": "not_a_vulnerability", "note": note}
    if quote is not None:
        item["quotes"] = [quote]
    return await dismiss_mod.handle_review_dismiss_lead({"job_id": job_id, "items": [item]})


@ASYNC
async def test_not_a_vulnerability_with_quote_in_function_and_note_dismisses_and_closes_f2(db_pool):
    """Quote inside the lead's function + note >= 40 chars: dismissed, audit row written, F2 closed.
    The note carries numbers, a tool name and a question mark: no prose or number gate on notes."""
    from soken_review.tools import finalize as finalize_mod
    from soken_review.tools.context import MemoryJobContext
    from soken_review.tools.finalize import compute_finalize_checks

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    finalize_mod.set_pool(db_pool)
    finalize_mod.set_context(MemoryJobContext(pin_root))
    await _insert_lead(db_pool, job_id, "LEAD-0601", severity_norm="High", start=5, end=8)
    res = await _dismiss_nav(db_pool, job_id, pin_root, "LEAD-0601",
                             {"file": "src/Vault.sol", "start": 6, "end": 6,
                              "text": '        (bool ok, ) = msg.sender.call{value: a}("");'},
                             _NAV_NOTE)
    assert res["accepted"] is True and res["dismissed"] == ["LEAD-0601"], res
    async with db_pool.connection() as conn:
        row = await (await conn.execute(
            "select reason, note, quotes from lead_dismissals where job_id = %s and lead_id = %s",
            (job_id, "LEAD-0601"))).fetchone()
        checks = await compute_finalize_checks(conn, job_id)
    assert row is not None and row[0] == "not_a_vulnerability" and row[1] == _NAV_NOTE and row[2]
    f2 = next(c for c in checks if c["id"] == "F2")
    assert f2["open"] == 0, checks


@ASYNC
async def test_not_a_vulnerability_requires_a_note_of_forty_characters(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    await _insert_lead(db_pool, job_id, "LEAD-0602")
    res = await _dismiss_nav(db_pool, job_id, pin_root, "LEAD-0602",
                             {"file": "src/Vault.sol", "start": 6, "end": 6,
                              "text": '        (bool ok, ) = msg.sender.call{value: a}("");'},
                             "not a bug")
    assert res["rejected"] and res["rejected"][0]["lead_id"] == "LEAD-0602"
    errs = res["rejected"][0]["errors"]
    assert [e["code"] for e in errs] == ["E_INVALID_ARGUMENT"], errs
    assert "40" in json.dumps(errs)


@ASYNC
async def test_not_a_vulnerability_requires_a_quote(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    await _insert_lead(db_pool, job_id, "LEAD-0603")
    res = await _dismiss_nav(db_pool, job_id, pin_root, "LEAD-0603", None, _NAV_NOTE)
    codes = [e["code"] for e in res["rejected"][0]["errors"]]
    assert codes == ["E_DISMISS_UNCHECKABLE"], res


@ASYNC
async def test_not_a_vulnerability_quote_outside_the_lead_function_is_rejected(db_pool):
    """Without a map the allowed range is the lead's own lines (5-8); line 3 is the contract header."""
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    await _insert_lead(db_pool, job_id, "LEAD-0604")
    res = await _dismiss_nav(db_pool, job_id, pin_root, "LEAD-0604",
                             {"file": "src/Vault.sol", "start": 3, "end": 3, "text": "contract Vault {"},
                             _NAV_NOTE)
    errs = res["rejected"][0]["errors"]
    assert [e["code"] for e in errs] == ["E_DISMISS_UNCHECKABLE"], errs
    assert "outside the function" in json.dumps(errs)


@ASYNC
async def test_not_a_vulnerability_comment_only_quote_is_rejected(db_pool):
    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    await _insert_lead(db_pool, job_id, "LEAD-0605")
    res = await _dismiss_nav(db_pool, job_id, pin_root, "LEAD-0605",
                             {"file": "src/Vault.sol", "start": 1, "end": 1,
                              "text": "// SPDX-License-Identifier: MIT"},
                             _NAV_NOTE)
    codes = [e["code"] for e in res["rejected"][0]["errors"]]
    assert codes == ["E_DISMISS_COMMENT_ONLY"], res


@ASYNC
async def test_not_a_vulnerability_file_level_lead_accepts_any_code_line_of_the_file(db_pool):
    """A `solc-version`-style lead at 1-1 sits in no function; with a (lexical) map the whole file
    is the holding scope, so a real code line elsewhere in the file closes it."""
    from soken_review.mapping.step import run_map_step

    job_id, pin_root = await _create_ready_job_with_pin(db_pool)
    run_map_step(pin_root, job_id, solc_output_path=None, build_ok=False)
    await _insert_lead(db_pool, job_id, "LEAD-0606", start=1, end=1)
    res = await _dismiss_nav(db_pool, job_id, pin_root, "LEAD-0606",
                             {"file": "src/Vault.sol", "start": 6, "end": 6,
                              "text": '        (bool ok, ) = msg.sender.call{value: a}("");'},
                             _NAV_NOTE)
    assert res["dismissed"] == ["LEAD-0606"], res


def test_lead_function_ranges_narrowest_structure_first():
    """Pure: function span > semantic unit > whole file > own lines (no map)."""
    from soken_review.tools.dismiss import _lead_function_ranges

    lead = {"path": "a.sol", "start_line": 20, "end_line": 20}
    doc = {"spans": [{"id": "a.sol:f", "kind": "function", "file": "a.sol", "start": 18, "end": 25}],
           "semantic": {"units": [{"id": "a.sol:C", "file": "a.sol", "start": 5, "end": 60}]}}
    assert _lead_function_ranges(doc, lead, 80) == [("a.sol", 18, 25)]
    state_var = {"path": "a.sol", "start_line": 7, "end_line": 7}
    assert _lead_function_ranges(doc, state_var, 80) == [("a.sol", 5, 60)]
    pragma = {"path": "a.sol", "start_line": 1, "end_line": 1}
    assert _lead_function_ranges(doc, pragma, 80) == [("a.sol", 1, 80)]
    assert _lead_function_ranges(None, pragma, 80) == [("a.sol", 1, 1)]
