"""Regression tests for the 8 bugs found during the 2026-10-25 blind client-path run.

Bug 1  – TON/Solana/Starknet render step intercepted by family runner; see test_supervisor.py
         (test_ton_render_step_uses_generic_handler added there).
Bug 2  – Disclaimer section class="keep" caused layout_overflow.
Bug 3  – review_set_section rejected roles_notes/coverage/out_of_scope_reasons because
         content was extracted from args["content"] not args[section]["rows"].
Bug 4a – F1 finalize check had no tool/reason field.
Bug 4b – Finalize passed with no roles_notes when J2/J3/J4 flags present (new F7 check).
Bug 5  – review_read_code raised E_RANGE_INVALID for end > total; now clamped (test_read.py
         and test_hardening.py updated; test_end_past_eof_clamped added).
Bug 6a – E_QUOTE_MISMATCH printed empty line numbers because callers passed start=/end=
         instead of the template's range= field.
Bug 6b – E_CHALLENGE_SCOPE for present answer did not name the offending quote.
Bug 6c – E_ABSENCE_UNRESOLVED did not name the prose field where the phrase was found.
Bug 7  – source.nsloc=0 for TON/TRON/Solana; now falls back to pin line counts.
Bug 8  – review_status(detailed) had no build section; map tool said "see review_status build".
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Bug 2 — Disclaimer must NOT have class="keep"
# ---------------------------------------------------------------------------


def test_disclaimer_has_no_keep_class():
    """Bug 2: disclaimer section must not carry class='keep' (causes layout_overflow)."""
    import inspect

    from soken_review.report.kit import build as build_mod

    src = inspect.getsource(build_mod)
    # The disclaimer section must not have class="keep" in non-comment code lines
    disclaimer_lines = [
        ln for ln in src.splitlines()
        if "disclaimer" in ln and 'class="keep"' in ln and not ln.lstrip().startswith("#")
    ]
    assert disclaimer_lines == [], (
        f"Bug 2: disclaimer code still carries class='keep': {disclaimer_lines!r}"
    )


# ---------------------------------------------------------------------------
# Bug 3 — review_set_section content extraction from args[section]["rows"]
# ---------------------------------------------------------------------------


def test_set_section_extracts_roles_notes_from_section_key():
    """Bug 3: roles_notes sent as {roles_notes: {rows: [...]}} must not reject with
    'content must be an array' — verify via source inspection that extraction is present."""
    import inspect

    from soken_review.tools import set_section as ss_mod

    src = inspect.getsource(ss_mod.handle_review_set_section)
    # The handler must extract from args[section]["rows"] for these sections
    assert "roles_notes" in src and "rows" in src, (
        "Bug 3: handler must extract content from args[section]['rows'] for roles_notes/coverage/out_of_scope_reasons"
    )
    # Verify specifically: the extraction block exists
    assert 'section_arg.get("rows")' in src or "section_arg.get('rows')" in src, (
        "Bug 3: content extraction from args[section]['rows'] not found in handler"
    )


def test_set_section_example_field_not_empty():
    """Bug 3: E_SECTION_INVALID fix must include a real example, not an empty {example}."""
    import asyncio

    from soken_review.tools import set_section as ss_mod

    async def _run():
        mock_pool = MagicMock()
        conn_ctx = AsyncMock()
        conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
        conn_ctx.__aexit__ = AsyncMock(return_value=False)
        cur_ctx = AsyncMock()
        cur_ctx.__aenter__ = AsyncMock(return_value=cur_ctx)
        cur_ctx.__aexit__ = AsyncMock(return_value=False)
        cur_ctx.execute = AsyncMock()
        cur_ctx.fetchone = AsyncMock(return_value={
            "job_id": "job_TEST_ROLES02",
            "state": "ready",
            "ownership_proven": False,
        })
        conn_ctx.cursor = MagicMock(return_value=cur_ctx)
        mock_pool.connection = MagicMock(return_value=conn_ctx)

        original = ss_mod._pool
        ss_mod._pool = mock_pool  # type: ignore[attr-defined]
        try:
            # Send a string instead of list/object — triggers "content must be an array"
            result = await ss_mod.handle_review_set_section({
                "job_id": "job_TEST_ROLES02",
                "section": "roles_notes",
                "content": "not_an_array",
            })
        finally:
            ss_mod._pool = original

        assert not result.get("accepted")
        fix_text = result["errors"][0].get("fix", "")
        # Bug 3: the fix text must NOT be empty ("Example: .")
        assert fix_text and fix_text != "Example: .", (
            f"E_SECTION_INVALID fix is empty or has unfilled {{example}}: {fix_text!r}"
        )
        # Must contain actual example content
        assert "[" in fix_text or "{" in fix_text, (
            f"E_SECTION_INVALID fix must include a JSON example: {fix_text!r}"
        )

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Bug 4a — F1 finalize check must carry a reason (no tool)
# ---------------------------------------------------------------------------


def test_f1_has_reason_when_open():
    """Bug 4a: F1 open must have a reason field so the model knows what to do."""
    import inspect

    from soken_review.tools import finalize as fin_mod

    src = inspect.getsource(fin_mod.compute_finalize_checks)
    # The F1 check must include "reason" so the model knows what to do when tier is D
    assert '"reason"' in src or "'reason'" in src, (
        "Bug 4a: F1 check must include a reason field (2026-10-25 fix)"
    )
    # Specifically, the F1 block should contain the reason about tier D
    assert "tier is D" in src or "tier D" in src.lower(), (
        "Bug 4a: F1 reason must explain that tier D requires a verified source match"
    )
    # F4 (invariant) is also allowed to have no tool - it's a different case.
    # The key check: F1 must not silently omit explanation.
    assert "F1" in src, "F1 check must be present in compute_finalize_checks"


# ---------------------------------------------------------------------------
# Bug 4b — F7 check exists in compute_finalize_checks
# ---------------------------------------------------------------------------


def test_f7_check_exists_in_finalize():
    """Bug 4b: F7 check for roles_notes when privileged flags exist must be in finalize."""
    import inspect

    from soken_review.tools import finalize as fin_mod
    src = inspect.getsource(fin_mod.compute_finalize_checks)
    assert '"F7"' in src or "'F7'" in src, (
        "Bug 4b: F7 check (roles_notes required when J2/J3/J4 flags) not found in compute_finalize_checks"
    )
    assert "roles_notes" in src, (
        "Bug 4b: F7 check must reference 'roles_notes'"
    )


# ---------------------------------------------------------------------------
# Bug 6a — E_QUOTE_MISMATCH must show line range (not blank)
# ---------------------------------------------------------------------------


def test_quote_mismatch_shows_range():
    """Bug 6a: QuoteMatchError must pass range='{start}-{end}' not start=/end= separately."""
    from soken_review.pinning.quote_match import QuoteMatchError, quote_match
    from soken_review.pinning.store import PinnedSource

    content = b"line one\nline two\nline three\n"
    pin = PinnedSource.from_files({"src/A.sol": content})

    with pytest.raises(QuoteMatchError) as exc_info:
        quote_match(pin, "src/A.sol", 1, 2, "completely wrong text")

    err = exc_info.value
    assert err.code == "E_QUOTE_MISMATCH"
    # The template uses {range}; verify the detail dict has "range" (not start/end separately)
    assert "range" in err.detail, (
        f"Bug 6a: QuoteMatchError.detail must have 'range' key for the template, got keys: {list(err.detail.keys())}"
    )
    range_val = err.detail["range"]
    assert "-" in str(range_val), (
        f"Bug 6a: range value must be 'start-end' format, got: {range_val!r}"
    )
    # Verify the ReviewError envelope renders the range correctly
    from soken_review.errors import ReviewError
    envelope = ReviewError(err.code, **err.detail).envelope()
    assert "lines ." not in envelope["what"], (
        f"Bug 6a: E_QUOTE_MISMATCH still renders blank line numbers: {envelope['what']!r}"
    )
    assert "1-2" in envelope["what"] or range_val in envelope["what"], (
        f"Bug 6a: range not shown in error what: {envelope['what']!r}"
    )


# ---------------------------------------------------------------------------
# Bug 6b — E_CHALLENGE_SCOPE for present names the offending quote
# ---------------------------------------------------------------------------


def test_challenge_scope_names_quote_in_error(tmp_path: Path):
    """Bug 6b: E_CHALLENGE_SCOPE for a present answer must include the offending quote location."""
    import inspect

    from soken_review.tools import challenge as ch_mod
    src = inspect.getsource(ch_mod)

    # Check the present-answer scope violation block names the quote in ranges=
    assert "quote {q_file}:{q_start}-{q_end}" in src or "q_file" in src, (
        "Bug 6b: E_CHALLENGE_SCOPE for present must include offending quote location in ranges"
    )
    # Verify the f-string format is present
    assert "outside the scope" in src or "outside scope" in src, (
        "Bug 6b: error must say 'outside scope' for present answer"
    )


# ---------------------------------------------------------------------------
# Bug 6c — E_ABSENCE_UNRESOLVED includes field name
# ---------------------------------------------------------------------------


def test_absence_unresolved_includes_field():
    """Bug 6c: _violation_to_error with field= must populate the field key in the envelope."""
    from soken_review.tools.submit import _violation_to_error

    class FakeViolation:
        code = "E_ABSENCE_UNRESOLVED"
        rule_id = "T24"
        match = "does not exist anywhere"
        span = (5, 30)

    v = FakeViolation()
    envelope_no_field = _violation_to_error(v)
    assert "field" not in envelope_no_field, (
        "field must not appear when not passed"
    )
    envelope_with_field = _violation_to_error(v, field="body.description")
    assert envelope_with_field.get("field") == "body.description", (
        f"Bug 6c: E_ABSENCE_UNRESOLVED must include field name when passed, got: {envelope_with_field}"
    )


# ---------------------------------------------------------------------------
# Bug 7 — nsloc fallback from pin when build returns 0 or None
# ---------------------------------------------------------------------------


def test_nsloc_fallback_from_pin(tmp_path: Path):
    """Bug 7: run_map_step must compute nsloc from pin lines when build returns 0/None."""
    from soken_review.mapping.facts import load_facts
    from soken_review.mapping.step import run_map_step
    from soken_review.pinning.store import PinnedSource

    # 9 files totalling 1400 lines (approximated here as 3 files with known line counts)
    files = {
        "src/A.fc": b"\n".join(f"line{i}".encode() for i in range(500)) + b"\n",
        "src/B.fc": b"\n".join(f"line{i}".encode() for i in range(600)) + b"\n",
        "src/C.fc": b"\n".join(f"line{i}".encode() for i in range(300)) + b"\n",
    }
    pin = PinnedSource.from_files(files)
    pin.persist(tmp_path, "job_NSLOC01")

    # Call run_map_step with nsloc=0 (as TON pipeline does when build fails)
    run_map_step(
        tmp_path, "job_NSLOC01",
        family="ton", chain="ton",
        solc_output_path=None, build_ok=False,
        nsloc=0,
    )

    facts = load_facts(tmp_path, "job_NSLOC01") or []
    nsloc_fact = next((f for f in facts if f["key"] == "source.nsloc"), None)
    assert nsloc_fact is not None, (
        "Bug 7: source.nsloc fact must be written even when build returns nsloc=0"
    )
    assert int(nsloc_fact["value"]) > 0, (
        f"Bug 7: source.nsloc must be > 0 when pin has files; got {nsloc_fact['value']}"
    )
    # Should be 500 + 600 + 300 = 1400
    assert int(nsloc_fact["value"]) == 1400, (
        f"Bug 7: expected 1400 lines from pin, got {nsloc_fact['value']}"
    )

    # Also check nsloc=None
    (tmp_path / "job_NSLOC02").mkdir(exist_ok=True)
    pin.persist(tmp_path, "job_NSLOC02")
    run_map_step(
        tmp_path, "job_NSLOC02",
        family="ton", chain="ton",
        solc_output_path=None, build_ok=False,
        nsloc=None,
    )
    facts2 = load_facts(tmp_path, "job_NSLOC02") or []
    nsloc_fact2 = next((f for f in facts2 if f["key"] == "source.nsloc"), None)
    assert nsloc_fact2 is not None and int(nsloc_fact2["value"]) == 1400, (
        f"Bug 7: source.nsloc fallback must work for nsloc=None too; got {nsloc_fact2}"
    )


# ---------------------------------------------------------------------------
# Bug 8 — review_status(detailed) must include a build section
# ---------------------------------------------------------------------------


def test_detailed_extras_includes_build_section(tmp_path: Path):
    """Bug 8: _detailed_extras must return a 'build' key with status/version/error."""
    from soken_review.mapping.build import build_map, write_map
    from soken_review.mapping.facts import static_facts, write_facts
    from soken_review.tools.start_status import _detailed_extras

    # Write a minimal map with a build_detail error
    files: dict[str, str] = {"src/A.sol": "contract A {}\n"}
    art = build_map(files, None, [], build_ok=False)
    write_map(tmp_path, "job_BUILD01", art, build_detail="CompileError: unknown identifier 'foo'")
    facts = static_facts(
        chain_id=1,
        address=None,
        chain_state=None,
        candidate={"compiler": {"version": "0.8.24+commit.e11b9ed9"}},
        nsloc=10,
        pin_files=1,
        source_pin="abcd1234",
        analyzers={},
    )
    write_facts(tmp_path, "job_BUILD01", facts)

    job_dict = {
        "job_id": "job_BUILD01",
        "state": "ready",
        "map_status": "failed",
    }

    class _FakeCtx:
        def get_pin_root(self):
            return tmp_path

    with patch("soken_review.tools.start_status._get_pool"), \
         patch("soken_review.tools.read._get_ctx", return_value=_FakeCtx()):
        extras = _detailed_extras(job_dict)

    assert "build" in extras, (
        "Bug 8: _detailed_extras must include a 'build' key for response_format=detailed"
    )
    build_info = extras["build"]
    assert build_info.get("status") == "failed", (
        f"Bug 8: build.status must match job map_status; got {build_info.get('status')!r}"
    )
    assert build_info.get("version") == "0.8.24", (
        f"Bug 8: build.version must come from compiler.version fact; got {build_info.get('version')!r}"
    )
    assert "CompileError" in (build_info.get("error") or ""), (
        f"Bug 8: build.error must include the build_detail text; got {build_info.get('error')!r}"
    )
