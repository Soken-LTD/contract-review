"""`note` text-gate scope: internal notes (dismiss, answer, withdraw) take only step0.

Notes land in the audit log (lead_dismissals, challenge_answers, withdrawals) and are never
rendered, so the report prose rules and the number provenance check must not fire on them. Each
false rejection cost the reviewer one attempt ("Number two in note has no source", 2026-10-22).
"""

from __future__ import annotations

import pytest

from soken_review.engine.text_gate import check_text
from soken_review.tools.dismiss import _check_note

NOTE = ("Slither flags this as reentrancy-eth, but the 2 external calls happen after the balance "
        "update on line 46; what else could re-enter? Nothing: the High rating is detector noise.")


def test_note_scope_ignores_prose_and_number_rules():
    assert check_text(NOTE, "note") == []
    assert check_text("Checked 3 callers and the owner guard, see src/Vault.sol:51.", "note") == []


def test_note_scope_still_rejects_control_and_bidi_characters():
    hits = check_text("looks fine" + chr(0x202E) + " but reversed", "note")   # RLO bidi control
    assert hits and all(h.rule_id.startswith("step0") or h.code.startswith("E_TEXT") for h in hits)


def test_model_scope_still_applies_the_prose_rules():
    assert check_text(NOTE, "model")


def test_dismiss_note_check_accepts_numbers_and_tool_names():
    assert _check_note(NOTE, "LEAD-0001") == []


def test_unknown_scope_is_an_error():
    with pytest.raises(ValueError):
        check_text("x", "notes")
