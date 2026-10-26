"""Stored sections are row lists (review_set_section); assembly must not assume `{rows: ...}` dicts.

Blind run 2026-10-26: every job with roles_notes, coverage or out_of_scope_reasons failed to render
with `'list' object has no attribute 'get'` (assemble.py:951), so no PDF reached the client."""

from __future__ import annotations

from soken_review.report.assemble import roles_section, section_rows


def test_section_rows_accepts_list_and_dict_and_none():
    rows = [{"area_id": "AC", "status": "n_a"}, "junk", None]
    assert section_rows(rows) == [{"area_id": "AC", "status": "n_a"}]
    assert section_rows({"rows": rows}) == [{"area_id": "AC", "status": "n_a"}]
    assert section_rows({"notes": [{"p": "x"}]}, "notes") == [{"p": "x"}]
    assert section_rows(None) == [] and section_rows({}) == []


def test_roles_notes_rows_attach_to_role_rows_and_overflow_to_notes():
    role_rows = [{"role": "Owner", "holder": "Unknown", "type": "EOA", "gated_functions": ["pause"]}]
    notes_in = [{"role": "owner", "risk_note": "Can pause every transfer with no time limit."},
                {"role": "Treasury", "risk_note": "Receives the full fee stream."},
                {"p": "A plain prose note."}]
    rows, notes = roles_section(role_rows, notes_in)
    assert rows[0]["risk_note"] == "Can pause every transfer with no time limit."
    assert role_rows[0].get("risk_note") is None  # input not mutated
    texts = [n.get("p") for n in notes]
    assert "Treasury: Receives the full fee stream." in texts
    assert "A plain prose note." in texts


def test_roles_section_without_notes_is_unchanged():
    role_rows = [{"role": "Owner", "holder": "Unknown", "type": "EOA", "gated_functions": []}]
    rows, notes = roles_section(role_rows, [])
    assert rows == role_rows and notes == []
