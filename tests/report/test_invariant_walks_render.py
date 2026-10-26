"""Invariant walks in the report (feat/lifecycle-invariant-pass): `review_coverage.invariant_walks`
assembled from map/lifecycle.json plus the invariant_walks section, printed as a table in the
coverage section."""

from __future__ import annotations

import pytest

from soken_review.report.assemble import invariant_walk_rows
from soken_review.report.kit import build as kb
from soken_review.report.kit.build import BuildError, build

from .fixtures import report

LC = {"walks": [{"id": "IW-VS-1", "title": "Supply returns to zero"},
                {"id": "IW-VS-2", "title": "First deposit into an empty vault"},
                {"id": "IW-VS-4", "title": "Rounding at the boundaries"}]}
SECTION = [
    {"walk_id": "IW-VS-1", "outcome": "violated", "draft_key": "d1",
     "refs": ["src/Vault.sol:10-14", "src/Vault.sol:20-30"], "note": "x" * 50},
    {"walk_id": "IW-VS-2", "outcome": "holds", "refs": ["src/Vault.sol:5-8"], "note": "y" * 50},
]


def test_rows_from_lifecycle_and_section():
    rows = invariant_walk_rows(LC, SECTION, {"d1": "H-001"})
    assert [r["verdict"] for r in rows] == ["violated", "holds", "not_answered"]
    assert rows[0]["finding"] == "H-001" and rows[0]["lines"][1] == {"path": "src/Vault.sol", "start": 20, "end": 30}
    assert "finding" not in rows[1] and rows[2]["lines"] == []
    assert all("note" not in r for r in rows)                  # audit-log text never prints
    assert invariant_walk_rows(None, SECTION, {}) == []
    assert invariant_walk_rows(LC, {"rows": SECTION}, {})[0].get("finding") is None


def test_walks_table_prints_in_coverage(tmp_path):
    r = report(severities=["High"])
    r["review_coverage"]["invariant_walks"] = invariant_walk_rows(LC, SECTION, {"d1": "H-001"})
    html = build(r, tmp_path / "print", mode="print").html_path.read_text(encoding="utf-8")
    iw = kb.kit_texts()["invariant_walks"]
    assert f"<h3>{iw['heading']}</h3>" in html
    for label in ("Violated", "Holds", "Not answered"):
        assert label in html
    assert "src/Vault.sol:20-30" in html and "IW-VS-1 Supply returns to zero" in html and "H-001" in html


def test_no_walks_no_table(tmp_path):
    html = build(report(), tmp_path / "print", mode="print").html_path.read_text(encoding="utf-8")
    assert kb.kit_texts()["invariant_walks"]["heading"] not in html


def test_walk_verdict_outside_the_enum_fails_the_schema(tmp_path):
    r = report()
    r["review_coverage"]["invariant_walks"] = [{"walk_id": "IW-VS-1", "title": "Supply returns to zero",
                                                "verdict": "probably", "lines": []}]
    with pytest.raises(BuildError) as e:
        build(r, tmp_path)
    assert e.value.code == "schema"


def test_every_verdict_has_a_label():
    enum = kb.schema()["$defs"]["review_coverage"]["properties"]["invariant_walks"]["items"]["properties"]["verdict"]["enum"]
    assert set(enum) == set(kb.kit_texts()["invariant_walks"]["verdict"])
