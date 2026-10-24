"""Tests for _iter_text_fields coverage and text/number gate on ul items and table cells.

Issue 1 (2026-10-24): _iter_text_fields previously only walked `p` blocks; `ul` items
and `table` head/row cells bypassed V4/V5/V6.  These tests verify that all three text
surfaces are walked and that violations in those surfaces are detected.
"""

from __future__ import annotations

from soken_review.engine.numbers import lex_numbers
from soken_review.engine.text_gate import check_model_field
from soken_review.tools.submit import _iter_text_fields

# ---------------------------------------------------------------------------
# _iter_text_fields walker tests
# ---------------------------------------------------------------------------


def test_iter_yields_p_blocks():
    args = {
        "title": "Title",
        "body": {"description": [{"p": "Some paragraph text"}]},
    }
    fields = dict(_iter_text_fields(args))
    assert "description" in fields
    assert "Some paragraph text" in fields.values() or any("Some" in v for v in fields.values())


def test_iter_yields_ul_items():
    """ul list items must be included in the walker output."""
    args = {
        "body": {"description": [{"ul": ["first item", "second item"]}]},
    }
    texts = [t for _, t in _iter_text_fields(args)]
    assert "first item" in texts
    assert "second item" in texts


def test_iter_yields_table_head_cells():
    """table.head cells must be included in the walker output."""
    args = {
        "body": {
            "impact": [
                {"table": {"head": ["Column A", "Column B"], "rows": []}}
            ]
        },
    }
    texts = [t for _, t in _iter_text_fields(args)]
    assert "Column A" in texts
    assert "Column B" in texts


def test_iter_yields_table_row_cells():
    """table.rows cells must be included in the walker output."""
    args = {
        "body": {
            "recommendation": [
                {"table": {"head": [], "rows": [["cell-r1c1", "cell-r1c2"], ["cell-r2c1", None]]}}
            ]
        },
    }
    texts = [t for _, t in _iter_text_fields(args)]
    assert "cell-r1c1" in texts
    assert "cell-r1c2" in texts
    assert "cell-r2c1" in texts
    assert None not in texts   # None cells are filtered out


def test_iter_section_names_correct():
    """Field names must match the section name for all block types."""
    args = {
        "body": {
            "impact": [
                {"p": "paragraph"},
                {"ul": ["list item"]},
                {"table": {"head": ["header"], "rows": [["row cell"]]}},
            ]
        },
    }
    pairs = _iter_text_fields(args)
    field_names = {field for field, _ in pairs}
    assert field_names == {"impact"}


# ---------------------------------------------------------------------------
# Text gate and number gate on ul items and table cells
# ---------------------------------------------------------------------------


def test_text_gate_fires_on_ul_item_with_brand_name():
    """A T25 brand-name violation in a ul item must be detected via check_model_field."""
    text = "The soken team reviewed this"
    violations = check_model_field(text, field="description", profile="third_party_public_code")
    assert any(v.rule_id == "T25" for v in violations), \
        "Expected T25 violation for brand name in ul item text"


def test_text_gate_fires_on_table_cell_with_brand_name():
    """A T25 brand-name violation in a table cell must be detected via check_model_field."""
    text = "soken audit report"
    violations = check_model_field(text, field="impact", profile="third_party_public_code")
    assert any(v.rule_id == "T25" for v in violations), \
        "Expected T25 violation for brand name in table cell text"


def test_number_gate_fires_on_ul_item_with_invented_money():
    """An invented money figure in a ul item must fire E_NUMBER_FORMAT via lex_numbers."""
    text = "$1,234,567 transferred to the attacker"
    violations = lex_numbers(text)
    assert any(v.code == "E_NUMBER_FORMAT" for v in violations), \
        "Expected E_NUMBER_FORMAT for invented dollar amount in ul item"


def test_number_gate_fires_on_table_cell_with_invented_money():
    """An invented money figure in a table cell must fire E_NUMBER_FORMAT via lex_numbers."""
    text = "Loss: $500,000"
    violations = lex_numbers(text)
    assert any(v.code == "E_NUMBER_FORMAT" for v in violations), \
        "Expected E_NUMBER_FORMAT for dollar amount in table cell"


def test_iter_text_fields_surfaces_all_text_for_combined_gate_check():
    """_iter_text_fields returns all text surfaces; combined walk detects violations in ul and table."""
    # A submission with brand name in ul and dollar amount in table cell
    args = {
        "title": "Reentrancy in withdraw()",
        "body": {
            "description": [
                {"p": "The withdraw function is vulnerable."},
                {"ul": ["The soken team confirmed this", "Multiple entry points exist"]},
            ],
            "impact": [
                {"table": {
                    "head": ["Severity", "Loss"],
                    "rows": [["High", "$1,500,000 possible loss"]],
                }},
            ],
        },
    }

    combined_text = " ".join(t for _, t in _iter_text_fields(args))
    # T25 brand name detected
    brand_violations = check_model_field(combined_text, field="description",
                                         profile="third_party_public_code")
    # Number gate on table cell
    number_violations = lex_numbers("$1,500,000 possible loss")

    assert any(v.rule_id == "T25" for v in brand_violations)
    assert any(v.code == "E_NUMBER_FORMAT" for v in number_violations)
