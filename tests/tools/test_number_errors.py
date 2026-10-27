"""Number rejections name the token, the field, the rule and what to write instead."""

from __future__ import annotations

from soken_review.engine.numbers import NumberContext, lex_numbers
from soken_review.tools.number_errors import nearest_allowed, number_error


def test_unsourced_number_names_token_field_rule_and_nearest_literals():
    ctx = NumberContext(allowed_literals=frozenset({"500", "10000", "3"}))
    v = lex_numbers("the fee is 42", ctx)[0]
    env = number_error(v, "impact", ctx)
    assert env["code"] == "E_NUMBER_UNSOURCED" and env["field"] == "impact"
    assert "42" in env["what"] and "impact" in env["what"] and "L8c" in env["what"]
    assert "nearest allowed: 3, 500, 10000" in env["fix"]


def test_identifier_rejection_says_it_must_be_spelled_as_in_the_code():
    v = lex_numbers("claim_v9")[0]
    env = number_error(v, "title", NumberContext())
    assert "claim_v9" in env["what"] and "L7" in env["what"]
    assert "identifier spelled exactly as in the pinned code" in env["fix"]
    assert "none (no literal on the quoted lines)" in env["fix"]


def test_format_rejection_names_the_word_and_the_rule():
    v = lex_numbers("thousands of tokens")[0]
    env = number_error(v, "description")
    assert env["code"] == "E_NUMBER_FORMAT"
    assert env["what"] == "Number word or format thousands is not allowed in report text (rule L9a)."
    assert "a count of code things in words" in env["fix"]


def test_nearest_allowed_caps_the_list():
    ctx = NumberContext(allowed_literals=frozenset(str(i) for i in range(10, 30)))
    assert nearest_allowed(ctx).count(",") == 5


def test_half_placeholder_error_names_the_double_brace_form_to_write():
    """E_PLACEHOLDER_SYNTAX (matrix run 2026-10-27): the fix says exactly what to write."""
    v = lex_numbers("supply of {fact:onchain.total_supply} token units", NumberContext())[0]
    env = number_error(v, "description", NumberContext())
    assert env["code"] == "E_PLACEHOLDER_SYNTAX" and env["field"] == "description"
    assert "{fact:onchain.total_supply}" in env["what"]
    assert env["fix"].startswith("Write {{fact:onchain.total_supply}} (two braces on each side)")
    assert "{{fact:<key>}}" in env["fix"]


def test_number_unsourced_fix_prints_the_double_brace_form():
    """The catalogue template once printed `{fact:<key>}` after formatting, which taught reviewers
    the single-brace form the kit does not expand."""
    v = lex_numbers("the fee is 250 units", NumberContext())[0]
    env = number_error(v, "impact", NumberContext())
    assert "{{fact:<key>}}" in env["fix"] and "{{calc:...}}" in env["fix"]
    assert "{fact:<key>}" not in env["fix"].replace("{{fact:<key>}}", "")
