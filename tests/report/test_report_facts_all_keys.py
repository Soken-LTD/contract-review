"""report.facts carries every job fact the kit may expand, not only context.* (blind run 2026-10-26:
BNB render failed with "fact state.initial_minted not in facts" after the submit gate accepted it)."""

from __future__ import annotations

from soken_review.report.assemble import context_facts, report_facts


def _facts():
    return [
        {"key": "state.initial_minted", "value": "true", "unit": None, "tags": [], "source": "eth_call"},
        {"key": "deploy.balance", "value": "1200000", "unit": "wei", "tags": ["amount_at_risk"]},
        {"key": "context.tvl", "value": "3.4", "unit": "M USD", "tags": []},
        {"key": "Bad Key", "value": "x", "unit": None, "tags": []},
    ]


def test_report_facts_includes_state_and_deploy_keys():
    out = report_facts(_facts())
    assert out["state.initial_minted"] == {"value": "true", "unit": None, "amount_at_risk": False}
    assert out["deploy.balance"]["value"] == "1,200,000" and out["deploy.balance"]["amount_at_risk"] is True
    assert "context.tvl" in out and "Bad Key" not in out


def test_context_facts_is_the_context_subset():
    assert set(context_facts(_facts())) == {"context.tvl"}
