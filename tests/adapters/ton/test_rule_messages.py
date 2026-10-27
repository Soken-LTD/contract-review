"""Every TON lead carries detector text: soken-ton-rules from the rule docstring, misti from the
SARIF message (blind run 2026-10-26: TON leads printed no detector name or message)."""

from __future__ import annotations

import json

from soken_review.adapters.ton import rules
from soken_review.adapters.ton.analyze import _build_leads, _parse_misti_sarif


def _rule_ids() -> list[str]:
    out = []
    for name in dir(rules):
        fn = getattr(rules, name)
        if name.startswith("check_") and callable(fn) and fn.__doc__:
            out.append(fn.__doc__.strip().splitlines()[0].split(":", 1)[0].strip())
    return out


def test_every_rule_has_a_message_without_the_plan_reference():
    ids = _rule_ids()
    assert ids, "no check_* rules found"
    for rid in ids:
        msg = rules.rule_message(rid)
        assert msg, rid
        assert "plan 06" not in msg and not msg.endswith(".") and "F2" not in msg[-6:], (rid, msg)
    assert rules.rule_message("TON-NOPE-99") == ""


def test_raw_rule_lead_carries_the_message():
    lead = rules._raw_lead("TON-RPL-01", "contracts/w.fc", 10, 12)
    assert lead["message"].startswith("accept_message")


def test_misti_sarif_message_is_kept_and_reaches_the_lead():
    sarif = {"runs": [{"results": [{
        "ruleId": "DivideBeforeMultiply", "level": "warning",
        "message": {"text": "Division before multiplication loses precision"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///work/src/contracts/a.tact"},
                                            "region": {"startLine": 40, "endLine": 41}}}],
    }]}]}
    raw = _parse_misti_sarif(json.dumps(sarif).encode())
    assert raw and raw[0]["message"] == "Division before multiplication loses precision"
    leads = _build_leads(raw)
    assert leads and leads[0]["message"] == "Division before multiplication loses precision"
    assert leads[0]["rule_id"] == "DivideBeforeMultiply"
