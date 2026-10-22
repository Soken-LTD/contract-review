"""03 section 13 CI checks that need no server: tools, schemas, errors."""

import json
import re

import pytest
import yaml
from jsonschema import Draft202012Validator

from soken_review.contract import CONTRACT_DIR, bundle_tools, load_errors

TOOL_ORDER = [
    "review_start", "review_status", "review_get_guide", "review_read_code", "review_search_code",
    "review_contract_map", "review_leads", "review_facts", "review_dismiss_lead",
    "review_submit_finding", "review_withdraw_finding", "review_challenge",
    "review_answer_challenge", "review_set_section", "review_finalize", "review_report",
    "review_delete_job", "review_publish",
]

# 03 section 2: (readOnly, destructive, idempotent, openWorld)
HINTS = {
    "review_start": (False, False, False, True),
    "review_dismiss_lead": (False, True, True, False),
    "review_submit_finding": (False, True, True, False),
    "review_withdraw_finding": (False, True, True, False),
    "review_answer_challenge": (False, True, True, False),
    "review_set_section": (False, True, True, False),
    "review_finalize": (False, True, True, False),
    "review_delete_job": (False, True, True, False),
    "review_publish": (False, False, True, False),
}
READ_ONLY = (True, False, True, False)

BULK_READ = {
    "review_get_guide", "review_read_code", "review_search_code",
    "review_contract_map", "review_leads", "review_facts",
}

TOOLS = bundle_tools()


def test_names_and_order():
    names = [t["name"] for t in TOOLS]
    assert names == TOOL_ORDER
    assert all(re.fullmatch(r"review_[a-z_]{1,25}", n) for n in names)


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t["name"])
def test_annotations_and_text_limits(tool):
    a = tool["annotations"]
    got = (a["readOnlyHint"], a["destructiveHint"], a["idempotentHint"], a["openWorldHint"])
    assert got == HINTS.get(tool["name"], READ_ONLY)
    assert a["title"] == tool["title"]
    assert len(tool["description"]) <= 600
    assert "soken" not in tool["description"].lower()


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t["name"])
def test_schemas(tool):
    for key in ("inputSchema", "outputSchema"):
        if key not in tool:
            continue
        schema = tool[key]
        Draft202012Validator.check_schema(schema)
        assert schema.get("type") == "object"
        assert not {"allOf", "anyOf", "oneOf"} & schema.keys()
        assert "$ref" not in json.dumps(schema)
        assert len(json.dumps(schema, separators=(",", ":"))) < 8192, f"{key} over 8 KB"
    if tool["name"] in BULK_READ:
        assert "outputSchema" not in tool
    else:
        out = tool["outputSchema"]
        assert out["required"] == ["accepted"]
        assert {"accepted", "errors", "errors_more"} <= out["properties"].keys()


def test_errors_catalog():
    rows = yaml.safe_load((CONTRACT_DIR / "errors.yaml").read_text())["codes"]
    codes = [r["code"] for r in rows]
    assert len(codes) == len(set(codes)), "duplicate error code"
    for r in rows:
        assert re.fullmatch(r"E_[A-Z_]+", r["code"])
        for field in ("owner", "channel", "class", "what", "fix"):
            assert r.get(field), f"{r['code']} missing {field}"


def test_server_uses_only_catalogued_codes():
    catalog = load_errors()
    src = "\n".join(p.read_text() for p in (CONTRACT_DIR.parent / "src").rglob("*.py"))
    used = set(re.findall(r'"(E_[A-Z_]+)"', src))
    assert used <= catalog.keys(), used - catalog.keys()


def test_rubric_contracts_parse():
    for path in (CONTRACT_DIR / "rubric").rglob("*.yaml"):
        yaml.safe_load(path.read_text())
    for path in CONTRACT_DIR.rglob("*.json"):
        Draft202012Validator.check_schema(json.loads(path.read_text()))


def test_answer_challenge_schema_accepts_fresh_finding_revision_zero():
    """review_submit_finding returns a draft at revision 0 (tests/tools/test_submit_finalize.py),
    and a High/Critical finding goes straight to needs_challenge at that same revision 0. The model
    must then answer the challenge AT revision 0. The input schema used to pin revision to
    minimum 1, so review_answer_challenge rejected revision 0 with E_INVALID_ARGUMENT before the
    handler ran, forcing a pointless re-submit just to bump the revision. revision 0 must validate
    (the handler already checks revision == the draft's real current_revision). Negatives stay out.
    """
    schema = {t["name"]: t for t in TOOLS}["review_answer_challenge"]["inputSchema"]
    v = Draft202012Validator(schema)
    base = {
        "job_id": "job_" + "0" * 26,
        "draft_key": "f-001",
        "answers": [{"item_id": "K1", "value": "absent", "note": "x" * 25}],
    }
    assert list(v.iter_errors({**base, "revision": 0})) == []  # fresh finding's current revision
    assert list(v.iter_errors({**base, "revision": 1})) == []  # a later revision still fine
    neg = [e.message for e in v.iter_errors({**base, "revision": -1})]
    assert any("minimum" in m for m in neg)  # negatives are still rejected
