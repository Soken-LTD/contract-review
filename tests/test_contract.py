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
    "review_answer_challenge", "review_set_section", "review_add_context", "review_finalize", "review_report",
    "review_delete_job", "review_publish", "review_chain_read", "review_chain_roles", "review_chain_balances",
    "review_verify_on_fork",
]
TOOL_COUNT = 23

# 03 section 2: (readOnly, destructive, idempotent, openWorld)
HINTS = {
    "review_start": (False, False, False, True),
    "review_dismiss_lead": (False, True, True, False),
    "review_submit_finding": (False, True, True, False),
    "review_withdraw_finding": (False, True, True, False),
    "review_answer_challenge": (False, True, True, False),
    "review_set_section": (False, True, True, False),
    "review_add_context": (False, False, True, True),   # mutates the job, never destructive; fetches public URLs
    "review_finalize": (False, True, True, False),
    "review_delete_job": (False, True, True, False),
    "review_publish": (False, True, True, False),   # public and replaces the target's file
    # chain tools record facts on the job (never destructive) and read public chains
    "review_chain_read": (False, False, True, True),
    "review_chain_roles": (False, False, True, True),
    "review_chain_balances": (False, False, True, True),
    # records a run on the job (a new run per call), reads a public chain through the read-only proxy
    "review_verify_on_fork": (False, False, False, True),
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
    assert len(names) == TOOL_COUNT
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


def test_context_surfaces_in_the_contract():
    """Context ingestion spec 2 and 8: start takes `context`, status reports it, the guide has the
    topic and review_add_context carries the item shape and the per-item result."""
    tools = {t["name"]: t for t in TOOLS}
    start = tools["review_start"]["inputSchema"]["properties"]["context"]
    items = start["properties"]["items"]
    assert start["required"] == ["items"] and items["maxItems"] == 12
    kinds = items["items"]["properties"]["kind"]["enum"]
    assert kinds == yaml.safe_load((CONTRACT_DIR / "rubric" / "enums.yaml").read_text())["context_kind"]
    assert items["items"]["properties"]["url"]["maxLength"] == 2048
    assert items["items"]["properties"]["content"]["maxLength"] == 60000
    add = tools["review_add_context"]
    assert add["inputSchema"]["properties"]["items"]["maxItems"] == 8
    assert add["inputSchema"]["required"] == ["job_id", "items"]
    out = add["outputSchema"]["properties"]
    assert out["items"]["items"]["properties"]["status"]["enum"] == ["queued", "ok", "failed", "exists"]
    assert out["context"]["required"] == ["requested", "done", "failed"]
    status = tools["review_status"]["outputSchema"]["properties"]["context"]
    assert status["required"] == ["requested", "done", "failed"]
    assert "context" in tools["review_get_guide"]["inputSchema"]["properties"]["topic"]["enum"]
    codes = {r["code"] for r in yaml.safe_load((CONTRACT_DIR / "errors.yaml").read_text())["codes"]}
    assert {"E_CONTEXT_URL", "E_CONTEXT_LIMIT", "E_CONTEXT_FETCH"} <= codes
    for name in ("review_start", "review_add_context"):
        desc = tools[name]["description"]
        assert "context" in desc.lower() and len(desc) <= 600 and "soken" not in desc.lower()


# ── held-out friction 2026-10-27: severity_reason is in the submit schema; npm paths allowed ──


def test_submit_finding_input_schema_has_severity_reason_and_validator_accepts_it():
    """The 2026-10-27 arms ran on a stale client schema; the shipped contract and the server
    validator both know severity_reason (20 to 200 characters, next to claimed_severity)."""
    import jsonschema

    tools = {t["name"]: t for t in TOOLS}
    schema = tools["review_submit_finding"]["inputSchema"]
    props = schema["properties"]
    assert props["severity_reason"]["minLength"] == 20 and props["severity_reason"]["maxLength"] == 200
    assert "claimed_severity" in props
    v = jsonschema.Draft202012Validator(schema)
    reason_errors = [e for e in v.iter_errors({"severity_reason": "x" * 25, "claimed_severity": "Low"})
                     if "severity_reason" in e.json_path or "claimed_severity" in e.json_path]
    assert reason_errors == []
    assert not [e for e in v.iter_errors({"severity_reason": "x" * 25}) if "additional" in e.message]


def test_files_path_and_line_refs_accept_npm_scoped_paths():
    tools = {t["name"]: t for t in TOOLS}
    files_schema = next(s for s in tools["review_start"]["inputSchema"]["properties"]["source"]["oneOf"]
                        if s["properties"]["kind"].get("const") == "files")
    pat = files_schema["properties"]["files"]["items"]["properties"]["path"]["pattern"]
    assert re.match(pat, "@openzeppelin/contracts/token/ERC20/ERC20.sol")
    assert re.match(pat, "node_modules/@openzeppelin/contracts/utils/Context.sol")
    assert not re.match(pat, "a b.sol")
    # traversal is the server gate (units.safe_store_path), not the pattern: @ paths pass it, .. does not
    from soken_review.adapters.evm.units import safe_store_path

    assert safe_store_path("@openzeppelin/contracts/token/ERC20/ERC20.sol") == "@openzeppelin/contracts/token/ERC20/ERC20.sol"
    assert safe_store_path("node_modules/@scope/pkg/A.sol") == "node_modules/@scope/pkg/A.sol"
    assert safe_store_path("../etc/passwd") is None and safe_store_path("/etc/passwd") is None
    raw = json.loads((CONTRACT_DIR / "mcp" / "tools.v1.json").read_text())["$defs"]
    assert re.match(raw["line_ref"]["pattern"], "@openzeppelin/contracts/token/ERC20/ERC20.sol:12-14")
    assert re.match(raw["range_ref"]["pattern"], "node_modules/@scope/pkg/A.sol:1-2")
