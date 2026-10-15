"""CI: run the 04 text gate over every server template (03 §13 row "Text").

Covered surfaces (04 §11.1):
  - contract/errors.yaml  ``what`` and ``fix`` texts  -> server scope
  - contract/mcp/tools.v1.json  tool ``description`` fields -> public scope

Template fill-slots (``{field}``, ``{value80}`` etc.) are data placeholders, not
gate targets. We strip them before checking.

If a template FAILS the gate the test is marked ``xfail`` with the failing rule
listed.  Do NOT edit the templates to make the test pass: a failure here is a
contract defect to fix in part 03.

Plan: 03 §13 ("Text"), 04 §11.1 (scopes), text_gate.yaml.
"""
from __future__ import annotations

import json
import re

import pytest
import yaml

from soken_review.contract import CONTRACT_DIR
from soken_review.engine.text_gate import CheckContext, check_text

# ── helpers ────────────────────────────────────────────────────────────────

_FILL_SLOT_RE = re.compile(r"\{[^{}]+\}")


def _strip_slots(text: str) -> str:
    """Remove ``{field}`` fill-slots so they don't trigger T31 (call syntax)."""
    return _FILL_SLOT_RE.sub("SLOT", text)


def _gate(text: str, scope: str, context: CheckContext | None = None) -> list[str]:
    """Return list of 'rule_id:match' strings for all violations."""
    vs = check_text(_strip_slots(text), scope, context)
    return [f"{v.rule_id}:{v.match!r}" for v in vs]


# ── errors.yaml: what / fix texts -> server scope ─────────────────────────

_ERRORS_FILE = CONTRACT_DIR / "errors.yaml"


def _load_error_templates() -> list[tuple[str, str, str]]:
    """Return list of (code, field, text) from errors.yaml."""
    rows = yaml.safe_load(_ERRORS_FILE.read_text())["codes"]
    items = []
    for row in rows:
        items.append((row["code"], "what", row["what"]))
        items.append((row["code"], "fix", row["fix"]))
    return items


_ERROR_TEMPLATES = _load_error_templates()

# Known template defects (code, field, rule_id) that cannot be fixed without
# changing the contract (owned by part 03).  Entries here become xfail marks.
_ERROR_XFAIL: set[tuple[str, str, str]] = {
    # Add entries as: ("E_CODE", "what", "T15") when a template violates a rule.
}


@pytest.mark.parametrize("code,field_name,text", _ERROR_TEMPLATES, ids=[f"{c}.{f}" for c, f, _ in _ERROR_TEMPLATES])
def test_error_template_server_scope(code: str, field_name: str, text: str) -> None:
    """Every error template passes the server-scope text gate (03 §1, 04 §11.1)."""
    ctx = CheckContext()  # no field; server templates are not finding fields
    failures = _gate(text, "server", ctx)
    known_failures = [r for r in failures if (code, field_name, r.split(":")[0]) in _ERROR_XFAIL]
    real_failures = [r for r in failures if r not in known_failures]

    if known_failures and not real_failures:
        pytest.xfail(f"contract defect in {code}.{field_name}: {known_failures}")
    elif known_failures and real_failures:
        # Mixed: report known as context, fail on new ones
        pytest.fail(f"{code}.{field_name}: gate failures {real_failures} (also known: {known_failures})")
    elif real_failures:
        pytest.fail(f"{code}.{field_name}: gate failures {real_failures}")
    # else: pass


# ── tools.v1.json: description fields -> public scope ─────────────────────

_TOOLS_FILE = CONTRACT_DIR / "mcp" / "tools.v1.json"


def _load_tool_descriptions() -> list[tuple[str, str]]:
    """Return list of (tool_name, description) from tools.v1.json."""
    data = json.loads(_TOOLS_FILE.read_text())
    return [(t["name"], t["description"]) for t in data["tools"] if "description" in t]


_TOOL_DESCS = _load_tool_descriptions()

# Known tool description defects: (tool_name, rule_id)
# Contract defects in contract/mcp/tools.v1.json (part 03); fix there, not here.
_TOOL_XFAIL: set[tuple[str, str]] = set()  # empty: both P1 defects fixed in tools.v1.json 2026-10-09


@pytest.mark.parametrize("name,desc", _TOOL_DESCS, ids=[n for n, _ in _TOOL_DESCS])
def test_tool_description_public_scope(name: str, desc: str) -> None:
    """Every tool description passes the public-scope text gate (03 §1, 04 §11.1).

    Tool descriptions are in the 'public' scope per 04 §11.1
    ("soken.dev pages, privacy policy, terms, README, listing text, tool descriptions (CI)").
    """
    ctx = CheckContext()
    failures = _gate(desc, "public", ctx)
    known_failures = [r for r in failures if (name, r.split(":")[0]) in _TOOL_XFAIL]
    real_failures = [r for r in failures if r not in known_failures]

    if known_failures and not real_failures:
        pytest.xfail(f"contract defect in tool {name}: {known_failures}")
    elif known_failures and real_failures:
        pytest.fail(f"tool {name}: gate failures {real_failures} (also known: {known_failures})")
    elif real_failures:
        pytest.fail(f"tool {name}: gate failures {real_failures}")
