"""Client-visible text defects of the matrix run 2026-10-27 (JUDGEMENT.md E3 to E6), reproduced on the
stored report.json of the three MCP jobs and fixed in the kit:

* Wallitelli (job_EFZNS2TXPND1JQM7HR7HAVXQ74): the reviewer wrote `{fact:onchain.total_supply}` and
  `{fact:compiler.version}` with one brace; the gate accepted them and the PDF printed them raw. The
  render now fails as a late gate on the reviewer's text instead of printing the token.
* APAD (job_BZJD7F3E01142Q3YK00P0EP0NT): `{{fact:onchain.balance}}` is an amount-at-risk fact, so the
  public projection printed "holds a native balance of (withheld), which shows that ...". Since CEO
  2026-10-28 every profile prints the value as is.
* 1inch (job_536H8JDV9PQ5NY4EXCA6GQWG17): the cover said "Not deployed" and labelled the sha256 source
  pin "Commit"; the failed build was visible only as "Checked without a contract map" on every card.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest

from soken_review.report.kit import build as kb
from soken_review.report.kit.build import (
    BuildError,
    assert_expanded,
    build,
    expand,
    malformed_placeholder,
    project,
)
from soken_review.report.render import failure_cause

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "matrix_2026_10_27"


def _report(name: str) -> dict:
    return json.loads((FIX / f"{name}.report.json").read_text(encoding="utf-8"))


def _html(r: dict, tmp_path: Path) -> str:
    return build(r, tmp_path / "out", mode="print").html_path.read_text(encoding="utf-8")


# ── E4: half placeholders ─────────────────────────────────────────────────────

def test_wallitelli_half_placeholder_fails_the_render_as_a_late_gate_on_the_reviewer_text(tmp_path):
    r = _report("wallitelli")
    desc = r["findings"][0]["description"][0]["p"]
    assert "{fact:onchain.total_supply}" in desc and "{{fact:" not in desc   # as stored by the server
    with pytest.raises(BuildError) as exc:
        build(r, tmp_path / "out", mode="print")
    err = exc.value
    assert err.code == "late_gate" and err.rule == "L0"
    assert err.path == "$.findings[0].description[0].p"
    assert "{fact:onchain.total_supply}" in err.detail
    # the failure is the reviewer's (model text), so review_finalize reopens the job for a fix
    assert failure_cause(err.code, err.path, r) == {"cause": "model", "path": err.path}


def test_wallitelli_with_double_braces_renders_without_any_placeholder_token(tmp_path):
    r = _report("wallitelli")
    for f in r["findings"]:
        for key in ("description", "impact", "recommendation"):
            for b in f.get(key, []):
                if "p" in b:
                    b["p"] = re.sub(r"(?<!\{)\{(fact:[a-z_.]+)\}(?!\})", r"{{\1}}", b["p"])
    html = _html(r, tmp_path)
    assert "fact:" not in html and "withheld" not in html.lower()
    assert "0.8.28" in html                                   # compiler.version expanded in I-001
    # onchain.total_supply is an amount-at-risk fact: it prints as is with its sentence (CEO 2026-10-28)
    assert "token units to msg.sender" in html
    assert "The token exposes only the standard ERC-20 entry points" in html


@pytest.mark.parametrize("text, bad", [
    ("supply of {fact:onchain.total_supply} token units", "{fact:onchain.total_supply}"),
    ("version {{fact:compiler.version} used", "{{fact:compiler.version}"),
    ("version {fact:compiler.version}} used", "{fact:compiler.version}}"),
    ("a bad body {{fact:Compiler Version}} here", "{{fact:Compiler Version}}"),
    ("fine {{fact:compiler.version}} and {{calc:fact:onchain.balance/2|2}} and {{finding:owner-role}}", None),
    ("no placeholder at all", None),
])
def test_malformed_placeholder_detection(text, bad):
    assert malformed_placeholder(text) == bad


def test_post_projection_sweep_refuses_any_surviving_placeholder():
    projected = {"meta": {"profile": "owner"}, "roles": {"notes": [{"p": "left {fact:onchain.owner} here"}]}}
    with pytest.raises(BuildError) as exc:
        assert_expanded(projected)
    assert exc.value.code == "schema" and exc.value.path == "$.roles.notes[0].p"


# ── E5: amount-at-risk values print as is (CEO 2026-10-28: nothing withheld) ──────

def test_apad_amount_at_risk_sentence_prints_with_its_value(tmp_path):
    r = _report("apad")
    assert r["facts"]["onchain.balance"]["amount_at_risk"] is True
    stored = next(p["p"] for f in r["findings"] for p in f["description"] if "{{fact:onchain.balance}}" in p.get("p", ""))
    assert "which shows that the deployment transaction carried nothing" in stored
    html = _html(r, tmp_path)
    assert "withheld" not in html.lower()
    assert "native balance of" in html
    assert "which shows that the deployment transaction carried nothing" in html
    assert "stays for the life of the contract" in html


def test_expand_prints_amount_at_risk_values_under_every_profile():
    facts = {"vault.balance": {"value": "1,250", "unit": "ETH", "amount_at_risk": True},
             "compiler.version": {"value": "0.8.28", "unit": None, "amount_at_risk": False}}
    text = ("The vault accepts deposits. It holds {{fact:vault.balance}} at the pinned block, which is the "
            "amount at stake. Built with {{fact:compiler.version}}.")
    assert expand(text, facts) == ("The vault accepts deposits. It holds 1,250 ETH at the pinned "
                                   "block, which is the amount at stake. Built with 0.8.28.")
    assert expand("{{calc:fact:vault.balance*2|0}} is twice the balance.", facts) == "2,500 is twice the balance."


@pytest.mark.parametrize("profile", ["public_review", "owner"])
def test_project_keeps_every_block_item_row_and_note_with_amount_at_risk_values(profile):
    r = _report("apad")
    f = r["findings"][0]
    f["title"] = "Balance of {{fact:onchain.balance}} is stranded"
    f["description"] = [{"p": "Holds {{fact:onchain.balance}}."},
                        {"ul": ["Balance {{fact:onchain.balance}} stays.", "The constructor is payable."]},
                        {"table": {"head": ["Item", "Value"], "rows": [["Balance", "{{fact:onchain.balance}} now"],
                                                                        ["Owner", "{{fact:onchain.owner}}"]]}},
                        {"p": "Kept paragraph."}]
    r["roles"]["notes"] = [{"p": "The owner holds {{fact:onchain.balance}}."}]
    r["review_coverage"]["areas"][0]["note"] = "Checked against {{fact:onchain.balance}}."
    r["scope"]["out_of_scope"] = [{"path": "x.sol", "reason": "Holds {{fact:onchain.balance}}.", "by": "model"}]
    p = project(copy.deepcopy(r), profile)
    pf = p["findings"][0]
    assert pf["title"] == "Balance of 0 wei is stranded"
    assert pf["description"] == [{"p": "Holds 0 wei."},
                                 {"ul": ["Balance 0 wei stays.", "The constructor is payable."]},
                                 {"table": {"head": ["Item", "Value"],
                                            "rows": [["Balance", "0 wei now"],
                                                     ["Owner", "0xa9e3e9afa056d200241b85aec824b039ffe17582"]]}},
                                 {"p": "Kept paragraph."}]
    assert p["roles"]["notes"] == [{"p": "The owner holds 0 wei."}]
    assert p["review_coverage"]["areas"][0]["note"] == "Checked against 0 wei."
    assert p["scope"]["out_of_scope"][0]["reason"] == "Holds 0 wei."
    assert_expanded(p)


# ── E6 / E3: cover facts on a repo job whose build failed ─────────────────────

def test_oneinch_stored_cover_reproduces_the_defects_and_the_new_meta_fixes_them(tmp_path):
    from soken_review.mapping.build_note import build_failure_sentence
    from soken_review.report.assemble import NO_DEPLOYMENT_LABEL, _source_id_label

    r = _report("oneinch")
    assert r["meta"]["network"] == "Not deployed" and r["meta"]["source_id_label"] == "Commit"
    assert "build_failure" not in r["meta"]
    old = _html(r, tmp_path / "old")
    assert "Not deployed" in old and re.search(r"Commit\s*<span[^>]*>f732a4a39124f7", old)

    status = json.loads((FIX / "oneinch.map_status.json").read_text(encoding="utf-8"))
    sentence = build_failure_sentence(r["facts"]["compiler.version"]["value"], status["build_detail"], "evm")
    assert sentence.startswith("The source did not compile with solc 0.8.0 (parser error).")
    assert "No contract map was built and the analyzers did not run" in sentence
    r["meta"]["network"] = NO_DEPLOYMENT_LABEL
    r["meta"]["source_id_label"] = _source_id_label(r["meta"]["provenance"], r["meta"]["chain"])
    r["meta"]["build_failure"] = sentence
    assert r["meta"]["source_id_label"] == "Files sha256"
    new = _html(r, tmp_path / "new")
    assert "Not deployed" not in new and NO_DEPLOYMENT_LABEL in new
    assert not re.search(r"Commit\s*<span[^>]*>f732a4a3", new) and re.search(r"Files sha256\s*<span[^>]*>f732a4a3", new)
    assert new.count(sentence) >= 2                       # cover and summary
    assert 'data-block="build_failure"' in new
    assert kb.kit_texts()["no_map_card_line"] in new      # the per-card line stays


def test_source_id_label_names_the_value_that_follows_it():
    from soken_review.report.assemble import _source_id_label

    assert _source_id_label({"code_hash": "sha256:ab", "source_hash": "cd"}, "evm") == "Bytecode hash"
    assert _source_id_label({"code_hash": "sha256:ab", "source_hash": "cd"}, "solana") == "Code hash"
    assert _source_id_label({"source_hash": "cd", "commit": "bbb8b0d"}, "evm") == "Files sha256"
    assert _source_id_label({"source_hash": "cd", "address": "0x" + "a" * 40}, "evm") == "Files sha256"
