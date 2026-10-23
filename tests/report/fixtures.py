"""Synthetic automated report.json fixtures (08 section 7 fixture matrix)."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path
from typing import Any

from soken_review.report.kit.build import SEV_PREFIX, kit_texts

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
# Context ingestion spec fixtures (sections 4, 5, 6): manifest + files, facts.json, comparison rows.
CONTEXT_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "context"
CONTEXT_TODAY = date(2026, 10, 23)
CONTEXT_NOTES = [
    {"p": "The whitepaper declares a total supply of {{fact:context.whitepaper.total_supply}} and a swap fee of "
          "{{fact:context.whitepaper.fee_pct_1}}; the documentation states {{fact:context.docs.fee_pct_1}} for the same fee."},
    {"ul": ["The whitepaper describes ownership as `renounced`; the documentation names an owner multisig that can pause the vault.",
            "The website lists the reviewed vault address on Base and names an external review firm."]},
]


def context_manifest() -> dict[str, Any]:
    return json.loads((CONTEXT_DIR / "manifest.json").read_text(encoding="utf-8"))


def context_facts_json() -> list[dict[str, Any]]:
    return json.loads((CONTEXT_DIR / "facts.json").read_text(encoding="utf-8"))


def context_comparison_json() -> list[dict[str, Any]]:
    return json.loads((CONTEXT_DIR / "comparison.json").read_text(encoding="utf-8"))


def context_fixture() -> dict[str, Any]:
    """Report `context` object built the way assemble builds it: 4 documents (one failed), 5 rows of
    mixed status, 2 notes."""
    from soken_review.report.assemble import context_documents, context_rows

    return {"documents": context_documents(context_manifest()["entries"], CONTEXT_TODAY),
            "comparison": context_rows(context_comparison_json()), "notes": copy.deepcopy(CONTEXT_NOTES)}


def context_report_facts() -> dict[str, dict[str, Any]]:
    from soken_review.report.assemble import context_facts

    return context_facts(context_facts_json())


EMPTY_CONTEXT: dict[str, Any] = {"documents": [], "comparison": [], "notes": []}
HIGH_TITLE = "Reentrant withdraw lets a caller drain the vault before the balance write"
CODE = [
    "function withdraw(uint256 amount) external {",
    "    require(balances[msg.sender] >= amount);",
    "    (bool ok, ) = msg.sender.call{value: amount}(\"\");",
    "    balances[msg.sender] -= amount;",
    "}",
]


def _basis() -> dict[str, Any]:
    return {"head": ["Impact class", "Trigger", "Precondition", "Rule"],
            "rows": [["theft_of_funds", "anyone", "none", "S1"]]}


def finding(i: int, sev: str, *, title: str | None = None, level: str = "reasoning_challenged",
            with_fact: str | None = None, code_lines: int = 5) -> dict[str, Any]:
    if level == "reasoning_only" and sev not in ("Low", "Informational"):
        level = "reasoning_challenged"
    lines = [[10 + n, CODE[n % len(CODE)]] for n in range(code_lines)]
    desc = "The `withdraw` function sends value before it writes the caller balance."
    if with_fact:
        desc += f" The vault holds {{{{fact:{with_fact}}}}} at the pinned block."
    f = {
        "id": f"{SEV_PREFIX[sev]}-{i:03d}",
        "severity": sev,
        "evidence_level": level,
        "title": title or f"Balance written after the external call in withdraw path {i}",
        "component": "Vault",
        "location": {"path": "src/Vault.sol", "start": 10, "end": 14},
        "category": "Reentrancy",
        "category_key": "evm.reentrancy",
        "description": [{"p": desc}],
        "impact": [{"p": "A contract caller can withdraw its balance more than once in one transaction."}],
        "recommendation": [{"p": "Write the balance before the external call and add a reentrancy lock."}],
        "evidence": {
            "code": [{"code": {"ref": {"path": "src/Vault.sol", "start": 10, "end": 10 + code_lines - 1},
                               "lines": lines}}],
            "basis": _basis(),
            "challenge": None if level == "reasoning_only" else
            {"head": ["Item", "Condition", "Answer"], "rows": [["R1", "State written before the call", "No"]]},
            "lead": {"analyzer": "slither 0.11.6", "rule_id": "reentrancy-eth"} if level == "analyzer_and_reasoning" else None,
        },
    }
    if with_fact:
        f["evidence"]["figures"] = [{"figure": "1,250 ETH", "operands": [
            {"value": "1,250", "source": {"fact": with_fact, "method": "eth_getBalance", "block_or_slot": 52392348}}]}]
    if sev == "Critical":
        f["attack_steps"] = [{"text": "Call `withdraw` from a contract whose fallback calls it again.",
                              "ref": {"path": "src/Vault.sol", "start": 12, "end": 12}}]
    return f


def report(n_findings: int = 3, profile: str = "public_review", severities: list[str] | None = None,
           tier: str = "B", label_key: str = "tier_b_not_checked", with_map: bool = False,
           context: str = "full") -> dict[str, Any]:
    """`context`: "full" (4 documents, 5 rows, 2 notes, `documents` KPI) or "empty" (no documents)."""
    t = kit_texts()
    ctx = context_fixture() if context == "full" else copy.deepcopy(EMPTY_CONTEXT)
    ctx_facts = context_report_facts() if context == "full" else {}
    n_docs = sum(1 for d in ctx["documents"] if d["status"] == "ok")
    doc_kpi = [{"key": "documents", "value": n_docs, "label": t["kpi_labels"]["documents"]}] if n_docs else []
    sevs = severities or [SEV_ORDER[i % 5] for i in range(n_findings)]
    sevs = sorted(sevs, key=SEV_ORDER.index)
    per: dict[str, int] = {}
    fs = []
    for k, s in enumerate(sevs):
        per[s] = per.get(s, 0) + 1
        fs.append(finding(per[s], s, with_fact="vault.balance" if s == "Medium" and per[s] == 1 else None,
                          level=["analyzer_and_reasoning", "reasoning_challenged", "reasoning_only"][k % 3]))
    prov: dict[str, Any] = {"tier": tier, "label": t["tier_labels"][label_key], "label_key": label_key,
                            "source_hash": "b4cc916ccf88bed8f28f6c15752c424fe8ef881983807d4240895a129f9adf49",
                            "address": "0xc2181d975c05c8c724b334bcED0764c0b86B1D53"}
    if tier == "A":
        prov.update(code_hash="0x" + "ab" * 32, as_of={"block_or_slot": 52392348, "date": "9 October 2026"},
                    upgrade_authority="Renounced", upgradeable=False)
    arch = {"title": t["architecture_title"], "cols": 4, "rows": 1, "edges": [],
            "nodes": [{"id": "no_map", "label": "Vault", "kind": "scope", "col": 0, "row": 0}]}
    if with_map:
        arch = {"title": t["architecture_title"], "cols": 4, "rows": 3,
                "nodes": [{"id": "r0", "label": "owner", "kind": "actor", "col": 1.5, "row": 0},
                          {"id": "u0", "label": "Vault", "sub": "contract", "kind": "scope", "col": 1.5, "row": 1},
                          {"id": "e0", "label": "WETH", "kind": "ext", "col": 1.5, "row": 2}],
                "edges": [{"a": "r0", "b": "u0"}, {"a": "u0", "b": "e0"}]}
    return {
        "meta": {"report_type": "automated", "kind": "Smart contract security review", "subject": "Vault",
                 "subject_source": "verified_name", "chain": "evm", "network": "Base (8453)", "chain_id": 8453,
                 "explorer": None, "addr_url": None, "deployed_noun": "contract", "source_id_label": "Bytecode hash",
                 "provenance": prov, "report_id": "abcdefghijklmnopqrstuvwxyz", "report_id_short": "abcdefghij",
                 "ownership_proven": profile == "owner", "profile": profile,
                 "requested_by": {"role": "third_party_public_code", "label": "Third party reviewing public code"},
                 "date": "10 October 2026", "expires": "2026-11-09", "out_name": "Automated_Review_abcdefghij.pdf"},
        "facts": {"vault.balance": {"value": "1,250", "unit": "ETH", "amount_at_risk": True}, **ctx_facts},
        "summary": {"kpis": [
            {"key": "files", "value": 3, "label": t["kpi_labels"]["files"]},
            {"key": "nsloc", "value": 412, "label": t["kpi_labels"]["nsloc"]},
            {"key": "leads", "value": 12, "label": t["kpi_labels"]["leads"]},
            {"key": "promoted", "value": 1, "label": t["kpi_labels"]["promoted"]},
            {"key": "areas_returned", "value": "4 of 31", "label": t["kpi_labels"]["areas_returned"]},
            {"key": "deployed_code", "value": "Not checked", "label": t["kpi_labels"]["deployed_code"]}, *doc_kpi]},
        "scope": {"head": ["Unit", "File", "nSLOC", "Address"],
                  "files": [{"name": "Vault", "file": "src/Vault.sol", "nsloc": 300},
                            {"name": "Lib", "file": "src/Lib.sol", "nsloc": 112}],
                  "out_of_scope": [{"path": "test/Vault.t.sol", "reason": "Test file", "by": "server"}]},
        "context": ctx,
        "architecture": arch,
        "roles": {"rows": [], "notes": []},
        "method": [{"step": t["method_steps"]["analyzer"], "detail": "slither 0.11.6, 12 leads"}],
        "severity_scale": [{"severity": s, "text": t["severity_scale"][s.lower()]} for s in SEV_ORDER],
        "findings": fs,
        "review_coverage": {
            "areas": [{"area_id": "evm.reentrancy", "area": "Reentrancy", "code_returned": "Yes",
                       "result": [f["id"] for f in fs][:20] or "No finding submitted"}],
            "leads": [{"analyzer": "slither", "version": "0.11.6", "leads": 12, "promoted": 1, "dismissed": 0}],
            "withdrawn": [], "injection_flags": []},
    }


def with_profile(r: dict[str, Any], profile: str) -> dict[str, Any]:
    out = copy.deepcopy(r)
    out["meta"]["profile"] = profile
    out["meta"]["ownership_proven"] = profile == "owner"
    return out
