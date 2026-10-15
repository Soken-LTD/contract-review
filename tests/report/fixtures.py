"""Synthetic automated report.json fixtures (08 section 7 fixture matrix)."""

from __future__ import annotations

import copy
from typing import Any

from soken_review.report.kit.build import SEV_PREFIX, kit_texts

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
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
           tier: str = "B", label_key: str = "tier_b_not_checked", with_map: bool = False) -> dict[str, Any]:
    t = kit_texts()
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
        "facts": {"vault.balance": {"value": "1,250", "unit": "ETH", "amount_at_risk": True}},
        "summary": {"kpis": [
            {"key": "files", "value": 3, "label": t["kpi_labels"]["files"]},
            {"key": "nsloc", "value": 412, "label": t["kpi_labels"]["nsloc"]},
            {"key": "leads", "value": 12, "label": t["kpi_labels"]["leads"]},
            {"key": "promoted", "value": 1, "label": t["kpi_labels"]["promoted"]},
            {"key": "areas_returned", "value": "4 of 31", "label": t["kpi_labels"]["areas_returned"]},
            {"key": "deployed_code", "value": "Not checked", "label": t["kpi_labels"]["deployed_code"]}]},
        "scope": {"head": ["Unit", "File", "nSLOC", "Address"],
                  "files": [{"name": "Vault", "file": "src/Vault.sol", "nsloc": 300},
                            {"name": "Lib", "file": "src/Lib.sol", "nsloc": 112}],
                  "out_of_scope": [{"path": "test/Vault.t.sol", "reason": "Test file", "by": "server"}]},
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
