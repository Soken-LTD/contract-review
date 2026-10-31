"""Replay the blind round 5 MCP arms (2026-10-31) against the thin server.

Usage:
    uv run python scripts/replay_r5_thin.py <matrix-run-2026-10-31-r5 dir>

Reads each arm's recorded call counts from <target>/mcp/result.md (YAML front matter) and replays what
the result files record of the arms' submits through this checkout's engines: the gate texts that were
rejected (through the text and number gates and gate_policy.yaml) and the severity overrides (through the
severity engine). Prints a Markdown report: calls saved per arm and which submits would now be accepted.

Approximations, stated in the output: the result files record counts and the friction texts, not every
call's arguments; a rejected text is replayed as the sentence the arm quoted; a matrix is the one the arm
names or the closest matrix to its description.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

from soken_review.engine import gate_policy
from soken_review.engine.numbers import NumberContext, lex_numbers
from soken_review.engine.severity import SeverityContext, compute_severity
from soken_review.engine.text_gate import check_model_field

TARGETS = ("venus", "revert", "magnum", "bakerfi", "metadao", "tonmultisig")
# Calls of the plain arm (JUDGEMENT.md section 7), for the ratio.
PLAIN_CALLS = {"venus": 11, "revert": 12, "magnum": 10, "bakerfi": 16, "metadao": 10, "tonmultisig": 19}

# Severity round trips the arms recorded (result.md Friction): calls spent only on E_SEVERITY_CONFIRM.
SEVERITY_ROUND_TRIPS = {"magnum": 4}

# Rejected submits the arms recorded, with the text or quote as the result file gives it.
# (target, what was rejected, field, text, kind) kind: text (prose gates) or quote_trivial.
REJECTED: list[tuple[str, str, str, str, str]] = [
    ("venus", "NatSpec quote of the documented fallback intent", "quotes", "", "quote_trivial"),
    ("metadao", "doc-comment-only quote for a doc-vs-code finding", "quotes", "", "quote_trivial"),
    ("revert", "code constant written as a percent", "impact",
     "The penalty moves toward the cap of 10 percent of the debt.", "text"),
    ("bakerfi", "token decimals written with a digit", "description",
     "A 6-decimal token such as USDC breaks the conversion.", "text"),
    ("bakerfi", "external contract names with a digit", "description",
     "The swap goes through UniV2 or UniV3 pools.", "text"),
    ("magnum", "mechanism sentence read as an attack recipe (T30)", "impact",
     ("An attacker who first pushes the price down, then calls stakeDelegator, then reverses the trade "
      "gets a stake worth several times the USDT paid."), "text"),
    ("magnum", "APR constants written as numbers", "impact",
     "That inflated stake then earns 30-55% APR.", "text"),
]
# Title-length rejections (schema maxLength 110): unchanged, the input schema refuses them.
TITLE_REJECTIONS = {"bakerfi": 4, "metadao": 2}

_THEFT = {"impact_class": "theft_of_funds", "magnitude": "unbounded", "trigger": "anyone",
          "precondition": "none", "reversibility": "irreversible"}
_FEE = {**_THEFT, "impact_class": "yield_or_fee_loss", "precondition": "normal_operation"}
_FREEZE = {**_THEFT, "impact_class": "permanent_freeze", "precondition": "normal_operation",
           "reversibility": "admin_reversible"}
_SPEC = {**_THEFT, "impact_class": "spec_deviation_bounded", "magnitude": "bounded", "precondition": "normal_operation"}
_CENTRAL = {**_THEFT, "impact_class": "centralization_risk", "trigger": "privileged_role"}
# Server overrides of round 5 (JUDGEMENT.md 4.1, 3.1): (finding, matrix, reviewer claim, r5 printed, judge)
OVERRIDES = [
    ("BakerFi C-003", _THEFT, "High", "Critical", "High"),
    ("BakerFi H-002", _FEE, "Medium", "High", "Medium"),
    ("BakerFi H-003", _FEE, "Medium", "High", "Medium"),
    ("BakerFi H-005", _FREEZE, "Medium", "High", "Medium"),
    ("BakerFi L-005", _SPEC, "Informational", "Low", "Low"),
    ("Magnum L-001", _CENTRAL, "Medium", "Low", "Medium"),
]


def front_matter(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    _, head, _ = text.split("---", 2)
    return yaml.safe_load(head) or {}


def tool_counts(fm: dict[str, Any]) -> dict[str, int]:
    calls = fm.get("tool_calls") or {}
    return {k: v for k, v in calls.items() if isinstance(v, int) and k.startswith("review_")}


def replay_text(field: str, text: str) -> tuple[bool, list[str]]:
    """(accepted now, blocking rule ids) for one prose text through the text and number gates."""
    blocking: list[str] = []
    for v in [*check_model_field(text, field=field), *lex_numbers(text, NumberContext())]:
        if gate_policy.is_blocking(v.code, v.rule_id):
            blocking.append(f"{v.code}:{v.rule_id}")
    return not blocking, blocking


def main(run_dir: Path) -> None:
    rows, totals = [], {"recorded": 0, "certain": 0, "likely": 0, "optional": 0, "plain": 0}
    accepted_now = {t: 0 for t in TARGETS}
    print("## Replay of the round 5 MCP arms against the thin server\n")
    print("### Submits the arms had rejected\n")
    print("| Target | Rejected submit | Then | Now | Changed by the thin server |")
    print("|---|---|---|---|---|")
    for target, what, field, text, kind in REJECTED:
        if kind == "quote_trivial":
            ok, why, ours = (not gate_policy.is_blocking("E_QUOTE_TRIVIAL")), "accepted with a warning", True
        else:
            ok, rules = replay_text(field, text)
            why = "accepted" if ok else "still refused: " + ", ".join(sorted(set(rules)))
            ours = False   # the prose and number rules are unchanged; a pass here predates this change
        accepted_now[target] += int(ok and ours)
        print(f"| {target} | {what} | refused | {why} | {'yes' if ours else 'no (rule unchanged)'} |")
    for target, n in TITLE_REJECTIONS.items():
        print(f"| {target} | title over 110 characters ({n}) | refused | still refused: input schema maxLength | no |")

    print("\n### Severity overrides\n")
    print("| Finding | Reviewer | r5 printed | Thin server prints | Calibration | Judge |")
    print("|---|---|---|---|---|---|")
    right_then = right_now = 0
    for name, matrix, claim, printed, judge in OVERRIDES:
        r = compute_severity(matrix, "submit", SeverityContext(claimed_severity=claim))
        right_then += printed == judge
        right_now += r.severity == judge
        print(f"| {name} | {claim} | {printed} | {r.severity} | {r.calibration} | {judge} |")
    print(f"\nAgainst the judge: r5 printed {right_then} of {len(OVERRIDES)} right, the thin server "
          f"{right_now} of {len(OVERRIDES)}.\n")

    print("### Calls\n")
    print("| Target | Recorded | Saved, certain | Saved, likely | Saved, no longer steered | Projected | Plain arm |"
          " Ratio then | Ratio now |")
    print("|---|---|---|---|---|---|---|---|---|")
    for target in TARGETS:
        fm = front_matter(run_dir / target / "mcp" / "result.md")
        c = tool_counts(fm)
        recorded = sum(c.values())
        certain = (c.get("review_get_guide", 0)                 # the default guide rides on review_start
                   + SEVERITY_ROUND_TRIPS.get(target, 0)         # no E_SEVERITY_CONFIRM round trip
                   + accepted_now[target])                       # a rejected submit now accepted
        likely = c.get("review_facts", 0)                        # live state is in review_status chain_state
        optional = (c.get("review_challenge", 0) + c.get("review_answer_challenge", 0)
                    + c.get("review_set_section", 0) + c.get("review_dismiss_lead", 0))
        projected = recorded - certain - likely - optional
        plain = PLAIN_CALLS[target]
        rows.append((target, recorded, certain, optional, projected, plain))
        totals["recorded"] += recorded
        totals["certain"] += certain
        totals["likely"] += likely
        totals["optional"] += optional
        totals["plain"] += plain
        print(f"| {target} | {recorded} | {certain} | {likely} | {optional} | {projected} | {plain} | "
              f"{recorded / plain:.1f}x | {projected / plain:.1f}x |")
    projected = totals["recorded"] - totals["certain"] - totals["likely"] - totals["optional"]
    print(f"| all six | {totals['recorded']} | {totals['certain']} | {totals['likely']} | {totals['optional']} | {projected} | "
          f"{totals['plain']} | {totals['recorded'] / totals['plain']:.1f}x | {projected / totals['plain']:.1f}x |")
    print("\nCertain: calls the thin server removes whatever the model does (guide calls, severity round trips,"
          " submits now accepted). Likely: review_facts calls, now answered by chain_state on review_status (a"
          " model may still list facts for placeholders). No longer steered: optional calls the server"
          " used to name in next_tools, the inline checklist or a repeating hint (challenge, answers, sections,"
          " lead dismissals); a model may still make them. review_status polls, code reads, auxiliary jobs and"
          " review_start retries are unchanged. Counts are from result.md front matter (ToolSearch excluded).")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]))
