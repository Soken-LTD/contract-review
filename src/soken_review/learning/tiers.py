"""Rule tiers (learning-loop design 2026-10-27, section 2.2, phase P1).

Two halves, both driven by data:

* `apply_tiers` is what `review_leads`, the ledger and the report coverage use: given the leads
  of one job and a policy version (`contract/learning/rule_tiers/<version>.yaml`), it annotates
  each lead with the tier it is shown in and the severity it is shown at, orders demoted and
  collapsed leads after the others (stable, so the analyzer order holds inside a tier), and picks
  a deterministic exploration sample of demoted and collapsed leads that is shown in its normal
  place at its analyzer severity. Nothing is removed: a collapsed lead is left out of the default
  page only, counted in the header and listed on request.
* `compute_tiers` is the generator `scripts/learning_tiers.py recompute` runs over the
  `rule_stats` view. It applies the minimum-sample rule, the Wilson bounds, one tier step per
  version, hysteresis, the swing hold and the protected list, and returns a new immutable policy
  plus the reviewed diff. It never activates anything: activation is the `learning.rule_tiers`
  flag, set by a person after the pull request is merged.

Tiers change ordering, visibility and the analyzer severity shown. They never touch a finding,
its printed severity, a gate, or whether a rule runs.
"""

from __future__ import annotations

import hashlib
import math
from functools import cache
from typing import Any

import yaml

from .config import TIERS_DIR, config, config_sha256, valid_version

SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"]
_SEV_INDEX = {s: i for i, s in enumerate(SEVERITIES)}
_TIER_ORDER = ("boosted", "normal", "demoted", "collapsed")
_ANALYZER_CEILING = "High"   # analyzer leads never show Critical (leads DDL)


# ── policy files ──────────────────────────────────────────────────────────────


@cache
def load_policy(version: str) -> dict[str, Any] | None:
    """The immutable policy file for `version`, or None when it does not exist or is malformed."""
    if not valid_version(version):
        return None
    path = TIERS_DIR / f"{version}.yaml"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("version") != version:
        return None
    rules = {}
    for row in doc.get("rules") or []:
        if isinstance(row, dict) and row.get("tool") and row.get("rule") and row.get("tier") in _TIER_ORDER:
            rules[(str(row["tool"]), str(row["rule"]))] = row
    return {**doc, "_index": rules}


def baseline_version() -> str:
    return str(config()["baseline_version"])


def resolve_version(flag_value: Any) -> str:
    """The version review_leads applies, from the `learning.rule_tiers` flag value (or None).

    `{"rollback": true}` is the rollback switch: the baseline is shown on the next call. An
    unknown version falls back to the baseline too; a typo never applies a policy nobody merged."""
    cfg = config()
    if isinstance(flag_value, dict):
        if flag_value.get("rollback"):
            return baseline_version()
        version = flag_value.get("version")
    else:
        version = None
    version = str(version or cfg["default_version"])
    return version if load_policy(version) is not None else baseline_version()


async def active_version(conn: Any) -> str:
    """Version from the flags table (key `learning.rule_tiers`), else the configured default."""
    value = None
    try:
        cur = await conn.execute("select value from flags where key = %s", (config()["flag_key"],))
        row = await cur.fetchone()
        value = row[0] if row else None
    except Exception:  # noqa: BLE001  # a missing flags table or a bad value never breaks listing
        value = None
    return resolve_version(value)


# ── apply ─────────────────────────────────────────────────────────────────────


def lead_tool(lead: dict[str, Any]) -> str:
    tools = lead.get("tools") or []
    if tools:
        return str(tools[0]).split("@", 1)[0]
    rule = str(lead.get("rule_id") or "")
    return rule.split(":", 1)[0] if ":" in rule else "analyzer"


def shift_severity(sev: str, steps: int) -> str:
    """`sev` moved `steps` steps; down to Info at most, up to High at most (never past it)."""
    if sev not in _SEV_INDEX or not steps:
        return sev
    i = _SEV_INDEX[sev]
    if steps > 0:
        return SEVERITIES[max(i, min(i + int(steps), _SEV_INDEX[_ANALYZER_CEILING]))]
    return SEVERITIES[max(0, i + int(steps))]


def _explore_score(version: str, job_id: str, lead_id: str) -> float:
    digest = hashlib.sha256(f"explore|{version}|{job_id}|{lead_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def apply_tiers(leads: list[dict[str, Any]], version: str, job_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Annotated copies of `leads` in display order, and a summary for the header and the report.

    Each copy carries `tier`, `severity_analyzer` (the mapped analyzer severity) and
    `severity_norm` (the severity shown). Previous-report leads are never tiered. The baseline,
    or an unknown version, returns the leads unchanged in their original order."""
    policy = load_policy(version)
    cfg = config()
    summary: dict[str, Any] = {"version": version if policy is not None else baseline_version(),
                               "demoted": 0, "collapsed": 0, "boosted": 0, "explore": 0, "by_tool": {}}
    out = []
    for lead in leads:
        c = dict(lead)
        c["severity_analyzer"] = c.get("severity_norm")
        c["tier"] = "normal"
        out.append(c)
    if policy is None or not policy["_index"]:
        return out, summary

    index = policy["_index"]
    exp = cfg["exploration"]
    candidates: list[tuple[float, dict[str, Any]]] = []
    for c in out:
        if c.get("origin", "analyzer") != "analyzer":
            continue
        row = index.get((lead_tool(c), str(c.get("rule_id") or "")))
        if row is None:
            continue
        c["tier"] = row["tier"]
        c["severity_norm"] = shift_severity(str(c.get("severity_norm") or ""), int(row.get("severity_shift") or 0))
        if c["tier"] in exp["tiers"]:
            candidates.append((_explore_score(summary["version"], job_id, str(c.get("id") or "")), c))
    picked = sorted((sc, c) for sc, c in candidates if sc < float(exp["rate"]))[: int(exp["max_per_job"])] \
        if candidates else []
    for _, c in picked:
        c["tier"] = "explore"
        c["severity_norm"] = c["severity_analyzer"]

    ranks = {name: int(row["rank"]) for name, row in cfg["tiers"].items()}
    out.sort(key=lambda c: ranks.get(c["tier"], 1))     # stable: analyzer order inside a tier
    for c in out:
        if c["tier"] in ("demoted", "collapsed", "boosted", "explore"):
            summary[c["tier"]] += 1
            if c["tier"] in ("demoted", "collapsed"):
                tool = str((c.get("tools") or ["analyzer@"])[0])
                summary["by_tool"][tool] = summary["by_tool"].get(tool, 0) + 1
    return out, summary


def listed_by_default(tier: str) -> bool:
    row = config()["tiers"].get(tier)
    return bool(row["listed"]) if row else True


def lead_suffix(lead: dict[str, Any]) -> str:
    """Server label appended to a lead line in review_leads ("" for a normal lead)."""
    tmpl = config()["labels"]["lead_suffix"].get(lead.get("tier") or "normal")
    if not tmpl:
        return ""
    return tmpl.format(analyzer_severity=str(lead.get("severity_analyzer") or "").lower())


def header_line(summary: dict[str, Any], collapsed_hidden: bool) -> str:
    """One header line naming the policy and how many leads it moved; "" when it moved none."""
    if not (summary.get("demoted") or summary.get("collapsed")):
        return ""
    labels = config()["labels"]
    hint = labels["collapsed_hint"] if collapsed_hidden and summary.get("collapsed") else ""
    return labels["header"].format(version=summary["version"], demoted=summary["demoted"],
                                   collapsed=summary["collapsed"], collapsed_hint=hint)


# ── generator ─────────────────────────────────────────────────────────────────

_Z = 1.96


def wilson(k: int, n: int) -> tuple[float, float]:
    """Wilson 95% interval on k / n; (0, 1) for an empty sample."""
    if n <= 0:
        return 0.0, 1.0
    p = k / n
    z2 = _Z * _Z
    centre = p + z2 / (2 * n)
    margin = _Z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    den = 1 + z2 / n
    return max(0.0, (centre - margin) / den), min(1.0, (centre + margin) / den)


def _meets(stat: dict[str, Any], sample: dict[str, Any]) -> bool:
    n = int(stat.get("triaged") or 0)
    if n < int(sample["triaged"]):
        return False
    if int(stat.get("targets") or 0) < int(sample["targets"]):
        return False
    if int(stat.get("principals") or 0) < int(sample["principals"]):
        return False
    share = (int(stat.get("max_principal_n") or 0) / n) if n else 1.0
    return share <= float(sample["max_principal_share"]) + 1e-9


def is_protected(tool: str, rule: str, extra: set[tuple[str, str]]) -> str | None:
    """Why (tool, rule) is protected, or None."""
    prot = config()["protected"]
    if tool in set(prot.get("tools") or []):
        return f"in-house lifecycle tool {tool}"
    for row in prot.get("rules") or []:
        if row.get("tool") == tool and row.get("rule") == rule:
            return str(row.get("evidence") or "listed in learning.yaml")
    if (tool, rule) in extra:
        return "judge-confirmed or printed High from a public-code promotion"
    return None


def _step(prev: str, target: str) -> str:
    """One tier step from prev toward target (max_tier_steps_per_version = 1)."""
    order = list(_TIER_ORDER)
    i, j = order.index(prev), order.index(target)
    if i == j:
        return prev
    return order[i + (1 if j > i else -1)]


def decide(stat: dict[str, Any], prev_row: dict[str, Any] | None, protected_why: str | None) -> dict[str, Any]:
    """Tier, severity shift and the reason for one rule (design 2.2 rules 1 to 6)."""
    cfg = config()
    th = cfg["thresholds"]
    n = int(stat.get("triaged") or 0)
    k = int(stat.get("promoted") or 0)
    gm = int(stat.get("promoted_ge_medium") or 0)
    above = int(stat.get("promoted_above_norm") or 0)
    lb, ub = wilson(k, n)
    gm_lb, gm_ub = wilson(gm, n)
    full = _meets(stat, cfg["min_sample"])
    dem = _meets(stat, cfg["demote_min_sample"])
    prev = str((prev_row or {}).get("tier") or "normal")
    basis = {"triaged": n, "promoted": k, "promoted_ge_medium": gm, "targets": int(stat.get("targets") or 0),
             "principals": int(stat.get("principals") or 0), "p": round(k / n, 3) if n else None,
             "p_lb": round(lb, 3), "p_ub": round(ub, 3), "p_ge_medium_lb": round(gm_lb, 3),
             "p_ge_medium_ub": round(gm_ub, 3)}

    target, why = prev, "keep"
    if protected_why and prev in ("demoted", "collapsed"):
        target, why = "normal", f"protected ({protected_why}): floor tier normal"
    elif prev in ("demoted", "collapsed") and dem and lb >= float(th["restore"]["p_lb_at_least"]):
        target, why = "normal", f"restore: P lower bound {lb:.3f} >= {th['restore']['p_lb_at_least']}"
    elif (prev == "demoted" and not protected_why and full and n >= int(th["collapse"]["triaged"])
          and basis["targets"] >= int(th["collapse"]["targets"]) and ub < float(th["collapse"]["p_ub_below"])):
        target, why = "collapsed", f"collapse: P upper bound {ub:.3f} < {th['collapse']['p_ub_below']} after a demoted release"
    elif prev in ("normal", "boosted") and not protected_why and dem and ub < float(th["demote"]["p_ub_below"]):
        target, why = "demoted", f"demote: P upper bound {ub:.3f} < {th['demote']['p_ub_below']}"
    elif (prev == "normal" and full and n >= int(th["boost"]["triaged"])
          and basis["targets"] >= int(th["boost"]["targets"])
          and gm_lb >= float(th["boost"]["p_ge_medium_lb_at_least"])):
        target, why = "boosted", f"boost: P(>=Medium) lower bound {gm_lb:.3f}"
    elif not dem:
        why = "insufficient sample"

    tier = _step(prev, target) if target != prev else prev
    held = False
    prev_p = ((prev_row or {}).get("basis") or {}).get("p")
    if tier != prev and prev_p is not None and basis["p"] is not None \
            and abs(basis["p"] - float(prev_p)) > float(th["swing_hold"]["p_delta_above"]) and not protected_why:
        tier, held, why = prev, True, f"held for manual review: P moved {prev_p} -> {basis['p']}"

    shift = int(cfg["tiers"][tier]["severity_shift"])
    sd, su = th["severity_down"], th["severity_up"]
    if not protected_why and dem and k >= int(sd["promoted_min"]) and gm_ub < float(sd["ge_medium_ub_below"]):
        shift = min(shift, -1)
        why += f"; severity one step down: P(>=Medium) upper bound {gm_ub:.3f}"
    elif dem and k >= int(su["promoted_min"]) and above / k >= float(su["above_norm_share_at_least"]) \
            and tier in ("normal", "boosted"):
        shift = max(shift, 1)
        why += f"; severity one step up: {above} of {k} promotions printed above the analyzer severity"
    return {"tier": tier, "severity_shift": shift, "basis": basis, "reason": why, "held": held,
            "protected": bool(protected_why), "sufficient": dem}


def compute_tiers(stats: list[dict[str, Any]], previous: dict[str, Any] | None, new_version: str,
                  extra_protected: set[tuple[str, str]], snapshot: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """New policy document and the list of per-rule decisions that differ from `previous`."""
    prev_index = (previous or {}).get("_index") or {}
    keys = {(str(s["tool"]), str(s["rule_id"])) for s in stats} | set(prev_index)
    by_key = {(str(s["tool"]), str(s["rule_id"])): s for s in stats}
    rules, protected, changes = [], [], []
    for tool, rule in sorted(keys):
        stat = by_key.get((tool, rule), {})
        prev_row = prev_index.get((tool, rule))
        why_prot = is_protected(tool, rule, extra_protected)
        d = decide(stat, prev_row, why_prot)
        if why_prot:
            protected.append({"tool": tool, "rule": rule, "floor_tier": "normal", "evidence": why_prot})
        if d["tier"] != "normal" or d["severity_shift"]:
            rules.append({"tool": tool, "rule": rule, "tier": d["tier"], "severity_shift": d["severity_shift"],
                          "basis": d["basis"], "reason": d["reason"]})
        prev_tier = str((prev_row or {}).get("tier") or "normal")
        prev_shift = int((prev_row or {}).get("severity_shift") or 0)
        if d["tier"] != prev_tier or d["severity_shift"] != prev_shift or d["held"]:
            changes.append({"tool": tool, "rule": rule, "from_tier": prev_tier, "to_tier": d["tier"],
                            "from_shift": prev_shift, "to_shift": d["severity_shift"], **d})
    cfg = config()
    doc = {
        "version": new_version,
        "previous": (previous or {}).get("version"),
        "generated_from": {"view": "rule_stats", "window_days": cfg["window_days"], "snapshot": snapshot,
                           "config_sha256": config_sha256(), "rules_with_stats": len(stats)},
        "min_sample": cfg["min_sample"],
        "demote_min_sample": cfg["demote_min_sample"],
        "rules": rules,
        "protected": protected,
    }
    return doc, changes


def render_diff(doc: dict[str, Any], changes: list[dict[str, Any]], stats: list[dict[str, Any]]) -> str:
    """Markdown diff for the pull request a person reviews before the version is activated."""
    lines = [f"# Rule tiers {doc['version']} (previous {doc['previous']})", "",
             (f"Snapshot {doc['generated_from']['snapshot']}, window {doc['generated_from']['window_days']} days, "
              f"{len(stats)} rules with outcomes. Not active until the `learning.rule_tiers` flag names this version."),
             ""]
    if changes:
        lines += ["| Tool | Rule | Tier | Severity shift | Triaged | Promoted | Targets | P upper | Reason |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for c in changes:
            b = c["basis"]
            lines.append(f"| {c['tool']} | {c['rule']} | {c['from_tier']} to {c['to_tier']} | "
                         f"{c['from_shift']} to {c['to_shift']} | {b['triaged']} | {b['promoted']} | {b['targets']} | "
                         f"{b['p_ub']} | {c['reason']} |")
    else:
        lines.append("No tier or severity change against the previous version.")
    insufficient = sum(1 for s in stats if not _meets(s, config()["demote_min_sample"]))
    lines += ["", f"Rules below the minimum sample (kept as they are): {insufficient}.",
              f"Protected rules: {len(doc['protected'])}."]
    return "\n".join(lines) + "\n"
