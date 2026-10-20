"""Severity engine (04 section 7). Pure; no I/O.

Entry points:
  impact_level(impact_class, magnitude, reversibility) -> int  (I0-I4)
  likelihood(trigger, precondition) -> int  (L0-L3)
  base_severity(i_level, l_level) -> str
  compute_severity(matrix, phase, context) -> SeverityResult

Plan: 04 §7.1 (matrix fields), §7.2 (impact level), §7.3 (likelihood/mapping),
§7.4 (pipeline, caps K1-K11), §16 (worked example).

Ambiguity SF-001: severity_rule wire value format documented in docs/w0/submit-finalize-ambiguities.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ── Severity scale ─────────────────────────────────────────────────────────

SEVS = ("Informational", "Low", "Medium", "High", "Critical")
_SEV_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVS)}
_RANK_SEV: dict[int, str] = {i: s for i, s in enumerate(SEVS)}


def _min_sev(a: str, b: str) -> str:
    """Return the lower (more restricted) of two severity strings."""
    return _RANK_SEV[min(_SEV_RANK[a], _SEV_RANK[b])]


def _lower_sev(sev: str, n: int) -> str:
    """Lower severity by n levels, floor at Informational."""
    return _RANK_SEV[max(0, _SEV_RANK[sev] - n)]


# ── Impact level (04 §7.2) ──────────────────────────────────────────────────

# (impact_class, magnitude) -> I-level (I0-I4)
_IMPACT_TABLE: dict[str, dict[str, int]] = {
    "theft_of_funds":               {"unbounded": 4, "bounded": 2, "dust": 1},
    "permanent_freeze":             {"unbounded": 4, "bounded": 2, "dust": 1},
    "insolvency_or_bad_debt":       {"unbounded": 4, "bounded": 2, "dust": 1},
    "control_takeover":             {"unbounded": 4, "bounded": 4, "dust": 4},
    "temporary_freeze":             {"unbounded": 3, "bounded": 2, "dust": 1},
    "yield_or_fee_loss":            {"unbounded": 3, "bounded": 2, "dust": 1},
    "unauthorized_state_change":    {"unbounded": 2, "bounded": 2, "dust": 1},
    "griefing_with_victim_loss":    {"unbounded": 2, "bounded": 2, "dust": 1},
    "dos_core_function":            {"unbounded": 2, "bounded": 2, "dust": 2},
    "centralization_risk":          {"unbounded": 2, "bounded": 2, "dust": 2},
    "dos_noncore_function":         {"unbounded": 1, "bounded": 1, "dust": 1},
    "incorrect_accounting_no_fund_effect": {"unbounded": 1, "bounded": 1, "dust": 1},
    "spec_deviation_bounded":       {"unbounded": 1, "bounded": 1, "dust": 1},
    "best_practice":                {"unbounded": 0, "bounded": 0, "dust": 0},
}

# Reversibility rules (04 §7.2): for permanent_freeze, admin_reversible lowers one, self_recovering reclasses
# For temporary_freeze and dos_core_function: either value lowers one. Floor I1.
_REVERSIBILITY_RECLASS = {
    "permanent_freeze": {
        "admin_reversible": ("permanent_freeze", -1),
        "self_recovering":  ("temporary_freeze", 0),
    },
    "temporary_freeze": {
        "admin_reversible": ("temporary_freeze", -1),
        "self_recovering":  ("temporary_freeze", -1),
    },
    "dos_core_function": {
        "admin_reversible": ("dos_core_function", -1),
        "self_recovering":  ("dos_core_function", -1),
    },
}


def impact_level(impact_class: str, magnitude: str, reversibility: str) -> int:
    """Compute I-level (0-4) from impact_class, magnitude, reversibility (04 §7.2).

    Raises KeyError for unknown values (V0 should have rejected them already).
    """
    row = _IMPACT_TABLE.get(impact_class)
    if row is None:
        raise ValueError(f"Unknown impact_class: {impact_class!r}")
    i = row.get(magnitude)
    if i is None:
        raise ValueError(f"Unknown magnitude: {magnitude!r}")

    # Apply reversibility modifier
    if reversibility != "irreversible":
        reclass = _REVERSIBILITY_RECLASS.get(impact_class, {}).get(reversibility)
        if reclass is not None:
            new_impact_class, delta = reclass
            i = _IMPACT_TABLE[new_impact_class][magnitude] + delta

    return max(1, i) if i > 0 else i  # floor I1 only when i > 0 (I0 stays I0)


# ── Likelihood (04 §7.3) ────────────────────────────────────────────────────

_TRIGGER_L: dict[str, int] = {
    "anyone": 3,
    "permissionless_role": 3,
    "privileged_role_unprotected": 3,
    "privileged_role": 1,
    "upgrade_authority": 1,
}

_PRECONDITION_L: dict[str, int] = {
    "none": 3,
    "normal_operation": 3,
    "market_condition": 2,
    "timing_or_ordering": 2,
    "uncommon_protocol_state": 1,
    "external_failure": 0,
    "victim_unusual_action": 0,
}


def likelihood(trigger: str, precondition: str) -> int:
    """L = min(T[trigger], P[precondition]) (04 §7.3)."""
    t = _TRIGGER_L.get(trigger)
    p = _PRECONDITION_L.get(precondition)
    if t is None:
        raise ValueError(f"Unknown trigger: {trigger!r}")
    if p is None:
        raise ValueError(f"Unknown precondition: {precondition!r}")
    return min(t, p)


# ── Base severity table (04 §7.3) ────────────────────────────────────────────

# _BASE_TABLE[i_level][l_level] -> severity string
_BASE_TABLE: list[list[str]] = [
    # L0, L1, L2, L3
    ["Informational", "Informational", "Informational", "Informational"],  # I0
    ["Low",           "Low",           "Low",           "Low"],            # I1
    ["Low",           "Low",           "Medium",        "Medium"],         # I2
    ["Medium",        "Medium",        "High",          "High"],           # I3
    ["Medium",        "Medium",        "High",          "Critical"],       # I4
]


def base_severity(i_level: int, l_level: int) -> str:
    """Look up base severity from the 04 §7.3 table."""
    if not (0 <= i_level <= 4 and 0 <= l_level <= 3):
        raise ValueError(f"Invalid i_level={i_level} or l_level={l_level}")
    return _BASE_TABLE[i_level][l_level]


# ── Severity context ──────────────────────────────────────────────────────────

@dataclass
class SeverityContext:
    """Caller-supplied context for compute_severity.

    Defaults are chosen to fail closed (unknown = most restrictive).
    """
    phase: str = "submit"                        # "submit" | "post_challenge" | "finalize"
    category_max_severity: str | None = None     # from enums.yaml max_severity
    category_generic: bool = False               # from enums.yaml generic
    linked_lead_same_cat: bool = False           # any lead_id has same category id (K11)
    has_attack_steps: bool = False               # for K8
    downgrade_items_present: int = 0             # count of 'present' challenge downgrade items (K5)
    open_downgrade_item: bool = False            # for K8: "no open downgrade item" check
    evidence_level: str | None = None           # E1/E2/E3, for K4 (finalize only)
    scope_not_covered: bool = False              # for K10: any item not_covered
    map_unavailable: bool = False               # for K10
    token_review: bool = False                   # retail-token/scam profile: owner IS the threat
    has_location_quote: bool = False             # finding quotes reviewed source (its own evidence)


@dataclass
class SeverityResult:
    """Output of compute_severity."""
    severity: str
    severity_rule: str
    caps_applied: list[str]
    evidence_level: str
    i_level: int
    l_level: int
    base: str


# Impact classes that are a direct loss of or seizure of value; under the retail-token profile an
# owner-controlled path to one of these is treated as reachable (owner = threat), not trusted.
_DIRECT_LOSS = frozenset({"theft_of_funds", "permanent_freeze", "insolvency_or_bad_debt", "control_takeover"})


def compute_severity(matrix: dict[str, Any], phase: str, ctx: SeverityContext) -> SeverityResult:
    """Compute severity per 04 §7.4 pipeline.

    matrix: dict with impact_class, magnitude, trigger, precondition, reversibility.
    phase: "submit" | "post_challenge" | "finalize"
    ctx: additional context fields.

    Returns SeverityResult with severity, severity_rule, caps_applied, evidence_level.
    """
    impact_class: str = matrix["impact_class"]
    magnitude: str = matrix["magnitude"]
    trigger: str = matrix["trigger"]
    precondition: str = matrix["precondition"]
    reversibility: str = matrix["reversibility"]

    # Retail-token profile (token_review): the privileged owner is the threat, so an owner path to a
    # direct-loss impact is as reachable as a permissionless one (treat as privileged_role_unprotected,
    # skip the K1 trusted-role cap). And a finding that quotes the deployed code carries its own
    # evidence, so the reasoning_only->Low gate (K4) does not apply to it. Benign centralization_risk
    # notes are not direct-loss, so K7 still pins them to Low and nothing changes for them.
    owner_is_threat = ctx.token_review and impact_class in _DIRECT_LOSS and trigger == "privileged_role"
    eff_trigger = "privileged_role_unprotected" if owner_is_threat else trigger
    code_evidenced = ctx.token_review and ctx.has_location_quote

    i = impact_level(impact_class, magnitude, reversibility)
    l = likelihood(eff_trigger, precondition)
    base = base_severity(i, l)

    sev = base
    caps_applied: list[str] = []

    # --- K1: trigger privileged_role or upgrade_authority -> cap Medium ---
    if trigger in ("privileged_role", "upgrade_authority") and not owner_is_threat:
        capped = _min_sev(sev, "Medium")
        if capped != sev:
            caps_applied.append("K1")
        sev = capped

    # --- K3: magnitude dust -> cap Low ---
    if magnitude == "dust":
        capped = _min_sev(sev, "Low")
        if capped != sev:
            caps_applied.append("K3")
        sev = capped

    # --- K6: precondition victim_unusual_action -> cap Low ---
    if precondition == "victim_unusual_action":
        capped = _min_sev(sev, "Low")
        if capped != sev:
            caps_applied.append("K6")
        sev = capped

    # --- K7: impact centralization_risk -> cap Low ---
    if impact_class == "centralization_risk":
        capped = _min_sev(sev, "Low")
        if capped != sev:
            caps_applied.append("K7")
        sev = capped

    # --- K11: category generic and no linked lead of same category -> cap High ---
    if ctx.category_generic and not ctx.linked_lead_same_cat:
        capped = _min_sev(sev, "High")
        if capped != sev:
            caps_applied.append("K11")
        sev = capped

    # --- K8: post_challenge/finalize: Critical stays Critical ONLY with E2/E3 AND
    # attack_steps AND no open downgrade item. Cap to High when ANY condition is missing.
    # (04 §7.4 K8: "all three required" — was previously inverted using `and` instead of `or`)
    if phase in ("post_challenge", "finalize"):
        requires_k8 = sev == "Critical" and (
            ctx.evidence_level not in ("reasoning_challenged", "analyzer_and_reasoning")
            or not ctx.has_attack_steps
            or ctx.open_downgrade_item
        )
        if requires_k8:
            capped = _min_sev(sev, "High")
            if capped != sev:
                caps_applied.append("K8")
            sev = capped

    # --- K10: post_challenge/finalize: any item not_covered or lexical fallback -> cap High ---
    if phase in ("post_challenge", "finalize") and (ctx.scope_not_covered or ctx.map_unavailable):
        capped = _min_sev(sev, "High")
        if capped != sev:
            caps_applied.append("K10")
        sev = capped

    # --- K4: finalize: evidence reasoning_only -> cap Low ---
    if phase == "finalize" and ctx.evidence_level == "reasoning_only" and not code_evidenced:
        capped = _min_sev(sev, "Low")
        if capped != sev:
            caps_applied.append("K4")
        sev = capped

    # --- category max_severity cap ---
    if ctx.category_max_severity is not None:
        capped = _min_sev(sev, ctx.category_max_severity)
        if capped != sev:
            caps_applied.append(f"max_severity:{ctx.category_max_severity}")
        sev = capped

    # --- K5: each downgrade item present lowers one level, at most 2 (post_challenge/finalize) ---
    if phase != "submit" and ctx.downgrade_items_present > 0:
        n = min(ctx.downgrade_items_present, 2)
        lowered = _lower_sev(sev, n)
        if lowered != sev:
            caps_applied.append("K5")
        sev = lowered

    # Floor Informational
    if _SEV_RANK[sev] < 0:
        sev = "Informational"

    # --- evidence_level ---
    if phase == "submit":
        ev = "reasoning_only" if not ctx.linked_lead_same_cat else "analyzer_and_reasoning"
    else:
        ev = ctx.evidence_level or "reasoning_only"

    # --- severity_rule ---
    rule_parts = [f"I{i}xL{l}={base}"]
    if caps_applied:
        rule_parts.append(f"caps=[{','.join(caps_applied)}]")
    severity_rule = " ".join(rule_parts)

    return SeverityResult(
        severity=sev,
        severity_rule=severity_rule,
        caps_applied=caps_applied,
        evidence_level=ev,
        i_level=i,
        l_level=l,
        base=base,
    )
