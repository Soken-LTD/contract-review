"""Severity engine (04 section 7). Pure; no I/O.

Entry points:
  impact_level(impact_class, magnitude, reversibility) -> int  (I0-I4)
  likelihood(trigger, precondition) -> int  (L0-L3)
  base_severity(i_level, l_level) -> str
  compute_severity(matrix, phase, context) -> SeverityResult

Plan: 04 §7.1 (matrix fields), §7.2 (impact level), §7.3 (likelihood/mapping),
§7.4 (pipeline, caps K1-K11), §16 (worked example).

Thin server (CEO decision 2026-10-31, blind rounds 1 to 5): the severity the client reads is the
reviewer's `claimed_severity`, always. The IxL cell and the named rules (K caps, K5, TR1, IRR1) are
still computed and returned as the calibration (`calibration`, `calibration_rule`), which the report
prints beside the finding when it differs; no rule changes the printed value. The rule registry is
`contract/rubric/severity_rules.yaml`; `RULE_TEXT` below mirrors it (a test keeps the two in step).

Ambiguity SF-001: severity_rule wire value format documented in docs/w0/submit-finalize-ambiguities.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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


def _step(a: str, b: str) -> int:
    """Signed distance in steps from b to a (positive when a is the higher severity)."""
    return _SEV_RANK[a] - _SEV_RANK[b]


# ── Impact level (04 §7.2) ──────────────────────────────────────────────────

# (impact_class, magnitude) -> I-level (I0-I4)
# magnitude `residual` (2026-10-27): the amount at risk is whatever is left over in the unit under
# normal operation (stranded excess, bounced value, rounding remainders): not capped by code, so not
# `bounded`, and not a rounding artefact, so not `dust`. One level under bounded, floor I1; classes
# where magnitude does not matter keep their bounded value.
_IMPACT_TABLE: dict[str, dict[str, int]] = {
    "theft_of_funds":               {"unbounded": 4, "bounded": 2, "residual": 1, "dust": 1},
    "permanent_freeze":             {"unbounded": 4, "bounded": 2, "residual": 1, "dust": 1},
    "insolvency_or_bad_debt":       {"unbounded": 4, "bounded": 2, "residual": 1, "dust": 1},
    # supply_inflation (2026-10-27): unbacked mint, a burn that is not a burn, a double-counted fee,
    # balances that exceed totalSupply. Holders are diluted although nobody takes a balance, so the
    # reviewer could not honestly pick theft_of_funds and the old fallbacks (spec_deviation_bounded,
    # incorrect_accounting_no_fund_effect) computed Low for a token whose supply invariant is broken.
    "supply_inflation":             {"unbounded": 4, "bounded": 2, "residual": 1, "dust": 1},
    "control_takeover":             {"unbounded": 4, "bounded": 4, "residual": 4, "dust": 4},
    "temporary_freeze":             {"unbounded": 3, "bounded": 2, "residual": 1, "dust": 1},
    "yield_or_fee_loss":            {"unbounded": 3, "bounded": 2, "residual": 1, "dust": 1},
    "unauthorized_state_change":    {"unbounded": 2, "bounded": 2, "residual": 1, "dust": 1},
    "griefing_with_victim_loss":    {"unbounded": 2, "bounded": 2, "residual": 1, "dust": 1},
    "dos_core_function":            {"unbounded": 2, "bounded": 2, "residual": 2, "dust": 2},
    "centralization_risk":          {"unbounded": 2, "bounded": 2, "residual": 2, "dust": 2},
    "dos_noncore_function":         {"unbounded": 1, "bounded": 1, "residual": 1, "dust": 1},
    "incorrect_accounting_no_fund_effect": {"unbounded": 1, "bounded": 1, "residual": 1, "dust": 1},
    "spec_deviation_bounded":       {"unbounded": 1, "bounded": 1, "residual": 1, "dust": 1},
    "best_practice":                {"unbounded": 0, "bounded": 0, "residual": 0, "dust": 0},
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

    Raises ValueError for unknown values (V0 should have rejected them already).
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


# ── Rule registry (ids the engine emits; text mirrors contract/rubric/severity_rules.yaml) ──

RULE_TEXT: dict[str, str] = {
    "K1": "trigger privileged_role or upgrade_authority caps at Medium",
    "K3": "magnitude dust caps at Low",
    "K4": "evidence reasoning_only at finalize caps at Low",
    "K5": "a downgrade item answered present lowers one step",
    "K6": "precondition victim_unusual_action caps at Low",
    "K7": "impact centralization_risk caps at Low",
    "K8": "Critical needs challenged evidence and attack steps, else High",
    "K10": "no contract map caps at High",
    "K11": "generic category without a linked lead of the same category caps at High",
    "IRR1": "irreversible unbounded loss: uncommon_protocol_state counts as L2, not L1",
    "TR1": "retail token, owner is the threat: an irreversible owner path to a direct loss is reachable, K1 waived",
    "RV1": "reviewer's claimed_severity is the printed severity; the matrix is a calibration note",
    "DG1": "retired 2026-10-31: a challenge never moves the printed severity",
}
_MAX_SEVERITY_RULE = "category max_severity caps the finding"

# Kept for importers; the thin server (2026-10-31) has no reviewer tolerance: the claim always stands.
REVIEWER_STEP = 1
# Minimum length of a `severity_reason` for RV1 (also enforced by the finding schema).
REASON_MIN_CHARS = 20


def rule_text(rule_id: str) -> str:
    """One-line client text for a rule id as it appears in caps_applied (`K1`, `MB1:magnitude=bounded`,
    `max_severity:Informational`, `RV1:reviewer=Medium`)."""
    head, _, tail = rule_id.partition(":")
    if head in RULE_TEXT:
        return RULE_TEXT[head] + (f" ({tail})" if tail else "")
    if head == "max_severity":
        return f"{_MAX_SEVERITY_RULE} at {tail}" if tail else _MAX_SEVERITY_RULE
    if head.startswith("MB") and tail:
        fld, _, val = tail.partition("=")
        return f"basis item {head} answered against expectation: {fld} becomes {val}"
    if head == "kill" and tail:
        return f"kill item {tail} answered present: finding withdrawn"
    return rule_id


_K_CAP_RE = re.compile(r"^K[0-9]{1,2}$")


def k_caps_only(rules: list[str]) -> list[str]:
    """The K cap ids of a rule list (the `caps_applied` shape older clients validate against)."""
    return [r for r in rules if _K_CAP_RE.match(r)]


def explain_rules(rules: list[str], limit: int = 200) -> str:
    """`K1: ...; DG1: ...` for the report's severity table and the verdict payload, at most `limit` chars."""
    parts = [f"{r}: {rule_text(r)}" for r in rules]
    text = "; ".join(parts)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "."


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
    # Any challenge item whose scope the map could not supply. Recorded, never a cap: until
    # 2026-10-27 it fed K10, and a rubric item with an empty scope capped the finding at High for
    # ever (Solana ata_owner_reassign, blind run 2026-10-26). A present answer on such an item is
    # rejected by the answer checker instead, because nothing can verify it.
    scope_not_covered: bool = False
    map_unavailable: bool = False               # for K10: no contract map for the job
    # never-worse (2026-10-27): the draft reached finalize without its optional challenge. K4 does not
    # cap it (the reviewer's severity stands, printed with evidence reasoning_only and a coverage note);
    # K8 still caps an unchallenged Critical at High.
    challenge_skipped: bool = False
    token_review: bool = False                   # retail-token/scam profile: owner IS the threat
    has_location_quote: bool = False             # finding quotes reviewed source (its own evidence)
    # Reviewer-first (RV1): the reviewer's proposal and its recorded reason (claimed_severity,
    # severity_reason on the submitted finding).
    claimed_severity: str | None = None
    claimed_reason: str | None = None
    # DG1: the severity accepted at submit for this revision; post_challenge and finalize never
    # print more than one step below it unless a kill item withdrew the finding.
    severity_before: str | None = None
    # post_challenge: every checklist item was answered and verified. Only a complete answer promotes
    # the evidence to reasoning_challenged; K8 reads the evidence the draft will carry after this
    # phase, so the challenge verdict and finalize compute the same value (BakerFi r5: the answer
    # printed High under K8 while finalize printed Critical from the stored, promoted evidence).
    challenge_complete: bool = True


def stage_evidence(phase: str, ctx: SeverityContext) -> str:
    """The evidence level a draft carries after `phase` (04 section 9). One function for every stage.

    E3 analyzer_and_reasoning: a same-category analyzer lead is linked.
    E2 reasoning_challenged: no qualifying lead, the checklist answered completely and verified.
    E1 reasoning_only: neither (submit, a partial answer, a draft that never took a challenge).
    """
    if phase == "submit":
        return "reasoning_only" if not ctx.linked_lead_same_cat else "analyzer_and_reasoning"
    prior = ctx.evidence_level or "reasoning_only"
    if phase == "post_challenge":
        if prior == "analyzer_and_reasoning" or ctx.linked_lead_same_cat:
            return "analyzer_and_reasoning"
        return "reasoning_challenged" if ctx.challenge_complete else prior
    return prior


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
    # Who set the printed severity: "reviewer" (claimed_severity, always final) or "matrix" (no claim:
    # the outcome accepted at submit). "cap" is no longer produced (thin server, 2026-10-31).
    set_by: str = "matrix"
    # The reviewer's reason when set_by == "reviewer", else the one-line text of the binding rules.
    reason: str = ""
    # The matrix outcome after caps and before the reviewer's choice (what RV1 measured against).
    computed: str = ""
    # submit only: the reviewer's claimed_severity is given and cannot stand silently; the caller
    # asks the reviewer to confirm `computed` or to reclassify (E_SEVERITY_CONFIRM).
    # Retired with the thin server (2026-10-31): the server never asks the reviewer to confirm.
    confirm_needed: bool = False
    confirm_why: str = ""
    # The matrix outcome after the K caps (and K5) and the rules that produced it. The report prints
    # "Calibration: <calibration> (<calibration_rule>)" beside the finding when it differs from severity.
    calibration: str = ""
    calibration_rule: str = ""
    rules: list[str] = field(default_factory=list)   # same as caps_applied (name kept for callers)


# Impact classes that are a direct loss of or seizure of value; under the retail-token profile an
# owner-controlled path to one of these is treated as reachable (owner = threat), not trusted.
_DIRECT_LOSS = frozenset({"theft_of_funds", "permanent_freeze", "insolvency_or_bad_debt", "control_takeover",
                          "supply_inflation"})

# IRR1: an irreversible, unbounded loss of value. State rarity lowers its likelihood one step, not two.
_IRREVERSIBLE_LOSS = frozenset({"theft_of_funds", "permanent_freeze", "insolvency_or_bad_debt", "supply_inflation"})
_PERMISSIONLESS = frozenset({"anyone", "permissionless_role", "privileged_role_unprotected"})
# Rules that shape the IxL cell itself (likelihood), as opposed to caps, steps and floors applied after it.
_CELL_RULES = frozenset({"TR1", "IRR1"})


def compute_severity(matrix: dict[str, Any], phase: str, ctx: SeverityContext) -> SeverityResult:
    """Compute the printed severity and the matrix calibration (04 §7.4, thin server 2026-10-31).

    matrix: dict with impact_class, magnitude, trigger, precondition, reversibility.
    phase: "submit" | "post_challenge" | "finalize"
    ctx: additional context fields.

    Calibration: IxL cell -> profile rules (TR1, IRR1) -> caps (K1 K3 K6 K7 K11 K8 K10 K4, category
    max) -> K5 = `calibration`. Printed: claimed_severity when given; otherwise the submit outcome
    (kept by later phases through severity_before). Every rule that moved the calibration away from
    the cell is named in caps_applied and severity_rule.
    """
    impact_class: str = matrix["impact_class"]
    magnitude: str = matrix["magnitude"]
    trigger: str = matrix["trigger"]
    precondition: str = matrix["precondition"]
    reversibility: str = matrix["reversibility"]

    rules: list[str] = []

    # TR1, retail-token profile: the privileged owner is the threat, so an owner path to a direct-loss
    # impact is as reachable as a permissionless one (treat as privileged_role_unprotected, skip the
    # K1 trusted-role cap). Since 2026-10-27 the waiver needs reversibility `irreversible`: an owner
    # action the owner can undo (a pause, an exclusion list, a fee switch) is a centralization risk
    # and keeps the K1 Medium cap (BNB ANTTIME F-01, owner pause printed High with no rule named);
    # an owner path with no undo (mint to self, drain, brick) is the retail-token threat.
    # A finding that quotes the deployed code carries its own evidence, so the reasoning_only->Low
    # gate (K4) does not apply to it. Benign centralization_risk notes are not direct-loss, so K7
    # still pins them to Low and nothing changes for them.
    owner_is_threat = (ctx.token_review and impact_class in _DIRECT_LOSS and trigger == "privileged_role"
                       and reversibility == "irreversible")
    eff_trigger = "privileged_role_unprotected" if owner_is_threat else trigger
    code_evidenced = ctx.token_review and ctx.has_location_quote

    i = impact_level(impact_class, magnitude, reversibility)
    l = likelihood(eff_trigger, precondition)
    if owner_is_threat and l != likelihood(trigger, precondition):
        rules.append("TR1")

    # IRR1: irreversibility outweighs state rarity. A permanent loss of all funds that anyone can
    # trigger is not halved because the enabling state is uncommon (Apyee F-01, a vault brick after
    # supply returns to zero, printed Medium under I4xL1). The state counts as L2.
    if (impact_class in _IRREVERSIBLE_LOSS and reversibility == "irreversible" and magnitude == "unbounded"
            and precondition == "uncommon_protocol_state" and eff_trigger in _PERMISSIONLESS and l < 2):
        l = 2
        rules.append("IRR1")

    base = base_severity(i, l)
    sev = base

    ceilings: list[tuple[str, int]] = []   # every cap that applies, moved or not (named when the claim is above)

    def cap(rule_id: str, ceiling: str) -> None:
        """A K cap on the calibration value (never on the printed severity)."""
        nonlocal sev
        ceilings.append((rule_id, _SEV_RANK[ceiling]))
        capped = _min_sev(sev, ceiling)
        if capped != sev:
            rules.append(rule_id)
        sev = capped

    # --- K1: trigger privileged_role or upgrade_authority -> cap Medium ---
    if trigger in ("privileged_role", "upgrade_authority") and not owner_is_threat:
        cap("K1", "Medium")

    # --- K3: magnitude dust -> cap Low ---
    if magnitude == "dust":
        cap("K3", "Low")

    # --- K6: precondition victim_unusual_action -> cap Low ---
    if precondition == "victim_unusual_action":
        cap("K6", "Low")

    # --- K7: impact centralization_risk -> cap Low ---
    if impact_class == "centralization_risk":
        cap("K7", "Low")

    # --- K11: category generic and no linked lead of same category -> cap High ---
    if ctx.category_generic and not ctx.linked_lead_same_cat:
        cap("K11", "High")

    # --- K8: post_challenge/finalize: Critical stays Critical ONLY with E2/E3 AND
    # attack_steps AND no open downgrade item. Cap to High when ANY condition is missing.
    # (04 §7.4 K8: "all three required" — was previously inverted using `and` instead of `or`)
    ev = stage_evidence(phase, ctx)
    if phase in ("post_challenge", "finalize"):
        requires_k8 = sev == "Critical" and (
            ev not in ("reasoning_challenged", "analyzer_and_reasoning")
            or not ctx.has_attack_steps
            or ctx.open_downgrade_item
        )
        if requires_k8:
            cap("K8", "High")

    # --- K10: post_challenge/finalize: no contract map (lexical fallback only) -> cap High ---
    if phase in ("post_challenge", "finalize") and ctx.map_unavailable:
        cap("K10", "High")

    # --- K4: finalize: evidence reasoning_only -> cap Low ---
    if (phase == "finalize" and ctx.evidence_level == "reasoning_only" and not code_evidenced
            and not ctx.challenge_skipped):
        cap("K4", "Low")

    # --- category max_severity cap ---
    if ctx.category_max_severity is not None:
        cap(f"max_severity:{ctx.category_max_severity}", ctx.category_max_severity)

    # --- K5: a downgrade item answered present lowers the calibration one level (post_challenge,
    # finalize). A calibration note only: it never moves the printed severity (thin server, CEO 2026-10-31).
    if phase != "submit" and ctx.downgrade_items_present > 0:
        lowered = _lower_sev(sev, 1)
        if lowered != sev:
            rules.append("K5")
        sev = lowered

    computed = sev

    # --- Printed severity (thin server, CEO decision 2026-10-31, blind round 5): the reviewer's
    # claimed_severity is final, always. The matrix cell and every K cap above are a calibration the
    # report prints beside the finding when it differs; nothing here raises, lowers, caps or asks the
    # reviewer to confirm. Without a claim the matrix outcome accepted at submit prints, and a later
    # phase (a challenge, finalize) keeps it: challenge answers are evidence, never severity.
    claimed = ctx.claimed_severity if ctx.claimed_severity in _SEV_RANK else None
    if claimed is not None:
        printed, set_by = claimed, "reviewer"
        reason = (ctx.claimed_reason or "").strip() or "reviewer's severity"
    elif phase != "submit" and ctx.severity_before in _SEV_RANK:
        printed, set_by = str(ctx.severity_before), "matrix"
        reason = "matrix outcome accepted at submit"
    else:
        printed, set_by = computed, "matrix"
        reason = explain_rules(rules) if rules else "matrix cell, no reviewer proposal"

    # The calibration names the rules that moved it and, when the reviewer's claim is above it, the caps
    # that would hold the matrix there even though the cell is already under them (Magnum r5: K7).
    named = list(rules)
    if claimed is not None and _SEV_RANK[claimed] > _SEV_RANK[computed]:
        named += [rid for rid, rank in ceilings if rank < _SEV_RANK[claimed] and rid not in named]
    calibration_rule = (f"I{i}xL{l}={base}; " + explain_rules(named, limit=180)) if named else f"matrix cell I{i}xL{l}={base}"

    rule_parts = [f"I{i}xL{l}={base}"]
    if rules:
        rule_parts.append(f"caps=[{','.join(rules)}]")
    rule_parts.append(f"set_by={set_by}")
    severity_rule = " ".join(rule_parts)

    return SeverityResult(
        severity=printed,
        severity_rule=severity_rule,
        caps_applied=list(rules),
        evidence_level=ev,
        i_level=i,
        l_level=l,
        base=base,
        set_by=set_by,
        reason=reason,
        computed=computed,
        calibration=computed,
        calibration_rule=calibration_rule,
        rules=list(rules),
    )
