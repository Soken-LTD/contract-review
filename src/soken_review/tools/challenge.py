"""Handlers for review_challenge and review_answer_challenge (03 §4.12, 04 §8).

review_challenge: Stateless — computes and returns checklist items for the current
revision.  Nothing is written.

review_answer_challenge: Verifies all answers, computes verdict, and writes to
challenge_answers.  Effective columns on finding_drafts are updated here.

Challenge item types (04 §8.1):
  kill      – present withdraws the finding and locks its location ranges (8.6)
  downgrade – present feeds K5 (minus one severity level, max 2)
  context   – recorded only; no effect on verdict or severity
  basis     – basis items (MB0-MB4); fallbacks feed matrix_effective

Verdict (04 §8.3):
  any kill present -> withdrawn
  else: basis fallbacks applied; severity(post_challenge); passed

Auto checks (04 §8.5): run_auto(id) -> present|absent|unknown.  unknown means
no map data; the answer stands unchallenged.

Scope resolution (04 §8.4): entry_function without a semantic layer -> NOT_COVERED;
K10 caps the severity at High.

Design choices (fail-closed):
  - Recompute items fresh from the current revision; if the revision changed,
    the checklist_sha256 changes and we reject with E_REVISION_CONFLICT.
  - Missing answer for any item -> E_CHALLENGE_INCOMPLETE (no partial success).
  - Auto contradiction -> E_CHALLENGE_CONTRADICTS_AUTO (fail closed).
  - not_applicable: predicate must evaluate to true; unknown -> reject.
  - absent: scope lines must be in (refs ∩ job_reads); missing -> E_CHALLENGE_SCOPE.
  - present: quote-match via PinnedSource; comment-only -> E_CHALLENGE_COMMENT_ONLY.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from functools import cache
from pathlib import Path
from typing import Any

import psycopg
import psycopg_pool
import yaml
from psycopg.rows import dict_row

from ..context.store import ContextStore, is_context_path
from ..db.pool import get_pool
from ..engine.severity import SeverityContext, compute_severity
from ..engine.text_gate import CheckContext, check_text
from ..errors import ReviewError
from ..mapping.build import load_map
from ..mapping.semantic_evm import detect_token_review, units_holding
from ..pinning.quote_match import QuoteMatchError, normalize_lines, quote_match
from ..pinning.store import PinnedSource
from ..server import handler
from .context import JobContext
from .submit import _category_info, _family_from_chain


def _load_map_with_status(pin_root: Path, job_id: str) -> dict | None:
    """Load map doc and store map_status as doc['_status'] for auto checks.

    Returns None when no map exists.  Callers should catch FileNotFoundError /
    OSError / ValueError around this function.
    """
    doc, status = load_map(pin_root, job_id)
    if doc is not None:
        doc["_status"] = status
    return doc

RUBRIC_DIR = Path(__file__).resolve().parents[3] / "contract" / "rubric"

logger = logging.getLogger(__name__)

_pool: psycopg_pool.AsyncConnectionPool | None = None
_ctx: JobContext | None = None


def set_pool(pool: psycopg_pool.AsyncConnectionPool) -> None:
    global _pool
    _pool = pool


def set_context(ctx: JobContext) -> None:
    global _ctx
    _ctx = ctx


def _get_pool() -> psycopg_pool.AsyncConnectionPool:
    return _pool if _pool is not None else get_pool()


def _get_ctx() -> JobContext:
    if _ctx is None:
        from ..errors import ReviewError
        raise ReviewError("E_INTERNAL", incident="challenge not wired (ctx is None)")
    return _ctx


# ── Checklist loading ─────────────────────────────────────────────────────────

@cache
def _load_checklist_yaml(family: str) -> dict[str, Any]:
    """Load the rubric/checklists/<family>.yaml file (cached)."""
    path = RUBRIC_DIR / "checklists" / f"{family}.yaml"
    if not path.exists():
        return {"generic_items": [], "categories": {}}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _checklist_items_for_category(family: str, category: str, is_generic: bool) -> list[dict[str, Any]]:
    """Return the raw checklist items for a category (or generic_items for generic categories)."""
    data = _load_checklist_yaml(family)
    if is_generic:
        # Generic categories use the family's generic_items
        return list(data.get("generic_items", []))
    cats = data.get("categories", {})
    cat_data = cats.get(category, {})
    if isinstance(cat_data, dict) and "items" in cat_data:
        return list(cat_data["items"])
    # Category not in the checklist file — use generic items as fallback
    return list(data.get("generic_items", []))


# ── Basis items (MB0-MB4, 04 §8.2) ───────────────────────────────────────────

_MB_FUND_IMPACT = frozenset({
    "theft_of_funds", "permanent_freeze", "insolvency_or_bad_debt",
    "yield_or_fee_loss", "control_takeover",
})
_MB_REVERSIBILITY_IMPACT = frozenset({
    "permanent_freeze", "temporary_freeze", "dos_core_function",
    "control_takeover", "theft_of_funds", "insolvency_or_bad_debt",
    "yield_or_fee_loss",
})


def _basis_items(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    """Compute MB0-MB4 basis items for Medium+ findings (04 §8.2)."""
    items: list[dict[str, Any]] = []
    impact = matrix.get("impact_class", "")
    magnitude = matrix.get("magnitude", "")
    precondition = matrix.get("precondition", "")
    reversibility = matrix.get("reversibility", "")
    trigger = matrix.get("trigger", "")

    # MB0: value-transfer line exists and trigger controls it
    if impact in _MB_FUND_IMPACT:
        fallback_mb0 = (
            "unauthorized_state_change" if impact == "control_takeover"
            else "incorrect_accounting_no_fund_effect"
        )
        items.append({
            "id": "MB0", "kind": "basis",
            "condition": (
                "A quoted value-transfer, fee, mint, burn, freeze or role-write line "
                "exists whose recipient, amount or effect the trigger controls."
            ),
            "scope": "entry_function",
            "expect": "present",
            "fallback_field": "impact_class",
            "fallback_value": fallback_mb0,
            "auto": None,
            "na": [],
        })

    # MB1: magnitude unbounded — full balance at quoted line
    if magnitude == "unbounded":
        items.append({
            "id": "MB1", "kind": "basis",
            "condition": (
                "The amount moved, charged, minted or frozen at a quoted line is set "
                "by the trigger or equals the full balance of the unit."
            ),
            "scope": "entry_function",
            "expect": "present",
            "fallback_field": "magnitude",
            "fallback_value": "bounded",
            "auto": None,
            "na": [],
        })

    # MB2: precondition none/normal_operation — check blocking the trigger
    if precondition in ("none", "normal_operation"):
        items.append({
            "id": "MB2", "kind": "basis",
            "condition": (
                "A check in the entry_function scope, other than the caller guard "
                "the trigger already accounts for, blocks the trigger under normal operation."
            ),
            "scope": "entry_function",
            "expect": "absent",
            "fallback_field": "precondition",
            "fallback_value": "uncommon_protocol_state",
            "auto": None,
            "na": [],
        })

    # MB3: reversibility irreversible and impact in the reversibility set
    if reversibility == "irreversible" and impact in _MB_REVERSIBILITY_IMPACT:
        items.append({
            "id": "MB3", "kind": "basis",
            "condition": (
                "An admin function in the map can restore the affected state."
            ),
            "scope": "entry_function",
            "expect": "absent",
            "fallback_field": "reversibility",
            "fallback_value": "admin_reversible",
            "auto": "map.admin_recovery",
            "na": [],
        })

    # MB4: trigger privileged_role_unprotected — assignment function has a caller guard
    if trigger == "privileged_role_unprotected":
        items.append({
            "id": "MB4", "kind": "basis",
            "condition": (
                "The assignment function at the role_path quote has a caller guard."
            ),
            "scope": "call_site",
            "expect": "absent",
            "fallback_field": "trigger",
            "fallback_value": "privileged_role",
            "auto": None,
            "na": [],
        })

    # MB5: integration-only scope — incorrect_accounting_no_fund_effect
    # Fires when the chosen impact class is incorrect_accounting_no_fund_effect.
    # If no transaction participant (vault user, vault state) is harmed — only a
    # hypothetical third-party contract reading protocol views during a callback
    # window would see the transient inconsistency — the impact is effectively a
    # documentation/hardening note (best_practice, I0).  If a real participant IS
    # affected the item is answered present and the original class is kept.
    if impact == "incorrect_accounting_no_fund_effect":
        items.append({
            "id": "MB5", "kind": "basis",
            "condition": (
                "A participant in this transaction — a vault user, a holder, or the "
                "vault's own state — loses funds, receives wrong state, or holds a "
                "position that changes adversely (not only a third-party contract "
                "reading protocol views during a callback window)."
            ),
            "scope": "entry_function",
            "expect": "present",
            "fallback_field": "impact_class",
            "fallback_value": "best_practice",
            "auto": None,
            "na": [],
        })

    # MB6: fee-bounded magnitude — yield_or_fee_loss bounded
    # Fires when the chosen impact is yield_or_fee_loss with bounded magnitude.
    # If a protocol fee, Chainlink deviation threshold, or equivalent spread is
    # the hard ceiling on per-cycle gain (the exploit is net-negative unless the
    # oracle lag clears that quoted threshold), the effective exposure is dust-
    # level: profit only materialises during an intermittent market condition and
    # is bounded above by the threshold minus the fee.  The model must quote the
    # specific fee or threshold line AND the line that prevents repetition inside one
    # price window; a per-cycle ceiling alone does not bound the total extracted from
    # holders.  If either is missing the item is absent and bounded magnitude is kept.
    if impact == "yield_or_fee_loss" and magnitude == "bounded":
        items.append({
            "id": "MB6", "kind": "basis",
            "condition": (
                "A protocol fee, documented deviation threshold, or equivalent spread "
                "at a quoted line is the hard ceiling on per-cycle gain, AND a quoted "
                "line stops the cycle from being repeated inside the same price window "
                "(a cooldown that cannot be bypassed, a per-block or per-account cap, or "
                "a price update forced by the trade itself). Quote both lines; a fee "
                "ceiling alone does not bound the total, since repeated cycles add up."
            ),
            "scope": "entry_function",
            "expect": "absent",
            "fallback_field": "magnitude",
            "fallback_value": "dust",
            "auto": None,
            "na": [],
        })

    return items


def basis_fallback(raw_item: dict[str, Any], value: str, *, scope_not_covered: bool,
                   quote_verified: bool) -> dict[str, Any] | None:
    """The matrix_effective fallback a basis answer triggers, or None (04 8.2, 8.3).

    A basis item carries `expect`; an answer that differs from it moves `fallback_field` to
    `fallback_value`. Before 2026-10-26 a `present` answer on a NOT_COVERED scope was also forced
    into the fallback, whatever evidence it carried: on the Solana blind run (ata_owner_reassign,
    location in an Accounts struct that no function span covers) MB0 and MB1 were answered present
    with quotes matched to the pinned source, the forced fallbacks turned permanent_freeze unbounded
    into incorrect_accounting bounded, and a computed Critical printed as Low with no cap named.

    The scope cap for an unresolved scope is K10 (High), applied by compute_severity; a present
    answer whose quote matched the pinned source is evidence and keeps the reviewer's matrix. Only
    a present answer without a verified quote still falls back (it is also rejected as incomplete).
    """
    if raw_item.get("kind") != "basis" or value not in ("present", "absent"):
        return None
    expect = raw_item.get("expect", "")
    unverified_present = scope_not_covered and value == "present" and not quote_verified
    if not unverified_present and value == expect:
        return None
    return {
        "item": raw_item.get("id", ""),
        "field": raw_item["fallback_field"],
        "value": raw_item["fallback_value"],
        "why": "present_without_verified_quote" if unverified_present else "answer_differs_from_expected",
    }


def fallback_labels(fallbacks: list[dict[str, Any]]) -> list[str]:
    """`MB1:magnitude=bounded` style names: the cause of every matrix change a verdict reports."""
    return [f"{fb['item']}:{fb['field']}={fb['value']}" for fb in fallbacks]


# ── Auto check registry (04 §8.5) ─────────────────────────────────────────────

# Maps auto_id -> (applies_when function, disproof_result)
# applies_when(category, map_doc, location_quotes) -> bool
# disproof_result: "present" means kill, "absent" means downgrade
_AUTO_REGISTRY: dict[str, tuple[Any, str]] = {}


def _reg(auto_id: str, disproof: str):
    """Decorator to register an auto check."""
    def dec(fn):
        _AUTO_REGISTRY[auto_id] = (fn, disproof)
        return fn
    return dec


# Function kinds that are externally/autonomously invocable (not reachable via normal
# BFS from public entry points).  If the location is inside one of these, we cannot
# prove unreachability via BFS alone → return 'unknown'.
_EXTERNALLY_INVOCABLE_KINDS: frozenset[str] = frozenset({
    "modifier", "constructor", "fallback", "receive", "fallback_payable",
})

# Call kinds whose targets are BFS-traversable.  All others are skipped; if a skipped
# call's target resolves to a known function we conservatively return 'unknown' (we may
# be missing a reachability edge).
_TRAVERSABLE_CALL_KINDS: frozenset[str] = frozenset({
    "internal",     # internal function call (same contract)
    "modifier",     # modifier invocation — body is inlined at _;
    "delegate",     # delegatecall to an internal helper (same-contract pattern)
})


def _callee_names(span_id: str, span: dict | None) -> set[str]:
    """Every name a call edge may use for the function behind `span_id`.

    Map span ids come in two shapes: `path:Contract:name@suffix` (lexical layer) and
    `Contract.name(type,...)` (semantic layer, solc AST). Call targets are bare names (`_claim`),
    sometimes qualified (`Lib.mulDiv`) and sometimes the span's own `name` field. Index all of them.
    """
    names: set[str] = {span_id}
    if span and span.get("name"):
        names.add(str(span["name"]))
    head = span_id.split("(", 1)[0]                 # drop the parameter list
    head = head.split("@", 1)[0]                     # drop override / inherited suffix
    last_colon = head.rsplit(":", 1)[-1]             # lexical: path:Contract:name -> name
    names.add(last_colon)
    if "." in last_colon:
        names.add(last_colon.rsplit(".", 1)[-1])     # semantic: Contract.name -> name
        names.add(last_colon)                        # keep Contract.name for qualified calls
    return {n for n in names if n}


@_reg("map.unreachable", "present")


def _auto_unreachable(category: str, map_doc: dict | None, location_quotes: list) -> str:
    """Return 'present' when the map PROVES no entry path reaches the quoted location.

    Strict proof requirements (all must hold):
    1. Semantic layer is present and map_status == 'full'.
    2. The location is inside at least one modelled function span.
    3. None of those covering functions has an externally-invocable kind
       (modifier, constructor, fallback, receive …) — those are autonomously invoked
       and reachability cannot be determined via call-graph BFS alone.
    4. BFS from all is_entry functions over traversable call kinds (internal, modifier,
       delegate) does not reach any covering function.
    5. No untraversable call in the BFS frontier resolves to a function in the map
       (which would indicate a potentially missing edge).

    Every other case returns 'unknown' (fail-closed).
    """
    if map_doc is None or map_doc.get("semantic") is None:
        return "unknown"

    map_status = map_doc.get("_status")  # stored by _load_map_with_status callers
    functions: list[dict] = map_doc.get("semantic", {}).get("functions", [])
    spans: list[dict] = map_doc.get("spans", [])

    if not location_quotes or not functions:
        return "unknown"

    loc = location_quotes[0]
    loc_path = loc.get("file", "")
    loc_start = loc.get("start", 0)
    loc_end = loc.get("end", loc_start)
    if not loc_path or loc_start <= 0:
        return "unknown"

    # Build span lookup: span_id -> {file, start, end, kind}
    span_meta: dict[str, dict[str, Any]] = {}
    for sp in spans:
        sid = sp.get("id", "")
        if sid and "file" in sp and "start" in sp and "end" in sp:
            span_meta[sid] = sp

    # Build function-by-name lookup.  Name = last colon-delimited segment of span_id,
    # before any "@" (override/inherited suffix).
    fn_by_name: dict[str, list[dict]] = {}
    fn_by_span: dict[str, dict] = {}
    for fn in functions:
        sid = fn.get("span", "")
        if not sid:
            continue
        fn_by_span[sid] = fn
        for name in _callee_names(sid, span_meta.get(sid)):
            fn_by_name.setdefault(name, []).append(fn)

    def _span_overlaps_loc(sid: str) -> bool:
        sp = span_meta.get(sid)
        if sp is None:
            return False
        return (sp.get("file") == loc_path
                and not (sp.get("end", 0) < loc_start or sp.get("start", 0) > loc_end))

    # ── Rule 2: location must be inside at least one modelled function ────────
    covering_fns = [fn for fn in functions if _span_overlaps_loc(fn.get("span", ""))]
    if not covering_fns:
        # Location is outside all modelled function spans (state vars, contract-level code,
        # inline assembly the analyzer did not attribute to a function, etc.).
        # Absence of coverage is NOT proof of unreachability.
        return "unknown"

    # ── Rule 3: location directly inside an externally-invocable function ───────
    # Constructor, modifier, fallback, receive, fallback_payable are autonomously
    # invoked by the EVM/runtime — they are BFS roots. A location DIRECTLY inside
    # such a function is unambiguously reachable: return "absent" immediately.
    # (Old behaviour returned "unknown" here, but that was overly conservative once
    # we made externally-invocable functions BFS roots.)
    for fn in covering_fns:
        sp_kind = span_meta.get(fn.get("span", ""), {}).get("kind", "function")
        if sp_kind in _EXTERNALLY_INVOCABLE_KINDS:
            return "absent"

    # ── Rule 1 (partial): map must be full for a 'present' verdict ────────────
    # (checked again at the end, after BFS)

    # ── Check if location is directly inside any entry function's span ────────
    for fn in covering_fns:
        if fn.get("is_entry"):
            return "absent"

    # ── BFS from all entry functions AND externally-invocable functions ───────
    # Constructor, modifier, fallback, receive are autonomously invoked by the EVM;
    # any function reachable ONLY from them is still reachable (not unreachable).
    # They must be BFS roots, not merely "exclusions" from the covering-fn guard.
    visited: set[str] = set()
    queue: list[dict] = []
    for fn in functions:
        sp_kind = span_meta.get(fn.get("span", ""), {}).get("kind", "function")
        if fn.get("is_entry") or sp_kind in _EXTERNALLY_INVOCABLE_KINDS:
            sid = fn.get("span", "")
            if sid and sid not in visited:
                visited.add(sid)
                queue.append(fn)

    head = 0
    while head < len(queue):
        fn = queue[head]
        head += 1
        for call in fn.get("calls", []):
            call_kind = call.get("kind", "")
            target_name = call.get("target", "")
            if not target_name:
                continue
            callees = fn_by_name.get(target_name, [])
            if call_kind in _TRAVERSABLE_CALL_KINDS:
                if not callees:
                    # An internal call whose target is not a modelled function (library,
                    # inherited helper the map did not attribute, a name this resolver does
                    # not know): the edge may lead to the location. Never claim proof here.
                    # 2026-10-22: every `_claim` edge was dropped this way because span ids
                    # (`C._claim(bytes)`) never matched the bare call target `_claim`, so an
                    # externally reachable internal function was "proven" unreachable and the
                    # auto kill removed true findings.
                    return "unknown"
                for callee in callees:
                    callee_sid = callee.get("span", "")
                    if not callee_sid or callee_sid in visited:
                        continue
                    visited.add(callee_sid)
                    if _span_overlaps_loc(callee_sid):
                        return "absent"
                    queue.append(callee)
            elif callees:
                # ── Rule 5: untraversable call that resolves to a known function ──
                # We may be missing a reachability edge (e.g. an external self-call
                # to a function that contains the location).  Fail-closed.
                return "unknown"

    # BFS complete — no path to location found.
    # Return 'present' only when map is full (complete parse proof); partial maps may
    # be missing edges that would connect an entry to the location.
    if map_status == "full":
        return "present"
    return "unknown"


@_reg("map.modifiers_and_bases", "present")
def _auto_modifiers_bases(category: str, map_doc: dict | None, location_quotes: list) -> str:
    """category evm.reentrancy or cairo.reentrancy; entry makes an external/value call."""
    if category not in ("evm.reentrancy", "cairo.reentrancy"):
        return "unknown"
    if map_doc is None or map_doc.get("semantic") is None:
        return "unknown"
    # For W0: return unknown (full guard check requires detailed map traversal)
    return "unknown"


@_reg("map.admin_recovery", "absent")
def _auto_admin_recovery(category: str, map_doc: dict | None, location_quotes: list) -> str:
    """A role-guarded function writes the frozen state. absent when NOT present."""
    if map_doc is None or map_doc.get("semantic") is None:
        return "unknown"
    return "unknown"


def _run_auto(auto_id: str, category: str, map_doc: dict | None, location_quotes: list) -> str:
    """Run an auto check. Returns present|absent|unknown."""
    if auto_id not in _AUTO_REGISTRY:
        return "unknown"
    fn, _ = _AUTO_REGISTRY[auto_id]
    try:
        result = fn(category, map_doc, location_quotes)
    except Exception as exc:  # noqa: BLE001
        logger.warning("auto check %s raised %r — returning unknown", auto_id, exc)
        return "unknown"
    return result if result in ("present", "absent") else "unknown"


# ── Scope resolution (04 §8.4) ───────────────────────────────────────────────

_RANGE_REF_RE = re.compile(r"^(.+):(\d+)-(\d+)$")


def _resolve_scope(
    scope_name: str,
    family: str,
    map_doc: dict | None,
    location_quotes: list[dict[str, Any]],
) -> tuple[list[str], bool, str]:
    """Resolve a scope to (ranges, not_covered, source).

    ranges: list of "path:start-end" strings.
    not_covered: True when scope cannot be resolved.
    source: 'semantic' | 'lexical' | 'not_covered' — explicit provenance of the ranges.

    The source flag MUST be propagated to callers that apply security effects (kill sweep,
    dismiss): a lexical span must never count as covered for kill/dismiss effects.  Only
    source='semantic' (BFS-resolved from the semantic layer) qualifies.
    """
    if map_doc is None or map_doc.get("semantic") is None:
        # Without a semantic layer, only entry_function can be approximated from the lexical span
        if scope_name == "entry_function" and location_quotes:
            # Use the lexical span of the first location quote as a display fallback only.
            # Source is 'lexical' — callers must NOT use this for security effects.
            loc = location_quotes[0]
            path = loc.get("file", "")
            start = loc.get("start", 0)
            end = loc.get("end", 0)
            if path and start > 0 and end >= start and (end - start + 1) <= 400:
                return [f"{path}:{start}-{end}"], False, "lexical"
        return [], True, "not_covered"

    # Semantic layer available
    if scope_name == "entry_function":
        ranges, nc = _resolve_entry_function_scope(family, map_doc, location_quotes)
        return ranges, nc, "not_covered" if nc else "semantic"
    elif scope_name == "call_site":
        ranges, nc = _resolve_call_site_scope(location_quotes)
        # call_site uses location quote directly (no BFS), so always lexical
        return ranges, nc, "not_covered" if nc else "lexical"
    elif scope_name in ("shared_state_writers", "account_struct", "handler", "module"):
        # W0: not implemented without full map traversal
        return [], True, "not_covered"
    return [], True, "not_covered"


_SCOPE_LINE_CAP = 400       # scopes.yaml: above this the item is NOT_COVERED
_SCOPE_CALL_DEPTH = 2       # scopes.yaml evm/solana/move/cairo: callees (and callers) to depth 2


def _resolve_entry_function_scope(
    family: str,
    map_doc: dict,
    location_quotes: list[dict[str, Any]],
) -> tuple[list[str], bool]:
    """Resolve entry_function scope (scopes.yaml): the functions holding the location, the entry
    functions that reach them, their modifiers, and internal callees to call-graph depth 2.

    When the location sits in an internal function the evidence for reachability (L1) and for
    the guards lives in the external caller, not in the internal body. Until 2026-10-22 the
    scope was the location's own function only, so every quote from the caller was rejected
    with E_CHALLENGE_SCOPE (65 rejections on one review). Callers are found by walking the
    internal call edges backwards up to depth 2 from the location's functions; every function on
    those paths is in scope, whether or not it is itself an entry.

    Line cap: the location functions, their callers and the modifiers are mandatory; above
    `_SCOPE_LINE_CAP` lines the scope is NOT_COVERED. Callees are added only while the cap holds.
    """
    if not location_quotes:
        return [], True
    loc = location_quotes[0]
    loc_path = loc.get("file", "")
    loc_start = loc.get("start", 0)
    loc_end = loc.get("end", 0)

    # spans[] carries file/start/end/kind; semantic.functions[].span references spans[].id.
    spans = map_doc.get("spans", []) or []
    span_meta: dict[str, dict[str, Any]] = {sp["id"]: sp for sp in spans if sp.get("id")}
    functions = (map_doc.get("semantic") or {}).get("functions", []) or []
    fn_by_span, fn_by_name = _function_indexes(functions, span_meta)
    callers = _caller_index(functions, fn_by_name)

    def overlaps(sid: str) -> bool:
        sp = span_meta.get(sid)
        return bool(sp) and sp.get("file") == loc_path \
            and not (sp.get("end", 0) < loc_start or sp.get("start", 0) > loc_end)

    covering = [sid for sid in fn_by_span if overlaps(sid)]
    if not covering:
        return [], True

    ordered: list[str] = []
    seen: set[str] = set()

    def add(sid: str) -> None:
        if sid not in seen and sid in span_meta:
            seen.add(sid)
            ordered.append(sid)

    for sid in covering:
        add(sid)
    # callers: reverse BFS over internal edges, depth-limited
    frontier = list(covering)
    for _ in range(_SCOPE_CALL_DEPTH):
        nxt: list[str] = []
        for sid in frontier:
            for caller in sorted(callers.get(sid, ())):
                if caller not in seen:
                    add(caller)
                    nxt.append(caller)
        frontier = nxt
    # modifiers of every function collected so far (modifier spans are not in functions[]; a
    # modifier is usually inherited, so the name is matched across units)
    mod_by_name = _modifier_spans(spans)
    collected = ordered[:]          # snapshot: add() appends while this loop runs
    for sid in collected:
        for mname in (fn_by_span.get(sid) or {}).get("modifiers", []) or []:
            for msid in mod_by_name.get(mname, ()):
                add(msid)

    def total(sids: list[str]) -> int:
        return sum(span_meta[s].get("end", 0) - span_meta[s].get("start", 0) + 1 for s in sids)

    if total(ordered) > _SCOPE_LINE_CAP:
        return [], True

    # callees depth 2 from the location functions, same unit only, while the cap holds.
    # `using X for` library helpers and base-contract helpers arrive as `internal` edges too;
    # pulling SafeMath into every scope would only grow the read requirement of an `absent`
    # answer without holding evidence for the item, so callees stay inside the unit.
    frontier = list(covering)
    for _ in range(_SCOPE_CALL_DEPTH):
        nxt = []
        for sid in frontier:
            unit = _span_unit(span_meta.get(sid) or {}, sid)
            for call in (fn_by_span.get(sid) or {}).get("calls", []) or []:
                if call.get("kind") not in _TRAVERSABLE_CALL_KINDS:
                    continue
                for callee in fn_by_name.get(call.get("target", ""), []):
                    csid = callee.get("span", "")
                    if not csid or csid in seen or _span_unit(span_meta.get(csid) or {}, csid) != unit:
                        continue
                    if total(ordered + [csid]) > _SCOPE_LINE_CAP:
                        continue
                    add(csid)
                    nxt.append(csid)
        frontier = nxt

    ranges = sorted(
        (f"{span_meta[s]['file']}:{span_meta[s]['start']}-{span_meta[s]['end']}" for s in ordered),
        key=lambda r: (_parse_range_ref(r) or ("", 0, 0))[:2],
    )
    return ranges, False


def _function_indexes(functions: list[dict], span_meta: dict[str, dict[str, Any]]
                      ) -> tuple[dict[str, dict], dict[str, list[dict]]]:
    """(span id -> function, callee name -> functions) for call-edge resolution.

    Names come from `_callee_names`, so both span-id shapes resolve bare, qualified and
    `name`-field call targets."""
    fn_by_span: dict[str, dict] = {}
    fn_by_name: dict[str, list[dict]] = {}
    for fn in functions:
        sid = fn.get("span", "")
        if not sid:
            continue
        fn_by_span[sid] = fn
        for name in _callee_names(sid, span_meta.get(sid)):
            fn_by_name.setdefault(name, []).append(fn)
    return fn_by_span, fn_by_name


def _caller_index(functions: list[dict], fn_by_name: dict[str, list[dict]]) -> dict[str, set[str]]:
    """callee span id -> span ids of functions that call it over a traversable edge."""
    callers: dict[str, set[str]] = {}
    for fn in functions:
        sid = fn.get("span", "")
        for call in fn.get("calls", []) or []:
            if call.get("kind") not in _TRAVERSABLE_CALL_KINDS:
                continue
            for callee in fn_by_name.get(call.get("target", ""), []):
                csid = callee.get("span", "")
                if csid and sid and csid != sid:
                    callers.setdefault(csid, set()).add(sid)
    return callers


def _span_unit(span: dict[str, Any], sid: str) -> str:
    """The unit (contract) a span belongs to: the span's `unit` field, else the `Contract.` prefix
    of a semantic id, else the `path:Contract` prefix of a lexical id."""
    if span.get("unit"):
        return str(span["unit"])
    head = sid.split("(", 1)[0]
    if ":" in head:
        return head.rsplit(":", 1)[0]
    return head.rsplit(".", 1)[0] if "." in head else head


def _modifier_spans(spans: list[dict]) -> dict[str, list[str]]:
    """modifier name -> span ids (modifier bodies are spans of kind `modifier`, not functions)."""
    out: dict[str, list[str]] = {}
    for sp in spans:
        if sp.get("kind") != "modifier" or not sp.get("id"):
            continue
        for name in _callee_names(sp["id"], sp):
            out.setdefault(name, []).append(sp["id"])
    return out


def _resolve_call_site_scope(location_quotes: list[dict[str, Any]]) -> tuple[list[str], bool]:
    """call_site: statement line plus enclosing function signature line."""
    if not location_quotes:
        return [], True
    loc = location_quotes[0]
    path = loc.get("file", "")
    start = loc.get("start", 0)
    end = loc.get("end", 0)
    if not path or start <= 0:
        return [], True
    return [f"{path}:{start}-{end}"], False


# ── Build challenge items output ──────────────────────────────────────────────

def _item_to_output(
    item: dict[str, Any],
    family: str,
    map_doc: dict | None,
    location_quotes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Convert an internal item dict to the output shape (03 §4.12 output schema)."""
    scope_name = item.get("scope", "entry_function")
    ranges, not_covered, source = _resolve_scope(scope_name, family, map_doc, location_quotes)

    scope_obj: dict[str, Any] = {"name": scope_name, "ranges": ranges, "source": source}
    if not_covered:
        scope_obj["not_covered"] = True

    out: dict[str, Any] = {
        "id": item["id"],
        "kind": item["kind"],
        "question": item.get("condition", item.get("question", "")),
        "answer_type": "present_absent",
        "scope": scope_obj,
        "allowed_na_reasons": list(item.get("na", [])),
        "auto": item.get("auto"),
    }
    return out


def compute_challenge_items(
    family: str,
    category: str,
    matrix: dict[str, Any],
    map_doc: dict | None,
    location_quotes: list[dict[str, Any]],
    is_generic: bool,
) -> tuple[list[dict[str, Any]], str]:
    """Compute all challenge items and return (items, checklist_sha256).

    Items = checklist items + basis items + auto-triggered AX items (04 §8).
    The sha256 is over the canonical JSON of the items list.
    """
    # 1. Category-specific checklist items
    raw_items = _checklist_items_for_category(family, category, is_generic)

    # 2. Basis items (always for Medium+)
    raw_items = raw_items + _basis_items(matrix)

    # 3. Auto items (AX-<id>) — added when auto check fires in disproof direction (04 §8.6)
    for auto_id, (_, disproof_result) in _AUTO_REGISTRY.items():
        # Check if the auto check applies and fires
        result = _run_auto(auto_id, category, map_doc, location_quotes)
        if result == disproof_result:
            # Check if this auto is already in the checklist (avoid duplicates)
            already_present = any(
                item.get("auto") == auto_id for item in raw_items
            )
            if not already_present:
                ax_item: dict[str, Any] = {
                    "id": f"AX-{auto_id.replace('.', '-')}",
                    "kind": "kill" if disproof_result == "present" else "downgrade",
                    "condition": f"Auto-check {auto_id} result: {disproof_result}.",
                    "scope": "entry_function",
                    "auto": auto_id,
                    "na": [],
                }
                raw_items = raw_items + [ax_item]

    # Build output items
    out_items = [
        _item_to_output(item, family, map_doc, location_quotes)
        for item in raw_items
    ]

    # Compute sha256 over canonical JSON
    sha256 = hashlib.sha256(
        json.dumps(out_items, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()

    return out_items, sha256


# ── State check helper ────────────────────────────────────────────────────────

def _check_job_state_for_write(state: str) -> dict[str, Any] | None:
    """Return an error dict if the job state blocks write tools (03 §3.5)."""
    if state in ("finalized", "render_queued", "rendering", "rendered", "render_failed"):
        return {"accepted": False, "errors": [ReviewError("E_JOB_FROZEN").envelope()]}
    if state in ("insufficient_source", "failed"):
        return {"accepted": False, "errors": [
            ReviewError("E_JOB_TERMINAL", state=state, exit_code="").envelope()
        ]}
    if state == "expired":
        raise ReviewError("E_JOB_EXPIRED", job=state, date="")
    if state == "deleted":
        raise ReviewError("E_JOB_NOT_FOUND")
    if state != "ready":
        return {"accepted": False, "errors": [
            ReviewError("E_JOB_NOT_READY", state=state, eta_s=0).envelope()
        ]}
    return None


# ── review_challenge handler ──────────────────────────────────────────────────

@handler("review_challenge")
async def handle_review_challenge(args: dict[str, Any]) -> dict[str, Any]:
    """Compute and return challenge items for a needs_challenge finding (03 §4.12).

    Stateless: nothing is written.  The model uses the returned items and
    checklist_sha256 to answer with review_answer_challenge.
    """
    job_id: str = args["job_id"]
    draft_key: str = args["draft_key"]
    pool = _get_pool()

    async with pool.connection() as conn:
        # Lock-free reads: challenge is read-only
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from jobs where job_id = %s", (job_id,))
            job = await cur.fetchone()

        if job is None:
            raise ReviewError("E_JOB_NOT_FOUND")

        state = job["state"]
        # review_challenge is a read tool for state check purposes (03 §3.5 table: same as Read tools 4-8)
        if state in ("insufficient_source", "failed"):
            return {"accepted": False, "errors": [
                ReviewError("E_JOB_TERMINAL", state=state, exit_code=job.get("error_code", "")).envelope()
            ]}
        if state == "expired":
            raise ReviewError("E_JOB_EXPIRED", job=job_id, date="")
        if state == "deleted":
            raise ReviewError("E_JOB_NOT_FOUND")
        if state not in ("ready",):
            return {"accepted": False, "errors": [
                ReviewError("E_JOB_NOT_READY", state=state, eta_s=0).envelope()
            ]}

        # Load draft
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from finding_drafts where job_id = %s and draft_key = %s",
                (job_id, draft_key),
            )
            draft = await cur.fetchone()

        if draft is None:
            return {"accepted": False, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=draft_key).envelope()
            ]}

        if draft["status"] != "needs_challenge":
            return {"accepted": False, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=draft_key).envelope()
            ]}

        revision = draft["current_revision"]

        # Load current revision
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from finding_revisions where job_id = %s and draft_key = %s and revision = %s",
                (job_id, draft_key, revision),
            )
            rev = await cur.fetchone()

        if rev is None:
            raise ReviewError("E_INTERNAL", incident=f"revision_missing:{draft_key}:{revision}")

        # Load location quotes
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from finding_quote_ranges where job_id = %s and draft_key = %s "
                "and revision = %s and role = 'location' order by ord",
                (job_id, draft_key, revision),
            )
            quote_rows = await cur.fetchall()

        location_quotes = [
            {"file": r["path"], "start": r["start_line"], "end": r["end_line"]}
            for r in quote_rows
        ]

    # Load map (may be absent); store map_status for auto checks
    try:
        pin_root = _get_ctx().get_pin_root()
        map_doc = _load_map_with_status(pin_root, job_id)
    except FileNotFoundError:
        map_doc = None
    except (OSError, ValueError):
        map_doc = None

    family = _family_from_chain(job.get("chain"))
    category = rev["category"]
    cat_info = _category_info(category) or {}
    is_generic = bool(cat_info.get("generic", False))

    # Parse matrix from stored content
    content = rev.get("content") or {}
    matrix = content.get("matrix") or {}
    if isinstance(matrix, str):
        try:
            matrix = json.loads(matrix)
        except (ValueError, TypeError):
            matrix = {}

    items, sha256 = compute_challenge_items(
        family, category, matrix, map_doc, location_quotes, is_generic
    )

    return {
        "accepted": True,
        "draft_key": draft_key,
        "revision": revision,
        "checklist_sha256": sha256,
        "items": items,
    }


# ── review_answer_challenge handler ──────────────────────────────────────────

def _parse_range_ref(ref: str) -> tuple[str, int, int] | None:
    """Parse 'path:start-end' into (path, start, end). Returns None on failure."""
    m = _RANGE_REF_RE.match(ref)
    if not m:
        return None
    path = m.group(1)
    try:
        start = int(m.group(2))
        end = int(m.group(3))
    except ValueError:
        return None
    if start <= 0 or end < start:
        return None
    return path, start, end


def _quote_in_scope_ranges(q_file: str, q_start: int, q_end: int, scope_ranges: list[str]) -> bool:
    """Return True when the quote overlaps at least one scope range.

    Used to enforce that a 'present' answer's quoted evidence lies within the
    scope the item was issued for (04 §8.3: evidence must bound the claim).
    """
    for ref in scope_ranges:
        parsed = _parse_range_ref(ref)
        if parsed is None:
            continue
        r_path, r_start, r_end = parsed
        if r_path == q_file and not (q_end < r_start or q_start > r_end):
            return True
    return False


def _ranges_cover(
    scope_ranges: list[str],
    answer_refs: list[str],
    job_reads_index: dict[str, list[tuple[int, int]]],  # path -> [(start, end)]
) -> list[str]:
    """Return scope range_refs that are NOT covered by (answer_refs ∩ job_reads).

    A scope range is 'covered' when its [start, end] interval is a subset of the
    union of answer ref ranges that overlap with job_reads entries for that path.
    """
    missing: list[str] = []

    # Build valid ref coverage: only refs that have a job_reads overlap
    valid_coverage: dict[str, list[tuple[int, int]]] = {}
    for ref in answer_refs:
        parsed = _parse_range_ref(ref)
        if parsed is None:
            continue
        path, start, end = parsed
        reads = job_reads_index.get(path, [])
        # Check if any job_reads entry overlaps this ref
        overlaps = any(
            not (rs > end or re < start)
            for rs, re in reads
        )
        if overlaps:
            valid_coverage.setdefault(path, []).append((start, end))

    # Check each scope range is covered
    for scope_ref in scope_ranges:
        parsed = _parse_range_ref(scope_ref)
        if parsed is None:
            missing.append(scope_ref)
            continue
        path, s_start, s_end = parsed
        valid = valid_coverage.get(path, [])
        # Every line in [s_start, s_end] must be within some valid ref range
        # Simplified: check if any valid range fully contains the scope range
        covered = any(
            vs <= s_start and ve >= s_end
            for vs, ve in valid
        )
        if not covered:
            missing.append(scope_ref)

    return missing


def _is_comment_only(quote_text: str, pin: PinnedSource, path: str, start: int, end: int) -> bool:
    """Return True when the quote references only comment lines (E_CHALLENGE_COMMENT_ONLY, 04 5.2)."""
    # A simple heuristic: if every non-empty normalized line starts with // or # or /* or *
    lines = normalize_lines(quote_text)
    if not lines:
        return True
    comment_patterns = ("//", "#", "/*", "*/", " *", "(*", "*)")
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        is_comment = any(stripped.startswith(p) for p in comment_patterns)
        if not is_comment:
            return False
    return True


@handler("review_answer_challenge")
async def handle_review_answer_challenge(args: dict[str, Any]) -> dict[str, Any]:
    """Answer a challenge, verify each item, compute verdict (03 §4.12, 04 §8.3)."""
    job_id: str = args["job_id"]
    draft_key: str = args["draft_key"]
    revision: int = args["revision"]
    answers: list[dict[str, Any]] = args["answers"]

    pool = _get_pool()

    async with pool.connection() as conn, conn.transaction():
        # Lock job row
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from jobs where job_id = %s for update", (job_id,))
            job = await cur.fetchone()

        if job is None:
            raise ReviewError("E_JOB_NOT_FOUND")

        state = job["state"]
        err = _check_job_state_for_write(state)
        if err is not None:
            return err

        # Load draft
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from finding_drafts where job_id = %s and draft_key = %s",
                (job_id, draft_key),
            )
            draft = await cur.fetchone()

        if draft is None:
            return {"accepted": False, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=draft_key).envelope()
            ]}

        current_revision = draft["current_revision"]

        # Idempotency check FIRST (before status check): must work even if status changed to
        # 'accepted' after the first successful call (03 §10 idempotency table).
        answers_hash = hashlib.sha256(
            json.dumps(answers, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()

        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from challenge_answers where job_id = %s and draft_key = %s and revision = %s",
                (job_id, draft_key, revision),
            )
            existing_ca = await cur.fetchone()

        if existing_ca is not None:
            if existing_ca["answers_hash"] == answers_hash:
                # Idempotent replay: return stored verdict regardless of current status
                return {
                    "accepted": True,
                    "draft_key": draft_key,
                    "verdict": existing_ca["verdict"],
                    "severity_before": existing_ca["severity_before"],
                    "severity_after": existing_ca.get("severity_after"),
                    "status": draft["status"],
                    "evidence_level": draft.get("evidence_level", "reasoning_only"),
                    "kill_item": draft.get("kill_item"),
                    "leads_reopened": [],
                    "caps_applied": list(draft.get("caps_applied") or []),
                }
            # Different answers for same revision = reject (revision already answered)
            return {"accepted": False, "errors": [
                ReviewError("E_REVISION_CONFLICT", revision=current_revision).envelope()
            ]}

        if draft["status"] != "needs_challenge":
            return {"accepted": False, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=draft_key).envelope()
            ]}

        # Revision check
        if revision != current_revision:
            return {"accepted": False, "errors": [
                ReviewError("E_REVISION_CONFLICT", revision=current_revision).envelope()
            ]}

        # Load current revision
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from finding_revisions where job_id = %s and draft_key = %s and revision = %s",
                (job_id, draft_key, revision),
            )
            rev = await cur.fetchone()

        if rev is None:
            raise ReviewError("E_INTERNAL", incident=f"revision_missing:{draft_key}:{revision}")

        # Load location quotes
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from finding_quote_ranges where job_id = %s and draft_key = %s "
                "and revision = %s and role = 'location' order by ord",
                (job_id, draft_key, revision),
            )
            quote_rows = await cur.fetchall()

        location_quotes = [
            {"file": r["path"], "start": r["start_line"], "end": r["end_line"]}
            for r in quote_rows
        ]

    # Load map and pin outside the transaction for the checks; store map_status for auto checks
    try:
        pin_root = _get_ctx().get_pin_root()
        map_doc = _load_map_with_status(pin_root, job_id)
    except FileNotFoundError:
        map_doc = None  # map worker not run yet; degrade gracefully
    except (OSError, ValueError) as exc:
        raise ReviewError("E_INTERNAL", incident=f"map load failed (corrupt/unreadable): {exc}") from exc

    try:
        pin = PinnedSource.load(pin_root, job_id)
    except (FileNotFoundError, OSError, ValueError):
        raise ReviewError("E_JOB_NOT_READY", state="pin_not_found", eta_s=60)
    context_store = ContextStore.load(pin_root, job_id)   # context ingestion spec 4: context/ quotes

    family = _family_from_chain(job.get("chain"))
    category = rev["category"]
    cat_info = _category_info(category) or {}
    is_generic = bool(cat_info.get("generic", False))

    # Parse matrix
    content = rev.get("content") or {}
    matrix = content.get("matrix") or {}
    if isinstance(matrix, str):
        try:
            matrix = json.loads(matrix)
        except (ValueError, TypeError):
            matrix = {}

    # Recompute items (same function as review_challenge)
    items, checklist_sha256 = compute_challenge_items(
        family, category, matrix, map_doc, location_quotes, is_generic
    )

    # Build answers index by item_id
    answers_by_id: dict[str, dict[str, Any]] = {a["item_id"]: a for a in answers}

    # Check all items are answered
    all_item_ids = [item["id"] for item in items]
    missing_ids = [iid for iid in all_item_ids if iid not in answers_by_id]
    if missing_ids:
        return {"accepted": False, "errors": [
            ReviewError("E_CHALLENGE_INCOMPLETE", ids=", ".join(missing_ids)).envelope()
        ]}

    # Load job_reads for absent scope coverage check
    async with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "select path, start_line, end_line from job_reads where job_id = %s",
            (job_id,),
        )
        reads_rows = await cur.fetchall()

    job_reads_index: dict[str, list[tuple[int, int]]] = {}
    for r in reads_rows:
        job_reads_index.setdefault(r["path"], []).append((r["start_line"], r["end_line"]))

    # Validate each answer
    violations: list[dict[str, Any]] = []
    kill_present: str | None = None       # item_id of the first kill answered present
    downgrade_count = 0
    basis_fallbacks: list[dict[str, Any]] = []  # for matrix_effective updates
    scope_not_covered = False             # for K10

    # Build internal items map for looking up fallback info
    raw_items_by_id: dict[str, dict[str, Any]] = {}
    for item in _checklist_items_for_category(family, category, is_generic) + _basis_items(matrix):
        raw_items_by_id[item["id"]] = item

    for output_item in items:
        item_id = output_item["id"]
        answer = answers_by_id[item_id]
        value = answer.get("value") or ""
        note = answer.get("note") or ""

        # Note gate: the answer note is stored with the challenge record and never rendered, so
        # only the `note` scope (control characters, scripts) applies. The prose rules T1-T31
        # and the number provenance check are report-text rules; on notes they only cost
        # attempts ("Number two in note has no source", 2026-10-22).
        for v in check_text(note, "note", CheckContext(field=f"answer.{item_id}.note")):
            violations.append(ReviewError(
                v.code, rule=v.rule_id,
                match=v.match[:80] if v.match else "",
                cp=(v.match[:5] if v.match else ""),
                pos=v.span[0],
                token=(v.match[:40] if v.match else ""),
            ).envelope())

        # Check auto contradiction
        auto_id = output_item.get("auto")
        if auto_id:
            auto_result = _run_auto(auto_id, category, map_doc, location_quotes)
            if auto_result != "unknown" and value != auto_result:
                violations.append(ReviewError(
                    "E_CHALLENGE_CONTRADICTS_AUTO", auto=f"{auto_id}={auto_result}"
                ).envelope())

        scope_obj = output_item.get("scope", {})
        scope_not_covered_item = scope_obj.get("not_covered", False)
        scope_ranges = scope_obj.get("ranges", [])
        if scope_not_covered_item:
            scope_not_covered = True

        quote_verified = False               # one quote of this answer matched the pinned source
        if value == "present":
            item_kind = output_item.get("kind", "")

            # When scope is not_covered, kill/downgrade items cannot be verified: the resolver
            # could not produce scope ranges (e.g. no semantic layer), so we have no bounds to
            # check the quote against.  Reject with E_CHALLENGE_SCOPE — only context/basis items
            # may carry unverified 'present' claims (and basis fallback is applied conservatively
            # below regardless).  (04 §8.3/§8.4: kill+downgrade require evidence bound to scope.)
            if scope_not_covered_item and item_kind in ("kill", "downgrade"):
                violations.append(ReviewError(
                    "E_CHALLENGE_SCOPE", item=item_id,
                    ranges="scope_not_covered",
                ).envelope())

            # Quote-match check
            quotes = answer.get("quotes") or []
            if not quotes:
                violations.append(ReviewError(
                    "E_CHALLENGE_INCOMPLETE", ids=item_id
                ).envelope())
                continue
            for q in quotes:
                qt = q.get("text") or ""
                q_file = q.get("file") or ""
                q_start_raw = q.get("start")
                q_end_raw = q.get("end")
                # A project document is never evidence for a scope-bound claim: kill and downgrade
                # items take code quotes inside their scope only (security review 2026-10-23,
                # context ingestion spec 4). Context and basis items may cite a document when their
                # scope leaves them unbound (the containment check below still applies otherwise).
                if is_context_path(q_file) and item_kind in ("kill", "downgrade"):
                    violations.append(ReviewError(
                        "E_CHALLENGE_SCOPE", item=item_id, ranges="code scope only; a context/ quote is not evidence",
                    ).envelope())
                    continue
                if not isinstance(q_start_raw, int) or not isinstance(q_end_raw, int):
                    violations.append(ReviewError(
                        "E_INVALID_ARGUMENT",
                        field="quote.start/end",
                        rule="must be integers",
                        value80="",
                    ).envelope())
                    continue
                q_start = q_start_raw
                q_end = q_end_raw
                # Comment-only check (code only: a document line is prose, never a comment)
                if not is_context_path(q_file) and _is_comment_only(qt, pin, q_file, q_start, q_end):
                    violations.append(ReviewError("E_CHALLENGE_COMMENT_ONLY").envelope())
                    continue
                try:
                    quote_match(pin, q_file, q_start, q_end, qt, context=context_store)
                except QuoteMatchError as e:
                    violations.append(ReviewError(e.code, **e.detail).envelope())
                    continue
                if not is_context_path(q_file):
                    quote_verified = True
                # Scope containment: quote must lie within the item's scope ranges (04 §8.3).
                # Evidence must be bound to the claim's scope; an unrelated line anywhere in
                # the codebase does not prove the item condition holds in the stated scope.
                # Skip when scope is not_covered — kill/downgrade already rejected above;
                # context/basis items allow unbound quotes (fallback applied conservatively).
                if (not scope_not_covered_item and scope_ranges
                        and not _quote_in_scope_ranges(q_file, q_start, q_end, scope_ranges)):
                    # Bug 6b fix (2026-10-25): name the offending quote and the allowed scope so
                    # the model can identify which quote is out of range without guessing.
                    _allowed = ", ".join(scope_ranges[:5])
                    violations.append(ReviewError(
                        "E_CHALLENGE_SCOPE", item=item_id,
                        ranges=f"quote {q_file}:{q_start}-{q_end} is outside the scope [{_allowed}]",
                    ).envelope())

            # Record kill/downgrade only when no violations raised yet
            if not violations:
                if item_kind == "kill":
                    if kill_present is None:
                        kill_present = item_id
                elif item_kind == "downgrade":
                    downgrade_count += 1

        elif value == "absent":
            # Scope coverage check against job_reads
            if not scope_not_covered_item and scope_ranges:
                # Document reads never cover a code scope range (spec 4: a context quote is not a location).
                refs = [r for r in (answer.get("refs") or []) if not is_context_path(str(r))]
                missing = _ranges_cover(scope_ranges, refs, job_reads_index)
                if missing:
                    # Names the item: a basis item with one ref fails while the kill items pass,
                    # and without the id the reviewer re-filed the wrong answers five times
                    # (c2 re-run, 2026-10-23).
                    violations.append(ReviewError(
                        "E_CHALLENGE_SCOPE", item=item_id,
                        ranges=", ".join(missing[:5]),
                    ).envelope())
            # If scope is NOT_COVERED: check passes trivially, K10 will apply

        elif value == "not_applicable":
            reason = answer.get("reason", "")
            allowed_reasons = output_item.get("allowed_na_reasons", [])
            if reason not in allowed_reasons:
                violations.append(ReviewError("E_CHALLENGE_NA_REASON", reasons=", ".join(allowed_reasons)).envelope())
                continue
            # Check predicate — at W0, predicates requiring map return unknown → reject (fail closed)
            predicate_result = _check_na_predicate(reason, map_doc, family)
            if predicate_result != "true":
                violations.append(ReviewError("E_CHALLENGE_NA_REASON", reasons=", ".join(allowed_reasons)).envelope())

        else:
            violations.append(ReviewError(
                "E_INVALID_ARGUMENT", field=f"answers.{item_id}.value",
                rule="must be present, absent, or not_applicable", value80=str(value)[:80],
            ).envelope())

        # For basis items: track fallbacks based on answer vs expect. On a NOT_COVERED scope the
        # severity cap is K10 (compute_severity); a present answer with a verified quote keeps the
        # matrix, a present answer without one falls back (basis_fallback).
        raw_item = raw_items_by_id.get(item_id)
        if raw_item:
            fb = basis_fallback(raw_item, value, scope_not_covered=scope_not_covered_item,
                                quote_verified=quote_verified)
            if fb is not None:
                basis_fallbacks.append(fb)

    if violations:
        return {
            "accepted": False,
            "errors": violations[:20],
            **({"errors_more": len(violations) - 20} if len(violations) > 20 else {}),
        }

    # ── All checks passed: compute verdict ────────────────────────────────────

    severity_before = draft["severity"] or "Informational"

    async with pool.connection() as conn, conn.transaction():
        # Re-lock draft to prevent concurrent answer submissions
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from finding_drafts where job_id = %s and draft_key = %s for update",
                (job_id, draft_key),
            )
            draft_locked = await cur.fetchone()

        if draft_locked is None:
            raise ReviewError("E_FINDING_NOT_FOUND", draft=draft_key)

        # TOCTOU guard: verify draft was not concurrently withdrawn or answered between transactions
        if draft_locked["status"] != "needs_challenge":
            return {"accepted": False, "errors": [
                ReviewError("E_FINDING_NOT_FOUND", draft=draft_key).envelope()
            ]}

        if draft_locked["current_revision"] != revision:
            return {"accepted": False, "errors": [
                ReviewError("E_REVISION_CONFLICT", revision=draft_locked["current_revision"]).envelope()
            ]}

        leads_reopened: list[str] = []

        if kill_present is not None:
            # Verdict: withdrawn
            verdict = "withdrawn"
            severity_after = None

            # Store withdrawal
            await conn.execute(
                """update finding_drafts
                   set status = 'withdrawn', withdrawn_by = 'challenge', kill_item = %s,
                       withdrawn_reason = 'disproved',
                       withdraw_evidence = %s
                   where job_id = %s and draft_key = %s""",
                (kill_present,
                 psycopg.types.json.Jsonb({"kill_item": kill_present, "items": items, "answers": answers}),
                 job_id, draft_key),
            )

            # Demote promoted leads: analyzer leads → disproved_by_challenge
            # carried leads → back to open (04 §10)
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    """select lead_id, origin from leads
                       where job_id = %s and state = 'promoted' and state_ref = %s""",
                    (job_id, draft_key),
                )
                promoted_leads = await cur.fetchall()

            for lead in promoted_leads:
                if lead["origin"] == "previous_report":
                    await conn.execute(
                        "update leads set state = 'open', state_ref = null where job_id = %s and lead_id = %s",
                        (job_id, lead["lead_id"]),
                    )
                    leads_reopened.append(lead["lead_id"])
                else:
                    await conn.execute(
                        """update leads set state = 'dismissed', reason = 'disproved_by_challenge',
                               state_item = %s
                           where job_id = %s and lead_id = %s""",
                        (kill_present, job_id, lead["lead_id"]),
                    )

            # Spec clarification (docs/w0/kill-sweep-spec-clarification.md):
            # Unlinked open analyzer leads are NOT automatically swept on a kill.
            # Every open lead must be closed individually via review_dismiss_lead with
            # its own evidence.  Only the killed draft's directly linked/promoted leads
            # are dismissed here.  F2 enforces no open leads remain before finalize.

            # Return duplicate_of chains pointing to this draft back to open (04 §4.11)
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    """select lead_id from leads
                       where job_id = %s and state = 'dismissed' and reason = 'duplicate_of'
                         and state_ref = %s""",
                    (job_id, draft_key),
                )
                chain_leads = await cur.fetchall()

            for lead in chain_leads:
                await conn.execute(
                    "update leads set state = 'open', reason = null, state_ref = null "
                    "where job_id = %s and lead_id = %s",
                    (job_id, lead["lead_id"]),
                )
                leads_reopened.append(lead["lead_id"])

            new_status = "withdrawn"
            new_evidence = draft_locked.get("evidence_level", "reasoning_only")
            severity_rule = f"kill={kill_present}"
            caps_named = [f"kill:{kill_present}"]

        else:
            # Apply basis fallbacks to matrix_effective
            matrix_effective = dict(matrix)
            for fb in basis_fallbacks:
                matrix_effective[fb["field"]] = fb["value"]

            # Compute severity at post_challenge phase
            ev_level = draft_locked.get("evidence_level", "reasoning_only")
            has_attack_steps = bool(
                content.get("attack_steps") or []
            ) if isinstance(content.get("attack_steps"), list) else False

            sev_ctx = SeverityContext(
                phase="post_challenge",
                evidence_level=ev_level,
                has_attack_steps=has_attack_steps,
                open_downgrade_item=False,  # all answered now
                downgrade_items_present=downgrade_count,
                scope_not_covered=scope_not_covered,
                map_unavailable=(map_doc is None or map_doc.get("semantic") is None),
                category_generic=is_generic,
                category_max_severity=cat_info.get("max_severity"),
                linked_lead_same_cat=draft_locked.get("evidence_level") == "analyzer_and_reasoning",
                token_review=detect_token_review(
                    map_doc.get("semantic") if map_doc else None,
                    units_holding(map_doc.get("semantic") if map_doc else None, location_quotes)),
                has_location_quote=bool(location_quotes),
            )

            try:
                sev_result = compute_severity(matrix_effective, "post_challenge", sev_ctx)
            except (KeyError, ValueError) as e:
                raise ReviewError("E_INTERNAL", incident=f"severity_post_challenge:{e!s:.40}")

            severity_after = sev_result.severity
            verdict = "downgraded" if severity_after != severity_before else "passed"
            new_status = "accepted"
            new_evidence = sev_result.evidence_level
            # Every cause of the verdict, by name: the K caps compute_severity applied and the
            # basis fallbacks that changed the matrix. A downgrade without a named cause is a
            # server defect and never a verdict (Solana blind run 2026-10-26: Critical -> Low,
            # caps_applied [], severity_rule empty).
            caps_named = list(sev_result.caps_applied) + fallback_labels(basis_fallbacks)
            severity_rule = sev_result.severity_rule
            if basis_fallbacks:
                severity_rule += f" basis=[{','.join(fallback_labels(basis_fallbacks))}]"
            if verdict == "downgraded" and not caps_named:
                raise ReviewError("E_INTERNAL",
                                  incident=f"downgrade_without_cause:{draft_key[:24]}:{severity_before}->{severity_after}")

            # Update finding_drafts with new severity/evidence
            await conn.execute(
                """update finding_drafts set status = 'accepted', severity = %s, evidence_level = %s,
                       matrix_effective = %s, caps_applied = %s
                   where job_id = %s and draft_key = %s""",
                (severity_after,
                 new_evidence,
                 psycopg.types.json.Jsonb(matrix_effective),
                 caps_named,
                 job_id, draft_key),
            )

        # Store challenge_answers
        await conn.execute(
            """insert into challenge_answers
               (job_id, draft_key, revision, checklist_sha256, items, answers_hash, answers,
                verdict, severity_before, severity_after)
               values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (job_id, draft_key, revision, checklist_sha256,
             psycopg.types.json.Jsonb(items),
             answers_hash,
             psycopg.types.json.Jsonb(answers),
             verdict, severity_before, severity_after),
        )

        await conn.execute("update jobs set last_call_at = now() where job_id = %s", (job_id,))

    return {
        "accepted": True,
        "draft_key": draft_key,
        "verdict": verdict,
        "severity_before": severity_before,
        "severity_after": severity_after,
        "status": new_status,
        "evidence_level": new_evidence,
        "kill_item": kill_present,
        "leads_reopened": leads_reopened,
        "severity_rule": severity_rule,
        "caps_applied": caps_named,
    }


def _check_na_predicate(reason: str, map_doc: dict | None, family: str) -> str:
    """Check a not_applicable predicate. Returns 'true', 'false', or 'unknown'."""
    if map_doc is None or map_doc.get("semantic") is None:
        # Without map, most predicates are unknown → reject (fail closed per spec)
        return "unknown"

    semantic = map_doc.get("semantic", {})
    functions = semantic.get("functions", [])
    # Load na_predicates.yaml
    preds_path = RUBRIC_DIR / "na_predicates.yaml"
    if not preds_path.exists():
        return "unknown"
    preds = yaml.safe_load(preds_path.read_text()) or {}
    fam_preds = preds.get(family, {})
    if reason not in fam_preds:
        return "unknown"

    # Simple implementations for common predicates
    if reason == "nr_no_external_call":
        # No call of kind external/delegatecall/value_transfer
        for fn in functions:
            for call in fn.get("calls", []):
                if call.get("kind") in ("external", "delegatecall", "value_transfer"):
                    return "false"
        return "true"
    if reason == "nr_no_proxy":
        units = semantic.get("units", [])
        for unit in units:
            if unit.get("proxy_address") or unit.get("upgrade_surface"):
                return "false"
        return "true"
    if reason == "nr_no_upgrade_path":
        units = semantic.get("units", [])
        for unit in units:
            if unit.get("upgrade_surface"):
                return "false"
        return "true"

    # Default: unknown for unimplemented predicates
    return "unknown"
