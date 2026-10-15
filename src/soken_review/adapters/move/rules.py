"""Move own-rule engine (plan v4 07 sections 5.2 and 5.3): soken-move-rules.

Rules are reference data in `adapters/<chain>/rules/*.yaml`. A rule fires on a function (or a
struct) only when both layers agree (07 5.1): every fact predicate holds on the bytecode facts
and the source layer matches (`pattern`, when given, must match; any `negative` match suppresses).

Plan 07 5.2 specifies a small expression grammar for `facts:`. This engine takes a closed list of
named predicates instead (the registry below); an unknown predicate name or category fails at
load time (no runtime error path), which is the property the grammar was for.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from soken_review.adapters.move.bytecode import FunctionFacts, ModuleFacts
from soken_review.adapters.move.facts import LinkedSet
from soken_review.adapters.move.source import FnSpan, SourceIndex, StructSpan
from soken_review.adapters.move.units import normalize_address

_REPO = Path(__file__).resolve().parents[4]
_ENUMS = _REPO / "contract" / "rubric" / "enums.yaml"
TOOL = "soken-move-rules"
TOOL_VERSION = "0.1.0"

_SUI2 = normalize_address("0x2")
_APT1 = normalize_address("0x1")


@dataclass
class Ctx:
    chain: str
    linked: LinkedSet
    source: SourceIndex
    chain_extras: dict[str, Any]
    shared_types: set[str]
    capabilities: set[str]
    unplaced: list[str] = field(default_factory=list)   # fact hits with no source span (degraded)


def _types(fn: FunctionFacts) -> list[str]:
    return [p["type"] for p in fn.params]


def _short(type_name: str) -> str:
    """`0x..::m::S<..>` -> `m::S`."""
    base = type_name.split("<", 1)[0]
    parts = base.split("::")
    return "::".join(parts[-2:]) if len(parts) >= 2 else base


def _calls_any(fn: FunctionFacts, names: set[str]) -> bool:
    return any(c in names for c in fn.calls)


# -- fact predicates (closed set) -------------------------------------------------
def _p_public_or_entry(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    # `friend` (Sui `public(package)`, Aptos `public(friend)`) is part of the callable surface:
    # any module declared as a friend can invoke these functions without capability proof.
    # Excluding them without positive proof that callers are safe is a fail-open.
    return fn.visibility in ("public", "friend") or fn.entry


def _p_public(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return fn.visibility == "public"


def _p_param_mut_shared(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return any(p["mut"] and p["type"].split("<", 1)[0] in ctx.shared_types for p in fn.params)


def _p_returns_ref_handle(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    refs = {f"{_APT1}::object::{n}" for n in ("ConstructorRef", "ExtendRef", "TransferRef", "DeleteRef")}
    return any(r["type"].split("<", 1)[0] in refs for r in fn.returns)


def _p_global_mut(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return fn.global_mut


def _p_address_param(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return "address" in _types(fn)


def _p_no_signer_param(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return not any(t in ("signer", "&signer") or (p["ref"] and p["type"] == "signer") for p, t in zip(fn.params, _types(fn)))


def _p_signer_param(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return not _p_no_signer_param(ctx, m, fn)


def _p_object_param(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return any(t.startswith(f"{_APT1}::object::Object<") for t in _types(fn))


def _p_shl(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return fn.shl


def _p_writes_balance(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    if ctx.chain == "sui":
        return any(c.startswith((f"{_SUI2}::balance::", f"{_SUI2}::coin::")) for c in fn.calls)
    return fn.global_mut or any(c.startswith((f"{_APT1}::coin::", f"{_APT1}::fungible_asset::")) for c in fn.calls)


def _p_calls_receive(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return _calls_any(fn, {f"{_SUI2}::transfer::receive", f"{_SUI2}::transfer::public_receive"})


def _p_calls_dynamic_field_add(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return _calls_any(fn, {f"{_SUI2}::dynamic_field::add", f"{_SUI2}::dynamic_object_field::add"})


def _p_generic_value_param(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return fn.type_params > 0 and any(not p["ref"] and re.fullmatch(r"T\d+", p["type"]) for p in fn.params)


def _p_no_otw_assert(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    otw = {f"{_SUI2}::types::is_one_time_witness", f"{_SUI2}::coin::create_currency",
           f"{_SUI2}::coin::create_regulated_currency_v2", f"{_SUI2}::package::claim",
           f"{_SUI2}::package::claim_and_keep"}
    reached, _, _ = ctx.linked.reach([f"{m.module_id}::{fn.name}"])
    return not (reached & otw)


def _p_calls_create_signer_with_cap(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    return _calls_any(fn, {f"{_APT1}::account::create_signer_with_capability"})


def _p_reaches_randomness(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
    reached, _, _ = ctx.linked.reach([f"{m.module_id}::{fn.name}"])
    return any(r.startswith(f"{_APT1}::randomness::") for r in reached)


def _p_upgrade_policy_compatible_address(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts | None) -> bool:
    up = ctx.chain_extras.get("upgrade") or {}
    if ctx.chain == "sui":
        return up.get("state") == "upgradable" and up.get("policy") == 0 and up.get("holder_kind") == "address"
    return up.get("policy") == 1 and up.get("publisher_kind") == "plain"


def _no_call(*targets: str) -> Callable[..., bool]:
    """No call from the function body to any target (bytecode CALL, not text)."""
    def pred(ctx: Ctx, m: ModuleFacts, fn: FunctionFacts) -> bool:
        return not any(c in targets for c in fn.calls)
    return pred


FN_PREDICATES: dict[str, Callable[..., bool]] = {
    "no_sender_call": _no_call(f"{_SUI2}::tx_context::sender"),
    "no_signer_address_of": _no_call(f"{_APT1}::signer::address_of"),
    "no_object_owner_check": _no_call(f"{_APT1}::object::owner", f"{_APT1}::object::is_owner",
                                      f"{_APT1}::object::owns"),
    "no_dynamic_field_exists": _no_call(f"{_SUI2}::dynamic_field::exists_", f"{_SUI2}::dynamic_field::exists_with_type",
                                        f"{_SUI2}::dynamic_object_field::exists_",
                                        f"{_SUI2}::dynamic_object_field::exists_with_type"),
    "fn_public_or_entry": _p_public_or_entry,
    "fn_public": _p_public,
    "param_mut_shared": _p_param_mut_shared,
    "returns_object_ref_handle": _p_returns_ref_handle,
    "global_mut": _p_global_mut,
    "address_param": _p_address_param,
    "no_signer_param": _p_no_signer_param,
    "signer_param": _p_signer_param,
    "object_param": _p_object_param,
    "shl": _p_shl,
    "writes_balance": _p_writes_balance,
    "calls_receive": _p_calls_receive,
    "calls_dynamic_field_add": _p_calls_dynamic_field_add,
    "generic_value_param": _p_generic_value_param,
    "no_otw_assert": _p_no_otw_assert,
    "calls_create_signer_with_capability": _p_calls_create_signer_with_cap,
    "reaches_randomness": _p_reaches_randomness,
}
PACKAGE_PREDICATES = {"upgrade_policy_compatible_address_holder": _p_upgrade_policy_compatible_address}
STRUCT_PREDICATES: dict[str, Callable[[Ctx, StructSpan], bool]] = {
    "struct_is_capability": lambda ctx, s: _qualified(ctx, s) in ctx.capabilities,
    "struct_key_store": lambda ctx, s: {"key", "store"} <= set(s.abilities),
    "struct_copy_or_drop": lambda ctx, s: bool({"copy", "drop"} & set(s.abilities)),
}


def _qualified(ctx: Ctx, s: StructSpan) -> str:
    mod = next((m for m in ctx.linked.root if m.name == s.module), None)
    return f"{mod.module_id}::{s.name}" if mod else s.name


# -- loading -------------------------------------------------------------------------
@dataclass
class Rule:
    id: str
    category: str
    raw: str
    chain: str
    scope: str                     # function | struct | package
    facts: list[str]
    pattern: re.Pattern[str] | None
    negative: list[re.Pattern[str]]
    fixtures: dict[str, str]


def _category_ids() -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(_ENUMS.read_text())
    return {c["id"]: c for c in data["categories"]}


def load_rules(rules_dir: Path, chain: str) -> list[Rule]:
    """Load and validate every rule file; raises ValueError on any unknown name (CI gate)."""
    cats = _category_ids()
    out: list[Rule] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        for doc in yaml.safe_load(path.read_text()) or []:
            cat = cats.get(doc["category"])
            if cat is None or cat.get("family") != "move" or cat.get("server_only"):
                raise ValueError(f"{doc['id']}: category {doc['category']} not an adapter move category")
            if cat.get("chains") and chain not in cat["chains"]:
                raise ValueError(f"{doc['id']}: category {doc['category']} not enabled for {chain}")
            scope = doc.get("scope", "function")
            registry = {"function": FN_PREDICATES, "struct": STRUCT_PREDICATES, "package": PACKAGE_PREDICATES}[scope]
            for name in doc.get("facts", []):
                if name not in registry:
                    raise ValueError(f"{doc['id']}: unknown fact predicate {name}")
            if doc.get("analyzer_severity_raw") not in ("high", "medium", "low", "info"):
                raise ValueError(f"{doc['id']}: bad analyzer_severity_raw")
            src = doc.get("source") or {}
            if src.get("negative"):
                raise ValueError(f"{doc['id']}: text negatives are not allowed; use a fact predicate")
            out.append(Rule(
                id=doc["id"], category=doc["category"], raw=doc["analyzer_severity_raw"], chain=chain, scope=scope,
                facts=list(doc.get("facts", [])),
                pattern=re.compile(src["pattern"], re.DOTALL) if src.get("pattern") else None,
                negative=[re.compile(n, re.DOTALL) for n in src.get("negative", [])],
                fixtures=doc.get("tests") or {},
            ))
    return out


# -- running -------------------------------------------------------------------------
def _source_ok(rule: Rule, text: str) -> bool:
    """Text may add a precondition, never suppress: only the positive pattern is read here."""
    return rule.pattern is None or bool(rule.pattern.search(text))


def run_rules(rules: list[Rule], ctx: Ctx) -> list[dict[str, Any]]:
    """Raw findings {tool, rule_id, severity_raw, category, file, start, end}."""
    raw: list[dict[str, Any]] = []
    tool = f"{TOOL}@{TOOL_VERSION}"
    for rule in rules:
        if rule.scope == "package":
            first = next(iter(sorted(ctx.source.modules.values())), None)
            if first and all(PACKAGE_PREDICATES[p](ctx, ctx.linked.root[0] if ctx.linked.root else None, None)
                             for p in rule.facts):
                raw.append(_raw(tool, rule, first[0], first[1], first[1]))
            continue
        if rule.scope == "struct":
            for s in ctx.source.structs:
                if all(STRUCT_PREDICATES[p](ctx, s) for p in rule.facts) and _source_ok(rule, s.body):
                    raw.append(_raw(tool, rule, s.file, s.start, s.end))
            continue
        for m in ctx.linked.root:
            for fn in m.functions:
                if fn.native or not all(FN_PREDICATES[p](ctx, m, fn) for p in rule.facts):
                    continue
                spans: list[FnSpan] = ctx.source.fns(m.name, fn.name)
                if not spans:
                    # No quotable lines: no lead can be placed, so the analysis is degraded (never
                    # a silent drop).
                    ctx.unplaced.append(f"{rule.id}:{m.module_id}::{fn.name}")
                    continue
                for span in spans:                  # ambiguous name: every span, no first match
                    attrs = "".join(f"#[{a}]" for a in span.attributes)
                    if _source_ok(rule, attrs + span.signature + "{" + span.body + "}"):
                        raw.append(_raw(tool, rule, span.file, span.start, span.end))
    return raw


def _raw(tool: str, rule: Rule, file: str, start: int, end: int) -> dict[str, Any]:
    return {"tool": tool, "rule_id": f"soken:{rule.id}", "severity_raw": rule.raw, "category": rule.category,
            "file": file, "start": start, "end": end}


def package_types(linked: LinkedSet, chain: str) -> tuple[set[str], set[str]]:
    """(shared types, capability types) of the root package from bytecode facts (07 6.3, 10).

    Shared: type argument of ``0x2::transfer::share_object`` / ``public_share_object`` calls
    (Sui only).

    Capabilities (detection only, never suppression): root structs with ``key`` ability that
    appear as an immutable reference parameter (``&T``, not ``&mut T``) in any public, friend,
    or entry function.  These are candidates for the positive ``struct_is_capability`` detection
    predicate (``move.capability_leak`` rule — struct with ``key+store`` abilities leaks the
    capability into global storage).

    Design note (wave-7): the detection set is intentionally WIDER than a packer-gate heuristic
    — no phase-2 packer-gate verification.  When in doubt, a struct is a candidate; a false
    positive costs one reviewer dismiss while a false negative (missed detection) is a silent gap.

    The ``no_capability_param`` suppression predicate was permanently deleted in wave-6.  This
    set is NOT consulted by any function-level predicate; it affects struct rules only.
    """
    shared: set[str] = set()
    if chain == "sui":
        share_fns = {f"{_SUI2}::transfer::share_object", f"{_SUI2}::transfer::public_share_object"}
        for m in linked.root:
            for fn in m.functions:
                for callee, targs in fn.generic_calls:
                    if callee in share_fns and targs:
                        shared.add(targs[0].split("<", 1)[0])

    # Phase-1 capability candidates: root key struct taken as &T in public/friend/entry.
    # No packer-gate (phase-2 removed wave-6); detection is intentionally wider than suppression.
    candidates: set[str] = set()
    root_structs = {
        f"{m.module_id}::{s['name']}": s
        for m in linked.root
        for s in m.structs
    }
    for m in linked.root:
        for fn in m.functions:
            if not (fn.visibility in ("public", "friend") or fn.entry):
                continue
            for p in fn.params:
                if not (p["ref"] and not p["mut"]):
                    continue
                t = p["type"].split("<", 1)[0]
                s = root_structs.get(t)
                if s and "key" in s["abilities"] and t not in shared:
                    candidates.add(t)

    return shared, candidates
