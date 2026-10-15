"""Move facts layer and `nr_*` predicates (plan v4 07 sections 5.1, 10, 12.2).

`facts.json` (internal, serialized into map.v1 by 04): per function name, visibility, entry,
params, returns, calls, lines; per struct name, abilities, lines. The call graph is closed over
every module the build linked (root package plus `bytecode_modules/dependencies`), so public
framework wrappers count (07 10). A call into a module that is not in the linked set, a
function-value call, or a module that could not be read gives `unknown` (never `true`).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from soken_review.adapters.move.bytecode import BytecodeError, ModuleFacts, parse_module
from soken_review.adapters.move.units import normalize_address


def _a(x: str) -> str:
    return normalize_address(x) or x


SUI = {
    "signature": {f"{_a('0x2')}::{m}" for m in ("ed25519", "ecdsa_k1", "ecdsa_r1", "bls12381", "zklogin_verified_id",
                                                "zklogin_verified_issuer")},
    "token": {f"{_a('0x2')}::{m}" for m in ("coin", "balance", "transfer")},
    "randomness": {f"{_a('0x2')}::random"},
}
APTOS = {
    "signature": {f"{_a('0x1')}::{m}" for m in ("ed25519", "multi_ed25519", "secp256k1", "bls12381")},
    "token": {f"{_a('0x1')}::coin", f"{_a('0x1')}::fungible_asset", f"{_a('0x3')}::token"},
    "token_fns": {f"{_a('0x1')}::object::{f}" for f in ("transfer", "transfer_call", "transfer_raw",
                                                       "transfer_to_object", "transfer_with_ref")},
    "randomness": {f"{_a('0x1')}::randomness"},
}
INIT_FN = {"sui": "init", "aptos": "init_module"}


class LinkedSet:
    """Root package modules plus linked dependency modules, parsed once."""

    def __init__(self, chain: str, root: dict[str, bytes], deps: dict[str, bytes]) -> None:
        self.chain = chain
        self.errors: list[str] = []
        self.root: list[ModuleFacts] = []
        self.modules: dict[str, ModuleFacts] = {}
        for label, blobs, is_root in (("root", root, True), ("dep", deps, False)):
            for path, data in sorted(blobs.items()):
                try:
                    mod = parse_module(data, chain)
                except BytecodeError as exc:
                    self.errors.append(f"{label}:{path}: {exc}")
                    continue
                self.modules.setdefault(mod.module_id, mod)
                if is_root:
                    self.root.append(mod)
        self.root_ids = {m.module_id for m in self.root}
        self.root_addresses = {m.address for m in self.root}
        self.fns: dict[str, Any] = {f"{m.module_id}::{f.name}": (m, f) for m in self.modules.values() for f in m.functions}

    # -- reachability ---------------------------------------------------------
    def roots(self) -> list[str]:
        """Public and entry functions, Sui `init`, Aptos `init_module` (07 12.2)."""
        out = []
        for m in self.root:
            for f in m.functions:
                if f.visibility == "public" or f.entry or f.name == INIT_FN[self.chain]:
                    out.append(f"{m.module_id}::{f.name}")
        return out

    def reach(self, start: list[str]) -> tuple[set[str], set[str], bool]:
        """(reached function ids, unresolved callee ids, function value seen)."""
        seen: set[str] = set()
        unresolved: set[str] = set()
        closure = False
        stack = list(start)
        while stack:
            fid = stack.pop()
            if fid in seen:
                continue
            seen.add(fid)
            entry = self.fns.get(fid)
            if entry is None:
                unresolved.add(fid)
                continue
            _, fn = entry
            closure = closure or fn.closure_call
            stack.extend(c for c in fn.calls if c not in seen)
        return seen, unresolved, closure

    # -- nr_* predicates (07 10) -------------------------------------------------
    def nr_predicates(self, upgrade: dict[str, Any] | None) -> dict[str, str]:
        tables = SUI if self.chain == "sui" else APTOS
        reached, unresolved, closure = self.reach(self.roots())
        doubt = bool(unresolved) or bool(self.errors) or closure
        reached_modules = {fid.rsplit("::", 1)[0] for fid in reached}

        def no_reach(modules: set[str], fns: set[str] = frozenset()) -> str:
            if reached_modules & modules or reached & set(fns):
                return "false"
            return "unknown" if doubt else "true"

        calls = [c for m in self.root for f in m.functions for c in f.calls]
        callee_modules = {c.rsplit("::", 1)[0] for c in calls}
        # Outside the root package = another address. A same-address module that is not a rebuilt
        # unit (e.g. a sourceless package of the account) is not proven internal: doubt.
        other_address = any(mid.split("::")[0] not in self.root_addresses for mid in callee_modules)
        same_address_unknown = any(mid not in self.root_ids and mid.split("::")[0] in self.root_addresses
                                   for mid in callee_modules)
        if other_address or closure:
            external = "false"
        elif same_address_unknown or self.errors:
            external = "unknown"
        else:
            external = "true"
        out = {
            "nr_no_external_call": external,
            "nr_no_signature_check": no_reach(tables["signature"]),
            "nr_no_token_transfer": no_reach(tables["token"], tables.get("token_fns", set())),
            "nr_no_randomness_source": no_reach(tables["randomness"]),
            "nr_no_upgrade_path": _upgrade_predicate(self.chain, upgrade),
        }
        if self.chain == "aptos" and any("randomness" in a for m in self.root for f in m.functions for a in f.attributes):
            out["nr_no_randomness_source"] = "false"
        return out

    def unreachable(self) -> dict[str, Any]:
        """Generic checklist item L1 auto answer (07 12.2): root functions no root reaches."""
        reached, _, closure = self.reach(self.roots())
        names = [f"{m.module_id}::{f.name}" for m in self.root for f in m.functions]
        if closure:
            return {"status": "unknown", "reason": "function_value_in_package", "functions": []}
        return {"status": "ok", "functions": sorted(n for n in names if n not in reached)}

    def facts_json(self) -> dict[str, Any]:
        return {"chain": self.chain, "errors": self.errors,
                "modules": [asdict(m) | {"metadata": sorted(k.decode(errors="replace") for k in m.metadata)}
                            for m in self.root]}


def _upgrade_predicate(chain: str, upgrade: dict[str, Any] | None) -> str:
    """Sui `upgrade = immutable`; Aptos policy 2 (07 10)."""
    if not upgrade:
        return "unknown"
    if chain == "sui":
        return {"immutable": "true", "upgradable": "false"}.get(upgrade.get("state"), "unknown")
    policy = upgrade.get("policy")
    return "true" if policy == 2 else ("false" if policy in (0, 1) else "unknown")
