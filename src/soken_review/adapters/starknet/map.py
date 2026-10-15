"""Starknet map: chain_extras and nr_* predicates (07 10), deployment row (07 12.4).

Predicates read only ClassFacts decoded from the hashed `sierra_program` (the deployed class from
the pinned RPC read when there is a deployment). A class is self-contained, so "the libfunc is not
in the program" is a closed-set answer. Unknown facts give `unknown`, never `true`.
"""

from __future__ import annotations

import re
from typing import Any

from soken_review.adapters.starknet.felt import selector
from soken_review.adapters.starknet.sierra import ClassFacts

_TOKEN_SELECTORS = ("transfer", "transfer_from", "transferFrom", "safe_transfer_from", "safeTransferFrom")
_SIG_SELECTORS = ("is_valid_signature", "isValidSignature")

# Syscalls are the only way a Sierra program reaches anything outside itself; every other libfunc
# is pure computation inside the class. Each predicate is an allowlist over the reviewed syscall
# set: a syscall in neither list gives `unknown` (07 10, absence by module/syscall set).
CALLING_SYSCALLS = frozenset({
    "call_contract_syscall", "library_call_syscall", "deploy_syscall", "meta_tx_v0_syscall",
    "send_message_to_l1_syscall",
})
NON_CALLING_SYSCALLS = frozenset({
    "storage_read_syscall", "storage_write_syscall", "emit_event_syscall", "get_execution_info_syscall",
    "get_execution_info_v2_syscall", "keccak_syscall", "sha256_process_block_syscall", "get_block_hash_syscall",
    "replace_class_syscall", "get_class_hash_at_syscall",
    "secp256k1_new_syscall", "secp256k1_add_syscall", "secp256k1_mul_syscall", "secp256k1_get_point_from_x_syscall",
    "secp256k1_get_xy_syscall", "secp256r1_new_syscall", "secp256r1_add_syscall", "secp256r1_mul_syscall",
    "secp256r1_get_point_from_x_syscall", "secp256r1_get_xy_syscall",
})


def _syscalls(libs: frozenset[str]) -> tuple[set[str], set[str]]:
    sys = {x for x in libs if x.endswith("_syscall")}
    unknown = sys - CALLING_SYSCALLS - NON_CALLING_SYSCALLS
    return sys, unknown


def nr_predicates(facts: ClassFacts | None) -> dict[str, str]:
    """07 10 Cairo column. Values: true | false | unknown; true only on a fully classified syscall set."""
    codes = ("nr_no_external_call", "nr_no_signature_check", "nr_no_token_transfer",
             "nr_no_upgrade_path", "nr_no_randomness_source")
    if facts is None or not facts.complete:
        return dict.fromkeys(codes, "unknown")
    libs = facts.libfuncs
    sys, unknown_sys = _syscalls(libs)
    calling = bool(sys & CALLING_SYSCALLS)
    unk = bool(unknown_sys)

    def verdict(present: bool, doubtful: bool) -> str:
        if present:
            return "false"
        return "unknown" if doubtful or unk else "true"

    sig_present = (any(x.startswith(("secp256k1_", "secp256r1_", "ec_")) for x in libs)
                   or any(selector(n) in facts.felt_consts for n in _SIG_SELECTORS))
    token_present = calling and any(selector(n) in facts.felt_consts for n in _TOKEN_SELECTORS)
    return {
        "nr_no_external_call": verdict(calling, False),
        # an external call may verify a signature in the callee
        "nr_no_signature_check": verdict(sig_present, calling),
        # a call with a selector not visible as a constant may be a transfer
        "nr_no_token_transfer": verdict(token_present, calling),
        # a library call may target a class hash read from storage
        "nr_no_upgrade_path": verdict("replace_class_syscall" in libs, "library_call_syscall" in libs),
        # execution info carries block number and timestamp (and the caller): doubt, not proof
        "nr_no_randomness_source": verdict("get_block_hash_syscall" in libs,
                                           bool(libs & {"get_execution_info_syscall", "get_execution_info_v2_syscall"})
                                           or calling),
    }


_PROV_FIELDS = ("match", "reason", "tier", "artifact", "rebuilt_class_hash", "onchain_class_hash", "untrusted_inputs")
_CODE_RE = re.compile(r"^[a-z0-9_]{1,64}(?::[A-Za-z0-9_./@-]{1,200})?$")
_HASH_RE = re.compile(r"^0x[0-9a-f]{1,64}$")


def safe_provenance(provenance: dict[str, Any] | None) -> dict[str, Any]:
    """Only allowlisted provenance fields, each in a fixed shape; trust reasons as codes."""
    p = provenance or {}
    out: dict[str, Any] = {}
    for k in _PROV_FIELDS:
        v = p.get(k)
        if v is None or isinstance(v, bool):
            out[k] = v
        elif k in ("rebuilt_class_hash", "onchain_class_hash"):
            out[k] = v if isinstance(v, str) and _HASH_RE.match(v) else None
        elif k == "artifact":
            out[k] = v if isinstance(v, str) and re.match(r"^[A-Za-z0-9_]{1,200}$", v) else None
        else:
            out[k] = v if isinstance(v, str) and _CODE_RE.match(v) else None
    out["trust_reasons"] = [r for r in (p.get("trust_reasons") or []) if isinstance(r, str) and _CODE_RE.match(r)]
    return out


def chain_extras(chain_state: dict[str, Any] | None, facts: ClassFacts | None,
                 static_map: dict[str, Any], provenance: dict[str, Any] | None) -> dict[str, Any]:
    cs = chain_state or {}
    fns = static_map.get("functions") or []
    by_kind = {k: sorted({f["name"] for f in fns if f["kind"] == k}) for k in ("external", "view", "l1_handler", "constructor")}
    reach = (facts.reachable if facts and facts.complete else {}) or {}
    components = static_map.get("components") or []
    return {
        "entry_points": {
            "external": by_kind["external"] + by_kind["view"],
            "l1_handler": by_kind["l1_handler"],
            "constructor": by_kind["constructor"],
            "counts_onchain": cs.get("entry_point_counts"),
        },
        "components": components,
        "replace_class": {
            "reachable_from": sorted(k for k, v in reach.items() if "replace_class_syscall" in v),
            "storage_class_hash_library_calls": (["library_call_syscall"]
                                                 if facts and facts.complete and "library_call_syscall" in facts.libfuncs
                                                 else []),
            "guard_role": None,
        },
        "l1_links": {
            "handlers": by_kind["l1_handler"],
            "send_sites": sorted(k for k, v in reach.items() if "send_message_to_l1_syscall" in v),
        },
        "compiler": {"sierra": cs.get("sierra_version"), "cairo": cs.get("cairo_version")},
        "class_hash": cs.get("class_hash"),
        "block": cs.get("block"),
        "account": bool(static_map.get("account")),
        "facts": "complete" if facts and facts.complete else "unknown",
        "nr": nr_predicates(facts),
        "provenance": safe_provenance(provenance),
    }
