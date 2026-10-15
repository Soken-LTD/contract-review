"""Sierra contract class reading (07 8.1, 8.2, 5.1): compiler version, selectors, class hash, facts.

All functions take plain JSON (the RPC `starknet_getClass` result or a Scarb
`<pkg>_<Contract>.contract_class.json` artifact) and run in the supervisor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from soken_review.adapters.starknet.felt import (
    NonCanonicalFelt,
    parse_felt,
    poseidon_hash_many,
    short_string,
    starknet_keccak,
)

ENTRY_POINT_TYPES = ("EXTERNAL", "L1_HANDLER", "CONSTRUCTOR")
_CLASS_VERSION = short_string("CONTRACT_CLASS_V0.1.0")


@dataclass(frozen=True)
class SierraVersions:
    sierra: str      # e.g. "1.7.0"
    cairo: str       # compiler version, e.g. "2.13.1"


def _felt(value: Any) -> int:
    return parse_felt(value)


def _function_idx(value: Any) -> int:
    """function_idx is a JSON integer >= 0; anything else is refused (bounds checked on decode)."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**64:
        raise NonCanonicalFelt(f"bad function_idx {value!r}"[:80])
    return value


def is_cairo0(contract_class: dict[str, Any]) -> bool:
    """07 8.1 step 3: a class with no `sierra_program` is Cairo 0."""
    return not contract_class.get("sierra_program")


def decode_versions(sierra_program: list[Any]) -> SierraVersions | None:
    """07 8.1 step 2: felts 0..5 are two VersionId {major, minor, patch}: Sierra, then compiler.

    Returns None when the header is not two plausible version triples (unknown, never a guess).
    """
    if not sierra_program or len(sierra_program) < 6:
        return None
    try:
        nums = [_felt(x) for x in sierra_program[:6]]
    except NonCanonicalFelt:
        return None
    if any(n < 0 or n > 10_000 for n in nums):
        return None
    return SierraVersions(sierra=".".join(map(str, nums[:3])), cairo=".".join(map(str, nums[3:6])))


def entry_points(contract_class: dict[str, Any]) -> dict[str, list[tuple[int, int]]]:
    """{type: [(selector, function_idx), ...]} in class order."""
    eps = contract_class.get("entry_points_by_type") or {}
    out: dict[str, list[tuple[int, int]]] = {}
    for kind in ENTRY_POINT_TYPES:
        rows = eps.get(kind) or []
        out[kind] = [(_felt(r["selector"]), _function_idx(r["function_idx"])) for r in rows]
    return out


def selector_set(contract_class: dict[str, Any]) -> dict[str, frozenset[int]]:
    """Entry point selector set per type: the interface compared in 07 8.2 step 3."""
    return {k: frozenset(s for s, _ in v) for k, v in entry_points(contract_class).items()}


def abi_string(contract_class: dict[str, Any]) -> str:
    """ABI text hashed into the class hash.

    On chain the ABI is the declared string. A Scarb artifact holds it as a JSON array; the
    declare tools (starknet-rs, starkli, sncast) serialize it in Python `json.dumps` default form
    (", " and ": " separators), which is what the live classes read in tests show.
    """
    abi = contract_class.get("abi")
    if isinstance(abi, str):
        return abi
    return json.dumps(abi if abi is not None else [], ensure_ascii=False)


def class_hash(contract_class: dict[str, Any]) -> int:
    """Sierra class hash (CONTRACT_CLASS_V0.1.0), Poseidon over entry points, ABI and program."""
    eps = entry_points(contract_class)

    def _ep_hash(kind: str) -> int:
        flat: list[int] = []
        for sel, idx in eps[kind]:
            flat += [sel, idx]
        return poseidon_hash_many(flat)

    program = [_felt(x) for x in contract_class.get("sierra_program") or []]
    return poseidon_hash_many([
        _CLASS_VERSION,
        _ep_hash("EXTERNAL"),
        _ep_hash("L1_HANDLER"),
        _ep_hash("CONSTRUCTOR"),
        starknet_keccak(abi_string(contract_class).encode("utf-8")),
        poseidon_hash_many(program),
    ])


def hex_felt(n: int) -> str:
    return "0x" + format(n, "064x")


# --------------------------------------------------------------------------------------------
# Facts from the hashed program (07 5.1 Starknet row)
# --------------------------------------------------------------------------------------------


@dataclass
class ClassFacts:
    """Libfunc-level facts of one class, decoded from `sierra_program` (covered by the class hash).

    The debug table (`sierra_program_debug_info`) is never read: it is not hashed and the build
    sandbox writes it. A class is self-contained (every callee is in the program), so the libfunc set
    is closed. `complete` is False when the program does not decode; predicates are then unknown.
    """
    libfuncs: frozenset[str]                     # generic libfunc ids in the program
    reachable: dict[str, frozenset[str]]         # entry point type -> libfuncs reachable from it
    felt_consts: frozenset[int]                  # every value argument (selectors among them)
    complete: bool
    error: str | None = None
    entry_types: frozenset[str] = frozenset()     # entry point types with at least one entry


def class_facts(contract_class: dict[str, Any]) -> ClassFacts:
    from soken_review.adapters.starknet.sierra_decode import SierraDecodeError, decode_program, reachable_statements

    empty = ClassFacts(frozenset(), {}, frozenset(), complete=False)
    if is_cairo0(contract_class):
        empty.error = "cairo0_class"
        return empty
    try:
        prog = decode_program(contract_class["sierra_program"])
        eps = entry_points(contract_class)
        reachable: dict[str, frozenset[str]] = {}
        for kind, rows in eps.items():
            stmts = reachable_statements(prog, [idx for _, idx in rows])
            reachable[kind] = frozenset(
                prog.libfuncs[prog.statements[s].libfunc_id].generic_id
                for s in stmts if prog.statements[s].libfunc_id is not None
            )
    except (SierraDecodeError, KeyError, ValueError, TypeError) as exc:
        empty.error = f"decode_failed: {exc}"
        return empty
    return ClassFacts(
        libfuncs=frozenset(lib.generic_id for lib in prog.libfuncs),
        reachable=reachable,
        felt_consts=frozenset(prog.consts),
        complete=True,
        entry_types=frozenset(k for k, v in eps.items() if v),
    )
