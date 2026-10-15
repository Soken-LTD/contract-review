"""Deployment comparison and `dep.match` (plan v4 07 sections 6.2, 7.2, 9.1). Supervisor only.

Inputs are the on-chain bytes from `chain_state` and the rebuilt bytes the supervisor copied out of
the build container (lstat-checked, `sandbox.read_artifacts`). The result goes to
`host/provenance.json`, which no container mounts. The trust flag of the candidate is an input
here, at the decision point: an untrusted candidate never yields `exact`.

Vocabulary: rubric/dep_match.yaml rows `sui` and `aptos`; reasons per 07 9.1, plus
`build_input_untrusted` (06 3.3.4 rule carried to Move, see W0 findings).
"""

from __future__ import annotations

import hashlib
from typing import Any

from soken_review.adapters.move.bytecode import BytecodeError, header


def _sha(b: bytes | None) -> str | None:
    return hashlib.sha256(b).hexdigest() if b is not None else None


def _rows(onchain: dict[str, bytes], rebuilt: dict[str, bytes]) -> list[dict[str, Any]]:
    rows = []
    for name in sorted(set(onchain) | set(rebuilt)):
        a, b = onchain.get(name), rebuilt.get(name)
        result = "equal" if a is not None and a == b else ("missing_rebuilt" if b is None else
                                                            "missing_onchain" if a is None else "differs")
        rows.append({"module": name, "onchain_sha256": _sha(a), "rebuilt_sha256": _sha(b), "result": result})
    return rows


def aptos_dep_match(
    onchain: dict[str, bytes],
    rebuilt: dict[str, bytes] | None,
    *,
    untrusted: bool,
    build_reason: str | None = None,
    method: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """07 7.2 / 9.1 Aptos: mismatch only on a differing module set; byte difference with equal
    sets is not_checkable (toolchain_version_unknown)."""
    out: dict[str, Any] = {"chain": "aptos", "method": method or {}}
    if rebuilt is None:
        return out | {"dep_match": "not_checkable", "reason": build_reason or "build_failed", "rows": []}
    rows = _rows(onchain, rebuilt)
    out["rows"] = rows
    if untrusted:
        # The rebuild proves nothing either way (06 3.3.4 rule): no exact and no mismatch.
        return out | {"dep_match": "not_checkable", "reason": "build_input_untrusted"}
    if set(onchain) != set(rebuilt):
        # A different module set is a different interface, whatever toolchain produced it (07 7.2).
        return out | {"dep_match": "mismatch", "reason": "module_set_differs"}
    if all(r["result"] == "equal" for r in rows):
        return out | {"dep_match": "exact", "reason": "all_modules_byte_equal"}
    return out | {"dep_match": "not_checkable", "reason": "toolchain_version_unknown"}


def rewrite_self_address(module: bytes, original_id: str) -> bytes:
    """Replace 0x0 entries of the address identifier table with the original id (DESIGN.md:
    "rewrite 0x0 self-addresses"). Any parse problem returns the input unchanged."""
    from soken_review.adapters.move.bytecode import T_ADDRESS_IDENTIFIERS, _Cursor

    try:
        header(module)
        cur = _Cursor(module, 8)
        tables = {}
        for _ in range(cur.uleb(255)):
            kind = cur.byte()
            tables[kind] = (cur.uleb(), cur.uleb())
        base = cur.pos
        if T_ADDRESS_IDENTIFIERS not in tables:
            return module
        off, cnt = tables[T_ADDRESS_IDENTIFIERS]
        if cnt % 32:
            return module
        target = bytes.fromhex(original_id.removeprefix("0x").rjust(64, "0"))
        out = bytearray(module)
        for i in range(base + off, base + off + cnt, 32):
            if out[i:i + 32] == bytes(32):
                out[i:i + 32] = target
        return bytes(out)
    except (BytecodeError, ValueError):
        return module


def sui_dep_match(
    cs: dict[str, Any],
    onchain: dict[str, bytes],
    rebuilt: dict[str, bytes] | None,
    *,
    untrusted: bool,
    toolchain: dict[str, Any],
    built_original_id: str | None,
    built_linkage: dict[str, str] | None = None,
    build_reason: str | None = None,
) -> dict[str, Any]:
    """07 6.2 / 9.1 Sui. `toolchain` = {recorded: version|None, image: version, matches: bool}.

    exact: every 6.2 check passes. mismatch: a check fails with the recorded toolchain image.
    Otherwise not_checkable with toolchain_unavailable / toolchain_version_unknown."""
    out: dict[str, Any] = {"chain": "sui", "toolchain": toolchain, "warnings": []}
    if rebuilt is None:
        return out | {"dep_match": "not_checkable", "reason": build_reason or "build_failed", "rows": []}
    original = cs.get("original_id")
    fixed = {n: rewrite_self_address(b, original) for n, b in rebuilt.items()} if original else rebuilt
    rows = _rows(onchain, fixed)
    out["rows"] = rows
    checks = {
        "original_id": built_original_id is None or built_original_id == original,
        "module_set": set(onchain) == set(fixed),
        "module_bytes": all(r["result"] == "equal" for r in rows),
    }
    if built_linkage is not None:
        chain_link = {x["original_id"]: x["storage_id"] for x in cs.get("linkage", [])}
        common = set(chain_link) & set(built_linkage)
        checks["linkage"] = all(chain_link[k] == built_linkage[k] for k in common)
        one_sided = sorted(set(chain_link) ^ set(built_linkage))
        if one_sided:
            out["warnings"].append({"linkage_one_sided": one_sided})
    out["checks"] = checks
    if untrusted:
        return out | {"dep_match": "not_checkable", "reason": "build_input_untrusted"}
    if all(checks.values()):
        return out | {"dep_match": "exact", "reason": "design_md_checks_pass"}
    if toolchain.get("recorded") and toolchain.get("matches"):
        return out | {"dep_match": "mismatch", "reason": next(k for k, v in checks.items() if not v)}
    reason = "toolchain_unavailable" if toolchain.get("recorded") else "toolchain_version_unknown"
    return out | {"dep_match": "not_checkable", "reason": reason}
