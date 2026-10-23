"""Declared vs observed (context ingestion spec 2026-10-23, section 6). Pure: facts in, rows out.

`compare(facts, map_doc, job)` returns rows `{claim, declared, declared_source, observed,
observed_source, status}` with `status` in `matches | differs | not_checkable`:

1. Reviewed contract referenced by website, app or docs (`context.*.mentions_reviewed_address`).
2. Declared total supply vs on-chain `onchain.total_supply` scaled by `onchain.decimals`.
3. Declared fee figures vs the map's folded constants with unit bps or percent.
4. Declared admin claims vs facts and map: `renounced` vs `onchain.owner` (zero address);
   `multisig` vs `onchain.owner.holder_kind` (chain_state holder facts: `multisig` matches, `eoa`
   differs, `contract` or absent is not checkable); `timelock` vs the same key (never `timelock`
   by design, so not checkable unless the holder is an `eoa`, which differs); `upgradeable|immutable`
   vs the semantic `upgrade_surface`; `pausable|blacklist|mint` vs the entry function names of the
   map (the category table has no category for those three, so the names of the lexical spans decide).
5. Declared chains vs the job's chain.

A row is produced only when the documents declare something; a claim without an observation is
`not_checkable`. No prose here: the reviewer's notes go to `review_set_section(context_notes)`.
"""

from __future__ import annotations

import re
from typing import Any

STATUSES = ("matches", "differs", "not_checkable")
_KIND_ORDER = ("whitepaper", "docs", "website", "app", "terms", "privacy", "other")
_SUPPLY_TOLERANCE = 0.001
_ZERO_ADDRESS = "0x" + "0" * 40
_FN_NAMES = {
    "pausable": re.compile(r"^(pause|unpause|_pause|_unpause|setpaused|emergencypause|togglepause)$", re.IGNORECASE),
    "blacklist": re.compile(r"(blacklist|blocklist|denylist|banaddress|setban|_ban$|^ban$)", re.IGNORECASE),
    "mint": re.compile(r"^(mint|_mint|mintto|safemint|mintfor|mintbatch|batchmint)$", re.IGNORECASE),
}
_ADMIN_LABEL = {
    "renounced": "Ownership renounced", "multisig": "Owner is a multisig", "timelock": "Owner is a timelock",
    "upgradeable": "Contract is upgradeable", "immutable": "Contract is immutable",
    "pausable": "Contract is pausable", "blacklist": "Contract has a blacklist", "mint": "Contract can mint",
}


def _row(claim: str, declared: str, declared_source: str, observed: str, observed_source: str, status: str) -> dict:
    assert status in STATUSES
    return {"claim": claim, "declared": declared, "declared_source": declared_source,
            "observed": observed, "observed_source": observed_source, "status": status}


def _context(facts: list[dict[str, Any]], suffix: str) -> list[dict[str, Any]]:
    rows = [f for f in facts if f["key"].startswith("context.") and f["key"].endswith("." + suffix)]
    return sorted(rows, key=lambda f: (_KIND_ORDER.index(_kind(f["key"])) if _kind(f["key"]) in _KIND_ORDER else 9,
                                       f.get("source", "")))


def _kind(key: str) -> str:
    parts = key.split(".")
    return parts[1] if len(parts) > 2 else ""


def _first(facts: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    return next((f for f in facts if f["key"] == key), None)


def _num(value: Any) -> float | None:
    try:
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return None


def compare(facts: list[dict[str, Any]], map_doc: dict[str, Any] | None, job: dict[str, Any] | None) -> list[dict]:
    """The declared-vs-observed rows of a job (spec section 6)."""
    job = job or {}
    map_doc = map_doc or {}
    out: list[dict] = []
    out.extend(_reviewed_address_rows(facts, job))
    out.extend(_supply_rows(facts))
    out.extend(_fee_rows(facts, map_doc))
    out.extend(_admin_rows(facts, map_doc))
    out.extend(_chain_rows(facts, job))
    return out


# 1. reviewed contract referenced ------------------------------------------------------------

def _reviewed_address_rows(facts: list[dict[str, Any]], job: dict[str, Any]) -> list[dict]:
    mentions = _context(facts, "mentions_reviewed_address")
    if not mentions:
        return []
    address = str(job.get("address") or (_first(facts, "deploy.address") or {}).get("value") or "")
    yes = [f for f in mentions if str(f["value"]).lower() == "true"]
    kinds = ", ".join(_kind(f["key"]) for f in mentions)
    if yes:
        return [_row("Reviewed contract referenced by the project documents",
                     "referenced in " + ", ".join(_kind(f["key"]) for f in yes), yes[0]["source"],
                     address or "reviewed address", "job input", "matches")]
    return [_row("Reviewed contract referenced by the project documents",
                 f"not referenced in {kinds}", mentions[0]["source"], address or "reviewed address", "job input",
                 "differs" if address else "not_checkable")]


# 2. total supply --------------------------------------------------------------------------

def _supply_rows(facts: list[dict[str, Any]]) -> list[dict]:
    declared = _context(facts, "total_supply") or _context(facts, "max_supply")
    if not declared:
        return []
    d = declared[0]
    declared_n = _num(d["value"])
    label = "Total supply" if d["key"].endswith("total_supply") else "Max supply"
    onchain = _first(facts, "onchain.total_supply")
    if onchain is None or declared_n is None:
        return [_row(label, f"{d['value']} tokens", d["source"], "no on-chain total supply read", "chain state",
                     "not_checkable")]
    decimals = _first(facts, "onchain.decimals") or next(iter(_context(facts, "decimals")), None)
    raw = _num(onchain["value"])
    dec = int(_num(decimals["value"]) or 0) if decimals is not None else None
    if raw is None or dec is None:
        return [_row(label, f"{d['value']} tokens", d["source"], f"{onchain['value']} base units, decimals unknown",
                     onchain["source"], "not_checkable")]
    scaled = raw / (10 ** dec)
    status = "matches" if scaled and abs(scaled - declared_n) / scaled <= _SUPPLY_TOLERANCE else "differs"
    return [_row(label, f"{d['value']} tokens", d["source"], f"{_fmt(scaled)} tokens ({dec} decimals)",
                 onchain["source"], status)]


def _fmt(n: float) -> str:
    return str(int(n)) if float(n).is_integer() else f"{n:.6f}".rstrip("0").rstrip(".")


# 3. fees ----------------------------------------------------------------------------------

def _to_bps(value: Any, unit: str | None) -> float | None:
    n = _num(value)
    if n is None:
        return None
    return n if unit == "bps" else n * 100.0


def _fee_rows(facts: list[dict[str, Any]], map_doc: dict[str, Any]) -> list[dict]:
    declared = _context(facts, "fee_pct")
    if not declared:
        return []
    constants = [c for c in (map_doc.get("constants") or []) if c.get("unit") in ("bps", "percent")]
    declared_text = ", ".join(dict.fromkeys(f"{f['value']} {'bps' if f.get('unit') == 'bps' else '%'}"
                                            for f in declared))[:200]
    if not constants:
        return [_row("Fee figures", declared_text, declared[0]["source"], "no fee constant in the map",
                     "contract map", "not_checkable")]
    declared_bps = {_to_bps(f["value"], f.get("unit")) for f in declared}
    const_bps = {_to_bps(c.get("folded_value"), c.get("unit")): c for c in constants}
    hit = next((c for b, c in const_bps.items() if b is not None and b in declared_bps), None)
    observed = ", ".join(f"{c['name']} = {c['folded_value']} {c['unit']}" for c in constants[:8])
    if hit is not None:
        return [_row("Fee figures", declared_text, declared[0]["source"], observed, hit.get("decl_ref", "contract map"),
                     "matches")]
    return [_row("Fee figures", declared_text, declared[0]["source"], observed,
                 constants[0].get("decl_ref", "contract map"), "differs")]


# 4. admin claims --------------------------------------------------------------------------

def _function_names(map_doc: dict[str, Any]) -> list[str]:
    names = [sp.get("name", "") for sp in map_doc.get("spans") or [] if sp.get("kind") == "function"]
    return [n for n in names if n]


def _admin_rows(facts: list[dict[str, Any]], map_doc: dict[str, Any]) -> list[dict]:
    claims = _context(facts, "admin_claims")
    if not claims:
        return []
    first: dict[str, dict[str, Any]] = {}
    for f in claims:
        first.setdefault(str(f["value"]), f)
    semantic = map_doc.get("semantic") or {}
    has_semantic = bool(semantic)
    surface = semantic.get("upgrade_surface") or []
    owner = _first(facts, "onchain.owner")
    holder_kind = _first(facts, "onchain.owner.holder_kind")
    holder_contract = _first(facts, "onchain.owner.holder_is_contract")
    fn_names = _function_names(map_doc)
    out: list[dict] = []
    for claim, f in first.items():
        label = _ADMIN_LABEL.get(claim, claim)
        declared = f"{claim} ({f.get('phrase', claim)})"
        if claim == "renounced":
            if owner is None:
                out.append(_row(label, declared, f["source"], "no owner read", "chain state", "not_checkable"))
            else:
                zero = str(owner["value"]).lower() == _ZERO_ADDRESS
                out.append(_row(label, declared, f["source"], f"owner {owner['value']}", owner["source"],
                                "matches" if zero else "differs"))
        elif claim in ("multisig", "timelock"):
            kind = str(holder_kind["value"]).lower() if holder_kind is not None else None
            if kind is None and holder_contract is not None:
                kind = "contract" if str(holder_contract["value"]).lower() == "true" else "eoa"
            source = (holder_kind or holder_contract or {}).get("source", "chain state")
            if kind is None:
                out.append(_row(label, declared, f["source"], "owner code not read", "chain state", "not_checkable"))
            elif kind == "eoa":
                out.append(_row(label, declared, f["source"], "owner is an externally owned account", source, "differs"))
            elif claim == "multisig" and kind == "multisig":
                out.append(_row(label, declared, f["source"], "owner is a known multisig singleton", source, "matches"))
            else:
                # a contract of unknown kind; timelocks have no canonical bytecode, so never a match
                out.append(_row(label, declared, f["source"], f"owner is a contract (holder kind {kind})", source,
                                "not_checkable"))
        elif claim in ("upgradeable", "immutable"):
            if not has_semantic:
                out.append(_row(label, declared, f["source"], "no semantic map", "contract map", "not_checkable"))
            else:
                mech = ", ".join(sorted({str(u.get("mechanism")) for u in surface})) or "none"
                observed = f"upgrade surface: {mech}"
                upgradeable = bool(surface)
                ok = upgradeable if claim == "upgradeable" else not upgradeable
                out.append(_row(label, declared, f["source"], observed, "contract map", "matches" if ok else "differs"))
        elif claim in _FN_NAMES:
            if not fn_names:
                out.append(_row(label, declared, f["source"], "no function spans in the map", "contract map",
                                "not_checkable"))
            else:
                hits = sorted({n for n in fn_names if _FN_NAMES[claim].search(n)})
                observed = "functions: " + ", ".join(hits[:6]) if hits else "no such function in the map"
                out.append(_row(label, declared, f["source"], observed, "contract map", "matches" if hits else "differs"))
    return out


# 5. chains --------------------------------------------------------------------------------

def _chain_rows(facts: list[dict[str, Any]], job: dict[str, Any]) -> list[dict]:
    declared = _context(facts, "chains")
    if not declared:
        return []
    job_chain_id = job.get("chain_id")
    job_chain = str(job.get("chain") or "")
    if job_chain_id is None and not job_chain:
        cid = _first(facts, "chain.chain_id")
        job_chain_id = int(cid["value"]) if cid else None
    names = ", ".join(dict.fromkeys(str(f["value"]) for f in declared))
    if job_chain_id is None and not job_chain:
        return [_row("Declared chains", names, declared[0]["source"], "job has no chain", "job input", "not_checkable")]
    observed = f"chain_id {job_chain_id}" if job_chain_id is not None else job_chain
    for f in declared:
        if job_chain_id is not None and f.get("chain_id") is not None and int(f["chain_id"]) == int(job_chain_id):
            return [_row("Declared chains", names, f["source"], observed, "job input", "matches")]
        if job_chain and f.get("chain") == job_chain:
            return [_row("Declared chains", names, f["source"], observed, "job input", "matches")]
    return [_row("Declared chains", names, declared[0]["source"], observed, "job input", "differs")]
