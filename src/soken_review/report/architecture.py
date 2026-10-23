"""Architecture diagram and privileged-roles rows from `map.v1` and the facts (08 section 2.2).

`architecture_block(map_doc, facts, job, deployment)` returns the report `architecture` object the
kit draws with `diagram()`: in-scope units (kind `scope`), the external systems their code calls
(kind `ext`), the EIP-1967 proxy in front of the deployed unit when the facts show one, and the
actors from the map roles plus the public caller (kind `actor`). `role_rows(map_doc, facts, job)`
returns the `roles.rows` list: one row per role and unit, the holder from the on-chain owner or
admin fact when the row belongs to the deployed unit, and a risk note made of the fixed phrases in
`contract/rubric/roles.yaml` (no free prose in code).

Both functions are pure and deterministic (sorted ids, stable tie-breaks) so repeated renders are
byte-identical. Layout is a four-column grid of at most four rows: actors, primary units, support
units (bases and libraries), external callees. Labels are cut to the kit fit rule, edges that would
cross another node or whose label would not fit are dropped or unlabelled, and the node and edge
counts stay within the schema caps; overflow is counted in the `sub` of a summary node. When the
map has no semantic layer the W0 `no_map` stub is returned so the kit prints its empty note.
"""

from __future__ import annotations

import logging
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .kit.build import BuildError, diagram, kit_texts

logger = logging.getLogger(__name__)

ROLES_YAML = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "roles.yaml"

# Kit geometry (report/kit/build.py diagram()): 720 wide, box height 44, label 6.2 px per char,
# sub 4.7 px per char, edge label 5 px per char plus 8, both must fit inside the cell minus margins.
W, BH, COLS = 720, 44, 4
MAX_NODES, MAX_EDGES, MAX_ROWS = 16, 14, 4
PER_ROW = COLS                               # actors, primary units, support units, externals
LABEL_MAX = int((W / COLS - 30) / 6.2)       # 24 characters at four columns
SUB_MAX = 24                                 # schema maxLength of `sub`
ROW_HEIGHT = 120                             # schema maximum: diagonals clear neighbouring boxes
ELL = "..."
MAX_ROLE_ROWS, MAX_GATED = 30, 40
LOWLEVEL = "address"                         # map target prefix of low-level calls
HOLDER_TYPES = {"eoa": "EOA", "multisig": "Multisig", "timelock": "Timelock", "contract": "Contract",
                "pda": "Program", "unknown": "Unknown"}
INLINE_ROLE = "inline_sender_check"
INLINE_LABEL = "msg.sender check"
PUBLIC_LABEL = "Any caller"
ZERO_ADDR_RE = re.compile(r"^0x0{40}$")


# ------------------------------------------------------------------ data access
@lru_cache(maxsize=1)
def _rules() -> dict[str, Any]:
    data = yaml.safe_load(ROLES_YAML.read_text(encoding="utf-8"))
    for s in data["signals"]:
        for key in ("functions", "writes", "call_members"):
            s[key] = [re.compile(p, re.IGNORECASE) for p in s.get(key) or []]
        s["categories"] = set(s.get("categories") or [])
        s["call_kinds"] = set(s.get("call_kinds") or [])
    return data


def _semantic(map_doc: dict[str, Any] | None) -> dict[str, Any] | None:
    sem = (map_doc or {}).get("semantic")
    return sem if sem and sem.get("units") else None


def _fact_values(facts: Any) -> dict[str, dict[str, Any]]:
    """`key -> record` from the facts.json list (the report-level facts dict is also accepted)."""
    if isinstance(facts, dict):
        return {k: {"key": k, **(v if isinstance(v, dict) else {"value": v})} for k, v in facts.items()}
    return {f["key"]: f for f in facts or [] if isinstance(f, dict) and f.get("key")}


def _unit_name(span_id: str) -> str:
    return span_id.partition(".")[0]


def _fn_name(span_id: str) -> str:
    return span_id.partition(".")[2].partition("(")[0]


def _short_addr(addr: str) -> str:
    return f"{addr[:6]}{ELL}{addr[-4:]}" if len(addr) > 14 else addr


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(1, limit - len(ELL))] + ELL


def _slug(prefix: str, name: str, used: set[str]) -> str:
    base = re.sub(r"_+", "_", re.sub(r"[^a-z0-9]", "_", name.lower())).strip("_") or "n"
    sid = (prefix + base)[:24]
    n = 2
    while sid in used:
        tail = f"_{n}"
        sid = (prefix + base)[: 24 - len(tail)] + tail
        n += 1
    used.add(sid)
    return sid


def _deployed_unit_id(sem: dict[str, Any], facts: dict[str, dict[str, Any]], job: dict[str, Any] | None,
                      deployment: dict[str, Any] | None) -> str | None:
    ids = {u["id"] for u in sem["units"]}
    for key in sorted(facts):
        if key.startswith("onchain.") and facts[key].get("unit_id") in ids:
            return facts[key]["unit_id"]
    dep = ((deployment or {}).get("dep") or {}).get("contract") or ""
    if dep in ids:
        return dep
    if (job or {}).get("address") and len(ids) == 1:   # a deployed job with one unit: that unit
        return next(iter(ids))
    return None


def _bases(sem: dict[str, Any]) -> dict[str, list[str]]:
    """unit id -> base unit ids (chain_extras.evm.units[].bases, names resolved to in-scope units)."""
    by_name = {u["name"]: u["id"] for u in sem["units"]}
    extras = ((sem.get("chain_extras") or {}).get("evm") or {}).get("units") or {}
    out: dict[str, list[str]] = {}
    for uid, ex in extras.items():
        out[uid] = [by_name[b] for b in ex.get("bases") or [] if b in by_name and by_name[b] != uid]
    return out


# ------------------------------------------------------------------ stub
def no_map_block() -> dict[str, Any]:
    return {"title": kit_texts()["architecture_title"], "cols": COLS, "rows": 1, "edges": [],
            "nodes": [{"id": "no_map", "label": "map", "kind": "scope", "col": 0, "row": 0}]}


# ------------------------------------------------------------------ diagram
class _Graph:
    """Collects nodes and edges, then lays them out on the kit grid."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str], dict[str, Any]] = {}
        self.used: set[str] = set()

    def node(self, prefix: str, name: str, label: str, kind: str, sub: str | None = None, *, rank: float = 0,
             fixed_id: str | None = None) -> str:
        nid = fixed_id or _slug(prefix, name, self.used)
        self.used.add(nid)
        n: dict[str, Any] = {"id": nid, "label": _cut(label, LABEL_MAX), "kind": kind, "rank": rank}
        if sub:
            n["sub"] = _cut(sub, SUB_MAX)
        self.nodes[nid] = n
        return nid

    def edge(self, a: str, b: str, label: str | None, prio: int) -> None:
        """Reciprocal pairs collapse into one `both` edge; a later label never replaces an earlier one."""
        if a == b:
            return
        if (b, a) in self.edges:
            e = self.edges[(b, a)]
            e["both"] = True
            e["prio"] = min(e["prio"], prio)
            return
        e = self.edges.setdefault((a, b), {"a": a, "b": b, "prio": prio, "members": []})
        e["prio"] = min(e["prio"], prio)
        if label and label not in e["members"]:
            e["members"].append(label)


def _row_order(ids: list[str], anchors: dict[str, float], edges: dict[tuple[str, str], Any],
               nodes: dict[str, dict[str, Any]]) -> list[str]:
    """Barycenter order: each node at the mean column of its already placed neighbours, ties by rank then id."""
    def key(nid: str) -> tuple[float, float, str]:
        cols = [anchors[o] for (a, b) in edges for o in ((b,) if a == nid else (a,) if b == nid else ())
                if o in anchors]
        bary = sum(cols) / len(cols) if cols else float(PER_ROW) / 2
        return (bary, -nodes[nid]["rank"], nid)
    seq = sorted(ids, key=key)
    # an edge inside one row can only be drawn between neighbours: move the target next to its source
    for a, b in sorted(edges):
        if a in seq and b in seq and abs(seq.index(a) - seq.index(b)) > 1:
            seq.remove(b)
            seq.insert(seq.index(a) + 1, b)
    return seq


def _place(rows: list[list[str]], nodes: dict[str, dict[str, Any]]) -> None:
    for r, ids in enumerate(rows):
        start = (COLS - len(ids)) / 2
        for i, nid in enumerate(ids):
            nodes[nid]["col"] = start + i
            nodes[nid]["row"] = r


def _boxes(nodes: list[dict[str, Any]], rh: int) -> dict[str, tuple[float, float, float, float]]:
    cw = W / COLS
    return {n["id"]: ((n["col"] + n.get("span", 1) / 2) * cw, n["row"] * rh + BH / 2 + 4,
                      cw * n.get("span", 1) - 22, BH) for n in nodes}


def _segment(box: dict[str, tuple[float, float, float, float]], a: str, b: str) -> tuple[float, float, float, float, float, float]:
    (ax, ay, aw, ah), (bx, by, bw, bh) = box[a], box[b]
    ln = math.hypot(bx - ax, by - ay) or 1
    ux, uy = (bx - ax) / ln, (by - ay) / ln

    def edge_t(w: float, h: float) -> float:
        return min((w / 2) / abs(ux) if ux else 1e9, (h / 2) / abs(uy) if uy else 1e9) + 3

    t1, t2 = edge_t(aw, ah), edge_t(bw, bh)
    return ax + ux * t1, ay + uy * t1, bx - ux * t2, by - uy * t2, ux, uy


LABEL_POSITIONS = (0.5, 0.35, 0.65, 0.25, 0.75)


def _label_pos(seg: tuple[float, ...], label: str, others: list[tuple[float, float, float, float]]) -> float | None:
    """Kit rule for the label on the line, then the first position along it where the label box is
    clear of every other node; None when the label cannot be printed."""
    x1, y1, x2, y2, ux, uy = seg
    tw = len(label) * 5.0 + 8
    if tw * abs(ux) + 14 * abs(uy) > math.hypot(x2 - x1, y2 - y1) - 12:
        return None
    for f in LABEL_POSITIONS:
        lx, ly = x1 + (x2 - x1) * f, y1 + (y2 - y1) * f
        if not any(abs(lx - cx) < (tw + w) / 2 + 4 and abs(ly - cy) < (14 + h) / 2 + 4 for cx, cy, w, h in others):
            return f
    return None


def _crosses(seg: tuple[float, ...], rect: tuple[float, float, float, float]) -> bool:
    """Liang-Barsky: does the segment enter the box (grown by a 4 px margin)?"""
    x1, y1, x2, y2 = seg[:4]
    cx, cy, w, h = rect
    xmin, xmax, ymin, ymax = cx - w / 2 - 4, cx + w / 2 + 4, cy - h / 2 - 4, cy + h / 2 + 4
    dx, dy = x2 - x1, y2 - y1
    t0, t1 = 0.0, 1.0
    for p, q in ((-dx, x1 - xmin), (dx, xmax - x1), (-dy, y1 - ymin), (dy, ymax - y1)):
        if p == 0:
            if q < 0:
                return False
            continue
        t = q / p
        if p < 0:
            t0 = max(t0, t)
        else:
            t1 = min(t1, t)
        if t0 > t1:
            return False
    return True


# Edge classes in cap order: role and proxy edges, public caller, external callees, cross-unit calls,
# inheritance. The weight scores a layout by the edges it keeps.
PRIO_ROLE, PRIO_PUBLIC, PRIO_EXT, PRIO_CALL, PRIO_INHERIT = 0, 1, 2, 3, 4
PRIO_WEIGHT = {PRIO_ROLE: 8, PRIO_PUBLIC: 4, PRIO_EXT: 3, PRIO_CALL: 2, PRIO_INHERIT: 1}


def _layout(g: _Graph, rows: list[list[str]]) -> tuple[dict[str, Any], int]:
    """Place rows, drop crossing edges, label what fits, cap edges; nodes carry only schema keys.

    Returns the block and its score (weighted count of edges kept) so the caller can pick a row order."""
    _place(rows, g.nodes)
    nodes = [g.nodes[i] for r in rows for i in r]
    box = _boxes(nodes, ROW_HEIGHT)
    out_edges: list[dict[str, Any]] = []
    score = 0
    for (a, b), e in sorted(g.edges.items(), key=lambda kv: (kv[1]["prio"], kv[0])):
        if a not in box or b not in box or len(out_edges) >= MAX_EDGES:
            continue
        seg = _segment(box, a, b)
        if any(_crosses(seg, box[o]) for o in box if o not in (a, b)):
            continue
        edge: dict[str, Any] = {"a": a, "b": b}
        if e.get("both"):
            edge["both"] = True
        members = e["members"]
        label = members[0] if len(members) == 1 else (f"{len(members)} calls" if members else None)
        pos = _label_pos(seg, label, [box[o] for o in box if o not in (a, b)]) if label else None
        if pos is not None:
            edge["label"] = label
            if pos != 0.5:
                edge["lpos"] = pos
        out_edges.append(edge)
        score += PRIO_WEIGHT[e["prio"]]
    clean = [{k: v for k, v in n.items() if k in ("id", "label", "sub", "kind", "col", "row", "span")} for n in nodes]
    block = {"title": kit_texts()["architecture_title"], "cols": COLS, "rows": len(rows),
             "row_height": ROW_HEIGHT, "nodes": clean[:MAX_NODES], "edges": out_edges}
    return block, score


def _finish(g: _Graph, capped: dict[str, list[str]]) -> dict[str, Any]:
    """Try the externals row above and below the support row; keep the layout with more edges.

    Columns: primary units by rank; every other row at the barycenter of the rows placed before it."""
    best: tuple[dict[str, Any], int] | None = None
    for display in (("a", "p", "s", "x"), ("a", "p", "x", "s")):
        anchors: dict[str, float] = {}
        ordered: dict[str, list[str]] = {}
        for key in ("p", *[k for k in display if k != "p"]):
            ids = capped[key]
            seq = (_row_order(ids, anchors, g.edges, g.nodes) if anchors
                   else sorted(ids, key=lambda i: (-g.nodes[i]["rank"], i)))
            start = (COLS - len(seq)) / 2
            anchors.update({nid: start + k for k, nid in enumerate(seq)})
            ordered[key] = seq
        block, score = _layout(g, [ordered[k] for k in display if ordered[k]])
        if best is None or score > best[1]:
            best = (block, score)
    assert best is not None
    try:
        diagram(best[0])
    except BuildError as err:  # never block assembly on a layout corner case
        logger.warning("architecture diagram does not fit (%s); printing the no-map note", err)
        return no_map_block()
    return best[0]


def _cap(ids: list[str], g: _Graph, more_id: str, label: str, kind: str) -> list[str]:
    """Keep the first PER_ROW ids; when more, the last slot becomes a summary node counting the rest."""
    if len(ids) <= PER_ROW:
        return ids
    keep = ids[: PER_ROW - 1]
    rest = len(ids) - len(keep)
    more = g.node("", more_id, label, kind, f"+{rest} more", rank=-1, fixed_id=more_id)
    return [*keep, more]


def architecture_block(map_doc: dict[str, Any] | None, facts: Any, job: dict[str, Any] | None,
                       deployment: dict[str, Any] | None) -> dict[str, Any]:
    """Report `architecture` object (schema $defs.architecture) from the map and facts."""
    sem = _semantic(map_doc)
    if sem is None:
        return no_map_block()
    fv = _fact_values(facts)
    units = sorted(sem["units"], key=lambda u: u["id"])
    by_name = {u["name"]: u["id"] for u in units}
    fns = sorted(sem.get("functions") or [], key=lambda f: f["span"])
    bases = _bases(sem)
    deployed = _deployed_unit_id(sem, fv, job, deployment)
    entries: dict[str, list[dict[str, Any]]] = {}
    for f in fns:
        uid = by_name.get(_unit_name(f["span"]))
        if uid and f.get("is_entry"):
            entries.setdefault(uid, []).append(f)
    upgrade = {u["unit"]: u["mechanism"] for u in sem.get("upgrade_surface") or []}
    is_base = {b for bl in bases.values() for b in bl}

    g = _Graph()
    # units: primary (own entry points, not a base of another unit) and support (bases, libraries)
    uid_of: dict[str, str] = {}
    primary, support = [], []
    for u in units:
        n_entries = len(entries.get(u["id"], []))
        mech = upgrade.get(u["id"])
        if u["id"] == deployed:
            sub = f"deployed, {n_entries} entries"
        elif mech == "uups":
            sub = f"UUPS, {n_entries} entries"
        elif mech == "proxy_delegatecall":
            sub = "delegatecall proxy"
        elif n_entries:
            sub = f"{n_entries} entries"
        else:
            sub = "library"
        rank = 1e6 if u["id"] == deployed else n_entries
        nid = g.node("u_", u["name"], u["name"], "scope", sub, rank=rank)
        uid_of[u["id"]] = nid
        is_primary = u["id"] == deployed or (n_entries > 0 and u["id"] not in is_base)
        (primary if is_primary else support).append(u["id"])

    def by_rank(ids: list[str]) -> list[str]:
        return sorted(ids, key=lambda i: (-g.nodes[uid_of[i]]["rank"], i))

    primary, support = by_rank(primary), by_rank(support)
    if not support and len(primary) > PER_ROW:
        primary, support = primary[:PER_ROW], primary[PER_ROW:]
    inheritors: dict[str, list[str]] = {}
    for p in primary:
        for b in bases.get(p, []):
            inheritors.setdefault(b, []).append(p)
    deployed_group = {deployed, *bases.get(deployed, [])} if deployed else set()

    def targets(uid: str) -> list[str]:
        """Units whose surface a function declared in `uid` belongs to: the primary units that inherit
        it and the deployed unit for its bases; a unit nobody inherits stands for itself."""
        out = set(inheritors.get(uid) or [])
        if deployed and uid in deployed_group:
            out.add(deployed)
        return sorted(out) or [uid]

    # roles -> actors; gated entry functions -> actor edges
    roles = sorted(sem.get("roles") or [], key=lambda r: (-len(r.get("gated_functions") or []), r["name"]))
    actor_ids: list[str] = []
    for r in roles:
        label = INLINE_LABEL if r["name"] == INLINE_ROLE else r["name"]
        aid = g.node("a_", r["name"], label, "actor", rank=len(r.get("gated_functions") or []))
        actor_ids.append(aid)
        per_unit: dict[str, list[str]] = {}
        for span in sorted(r.get("gated_functions") or []):
            uid = by_name.get(_unit_name(span))
            if uid:
                for t in targets(uid):
                    per_unit.setdefault(t, []).append(_fn_name(span))
        for uid, names in per_unit.items():
            g.edge(aid, uid_of[uid], names[0] if len(names) == 1 else f"{len(names)} functions", PRIO_ROLE)
    gated = {s for r in roles for s in r.get("gated_functions") or []}
    public_units = sorted({t for uid, fs in entries.items() for f in fs
                           if f["span"] not in gated
                           and not any(gd.get("class") == "caller_check" for gd in f.get("guards") or [])
                           for t in targets(uid)})
    if public_units:
        pid = g.node("a_", "public", PUBLIC_LABEL, "actor", rank=1e6, fixed_id="a_public")
        actor_ids.insert(0, pid)
        for uid in public_units:
            g.edge(pid, uid_of[uid], None, PRIO_PUBLIC)

    # EIP-1967 proxy in front of the deployed unit (facts), with its admin as an actor
    impl = fv.get("onchain.eip1967.implementation")
    if impl and deployed:
        addr = (job or {}).get("address") or ""
        pxid = g.node("x_", "proxy", "Proxy", "ext", _short_addr(addr) if addr else "EIP-1967", rank=2e6,
                      fixed_id="x_proxy")
        actor_ids.insert(0, pxid)
        g.edge(pxid, uid_of[deployed], "delegatecall", PRIO_ROLE)
        admin = fv.get("onchain.eip1967.admin")
        if admin:
            adid = g.node("a_", "proxy_admin", "Proxy admin", "actor", _short_addr(str(admin["value"])), rank=3e6,
                          fixed_id="a_proxy_admin")
            actor_ids.insert(0, adid)
            g.edge(adid, pxid, "upgrades", PRIO_ROLE)

    # calls: unit -> unit (cross-unit internal calls and calls on in-scope types) and unit -> external
    defined: dict[str, set[str]] = {}
    for f in fns:
        uid = by_name.get(_unit_name(f["span"]))
        if uid:
            defined.setdefault(_fn_name(f["span"]), set()).add(uid)
    ext_members: dict[str, dict[str, set[str]]] = {}   # ext name -> caller uid -> members
    for f in fns:
        uid = by_name.get(_unit_name(f["span"]))
        if not uid:
            continue
        own = {uid, *bases.get(uid, [])}
        for c in f.get("calls") or []:
            target = c.get("target") or ""
            prefix, _, member = target.rpartition(".")
            kind = c.get("kind")
            if kind == "internal":
                cands = defined.get(target, set())
                if cands & own or len(cands) != 1:
                    continue
                g.edge(uid_of[uid], uid_of[next(iter(cands))], target, PRIO_CALL)
            elif prefix in by_name and by_name[prefix] != uid:
                g.edge(uid_of[uid], uid_of[by_name[prefix]], member, PRIO_CALL)
            elif prefix and prefix not in by_name:
                name = "Any address" if prefix == LOWLEVEL else prefix
                ext_members.setdefault(name, {}).setdefault(uid, set()).add(member if kind != "delegatecall" else kind)
            elif not prefix and kind in ("value_transfer", "delegatecall", "cpi", "message"):
                ext_members.setdefault("Any address", {}).setdefault(uid, set()).add(target or kind)
    ext_ids: list[str] = []
    for name in sorted(ext_members, key=lambda n: (-sum(len(m) for m in ext_members[n].values()), n)):
        members = sorted({m for ms in ext_members[name].values() for m in ms})
        xid = g.node("x_", name, name, "ext", ", ".join(members), rank=len(members))
        ext_ids.append(xid)
        for uid, ms in sorted(ext_members[name].items()):
            for m in sorted(ms):
                g.edge(uid_of[uid], xid, m, PRIO_EXT)
    for uid, bl in sorted(bases.items()):
        for b in bl:
            if uid in uid_of and b in uid_of:
                g.edge(uid_of[uid], uid_of[b], "inherits", PRIO_INHERIT)

    # rows: actors, primary units, support units, externals; each capped with a summary node
    return _finish(g, {"p": _cap([uid_of[i] for i in primary], g, "u_more", "Other units", "scope"),
                       "s": _cap([uid_of[i] for i in support], g, "u_more_s", "Other units", "scope"),
                       "a": _cap(actor_ids, g, "a_more", "Other roles", "actor"),
                       "x": _cap(ext_ids, g, "x_more", "Other callees", "ext")})


# ------------------------------------------------------------------ roles table
def _signals(gated: list[dict[str, Any]], cats_of: dict[str, set[str]]) -> list[str]:
    rules = _rules()
    phrases: list[str] = []
    for s in rules["signals"]:
        hit = False
        for f in gated:
            name = _fn_name(f["span"])
            cats = cats_of.get(f["span"], set())
            writes = [w.get("var") or "" for w in f.get("writes") or []]
            calls = f.get("calls") or []
            if (cats & s["categories"] or any(p.search(name) for p in s["functions"])
                    or any(p.search(v) for p in s["writes"] for v in writes)
                    or any(c.get("kind") in s["call_kinds"] for c in calls)
                    or any(p.search((c.get("target") or "").rpartition(".")[2]) for p in s["call_members"] for c in calls)):
                hit = True
                break
        if hit and s["phrase"] not in phrases:
            phrases.append(s["phrase"])
        if len(phrases) >= int(rules["max_phrases"]):
            break
    return phrases


HOLDER_FACT = {"owner": "onchain.owner", "admin": "onchain.eip1967.admin"}
_ROLE_NOISE = frozenset({"only", "role", "roles", "check", "sender", "msg", "is", "has", "require", "when", "not"})


def _role_keys(role: str) -> list[str]:
    """Holder fact keys a role name may resolve through, most specific first: `onlyGovernance`
    → onchain.governance; `GUARDIAN_ROLE` → onchain.guardian; `onlyAdmin` → onchain.admin then
    the EIP-1967 admin slot; anything with `owner` → onchain.owner (mapping/facts.HOLDER_GETTERS)."""
    from soken_review.mapping.facts import HOLDER_GETTERS, holder_fact_key

    words = [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", role)]
    words = [w for w in words if w not in _ROLE_NOISE]
    getters = {g.lower(): g for g in HOLDER_GETTERS}
    keys: list[str] = []
    i = 0
    while i < len(words):
        pair = "".join(words[i:i + 2]) if i + 1 < len(words) else ""
        if pair in getters:                       # two-word getters: pendingOwner, feeRecipient
            keys.append(holder_fact_key(getters[pair]))
            i += 2
            continue
        w = words[i]
        if w == "owner":
            keys.append("onchain.owner")
        elif w in getters:
            keys.append(holder_fact_key(getters[w]))
            if w == "admin":
                keys.append("onchain.eip1967.admin")
        i += 1
    if not keys and re.search("owner", role, re.IGNORECASE):
        keys.append("onchain.owner")
    if not keys and re.search("admin", role, re.IGNORECASE):
        keys += ["onchain.admin", "onchain.eip1967.admin"]
    return list(dict.fromkeys(keys))
KIND_FACT_TYPES = {"eoa": "EOA", "multisig": "Multisig", "timelock": "Timelock", "contract": "Contract"}


def _holder_type(role_key: str | None, fv: dict[str, dict[str, Any]], map_kind: str | None) -> str:
    """Schema `type` from the chain_state holder facts (`onchain.<role>.holder_kind`, else the
    `holder_is_contract` flag), falling back to the map `holder_kind`; `Unknown` when nothing says."""
    if role_key:
        kind = fv.get(f"onchain.{role_key}.holder_kind")
        if kind and str(kind.get("value")) in KIND_FACT_TYPES:
            return KIND_FACT_TYPES[str(kind["value"])]
        flag = fv.get(f"onchain.{role_key}.holder_is_contract")
        if flag and str(flag.get("value")) in ("true", "false"):
            return "Contract" if str(flag["value"]) == "true" else "EOA"
    return HOLDER_TYPES.get(map_kind or "unknown", "Unknown")


def _holder(role: str, unit_is_deployed: bool, fv: dict[str, dict[str, Any]],
            map_kind: str | None) -> tuple[dict[str, str] | str, str]:
    """(holder cell, type) of a role row; the address facts apply to the deployed unit only."""
    keys = _role_keys(role) if unit_is_deployed else []
    rec, key = None, None
    for key in keys:
        rec = fv.get(key)
        if rec:
            break
    if not rec or key is None:
        return "Unknown", _holder_type(None, fv, map_kind)
    value = str(rec.get("value") or "")
    if ZERO_ADDR_RE.match(value):
        return "Renounced", _holder_type(None, fv, map_kind)
    if len(value) < 20:
        return "Unknown", _holder_type(None, fv, map_kind)
    # holder facts are keyed by the role token: onchain.<token>.holder_kind (facts.holder_facts)
    role_key = "admin" if key == "onchain.eip1967.admin" else key.removeprefix("onchain.")
    return {"addr": value}, _holder_type(role_key, fv, map_kind)


def _gated_labels(spans: list[str]) -> list[str]:
    """`Unit.fn` per gated span; the parameter list stays only when the name repeats (overloads)."""
    names = [span.partition("(")[0] for span in spans]
    return [span if names.count(n) > 1 else n for span, n in zip(spans, names, strict=True)]


def role_rows(map_doc: dict[str, Any] | None, facts: Any, job: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Report `roles.rows` (schema $defs.role_row): one row per role and unit, deployed unit first."""
    sem = _semantic(map_doc)
    if sem is None:
        return []
    fv = _fact_values(facts)
    by_name = {u["name"]: u["id"] for u in sem["units"]}
    fns = {f["span"]: f for f in sem.get("functions") or []}
    cats_of: dict[str, set[str]] = {}
    for cat, spans in (sem.get("category_to_functions") or {}).items():
        for s in spans:
            cats_of.setdefault(s, set()).add(cat)
    bases = _bases(sem)
    deployed = _deployed_unit_id(sem, fv, job, None)
    deployed_group = {deployed, *bases.get(deployed, [])} if deployed else set()
    rows: list[tuple[tuple[int, str, str], dict[str, Any]]] = []
    for r in sorted(sem.get("roles") or [], key=lambda r: r["name"]):
        label = INLINE_LABEL if r["name"] == INLINE_ROLE else r["name"]
        groups: dict[str, list[str]] = {}
        for span in sorted(r.get("gated_functions") or []):
            uid = by_name.get(_unit_name(span))
            if uid is None:
                continue
            key = deployed if uid in deployed_group else uid
            groups.setdefault(key, []).append(span)
        for uid, spans in groups.items():
            is_dep = uid == deployed
            unit_name = next(u["name"] for u in sem["units"] if u["id"] == uid)
            role = label if len(groups) == 1 else f"{label} ({unit_name})"
            gated = [fns[s] for s in spans if s in fns]
            phrases = _signals(gated, cats_of) or [_rules()["fallback"]]
            holder, kind = _holder(r["name"], is_dep, fv, r.get("holder_kind"))
            row = {"role": role[:300], "holder": holder, "type": kind,
                   "gated_functions": _gated_labels(spans)[:MAX_GATED],
                   "risk_note": "; ".join(phrases)[:300]}
            rows.append(((0 if is_dep else 1, unit_name, role), row))
    admin = fv.get("onchain.eip1967.admin")
    if admin and deployed and len(str(admin.get("value") or "")) >= 20:
        rows.append(((0, "", "Proxy admin"), {"role": "Proxy admin", "holder": {"addr": str(admin["value"])},
                                              "type": _holder_type("admin", fv, None), "gated_functions": [],
                                              "risk_note": next(s["phrase"] for s in _rules()["signals"]
                                                                if s["id"] == "code_change")}))
    return [row for _, row in sorted(rows, key=lambda kv: kv[0])][:MAX_ROLE_ROWS]
