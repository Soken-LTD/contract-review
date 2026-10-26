"""State-lifecycle signals for Solidity from the solc compact AST (feat/lifecycle-invariant-pass).

Pattern detectors look at one statement; the bugs this module points at only show up across a
sequence of states: a stored snapshot that survives the share supply returning to zero, a zero
branch that runs on the first deposit and again after the last exit, an accrual skipped while
nothing is staked although the clock still moves. The module finds the anchors of those
sequences deterministically and returns them as signals; `lifecycle.py` turns them into leads
and invariant walks. It never decides that a bug exists.

Signals (ids in `contract/rubric/invariants.yaml`):
  LC-EVM-STALE   a numeric state variable written as a snapshot (`v = expr` without `v` on the
                 right) by a non-admin path, coupled to a population measure (read next to it or
                 computed from it), with no reset anywhere: no `delete v`, no `v = 0`, no write in
                 a branch taken when the population is zero.
  LC-EVM-EMPTY   a function that branches on a population measure being zero.
  LC-EVM-ACCRUE  a function that skips an accumulator update while the population is zero but
                 writes a clock (last update time or block) on that path or unconditionally.
  LC-EVM-DIV     a division by a population measure in a function with no zero check on it.

Population measures (reference data in invariants.yaml `evm`): calls such as `totalSupply()`,
`totalAssets()`, `balanceOf(address(this))`, state variables such as `totalStaked`, and locals
initialised from either. Reads and writes are closed over internal callees and modifiers (depth
4), so a check in a helper counts for its callers. Dependency and test files feed the call graph
but never carry a signal. Pure: AST in, plain dicts out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .semantic_evm import SemanticBuilder, _Ctx, _is_zero_literal, _strip, _walk

_MAX_CLOSURE_DEPTH = 4
_MULDIV_RE = re.compile(r"^(mulDiv|mulDivDown|mulDivUp|mulDivRoundingUp|fullMulDiv|fullMulDivUp|divWadDown|divWadUp|"
                        r"divWad|wDiv|wdiv|div|divDown|divUp|ceilDiv)$")
_ASSIGN_ACCUM_OPS = frozenset({"+=", "-="})
_EMPTY_TRUE_OPS = frozenset({"==", "<="})        # P == 0, P <= 0: true means empty
_EMPTY_FALSE_OPS = frozenset({"!=", ">"})        # P != 0, P > 0: false means empty
_FLIP = {"==": "==", "!=": "!=", "<": ">", ">": "<", "<=": ">=", ">=": "<="}


@dataclass
class _Write:
    var: str                 # state variable name or struct member name
    line: int
    kind: str                # reset | assign | accum
    is_member: bool          # struct member (pool.lastRewardBlock), not a state variable
    empty_branch: bool       # inside the branch taken when a population is zero
    nonempty_branch: bool    # inside the branch taken when a population is not zero
    rhs_pop: bool            # right-hand side reads a population measure or calls a zero-branch function
    var_id: int | None = None
    rhs_time: bool = False   # right-hand side reads block.timestamp or block.number (a clock write)
    rhs_callees: tuple[int, ...] = ()   # functions called on the right-hand side


@dataclass
class _FnInfo:
    node: dict
    contract: dict
    path: str
    name: str
    span_id: str
    in_scope: bool
    is_entry: bool
    mutability: str
    writes: list[_Write] = field(default_factory=list)
    reads: set[int] = field(default_factory=set)          # state var ids read
    pop_subjects: set[str] = field(default_factory=set)   # population measures read
    empty_preds: list[tuple[int, str]] = field(default_factory=list)   # (line, subject), any zero check
    empty_branches: list[tuple[int, str]] = field(default_factory=list)  # (line, subject), if / ternary only
    divisions: list[tuple[int, str]] = field(default_factory=list)     # (line, subject)
    cond_reads: set[int] = field(default_factory=set)     # state vars read in require/if conditions
    callees: set[int] = field(default_factory=set)


class LifecycleEvm:
    def __init__(self, output: dict, texts: dict[str, str], compiled_texts: dict[str, str] | None,
                 semantic: dict | None, cfg: dict[str, Any]) -> None:
        self.ctx = _Ctx(output, texts, compiled_texts)
        self.pop_call_re = re.compile(cfg["population_calls"])
        self.pop_var_re = re.compile(cfg["population_vars"])
        self.clock_re = re.compile(cfg["clock_vars"])
        self.dep_re = re.compile(cfg["dependency_paths"])
        self.guarded: set[str] = set()
        for f in (semantic or {}).get("functions") or []:
            if any(g.get("class") == "caller_check" for g in f.get("guards") or []):
                self.guarded.add(f["span"])
        self.state_vars: dict[int, dict] = {}
        self.fns: dict[int, _FnInfo] = {}

    # ── public ──────────────────────────────────────────────────────────────

    def signals(self) -> list[dict[str, Any]]:
        if not self.ctx.asts:
            return []
        self._index()
        for info in self.fns.values():
            self._analyze(info)
        closure = {fid: self._closure(fid) for fid in self.fns}
        out: list[dict[str, Any]] = []
        out += self._stale(closure)
        out += self._empty(closure)
        out += self._accrue(closure)
        out += self._div(closure)
        return out

    # ── indexing ────────────────────────────────────────────────────────────

    def _in_scope(self, path: str) -> bool:
        return not self.dep_re.search(path)

    def _index(self) -> None:
        ctx = self.ctx
        for nid, n in ctx.nodes.items():
            t = n.get("nodeType")
            if t == "VariableDeclaration" and n.get("stateVariable"):
                self.state_vars[nid] = n
            elif t in ("FunctionDefinition", "ModifierDefinition") and isinstance(n.get("body"), dict):
                contract = ctx.parent_contract.get(nid)
                if contract is None:
                    continue
                path = ctx.node_path[nid]
                name = SemanticBuilder._fn_name(n, contract) if t == "FunctionDefinition" else n.get("name") or ""
                params = [SemanticBuilder._param_type(p) for p in (n.get("parameters") or {}).get("parameters") or []]
                span_id = f"{contract.get('name')}.{name}({','.join(params)})"
                is_entry = (t == "FunctionDefinition" and contract.get("contractKind") == "contract"
                            and name not in ("constructor",)
                            and (n.get("visibility") or "public") in ("public", "external"))
                self.fns[nid] = _FnInfo(node=n, contract=contract, path=path, name=name, span_id=span_id,
                                        in_scope=self._in_scope(path), is_entry=is_entry,
                                        mutability=n.get("stateMutability") or ("nonpayable" if t == "FunctionDefinition" else "modifier"))

    def _line(self, node: dict) -> int:
        loc = self.ctx.loc(node)
        return loc[1] if loc else 0

    def _state_var(self, node: dict) -> dict | None:
        if node.get("nodeType") != "Identifier":
            return None
        ref = node.get("referencedDeclaration")
        return self.state_vars.get(ref) if isinstance(ref, int) else None

    # ── population measures ────────────────────────────────────────────────

    def _pop_subject(self, e: Any, aliases: dict[int, str]) -> str | None:
        """Name of the population measure an expression is, or None."""
        if not isinstance(e, dict):
            return None
        e = _strip(e)
        t = e.get("nodeType")
        if t == "Identifier":
            ref = e.get("referencedDeclaration")
            if isinstance(ref, int) and ref in aliases:
                return aliases[ref]
            sv = self._state_var(e)
            if sv is not None and self.pop_var_re.match(sv.get("name") or ""):
                return sv["name"]
            return None
        if t == "MemberAccess":
            # storage struct member such as pool.totalStaked
            name = e.get("memberName") or ""
            if self.pop_var_re.match(name) and (e.get("typeDescriptions") or {}).get("typeString", "").startswith(("uint", "int")):
                return name
            return None
        if t == "FunctionCall":
            ex = e.get("expression") or {}
            if ex.get("nodeType") == "FunctionCallOptions":
                ex = ex.get("expression") or {}
            name = ex.get("name") or ex.get("memberName") or ""
            if self.pop_call_re.match(name):
                return f"{name}()"
            if name == "balanceOf" and len(e.get("arguments") or []) == 1 and _is_this(e["arguments"][0]):
                return "balanceOf(this)"
        return None

    def _empty_pred(self, cond: Any, aliases: dict[int, str]) -> tuple[str, bool] | None:
        """(subject, true_means_empty) when `cond` is or contains `P == 0` and friends."""
        for n in _walk(cond):
            if n.get("nodeType") != "BinaryOperation":
                continue
            op = n.get("operator")
            left, right = n.get("leftExpression") or {}, n.get("rightExpression") or {}
            if _is_zero_literal(right):
                subj = self._pop_subject(left, aliases)
            elif _is_zero_literal(left):
                subj = self._pop_subject(right, aliases)
                op = _FLIP.get(op, op)
            else:
                continue
            if subj is None:
                continue
            if op in _EMPTY_TRUE_OPS:
                return subj, True
            if op in _EMPTY_FALSE_OPS:
                return subj, False
        return None

    # ── per-function body analysis ──────────────────────────────────────────

    def _analyze(self, info: _FnInfo) -> None:
        body = info.node.get("body")
        aliases: dict[int, str] = {}
        # locals initialised from a population measure: `uint256 supply = totalSupply();`
        for n in _walk(body):
            if n.get("nodeType") == "VariableDeclarationStatement":
                decls = n.get("declarations") or []
                if len(decls) == 1 and isinstance(decls[0], dict):
                    subj = self._pop_subject(n.get("initialValue"), aliases)
                    if subj is not None:
                        aliases[decls[0]["id"]] = subj
        # modifiers invoked by the function are callees
        for m in info.node.get("modifiers") or []:
            ref = (m.get("modifierName") or {}).get("referencedDeclaration")
            if isinstance(ref, int) and ref in self.fns:
                info.callees.add(ref)
        self._visit(body, info, aliases, empty=False, nonempty=False)

    def _visit(self, node: Any, info: _FnInfo, aliases: dict[int, str], empty: bool, nonempty: bool) -> None:
        stack: list[tuple[Any, bool, bool]] = [(node, empty, nonempty)]
        while stack:
            n, emp, nonemp = stack.pop()
            if isinstance(n, list):
                stack.extend((v, emp, nonemp) for v in n)
                continue
            if not isinstance(n, dict):
                continue
            t = n.get("nodeType")
            if t in ("IfStatement", "Conditional"):
                cond = n.get("condition")
                pred = self._empty_pred(cond, aliases)
                self._reads(cond, info, aliases, in_cond=True)
                if pred is not None:
                    info.empty_preds.append((self._line(cond or n), pred[0]))
                    info.empty_branches.append((self._line(cond or n), pred[0]))
                    t_body = n.get("trueBody") if t == "IfStatement" else n.get("trueExpression")
                    f_body = n.get("falseBody") if t == "IfStatement" else n.get("falseExpression")
                    true_empty = pred[1]
                    stack.append((t_body, emp or true_empty, nonemp or not true_empty))
                    stack.append((f_body, emp or not true_empty, nonemp or true_empty))
                    # `if (P == 0) return;` makes the rest of the block the non-empty path; the
                    # block-level handling below marks statements after an early exit.
                else:
                    stack.append((n.get("trueBody") if t == "IfStatement" else n.get("trueExpression"), emp, nonemp))
                    stack.append((n.get("falseBody") if t == "IfStatement" else n.get("falseExpression"), emp, nonemp))
                continue
            if t == "Block" or t == "UncheckedBlock":
                stmts = n.get("statements") or []
                after_exit = None
                for st in stmts:
                    if after_exit is None:
                        stack.append((st, emp, nonemp))
                    else:
                        stack.append((st, emp or after_exit, nonemp or not after_exit))
                    exit_kind = self._early_exit(st, aliases)
                    if exit_kind is not None and after_exit is None:
                        after_exit = exit_kind   # True: the rest runs only when empty
                continue
            if t == "FunctionCall":
                self._call(n, info, aliases)
                name = _callee_name(n)
                if name in ("require", "assert"):
                    args = n.get("arguments") or []
                    if args:
                        self._reads(args[0], info, aliases, in_cond=True)
                        pred = self._empty_pred(args[0], aliases)
                        if pred is not None:
                            info.empty_preds.append((self._line(n), pred[0]))
                    for a in args[1:]:
                        stack.append((a, emp, nonemp))
                    continue
                stack.extend((a, emp, nonemp) for a in (n.get("arguments") or []))
                stack.append((n.get("expression"), emp, nonemp))
                continue
            if t == "Assignment":
                self._assignment(n, info, aliases, emp, nonemp)
                stack.append((n.get("rightHandSide"), emp, nonemp))
                lhs = n.get("leftHandSide") or {}
                if lhs.get("nodeType") == "IndexAccess":
                    stack.append((lhs.get("indexExpression"), emp, nonemp))
                continue
            if t == "UnaryOperation" and n.get("operator") in ("delete", "++", "--"):
                target = self._target(n.get("subExpression") or {})
                if target is not None:
                    name, var_id, is_member = target
                    kind = "reset" if n.get("operator") == "delete" else "accum"
                    info.writes.append(_Write(name, self._line(n), kind, is_member, emp, nonemp, False, var_id))
                continue
            if t == "BinaryOperation":
                if n.get("operator") == "/":
                    subj = self._pop_subject(n.get("rightExpression"), aliases)
                    if subj is not None:
                        info.divisions.append((self._line(n), subj))
                pred = self._empty_pred(n, aliases) if n.get("operator") in ("==", "!=", ">", "<", "<=", ">=") else None
                if pred is not None:
                    info.empty_preds.append((self._line(n), pred[0]))
                stack.append((n.get("leftExpression"), emp, nonemp))
                stack.append((n.get("rightExpression"), emp, nonemp))
                continue
            if t == "Identifier":
                sv = self._state_var(n)
                if sv is not None:
                    info.reads.add(sv["id"])
                subj = self._pop_subject(n, aliases)
                if subj is not None:
                    info.pop_subjects.add(subj)
                continue
            if t == "MemberAccess":
                subj = self._pop_subject(n, aliases)
                if subj is not None:
                    info.pop_subjects.add(subj)
                stack.append((n.get("expression"), emp, nonemp))
                continue
            for k, v in n.items():
                if isinstance(v, (dict, list)) and k not in ("typeDescriptions", "documentation"):
                    stack.append((v, emp, nonemp))

    def _early_exit(self, st: dict, aliases: dict[int, str]) -> bool | None:
        """`if (P == 0) return/revert;` -> False (the rest runs only when not empty);
        `if (P != 0) return;` -> True."""
        if not isinstance(st, dict) or st.get("nodeType") != "IfStatement" or st.get("falseBody") is not None:
            return None
        pred = self._empty_pred(st.get("condition"), aliases)
        if pred is None:
            return None
        body = st.get("trueBody") or {}
        exits = any(x.get("nodeType") in ("Return", "RevertStatement") or
                    (x.get("nodeType") == "FunctionCall" and _callee_name(x) == "revert") for x in _walk(body))
        if not exits:
            return None
        return not pred[1]

    def _reads(self, expr: Any, info: _FnInfo, aliases: dict[int, str], in_cond: bool) -> None:
        for n in _walk(expr):
            sv = self._state_var(n)
            if sv is not None:
                info.reads.add(sv["id"])
                if in_cond:
                    info.cond_reads.add(sv["id"])
            subj = self._pop_subject(n, aliases)
            if subj is not None:
                info.pop_subjects.add(subj)
            if n.get("nodeType") == "FunctionCall":
                self._call(n, info, aliases)

    def _call(self, call: dict, info: _FnInfo, aliases: dict[int, str]) -> None:
        ex = call.get("expression") or {}
        if ex.get("nodeType") == "FunctionCallOptions":
            ex = ex.get("expression") or {}
        ref = ex.get("referencedDeclaration")
        internal = ex.get("nodeType") == "Identifier" or (
            ex.get("nodeType") == "MemberAccess" and _is_internal_member(ex, self.ctx))
        if isinstance(ref, int) and ref in self.fns and internal:
            info.callees.add(ref)
        subj = self._pop_subject(call, aliases)
        if subj is not None:
            info.pop_subjects.add(subj)
        name = ex.get("name") or ex.get("memberName") or ""
        args = call.get("arguments") or []
        if _MULDIV_RE.match(name) and args:
            # x.mulDiv(y, P) (using-for, two args) or mulDiv(x, y, P): the divisor is the last argument
            subj = self._pop_subject(args[-1], aliases)
            if subj is not None and (len(args) >= 2 or name in ("div", "divDown", "divUp", "wdiv", "wDiv", "divWad",
                                                                   "divWadDown", "divWadUp", "ceilDiv")):
                info.divisions.append((self._line(call), subj))

    def _target(self, lhs: dict) -> tuple[str, int | None, bool] | None:
        lhs = _strip(lhs)
        if lhs.get("nodeType") == "Identifier":
            sv = self._state_var(lhs)
            if sv is not None:
                return sv.get("name") or "", sv["id"], False
            return None
        if lhs.get("nodeType") == "MemberAccess":
            base = lhs.get("expression") or {}
            if (base.get("typeDescriptions") or {}).get("typeString", "").endswith(" storage pointer") or \
                    (base.get("typeDescriptions") or {}).get("typeString", "").endswith(" storage ref"):
                return lhs.get("memberName") or "", None, True
        return None

    def _assignment(self, n: dict, info: _FnInfo, aliases: dict[int, str], emp: bool, nonemp: bool) -> None:
        target = self._target(n.get("leftHandSide") or {})
        if target is None:
            return
        name, var_id, is_member = target
        rhs = n.get("rightHandSide") or {}
        op = n.get("operator")
        if op in _ASSIGN_ACCUM_OPS:
            kind = "accum"
        elif op == "=" and _is_zero_literal(rhs):
            kind = "reset"
        elif op == "=" and var_id is not None and any(
                x.get("nodeType") == "Identifier" and x.get("referencedDeclaration") == var_id for x in _walk(rhs)):
            kind = "accum"            # v = v + x
        else:
            kind = "assign"
        rhs_pop = any(self._pop_subject(x, aliases) is not None for x in _walk(rhs))
        rhs_callees = tuple(ref for x in _walk(rhs) if x.get("nodeType") == "FunctionCall"
                            for ref in [(x.get("expression") or {}).get("referencedDeclaration")]
                            if isinstance(ref, int) and ref in self.fns)
        if op == "=" and rhs.get("nodeType") == "Conditional" and self._empty_pred(rhs.get("condition"), aliases):
            emp = True                # v = P == 0 ? a : b handles the empty case
        rhs_time = any(x.get("nodeType") == "MemberAccess" and x.get("memberName") in ("timestamp", "number")
                       and (x.get("expression") or {}).get("name") == "block" for x in _walk(rhs)) or any(
            x.get("nodeType") == "Identifier" and x.get("name") == "now" for x in _walk(rhs))
        info.writes.append(_Write(name, self._line(n), kind, is_member, emp, nonemp, rhs_pop, var_id, rhs_time,
                                  rhs_callees))

    # ── closure ─────────────────────────────────────────────────────────────

    def _closure(self, fid: int) -> set[int]:
        seen = {fid}
        frontier = [fid]
        for _ in range(_MAX_CLOSURE_DEPTH):
            nxt = []
            for f in frontier:
                for c in self.fns[f].callees:
                    if c not in seen:
                        seen.add(c)
                        nxt.append(c)
            frontier = nxt
        return seen

    def _has_pred(self, closure: set[int], subject: str | None = None) -> bool:
        return any(subject is None or s == subject for c in closure for _, s in self.fns[c].empty_preds)

    def _admin_only(self, info: _FnInfo) -> bool:
        return info.span_id in self.guarded or info.name in ("constructor",) or \
            info.name.lower().startswith("initiali")

    # ── signals ─────────────────────────────────────────────────────────────

    def _numeric(self, var_id: int) -> bool:
        node = self.state_vars.get(var_id) or {}
        if node.get("constant") or node.get("mutability") in ("constant", "immutable"):
            return False
        ts = (node.get("typeDescriptions") or {}).get("typeString", "")
        return ts.startswith(("uint", "int"))

    def _stale(self, closure: dict[int, set[int]]) -> list[dict[str, Any]]:
        out = []
        entries = [fid for fid, f in self.fns.items() if f.is_entry and not self._admin_only(f)
                   and f.mutability not in ("view", "pure")]
        resets: set[int] = set()
        clocks: set[int] = set()
        for f in self.fns.values():
            for w in f.writes:
                if w.var_id is not None and (w.kind == "reset" or w.empty_branch):
                    resets.add(w.var_id)
                if w.var_id is not None and w.rhs_time:
                    clocks.add(w.var_id)
        for var_id, node in self.state_vars.items():
            path = self.ctx.node_path.get(var_id, "")
            name = node.get("name") or ""
            if not self._in_scope(path) or not self._numeric(var_id) or var_id in resets or var_id in clocks:
                continue
            if self.pop_var_re.match(name) or self.clock_re.search(name):
                continue
            # snapshot writes by a non-admin entry path
            writer_hits: list[tuple[_FnInfo, _Write]] = []
            writer_entries: set[str] = set()
            for e in entries:
                for c in closure[e]:
                    for w in self.fns[c].writes:
                        # `v = f()` where f reads v is an accumulator update (Synthetix
                        # rewardPerTokenStored), not a snapshot: LC-EVM-ACCRUE covers it
                        if w.var_id == var_id and w.kind == "assign" and not any(
                                var_id in self.fns[x].reads for k in w.rhs_callees if k in closure
                                for x in closure[k]):
                            writer_hits.append((self.fns[c], w))
                            writer_entries.add(self.fns[e].name)
            if not writer_hits:
                continue
            # coupling: a function reading the variable also reads a population measure, or a
            # snapshot write computes from one
            subjects: set[str] = set()
            readers: set[str] = set()
            for fid, f in self.fns.items():
                cl = closure[fid]
                if not any(var_id in self.fns[c].reads for c in cl):
                    continue
                pops = set().union(*(self.fns[c].pop_subjects for c in cl))
                if pops:
                    subjects |= pops
                    if f.is_entry or f.in_scope:
                        readers.add(f.name)
            for f, w in writer_hits:
                if w.rhs_pop:
                    subjects |= f.pop_subjects or {"the population"}
            if not subjects:
                continue
            # strength: read in a zero-branch function, a condition, or as a divisor
            strong = any(var_id in self.fns[c].cond_reads for fid in self.fns for c in closure[fid]) or any(
                self.fns[fid].empty_preds and any(var_id in self.fns[c].reads for c in closure[fid]) for fid in self.fns)
            f0, w0 = min(writer_hits, key=lambda h: (not h[0].in_scope, h[0].path, h[1].line))
            if not f0.in_scope:
                continue
            out.append({
                "signal": "LC-EVM-STALE", "file": f0.path, "start": w0.line, "end": w0.line,
                "unit": f"{f0.path}:{f0.contract.get('name')}", "strong": strong,
                "score": 90 if strong else 60,
                "params": {"var": name, "writers": _names(writer_entries), "readers": _names(readers),
                           "subject": _subject(subjects)},
                "names": sorted({name, *writer_entries}),
            })
        return out

    def _empty(self, closure: dict[int, set[int]]) -> list[dict[str, Any]]:
        out = []
        callers: dict[int, set[int]] = {}
        for fid, cl in closure.items():
            for c in cl:
                if c != fid:
                    callers.setdefault(c, set()).add(fid)
        for fid, f in self.fns.items():
            if not f.in_scope or not f.empty_branches:
                continue
            line, subj = min(f.empty_branches)
            # a zero branch matters when state changes on it: the function itself or a caller writes;
            # an admin-only function keeps a low grade (its caller is trusted)
            mutating = (f.mutability not in ("view", "pure") or any(
                self.fns[c].mutability not in ("view", "pure", "modifier") for c in callers.get(fid, ()))) \
                and not self._admin_only(f)
            read_vars = {self.state_vars[v].get("name") or "" for c in closure[fid] for v in self.fns[c].reads
                         if v in self.state_vars and self._numeric(v)
                         and not self.pop_var_re.match(self.state_vars[v].get("name") or "")}
            out.append({
                "signal": "LC-EVM-EMPTY", "file": f.path, "start": line, "end": line,
                "unit": f"{f.path}:{f.contract.get('name')}", "strong": mutating,
                "score": 70 if mutating else 30,
                "params": {"fn": f.name, "subject": subj, "vars": _names(read_vars, 5) or "none"},
                "names": [f.name],
            })
        return out

    def _accrue(self, closure: dict[int, set[int]]) -> list[dict[str, Any]]:
        out = []
        for fid, f in self.fns.items():
            if not f.in_scope:
                continue
            cl = closure[fid]
            preds = [(ln, s) for c in cl for ln, s in self.fns[c].empty_preds]
            if not preds:
                continue
            # a clock: written from block.timestamp or block.number, or named like one (lastUpdateTime)
            clocks = [w for w in f.writes if (w.rhs_time or self.clock_re.search(w.var)) and w.kind != "reset"]
            # an accrual skipped while empty, written in the same function as the clock: inside the
            # non-empty branch, or computed by a callee that returns early on an empty population
            # (Synthetix rewardPerToken)
            accum_names: set[str] = set()
            for w in f.writes:
                if w.rhs_time or self.clock_re.search(w.var) or w.kind == "reset" or w.empty_branch:
                    continue
                if w.nonempty_branch or any(self._has_pred(closure[c]) for c in w.rhs_callees if c in closure):
                    accum_names.add(w.var)
            accum_names -= {w.var for w in clocks}
            if not clocks or not accum_names:
                continue
            _, subj = min(preds)
            anchor = min(clocks, key=lambda w: w.line)
            out.append({
                "signal": "LC-EVM-ACCRUE", "file": f.path, "start": anchor.line, "end": anchor.line,
                "unit": f"{f.path}:{f.contract.get('name')}", "strong": True, "score": 80,
                "params": {"fn": f.name, "subject": subj, "accumulators": _names(accum_names),
                           "clocks": _names({w.var for w in clocks})},
                "names": [f.name],
            })
        return out

    def _div(self, closure: dict[int, set[int]]) -> list[dict[str, Any]]:
        out = []
        callers: dict[int, set[int]] = {}
        for fid, cl in closure.items():
            for c in cl:
                callers.setdefault(c, set()).add(fid)
        for fid, f in self.fns.items():
            if not f.in_scope or not f.divisions:
                continue
            for line, subj in sorted(f.divisions):
                guarded = self._has_pred(closure[fid], subj) or any(
                    self._has_pred({c}, subj) for c in callers.get(fid, ()))
                if guarded:
                    continue
                out.append({
                    "signal": "LC-EVM-DIV", "file": f.path, "start": line, "end": line,
                    "unit": f"{f.path}:{f.contract.get('name')}", "strong": False, "score": 20,
                    "params": {"fn": f.name, "subject": subj}, "names": [f.name],
                })
                break
        return out


def _callee_name(call: dict) -> str:
    ex = call.get("expression") or {}
    if ex.get("nodeType") == "FunctionCallOptions":
        ex = ex.get("expression") or {}
    return ex.get("name") or ex.get("memberName") or ""


def _is_this(e: Any) -> bool:
    if not isinstance(e, dict):
        return False
    e = _strip(e)
    if e.get("nodeType") == "Identifier" and e.get("name") == "this":
        return True
    if e.get("nodeType") == "FunctionCall" and e.get("kind") == "typeConversion":
        args = e.get("arguments") or []
        return len(args) == 1 and _is_this(args[0])
    return False


def _is_internal_member(ex: dict, ctx: _Ctx) -> bool:
    """`super.f()`, `Library.f()` (internal library call) or a using-for call into a library."""
    base = ex.get("expression") or {}
    if base.get("nodeType") == "Identifier" and base.get("name") == "super":
        return True
    ref = ex.get("referencedDeclaration")
    target_contract = ctx.parent_contract.get(ref) if isinstance(ref, int) else None
    return target_contract is not None and target_contract.get("contractKind") == "library"


def _names(items: set[str] | list[str], cap: int = 3) -> str:
    vals = sorted({i for i in items if i})
    if not vals:
        return ""
    head = ", ".join(vals[:cap])
    return head + (f" and {len(vals) - cap} more" if len(vals) > cap else "")


def _subject(subjects: set[str]) -> str:
    vals = sorted(s for s in subjects if s != "the population") or ["the population"]
    return vals[0] if len(vals) == 1 else f"{vals[0]} or {vals[1]}"


def evm_signals(output: dict | None, texts: dict[str, str], compiled_texts: dict[str, str] | None,
                semantic: dict | None, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Lifecycle signals for a solc standard-JSON output; [] when there is no AST."""
    if not output:
        return []
    return LifecycleEvm(output, texts, compiled_texts, semantic, cfg).signals()
