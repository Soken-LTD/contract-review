"""Semantic layer of `map.v1` for Solidity from the solc compact AST (04 section 2.1, 7.5, 8.5).

`build_semantic(solc_output, texts, enums)` reads `sources[path].ast` of the build's standard-JSON
output (the build requests `ast` for every source) and returns the `semantic` object plus the span
ids per (path, start line). Pure: the caller loads the files.

Rules (04 2.1): a guard reached through a modifier, an inherited base or an internal callee is
listed on the function with the line where it executes; unit ids are `<path>:<UnitName>`; names
are validated against the Solidity identifier grammar, so free text from code never enters the map.
Used by EVM, HyperEVM and TRON (same compiler output format).

Dependencies (2026-10-27, Apyee blind run): every source the compiler saw is indexed for name
resolution, so a modifier, base contract or internal callee that lives in `node_modules/` or
`lib/` (OpenZeppelin `onlyOwner`, `whenNotPaused`, `nonReentrant`) is followed like one in the
reviewed tree. Units, functions and spans are still emitted for the pinned files only. A guard
that executes in an unpinned file is listed on the nearest reviewed line that applies it (the
modifier invocation on the function header, or the internal call site) with `via` naming the
dependency line, because fp_guarded quotes pinned lines only.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Any

_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,63}$")   # 04 2.1 identifier grammar, length-capped
_SENDER_FN_RE = re.compile(r"msgsender", re.IGNORECASE)
_CHECK_FN_RE = re.compile(r"role|auth|owner|admin|allowed|whitelist|operator|guardian|keeper|minter|"
                          r"check|only|isvalid|verify|governance|governor|manager", re.IGNORECASE)
_REENTRANCY_MOD_RE = re.compile(r"nonreentrant|noreentran|reentrancy|^lock$|^locked$|mutex", re.IGNORECASE)
_INIT_MOD_RE = re.compile(r"^(initializer|reinitializer|onlyinitializing)$", re.IGNORECASE)
_PAUSE_RE = re.compile(r"paused", re.IGNORECASE)
_ORACLE_MEMBERS = frozenset({"latestRoundData", "latestAnswer", "getRoundData", "getPrice", "getReserves",
                             "consult", "observe", "slot0", "getAssetPrice", "price", "read", "peek"})
_TOKEN_MEMBERS = frozenset({"transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "approve",
                            "safeApprove", "forceApprove", "safeIncreaseAllowance", "safeTransferETH",
                            "safeTransferAllETH", "forceSafeTransferETH", "permit"})
_LOWLEVEL = frozenset({"call", "delegatecall", "staticcall", "send", "callcode"})
_UPGRADE_FNS = frozenset({"upgradeTo", "upgradeToAndCall", "_authorizeUpgrade"})
_MAX_DEPTH = 3

# 13: category -> features an entry function must have to be a candidate. Categories without a
# row have no candidates from the map (coverage `no_candidates`); `never` marks chain extras the
# map cannot see.
_CATEGORY_FEATURES: dict[str, tuple[str, ...]] = {
    "evm.access_control": ("writes_state",),
    "evm.selfdestruct": ("selfdestruct",),
    "evm.centralization": ("caller_guard",),
    "evm.upgradeability.initialization": ("initializer",),
    "evm.upgradeability.storage_authority": ("upgrade",),
    "evm.delegatecall_proxy": ("delegatecall",),
    "evm.storage": ("upgradeable_unit", "writes_state"),
    "evm.reentrancy": ("external_call",),
    "evm.ordering_mev": ("value_flow",),
    "evm.unchecked_call": ("lowlevel_call",),
    "evm.arithmetic_precision": ("arithmetic",),
    "evm.accounting_logic": ("writes_state",),
    "evm.token_integration": ("token_call",),
    "evm.oracle_manipulation": ("oracle",),
    "evm.randomness": ("randomness",),
    "evm.timestamp": ("timestamp",),
    "evm.signature_replay": ("signature",),
    "evm.dos": ("loop",),
    "evm.input_validation": ("has_params", "writes_state"),
    "evm.other": (),
    "evm.events": ("writes_state",),
    "evm.best_practice": (),
}


@dataclass
class _Fn:
    node: dict
    contract: dict
    path: str
    span_id: str
    kind: str                     # function | modifier
    pinned: bool = True           # declared in a pinned (reviewed) file
    guards: list[tuple[str, str, str]] = field(default_factory=list)  # (class, path:line, via path:line or "")
    calls: list[dict] = field(default_factory=list)
    writes: list[dict] = field(default_factory=list)
    reads: list[dict] = field(default_factory=list)
    features: set[str] = field(default_factory=set)
    internal_callees: list[int] = field(default_factory=list)
    hints: list[tuple[str, str, str]] = field(default_factory=list)  # name_only guard hints (class, line, via)
    role_names: set[str] = field(default_factory=set)


def _line_starts(text: str) -> list[int]:
    """Byte offsets at which lines start, counting CRLF, lone CR and LF as one line break each.

    This is the same line rule the pin applies (`_lf_normalize`: CRLF and lone CR -> LF), so a
    line number computed from the compiled bytes names the same line in the LF-normalised text.
    """
    data = text.encode("utf-8")
    starts = [0]
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b == 0x0A:
            starts.append(i + 1)
        elif b == 0x0D:
            if i + 1 < n and data[i + 1] == 0x0A:
                i += 1
            starts.append(i + 1)
        i += 1
    return starts


class _Ctx:
    def __init__(self, output: dict, texts: dict[str, str], compiled_texts: dict[str, str] | None = None,
                 index_all: bool = False) -> None:
        """`texts` are the pinned (LF) files; `compiled_texts` the bytes the compiler actually saw
        for the same paths (the fetched Standard JSON keeps CRLF so the rebuild can be exact).
        solc `src` offsets are byte offsets into the compiled text, so lines must be resolved
        against it: resolving them against the LF text shifts every function after a CR down by
        the number of CRs before it (MasterChef 2026-10-22). Paths without a compiled text fall
        back to the pinned text.

        `index_all`: index every source with an AST, pinned or not, so references into
        dependencies (`node_modules/`, `lib/`) resolve. `asts` then holds the pinned files only
        (the emitted layer), `dep_asts` the rest; a dependency without any text keeps its nodes
        but resolves no lines (`loc` is None there)."""
        self.paths: dict[int, str] = {}
        self.line_starts: dict[str, list[int]] = {}
        self.nodes: dict[int, dict] = {}
        self.parent_contract: dict[int, dict] = {}
        self.node_path: dict[int, str] = {}
        self.asts: dict[str, dict] = {}
        self.dep_asts: dict[str, dict] = {}
        self.pinned: frozenset[str] = frozenset(texts)
        compiled_texts = compiled_texts or {}
        for path, src in (output.get("sources") or {}).items():
            ast = src.get("ast")
            if not isinstance(ast, dict):
                continue
            is_pinned = path in texts
            if not is_pinned and not index_all:
                continue
            self.paths[int(src.get("id", ast.get("src", "0:0:0").split(":")[2]))] = path
            (self.asts if is_pinned else self.dep_asts)[path] = ast
            text = compiled_texts.get(path) if not is_pinned else (compiled_texts.get(path) or texts[path])
            if text is not None:
                self.line_starts[path] = _line_starts(text)
        for path, ast in (*self.asts.items(), *self.dep_asts.items()):
            self._index(ast, path, None)

    def _index(self, node: Any, path: str, contract: dict | None) -> None:
        stack = [(node, contract)]
        while stack:
            n, c = stack.pop()
            if isinstance(n, dict):
                if n.get("nodeType") == "ContractDefinition":
                    c = n
                nid = n.get("id")
                if isinstance(nid, int) and "nodeType" in n:
                    self.nodes[nid] = n
                    self.node_path[nid] = path
                    if c is not None:
                        self.parent_contract[nid] = c
                stack.extend((v, c) for v in n.values() if isinstance(v, (dict, list)))
            elif isinstance(n, list):
                stack.extend((v, c) for v in n if isinstance(v, (dict, list)))

    def loc(self, node: dict) -> tuple[str, int] | None:
        """(path, 1-based line) of a node's `src` start."""
        try:
            start, _length, idx = (int(x) for x in str(node.get("src", "")).split(":")[:3])
        except ValueError:
            return None
        path = self.paths.get(idx)
        if path is None or start < 0 or path not in self.line_starts:
            return None
        return path, bisect.bisect_right(self.line_starts[path], start)

    def end_line(self, node: dict) -> int | None:
        try:
            start, length, idx = (int(x) for x in str(node.get("src", "")).split(":")[:3])
        except ValueError:
            return None
        path = self.paths.get(idx)
        if path is None or path not in self.line_starts:
            return None
        return bisect.bisect_right(self.line_starts[path], max(start, start + length - 1))

    def ref(self, line: tuple[str, int] | None) -> str | None:
        return f"{line[0]}:{line[1]}" if line else None

    def path_of(self, node: dict) -> str | None:
        """Source path of a node, with or without a resolvable line."""
        try:
            idx = int(str(node.get("src", "")).split(":")[2])
        except (ValueError, IndexError):
            return None
        return self.paths.get(idx)

    def in_pin(self, ref: str) -> bool:
        """True when a `path:line` reference (or a bare path) names a pinned file."""
        path, sep, line = ref.rpartition(":")
        return (path if sep and line.isdigit() else ref) in self.pinned


def _walk(node: Any):
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            yield n
            stack.extend(v for v in reversed(list(n.values())) if isinstance(v, (dict, list)))
        elif isinstance(n, list):
            stack.extend(v for v in reversed(n) if isinstance(v, (dict, list)))


def _type_str(node: dict | None) -> str:
    return ((node or {}).get("typeDescriptions") or {}).get("typeString") or ""


def _is_sender(node: dict, senders: frozenset[int] = frozenset()) -> bool:
    """msg.sender, a no-argument `_msgSender()` call, or a parameter bound to one of them (not tx.origin)."""
    t = node.get("nodeType")
    if t == "MemberAccess" and node.get("memberName") == "sender":
        base = node.get("expression") or {}
        return base.get("nodeType") == "Identifier" and base.get("name") == "msg"
    if t == "FunctionCall":
        ex = node.get("expression") or {}
        name = ex.get("name") or ex.get("memberName") or ""
        return bool(_SENDER_FN_RE.search(name)) and not (node.get("arguments") or [])
    if t == "Identifier" and senders:
        return node.get("referencedDeclaration") in senders
    return False


def _contains_sender(node: Any, senders: frozenset[int] = frozenset()) -> bool:
    return any(_is_sender(n, senders) for n in _walk(node))


def _callee_name(call: dict) -> str:
    ex = call.get("expression") or {}
    if ex.get("nodeType") == "FunctionCallOptions":
        ex = ex.get("expression") or {}
    return ex.get("name") or ex.get("memberName") or ""


def _strip(e: dict) -> dict:
    """Unwrap `(expr)`."""
    while e.get("nodeType") == "TupleExpression" and len(e.get("components") or []) == 1:
        e = (e.get("components") or [{}])[0] or {}
    return e


def _contains_tx_origin(node: Any) -> bool:
    return any(n.get("nodeType") == "MemberAccess" and n.get("memberName") == "origin"
               and (n.get("expression") or {}).get("name") == "tx" for n in _walk(node))


def _is_zero_literal(value: Any) -> bool:
    """`0`, `address(0)` and friends as a constant initializer."""
    if not isinstance(value, dict):
        return False
    v = _strip(value)
    if v.get("nodeType") == "FunctionCall" and v.get("kind") == "typeConversion":
        args = v.get("arguments") or []
        return len(args) == 1 and _is_zero_literal(args[0])
    return v.get("nodeType") == "Literal" and str(v.get("value")) in ("0", "0x0", "0x00")


def _yul_caller_eq_sload(cond: dict) -> bool:
    """`if iszero(eq(caller(), sload(s)))` or `if xor(caller(), sload(s))`: revert unless caller is stored."""
    def name(n: dict) -> str:
        return (n.get("functionName") or {}).get("name") or ""

    def pair(args: list) -> bool:
        if len(args) != 2:
            return False
        has_caller = any(name(a) == "caller" for a in args)
        has_sload = any(any(name(z) == "sload" for z in _walk(a)) for a in args if name(a) != "caller")
        return has_caller and has_sload

    if name(cond) == "iszero":
        inner = (cond.get("arguments") or [{}])[0] or {}
        return name(inner) == "eq" and pair(inner.get("arguments") or [])
    return name(cond) in ("xor", "sub") and pair(cond.get("arguments") or [])


def _is_revert_body_yul(node: Any) -> bool:
    return any((y.get("functionName") or {}).get("name") in ("revert", "invalid") for y in _walk(node or {}))


def _is_revert_body(node: Any) -> bool:
    for n in _walk(node):
        t = n.get("nodeType")
        if t in ("RevertStatement", "Throw"):
            return True
        if t == "FunctionCall" and (n.get("expression") or {}).get("name") == "revert":
            return True
    return False


class SemanticBuilder:
    def __init__(self, output: dict, texts: dict[str, str], categories: list[str],
                 compiled_texts: dict[str, str] | None = None) -> None:
        self.ctx = _Ctx(output, texts, compiled_texts, index_all=True)
        self.categories = categories
        self.fns: dict[int, _Fn] = {}
        self.span_ids: dict[tuple[str, int], str] = {}

    # ── public ──────────────────────────────────────────────────────────────

    def build(self) -> tuple[dict, dict[tuple[str, int], tuple[str, str]]]:
        ctx = self.ctx
        contracts = [n for n in ctx.nodes.values() if n.get("nodeType") == "ContractDefinition"
                     and _IDENT_RE.match(n.get("name") or "")]
        units: list[dict] = []
        state_vars: list[dict] = []
        for c in sorted(contracts, key=lambda c: (ctx.node_path[c["id"]], c.get("src", ""))):
            path = ctx.node_path[c["id"]]
            pinned = path in ctx.pinned
            loc = ctx.loc(c)
            end = ctx.end_line(c)
            if pinned and (loc is None or end is None):
                continue
            if pinned and c.get("contractKind") in ("contract", "library") and not c.get("abstract"):
                units.append({"id": f"{path}:{c['name']}", "name": c["name"], "kind": "contract",
                              "file": path, "start": loc[1], "end": end})
            for sub in c.get("nodes") or []:
                if sub.get("nodeType") == "VariableDeclaration" and sub.get("stateVariable") \
                        and _IDENT_RE.match(sub.get("name") or ""):
                    sloc = ctx.loc(sub) if pinned else None
                    if sloc:
                        state_vars.append({"id": f"{path}:{c['name']}.{sub['name']}", "unit": f"{path}:{c['name']}",
                                           "name": sub["name"], "decl_ref": ctx.ref(sloc)})
                elif sub.get("nodeType") in ("FunctionDefinition", "ModifierDefinition"):
                    # dependency functions are registered for callee resolution and feature
                    # propagation only; they never become units, functions or spans
                    self._register(sub, c, path, pinned=pinned)
        for fn in self.fns.values():
            self._analyze_body(fn)
        for fn in self.fns.values():
            self._resolve_guards(fn)
        functions = []
        span_out: dict[tuple[str, int], tuple[str, str]] = {}
        for fid, fn in sorted(self.fns.items(), key=lambda kv: kv[1].span_id):
            if not fn.pinned:
                continue
            loc = ctx.loc(fn.node)
            if loc is None:
                continue
            span_out[loc] = (fn.span_id, f"{fn.path}:{fn.contract['name']}")
            if fn.kind != "function":
                continue
            guard_keys = {(c, line) for c, line, _ in fn.guards}
            functions.append({
                "span": fn.span_id,
                "visibility": fn.node.get("visibility") or "public",
                "is_entry": self._is_entry(fn),
                "modifiers": [m for m in self._modifier_names(fn.node) if _IDENT_RE.match(m)],
                "guards": [_guard_row(c, line, via) for c, line, via in _dedup(fn.guards)]
                + [_guard_row("name_only", line, via, hint=c) for c, line, via in _dedup(fn.hints)
                   if (c, line) not in guard_keys],
                "calls": fn.calls,
                "writes": fn.writes,
                "reads": fn.reads,
            })
        semantic = {
            "units": units,
            "functions": functions,
            "state_vars": state_vars,
            "category_to_functions": self._categories(),
            "roles": self._roles(),
            "upgrade_surface": self._upgrade_surface(units),
            "chain_extras": {"evm": self._chain_extras(units)},
        }
        return semantic, span_out

    # ── registration and per-body analysis ──────────────────────────────────

    def _register(self, node: dict, contract: dict, path: str, pinned: bool = True) -> None:
        kind = "modifier" if node.get("nodeType") == "ModifierDefinition" else "function"
        name = self._fn_name(node, contract)
        if not _IDENT_RE.match(name):
            return
        params = [self._param_type(p) for p in (node.get("parameters") or {}).get("parameters") or []]
        span_id = f"{contract['name']}.{name}({','.join(params)})"
        self.fns[node["id"]] = _Fn(node=node, contract=contract, path=path, span_id=span_id, kind=kind, pinned=pinned)

    @staticmethod
    def _fn_name(node: dict, contract: dict) -> str:
        kind = node.get("kind")
        if kind in ("constructor", "fallback", "receive"):
            return kind
        if node.get("isConstructor") or (node.get("name") == contract.get("name") and node.get("nodeType") == "FunctionDefinition"):
            return "constructor"
        if node.get("nodeType") == "FunctionDefinition" and not node.get("name"):
            return "fallback"
        return node.get("name") or ""

    @staticmethod
    def _param_type(p: dict) -> str:
        t = _type_str(p)
        for suffix in (" memory", " storage", " calldata", " pointer", " ref"):
            t = t.replace(suffix, "")
        for prefix in ("contract ", "struct ", "enum ", "type(", "function "):
            t = t.removeprefix(prefix)
        t = t.split(".")[-1].replace(" ", "")
        return re.sub(r"[^A-Za-z0-9_\[\]]", "", t)[:64]

    def _modifier_names(self, node: dict) -> list[str]:
        out = []
        for m in node.get("modifiers") or []:
            ref = (m.get("modifierName") or {}).get("referencedDeclaration")
            target = self.ctx.nodes.get(ref) if isinstance(ref, int) else None
            if target is not None and target.get("nodeType") == "ModifierDefinition":
                out.append(target.get("name") or "")
        return out

    def _is_entry(self, fn: _Fn) -> bool:
        node = fn.node
        if fn.contract.get("contractKind") != "contract" or not node.get("implemented", node.get("body") is not None):
            return False
        if self._fn_name(node, fn.contract) == "constructor":
            return False
        return (node.get("visibility") or "public") in ("public", "external")

    def _analyze_body(self, fn: _Fn) -> None:
        body = fn.node.get("body")
        if not isinstance(body, dict):
            return
        params = (fn.node.get("parameters") or {}).get("parameters") or []
        if params:
            fn.features.add("has_params")
        self._walk_access(body, fn, write=False)
        for n in _walk(body):
            t = n.get("nodeType")
            if t in ("ForStatement", "WhileStatement", "DoWhileStatement"):
                fn.features.add("loop")
            elif t == "BinaryOperation" and n.get("operator") in ("*", "/", "%", "**"):
                fn.features.add("arithmetic")
            elif t == "MemberAccess":
                base = n.get("expression") or {}
                if base.get("nodeType") == "Identifier" and base.get("name") == "block":
                    if n.get("memberName") == "timestamp":
                        fn.features.add("timestamp")
                    elif n.get("memberName") in ("prevrandao", "difficulty"):
                        fn.features.add("randomness")
            elif t == "Identifier" and n.get("name") == "now" and n.get("referencedDeclaration", 0) < 0:
                fn.features.add("timestamp")
            elif t == "EmitStatement":
                fn.features.add("emits")
            elif t == "FunctionCall":
                self._call(n, fn)
            elif t == "InlineAssembly":
                for y in _walk(n.get("AST") or {}):
                    if y.get("nodeType") == "YulFunctionCall":
                        yname = (y.get("functionName") or {}).get("name")
                        if yname in ("call", "staticcall", "delegatecall", "callcode"):
                            fn.features.update({"external_call", "lowlevel_call"})
                            if yname == "delegatecall":
                                fn.features.add("delegatecall")
                        elif yname in ("selfdestruct",):
                            fn.features.add("selfdestruct")
                        elif yname == "timestamp":
                            fn.features.add("timestamp")
        name = self._fn_name(fn.node, fn.contract)
        if name in _UPGRADE_FNS:
            fn.features.add("upgrade")
        if name.lower().startswith("initiali") or "initializer" in self._modifier_names(fn.node) \
                or "reinitializer" in self._modifier_names(fn.node):
            fn.features.add("initializer")
        if fn.features & {"value_transfer", "token_call", "oracle"}:
            fn.features.add("value_flow")

    def _call(self, call: dict, fn: _Fn) -> None:
        ctx = self.ctx
        ex = call.get("expression") or {}
        value_bearing = False
        if ex.get("nodeType") == "FunctionCallOptions":
            value_bearing = "value" in (ex.get("names") or [])
            ex = ex.get("expression") or {}
        if call.get("kind") in ("typeConversion", "structConstructorCall"):
            return
        loc = ctx.loc(call)
        line = ctx.ref(loc)
        if line is None:
            return
        t = ex.get("nodeType")
        if t == "Identifier":
            ref = ex.get("referencedDeclaration")
            name = ex.get("name") or ""
            if name in ("selfdestruct", "suicide"):
                fn.features.add("selfdestruct")
            elif name == "ecrecover":
                fn.features.add("signature")
            elif name == "blockhash":
                fn.features.add("randomness")
            target = ctx.nodes.get(ref) if isinstance(ref, int) and ref >= 0 else None
            if target is not None and target.get("nodeType") == "FunctionDefinition" and _IDENT_RE.match(name):
                fn.calls.append({"kind": "internal", "target": name, "line": line})
                fn.internal_callees.append(target["id"])
            return
        if t == "NewExpression":
            fn.calls.append({"kind": "external", "target": "new", "line": line})
            fn.features.add("external_call")
            return
        if t != "MemberAccess":
            return
        member = ex.get("memberName") or ""
        if not _IDENT_RE.match(member):
            return
        base = ex.get("expression") or {}
        base_type = _type_str(base)
        ref = ex.get("referencedDeclaration")
        target = ctx.nodes.get(ref) if isinstance(ref, int) and ref >= 0 else None
        if member in _ORACLE_MEMBERS:
            fn.features.add("oracle")
        if member in _TOKEN_MEMBERS and not (base_type.startswith("address") and member == "transfer"):
            fn.features.add("token_call")
        if re.search(r"recover|isValidSignature|isValidSignatureNow", member):
            fn.features.add("signature")
        if base_type.startswith("address") and member in _LOWLEVEL | {"transfer"}:
            if member == "delegatecall":
                kind = "delegatecall"
                fn.features.update({"delegatecall", "lowlevel_call", "external_call"})
            elif member in ("transfer", "send"):
                kind = "value_transfer"
                value_bearing = True
                fn.features.update({"value_transfer", "external_call"})
                if member == "send":
                    fn.features.add("lowlevel_call")
            else:
                kind = "external"
                fn.features.update({"lowlevel_call", "external_call"})
                if value_bearing:
                    fn.features.add("value_transfer")
            entry = {"kind": kind, "target": f"address.{member}", "line": line}
            if value_bearing:
                entry["value_bearing"] = True
            fn.calls.append(entry)
            return
        if target is not None and target.get("nodeType") == "FunctionDefinition":
            owner = ctx.parent_contract.get(target["id"]) or {}
            internal = (target.get("visibility") in ("internal", "private")) or (
                base.get("nodeType") == "Identifier" and base.get("name") == "super")
            if internal:
                fn.calls.append({"kind": "internal", "target": member, "line": line})
                fn.internal_callees.append(target["id"])
                return
            owner_name = owner.get("name") or "contract"
            if not _IDENT_RE.match(owner_name):
                owner_name = "contract"
            entry = {"kind": "external", "target": f"{owner_name}.{member}", "line": line}
            if value_bearing:
                entry["value_bearing"] = True
                fn.features.add("value_transfer")
            fn.calls.append(entry)
            fn.features.add("external_call")

    def _walk_access(self, node: Any, fn: _Fn, write: bool) -> None:
        """State-variable writes and reads with lines (04 2.1 `writes`, `reads`)."""
        ctx = self.ctx
        stack: list[tuple[Any, bool]] = [(node, write)]
        while stack:
            n, w = stack.pop()
            if isinstance(n, list):
                stack.extend((v, w) for v in n)
                continue
            if not isinstance(n, dict):
                continue
            t = n.get("nodeType")
            if t == "Assignment":
                stack.append((n.get("leftHandSide"), True))
                if n.get("operator") not in ("=", None):
                    stack.append((n.get("leftHandSide"), False))
                stack.append((n.get("rightHandSide"), False))
                continue
            if t == "UnaryOperation" and n.get("operator") in ("++", "--", "delete"):
                stack.append((n.get("subExpression"), True))
                if n.get("operator") != "delete":
                    stack.append((n.get("subExpression"), False))
                continue
            if t == "IndexAccess":
                stack.append((n.get("baseExpression"), w))
                stack.append((n.get("indexExpression"), False))
                continue
            if t == "MemberAccess":
                stack.append((n.get("expression"), w))
                continue
            if t == "FunctionCall" and w:
                # `x.push(v)` writes x; arguments are reads
                stack.append((n.get("expression"), True))
                stack.append((n.get("arguments"), False))
                continue
            if t == "Identifier":
                ref = n.get("referencedDeclaration")
                target = ctx.nodes.get(ref) if isinstance(ref, int) and ref >= 0 else None
                if target is not None and target.get("nodeType") == "VariableDeclaration" and target.get("stateVariable"):
                    line = ctx.ref(ctx.loc(n))
                    name = target.get("name") or ""
                    if line and _IDENT_RE.match(name):
                        (fn.writes if w else fn.reads).append({"var": name, "line": line})
                        if w and not target.get("constant") and target.get("mutability") not in ("constant", "immutable"):
                            fn.features.add("writes_state")
                continue
            for k, v in n.items():
                if isinstance(v, (dict, list)) and k not in ("typeDescriptions", "documentation"):
                    stack.append((v, False if t == "FunctionCall" else w))
        # `x.push()` on a state array: MemberAccess push under a FunctionCall
        for c in _walk(node):
            if c.get("nodeType") == "FunctionCall":
                ex = c.get("expression") or {}
                if ex.get("nodeType") == "MemberAccess" and ex.get("memberName") in ("push", "pop"):
                    self._walk_access(ex.get("expression"), fn, write=True)
        fn.writes = _dedup_dicts(fn.writes)
        fn.reads = _dedup_dicts(fn.reads)

    # ── guards (04 2.1: line where the guard executes) ──────────────────────

    def _resolve_guards(self, fn: _Fn) -> None:
        """Guards structurally verified only (04 2.1; 10 fp_guarded and `fixed` read them).

        caller_check: the condition must hold for execution to continue and deny other callers:
        `msg.sender` (or `_msgSender()`, or a parameter bound to it) equal to an authority (a state
        variable, immutable or constant, a state mapping or struct read, or a no-argument view
        returning one); or a bool state-mapping lookup indexed by the sender that must be true.
        Literals, `address(0)`, tx.origin, parameters, locals and the sender itself are no authority.
        `&&` combines; an OR (either polarity) yields nothing. pause_check: a bool state variable
        (or a view returning one) is the sole operand of the condition. reentrancy_lock: the revert
        condition reads a state key the modifier writes before `_` and writes back after `_`.
        initializer_guard: the same read and write-before on one state key. Anything else that a
        name suggests is a `name_only` hint, never usable by fp_guarded or a `fixed` dismissal.
        """
        if fn.kind != "function" or not fn.pinned:
            return
        seen: set[int] = set()
        for m in fn.node.get("modifiers") or []:
            ref = (m.get("modifierName") or {}).get("referencedDeclaration")
            mod = self.ctx.nodes.get(ref) if isinstance(ref, int) else None
            if mod is None or mod.get("nodeType") != "ModifierDefinition":
                continue
            mname = mod.get("name") or ""
            before, after = self._split_placeholder(mod)
            senders = self._bind_senders(mod, m.get("arguments") or [], frozenset())
            found = self._guards_in(before, depth=1, seen=seen, senders=senders)
            classes = {c for c, _, _ in found}
            hint_line = self._first_stmt_line(mod) or self.ctx.path_of(mod)
            hints: list[tuple[str, str, str]] = []
            if _REENTRANCY_MOD_RE.search(mname):
                line = self._read_check_write(before, after)
                if line:
                    found.append(("reentrancy_lock", line, ""))
                elif hint_line:
                    hints.append(("reentrancy_lock", hint_line, ""))
            if _INIT_MOD_RE.search(mname):
                line = self._read_check_write(before, None)
                if line:
                    found.append(("initializer_guard", line, ""))
                elif hint_line:
                    hints.append(("initializer_guard", hint_line, ""))
            if _PAUSE_RE.search(mname) and "pause_check" not in classes and hint_line:
                hints.append(("pause_check", hint_line, ""))
            if "caller_check" in classes:
                role = self._role_from_modifier(m, mname)
                if role:
                    fn.role_names.add(role)
            elif _CHECK_FN_RE.search(mname) and hint_line:
                hints.append(("caller_check", hint_line, ""))
            # a modifier declared in an unpinned dependency executes outside the reviewed tree:
            # the guard is listed on the invocation line of the reviewed function header
            site = self.ctx.ref(self.ctx.loc(m)) or self.ctx.ref(self.ctx.loc(fn.node))
            fn.guards.extend(self._rehome(found, site))
            fn.hints.extend(self._rehome(hints, site))
        fn.guards.extend(self._guards_in(fn.node.get("body"), depth=0, seen=seen, role_sink=fn.role_names,
                                         hints=fn.hints))
        if any(c == "caller_check" for c, _, _ in fn.guards):
            fn.features.add("caller_guard")
        # transitive features through internal callees (depth 2) for candidate selection
        stack = [(cid, 1) for cid in fn.internal_callees]
        visited: set[int] = set()
        while stack:
            cid, d = stack.pop()
            if cid in visited or d > 2:
                continue
            visited.add(cid)
            callee = self.fns.get(cid)
            if callee is None:
                continue
            fn.features |= callee.features - {"has_params", "upgrade", "initializer"}
            stack.extend((x, d + 1) for x in callee.internal_callees)

    def _rehome(self, found: list[tuple[str, str, str]], site: str | None) -> list[tuple[str, str, str]]:
        """Guards whose line is outside the pinned files are listed at `site` (a pinned line that
        applies them) with the executing dependency line kept as `via`; pinned lines stay."""
        out: list[tuple[str, str, str]] = []
        for c, line, via in found:
            if self.ctx.in_pin(line) or site is None:
                out.append((c, line, via))
            else:
                out.append((c, site, via or line))
        return out

    @staticmethod
    def _split_placeholder(mod: dict) -> tuple[dict, dict]:
        """(statements before `_`, statements after `_`) of a modifier body, as synthetic Blocks."""
        before: list = []
        after: list = []
        cur = before
        for st in ((mod.get("body") or {}).get("statements")) or []:
            if st.get("nodeType") == "PlaceholderStatement" and cur is before:
                cur = after
                continue
            cur.append(st)
        return {"nodeType": "Block", "statements": before}, {"nodeType": "Block", "statements": after}

    def _callee(self, call: dict) -> dict | None:
        ref = (call.get("expression") or {}).get("referencedDeclaration")
        target = self.ctx.nodes.get(ref) if isinstance(ref, int) and ref >= 0 else None
        return target if target is not None and target.get("nodeType") == "FunctionDefinition" else None

    def _state_var(self, node: dict) -> dict | None:
        if node.get("nodeType") != "Identifier":
            return None
        ref = node.get("referencedDeclaration")
        target = self.ctx.nodes.get(ref) if isinstance(ref, int) and ref >= 0 else None
        if target is not None and target.get("nodeType") == "VariableDeclaration" and target.get("stateVariable"):
            return target
        return None

    def _key(self, node: dict) -> str | None:
        """State key of an lvalue or read: a state variable, or a member of a storage struct pointer."""
        sv = self._state_var(node)
        if sv is not None:
            return sv.get("name")
        if node.get("nodeType") == "MemberAccess" and "storage" in _type_str(node.get("expression")):
            return "." + (node.get("memberName") or "")
        return None

    def _keys_read(self, expr: Any, depth: int = 0) -> set[str]:
        out: set[str] = set()
        for n in _walk(expr):
            k = self._key(n)
            if k:
                out.add(k)
            if n.get("nodeType") == "FunctionCall" and depth < _MAX_DEPTH:
                target = self._callee(n)
                if target is not None and target.get("body"):
                    for r in _walk(target["body"]):
                        if r.get("nodeType") == "Return" and isinstance(r.get("expression"), dict):
                            out |= self._keys_read(r["expression"], depth + 1)
        return out

    def _keys_written(self, block: Any, depth: int = 0) -> set[str]:
        out: set[str] = set()
        for n in _walk(block):
            t = n.get("nodeType")
            lhs = None
            if t == "Assignment":
                lhs = n.get("leftHandSide")
            elif t == "UnaryOperation" and n.get("operator") in ("++", "--", "delete"):
                lhs = n.get("subExpression")
            if isinstance(lhs, dict):
                node = lhs
                while node.get("nodeType") in ("IndexAccess",):
                    node = node.get("baseExpression") or {}
                k = self._key(node)
                if k is None and node.get("nodeType") == "MemberAccess":
                    k = self._key(node.get("expression") or {})
                if k:
                    out.add(k)
            if t == "FunctionCall" and depth < _MAX_DEPTH:
                target = self._callee(n)
                if target is not None and target.get("body"):
                    out |= self._keys_written(target["body"], depth + 1)
        return out

    def _cond_sites(self, block: Any, depth: int, seen: set[int]):
        """(condition, must_be_true, node) for every require/assert/if-revert reached from `block`."""
        if not isinstance(block, dict):
            return
        for n in _walk(block):
            t = n.get("nodeType")
            if t == "FunctionCall" and (n.get("expression") or {}).get("name") in ("require", "assert") \
                    and (n.get("expression") or {}).get("referencedDeclaration", 0) < 0:
                args = n.get("arguments") or []
                if args:
                    yield args[0], True, n
            elif t == "IfStatement" and _is_revert_body(n.get("trueBody")):
                yield n.get("condition"), False, n
            elif t == "FunctionCall" and depth < _MAX_DEPTH:
                target = self._callee(n)
                if target is not None and target["id"] not in seen:
                    seen.add(target["id"])
                    yield from self._cond_sites(target.get("body"), depth + 1, seen)

    def _read_check_write(self, before: dict, after: dict | None) -> str | None:
        """Line of a condition that reads a state key written before `_` (and written back after `_`
        when `after` is given): the reentrancy lock and initializer pattern."""
        written = self._keys_written(before)
        if after is not None:
            written &= self._keys_written(after)
        if not written:
            return None
        for cond, _pos, node in self._cond_sites(before, 0, set()):
            if self._keys_read(cond) & written:
                return self.ctx.ref(self.ctx.loc(node))
        return None

    @staticmethod
    def _bind_senders(target: dict, args: list, senders: frozenset[int]) -> frozenset[int]:
        """Parameter ids of `target` that receive the caller (msg.sender or a bound parameter)."""
        params = (target.get("parameters") or {}).get("parameters") or []
        return frozenset(p["id"] for p, a in zip(params, args, strict=False)
                         if isinstance(p.get("id"), int) and _is_sender(_strip(a), senders))

    def _is_authority(self, e: dict, senders: frozenset[int], depth: int = 0) -> bool:
        e = _strip(e)
        if _contains_sender(e, senders) or _contains_tx_origin(e):
            return False
        t = e.get("nodeType")
        if t == "FunctionCall" and e.get("kind") == "typeConversion":
            args = e.get("arguments") or []
            return len(args) == 1 and self._is_authority(args[0], senders, depth)
        if t == "Identifier":
            sv = self._state_var(e)
            return sv is not None and not _is_zero_literal(sv.get("value"))
        if t in ("MemberAccess", "IndexAccess"):
            root = e
            while root.get("nodeType") in ("MemberAccess", "IndexAccess"):
                root = root.get("expression") or root.get("baseExpression") or {}
            return self._state_var(root) is not None or self._key(e) is not None
        if t == "FunctionCall" and not (e.get("arguments") or []) and depth < _MAX_DEPTH:
            target = self._callee(e)
            if target is None or not target.get("body"):
                return False
            rets = [r.get("expression") for r in _walk(target["body"]) if r.get("nodeType") == "Return"]
            return bool(rets) and all(isinstance(r, dict) and self._is_authority(r, senders, depth + 1) for r in rets)
        return False

    def _caller_ok(self, e: Any, pos: bool, senders: frozenset[int], depth: int) -> bool:
        """The condition, required to equal `pos`, admits only the authority as caller."""
        if not isinstance(e, dict):
            return False
        e = _strip(e)
        t = e.get("nodeType")
        if t == "UnaryOperation" and e.get("operator") == "!":
            return self._caller_ok(e.get("subExpression"), not pos, senders, depth)
        if t == "BinaryOperation":
            op = e.get("operator")
            left, right = e.get("leftExpression") or {}, e.get("rightExpression") or {}
            if op == "&&":
                return pos and (self._caller_ok(left, True, senders, depth) or self._caller_ok(right, True, senders, depth))
            if op == "||":
                return (not pos) and (self._caller_ok(left, False, senders, depth)
                                      or self._caller_ok(right, False, senders, depth))
            if op in ("==", "!="):
                if (op == "==") != pos:
                    return False  # reversed polarity admits every other caller
                ls, rs = _is_sender(_strip(left), senders), _is_sender(_strip(right), senders)
                return (ls and self._is_authority(right, senders)) or (rs and self._is_authority(left, senders))
            return False
        if t == "IndexAccess" and _type_str(e) == "bool":
            if not pos or not _is_sender(_strip(e.get("indexExpression") or {}), senders):
                return False  # a negated lookup (`!blacklist[msg.sender]`) admits every other caller
            return self._is_authority(e.get("baseExpression") or {}, senders) or \
                self._key(e.get("baseExpression") or {}) is not None
        if t == "FunctionCall" and pos and _type_str(e) == "bool" and depth < _MAX_DEPTH:
            target = self._callee(e)
            if target is None or not target.get("body"):
                return False
            bound = self._bind_senders(target, e.get("arguments") or [], senders)
            if not bound:
                return False
            rets = [r.get("expression") for r in _walk(target["body"]) if r.get("nodeType") == "Return"]
            return bool(rets) and all(self._caller_ok(r, True, bound, depth + 1) for r in rets)
        return False

    def _pause_operand(self, cond: Any, depth: int = 0) -> bool:
        """A bool state variable (or a no-argument view returning one) is the sole operand."""
        e = _strip(cond) if isinstance(cond, dict) else {}
        while e.get("nodeType") == "UnaryOperation" and e.get("operator") == "!":
            e = _strip(e.get("subExpression") or {})
        if _type_str(e) != "bool":
            return False
        # a bool state key whose name says pause (`paused`, `_paused`, `$._paused`): an initializer
        # flag is the same shape and is no pause check
        key = self._key(e) if e.get("nodeType") in ("Identifier", "MemberAccess") else None
        if key is not None:
            return bool(_PAUSE_RE.search(key))
        if e.get("nodeType") == "FunctionCall" and not (e.get("arguments") or []) and depth < _MAX_DEPTH:
            target = self._callee(e)
            rets = [r.get("expression") for r in _walk((target or {}).get("body") or {}) if r.get("nodeType") == "Return"]
            return bool(rets) and all(isinstance(r, dict) and self._pause_operand(r, depth + 1) for r in rets)
        return False

    def _guards_in(self, body: Any, depth: int, seen: set[int], role_sink: set[str] | None = None,
                   senders: frozenset[int] = frozenset(),
                   hints: list[tuple[str, str, str]] | None = None) -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        if not isinstance(body, dict):
            return out
        ctx = self.ctx
        for n in _walk(body):
            t = n.get("nodeType")
            cond, pos = None, True
            if t == "FunctionCall" and (n.get("expression") or {}).get("name") in ("require", "assert") \
                    and (n.get("expression") or {}).get("referencedDeclaration", 0) < 0:
                args = n.get("arguments") or []
                cond = args[0] if args else None
            elif t == "IfStatement" and _is_revert_body(n.get("trueBody")):
                cond, pos = n.get("condition"), False
            elif t == "InlineAssembly":
                for y in _walk(n.get("AST") or {}):
                    if y.get("nodeType") == "YulIf" and _is_revert_body_yul(y.get("body")) and _yul_caller_eq_sload(
                            y.get("condition") or {}):
                        line = self._yul_line(n, y)
                        if line:
                            out.append(("caller_check", line, ""))
                continue
            if cond is not None:
                # a condition in a dependency without text has no line: keep the path so the
                # caller can list the guard at its own call site with `via` = that path
                line = ctx.ref(ctx.loc(n)) or ctx.path_of(n)
                if line:
                    if self._caller_ok(cond, pos, senders, depth):
                        out.append(("caller_check", line, ""))
                    if self._pause_operand(cond):
                        out.append(("pause_check", line, ""))
                continue
            if t == "FunctionCall" and depth < _MAX_DEPTH:
                ex = n.get("expression") or {}
                target = self._callee(n)
                if target is None:
                    continue
                if target.get("visibility") not in ("internal", "private") and ex.get("nodeType") != "Identifier":
                    continue
                if target["id"] in seen:
                    continue
                name = target.get("name") or ""
                args = n.get("arguments") or []
                seen.add(target["id"])
                inner = self._guards_in(target.get("body"), depth + 1, seen,
                                        senders=self._bind_senders(target, args, senders))
                seen.discard(target["id"])
                verified = any(c == "caller_check" for c, _, _ in inner)
                if verified and role_sink is not None and _IDENT_RE.match(name):
                    role_sink.add(name)
                if not verified and hints is not None and _CHECK_FN_RE.search(name) \
                        and any(_contains_sender(a, senders) for a in args):
                    line = ctx.ref(ctx.loc(n))
                    if line:
                        hints.append(("caller_check", line, ""))
                # a callee declared in an unpinned dependency: its guards are listed at this call
                # site (the nearest reviewed line) with the executing line kept as `via`
                out.extend(self._rehome(inner, ctx.ref(ctx.loc(n)) or ctx.path_of(n)))
        return out

    def _yul_line(self, asm: dict, yul: dict) -> str | None:
        src = yul.get("src") or ""
        try:
            start, _l, idx = (int(x) for x in src.split(":")[:3])
        except ValueError:
            return self.ctx.ref(self.ctx.loc(asm))
        path = self.ctx.paths.get(idx)
        if path is None:
            return self.ctx.ref(self.ctx.loc(asm))
        return f"{path}:{bisect.bisect_right(self.ctx.line_starts[path], start)}"

    def _first_stmt_line(self, node: dict) -> str | None:
        stmts = ((node.get("body") or {}).get("statements")) or []
        for s in stmts:
            if s.get("nodeType") != "PlaceholderStatement":
                return self.ctx.ref(self.ctx.loc(s))
        return self.ctx.ref(self.ctx.loc(node))

    def _role_from_modifier(self, invocation: dict, mname: str) -> str | None:
        args = invocation.get("arguments") or []
        if args and args[0].get("nodeType") == "Identifier" and _IDENT_RE.match(args[0].get("name") or ""):
            return args[0]["name"]
        return mname if _IDENT_RE.match(mname) else None

    # ── derived tables ──────────────────────────────────────────────────────

    def _entries(self) -> list[_Fn]:
        return [f for f in self.fns.values() if f.kind == "function" and f.pinned and self._is_entry(f)]

    def _categories(self) -> dict[str, list[str]]:
        upgradeable = {id(f.contract) for f in self.fns.values() if "upgrade" in f.features or "delegatecall" in f.features}
        out: dict[str, list[str]] = {}
        entries = self._entries()
        for cat in self.categories:
            need = _CATEGORY_FEATURES.get(cat)
            if need is None:
                out[cat] = []
                continue
            chosen = []
            for f in entries:
                feats = set(f.features)
                if id(f.contract) in upgradeable:
                    feats.add("upgradeable_unit")
                if all(x in feats for x in need):
                    chosen.append(f.span_id)
            out[cat] = sorted(set(chosen))
        return out

    def _roles(self) -> list[dict]:
        gated: dict[str, set[str]] = {}
        for f in self._entries():
            if not any(c == "caller_check" for c, _, _ in f.guards):
                continue
            names = f.role_names or {"inline_sender_check"}
            for r in names:
                gated.setdefault(r, set()).add(f.span_id)
        return [{"name": r, "holder_kind": "unknown", "gated_functions": sorted(v)} for r, v in sorted(gated.items())]

    def _upgrade_surface(self, units: list[dict]) -> list[dict]:
        out = []
        for u in units:
            contract = next((f.contract for f in self.fns.values() if f.contract.get("name") == u["name"]
                             and f"{f.path}:{f.contract['name']}" == u["id"]), None)
            if contract is None:
                continue
            bases = set(contract.get("linearizedBaseContracts") or [])
            fns = [f for f in self.fns.values() if f.contract.get("id") in bases]
            names = {self._fn_name(f.node, f.contract) for f in fns}
            mechanism = None
            if names & _UPGRADE_FNS:
                mechanism = "uups"
            elif any(self._fn_name(f.node, f.contract) == "fallback" and "delegatecall" in f.features for f in fns):
                mechanism = "proxy_delegatecall"
            if mechanism:
                key = "onchain.owner" if "owner" in names else "onchain.eip1967.admin"
                out.append({"unit": u["id"], "mechanism": mechanism, "authority_fact_key": key})
        return out

    def _chain_extras(self, units: list[dict]) -> dict:
        out: dict[str, dict] = {}
        for u in units:
            ctor = next((f for f in self.fns.values() if f"{f.path}:{f.contract['name']}" == u["id"]
                         and self._fn_name(f.node, f.contract) == "constructor"), None)
            disables = False
            if ctor is not None:
                disables = any(c.get("target") == "_disableInitializers" for c in ctor.calls)
            contract = next((f.contract for f in self.fns.values() if f"{f.path}:{f.contract['name']}" == u["id"]), None)
            bases = []
            for cid in (contract or {}).get("linearizedBaseContracts") or []:
                base = self.ctx.nodes.get(cid)
                if base is not None and _IDENT_RE.match(base.get("name") or ""):
                    bases.append(base["name"])
            out[u["id"]] = {"constructor_disables_initializers": disables, "bases": bases or [u["name"]]}
        return {"units": out}


def _guard_row(cls: str, line: str, via: str, hint: str | None = None) -> dict[str, str]:
    row = {"class": cls, "line": line}
    if hint is not None:
        row["hint"] = hint
    if via:
        row["via"] = via
    return row


def _dedup(pairs: list) -> list:
    seen: set = set()
    out = []
    for p in pairs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _dedup_dicts(items: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out = []
    for d in items:
        k = tuple(sorted(d.items()))
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


def build_semantic(output: dict, texts: dict[str, str], categories: list[str],
                   compiled_texts: dict[str, str] | None = None) -> tuple[dict, dict[tuple[str, int], tuple[str, str]]] | None:
    """Semantic layer, or None when the output carries no AST for any pinned file (04 1.3: map partial).

    `compiled_texts`: the per-path source text the compiler was given (may differ from the pinned
    text in line endings); AST offsets are resolved against it, see `_Ctx`."""
    builder = SemanticBuilder(output, texts, categories, compiled_texts)
    if not builder.ctx.asts:
        return None
    return builder.build()


# ── retail-token profile (04 7.4 token_review) ────────────────────────────────────────────────
# A contract gets the token_review profile only when it DECLARES the ERC-20 external surface AND
# holds an owner-gated supply/transfer control. Requiring the declaration (not merely a token_call
# to some other token) keeps the profile off protocols that transact in tokens but are not one.
_ERC20_REQUIRED = frozenset({"transfer", "transferfrom", "approve", "balanceof", "totalsupply"})
# Owner-gated mutators that let a privileged role move, seize, block or dilute holder balances.
_PRIV_TOKEN_MUTATOR_RE = re.compile(
    r"^(mint|burn|burnfrom|pause|unpause|freeze|unfreeze|blacklist|blocklist|unblacklist|ban|unban"
    r"|setfee|setfees|settax|settaxes|updatefee|updatefees|setbuytax|setselltax|setmaxtx|setmaxwallet"
    r"|setlimit|setlimits|removelimit|removelimits|excludefromfee|includeinfee|setfeewallet|settaxwallet"
    r"|enabletrading|settradingenabled|settradingstatus)$"
)


def units_holding(semantic: dict | None, quotes: list[dict] | None) -> set[str] | None:
    """Ids of the semantic units (contracts) whose span overlaps any of the given location quotes
    (`{file, start, end}`); None when the map or the quotes give no answer (caller falls back to
    the whole map)."""
    if not semantic or not quotes:
        return None
    out: set[str] = set()
    for u in semantic.get("units") or []:
        for q in quotes:
            try:
                qs, qe = int(q.get("start", 0)), int(q.get("end", q.get("start", 0)))
            except (TypeError, ValueError):
                continue
            if u.get("file") == q.get("file") and qs and not (int(u.get("end", 0)) < qs or int(u.get("start", 0)) > qe):
                out.add(str(u.get("id")))
    return out or None


def detect_token_review(semantic: dict | None, unit_ids: set[str] | None = None) -> bool:
    """True when a deployable contract in the map is a retail token whose owner can move, seize,
    block or dilute holder balances. Deterministic over the semantic map; narrow by construction
    (the ERC-20 declaration requirement excludes protocols that merely call tokens).

    `unit_ids`: restrict the verdict to these units, normally the unit(s) holding the finding's
    location (`units_holding`). The profile is per finding, not per job: a flattened Sourcify
    source carries the vendored token next to the protocol contract (MasterChef + SushiToken),
    and with a job-wide verdict an owner-only migrator finding on the farm lost the K1 cap and
    printed Critical (deployed re-run, 2026-10-23). None = every unit (legacy, files without a
    location).

    Inheritance-aware: functions are stored under their DECLARING contract, so a standard
    OpenZeppelin token inherits transfer/approve/... from base `ERC20` and declares only `mint`
    itself. The ERC-20 surface and the owner-gated mutator are therefore aggregated across each
    deployable unit and its linearized bases (`chain_extras.evm.units[id].bases`)."""
    if not semantic:
        return False
    owner_gated_spans: set[str] = set()
    for role in semantic.get("roles") or []:
        owner_gated_spans.update(role.get("gated_functions") or [])

    # Index by DECLARING contract name; the per-unit check below unions across its base names.
    declared_by_contract: dict[str, set[str]] = {}   # contract name -> declared entry fn names
    mutator_contracts: set[str] = set()              # contracts declaring an owner-gated token mutator
    for fn in semantic.get("functions") or []:
        span = fn.get("span") or ""
        head = span.split("(", 1)[0]
        if "." not in head:
            continue
        contract, name = head.rsplit(".", 1)
        lname = name.lower()
        if fn.get("is_entry") and fn.get("visibility") in ("public", "external"):
            declared_by_contract.setdefault(contract, set()).add(lname)
        if _PRIV_TOKEN_MUTATOR_RE.match(lname):
            caller_checked = any(g.get("class") == "caller_check" for g in fn.get("guards") or [])
            if caller_checked or span in owner_gated_spans:
                mutator_contracts.add(contract)

    extras = (((semantic.get("chain_extras") or {}).get("evm") or {}).get("units")) or {}
    for unit in semantic.get("units") or []:
        if unit_ids is not None and unit.get("id") not in unit_ids:
            continue
        base_names = extras.get(unit.get("id"), {}).get("bases") or [unit.get("name")]
        names: set[str] = set()
        has_owner_mutator = False
        for bn in base_names:
            names |= declared_by_contract.get(bn, set())
            has_owner_mutator = has_owner_mutator or bn in mutator_contracts
        if _ERC20_REQUIRED <= names and has_owner_mutator:
            return True
    return False
