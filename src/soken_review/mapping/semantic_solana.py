"""Semantic layer of `map.v1` for Solana programs (Anchor, native, Pinocchio) from the Rust parse.

`build_semantic_solana(files, categories)` parses every pinned `.rs` file with the tree-sitter Rust
grammar (the lexical layer's parser) and returns the `semantic` object plus the span ids per
(path, start line), the same contract as `semantic_evm.build_semantic`. Pure.

Why a parsed layer: Solana programs have no solc-style AST in the build output, and the build may
be impossible offline for some repos. The parse needs no build, so a Solana job always gets units,
instructions, account contexts and a call graph. It is not compiler-resolved (trait dispatch,
macro bodies and closures are not followed), so a map holding it is `partial`, never `full`:
the `map.unreachable` auto-proof stays off (challenge.py requires `full`).

Model (04 2.1 shapes):
  units          `#[program] mod` -> program; `#[account]` structs -> account; every file holding
                 other functions -> module (named after the file, `mod.rs`/`lib.rs` after the dir)
  functions      every `fn`; span id `<Unit>.<name>`. `is_entry` for the public functions of the
                 `#[program]` module and for the function an `entrypoint!` macro names
  guards         caller_check for a Signer account, `has_one`/`constraint` binding a signer,
                 `require*!`/`assert*!` over `is_signer` or a key comparison; initializer_guard for
                 `init`; pause_check for a constraint or require naming a pause flag. Guards of the
                 instruction's `Context<...>` struct and of internal callees are listed on the entry
  calls          internal (a function defined in the pin), cpi (SPL Token, Token-2022, System,
                 ATA program helpers, invoke / invoke_signed); value_bearing for value moves
  writes         field assignments (`x.field = ..`, `x.field += ..`) and lamport moves
  state_vars     fields of `#[account]` structs
  roles          a Signer account that a constraint binds to stored state (has_one / constraint)
  chain_extras   solana: program id, instructions with their context, contexts with account flags
Names pass the 04 2.1 identifier grammar (safe_name); free text from code never enters the map.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from .lexers import _grammar

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_MAX_DEPTH = 3

# CPI helpers by name (anchor_spl / spl_token / system_program wrappers). Reference data.
_CPI_FNS = frozenset({
    "transfer", "transfer_checked", "mint_to", "mint_to_checked", "burn", "burn_checked", "close_account",
    "set_authority", "approve", "approve_checked", "revoke", "freeze_account", "thaw_account", "sync_native",
    "create_account", "allocate", "assign", "create", "create_idempotent", "initialize_account",
    "initialize_account3", "initialize_mint", "initialize_mint2", "harvest_withheld_tokens_to_mint",
    "withdraw_withheld_tokens_from_accounts", "withdraw_withheld_tokens_from_mint", "transfer_checked_with_fee",
})
_VALUE_FNS = frozenset({
    "transfer", "transfer_checked", "transfer_checked_with_fee", "mint_to", "mint_to_checked", "burn",
    "burn_checked", "close_account", "withdraw_withheld_tokens_from_accounts", "withdraw_withheld_tokens_from_mint",
})
_CPI_MODULES = frozenset({"token", "token_2022", "token_interface", "system_program", "associated_token",
                          "spl_token", "spl_token_2022", "spl_associated_token_account", "anchor_spl", "instruction"})
_INVOKE_FNS = frozenset({"invoke", "invoke_signed", "invoke_unchecked", "invoke_signed_unchecked"})
_SIGNED_RE = re.compile(r"new_with_signer|invoke_signed|with_signer|signer_seeds", re.IGNORECASE)
_GUARD_MACROS = frozenset({"require", "require_eq", "require_neq", "require_keys_eq", "require_keys_neq",
                           "require_gt", "require_gte", "assert", "assert_eq", "assert_ne"})
_CALLER_TEXT_RE = re.compile(r"is_signer|\.key\(\)|\bkey\b|authority|owner|admin", re.IGNORECASE)
_PAUSE_RE = re.compile(r"paus", re.IGNORECASE)
_ENTRYPOINT_MACROS = frozenset({"entrypoint", "program_entrypoint", "lazy_program_entrypoint",
                                "entrypoint_no_alloc", "custom_heap_default"})
_UNCHECKED_TYPES = frozenset({"UncheckedAccount", "AccountInfo"})
_ARITH_OPS = frozenset({"+", "-", "*", "/", "+=", "-=", "*=", "/=", "<<", "**"})
_WRAPPERS = frozenset({"Box", "Option"})

# 13: category -> features an entry function (with its callees) must have to be a candidate.
# Categories without a row have no candidates from the map (coverage `no_candidates`).
_CATEGORY_FEATURES: dict[str, tuple[str, ...]] = {
    "solana.missing_signer": ("mut_accounts",),
    "solana.missing_owner_check": ("unchecked_account",),
    "solana.type_confusion": ("unchecked_account",),
    "solana.pda_seeds": ("pda",),
    "solana.pda_sharing": ("pda",),
    "solana.seed_collision": ("pda",),
    "solana.signed_cpi_accounts": ("signed_cpi",),
    "solana.ata_validation": ("token_account",),
    "solana.ata_owner_reassign": ("ata",),
    "solana.account_relationship": ("relationship",),
    "solana.sysvar_address": ("sysvar",),
    "solana.introspection": ("introspection",),
    "solana.duplicate_mutable": ("duplicate_mutable",),
    "solana.remaining_accounts": ("remaining_accounts",),
    "solana.arbitrary_cpi": ("cpi",),
    "solana.stale_after_cpi": ("cpi", "writes_state"),
    "solana.cpi_recursion": ("cpi",),
    "solana.reinitialization": ("init",),
    "solana.close_revival": ("close",),
    "solana.token2022_extensions": ("token_interface",),
    "solana.arithmetic": ("arithmetic",),
    "solana.precreation": ("init",),
    "solana.business_logic": ("writes_state",),
    "solana.economic": ("value_flow",),
}


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None and node.text is not None else ""


def _line(node: Any) -> int:
    return node.start_point[0] + 1


def _walk(node: Any):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _safe(name: str) -> str | None:
    return name if _IDENT_RE.match(name or "") else None


def _attrs_before(node: Any) -> list[Any]:
    """`attribute_item` siblings directly above a node (doc comments in between are skipped)."""
    out = []
    prev = node.prev_sibling
    while prev is not None and prev.type in ("attribute_item", "line_comment", "block_comment"):
        if prev.type == "attribute_item":
            out.append(prev)
        prev = prev.prev_sibling
    return list(reversed(out))


def _attr_name(attr_item: Any) -> str:
    attr = next((c for c in attr_item.children if c.type == "attribute"), None)
    if attr is None or not attr.children:
        return ""
    return _text(attr.children[0])


def _attr_args(attr_item: Any) -> Any | None:
    attr = next((c for c in attr_item.children if c.type == "attribute"), None)
    if attr is None:
        return None
    return next((c for c in attr.children if c.type == "token_tree"), None)


def _attr_items(attr_item: Any) -> list[tuple[str, int]]:
    """Top-level comma-separated items of `#[name(...)]` as (text, line)."""
    tree = _attr_args(attr_item)
    if tree is None:
        return []
    items: list[tuple[str, int]] = []
    cur: list[Any] = []
    for c in tree.children[1:-1]:
        if c.type == ",":
            if cur:
                items.append((" ".join(_text(x) for x in cur), _line(cur[0])))
            cur = []
        else:
            cur.append(c)
    if cur:
        items.append((" ".join(_text(x) for x in cur), _line(cur[0])))
    return items


def _type_head(type_node: Any) -> tuple[str, str | None]:
    """(outer type name, inner data type) of an account field type: Box/Option unwrapped."""
    node = type_node
    for _ in range(4):
        if node is None:
            break
        if node.type == "generic_type":
            head = _text(node.child_by_field_name("type")).split("::")[-1]
            args = node.child_by_field_name("type_arguments")
            types = [c for c in (args.children if args is not None else []) if c.type not in ("<", ">", ",", "lifetime")]
            if head in _WRAPPERS and types:
                node = types[0]
                continue
            inner = _text(types[-1]).split("::")[-1] if types else None
            return head, inner
        return _text(node).split("::")[-1].split("<")[0], None
    return "", None


@dataclass
class _Account:
    name: str
    kind: str                     # outer type: Signer, Account, AccountLoader, UncheckedAccount, ...
    inner: str | None
    line: int
    constraints: list[tuple[str, int]] = field(default_factory=list)

    def has(self, word: str) -> bool:
        return any(re.match(rf"^{word}\b(?!_)", t) for t, _ in self.constraints)

    @property
    def signer(self) -> bool:
        return self.kind == "Signer" or self.has("signer")

    @property
    def mutable(self) -> bool:
        return self.has("mut") or self.has("init") or self.has("init_if_needed")


@dataclass
class _Context:
    name: str
    path: str
    start: int
    end: int
    accounts: list[_Account] = field(default_factory=list)


@dataclass
class _Fn:
    node: Any
    path: str
    name: str
    unit_name: str
    unit_kind: str
    is_entry: bool
    visibility: str
    context: str | None = None
    sid: str = ""
    unit_id: str = ""
    guards: list[dict[str, str]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    writes: list[dict[str, str]] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    features: set[str] = field(default_factory=set)


def _module_name(path: str) -> str:
    p = PurePosixPath(path)
    stem = p.stem
    if stem in ("mod", "lib", "main") and p.parent.name:
        stem = p.parent.name if stem == "mod" else f"{p.parent.name}_{stem}" if p.parent.name != "src" else stem
    return _safe(re.sub(r"[^A-Za-z0-9_]", "_", stem)) or "module"


class _Builder:
    def __init__(self, files: dict[str, str]) -> None:
        self.files = {p: t for p, t in files.items() if p.endswith(".rs")}
        self.trees: dict[str, Any] = {}
        self.fns: list[_Fn] = []
        self.contexts: dict[str, _Context] = {}
        self.account_structs: dict[str, dict[str, Any]] = {}   # name -> unit row + fields
        self.programs: list[dict[str, Any]] = []
        self.program_id: str | None = None
        self.entry_names: set[str] = set()

    # ── parse ────────────────────────────────────────────────────────────────

    def parse(self) -> bool:
        parser = _grammar("rust")
        if parser is None:
            return False
        for path in sorted(self.files):
            self.trees[path] = parser.parse(self.files[path].encode("utf-8")).root_node
        return True

    def collect(self) -> None:
        for path, root in self.trees.items():
            for n in _walk(root):
                if n.type == "struct_item":
                    self._struct(path, n)
                elif n.type == "mod_item" and any(_attr_name(a) == "program" for a in _attrs_before(n)):
                    name = _safe(_text(n.child_by_field_name("name")))
                    if name:
                        self.programs.append({"name": name, "path": path, "start": _line(n),
                                              "end": n.end_point[0] + 1})
                elif n.type == "macro_invocation":
                    self._macro_top(n)
        program_spans = [(p["path"], p["start"], p["end"], p["name"]) for p in self.programs]
        for path, root in self.trees.items():
            for n in _walk(root):
                if n.type == "function_item":
                    self._function(path, n, program_spans)

    def _macro_top(self, n: Any) -> None:
        name = _text(n.child_by_field_name("macro"))
        args = next((c for c in n.children if c.type == "token_tree"), None)
        if name in ("declare_id",) and args is not None:
            lit = re.search(r'"([1-9A-HJ-NP-Za-km-z]{32,44})"', _text(args))
            if lit and self.program_id is None:
                self.program_id = lit.group(1)
        elif name in _ENTRYPOINT_MACROS and args is not None:
            ident = next((c for c in args.children if c.type == "identifier"), None)
            if ident is not None:
                self.entry_names.add(_text(ident))

    def _struct(self, path: str, n: Any) -> None:
        name = _safe(_text(n.child_by_field_name("name")))
        if not name:
            return
        attrs = _attrs_before(n)
        derive = " ".join(_text(_attr_args(a)) for a in attrs if _attr_name(a) == "derive")
        body = n.child_by_field_name("body")
        if re.search(r"\bAccounts\b", derive) and body is not None:
            ctx = _Context(name, path, _line(n), n.end_point[0] + 1)
            for fdecl in body.children:
                if fdecl.type != "field_declaration":
                    continue
                fname = _safe(_text(fdecl.child_by_field_name("name")))
                if not fname:
                    continue
                kind, inner = _type_head(fdecl.child_by_field_name("type"))
                acc = _Account(fname, kind, inner, _line(fdecl))
                for a in _attrs_before(fdecl):
                    if _attr_name(a) == "account":
                        acc.constraints.extend(_attr_items(a))
                ctx.accounts.append(acc)
            self.contexts[name] = ctx
        elif any(_attr_name(a) == "account" for a in attrs):
            fields = []
            if body is not None:
                for fdecl in body.children:
                    if fdecl.type == "field_declaration":
                        fname = _safe(_text(fdecl.child_by_field_name("name")))
                        if fname:
                            fields.append((fname, _line(fdecl)))
            self.account_structs[name] = {"name": name, "path": path, "start": _line(n),
                                          "end": n.end_point[0] + 1, "fields": fields}

    def _function(self, path: str, n: Any, program_spans: list[tuple[str, int, int, str]]) -> None:
        name = _safe(_text(n.child_by_field_name("name")))
        if not name:
            return
        vis_node = next((c for c in n.children if c.type == "visibility_modifier"), None)
        visibility = _text(vis_node).replace(" ", "") if vis_node is not None else "private"
        line = _line(n)
        program = next((p for p in program_spans if p[0] == path and p[1] <= line <= p[2]), None)
        # the innermost enclosing impl / mod decides the unit
        unit_name, unit_kind = _module_name(path), "module"
        parent = n.parent
        while parent is not None:
            if parent.type == "impl_item":
                ty = parent.child_by_field_name("type")
                tname = _safe(_text(ty.child_by_field_name("type") if ty is not None and ty.type == "generic_type"
                                    else ty).split("::")[-1])
                if tname:
                    unit_name = tname
                    unit_kind = "account" if tname in self.account_structs else "module"
                break
            if parent.type == "mod_item":
                mname = _safe(_text(parent.child_by_field_name("name")))
                if mname:
                    unit_name = mname
                    unit_kind = "program" if program is not None and program[3] == mname else "module"
                break
            parent = parent.parent
        is_entry = (unit_kind == "program" and visibility.startswith("pub")
                    and n.parent is not None and n.parent.type == "declaration_list"
                    and n.parent.parent is not None and n.parent.parent.type == "mod_item") \
            or name in self.entry_names
        fn = _Fn(n, path, name, unit_name, unit_kind, is_entry, visibility)
        params = n.child_by_field_name("parameters")
        if params is not None:
            for t in _walk(params):
                if t.type == "generic_type" and _text(t.child_by_field_name("type")).split("::")[-1] == "Context":
                    args = t.child_by_field_name("type_arguments")
                    idents = [c for c in _walk(args) if c.type == "type_identifier"] if args is not None else []
                    if idents:
                        fn.context = _text(idents[-1])
                    break
        for a in _attrs_before(n):
            if _attr_name(a) == "access_control":
                for text, _ln in _attr_items(a):
                    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", text)
                    if m and _safe(m.group(1)):
                        fn.modifiers.append(m.group(1))
        self.fns.append(fn)

    # ── per function facts ───────────────────────────────────────────────────

    def analyze(self) -> None:
        defined = {f.name for f in self.fns}
        for fn in self.fns:
            body = fn.node.child_by_field_name("body")
            if body is None:
                continue
            seen_calls: set[tuple[str, str, str]] = set()
            for n in _walk(body):
                if n.type == "function_item" and n is not fn.node:
                    continue
                t = n.type
                if t == "call_expression":
                    self._call(fn, n, defined, seen_calls)
                elif t == "macro_invocation":
                    self._macro(fn, n)
                elif t in ("assignment_expression", "compound_assignment_expr"):
                    self._write(fn, n)
                elif t == "binary_expression":
                    op = n.child_by_field_name("operator")
                    if op is not None and _text(op) in _ARITH_OPS:
                        fn.features.add("arithmetic")
                elif t in ("field_expression", "identifier") and _text(n) == "remaining_accounts":
                    fn.features.add("remaining_accounts")
                elif t == "identifier" and _text(n) in ("load_instruction_at", "load_instruction_at_checked",
                                                       "get_instruction_relative", "load_current_index_checked"):
                    fn.features.add("introspection")
            if fn.writes:
                fn.features.add("writes_state")
            text = _text(body)
            if "try_from_slice" in text or "try_deserialize_unchecked" in text:
                fn.features.add("unchecked_account")

    def _call(self, fn: _Fn, n: Any, defined: set[str], seen: set[tuple[str, str, str]]) -> None:
        f = n.child_by_field_name("function")
        if f is None:
            return
        if f.type == "generic_function":
            f = f.child_by_field_name("function") or f
        line = f"{fn.path}:{_line(n)}"
        kind: str | None = None
        target = ""
        value = False
        if f.type == "identifier":
            name = _text(f)
            if name in _INVOKE_FNS:
                kind, target = "cpi", name
            elif name in defined:
                kind, target = "internal", name
        elif f.type == "scoped_identifier":
            parts = [p for p in _text(f).replace(" ", "").split("::") if p]
            name = parts[-1] if parts else ""
            mods = set(parts[:-1])
            if name in _INVOKE_FNS:
                kind, target = "cpi", name
            elif name in _CPI_FNS and mods & _CPI_MODULES:
                kind, target = "cpi", "::".join(p for p in parts[-2:] if _safe(p))
                value = name in _VALUE_FNS
            elif name in defined:
                kind, target = "internal", name
        elif f.type == "field_expression":
            name = _text(f.child_by_field_name("field"))
            if name in defined:
                kind, target = "internal", name
        if kind is None or not target:
            return
        if kind == "cpi":
            fn.features.add("cpi")
            if value:
                fn.features.add("value_flow")
            if target.startswith("invoke_signed") or _SIGNED_RE.search(_text(n)):
                fn.features.add("signed_cpi")
            if target.split("::")[0] in ("token_interface", "token_2022", "spl_token_2022"):
                fn.features.add("token_interface")
            if target.endswith("close_account"):
                fn.features.add("close")
        key = (kind, target, line)
        if key in seen:
            return
        seen.add(key)
        call: dict[str, Any] = {"kind": kind, "target": target, "line": line}
        if kind == "cpi":
            call["value_bearing"] = value
        fn.calls.append(call)

    def _macro(self, fn: _Fn, n: Any) -> None:
        name = _text(n.child_by_field_name("macro"))
        args = next((c for c in n.children if c.type == "token_tree"), None)
        if args is None:
            return
        body = _text(args)
        if "remaining_accounts" in body:
            fn.features.add("remaining_accounts")
        if name not in _GUARD_MACROS:
            return
        line = f"{fn.path}:{_line(n)}"
        if _PAUSE_RE.search(body):
            fn.guards.append({"class": "pause_check", "line": line, "hint": name})
        elif "is_signer" in body or name in ("require_keys_eq", "require_keys_neq") or \
                (re.search(r"\.key\(\)|\bkey\b", body) and _CALLER_TEXT_RE.search(body)):
            fn.guards.append({"class": "caller_check", "line": line, "hint": name})

    def _write(self, fn: _Fn, n: Any) -> None:
        left = n.child_by_field_name("left")
        if left is None:
            return
        target = left
        while target.type in ("unary_expression", "parenthesized_expression", "reference_expression"):
            inner = [c for c in target.children if c.is_named]
            if not inner:
                break
            target = inner[-1]
        var: str | None = None
        if target.type == "field_expression":
            var = _safe(_text(target.child_by_field_name("field")))
        elif "lamports" in _text(left):
            var = "lamports"
        if var:
            fn.writes.append({"var": var, "line": f"{fn.path}:{_line(n)}"})
            if var == "lamports":
                fn.features.add("value_flow")

    def context_facts(self, fn: _Fn) -> None:
        """Guards and features an instruction gets from its `#[derive(Accounts)]` struct."""
        ctx = self.contexts.get(fn.context or "")
        if ctx is None:
            return
        signers = {a.name for a in ctx.accounts if a.signer}
        types_mut: dict[str, int] = {}
        for a in ctx.accounts:
            # A bare Signer (payer, crank) authorizes nothing; it is a caller check only where a
            # constraint binds it to stored state (has_one / constraint / address below).
            if a.kind in _UNCHECKED_TYPES:
                fn.features.add("unchecked_account")
            if a.kind in ("Sysvar",) or (a.inner or "") in ("Clock", "Rent", "Instructions"):
                fn.features.add("sysvar")
            if a.kind in ("Interface", "InterfaceAccount"):
                fn.features.add("token_interface")
            if (a.inner or "") in ("TokenAccount", "Mint"):
                fn.features.add("token_account")
            if a.mutable:
                fn.features.add("mut_accounts")
                key = f"{a.kind}:{a.inner}"
                types_mut[key] = types_mut.get(key, 0) + 1
            for text, ln in a.constraints:
                cline = f"{ctx.path}:{ln}"
                head = text.split("=", 1)[0].strip()
                value = text.split("=", 1)[1].strip() if "=" in text else ""
                if head == "init":
                    fn.features.add("init")
                    fn.guards.append({"class": "initializer_guard", "line": cline, "hint": f"init {a.name}"})
                elif head == "init_if_needed":
                    fn.features.add("init")
                elif head == "close":
                    fn.features.add("close")
                elif head == "seeds":
                    fn.features.add("pda")
                elif head.startswith("associated_token"):
                    fn.features.update(("ata", "token_account"))
                elif head.startswith(("token", "mint")):
                    fn.features.add("token_account")
                elif head == "has_one":
                    fn.features.add("relationship")
                    target = value.split("@")[0].strip()
                    if target in signers:
                        fn.guards.append({"class": "caller_check", "line": cline, "hint": f"has_one {target}"})
                elif head in ("constraint", "address", "owner"):
                    fn.features.add("relationship")
                    if _PAUSE_RE.search(value):
                        fn.guards.append({"class": "pause_check", "line": cline, "hint": head})
                    elif any(re.search(rf"\b{re.escape(s)}\b", value) for s in signers):
                        fn.guards.append({"class": "caller_check", "line": cline, "hint": head})
        if any(c > 1 for c in types_mut.values()):
            fn.features.add("duplicate_mutable")

    # ── assemble ─────────────────────────────────────────────────────────────

    def assign_ids(self) -> list[dict[str, Any]]:
        units: dict[str, dict[str, Any]] = {}
        for p in self.programs:
            uid = f"{p['path']}:{p['name']}"
            row = {"id": uid, "name": p["name"], "kind": "program", "file": p["path"],
                   "start": p["start"], "end": p["end"]}
            if self.program_id:
                row["address"] = self.program_id
            units[uid] = row
        for s in self.account_structs.values():
            uid = f"{s['path']}:{s['name']}"
            units[uid] = {"id": uid, "name": s["name"], "kind": "account", "file": s["path"],
                          "start": s["start"], "end": s["end"]}
        program_units = {p["name"]: f"{p['path']}:{p['name']}" for p in self.programs}
        module_rows: dict[str, dict[str, Any]] = {}
        seen_sid: set[str] = set()
        for fn in self.fns:
            if fn.unit_kind == "program" and fn.unit_name in program_units:
                fn.unit_id = program_units[fn.unit_name]
            elif fn.unit_kind == "account" and fn.unit_name in self.account_structs:
                s = self.account_structs[fn.unit_name]
                fn.unit_id = f"{s['path']}:{s['name']}"
            else:
                fn.unit_id = f"{fn.path}:{fn.unit_name}"
                row = module_rows.setdefault(fn.unit_id, {"id": fn.unit_id, "name": fn.unit_name, "kind": "module",
                                                          "file": fn.path, "start": _line(fn.node),
                                                          "end": fn.node.end_point[0] + 1})
                row["start"] = min(row["start"], _line(fn.node))
                row["end"] = max(row["end"], fn.node.end_point[0] + 1)
            sid = f"{fn.unit_name}.{fn.name}"
            if sid in seen_sid:
                sid = f"{sid}@{fn.path}:{_line(fn.node)}"
            seen_sid.add(sid)
            fn.sid = sid
        for uid, row in module_rows.items():
            units.setdefault(uid, row)
        return sorted(units.values(), key=lambda u: (u["kind"] != "program", u["file"], u["start"]))

    def reach(self, fn: _Fn, by_name: dict[str, list[_Fn]]) -> list[_Fn]:
        seen = {id(fn)}
        frontier = [fn]
        out = [fn]
        for _ in range(_MAX_DEPTH):
            nxt = []
            for g in frontier:
                for c in g.calls:
                    if c["kind"] != "internal":
                        continue
                    for h in by_name.get(c["target"], []):
                        if id(h) not in seen:
                            seen.add(id(h))
                            nxt.append(h)
                            out.append(h)
            frontier = nxt
        return out


def build_semantic_solana(files: dict[str, str], categories: list[str]
                          ) -> tuple[dict[str, Any], dict[tuple[str, int], tuple[str, str]]] | None:
    """Semantic layer from the Rust parse, or None when no `.rs` file holds a function."""
    b = _Builder(files)
    if not b.files or not b.parse():
        return None
    b.collect()
    if not b.fns:
        return None
    b.analyze()
    units = b.assign_ids()
    by_name: dict[str, list[_Fn]] = {}
    for fn in b.fns:
        by_name.setdefault(fn.name, []).append(fn)
    entries = [fn for fn in b.fns if fn.is_entry]
    for fn in entries:
        b.context_facts(fn)
    # An entry inherits the guards and features of what it reaches (04 2.1: guards where they execute).
    reach_features: dict[int, set[str]] = {}
    for fn in entries:
        reached = b.reach(fn, by_name)
        feats: set[str] = set(fn.features)
        guards = list(fn.guards)
        for g in reached[1:]:
            feats |= g.features
            guards.extend(x for x in g.guards if x not in guards)
        fn.guards = guards
        reach_features[id(fn)] = feats

    functions = []
    span_ids: dict[tuple[str, int], tuple[str, str]] = {}
    for fn in b.fns:
        span_ids[(fn.path, _line(fn.node))] = (fn.sid, fn.unit_id)
        functions.append({"span": fn.sid, "visibility": fn.visibility, "is_entry": fn.is_entry,
                          "modifiers": fn.modifiers, "guards": fn.guards, "calls": fn.calls,
                          "writes": fn.writes, "reads": []})

    category_to_functions: dict[str, list[str]] = {}
    for cat in categories:
        need = _CATEGORY_FEATURES.get(cat)
        if not need:
            continue
        hits = sorted(fn.sid for fn in entries if all(x in reach_features[id(fn)] for x in need))
        if hits:
            category_to_functions[cat] = hits

    state_vars = []
    for s in b.account_structs.values():
        uid = f"{s['path']}:{s['name']}"
        for fname, ln in s["fields"]:
            state_vars.append({"id": f"{uid}.{fname}", "unit": uid, "name": fname, "decl_ref": f"{s['path']}:{ln}"})

    roles: dict[str, set[str]] = {}
    pda_signers: set[str] = set()
    for fn in entries:
        ctx = b.contexts.get(fn.context or "")
        if ctx is None:
            continue
        signers = {a.name: a for a in ctx.accounts if a.signer}
        bound: set[str] = set()
        for a in ctx.accounts:
            for text, _ln in a.constraints:
                head, _, value = text.partition("=")
                if head.strip() == "has_one" and value.split("@")[0].strip() in signers:
                    bound.add(value.split("@")[0].strip())
                elif head.strip() in ("constraint", "address"):
                    bound.update(s for s in signers if re.search(rf"\b{re.escape(s)}\b", value))
        for s in bound:
            roles.setdefault(s, set()).add(fn.sid)
            if signers[s].has("seeds"):
                pda_signers.add(s)

    instructions = [{"name": fn.name, "span": fn.sid, "context": fn.context} for fn in entries]
    contexts = {}
    for name, ctx in sorted(b.contexts.items()):
        contexts[name] = {
            "file": ctx.path, "start": ctx.start, "end": ctx.end,
            "accounts": [{"name": a.name, "type": _safe(a.kind) or "other", "data": _safe(a.inner or "") or None,
                          "line": a.line, "signer": a.signer, "mut": a.mutable,
                          "flags": sorted({t.split("=", 1)[0].strip().split("::")[0] for t, _ in a.constraints
                                           if _safe(t.split("=", 1)[0].strip().split("::")[0])})}
                         for a in ctx.accounts],
        }
    semantic = {
        "units": units,
        "functions": functions,
        "state_vars": state_vars,
        "category_to_functions": category_to_functions,
        "roles": [{"name": name, "holder_kind": "pda" if name in pda_signers else "unknown",
                   "gated_functions": sorted(fns)} for name, fns in sorted(roles.items())],
        "upgrade_surface": [{"unit": u["id"], "mechanism": "bpf_loader_upgradeable",
                             "authority_fact_key": "onchain.upgrade_authority"}
                            for u in units if u["kind"] == "program"],
        "chain_extras": {"solana": {"layer": "parsed", "program_id": b.program_id,
                                    "instructions": instructions, "contexts": contexts}},
    }
    return semantic, span_ids
