"""Compiler advisories and construct detectors for solc (05 section 6.2).

Input: the build's std-json input and solc output (compact AST) in <work_dir>/out/, plus the
candidate's recorded compiler version and how it was pinned.

  A1  nothing runs when the version was guessed from a pragma (`version_pinned_by` pragma*)
  A2  a bug that affects the version and settings AND whose construct detector matches emits a
      located lead: category `evm.compiler_bug`, rule_id `compiler.<BugName>`
  A3  affected, detector present, no match: advisory row "construct_not_found"
  A4  affected, no detector: advisory row "not_machine_checked"

Reference data, pinned (data/compilers/PINNED.json, sha256-checked on load):
  solc_bugs.json, solc_bugs_by_version.json  ethereum/solidity docs/ at a recorded commit
  ../compiler_bug_detectors.json             bug name -> detector id (null = none)

A setting that cannot be read (for example evmVersion with no default known for the release)
keeps the bug in scope and is listed in the row's `conditions_unknown`; it never drops the bug.
Detectors read the compact AST only: no source is executed, nothing leaves the host.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DATA = Path(__file__).parent / "data"
_COMPILERS = _DATA / "compilers"
_DETECTORS_FILE = _DATA / "compiler_bug_detectors.json"

CATEGORY = "evm.compiler_bug"


class PinnedDataError(RuntimeError):
    """A pinned reference file is missing or its sha256 differs from PINNED.json."""


def _load_pinned(name: str) -> Any:
    pinned = json.loads((_COMPILERS / "PINNED.json").read_text())
    row = pinned["files"][name]
    raw = (_COMPILERS / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != row["sha256"]:
        raise PinnedDataError(f"{name}: sha256 differs from PINNED.json")
    return json.loads(raw)


def solc_bugs_tool() -> str:
    """lead.v1 `tools[]` entry: the pinned bug list's identity (commit)."""
    pinned = json.loads((_COMPILERS / "PINNED.json").read_text())
    return f"solc-bugs@{pinned['solidity_commit'][:10]}"


# ---------------------------------------------------------------------------
# Versions and settings
# ---------------------------------------------------------------------------

def short_version(version: str) -> str:
    return version.split("+", 1)[0].removeprefix("v")


def _vt(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in short_version(version).split("."))
    except ValueError:
        return (0, 0, 0)


EVM_ORDER = [
    "homestead", "tangerineWhistle", "spuriousDragon", "byzantium", "constantinople", "petersburg",
    "istanbul", "berlin", "london", "paris", "shanghai", "cancun", "prague", "osaka",
]

# solc default evmVersion per release range (solc changelog); first match wins.
_EVM_DEFAULTS: list[tuple[tuple[int, ...], str]] = [
    ((0, 8, 30), "prague"), ((0, 8, 25), "cancun"), ((0, 8, 20), "shanghai"), ((0, 8, 18), "paris"),
    ((0, 8, 7), "london"), ((0, 8, 5), "berlin"), ((0, 5, 14), "istanbul"), ((0, 5, 5), "petersburg"),
    ((0, 4, 21), "byzantium"), ((0, 0, 0), "homestead"),
]


@dataclass
class Settings:
    optimizer: bool
    yul_optimizer: bool
    via_ir: bool
    evm_version: str | None
    abi_encoder_v2: bool | None  # None: no compact AST to read the pragmas from (unknown)


def _unit_abi_v2(unit: dict, v: tuple[int, ...]) -> bool:
    """ABI coder of one source unit from its PragmaDirective literals (comments are not pragmas)."""
    v2 = v >= (0, 8, 0)  # v2 is the default from 0.8.0
    for node in unit.get("nodes") or []:
        if not isinstance(node, dict) or node.get("nodeType") != "PragmaDirective":
            continue
        lits = [str(x) for x in node.get("literals") or []]
        if lits[:2] == ["experimental", "ABIEncoderV2"] or lits[:2] == ["abicoder", "v2"]:
            v2 = True
        elif lits[:2] == ["abicoder", "v1"]:
            v2 = False
    return v2


def derive_settings(version: str, std_input: dict, ctx: Ctx | None = None) -> Settings:
    """Settings that decide bug conditions. A value that cannot be proven is None (unknown), and an
    unknown condition keeps the bug in scope: nothing here may drop a bug on a guess."""
    s = std_input.get("settings") or {}
    opt = s.get("optimizer") or {}
    optimizer = opt.get("enabled") is True
    details = opt.get("details") or {}
    v = _vt(version)
    if "yul" in details:
        yul = bool(details["yul"]) and (optimizer or v >= (0, 8, 0))
    else:
        yul = optimizer and v >= (0, 6, 0)  # 0.5.x: Yul optimizer off unless details.yul
    via_ir = s.get("viaIR") is True
    evm = s.get("evmVersion")
    if evm not in EVM_ORDER:
        evm = next((name for floor, name in _EVM_DEFAULTS if v >= floor), None)
    # ABIEncoderV2: true when ANY source unit is compiled with coder v2 (per-unit pragmas, AST only)
    abi_v2 = None if ctx is None else any(_unit_abi_v2(unit, v) for unit in ctx.asts.values())
    return Settings(optimizer, yul, via_ir, evm, abi_v2)


def _condition_holds(key: str, want: Any, st: Settings) -> bool | None:
    """True / False, or None when the setting is unknown."""
    if key == "optimizer":
        return st.optimizer == want
    if key == "yulOptimizer":
        return st.yul_optimizer == want
    if key == "viaIR":
        return st.via_ir == want
    if key == "ABIEncoderV2":
        return None if st.abi_encoder_v2 is None else st.abi_encoder_v2 == want
    if key == "evmVersion":
        if st.evm_version is None:
            return None
        spec = str(want).strip()
        op = next((o for o in (">=", "<=", ">", "<", "=") if spec.startswith(o)), "=")
        name = spec[len(op):].strip() if spec.startswith(op) else spec
        if name not in EVM_ORDER:
            return None
        a, b = EVM_ORDER.index(st.evm_version), EVM_ORDER.index(name)
        return {">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b, "=": a == b}[op]
    return None  # a condition key this code does not know: unknown, bug stays in scope


# ---------------------------------------------------------------------------
# AST context
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    source: str
    start: int  # byte offset
    length: int


@dataclass
class Ctx:
    sources: dict[str, bytes]                       # source key -> content bytes
    asts: dict[str, dict]                           # source key -> SourceUnit
    file_index: dict[int, str]                      # solc source id -> source key
    by_id: dict[int, dict] = field(default_factory=dict)
    parent: dict[int, dict] = field(default_factory=dict)   # id(node) -> parent node
    contract_of: dict[int, dict] = field(default_factory=dict)  # id(node) -> ContractDefinition

    def walk(self) -> Iterator[dict]:
        for ast in self.asts.values():
            yield from _iter_nodes(ast)

    def text(self, node: dict) -> str:
        loc = _src(node)
        if loc is None or loc[2] not in self.file_index:
            return ""
        data = self.sources.get(self.file_index[loc[2]], b"")
        return data[loc[0] : loc[0] + loc[1]].decode("utf-8", errors="replace")

    def hit(self, node: dict) -> Hit | None:
        loc = _src(node)
        if loc is None or loc[2] not in self.file_index:
            return None
        return Hit(self.file_index[loc[2]], loc[0], loc[1])


def _iter_nodes(node: Any) -> Iterator[dict]:
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if "nodeType" in cur:
                yield cur
            stack.extend(v for v in cur.values() if isinstance(v, (dict, list)))
        elif isinstance(cur, list):
            stack.extend(cur)


def _src(node: dict) -> tuple[int, int, int] | None:
    try:
        start, length, idx = (int(x) for x in str(node.get("src", "")).split(":")[:3])
    except ValueError:
        return None
    return (start, length, idx) if start >= 0 else None


def build_ctx(std_input: dict, output: dict) -> Ctx | None:
    """Compact AST of every source, or None when the output has no compact AST (pre-0.4.12 etc.)."""
    sources = {k: ((v or {}).get("content") or "").encode() for k, v in (std_input.get("sources") or {}).items()}
    asts: dict[str, dict] = {}
    file_index: dict[int, str] = {}
    for key, entry in (output.get("sources") or {}).items():
        ast = (entry or {}).get("ast")
        if not isinstance(ast, dict) or ast.get("nodeType") != "SourceUnit":
            return None
        asts[key] = ast
        if isinstance(entry.get("id"), int):
            file_index[entry["id"]] = key
    if not asts:
        return None
    ctx = Ctx(sources=sources, asts=asts, file_index=file_index)
    for ast in asts.values():
        _index(ctx, ast, None, None)
    return ctx


def _index(ctx: Ctx, node: Any, parent: dict | None, contract: dict | None) -> None:
    stack: list[tuple[Any, dict | None, dict | None]] = [(node, parent, contract)]
    while stack:
        cur, par, con = stack.pop()
        if isinstance(cur, list):
            stack.extend((v, par, con) for v in cur)
            continue
        if not isinstance(cur, dict):
            continue
        if "nodeType" in cur:
            if isinstance(cur.get("id"), int):
                ctx.by_id[cur["id"]] = cur
            if par is not None:
                ctx.parent[id(cur)] = par
            if con is not None:
                ctx.contract_of[id(cur)] = con
            if cur["nodeType"] == "ContractDefinition":
                con = cur
            par = cur
        stack.extend((v, par, con) for v in cur.values() if isinstance(v, (dict, list)))


def _ts(node: dict | None) -> str:
    return ((node or {}).get("typeDescriptions") or {}).get("typeString") or ""


def _int_bits(type_string: str) -> int | None:
    m = re.fullmatch(r"u?int(\d*)", type_string)
    if not m:
        return None
    return int(m.group(1) or 256)


def _is_constructor(fn: dict, contract: dict | None) -> bool:
    if fn.get("kind") == "constructor" or fn.get("isConstructor") is True:
        return True
    return contract is not None and fn.get("kind") is None and fn.get("name") == contract.get("name")


def _functions(contract: dict) -> list[dict]:
    return [n for n in contract.get("nodes", []) if n.get("nodeType") == "FunctionDefinition"]


def _member_call(node: dict, member: str) -> bool:
    expr = node.get("expression") or {}
    return node.get("nodeType") == "FunctionCall" and expr.get("nodeType") == "MemberAccess" and expr.get("memberName") == member


def _ident_call(node: dict, name: str) -> bool:
    expr = node.get("expression") or {}
    return node.get("nodeType") == "FunctionCall" and expr.get("nodeType") == "Identifier" and expr.get("name") == name


# Source text and type strings are attacker-controlled: no regex below has nested or adjacent
# overlapping quantifiers. Structure (array dims, Yul function bodies) is parsed with str scans.

def _has_two_dim_array(type_string: str, fixed: bool) -> bool:
    """`[a][b]` in a type string; fixed=True needs digits in both brackets. Linear scan."""
    pos = type_string.find("][")
    while pos != -1:
        left = type_string.rfind("[", 0, pos)
        right = type_string.find("]", pos + 2)
        if left != -1 and right != -1:
            a, b = type_string[left + 1 : pos], type_string[pos + 2 : right]
            if (a.isdigit() and b.isdigit()) or (not fixed and (a == "" or a.isdigit()) and (b == "" or b.isdigit())):
                return True
        pos = type_string.find("][", pos + 2)
    return False


def _yul_ast(asm: dict) -> dict | None:
    """The Yul AST of an InlineAssembly node (solc >= 0.6.0 `AST`); None when the output has only
    the legacy `operations` text. Without it a Yul condition is unknown: the block is a hit."""
    ast = asm.get("AST")
    return ast if isinstance(ast, dict) and str(ast.get("nodeType", "")).startswith("Yul") else None


def _yul_calls(node: Any) -> Iterator[str]:
    for n in _iter_nodes(node):
        if n["nodeType"] == "YulFunctionCall":
            name = (n.get("functionName") or {}).get("name")
            if isinstance(name, str):
                yield name


def _asm_calls_any(asm: dict, names: frozenset[str]) -> bool:
    """True when the block calls one of names, or when its Yul cannot be read (doubt = hit)."""
    ast = _yul_ast(asm)
    return True if ast is None else any(c in names for c in _yul_calls(ast))


_YUL_TERMINATION = frozenset({"return", "stop"})
_MEM_WRITE = frozenset({"mstore", "mstore8", "calldatacopy", "codecopy", "extcodecopy", "returndatacopy", "mcopy"})
_KECCAK = frozenset({"keccak256", "sha3"})


# ---------------------------------------------------------------------------
# Construct detectors: Ctx -> nodes where the construct appears
# ---------------------------------------------------------------------------

def d_exp_small_exponent(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] == "BinaryOperation" and n.get("operator") == "**":
            bits = _int_bits(_ts(n.get("rightExpression")))
            if bits is not None and bits < 256:
                out.append(n)
    return out


def d_event_struct(ctx: Ctx) -> list[dict]:
    return [
        n for n in ctx.walk()
        if n["nodeType"] == "EventDefinition"
        and any(_ts(p).startswith("struct ") for p in (n.get("parameters") or {}).get("parameters", []))
    ]


def d_call_returns_nested_fixed_array(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] == "FunctionCall":
            ts = _ts(n.get("expression"))
            at = ts.find("returns (")
            if at != -1 and _has_two_dim_array(ts[at:], fixed=True):
                out.append(n)
    return out


def d_keccak_in_assembly(ctx: Ctx) -> list[dict]:
    return [n for n in ctx.walk() if n["nodeType"] == "InlineAssembly" and _asm_calls_any(n, _KECCAK)]


def d_selector_on_side_effect_expression(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] == "MemberAccess" and n.get("memberName") == "selector":
            for sub in _iter_nodes(n.get("expression")):
                kind = sub["nodeType"]
                if kind in ("Assignment", "Conditional") or (
                    kind == "FunctionCall" and sub.get("kind") != "typeConversion"
                ) or (kind == "UnaryOperation" and sub.get("operator") in ("++", "--", "delete")):
                    out.append(n)
                    break
    return out


class _Prefix:
    """startswith-based matcher with the .match() shape the detectors use (no regex)."""

    def __init__(self, *prefixes: str) -> None:
        self.prefixes = prefixes

    def match(self, s: str) -> bool:
        return s.startswith(self.prefixes)


_BYTES_STORAGE = _Prefix("bytes storage", "string storage")
_BYTES_SOURCE = _Prefix("bytes memory", "bytes calldata", "string memory", "string calldata")


def _bytes_storage_growth(ctx: Ctx) -> bool:
    """A zero-argument .push() on a storage bytes/string, or an assignment to its .length."""
    for n in ctx.walk():
        if (
            _member_call(n, "push") and not n.get("arguments")
            and _BYTES_STORAGE.match(_ts((n.get("expression") or {}).get("expression")))
        ):
            return True
        if n["nodeType"] == "Assignment":
            lhs = n.get("leftHandSide") or {}
            if lhs.get("nodeType") == "MemberAccess" and lhs.get("memberName") == "length" and _BYTES_STORAGE.match(
                _ts(lhs.get("expression"))
            ):
                return True
    return False


def d_bytes_copy_to_storage_then_grow(ctx: Ctx) -> list[dict]:
    if not _bytes_storage_growth(ctx):
        return []
    return [
        n for n in ctx.walk()
        if n["nodeType"] == "Assignment" and n.get("operator") == "="
        and _BYTES_STORAGE.match(_ts(n.get("leftHandSide")))
        and _BYTES_SOURCE.match(_ts(n.get("rightHandSide")))
    ]


def _small_dynamic_array_base_size(type_string: str) -> int | None:
    """Byte size of T for a `T[] storage...` type with an elementary T, else None."""
    base, sep, _ = type_string.partition("[] storage")
    if not sep or "[" in base:
        return None
    bits = _int_bits(base)
    if bits is not None:
        return bits // 8
    if base.startswith("bytes") and base[5:].isdigit():
        return int(base[5:])
    if base == "bool" or base.startswith("enum "):
        return 1
    return None


def d_small_dynamic_array_assign(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] != "Assignment" or n.get("operator") != "=":
            continue
        size = _small_dynamic_array_base_size(_ts(n.get("leftHandSide")))
        if size is not None and size <= 16 and "[]" in _ts(n.get("rightHandSide")):
            out.append(n)
    return out


def d_inherited_constructor_no_own(ctx: Ctx) -> list[dict]:
    """Deployable leaf contracts (no other contract derives from them: only their creation code
    runs) with no constructor of their own and a base with a non-payable constructor."""
    contracts = [n for n in ctx.walk() if n["nodeType"] == "ContractDefinition"]
    bases = {b for c in contracts for b in (c.get("linearizedBaseContracts") or [])[1:]}
    out = []
    for c in contracts:
        if c.get("contractKind") != "contract" or c.get("abstract") is True or c.get("fullyImplemented") is False:
            continue
        if c.get("id") in bases:
            continue
        if any(_is_constructor(f, c) for f in _functions(c)):
            continue
        for base_id in (c.get("linearizedBaseContracts") or [])[1:]:
            base = ctx.by_id.get(base_id)
            if not base:
                continue
            ctors = [f for f in _functions(base) if _is_constructor(f, base)]
            if any(f.get("stateMutability") != "payable" and f.get("payable") is not True for f in ctors):
                out.append(c)
                break
    return out


def d_tuple_assign_multi_slot(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] != "Assignment":
            continue
        lhs = n.get("leftHandSide") or {}
        if lhs.get("nodeType") != "TupleExpression":
            continue
        comps = lhs.get("components") or []
        omission_or_nested = any(c is None or (c or {}).get("nodeType") == "TupleExpression" for c in comps)
        rhs = _ts(n.get("rightHandSide"))
        multi_slot = "external" in rhs or "[] calldata" in rhs or rhs.count("tuple(") > 1
        if omission_or_nested and multi_slot:
            out.append(n)
    return out


def _param_types(fn: dict) -> tuple[str, ...]:
    return tuple(_ts(p) for p in (fn.get("parameters") or {}).get("parameters", []))


def d_private_overridden(ctx: Ctx) -> list[dict]:
    out = []
    for c in (n for n in ctx.walk() if n["nodeType"] == "ContractDefinition"):
        own = {(f.get("name"), _param_types(f)): f for f in _functions(c) if f.get("name")}
        for base_id in (c.get("linearizedBaseContracts") or [])[1:]:
            base = ctx.by_id.get(base_id)
            for f in _functions(base or {}):
                if f.get("visibility") == "private" and (f.get("name"), _param_types(f)) in own:
                    out.append(own[(f.get("name"), _param_types(f))])
    return out


def d_signed_array_storage_copy(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] != "Assignment" or n.get("operator") != "=":
            continue
        lhs, rhs = _ts(n.get("leftHandSide")), _ts(n.get("rightHandSide"))
        base = lhs.split("[", 1)[0]
        signed = base.startswith("int") and _int_bits(base) is not None
        if signed and "[" in lhs and " storage" in lhs and "[" in rhs and rhs.split("[", 1)[0] != base:
            out.append(n)
    return out


def d_new_memory_array_dynamic_length(ctx: Ctx) -> list[dict]:
    return [
        n for n in ctx.walk()
        if n["nodeType"] == "FunctionCall" and (n.get("expression") or {}).get("nodeType") == "NewExpression"
        and "[] memory" in _ts(n) and n.get("arguments")
        and n["arguments"][0].get("nodeType") != "Literal"
        and not n["arguments"][0].get("isConstant")
    ]


def d_abi_decode_two_dim(ctx: Ctx) -> list[dict]:
    return [
        n for n in ctx.walk()
        if _member_call(n, "decode") and " memory" in _ts(n) and _has_two_dim_array(_ts(n), fixed=False)
    ]


def d_library_event_contract_param(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] != "EventDefinition":
            continue
        con = ctx.contract_of.get(id(n)) or {}
        if con.get("contractKind") == "library" and any(
            _ts(p).startswith("contract ") for p in (n.get("parameters") or {}).get("parameters", [])
        ):
            out.append(n)
    return out


def d_delete_memory_bytes_element(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] == "UnaryOperation" and n.get("operator") == "delete":
            sub = n.get("subExpression") or {}
            if sub.get("nodeType") == "IndexAccess" and _ts(sub.get("baseExpression")).startswith("bytes memory"):
                out.append(n)
    return out


def d_require_named_error_args(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if _ident_call(n, "require") and len(n.get("arguments") or []) == 2:
            arg = n["arguments"][1]
            if arg.get("nodeType") == "FunctionCall" and len(arg.get("names") or []) > 1:
                out.append(n)
    return out


def d_delete_transient(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] == "UnaryOperation" and n.get("operator") == "delete":
            for sub in _iter_nodes(n.get("subExpression")):
                decl = ctx.by_id.get(sub.get("referencedDeclaration") or -1) or {}
                if decl.get("nodeType") == "VariableDeclaration" and decl.get("storageLocation") == "transient":
                    out.append(n)
                    break
    return out


def d_storage_layout_specifier(ctx: Ctx) -> list[dict]:
    return [n for n in ctx.walk() if n["nodeType"] == "ContractDefinition" and n.get("storageLayout")]


def _call_graph(ctx: Ctx) -> dict[int, set[int]]:
    graph: dict[int, set[int]] = {}
    for fn in ctx.walk():
        if fn["nodeType"] not in ("FunctionDefinition", "ModifierDefinition") or not isinstance(fn.get("id"), int):
            continue
        callees = graph.setdefault(fn["id"], set())
        for n in _iter_nodes(fn.get("body")):
            if n["nodeType"] == "FunctionCall":
                ref = (n.get("expression") or {}).get("referencedDeclaration")
                if isinstance(ref, int) and (ctx.by_id.get(ref) or {}).get("nodeType") == "FunctionDefinition":
                    callees.add(ref)
            elif n["nodeType"] == "ModifierInvocation":
                ref = (n.get("modifierName") or {}).get("referencedDeclaration")
                if isinstance(ref, int):
                    callees.add(ref)
        for m in fn.get("modifiers") or []:
            ref = (m.get("modifierName") or {}).get("referencedDeclaration")
            if isinstance(ref, int):
                callees.add(ref)
    return graph


def _sccs(graph: dict[int, set[int]]) -> list[set[int]]:
    """Tarjan, iterative."""
    index: dict[int, int] = {}
    low: dict[int, int] = {}
    on: set[int] = set()
    stack: list[int] = []
    out: list[set[int]] = []
    counter = 0
    for root in graph:
        if root in index:
            continue
        work = [(root, iter(graph.get(root, ())))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on.add(root)
        while work:
            node, it = work[-1]
            nxt = next(it, None)
            if nxt is None:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[node])
                if low[node] == index[node]:
                    comp = set()
                    while True:
                        w = stack.pop()
                        on.discard(w)
                        comp.add(w)
                        if w == node:
                            break
                    out.append(comp)
            elif nxt not in index:
                index[nxt] = low[nxt] = counter
                counter += 1
                stack.append(nxt)
                on.add(nxt)
                work.append((nxt, iter(graph.get(nxt, ()))))
            elif nxt in on:
                low[node] = min(low[node], index[nxt])
    return out


def d_mutual_recursion(ctx: Ctx) -> list[dict]:
    out = []
    for comp in _sccs(_call_graph(ctx)):
        if len(comp) > 1:
            out.extend(ctx.by_id[i] for i in sorted(comp) if i in ctx.by_id)
    return out


def d_signed_immutable_in_assembly(ctx: Ctx) -> list[dict]:
    immut = {
        n["id"]: n for n in ctx.walk()
        if n["nodeType"] == "VariableDeclaration" and n.get("mutability") == "immutable"
        and (b := _int_bits(_ts(n))) is not None and b < 256 and _ts(n).startswith("int")
    }
    out = []
    for n in ctx.walk():
        if n["nodeType"] == "InlineAssembly":
            for ref in n.get("externalReferences") or []:
                decl = ref.get("declaration") if isinstance(ref, dict) else None
                if decl in immut:
                    out.append(n)
                    break
    return out


def d_override_data_location_change(ctx: Ctx) -> list[dict]:
    out = []
    for fn in ctx.walk():
        if fn["nodeType"] != "FunctionDefinition" or fn.get("visibility") not in ("public", "internal"):
            continue
        params = (fn.get("parameters") or {}).get("parameters", [])
        for base_id in fn.get("baseFunctions") or []:
            base = ctx.by_id.get(base_id) or {}
            bparams = (base.get("parameters") or {}).get("parameters", [])
            if len(bparams) == len(params) and any(
                {a.get("storageLocation"), b.get("storageLocation")} == {"memory", "calldata"}
                for a, b in zip(params, bparams)
            ):
                out.append(fn)
                break
    return out


def d_assembly_memory_write_no_locals(ctx: Ctx) -> list[dict]:
    return [
        n for n in ctx.walk()
        if n["nodeType"] == "InlineAssembly" and not n.get("externalReferences") and _asm_calls_any(n, _MEM_WRITE)
    ]


def d_yul_function_conditional_termination(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] != "InlineAssembly":
            continue
        ast = _yul_ast(n)
        if ast is None or any(
            f["nodeType"] == "YulFunctionDefinition" and any(c in _YUL_TERMINATION for c in _yul_calls(f.get("body")))
            for f in _iter_nodes(ast)
        ):
            out.append(n)
    return out


def d_udvt_short_underlying(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if n["nodeType"] == "UserDefinedValueTypeDefinition":
            under = _ts(n.get("underlyingType"))
            bits = _int_bits(under)
            m = re.fullmatch(r"bytes(\d+)", under)
            if (bits is not None and bits < 256) or (m and int(m.group(1)) < 32) or under in ("bool", "address"):
                out.append(n)
    return out


def d_encode_call_literal(ctx: Ctx) -> list[dict]:
    out = []
    for n in ctx.walk():
        if (
            _member_call(n, "encodeCall") and len(n.get("arguments") or []) == 2
            and any(s["nodeType"] == "Literal" for s in _iter_nodes(n["arguments"][1]))
        ):
            out.append(n)
    return out


def d_two_constructors(ctx: Ctx) -> list[dict]:
    out = []
    for c in (n for n in ctx.walk() if n["nodeType"] == "ContractDefinition"):
        fns = _functions(c)
        if any(f.get("isConstructor") and f.get("name") == "" for f in fns) and any(
            f.get("name") == c.get("name") for f in fns
        ):
            out.append(c)
    return out


def d_ecrecover(ctx: Ctx) -> list[dict]:
    return [n for n in ctx.walk() if _ident_call(n, "ecrecover")]


def d_delegatecall_value_used(ctx: Ctx) -> list[dict]:
    return [
        n for n in ctx.walk()
        if _member_call(n, "delegatecall") and (ctx.parent.get(id(n)) or {}).get("nodeType") != "ExpressionStatement"
    ]


def d_empty_string_argument(ctx: Ctx) -> list[dict]:
    return [
        n for n in ctx.walk()
        if n["nodeType"] == "FunctionCall"
        and any(a.get("nodeType") == "Literal" and a.get("value") == "" for a in n.get("arguments") or [])
    ]


def d_send(ctx: Ctx) -> list[dict]:
    return [n for n in ctx.walk() if _member_call(n, "send")]


DETECTORS: dict[str, Callable[[Ctx], list[dict]]] = {
    "exp_small_exponent": d_exp_small_exponent,
    "event_struct": d_event_struct,
    "call_returns_nested_fixed_array": d_call_returns_nested_fixed_array,
    "keccak_in_assembly": d_keccak_in_assembly,
    "selector_on_side_effect_expression": d_selector_on_side_effect_expression,
    "bytes_copy_to_storage_then_grow": d_bytes_copy_to_storage_then_grow,
    "small_dynamic_array_assign": d_small_dynamic_array_assign,
    "inherited_constructor_no_own": d_inherited_constructor_no_own,
    "tuple_assign_multi_slot": d_tuple_assign_multi_slot,
    "private_overridden": d_private_overridden,
    "signed_array_storage_copy": d_signed_array_storage_copy,
    "new_memory_array_dynamic_length": d_new_memory_array_dynamic_length,
    "abi_decode_two_dim": d_abi_decode_two_dim,
    "library_event_contract_param": d_library_event_contract_param,
    "delete_memory_bytes_element": d_delete_memory_bytes_element,
    "require_named_error_args": d_require_named_error_args,
    "delete_transient": d_delete_transient,
    "storage_layout_specifier": d_storage_layout_specifier,
    "mutual_recursion": d_mutual_recursion,
    "signed_immutable_in_assembly": d_signed_immutable_in_assembly,
    "override_data_location_change": d_override_data_location_change,
    "assembly_memory_write_no_locals": d_assembly_memory_write_no_locals,
    "yul_function_conditional_termination": d_yul_function_conditional_termination,
    "udvt_short_underlying": d_udvt_short_underlying,
    "encode_call_literal": d_encode_call_literal,
    "two_constructors": d_two_constructors,
    "ecrecover": d_ecrecover,
    "delegatecall_value_used": d_delegatecall_value_used,
    "empty_string_argument": d_empty_string_argument,
    "send": d_send,
}


def detector_map() -> dict[str, str | None]:
    return json.loads(_DETECTORS_FILE.read_text())["solc"]


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

@dataclass
class CompilerBugReport:
    status: str                                   # ok | not_run
    reason: str | None = None
    version: str | None = None
    advisories: list[dict] = field(default_factory=list)   # one row per affected bug (A2 to A4)
    raw_leads: list[dict] = field(default_factory=list)    # analyze.py raw lead items (A2)


def _line_of(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, max(0, offset)) + 1


def solc_report(version: str, pinned_by: str | None, std_input: dict, output: dict) -> CompilerBugReport:
    """Advisory rows and located leads for one solc build (05 6.2 A1 to A4)."""
    if not version:
        return CompilerBugReport("not_run", "compiler_version_unknown")
    if (pinned_by or "").startswith("pragma"):
        return CompilerBugReport("not_run", "version_pinned_by_pragma", version)  # A1
    by_version = _load_pinned("solc_bugs_by_version.json")
    bugs = {b["name"]: b for b in _load_pinned("solc_bugs.json")}
    sv = short_version(version)
    if sv not in by_version:
        return CompilerBugReport("not_run", "version_not_in_bug_list", version)
    ctx = build_ctx(std_input, output)
    settings = derive_settings(version, std_input, ctx)
    dmap = detector_map()
    tool = solc_bugs_tool()
    report = CompilerBugReport("ok", None, version)

    for name in by_version[sv]["bugs"]:
        bug = bugs.get(name, {})
        unknown = []
        applies = True
        for key, want in (bug.get("conditions") or {}).items():
            held = _condition_holds(key, want, settings)
            if held is None:
                unknown.append(key)
            elif not held:
                applies = False
        row = {
            "compiler": "solc", "version": sv, "bug": name, "severity": bug.get("severity"),
            "link": bug.get("link"), "conditions": bug.get("conditions") or {},
            "conditions_unknown": unknown, "rule_id": f"compiler.{name}",
        }
        if not applies:
            row["status"] = "settings_not_affected"
            report.advisories.append(row)
            continue
        det_id = dmap.get(name)
        if det_id is None or det_id not in DETECTORS:
            row["status"] = "not_machine_checked"  # A4
        elif ctx is None:
            row["status"] = "not_machine_checked"
            row["reason"] = "no_compact_ast"
        else:
            hits = [(n, ctx.hit(n)) for n in DETECTORS[det_id](ctx)]
            hits = [(n, h) for n, h in hits if h is not None and h.source in ctx.sources]
            row["status"] = "lead" if hits else "construct_not_found"  # A2 / A3
            row["detector"] = det_id
            for node, h in hits:
                data = ctx.sources[h.source]
                start = _line_of(data, h.start)
                end = max(start, _line_of(data, h.start + max(h.length - 1, 0)))
                if node["nodeType"] in ("ContractDefinition", "FunctionDefinition") or end - start > 40:
                    end = start  # a whole contract or function: point at its header line
                report.raw_leads.append({
                    "tool": tool, "rule_id": f"compiler.{name}", "severity_raw": bug.get("severity") or "",
                    "file": h.source, "start": start, "end": end, "category": CATEGORY,
                })
        report.advisories.append(row)
    return report


def report_from_work_dir(work_dir: Path, version: str, pinned_by: str | None) -> CompilerBugReport:
    """Reads only the host-only build copies (`<attempt>.host/build`), never work/: no copy means
    advisories `not_run` (every bug stays unknown, nothing is reported as absent)."""
    from soken_review.adapters.evm.analyze import build_input, build_output

    std_input, output = build_input(Path(work_dir)), build_output(Path(work_dir))
    if std_input is None or output is None:
        return CompilerBugReport("not_run", "build_output_missing", version)
    return solc_report(version, pinned_by, std_input, output)
