"""Move bytecode reader for Sui and Aptos modules (plan v4 07 section 5.1, facts layer).

Plan 07 5.1 names a Rust helper `soken-move-facts` linked to `move-binary-format`. This module is
a Python reader of the same binary format, written from `deserializer.rs` and
`file_format_common.rs` at the pinned tags (Sui `mainnet-v1.81.1`, aptos-core
`aptos-cli-v9.6.0`). It reads only what the facts need: module handles, datatype handles with
abilities, function handles with signatures, function definitions (visibility, entry, native) and
the call/global-storage/closure instructions of each body, and Aptos metadata.

Untrusted input: every read is bounds checked; any malformed or unknown byte raises
`BytecodeError`, and callers turn that into `unknown` facts (07 10: unknown on doubt).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MAGIC = b"\xa1\x1c\xeb\x0b"
SUI_FLAVOR = 0x05            # sui file_format_common.rs BinaryFlavor::SUI_FLAVOR (versions >= 7)
APTOS_VERSION_MASK = 0x0A000000  # aptos file_format_common.rs APTOS_BYTECODE_VERSION_MASK

# Table kinds (both forks share the numbers 0x1..0x10; 0x11..0x14 differ in meaning, unused here).
T_MODULE_HANDLES, T_DATATYPE_HANDLES, T_FUNCTION_HANDLES, T_FUNCTION_INST = 0x1, 0x2, 0x3, 0x4
T_SIGNATURES, T_IDENTIFIERS, T_ADDRESS_IDENTIFIERS = 0x5, 0x7, 0x8
T_STRUCT_DEFS, T_STRUCT_DEF_INST, T_FUNCTION_DEFS, T_FRIEND_DECLS, T_METADATA = 0xA, 0xB, 0xC, 0xF, 0x10
_KNOWN_TABLES = set(range(0x1, 0x15)) - {0x9}

ABILITY_NAMES = ((0x1, "copy"), (0x2, "drop"), (0x4, "store"), (0x8, "key"))
VISIBILITY = {0x0: "private", 0x1: "public", 0x2: "script", 0x3: "friend"}
NATIVE_FLAG, ENTRY_FLAG = 0x2, 0x4

# Operand layout per opcode: "" none, "u" uleb, "b" one raw byte, digits = raw little-endian bytes,
# "uu8" uleb then 8 raw bytes. Built from the load_code match arms of each fork.
_COMMON_OPS: dict[int, str] = {
    0x01: "", 0x02: "", 0x03: "u", 0x04: "u", 0x05: "u", 0x06: "8", 0x07: "u", 0x08: "", 0x09: "",
    0x0A: "u", 0x0B: "u", 0x0C: "u", 0x0D: "u", 0x0E: "u", 0x0F: "u", 0x10: "u", 0x11: "u",
    0x12: "u", 0x13: "u", 0x14: "", 0x15: "", 0x16: "", 0x17: "", 0x18: "", 0x19: "", 0x1A: "",
    0x1B: "", 0x1C: "", 0x1D: "", 0x1E: "", 0x1F: "", 0x20: "", 0x21: "", 0x22: "", 0x23: "",
    0x24: "", 0x25: "", 0x26: "", 0x27: "", 0x28: "",
    0x29: "u", 0x2A: "u", 0x2B: "u", 0x2C: "u", 0x2D: "u",      # global storage (Sui: deprecated)
    0x2E: "", 0x2F: "", 0x30: "", 0x31: "b", 0x32: "16", 0x33: "", 0x34: "", 0x35: "",
    0x36: "u", 0x37: "u", 0x38: "u", 0x39: "u", 0x3A: "u",
    0x3B: "u", 0x3C: "u", 0x3D: "u", 0x3E: "u", 0x3F: "u",     # generic global storage
    0x40: "uu8", 0x41: "u", 0x42: "u", 0x43: "u", 0x44: "u", 0x45: "u", 0x46: "uu8", 0x47: "u",
    0x48: "2", 0x49: "4", 0x4A: "32", 0x4B: "", 0x4C: "", 0x4D: "",
}
_SUI_OPS = {**_COMMON_OPS, **{op: "u" for op in range(0x4E, 0x57)}}   # enum ops, VARIANT_SWITCH
_APTOS_OPS = {
    **_COMMON_OPS,
    **{op: "u" for op in range(0x4E, 0x58)},                             # variant field/pack/test
    0x58: "uu", 0x59: "uu", 0x5A: "u",                                   # closures (v8)
    0x5B: "1", 0x5C: "2", 0x5D: "4", 0x5E: "8", 0x5F: "16", 0x60: "32",  # signed loads (v9)
    **{op: "" for op in range(0x61, 0x69)},                               # signed casts, NEGATE, ABORT_MSG
}
OP_CALL, OP_CALL_GENERIC, OP_PACK, OP_PACK_GENERIC = 0x11, 0x38, 0x12, 0x39
OP_SHL, OP_DIV, OP_MUL = 0x2F, 0x1A, 0x18
GLOBAL_MUT_OPS = {0x2A, 0x2C, 0x3C, 0x3E}       # mut borrow global, move_from (+ generic)
APTOS_CLOSURE_OPS = {0x58, 0x59, 0x5A}


class BytecodeError(ValueError):
    """Malformed, truncated or unsupported module bytes."""


@dataclass
class FunctionFacts:
    name: str
    visibility: str            # public | friend | private (Sui `public(package)` is friend)
    entry: bool
    native: bool
    params: list[dict[str, Any]]
    returns: list[dict[str, Any]]
    type_params: int
    calls: list[str] = field(default_factory=list)          # "0xADDR::module::fn"
    generic_calls: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)  # (callee, type args)
    packs: list[str] = field(default_factory=list)          # struct names packed in this module
    global_mut: bool = False
    closure_call: bool = False                                # Aptos function value call or pack
    shl: bool = False
    attributes: list[str] = field(default_factory=list)


@dataclass
class ModuleFacts:
    flavor: str                # sui | aptos
    version: int
    address: str               # 0x + 64 hex
    name: str
    functions: list[FunctionFacts]
    structs: list[dict[str, Any]]          # {name, abilities}
    friends: list[str]
    metadata: dict[str, bytes]

    @property
    def module_id(self) -> str:
        return f"{self.address}::{self.name}"


class _Cursor:
    def __init__(self, data: bytes, start: int = 0, end: int | None = None) -> None:
        self.data, self.pos, self.end = data, start, len(data) if end is None else end

    def byte(self) -> int:
        if self.pos >= self.end:
            raise BytecodeError("unexpected end")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def raw(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise BytecodeError("unexpected end")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uleb(self, limit: int = 2**64 - 1) -> int:
        value, shift = 0, 0
        while True:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                break
            shift += 7
            if shift > 63:
                raise BytecodeError("bad uleb")
        if value > limit:
            raise BytecodeError("uleb over limit")
        return value

    @property
    def done(self) -> bool:
        return self.pos >= self.end


def header(data: bytes) -> tuple[str, int]:
    """(flavor, bytecode version) from the module header. Flavor `aptos` for any non-Sui flavor."""
    if len(data) < 8 or data[:4] != MAGIC:
        raise BytecodeError("bad magic")
    raw = int.from_bytes(data[4:8], "little")
    if (raw >> 24) == SUI_FLAVOR:
        return "sui", raw & 0x00FFFFFF
    if raw & APTOS_VERSION_MASK == APTOS_VERSION_MASK or raw < 7:
        version = raw & ~APTOS_VERSION_MASK
        # Unflavored v5/v6 modules are valid on both chains; the caller's chain decides.
        return ("aptos" if raw & APTOS_VERSION_MASK else "unflavored"), version
    raise BytecodeError(f"unknown flavor {raw:#x}")


def parse_module(data: bytes, chain: str) -> ModuleFacts:
    """Read one compiled module. `chain` is sui or aptos (selects the opcode table)."""
    flavor, version = header(data)
    if flavor not in (chain, "unflavored"):
        raise BytecodeError(f"{flavor} module on {chain}")
    if not 5 <= version <= (7 if chain == "sui" else 10):
        raise BytecodeError(f"unsupported bytecode version {version}")
    cur = _Cursor(data, 8)
    tables: dict[int, tuple[int, int]] = {}
    for _ in range(cur.uleb(255)):
        kind = cur.byte()
        offset, count = cur.uleb(2**32 - 1), cur.uleb(2**32 - 1)
        if kind not in _KNOWN_TABLES or kind in tables:
            raise BytecodeError(f"bad table {kind}")
        tables[kind] = (offset, count)
    base = cur.pos
    content_len = sum(c for _, c in tables.values())
    if base + content_len > len(data):
        raise BytecodeError("tables exceed binary")
    expected = 0
    for off, cnt in sorted(tables.values()):
        if off != expected:
            raise BytecodeError("tables not contiguous")
        expected = off + cnt
    after = _Cursor(data, base + content_len)
    self_idx = after.uleb()

    reader = _Reader(data, base, tables, version, chain)
    return reader.build(self_idx)


class _Reader:
    def __init__(self, data: bytes, base: int, tables: dict[int, tuple[int, int]], version: int, chain: str):
        self.data, self.base, self.tables, self.version, self.chain = data, base, tables, version, chain
        self.ops = _SUI_OPS if chain == "sui" else _APTOS_OPS

    def _table(self, kind: int) -> _Cursor | None:
        if kind not in self.tables:
            return None
        off, cnt = self.tables[kind]
        return _Cursor(self.data, self.base + off, self.base + off + cnt)

    def _items(self, kind: int, read) -> list[Any]:
        cur = self._table(kind)
        out: list[Any] = []
        while cur is not None and not cur.done:
            out.append(read(cur))
        return out

    # -- pools ---------------------------------------------------------------
    def _identifier(self, cur: _Cursor) -> str:
        raw = cur.raw(cur.uleb(65535))
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise BytecodeError("bad identifier") from exc

    def _abilities(self, cur: _Cursor) -> list[str]:
        mask = cur.uleb(0xF)
        return [name for bit, name in ABILITY_NAMES if mask & bit]

    def _datatype_handle(self, cur: _Cursor) -> dict[str, Any]:
        module, name = cur.uleb(), cur.uleb()
        abilities = self._abilities(cur)
        for _ in range(cur.uleb(255)):
            self._abilities(cur)
            cur.uleb(1)                                   # is_phantom (version >= 3)
        return {"module": module, "name": name, "abilities": abilities}

    def _access_specifiers(self, cur: _Cursor) -> None:
        tag = cur.byte()
        if tag == 0x1:                                    # SerializedOption::NONE
            return
        if tag != 0x2:
            raise BytecodeError("bad option")
        for _ in range(cur.uleb(64)):
            cur.byte()                                    # kind
            cur.byte()                                    # negated
            res = cur.byte()
            if res == 0x1:
                pass
            elif res in (0x2, 0x3, 0x4):
                cur.uleb()
            elif res == 0x5:
                cur.uleb()
                cur.uleb()
            else:
                raise BytecodeError("bad resource specifier")
            addr = cur.byte()
            if addr == 0x1:
                pass
            elif addr == 0x2:
                cur.uleb()
            elif addr == 0x3:
                cur.uleb(255)
                opt = cur.byte()
                if opt == 0x2:
                    cur.uleb()
                elif opt != 0x1:
                    raise BytecodeError("bad option")
            else:
                raise BytecodeError("bad address specifier")

    def _attributes(self, cur: _Cursor) -> list[str]:
        names = {0x1: "persistent", 0x2: "module_lock", 0x3: "pack", 0x4: "pack_variant", 0x5: "unpack",
                 0x6: "unpack_variant", 0x7: "test_variant", 0x8: "borrow", 0x9: "borrow_mut"}
        out = []
        for _ in range(cur.uleb(64)):
            tag = cur.byte()
            if tag not in names:
                raise BytecodeError("bad function attribute")
            if tag in (0x4, 0x6, 0x7, 0x8, 0x9):
                cur.raw(2)
            out.append(names[tag])
        return out

    def _function_handle(self, cur: _Cursor) -> dict[str, Any]:
        module, name, params, returns = cur.uleb(), cur.uleb(), cur.uleb(), cur.uleb()
        tparams = cur.uleb(255)
        for _ in range(tparams):
            self._abilities(cur)
        attributes: list[str] = []
        if self.chain == "aptos" and self.version >= 7:
            self._access_specifiers(cur)
        if self.chain == "aptos" and self.version >= 8:
            attributes = self._attributes(cur)
        return {"module": module, "name": name, "params": params, "returns": returns,
                "tparams": tparams, "attributes": attributes}

    def _type(self, cur: _Cursor, depth: int = 0) -> Any:
        """One signature token as a nested tuple; ('struct', handle_idx, [args]) etc."""
        if depth > 64:
            raise BytecodeError("type too deep")
        tag = cur.byte()
        simple = {0x1: "bool", 0x2: "u8", 0x3: "u64", 0x4: "u128", 0x5: "address", 0xC: "signer",
                  0xD: "u16", 0xE: "u32", 0xF: "u256"}
        if self.chain == "aptos":
            simple.update({0x11: "i8", 0x12: "i16", 0x13: "i32", 0x14: "i64", 0x15: "i128", 0x16: "i256"})
        if tag in simple:
            return simple[tag]
        if tag == 0x6:
            return ("ref", self._type(cur, depth + 1))
        if tag == 0x7:
            return ("mut", self._type(cur, depth + 1))
        if tag == 0xA:
            return ("vector", self._type(cur, depth + 1))
        if tag == 0x8:
            return ("struct", cur.uleb(), [])
        if tag == 0xB:
            idx, arity = cur.uleb(), cur.uleb(255)
            if arity == 0:
                raise BytecodeError("inst arity 0")
            return ("struct", idx, [self._type(cur, depth + 1) for _ in range(arity)])
        if tag == 0x9:
            return ("tparam", cur.uleb(65535))
        if tag == 0x10 and self.chain == "aptos":
            self._abilities(cur)
            n_args, n_res = cur.uleb(255), cur.uleb(255)
            return ("function", [self._type(cur, depth + 1) for _ in range(n_args + n_res)])
        raise BytecodeError(f"bad type tag {tag}")

    def _signature(self, cur: _Cursor) -> list[Any]:
        return [self._type(cur) for _ in range(cur.uleb(255))]

    def _metadata(self, cur: _Cursor) -> tuple[bytes, bytes]:
        key = cur.raw(cur.uleb(1023))
        return key, cur.raw(cur.uleb(2**24))

    # -- definitions -----------------------------------------------------------
    def _code(self, cur: _Cursor, facts: dict[str, Any]) -> None:
        cur.uleb()                                        # locals signature
        for _ in range(cur.uleb(65535)):
            op = cur.byte()
            layout = self.ops.get(op)
            if layout is None:
                raise BytecodeError(f"unknown opcode {op:#x}")
            operand = None
            for part in _split_layout(layout):
                if part == "u":
                    v = cur.uleb()
                    operand = v if operand is None else operand
                elif part == "b":
                    cur.byte()
                else:
                    cur.raw(int(part))
            if op == OP_CALL:
                facts["calls"].append(("h", operand))
            elif op == OP_CALL_GENERIC:
                facts["calls"].append(("i", operand))
            elif op == OP_PACK:
                facts["packs"].append(("d", operand))
            elif op == OP_PACK_GENERIC:
                facts["packs"].append(("di", operand))
            elif op in GLOBAL_MUT_OPS:
                facts["global_mut"] = True
            elif op == OP_SHL:
                facts["shl"] = True
            elif self.chain == "aptos" and op in APTOS_CLOSURE_OPS:
                facts["closure_call"] = True
        if self.chain == "sui" and self.version >= 7:
            for _ in range(cur.uleb(65535)):              # variant jump tables
                cur.uleb()
                branches = cur.uleb(65535)
                if cur.byte() != 0x1:                      # SerializedJumpTableFlag::FULL
                    raise BytecodeError("bad jump table")
                for _ in range(branches):
                    cur.uleb()

    def _function_def(self, cur: _Cursor) -> dict[str, Any]:
        handle = cur.uleb()
        vis = cur.byte()
        if vis not in VISIBILITY:
            raise BytecodeError("bad visibility")
        flags = cur.byte()
        for _ in range(cur.uleb(255)):                    # acquires
            cur.uleb()
        facts: dict[str, Any] = {"handle": handle, "visibility": VISIBILITY[vis], "entry": bool(flags & ENTRY_FLAG),
                                 "native": bool(flags & NATIVE_FLAG), "calls": [], "packs": [], "global_mut": False,
                                 "shl": False, "closure_call": False}
        if flags & ~(ENTRY_FLAG | NATIVE_FLAG):
            raise BytecodeError("bad function flags")
        if not facts["native"]:
            self._code(cur, facts)
        return facts

    def _struct_def(self, cur: _Cursor) -> int:
        handle = cur.uleb()
        kind = cur.byte()
        if kind == 0x1:
            return handle
        if kind == 0x2:
            for _ in range(cur.uleb()):
                cur.uleb()
                self._type(cur)
            return handle
        if kind == 0x3 and self.chain == "aptos" and self.version >= 7:
            for _ in range(cur.uleb()):
                cur.uleb()
                for _ in range(cur.uleb()):
                    cur.uleb()
                    self._type(cur)
            return handle
        raise BytecodeError("bad struct field info")

    def build(self, self_idx: int) -> ModuleFacts:
        idents = self._items(T_IDENTIFIERS, self._identifier)
        addrs = ["0x" + a.hex() for a in self._items(T_ADDRESS_IDENTIFIERS, lambda c: c.raw(32))]
        mods = self._items(T_MODULE_HANDLES, lambda c: (c.uleb(), c.uleb()))
        dts = self._items(T_DATATYPE_HANDLES, self._datatype_handle)
        fhs = self._items(T_FUNCTION_HANDLES, self._function_handle)
        finst = self._items(T_FUNCTION_INST, lambda c: (c.uleb(), c.uleb()))
        sigs = self._items(T_SIGNATURES, self._signature)
        fdefs = self._items(T_FUNCTION_DEFS, self._function_def)
        sdefs = self._items(T_STRUCT_DEFS, self._struct_def)
        sdef_inst = self._items(T_STRUCT_DEF_INST, lambda c: (c.uleb(), c.uleb()))
        friends = self._items(T_FRIEND_DECLS, lambda c: (c.uleb(), c.uleb()))
        metadata = dict(self._items(T_METADATA, self._metadata))

        def ident(i: int) -> str:
            if not 0 <= i < len(idents):
                raise BytecodeError("identifier index")
            return idents[i]

        def module_id(i: int) -> str:
            if not 0 <= i < len(mods):
                raise BytecodeError("module index")
            a, n = mods[i]
            if not 0 <= a < len(addrs):
                raise BytecodeError("address index")
            return f"{addrs[a]}::{ident(n)}"

        def sig(i: int) -> list[Any]:
            if not 0 <= i < len(sigs):
                raise BytecodeError("signature index")
            return sigs[i]

        def render(t: Any) -> dict[str, Any]:
            return _render_type(t, dts, module_id, ident)

        if not 0 <= self_idx < len(mods):
            raise BytecodeError("self module index")
        self_id = module_id(self_idx)
        address, name = self_id.split("::")

        def callee(kind: str, idx: int) -> str:
            if kind == "i":
                if not 0 <= idx < len(finst):
                    raise BytecodeError("function inst index")
                idx = finst[idx][0]
            if not 0 <= idx < len(fhs):
                raise BytecodeError("function handle index")
            fh = fhs[idx]
            return f"{module_id(fh['module'])}::{ident(fh['name'])}"

        def type_args(kind: str, idx: int) -> tuple[str, ...]:
            if kind != "i":
                return ()
            return tuple(_type_text(t, dts, module_id, ident)[0] for t in sig(finst[idx][1]))

        def packed(kind: str, idx: int) -> str:
            if kind == "di":
                if not 0 <= idx < len(sdef_inst):
                    raise BytecodeError("struct inst index")
                idx = sdef_inst[idx][0]
            if not 0 <= idx < len(sdefs) or not 0 <= sdefs[idx] < len(dts):
                raise BytecodeError("struct def index")
            return ident(dts[sdefs[idx]]["name"])

        functions: list[FunctionFacts] = []
        for fd in fdefs:
            if not 0 <= fd["handle"] < len(fhs):
                raise BytecodeError("function handle index")
            fh = fhs[fd["handle"]]
            vis = "friend" if fd["visibility"] == "friend" else fd["visibility"]
            functions.append(FunctionFacts(
                name=ident(fh["name"]), visibility=vis, entry=fd["entry"], native=fd["native"],
                params=[render(t) for t in sig(fh["params"])], returns=[render(t) for t in sig(fh["returns"])],
                type_params=fh["tparams"], calls=sorted({callee(k, i) for k, i in fd["calls"]}),
                generic_calls=sorted({(callee(k, i), type_args(k, i)) for k, i in fd["calls"] if k == "i"}),
                packs=sorted({packed(k, i) for k, i in fd["packs"]}),
                global_mut=fd["global_mut"], closure_call=fd["closure_call"], shl=fd["shl"],
                attributes=fh["attributes"],
            ))
        structs = []
        for h in sdefs:
            if not 0 <= h < len(dts):
                raise BytecodeError("datatype handle index")
            structs.append({"name": ident(dts[h]["name"]), "abilities": dts[h]["abilities"]})
        return ModuleFacts(
            flavor=self.chain, version=self.version, address=address, name=name, functions=functions,
            structs=structs, friends=sorted({module_id_from(a, n, addrs, ident) for a, n in friends}),
            metadata=metadata,
        )


def module_id_from(a: int, n: int, addrs: list[str], ident) -> str:
    if not 0 <= a < len(addrs):
        raise BytecodeError("address index")
    return f"{addrs[a]}::{ident(n)}"


def _split_layout(layout: str) -> list[str]:
    if layout in ("", "u", "b"):
        return [layout] if layout else []
    if layout == "uu8":
        return ["u", "8"]
    if layout == "uu":
        return ["u", "u"]
    return [layout]


def _render_type(t: Any, dts: list[dict[str, Any]], module_id, ident) -> dict[str, Any]:
    """Signature token -> {type, ref, mut, abilities} where `type` is a readable string."""
    ref = mut = False
    if isinstance(t, tuple) and t[0] in ("ref", "mut"):
        ref, mut, t = True, t[0] == "mut", t[1]
    text, abilities = _type_text(t, dts, module_id, ident)
    return {"type": text, "ref": ref, "mut": mut, "abilities": abilities}


def _type_text(t: Any, dts, module_id, ident, depth: int = 0) -> tuple[str, list[str]]:
    if isinstance(t, str):
        return t, []
    kind = t[0]
    if kind in ("ref", "mut"):
        inner, _ = _type_text(t[1], dts, module_id, ident, depth + 1)
        return ("&mut " if kind == "mut" else "&") + inner, []
    if kind == "vector":
        inner, _ = _type_text(t[1], dts, module_id, ident, depth + 1)
        return f"vector<{inner}>", []
    if kind == "tparam":
        return f"T{t[1]}", []
    if kind == "function":
        return "fun", []
    if kind == "struct":
        if not 0 <= t[1] < len(dts):
            raise BytecodeError("datatype handle index")
        h = dts[t[1]]
        name = f"{module_id(h['module'])}::{ident(h['name'])}"
        if t[2]:
            name += "<" + ", ".join(_type_text(a, dts, module_id, ident, depth + 1)[0] for a in t[2]) + ">"
        return name, list(h["abilities"])
    raise BytecodeError("bad type")


def aptos_compilation_metadata(mod: ModuleFacts) -> dict[str, str] | None:
    """Aptos `compilation_metadata` entry (07 7.2, U-22): BCS {unstable: bool, compiler_version,
    language_version}. None when absent or not decodable."""
    raw = mod.metadata.get(b"compilation_metadata")
    if raw is None:
        return None
    try:
        cur = _Cursor(raw)
        unstable = cur.byte()
        compiler = cur.raw(cur.uleb(64)).decode("ascii")
        language = cur.raw(cur.uleb(64)).decode("ascii")
    except (BytecodeError, UnicodeDecodeError):
        return None
    if unstable not in (0, 1):
        return None
    return {"compiler_version": compiler, "language_version": language, "unstable": str(bool(unstable)).lower()}
