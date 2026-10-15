"""Decode the hashed `sierra_program` felts into a Sierra program (07 5.1, soken-sierra-facts role).

Facts must come from what the class hash covers: the debug table of an artifact is not hashed and
is written by the build sandbox, so it is never read here. Port of cairo-lang-starknet-classes
`felt252_vec_compression.rs` (decompress) and `felt252_serde.rs` (Program deserialize) at v2.13.1:
https://github.com/starkware-libs/cairo/tree/v2.13.1/crates/cairo-lang-starknet-classes/src

Any malformed input raises SierraDecodeError; callers turn that into `unknown` facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from soken_review.adapters.starknet.felt import NonCanonicalFelt, P, parse_felt, starknet_keccak

_USIZE_MAX = 2**64 - 1           # usize::MAX on the 64-bit build that serializes Fallthrough
_U64_MAX = 2**64 - 1
_TYPE_INFO_SHIFT = 128

# felt252_serde.rs SERDE_SUPPORTED_LONG_IDS (generic ids longer than 31 bytes, keccak encoded)
_LONG_IDS = (
    "storage_address_from_base_and_offset",
    "contract_address_try_from_felt252",
    "storage_base_address_from_felt252",
    "storage_address_try_from_felt252",
    "secp256k1_get_point_from_x_syscall",
    "secp256r1_get_point_from_x_syscall",
    "circuit_failure_guarantee_verify",
    "u96_limbs_less_than_guarantee_verify",
    "u96_single_limb_less_than_guarantee_verify",
)
_LONG_NAME_FIX = {starknet_keccak(n.encode()): n for n in _LONG_IDS}


class SierraDecodeError(ValueError):
    pass


# GenericArg kinds (felt252_serde.rs GenericArg)
ARG_USER_TYPE, ARG_TYPE, ARG_VALUE, ARG_USER_FUNC, ARG_LIBFUNC = "user_type", "type", "value", "user_func", "libfunc"


@dataclass
class LibfuncDecl:
    generic_id: str
    args: list[tuple[str, int]]


@dataclass
class TypeDecl:
    generic_id: str
    args: list[tuple[str, int]]


@dataclass
class Statement:
    libfunc_id: int | None          # None for Return
    branch_targets: list[int | None]  # None = fallthrough


@dataclass
class Program:
    types: list[TypeDecl]
    libfuncs: list[LibfuncDecl]
    statements: list[Statement]
    func_entries: list[int]          # entry statement index per user function id
    consts: set[int] = field(default_factory=set)


def _felt(value: Any) -> int:
    try:
        return parse_felt(value)
    except NonCanonicalFelt as exc:
        raise SierraDecodeError(str(exc)) from exc


def words_per_felt(padded_code_size: int) -> int:
    count = 0
    max_encoded = padded_code_size
    while max_encoded < P:
        max_encoded *= padded_code_size
        count += 1
    return count


def decompress(packed: list[int]) -> list[int]:
    if len(packed) < 3:
        raise SierraDecodeError("short program")
    code_size, padding = packed[0], packed[1]
    if code_size >= len(packed) - 1:
        raise SierraDecodeError("bad code size")
    code = packed[2:2 + code_size]
    rest = packed[2 + code_size:]
    if not rest:
        raise SierraDecodeError("no length")
    remaining, words = rest[0], rest[1:]
    padded = code_size + padding
    if padded < 2:
        raise SierraDecodeError("bad padding")
    per_felt = words_per_felt(padded)
    out: list[int] = []
    for value in words:
        n = min(per_felt, remaining)
        for _ in range(n):
            value, word = divmod(value, padded)
            if word >= code_size:
                raise SierraDecodeError("code word out of range")
            out.append(code[word])
        remaining -= n
    if remaining:
        raise SierraDecodeError("truncated program")
    return out


class _Reader:
    def __init__(self, values: list[int]) -> None:
        self.v = values
        self.i = 0

    def take(self) -> int:
        if self.i >= len(self.v):
            raise SierraDecodeError("unexpected end")
        x = self.v[self.i]
        self.i += 1
        return x

    def usize(self) -> int:
        x = self.take()
        if x > _USIZE_MAX:
            raise SierraDecodeError("usize out of range")
        return x

    def u64(self) -> int:
        x = self.take()
        if x > _U64_MAX:
            raise SierraDecodeError("u64 out of range")
        return x

    def length(self) -> int:
        n = self.usize()
        if n > len(self.v) - self.i:
            raise SierraDecodeError("length beyond input")
        return n

    def generic_id(self) -> str:
        x = self.take()
        if x in _LONG_NAME_FIX:
            return _LONG_NAME_FIX[x]
        raw = x.to_bytes((x.bit_length() + 7) // 8, "big") if x else b""
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SierraDecodeError("generic id not utf-8") from exc

    def generic_arg(self) -> tuple[str, int]:
        kind = self.usize()
        if kind == 0:
            return ARG_USER_TYPE, self.take()
        if kind == 1:
            return ARG_TYPE, self.u64()
        if kind == 2:
            return ARG_VALUE, self.take()
        if kind == 3:
            return ARG_USER_FUNC, self.u64()
        if kind == 4:
            return ARG_LIBFUNC, self.u64()
        if kind == 5:
            return ARG_VALUE, -self.take()
        raise SierraDecodeError("bad generic arg kind")


def decode_program(sierra_program: list[Any]) -> Program:
    """Full decode: versions (6 felts), then the compressed Program."""
    felts = [_felt(x) for x in sierra_program]
    if len(felts) < 7:
        raise SierraDecodeError("program too short")
    r = _Reader(decompress(felts[6:]))
    types: list[TypeDecl] = []
    for _ in range(r.length()):
        gid = r.generic_id()
        len_and_info = r.take()
        n_args = len_and_info & (2**128 - 1)
        if n_args > len(r.v) - r.i:
            raise SierraDecodeError("type args beyond input")
        types.append(TypeDecl(gid, [r.generic_arg() for _ in range(n_args)]))
    libfuncs: list[LibfuncDecl] = []
    for _ in range(r.length()):
        gid = r.generic_id()
        n_args = r.length()
        libfuncs.append(LibfuncDecl(gid, [r.generic_arg() for _ in range(n_args)]))
    statements: list[Statement] = []
    for _ in range(r.length()):
        kind = r.u64()
        if kind == 0:
            lib = r.u64()
            for _ in range(r.length()):          # args
                r.u64()
            targets: list[int | None] = []
            for _ in range(r.length()):          # branches
                t = r.usize()
                targets.append(None if t == _USIZE_MAX else t)
                for _ in range(r.length()):      # results
                    r.u64()
            statements.append(Statement(lib, targets))
        elif kind == 1:
            for _ in range(r.length()):
                r.u64()
            statements.append(Statement(None, []))
        else:
            raise SierraDecodeError("bad statement kind")
    entries: list[int] = []
    for _ in range(r.length()):
        n_params = r.length()
        for _ in range(n_params):
            r.u64()
        for _ in range(r.length()):              # ret types
            r.u64()
        for _ in range(n_params):                # param var ids
            r.u64()
        entries.append(r.usize())
    if r.i != len(r.v):
        raise SierraDecodeError("trailing data")
    for lib in libfuncs:
        if lib.args and any(k == ARG_LIBFUNC and v >= len(libfuncs) for k, v in lib.args):
            raise SierraDecodeError("libfunc arg out of range")
    prog = Program(types, libfuncs, statements, entries)
    prog.consts = {v % P for decl in (*types, *libfuncs) for k, v in decl.args if k == ARG_VALUE}
    for st in statements:
        if st.libfunc_id is not None and st.libfunc_id >= len(libfuncs):
            raise SierraDecodeError("statement libfunc out of range")
    return prog


def reachable_statements(prog: Program, roots: list[int]) -> set[int]:
    """Statement indices reachable from the given user function ids, following branches and
    user-function arguments of libfuncs (`function_call`, `coupon_call`; 07 12.2 roots).

    Out-of-range roots, call targets or branch targets raise SierraDecodeError: a program whose
    graph does not close gives unknown facts, never a smaller reachable set.
    """
    n_funcs, n_stmts = len(prog.func_entries), len(prog.statements)
    seen_funcs: set[int] = set()
    seen: set[int] = set()
    for f in roots:
        if not isinstance(f, int) or isinstance(f, bool) or not 0 <= f < n_funcs:
            raise SierraDecodeError(f"function index out of range: {f!r}")
    func_stack = list(roots)
    while func_stack:
        f = func_stack.pop()
        if f in seen_funcs:
            continue
        seen_funcs.add(f)
        stack = [prog.func_entries[f]]
        while stack:
            s = stack.pop()
            if not 0 <= s < n_stmts:
                raise SierraDecodeError(f"statement index out of range: {s}")
            if s in seen:
                continue
            seen.add(s)
            st = prog.statements[s]
            if st.libfunc_id is None:
                continue
            for kind, value in prog.libfuncs[st.libfunc_id].args:
                if kind == ARG_USER_FUNC:
                    if not 0 <= value < n_funcs:
                        raise SierraDecodeError(f"user function arg out of range: {value}")
                    func_stack.append(value)
            for t in st.branch_targets:
                stack.append(s + 1 if t is None else t)
    return seen
