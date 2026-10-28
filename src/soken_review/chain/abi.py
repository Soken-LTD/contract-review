"""Small Solidity ABI codec for chain reads (chain access design 1.2). Pure Python, no I/O.

Covers what getters and reverts need: `uint<N>`, `int<N>`, `address`, `bool`, `bytes<N>`, `bytes`,
`string`, fixed and dynamic arrays and tuples, plus revert decoding: `Error(string)`,
`Panic(uint256)` with the compiler's code names, and custom errors named by selector.
"""

from __future__ import annotations

import re
from functools import cache
from typing import Any

from ..mapping.keccak import keccak256

PANIC_CODES = {
    0x00: "generic compiler panic", 0x01: "assert failed", 0x11: "arithmetic underflow or overflow",
    0x12: "division or modulo by zero", 0x21: "invalid enum conversion", 0x22: "bad storage byte array encoding",
    0x31: "pop on an empty array", 0x32: "array index out of bounds", 0x41: "memory allocation too large",
    0x51: "call to a zero function pointer",
}
_ERROR_SEL = bytes.fromhex("08c379a0")
_PANIC_SEL = bytes.fromhex("4e487b71")
MAX_FIXED_DIM = 256      # T[k]: k at most this
MAX_NESTING = 3          # arrays and tuples inside each other
MAX_VALUES = 10_000      # values one encode or decode call may produce (security review 2026-10-28)
MAX_DYNAMIC_LEN = 4096   # length word of one dynamic array
_SIG_RE = re.compile(r"^([A-Za-z_$][A-Za-z0-9_$]{0,63})\((.*)\)$")
_ELEM_RE = re.compile(r"^(uint|int)(\d{0,3})$|^address$|^bool$|^bytes(\d{1,2})?$|^string$")


class AbiError(ValueError):
    """Bad signature, argument or return data."""


def split_types(s: str, depth: int = 0) -> list[str]:
    """`uint256,(address,bool)[],string` -> top-level types (validated, nesting bounded)."""
    s = s.strip()
    if not s:
        return []
    out, level, cur = [], 0, []
    for ch in s:
        if ch == "(":
            level += 1
        elif ch == ")":
            level -= 1
            if level < 0:
                raise AbiError("unbalanced parentheses")
        if ch == "," and level == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if level:
        raise AbiError("unbalanced parentheses")
    out.append("".join(cur).strip())
    if any(not t for t in out):
        raise AbiError("empty type")
    if len(out) > 64:
        raise AbiError("more than 64 types in one tuple")
    for t in out:
        _check_type(t, depth)
    return out


def _check_type(t: str, depth: int = 0) -> None:
    if len(t) > 400:
        raise AbiError("type string too long")
    base, dims = _split_array(t)
    if dims is not None:
        if dims and (not dims.isdigit() or not 1 <= int(dims) <= MAX_FIXED_DIM):
            raise AbiError(f"fixed array size must be 1 to {MAX_FIXED_DIM}")
        if depth + 1 > MAX_NESTING:
            raise AbiError(f"types nest more than {MAX_NESTING} levels")
        _check_type(base, depth + 1)
        return
    if base.startswith("("):
        if not base.endswith(")"):
            raise AbiError(f"unsupported type {t[:40]!r}")
        if depth + 1 > MAX_NESTING:
            raise AbiError(f"types nest more than {MAX_NESTING} levels")
        split_types(base[1:-1], depth + 1)
        return
    m = _ELEM_RE.match(base)
    if not m:
        raise AbiError(f"unsupported type {t[:40]!r}")
    if base.startswith(("uint", "int")):
        bits = int(m.group(2) or 256)
        if bits % 8 or not 8 <= bits <= 256:
            raise AbiError(f"bad integer width {t}")
    if base.startswith("bytes") and m.group(3) and not 1 <= int(m.group(3)) <= 32:
        raise AbiError(f"bad bytes width {t}")


class _Budget:
    """One shared value budget per encode or decode call."""

    def __init__(self, n: int = MAX_VALUES) -> None:
        self.left = n

    def take(self, n: int = 1) -> None:
        self.left -= n
        if self.left < 0:
            raise AbiError(f"more than {MAX_VALUES} values in one call")


def _split_array(t: str) -> tuple[str, str | None]:
    """`uint256[3][]` -> (`uint256[3]`, ``) (the outer dimension), `uint256` -> (`uint256`, None)."""
    if t.endswith("]"):
        i = t.rfind("[")
        return t[:i], t[i + 1:-1]
    return t, None


def parse_signature(sig: str) -> tuple[str, list[str], str]:
    """`getPastTotalSupply(uint256)` -> (name, [types], canonical signature)."""
    m = _SIG_RE.match(sig.replace(" ", ""))
    if not m:
        raise AbiError("a function signature looks like name(type1,type2)")
    types = split_types(m.group(2))
    types = [_canonical(t) for t in types]
    return m.group(1), types, f"{m.group(1)}({','.join(types)})"


def _canonical(t: str) -> str:
    base, dim = _split_array(t)
    if dim is not None:
        return f"{_canonical(base)}[{dim}]"
    if base.startswith("("):
        return "(" + ",".join(_canonical(x) for x in split_types(base[1:-1])) + ")"
    if base in ("uint", "int"):
        return base + "256"
    return base


@cache
def selector(canonical_sig: str) -> bytes:
    return keccak256(canonical_sig.encode())[:4]


def _is_dynamic(t: str) -> bool:
    base, dim = _split_array(t)
    if dim is not None:
        return dim == "" or _is_dynamic(base)
    if base.startswith("("):
        return any(_is_dynamic(x) for x in split_types(base[1:-1]))
    return base in ("bytes", "string")


def _static_size(t: str) -> int:
    base, dim = _split_array(t)
    if dim is not None:
        return int(dim) * _static_size(base)
    if base.startswith("("):
        return sum(_static_size(x) for x in split_types(base[1:-1]))
    return 32


# ── encode ─────────────────────────────────────────────────────────────────


def _to_int(v: Any) -> int:
    if isinstance(v, bool):
        raise AbiError("a number argument must not be a boolean")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip().replace("_", "")
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    raise AbiError("a number argument must be an integer or a decimal or 0x string")


def _enc_elem(t: str, v: Any) -> bytes:
    if t.startswith("uint"):
        n = _to_int(v)
        bits = int(t[4:] or 256)
        if not 0 <= n < 1 << bits:
            raise AbiError(f"{n} is outside {t}")
        return n.to_bytes(32, "big")
    if t.startswith("int"):
        n = _to_int(v)
        bits = int(t[3:] or 256)
        if not -(1 << (bits - 1)) <= n < 1 << (bits - 1):
            raise AbiError(f"{n} is outside {t}")
        return (n % (1 << 256)).to_bytes(32, "big")
    if t == "address":
        if not isinstance(v, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", v):
            raise AbiError("an address argument is 0x and 40 hex digits")
        return bytes(12) + bytes.fromhex(v[2:])
    if t == "bool":
        if not isinstance(v, bool):
            raise AbiError("a bool argument is true or false")
        return (1 if v else 0).to_bytes(32, "big")
    if t.startswith("bytes") and t != "bytes":
        size = int(t[5:])
        raw = _hex_bytes(v)
        if len(raw) != size:
            raise AbiError(f"{t} needs {size} bytes")
        return raw + bytes(32 - size)
    raise AbiError(f"unsupported type {t}")


def _hex_bytes(v: Any) -> bytes:
    if not isinstance(v, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", v):
        raise AbiError("a bytes argument is a 0x hex string")
    return bytes.fromhex(v[2:])


def _pad(b: bytes) -> bytes:
    return b + bytes((-len(b)) % 32)


def _enc(t: str, v: Any, budget: _Budget) -> bytes:
    base, dim = _split_array(t)
    if dim is not None:
        if not isinstance(v, list):
            raise AbiError(f"{t} needs a list")
        if dim and len(v) != int(dim):
            raise AbiError(f"{t} needs {dim} items")
        if len(v) > MAX_DYNAMIC_LEN:
            raise AbiError(f"array longer than {MAX_DYNAMIC_LEN} items")
        body = encode([base] * len(v), v, _budget=budget)
        return (len(v).to_bytes(32, "big") + body) if dim == "" else body
    if base.startswith("("):
        inner = split_types(base[1:-1])
        if not isinstance(v, list) or len(v) != len(inner):
            raise AbiError(f"{t} needs a list of {len(inner)} values")
        return encode(inner, v, _budget=budget)
    if base == "string":
        if not isinstance(v, str):
            raise AbiError("a string argument must be text")
        raw = v.encode()
        return len(raw).to_bytes(32, "big") + _pad(raw)
    if base == "bytes":
        raw = _hex_bytes(v)
        return len(raw).to_bytes(32, "big") + _pad(raw)
    return _enc_elem(base, v)


def encode(types: list[str], values: list[Any], *, _budget: _Budget | None = None) -> bytes:
    budget = _budget or _Budget()
    if len(types) != len(values):
        raise AbiError(f"{len(types)} arguments expected, {len(values)} given")
    if _budget is None:
        for t in types:
            _check_type(t)
    budget.take(len(types))
    heads: list[bytes | None] = []
    tails: list[bytes] = []
    head_size = sum(32 if _is_dynamic(t) else _static_size(t) for t in types)
    for t, v in zip(types, values, strict=True):
        if _is_dynamic(t):
            heads.append(None)
            tails.append(_enc(t, v, budget))
        else:
            heads.append(_enc(t, v, budget))
            tails.append(b"")
    out, offset = b"", head_size
    for h, tail in zip(heads, tails, strict=True):
        if h is None:
            out += offset.to_bytes(32, "big")
            offset += len(tail)
        else:
            out += h
    return out + b"".join(tails)


def encode_call(sig: str, args: list[Any]) -> tuple[bytes, str]:
    """Calldata and the canonical signature."""
    _name, types, canonical = parse_signature(sig)
    return selector(canonical) + encode(types, list(args)), canonical


# ── decode ─────────────────────────────────────────────────────────────────


def _word(data: bytes, pos: int) -> int:
    if pos + 32 > len(data):
        raise AbiError("return data is shorter than the declared types")
    return int.from_bytes(data[pos:pos + 32], "big")


def _dec(t: str, data: bytes, pos: int, base_pos: int, budget: _Budget) -> Any:
    """Value of type t whose head is at data[pos]; dynamic offsets are relative to base_pos."""
    base, dim = _split_array(t)
    if _is_dynamic(t):
        start = base_pos + _word(data, pos)
        if start > len(data):
            raise AbiError("offset outside the return data")
        if dim is not None:
            if dim == "":
                n = _word(data, start)
                if n > MAX_DYNAMIC_LEN:
                    raise AbiError(f"array longer than {MAX_DYNAMIC_LEN} items")
                return decode([base] * n, data, start + 32, _budget=budget)
            return decode([base] * int(dim), data, start, _budget=budget)
        if base.startswith("("):
            return decode(split_types(base[1:-1]), data, start, _budget=budget)
        n = _word(data, start)
        if start + 32 + n > len(data):
            raise AbiError("bytes run past the return data")
        raw = data[start + 32:start + 32 + n]
        return raw.decode("utf-8", errors="replace") if base == "string" else "0x" + raw.hex()
    if dim is not None:
        return decode([base] * int(dim), data, pos, _budget=budget)
    if base.startswith("("):
        return decode(split_types(base[1:-1]), data, pos, _budget=budget)
    w = _word(data, pos)
    if base.startswith("uint"):
        return w
    if base.startswith("int"):
        return w - (1 << 256) if w >> 255 else w
    if base == "address":
        if w >> 160:
            raise AbiError("address word has high bits set")
        return "0x" + data[pos + 12:pos + 32].hex()
    if base == "bool":
        if w > 1:
            raise AbiError("bool word is not 0 or 1")
        return bool(w)
    size = int(base[5:])
    return "0x" + data[pos:pos + size].hex()


def decode(types: list[str], data: bytes, base_pos: int = 0, *, _budget: _Budget | None = None) -> list[Any]:
    budget = _budget or _Budget()
    if _budget is None:
        for t in types:
            _check_type(t)
    budget.take(len(types))
    out, pos = [], base_pos
    for t in types:
        out.append(_dec(t, data, pos, base_pos, budget))
        pos += 32 if _is_dynamic(t) else _static_size(t)
    return out


def parse_returns(spec: str | None) -> list[str] | None:
    if spec is None:
        return None
    s = spec.strip()
    if s.startswith("(") and s.endswith(")") and _balanced_outer(s):
        s = s[1:-1]
    return [_canonical(t) for t in split_types(s)]


def _balanced_outer(s: str) -> bool:
    depth = 0
    for i, ch in enumerate(s):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and i < len(s) - 1:
            return False
    return True


def decode_revert(data: bytes) -> dict[str, Any]:
    """`{kind, reason, code?, selector?}`. `reason` for Error(string) is chain text (untrusted)."""
    if not data:
        return {"kind": "empty", "reason": "reverted without data"}
    if data[:4] == _ERROR_SEL:
        try:
            (msg,) = decode(["string"], data[4:])
            return {"kind": "error_string", "reason": msg}
        except AbiError:
            return {"kind": "malformed", "reason": "Error(string) with malformed data", "selector": "0x08c379a0"}
    if data[:4] == _PANIC_SEL and len(data) >= 36:
        code = int.from_bytes(data[4:36], "big")
        name = PANIC_CODES.get(code, "unknown panic code")
        return {"kind": "panic", "code": code, "reason": f"Panic(0x{code:02x}): {name}"}
    if len(data) >= 4:
        return {"kind": "custom_error", "selector": "0x" + data[:4].hex(),
                "reason": f"custom error 0x{data[:4].hex()}"}
    return {"kind": "malformed", "reason": f"{len(data)} bytes of revert data"}


def name_custom_error(sel: str, signatures: list[str]) -> str | None:
    """The signature among `signatures` (`InsufficientBalance(uint256)`) whose selector is sel."""
    for s in signatures:
        try:
            _n, _t, canonical = parse_signature(s)
        except AbiError:
            continue
        if "0x" + selector(canonical).hex() == sel:
            return canonical
    return None
