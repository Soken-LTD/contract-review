"""TON helpers for chain reads: typed get-method stack (toncenter v2 runGetMethodStd), addresses and
one-cell slice BoCs. Pure.

The typed stack keeps tuples and lists nested and decodes addr_std slices to addresses, which the
legacy runGetMethod flattening lost (Hipo r4: getter arity 31 against 20).
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from ..adapters.ton.cell import BocError, parse_boc
from ..adapters.ton.fetch import _crc16_xmodem, _ton_address_b64

_RAW_RE = re.compile(r"^(-?\d{1,3}):([0-9a-fA-F]{64})$")
MAX_DEPTH = 6
MAX_ITEMS = 64


def parse_address(addr: str) -> tuple[int, bytes]:
    """`0:<64 hex>` or a 48-character user-friendly address -> (workchain, 32-byte hash)."""
    m = _RAW_RE.match(addr.strip())
    if m:
        return int(m.group(1)), bytes.fromhex(m.group(2))
    s = addr.strip()
    try:
        raw = base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_") + "=" * (-len(s) % 4))
    except ValueError as exc:
        raise ValueError("not a TON address") from exc
    if len(raw) != 36 or _crc16_xmodem(raw[:34]) != int.from_bytes(raw[34:], "big"):
        raise ValueError("not a TON address (length or checksum)")
    wc = raw[1] - 256 if raw[1] >= 128 else raw[1]
    return wc, raw[2:34]


def raw_form(wc: int, h: bytes) -> str:
    return f"{wc}:{h.hex()}"


def friendly(wc: int, h: bytes) -> str:
    return _ton_address_b64(wc, h)


def _cell_bits(data: bytes, d2: int) -> tuple[int, int]:
    """(value as int, bit length) of a cell's data, completion tag removed."""
    n = int.from_bytes(data, "big") if data else 0
    bits = len(data) * 8
    if d2 % 2 == 1 and data:
        # strip the completion tag: trailing zeros then one 1 bit
        while n and not n & 1:
            n >>= 1
            bits -= 1
        n >>= 1
        bits -= 1
    return n, bits


def slice_address(boc_b64: str) -> tuple[int, bytes] | None:
    """addr_std at the start of the root cell of a slice BoC, else None."""
    try:
        cells, roots = parse_boc(base64.b64decode(boc_b64))
    except (BocError, ValueError):
        return None
    root = cells[roots[0]]
    n, bits = _cell_bits(root.data, root.d2)
    if bits < 267:
        return None
    top = n >> (bits - 267)
    if top >> 265 != 0b10 or (top >> 264) & 1:
        return None
    wc = (top >> 256) & 0xFF
    return (wc - 256 if wc >= 128 else wc), (top & ((1 << 256) - 1)).to_bytes(32, "big")


def address_slice_boc(wc: int, h: bytes) -> str:
    """Base64 BoC of a one-cell slice holding addr_std (the argument of get_wallet_address)."""
    value = (0b100 << 264) | ((wc & 0xFF) << 256) | int.from_bytes(h, "big")   # 10, anycast 0, wc, hash
    bits = 267
    pad = (-(bits + 1)) % 8
    data_int = ((value << 1) | 1) << pad          # completion tag
    n_bytes = (bits + 1 + pad) // 8
    data = data_int.to_bytes(n_bytes, "big")
    d1, d2 = 0, (bits // 8) * 2 + (1 if bits % 8 else 0)
    cell = bytes([d1, d2]) + data
    header = bytes.fromhex("b5ee9c72") + bytes([0x01, 0x01, 0x01, 0x01, 0x00, len(cell), 0x00])
    return base64.b64encode(header + cell).decode()


def decode_stack(stack: Any, depth: int = 0) -> list[dict[str, Any]]:
    """Typed values `{type, value, ...}` for a runGetMethodStd stack."""
    out: list[dict[str, Any]] = []
    if not isinstance(stack, list):
        return out
    for entry in stack[:MAX_ITEMS]:
        out.append(_entry(entry, depth))
    return out


def _entry(e: Any, depth: int) -> dict[str, Any]:
    if not isinstance(e, dict):
        return {"type": "unknown"}
    t = e.get("@type", "")
    if t == "tvm.stackEntryNumber":
        num = ((e.get("number") or {}).get("number"))
        try:
            return {"type": "int", "value": int(str(num))}
        except ValueError:
            return {"type": "unknown"}
    if t in ("tvm.stackEntryCell", "tvm.stackEntrySlice"):
        obj = e.get("cell") if t == "tvm.stackEntryCell" else e.get("slice")
        b64 = (obj or {}).get("bytes") or ""
        kind = "cell" if t == "tvm.stackEntryCell" else "slice"
        addr = slice_address(b64) if b64 else None
        rec: dict[str, Any] = {"type": kind, "boc_sha256": hashlib.sha256(b64.encode()).hexdigest()[:16],
                               "boc_bytes": len(b64) * 3 // 4}
        if addr is not None:
            rec.update(type="address", value=raw_form(*addr), friendly=friendly(*addr))
        return rec
    if t in ("tvm.stackEntryTuple", "tvm.stackEntryList"):
        inner = (e.get("tuple") or e.get("list") or {}).get("elements") or []
        if depth >= MAX_DEPTH:
            return {"type": "tuple", "items": [], "truncated": True}
        return {"type": "tuple" if t.endswith("Tuple") else "list", "items": [_entry(x, depth + 1) for x in inner[:MAX_ITEMS]]}
    return {"type": "unknown"}


def num_arg(v: Any) -> dict[str, Any]:
    if isinstance(v, bool) or not isinstance(v, int | str):
        raise TypeError("TON get-method arguments are integers (or an address string)")
    if isinstance(v, str) and not re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", v.strip()):
        wc, h = parse_address(v)
        return {"@type": "tvm.stackEntrySlice", "slice": {"@type": "tvm.slice", "bytes": address_slice_boc(wc, h)}}
    n = int(v, 0) if isinstance(v, str) else v
    return {"@type": "tvm.stackEntryNumber", "number": {"@type": "tvm.numberDecimal", "number": str(n)}}
