"""Starknet field arithmetic and hashes computed by the supervisor (07 8.2, 9.1).

Supervisor-only: the class hash that decides `dep.match` is computed here from artifact bytes,
never taken from a build container. Pure Python, no third-party crypto dependency.

- P: Stark field prime 2^251 + 17 * 2^192 + 1.
- keccak256: original Keccak (pad 0x01), as Ethereum and Starknet use it.
- starknet_keccak: keccak256 masked to 250 bits; selectors are starknet_keccak(name).
- Poseidon: Hades permutation, width 3, 8 full + 83 partial rounds, x^3, MDS
  [[3,1,1],[1,-1,1],[1,1,-2]]; round constants are sha256("Hades<i>") mod P (cairo-lang
  poseidon_utils). Checked against live mainnet class hashes in tests (sierra_class_hash).
"""

from __future__ import annotations

import hashlib
import re

P = 2**251 + 17 * 2**192 + 1
_MASK_250 = 2**250 - 1

_HEX_FELT_RE = re.compile(r"^0x[0-9a-fA-F]{1,64}$")


class NonCanonicalFelt(ValueError):
    """A felt outside [0, P) or not in the RPC hex form: refused, never reduced (no aliases)."""


def parse_felt(value: object) -> int:
    """The one felt parser for hashing and decoding: int in [0, P) or "0x<hex>" below P.

    Decimal strings, bools, negatives and values >= P are refused, so the value hashed into the
    class hash and the value the decoder reads are always the same integer.
    """
    if isinstance(value, bool):
        raise NonCanonicalFelt("bool is not a felt")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str) and _HEX_FELT_RE.match(value):
        n = int(value, 16)
    else:
        raise NonCanonicalFelt(f"not a canonical felt: {value!r}"[:120])
    if not 0 <= n < P:
        raise NonCanonicalFelt("felt out of range [0, P)")
    return n


# --------------------------------------------------------------------------------------------
# Addresses (07 9.3: 1 to 64 hex, below P; leading zeros stripped for storage and lookup)
# --------------------------------------------------------------------------------------------

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{1,64}$")


def normalize_address(value: str) -> str | None:
    """Canonical lower-case `0x<hex>` without leading zeros, or None when invalid (E_ADDRESS_INVALID)."""
    if not isinstance(value, str) or not _ADDR_RE.match(value.strip()):
        return None
    n = int(value.strip(), 16)
    if n >= P:
        return None
    return hex(n)


def display_address(value: str) -> str:
    """64-hex zero-padded form used in links and reports."""
    return "0x" + format(int(value, 16), "064x")


# --------------------------------------------------------------------------------------------
# Keccak-256 (pure Python)
# --------------------------------------------------------------------------------------------

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M64 = 2**64 - 1


def _rol(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _M64 if n else x


def _keccak_f(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


def starknet_keccak(data: bytes) -> int:
    return int.from_bytes(keccak256(data), "big") & _MASK_250


def selector(name: str) -> int:
    """Entry point selector of a function name (sn_keccak of the ASCII name)."""
    return starknet_keccak(name.encode("ascii"))


def short_string(text: str) -> int:
    raw = text.encode("ascii")
    if len(raw) > 31:
        raise ValueError("short string longer than 31 bytes")
    return int.from_bytes(raw, "big")


# --------------------------------------------------------------------------------------------
# Poseidon (Hades permutation over P)
# --------------------------------------------------------------------------------------------

_FULL_ROUNDS = 8
_PARTIAL_ROUNDS = 83
_WIDTH = 3


def _round_constants() -> list[list[int]]:
    flat = [int(hashlib.sha256(f"Hades{i}".encode("ascii")).hexdigest(), 16) % P
            for i in range((_FULL_ROUNDS + _PARTIAL_ROUNDS) * _WIDTH)]
    return [flat[i:i + _WIDTH] for i in range(0, len(flat), _WIDTH)]


_ARK = _round_constants()


def _mix(s: list[int]) -> list[int]:
    a, b, c = s
    t = a + b + c
    return [(t + 2 * a) % P, (t - 2 * b) % P, (t - 3 * c) % P]


def hades_permutation(state: list[int]) -> list[int]:
    s = [x % P for x in state]
    half = _FULL_ROUNDS // 2
    r = 0
    for _ in range(half):
        s = [pow((x + k) % P, 3, P) for x, k in zip(s, _ARK[r], strict=True)]
        s = _mix(s)
        r += 1
    for _ in range(_PARTIAL_ROUNDS):
        s = [(x + k) % P for x, k in zip(s, _ARK[r], strict=True)]
        s[2] = pow(s[2], 3, P)
        s = _mix(s)
        r += 1
    for _ in range(half):
        s = [pow((x + k) % P, 3, P) for x, k in zip(s, _ARK[r], strict=True)]
        s = _mix(s)
        r += 1
    return s


def poseidon_hash(x: int, y: int) -> int:
    return hades_permutation([x, y, 2])[0]


def poseidon_hash_many(values: list[int]) -> int:
    padded = [v % P for v in values] + [1]
    if len(padded) % 2:
        padded.append(0)
    s = [0, 0, 0]
    for i in range(0, len(padded), 2):
        s = hades_permutation([(s[0] + padded[i]) % P, (s[1] + padded[i + 1]) % P, s[2]])
    return s[0]
