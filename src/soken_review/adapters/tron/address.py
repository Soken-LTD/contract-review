"""TRON address codec (05 section 4.3).

TRON addresses are base58check encoded with a 0x41 network byte (21 bytes total).
Internal form: lowercase hex of the 20 bytes *after* 0x41, no prefix.
Display form: base58check string starting with 'T'.

Example (F24, USDT-TRC20):
  display  TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
  wire     41a614f803b6fd780986a42c78ec9c7f77e6ded13c  (21 bytes, 0x41 prefix)
  internal a614f803b6fd780986a42c78ec9c7f77e6ded13c   (20 bytes, used for unit_label h6)

unit_label h6 (05 3.4): first 6 lowercase hex of the 20-byte internal address.
  TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t  ->  h6 = a614f8
"""

from __future__ import annotations

import hashlib

_TRON_NETWORK_BYTE = 0x41
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class TronAddressError(ValueError):
    """Invalid TRON address."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _b58decode(s: str) -> bytes:
    """Decode a base58 string to bytes (no checksum verification)."""
    alphabet = _B58_ALPHABET
    n = 0
    for char in s.encode("ascii"):
        n = n * 58 + alphabet.index(char)
    result = []
    while n > 0:
        n, r = divmod(n, 256)
        result.append(r)
    # Count leading '1's (= leading zero bytes)
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return bytes(pad) + bytes(reversed(result))


def _b58encode(data: bytes) -> str:
    """Base58 encode bytes."""
    alphabet = _B58_ALPHABET
    n = int.from_bytes(data, "big")
    result: list[bytes] = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(alphabet[r : r + 1])
    for byte in data:
        if byte == 0:
            result.append(b"1")
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def _checksum(payload: bytes) -> bytes:
    """SHA256(SHA256(payload))[:4] — TRON base58check checksum."""
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def b58_to_hex(addr: str) -> str:
    """Decode a TRON base58check address to the 20-byte internal hex (no 0x41 prefix).

    Raises TronAddressError on invalid input.
    Returns lowercase hex string of 40 chars (20 bytes).
    """
    try:
        raw = _b58decode(addr)
    except (ValueError, IndexError) as exc:
        raise TronAddressError(f"not valid base58: {addr!r}") from exc
    if len(raw) != 25:
        raise TronAddressError(f"expected 25 bytes after decode, got {len(raw)}: {addr!r}")
    payload, checksum = raw[:21], raw[21:]
    if _checksum(payload) != checksum:
        raise TronAddressError(f"checksum mismatch for {addr!r}")
    if payload[0] != _TRON_NETWORK_BYTE:
        raise TronAddressError(
            f"expected network byte 0x{_TRON_NETWORK_BYTE:02x}, got 0x{payload[0]:02x}: {addr!r}"
        )
    return payload[1:].hex()


def hex_to_b58(addr_hex: str) -> str:
    """Encode a 20-byte (or 21-byte 0x41-prefixed) hex string to TRON base58check.

    Accepts:
      - 40-char hex (20 bytes, internal form): a614f803...
      - 42-char hex with 0x41 prefix: 41a614f803...
    Returns the base58check display address (T...).
    Raises TronAddressError on invalid input.
    """
    raw = addr_hex.lower().lstrip("0x").lstrip("0X")
    if len(raw) == 42 and raw.startswith("41"):
        # Already 0x41-prefixed 21-byte hex
        body = bytes.fromhex(raw[2:])  # 20 bytes
    elif len(raw) == 40:
        body = bytes.fromhex(raw)
    else:
        raise TronAddressError(
            f"expected 40-char (20-byte) or 42-char (0x41+20-byte) hex, got {len(raw)} chars: {addr_hex!r}"
        )
    payload = bytes([_TRON_NETWORK_BYTE]) + body
    checksum = _checksum(payload)
    return _b58encode(payload + checksum)


def is_tron_address(addr: str) -> bool:
    """Return True if addr looks like a TRON base58check address (T... length 34)."""
    if not addr.startswith("T") or len(addr) != 34:
        return False
    try:
        b58_to_hex(addr)
        return True
    except TronAddressError:
        return False


def to_wire_hex(internal_hex: str) -> str:
    """Return the 21-byte wire hex (0x41 + 20 bytes, lowercase, no 0x prefix).

    Used for TronGrid native API calls that expect the hex address with the 0x41 prefix.
    """
    if len(internal_hex) != 40:
        raise TronAddressError(f"expected 40-char hex, got {len(internal_hex)}: {internal_hex!r}")
    return "41" + internal_hex.lower()


def tron_h6(internal_hex: str) -> str:
    """First 6 lowercase hex chars of the 20-byte internal address (05 3.4)."""
    if len(internal_hex) < 6:
        raise TronAddressError(f"hex too short: {internal_hex!r}")
    return internal_hex[:6].lower()
