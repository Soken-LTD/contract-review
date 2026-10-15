"""TON address detection and normalisation (plan v4 06 section 4.1).

Formats accepted:
  raw      -1:0000...0000   workchain (int), colon, 64 lowercase hex chars
  user-friendly  48-char base64url or base64, 36-byte decoded:
               byte 0: tag (0x11=non-bounc/non-test, 0x51=non-bounc/test,
                            0x91=bounc/non-test, 0xD1=bounc/test)
               byte 1: workchain (0x00=0, 0xFF=-1)
               bytes 2-33: 32-byte account id
               bytes 34-35: CRC16-CCITT over bytes 0-33

Testnet flag in user-friendly is rejected (tag bits 0x40 set -> tags 0x51, 0xD1).
"""

from __future__ import annotations

import logging
import re
import struct

logger = logging.getLogger(__name__)

# ── raw address pattern ────────────────────────────────────────────────────

_RAW_RE = re.compile(r"^(-?\d+):([0-9a-fA-F]{64})$")

# ── valid user-friendly tags (non-testnet only) ────────────────────────────

_VALID_TAGS = {0x11, 0x91}  # non-bounceable/non-test and bounceable/non-test

# ── CRC16-CCITT (XMODEM polynomial 0x1021) ───────────────────────────────

_CRC16_TABLE: list[int] = []


def _build_crc16_table() -> None:
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
        _CRC16_TABLE.append(crc & 0xFFFF)


_build_crc16_table()


def _crc16(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC16_TABLE[((crc >> 8) ^ byte) & 0xFF]
    return crc


def _b64_decode(s: str) -> bytes | None:
    """Try base64url then base64; return raw bytes or None."""
    import base64
    # Normalize: base64url uses - and _, base64 uses + and /
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    for urlsafe in (True, False):
        try:
            if urlsafe:
                return base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
            else:
                return base64.b64decode(padded, validate=True)
        except Exception as exc:  # noqa: BLE001
            logger.debug("base64 decode attempt urlsafe=%s failed: %s", urlsafe, exc)
            continue
    return None


def parse_raw_address(s: str) -> tuple[str | None, str | None]:
    """Parse a raw address string. Returns (raw_internal, display) or (None, None).

    raw_internal: lowercase  '-1:0000...' form used internally
    display: same as raw_internal for raw addresses
    """
    m = _RAW_RE.match(s.strip())
    if not m:
        return None, None
    wc = int(m.group(1))
    if wc not in (0, -1):
        return None, None
    account = m.group(2).lower()
    raw = f"{wc}:{account}"
    return raw, raw


def parse_friendly_address(s: str) -> tuple[str | None, str | None]:
    """Parse a user-friendly TON address. Returns (raw_internal, display) or (None, None).

    Rejects testnet flag (tags 0x51 and 0xD1).
    raw_internal: '-1:hex64' or '0:hex64'
    display: the original input string (validated)
    """
    s = s.strip()
    if len(s) != 48:
        return None, None
    decoded = _b64_decode(s)
    if decoded is None or len(decoded) != 36:
        return None, None
    tag = decoded[0]
    if tag not in _VALID_TAGS:
        return None, None
    wc_byte = decoded[1]
    if wc_byte == 0x00:
        wc = 0
    elif wc_byte == 0xFF:
        wc = -1
    else:
        return None, None
    account_id = decoded[2:34]
    checksum = struct.unpack(">H", decoded[34:36])[0]
    if _crc16(decoded[:34]) != checksum:
        return None, None
    raw = f"{wc}:{account_id.hex()}"
    return raw, s


def parse_ton_address(s: str) -> tuple[str | None, str | None]:
    """Try raw then user-friendly. Returns (raw_internal, display) or (None, None)."""
    raw, display = parse_raw_address(s)
    if raw is not None:
        return raw, display
    return parse_friendly_address(s)


def raw_to_friendly(raw: str, *, bounceable: bool = True) -> str | None:
    """Convert a raw address to user-friendly base64url (non-testnet).

    Returns None if raw is not a valid raw address.
    """
    import base64
    m = _RAW_RE.match(raw)
    if not m:
        return None
    wc = int(m.group(1))
    if wc not in (0, -1):
        return None
    account_id = bytes.fromhex(m.group(2))
    tag = 0x91 if bounceable else 0x11
    wc_byte = 0x00 if wc == 0 else 0xFF
    payload = bytes([tag, wc_byte]) + account_id
    checksum = _crc16(payload)
    full = payload + struct.pack(">H", checksum)
    return base64.urlsafe_b64encode(full).decode("ascii")


def detect_language_from_files(files: dict[str, str]) -> str | None:
    """Infer TON contract language from file extensions in a candidate (plan 06 4.1).

    Returns 'func', 'tact', 'tolk', or None.
    """
    exts: dict[str, int] = {}
    for path in files:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if ext in ("fc", "func"):
            exts["func"] = exts.get("func", 0) + 1
        elif ext == "tact":
            exts["tact"] = exts.get("tact", 0) + 1
        elif ext == "tolk":
            exts["tolk"] = exts.get("tolk", 0) + 1
    # Tolk config files
    for path in files:
        base = path.rsplit("/", 1)[-1]
        if base == "Acton.toml":
            exts["tolk"] = exts.get("tolk", 0) + 1
        elif base == "tact.config.json":
            exts["tact"] = exts.get("tact", 0) + 1
    if not exts:
        return None
    return max(exts, key=lambda k: exts[k])
