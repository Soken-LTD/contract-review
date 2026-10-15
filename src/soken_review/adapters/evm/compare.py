"""Deployment comparison for the EVM family: EVM, HyperEVM, TRON (05 sections 13.1, 13.2).

Pure functions over hex strings: no network, no sandbox, no job code. The supervisor calls
them on the solc output it parsed and the runtime it read at the pinned block (05 3.1: the
supervisor computes `dep.match`, no sandbox asserts a match).

compare(local, on-chain), equal length required:
  1. base masks, all from our own compile: solc `immutableReferences` (32-byte slots, zero in
     the local runtime, one on-chain word per immutable), library link references (20 bytes,
     placeholders in the local runtime), the library self-address push (PUSH20 0 ADDRESS)
  2. equal under base masks                       -> "exact"
  3. equal under base masks + auxdata blocks      -> "metadata_only"
  4. else                                         -> "differs"

Auxdata blocks (13.2) are bounded (security review 2026-10-10): a block is a solc metadata map
(keys ipfs, bzzr0, bzzr1, tron, solc, experimental with their fixed value shapes) followed by its
2-byte length, found in the LOCAL runtime and covering an X2 range; the on-chain bytes at the
same offsets must parse as a metadata block of the same length. X2 bytes outside any such block
are never masked (`auxdata_source = "x2_partial"`), since they can be code constants (a folded
keccak of child creation code). Without X2 ranges only the local trailer is masked
(`"trailer"`); a difference is then not evidence of a mismatch (05 13.2: UNKNOWN gives
not_checkable).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Range = tuple[int, int]  # [start, end) byte offsets in the runtime
Outcome = Literal["exact", "metadata_only", "differs", "invalid_refs"]
AuxdataSource = Literal["x2", "x2_partial", "trailer", "none", "unknown"]

IMMUTABLE_LEN = 32
LINK_LEN = 20
_MAX_CBOR_SEARCH = 96   # bytes searched before an X2 range for the metadata map header

# solc metadata keys and the CBOR value each may hold (major type, allowed lengths or None).
_META_KEYS: dict[str, tuple[tuple[int, frozenset[int] | None], ...]] = {
    "ipfs": ((2, frozenset({34})),),
    "bzzr0": ((2, frozenset({32})),),
    "bzzr1": ((2, frozenset({32})),),
    "tron": ((2, frozenset({34})),),          # tron-solc (05 F21)
    "solc": ((2, frozenset({3})), (3, None)),  # release: 3 bytes; prerelease: text
    "experimental": ((7, None),),              # true / false
}
_MAX_TEXT = 64


@dataclass
class Comparison:
    outcome: Outcome
    local_len: int
    onchain_len: int
    immutable_ranges: list[Range] = field(default_factory=list)
    link_ranges: list[Range] = field(default_factory=list)
    auxdata_ranges: list[Range] = field(default_factory=list)
    auxdata_source: AuxdataSource = "unknown"
    unmasked_x2: list[Range] = field(default_factory=list)  # X2 bytes outside metadata blocks
    linked_libraries: dict[str, str] = field(default_factory=dict)  # "file:Lib" -> on-chain address
    differing: list[Range] = field(default_factory=list)  # outside every mask applied last
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "local_len": self.local_len,
            "onchain_len": self.onchain_len,
            "immutable_ranges": [list(r) for r in self.immutable_ranges],
            "link_ranges": [list(r) for r in self.link_ranges],
            "auxdata_ranges": [list(r) for r in self.auxdata_ranges],
            "auxdata_source": self.auxdata_source,
            "unmasked_x2": [list(r) for r in self.unmasked_x2],
            "linked_libraries": dict(self.linked_libraries),
            "masked_bytes": {
                "immutables": _size(self.immutable_ranges),
                "links": _size(self.link_ranges),
                "auxdata": _size(self.auxdata_ranges),
            },
            "differing": [list(r) for r in self.differing[:50]],
            "differing_bytes": _size(self.differing),
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compare_runtime(
    local_hex: str,
    onchain_hex: str,
    *,
    immutable_refs: dict[str, Any] | None,
    link_refs: dict[str, Any] | None = None,
    x2_ranges: list[Range] | None = None,
    no_auxdata: bool = False,
    self_address: str | None = None,
) -> Comparison:
    """Compare a rebuilt runtime with the on-chain runtime under 13.1 masks.

    x2_ranges: the build's 13.2 X2 ranges for this contract; None when the build recorded none
      for it. no_auxdata: 13.2 X3 (appendCBOR false or solc before 0.4.7). self_address: the
      unit's own 20-byte address (TRON: the bytes after 0x41); a library runtime must push it.
    """
    libraries = _link_slots(link_refs)
    link_ranges = _merge([r for rs in libraries.values() for r in rs])
    local_str = _strip(local_hex)
    for s, e in link_ranges:
        if not local_str[2 * s:2 * e].startswith("__") or len(local_str) < 2 * e:
            return Comparison("invalid_refs", 0, 0, link_ranges=link_ranges,
                              detail=f"link reference {s}-{e} is not a placeholder")
    try:
        local = bytes.fromhex(_fill_link_placeholders(local_str, link_ranges))
        onchain = bytes.fromhex(_strip(onchain_hex))
    except ValueError as exc:
        return Comparison("invalid_refs", 0, 0, detail=f"hex: {exc}")

    cmp = Comparison("differs", len(local), len(onchain), link_ranges=link_ranges)
    if not local or not onchain:
        cmp.outcome = "invalid_refs"
        cmp.detail = "empty runtime"
        return cmp

    slots, err = _immutable_slots(immutable_refs, local)
    if err:
        cmp.outcome = "invalid_refs"
        cmp.detail = err
        return cmp
    cmp.immutable_ranges = _merge([r for rs in slots.values() for r in rs])
    cmp.auxdata_ranges, cmp.unmasked_x2, cmp.auxdata_source = auxdata_mask(local, x2_ranges, no_auxdata=no_auxdata)

    if len(local) != len(onchain):
        cmp.detail = "length differs"
        cmp.differing = [(min(len(local), len(onchain)), max(len(local), len(onchain)))]
        return cmp

    for ast_id, ranges in slots.items():
        if len({onchain[s:e] for s, e in ranges}) > 1:
            cmp.detail = f"immutable {ast_id} has different on-chain values at its references"
            cmp.differing = ranges
            return cmp

    for lib, ranges in libraries.items():
        addrs = {onchain[s:e] for s, e in ranges}
        if len(addrs) > 1:
            cmp.detail = f"library {lib} is linked to different addresses at its references"
            cmp.differing = ranges
            return cmp
        cmp.linked_libraries[lib] = "0x" + addrs.pop().hex()

    if _is_library(local):
        # Library runtime: PUSH20 <own address> ADDRESS EQ. The pushed word must be this unit's
        # address, else the call guard compares against some other contract.
        own = _strip(self_address)
        if len(own) != 40 or onchain[1:21] != bytes.fromhex(own):
            cmp.detail = "library self-address is not the unit's address" if own else "library self-address unknown"
            cmp.differing = [(1, 21)]
            return cmp
    base = _merge(cmp.immutable_ranges + link_ranges + ([(1, 21)] if _is_library(local) else []))
    if _masked(local, base) == _masked(onchain, base):
        cmp.outcome = "exact"
        return cmp

    # The on-chain bytes at each block must be a metadata block of the same span and key order.
    bad_blocks = [(s, e) for s, e in cmp.auxdata_ranges
                  if (theirs := _parse_metadata(onchain, s)) is None or theirs != _parse_metadata(local, s)]
    if bad_blocks:
        cmp.detail = "on-chain bytes at an auxdata block are not a metadata block of the same length"
        cmp.differing = bad_blocks
        return cmp
    full = _merge(base + cmp.auxdata_ranges)
    lm, om = _masked(local, full), _masked(onchain, full)
    if cmp.auxdata_ranges and lm == om:
        cmp.outcome = "metadata_only"
        return cmp
    cmp.differing = _diff_ranges(lm, om)
    return cmp


def auxdata_mask(
    local: bytes, x2_ranges: list[Range] | None, *, no_auxdata: bool = False,
) -> tuple[list[Range], list[Range], AuxdataSource]:
    """13.2 blocks to mask, X2 ranges left unmasked, and where the blocks came from."""
    if no_auxdata:
        return [], [], "none"
    trailer = cbor_trailer(local)
    if x2_ranges is not None:
        # X2 ran; an empty list means nothing varied (bytecodeHash none): the trailer alone.
        blocks: list[Range] = [trailer] if trailer else []
        loose: list[Range] = []
        for s, e in x2_ranges:
            if not (0 <= s < e <= len(local)):
                return [], [], "unknown"
            block = enclosing_cbor(local, s, e)
            if block:
                blocks.append(block)
            else:
                loose.append((s, e))
        return _merge(blocks), _merge(loose), ("x2_partial" if loose else "x2")
    if trailer:
        return [trailer], [], "trailer"
    return [], [], "unknown"


def cbor_trailer(code: bytes) -> Range | None:
    """The final solc auxdata block: metadata map followed by its 2-byte big-endian length."""
    if len(code) < 4:
        return None
    start = len(code) - 2 - int.from_bytes(code[-2:], "big")
    if start < 0:
        return None
    block = _metadata_block(code, start)
    return block if block and block[1] == len(code) else None


def enclosing_cbor(code: bytes, start: int, end: int) -> Range | None:
    """Nearest solc metadata block (map + 2-byte length) covering [start, end)."""
    for pos in range(start, max(-1, start - _MAX_CBOR_SEARCH), -1):
        block = _metadata_block(code, pos)
        if block and block[1] - 2 >= end:
            return block
    return None


# ---------------------------------------------------------------------------
# Masks
# ---------------------------------------------------------------------------


def _immutable_slots(refs: dict[str, Any] | None, local: bytes) -> tuple[dict[str, list[Range]], str | None]:
    """solc `immutableReferences`: {ast_id: [{start, length}]}. Every slot is 32 bytes and solc
    leaves zeros there; anything else means the artifact is not what the masks assume."""
    out: dict[str, list[Range]] = {}
    for ast_id, slots in (refs or {}).items():
        for slot in slots or []:
            try:
                s, n = int(slot["start"]), int(slot["length"])
            except (KeyError, TypeError, ValueError):
                return {}, f"immutable {ast_id}: malformed reference"
            if n != IMMUTABLE_LEN or s < 0 or s + n > len(local):
                return {}, f"immutable {ast_id}: range {s}+{n} invalid"
            if any(local[s:s + n]):
                return {}, f"immutable {ast_id}: local bytes at {s} are not zero"
            out.setdefault(str(ast_id), []).append((s, s + n))
    return out, None


def _link_slots(refs: dict[str, Any] | None) -> dict[str, list[Range]]:
    """`linkReferences`: {file: {library: [{start, length}]}} -> {"file:library": ranges}; the
    on-chain bytes there are the linked library address, one per library."""
    out: dict[str, list[Range]] = {}
    for file, libs in (refs or {}).items():
        for lib, slots in (libs or {}).items():
            for slot in slots or []:
                s, n = int(slot.get("start", -1)), int(slot.get("length", 0))
                if s >= 0 and n == LINK_LEN:
                    out.setdefault(f"{file}:{lib}", []).append((s, s + n))
    return out


def _is_library(local: bytes) -> bool:
    """A library runtime starts with PUSH20 <own address> ADDRESS EQ, zero in the compiled code."""
    return len(local) > 23 and local[0] == 0x73 and not any(local[1:21]) and local[21:23] == b"\x30\x14"


def _fill_link_placeholders(hex_str: str, link_ranges: list[Range]) -> str:
    """Unlinked runtimes carry `__$<hash>$__` placeholders; zero them so the hex decodes."""
    chars = list(hex_str)
    for s, e in link_ranges:
        chars[2 * s:2 * e] = "0" * (2 * (e - s))
    return "".join(chars)


def _masked(code: bytes, ranges: list[Range]) -> bytes:
    buf = bytearray(code)
    for s, e in ranges:
        buf[s:e] = b"\x00" * (min(e, len(buf)) - s)
    return bytes(buf)


def _merge(ranges: list[Range]) -> list[Range]:
    out: list[Range] = []
    for s, e in sorted(ranges):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _size(ranges: list[Range]) -> int:
    return sum(e - s for s, e in ranges)


def _diff_ranges(a: bytes, b: bytes) -> list[Range]:
    out: list[Range] = []
    i = 0
    while i < len(a):
        if a[i] != b[i]:
            j = i
            while j < len(a) and a[j] != b[j]:
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    return out


def _strip(hex_str: str | None) -> str:
    return (hex_str or "").strip().lower().removeprefix("0x")


# ---------------------------------------------------------------------------
# solc metadata block parser (strict: known keys, fixed value shapes, length suffix)
# ---------------------------------------------------------------------------


def _metadata_block(b: bytes, pos: int) -> Range | None:
    """[pos, end) when b[pos:] is a solc metadata map followed by its own 2-byte length."""
    parsed = _parse_metadata(b, pos)
    return parsed[0] if parsed else None


def _parse_metadata(b: bytes, pos: int) -> tuple[Range, tuple[str, ...]] | None:
    """(block range, key sequence) of a solc metadata map with its 2-byte length suffix."""
    if pos < 0 or pos >= len(b) or not 0xA1 <= b[pos] <= 0xA6:
        return None
    entries, i, seen, shape_sig = b[pos] & 0x1F, pos + 1, [], []
    for _ in range(entries):
        key, i = _cbor_head(b, i, want_major=3)
        if key is None or i + key > len(b):
            return None
        try:
            name = b[i:i + key].decode("ascii")
        except UnicodeDecodeError:
            return None
        i += key
        shapes = _META_KEYS.get(name)
        if shapes is None or name in seen:
            return None
        seen.append(name)
        if i >= len(b):
            return None
        major = b[i] >> 5
        shape = next((s for s in shapes if s[0] == major), None)
        if shape is None:
            return None
        shape_sig.append(f"{name}:{major}")
        if major == 7:
            if b[i] not in (0xF4, 0xF5):
                return None
            i += 1
            continue
        length, i = _cbor_head(b, i, want_major=major)
        if length is None or (shape[1] is not None and length not in shape[1]) or length > _MAX_TEXT:
            return None
        i += length
    end = i + 2
    if end > len(b) or int.from_bytes(b[i:end], "big") != i - pos:
        return None
    return (pos, end), tuple(shape_sig)


def _cbor_head(b: bytes, i: int, *, want_major: int) -> tuple[int | None, int]:
    """Length argument of a byte or text string head (short form or one-byte length)."""
    if i >= len(b) or b[i] >> 5 != want_major:
        return None, i
    info = b[i] & 0x1F
    if info < 24:
        return info, i + 1
    if info == 24 and i + 1 < len(b):
        return b[i + 1], i + 2
    return None, i
