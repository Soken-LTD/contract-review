"""BoC parsing and cell representation hash, supervisor side (plan v4 06 2.4, 4.2, 4.3).

The supervisor hashes every code cell itself: the on-chain account code, the library body
returned by `getLibraries`, and the BoC a build container wrote. A container never reports a
hash (09 3.5). The hash is the TVM representation hash of the root cell at level 0, the value
`@ton/core` `Cell.hash()` returns and the verifier registry keys on (F13).

Supported: the standard BoC (magic b5ee9c72, also the two legacy indexed magics), ordinary cells
and library-reference exotic cells, all at level 0. Anything else (pruned branches, Merkle
cells, a non-zero level mask) raises `BocError`: the caller treats the code as not hashable
and never as a match.

Inputs are untrusted: every length, index and count is bounds-checked, refs must point
forward (BoC topological order), and the parser caps cells and depth.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_MAGIC_GENERIC = 0xB5EE9C72
_MAGIC_INDEXED = 0x68FF65F3
_MAGIC_INDEXED_CRC = 0xACC3A728

MAX_CELLS = 65_536          # code cells are at most a few thousand; the TVM limit is lower
MAX_BOC_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 1024            # TVM cell depth limit

LIBRARY_CELL_TYPE = 2


class BocError(ValueError):
    """The BoC is malformed or uses a cell kind this module does not hash."""


@dataclass(frozen=True)
class Cell:
    d1: int
    d2: int
    data: bytes             # serialized data bytes, completion-tagged when d2 is odd
    refs: tuple[int, ...]   # indices into the BoC cell list

    @property
    def exotic(self) -> bool:
        return bool(self.d1 & 8)

    @property
    def level_mask(self) -> int:
        return self.d1 >> 5


@dataclass(frozen=True)
class RootInfo:
    hash: str               # 64 hex, representation hash of the root cell
    is_library_ref: bool
    library_hash: str | None  # 64 hex when the root is a library reference cell


def _read_int(buf: bytes, pos: int, size: int) -> tuple[int, int]:
    end = pos + size
    if size < 0 or end > len(buf):
        raise BocError("truncated BoC")
    return int.from_bytes(buf[pos:end], "big"), end


def parse_boc(boc: bytes) -> tuple[list[Cell], list[int]]:
    """Return (cells, root indices). Raises BocError on any malformed input."""
    if not isinstance(boc, bytes | bytearray):
        raise BocError("BoC must be bytes")
    if len(boc) > MAX_BOC_BYTES:
        raise BocError("BoC too large")
    magic, pos = _read_int(boc, 0, 4)

    if magic == _MAGIC_GENERIC:
        flags, pos = _read_int(boc, pos, 1)
        has_idx = bool(flags & 0x80)
        has_crc = bool(flags & 0x40)
        size = flags & 0x07
    elif magic in (_MAGIC_INDEXED, _MAGIC_INDEXED_CRC):
        flags, pos = _read_int(boc, pos, 1)
        has_idx = True
        has_crc = magic == _MAGIC_INDEXED_CRC
        size = flags
    else:
        raise BocError("unknown BoC magic")
    if not 1 <= size <= 4:
        raise BocError("bad ref size")

    off_bytes, pos = _read_int(boc, pos, 1)
    if not 1 <= off_bytes <= 8:
        raise BocError("bad offset size")
    n_cells, pos = _read_int(boc, pos, size)
    n_roots, pos = _read_int(boc, pos, size)
    _absent, pos = _read_int(boc, pos, size)
    tot_size, pos = _read_int(boc, pos, off_bytes)
    if n_cells == 0 or n_cells > MAX_CELLS:
        raise BocError("cell count out of range")
    if n_roots == 0 or n_roots > n_cells:
        raise BocError("root count out of range")

    if magic == _MAGIC_GENERIC:
        roots = []
        for _ in range(n_roots):
            r, pos = _read_int(boc, pos, size)
            roots.append(r)
    else:
        roots = [0]  # legacy indexed formats have a single root at index 0
    if any(r >= n_cells for r in roots):
        raise BocError("root index out of range")

    if has_idx:
        pos += n_cells * off_bytes
    data_start = pos
    data_end = data_start + tot_size
    expected_end = data_end + (4 if has_crc else 0)
    if expected_end != len(boc):
        raise BocError("BoC length does not match its header")

    cells: list[Cell] = []
    for i in range(n_cells):
        d1, pos = _read_int(boc, pos, 1)
        d2, pos = _read_int(boc, pos, 1)
        n_refs = d1 & 7
        if n_refs > 4:
            raise BocError("more than 4 refs")
        if d1 & 16:  # with_hashes: stored hashes and depths precede the data
            levels = (d1 >> 5).bit_count() + 1
            pos += levels * (32 + 2)
        n_data = (d2 + 1) // 2
        if pos + n_data > data_end:
            raise BocError("cell data out of range")
        data = bytes(boc[pos : pos + n_data])
        pos += n_data
        if d2 % 2 == 1 and (n_data == 0 or data[-1] == 0):
            raise BocError("missing completion tag")
        refs = []
        for _ in range(n_refs):
            r, pos = _read_int(boc, pos, size)
            if r <= i or r >= n_cells:
                raise BocError("ref does not point forward")
            refs.append(r)
        if pos > data_end:
            raise BocError("cell out of range")
        cells.append(Cell(d1=d1 & ~16, d2=d2, data=data, refs=tuple(refs)))
    if pos != data_end:
        raise BocError("trailing bytes in cell data")

    if has_crc:
        crc = int.from_bytes(boc[data_end : data_end + 4], "little")
        if crc != _crc32c(bytes(boc[:data_end])):
            raise BocError("crc32c mismatch")
    return cells, roots


def _hashes(cells: list[Cell]) -> tuple[list[bytes], list[int]]:
    """Representation hash and depth per cell, computed from the last cell back."""
    n = len(cells)
    hashes: list[bytes] = [b""] * n
    depths: list[int] = [0] * n
    for i in range(n - 1, -1, -1):
        c = cells[i]
        if c.level_mask != 0:
            raise BocError("non-zero level cell (pruned or Merkle) is not hashed here")
        if c.exotic:
            if not c.data:
                raise BocError("exotic cell without type byte")
            if c.data[0] != LIBRARY_CELL_TYPE:
                raise BocError(f"exotic cell type {c.data[0]} is not hashed here")
            if c.d2 != 66 or c.refs:
                raise BocError("malformed library cell")
        depth = 0
        for r in c.refs:
            depth = max(depth, depths[r] + 1)
        if depth > MAX_DEPTH:
            raise BocError("cell depth over limit")
        h = hashlib.sha256()
        h.update(bytes((c.d1, c.d2)))
        h.update(c.data)
        for r in c.refs:
            h.update(depths[r].to_bytes(2, "big"))
        for r in c.refs:
            h.update(hashes[r])
        hashes[i] = h.digest()
        depths[i] = depth
    return hashes, depths


def root_info(boc: bytes) -> RootInfo:
    """Hash the first root of a BoC and say whether it is a library reference (06 4.3)."""
    cells, roots = parse_boc(boc)
    hashes, _ = _hashes(cells)
    root = cells[roots[0]]
    is_lib = root.exotic and root.data[:1] == bytes((LIBRARY_CELL_TYPE,))
    return RootInfo(
        hash=hashes[roots[0]].hex(),
        is_library_ref=is_lib,
        library_hash=root.data[1:33].hex() if is_lib else None,
    )


def root_hash(boc: bytes) -> str:
    """64-hex representation hash of the first root cell."""
    return root_info(boc).hash


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 & -(crc & 1))
    return crc ^ 0xFFFFFFFF
