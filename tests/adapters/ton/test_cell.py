"""Supervisor-side BoC parser and cell hash (06 2.4, 4.2, 4.3).

Vectors were produced by @ton/core 0.61.0 (`Cell.hash()`, `toBoc`) and the USDT master code hash
read from toncenter v2 at mc seqno 98074721 (2026-10-10); F27 gives the USDT wallet library cell.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from soken_review.adapters.ton.cell import BocError, parse_boc, root_hash, root_info

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ton"

EMPTY = bytes.fromhex("b5ee9c72010101010002000000")
LIB = bytes.fromhex(
    "b5ee9c72010101010023000842028f452d7a4dfd74066b682365177259ed05734435be76b5fd4bd5d8af2b7c3d68"
)
TREE_IDX_CRC = bytes.fromhex("b5ee9c72c1010301000a0005070a0201b001020000000103dad7232a")


def test_empty_cell_hash() -> None:
    assert root_hash(EMPTY) == "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"


def test_tree_with_index_and_crc() -> None:
    assert root_hash(TREE_IDX_CRC) == "b7bf00365acc3e38c3120714b1332cde119834336170e9b16aa0c54f9c21913d"


def test_library_ref_cell_matches_f27() -> None:
    info = root_info(LIB)
    assert info.is_library_ref
    assert info.library_hash == "8f452d7a4dfd74066b682365177259ed05734435be76b5fd4bd5d8af2b7c3d68"
    # F27: the ref cell hash equals the live USDT wallet code_hash
    assert info.hash == "89468f02c78e570802e39979c8516fc38df07ea76a48357e0536f2ba7b3ee37b"


def test_usdt_master_code_hash() -> None:
    acct = json.loads((FIXTURES / "usdt_master_98074721.json").read_text())["result"]
    info = root_info(base64.b64decode(acct["code"]))
    assert not info.is_library_ref
    assert info.hash == "18d5b6e780ff0bb451254c2c760d09d6e485638cd1407abb97078752c3c1c9ee"


def test_bad_crc_rejected() -> None:
    bad = TREE_IDX_CRC[:-1] + bytes([TREE_IDX_CRC[-1] ^ 1])
    with pytest.raises(BocError, match="crc32c"):
        parse_boc(bad)


@pytest.mark.parametrize(
    "boc",
    [
        b"",
        b"\x00\x00\x00\x00",
        EMPTY[:-1],                        # truncated
        EMPTY + b"\x00",                   # trailing byte
        bytes.fromhex("b5ee9c72410101010002000000"),  # crc flag set, no crc
        bytes.fromhex("b5ee9c720101020100050001000000"),  # ref points back to itself
    ],
)
def test_malformed_rejected(boc: bytes) -> None:
    with pytest.raises(BocError):
        root_hash(boc)


def test_pruned_branch_not_hashed() -> None:
    # exotic cell, level mask 1, type 1 (pruned branch): must not produce a hash
    data = bytes([1, 1]) + b"\x11" * 32 + b"\x00\x01"
    cell = bytes([0x28, len(data) * 2]) + data
    boc = bytes.fromhex("b5ee9c72") + bytes([1, 1, 1, 1, 0, len(cell), 0]) + cell
    with pytest.raises(BocError):
        root_hash(boc)
