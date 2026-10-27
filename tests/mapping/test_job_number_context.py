"""`job_number_context`: the write tools pass the job's word set to the number lexer, so an
identifier that carries a digit is not an unsourced number (matrix run 2026-10-26: ERC20Burnable,
claim_v2, u5 and u6 were rejected on three arms)."""

from __future__ import annotations

from pathlib import Path

from soken_review.engine.numbers import lex_numbers
from soken_review.mapping.build import build_map, write_map
from soken_review.mapping.step import family_categories, job_number_context

SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ANTToken {
    uint256 public claim_v2;
    struct Slots { uint8 u5; uint8 u6; }
    function burnFrom(address a, uint256 n) external {}
}
"""


def test_word_set_comes_from_the_job_map(tmp_path: Path):
    art = build_map({"src/ANTToken.sol": SOL}, None, list(family_categories("evm")), build_ok=False)
    write_map(tmp_path, "job_x", art)
    ctx = job_number_context(tmp_path, "job_x")
    assert {"ANTToken", "claim_v2", "u5", "u6", "burnFrom"} <= ctx.word_set
    assert not lex_numbers("ANTToken.burnFrom writes claim_v2; fields u5 and u6 hold the slots", ctx)
    assert lex_numbers("the claim_v9 path", ctx)[0].match == "claim_v9"


def test_missing_map_gives_an_empty_context(tmp_path: Path):
    ctx = job_number_context(tmp_path, "job_missing")
    assert ctx.word_set == frozenset()
