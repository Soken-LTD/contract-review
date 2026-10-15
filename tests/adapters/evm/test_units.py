"""Unit tests for EVM unit-label and nSLOC helpers (05 section 3.4)."""

from __future__ import annotations

from soken_review.adapters.evm.units import (
    count_nsloc,
    make_unit_label,
    resolve_collision,
    shared_path,
    store_path,
)


def test_unit_label_gblin():
    """Example from 05 3.4: GBLIN_c2181d for Base 0xc2181d975c05c8c724b334bcED0764c0b86B1D53."""
    label = make_unit_label("GBLIN", "0xc2181d975c05c8c724b334bcED0764c0b86B1D53")
    assert label == "GBLIN_c2181d"


def test_unit_label_checksum_case_insensitive():
    """h6 must be lowercase and address-case-insensitive."""
    label1 = make_unit_label("Foo", "0xABCDEF1234567890ABCDEF1234567890ABCDEF12")
    label2 = make_unit_label("Foo", "0xabcdef1234567890abcdef1234567890abcdef12")
    assert label1 == label2
    # h6 = first 6 chars of last 40 hex of address
    assert label1.endswith("_abcdef")


def test_unit_label_name_sanitization():
    """Non-alphanumeric chars replaced with _, truncated to 40 chars."""
    label = make_unit_label("My-Contract.sol:v2", "0xc2181d975c05c8c724b334bcED0764c0b86B1D53")
    assert " " not in label
    assert "-" not in label
    assert "." not in label
    assert ":" not in label
    name_part = label.split("_")[:-1]
    assert len("_".join(name_part)) <= 40


def test_unit_label_no_address_uses_path():
    """Without address, h6 comes from store path sha256."""
    label = make_unit_label("FooContract", None, store_path="contracts/Foo.sol")
    assert label.startswith("FooContract_")
    h6 = label.split("_")[-1]
    assert len(h6) == 6
    assert h6 == h6.lower()


def test_store_path_format():
    assert store_path("GBLIN_c2181d", "src/GBLIN.sol") == "GBLIN_c2181d/src/GBLIN.sol"


def test_shared_path_format():
    assert shared_path("lib/OpenZeppelin/ERC20.sol") == "shared/lib/OpenZeppelin/ERC20.sol"


def test_resolve_collision():
    existing = {"GBLIN_c2181d"}
    assert resolve_collision("GBLIN_c2181d", existing) == "GBLIN_c2181d_2"
    existing.add("GBLIN_c2181d_2")
    assert resolve_collision("GBLIN_c2181d", existing) == "GBLIN_c2181d_3"


def test_resolve_no_collision():
    assert resolve_collision("FooBar_aabbcc", set()) == "FooBar_aabbcc"


class TestCountNsloc:
    def test_simple_contract(self):
        src = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Foo {
    uint256 public x;

    // A comment
    function bar() public {
        x = 1;
    }
}
"""
        nsloc = count_nsloc(src)
        # Should count: pragma, contract, uint256 line, function, x=1, closing braces
        assert nsloc >= 5
        assert nsloc < 12  # comments and blanks excluded

    def test_block_comment_excluded(self):
        src = """\
/*
 * This is a block comment
 */
contract Foo {}
"""
        assert count_nsloc(src) == 1

    def test_blank_lines_excluded(self):
        src = "\n\n\ncontract Foo {}\n\n\n"
        assert count_nsloc(src) == 1

    def test_empty_source(self):
        assert count_nsloc("") == 0

    def test_only_comments(self):
        src = "// comment\n// another\n"
        assert count_nsloc(src) == 0
