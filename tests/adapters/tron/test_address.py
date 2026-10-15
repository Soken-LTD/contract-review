"""Tests for TRON address codec (05 section 4.3).

Verifies round-trip encode/decode, h6 computation, and edge cases.
USDT-TRC20 example from plan F24:
  TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t  <->  a614f803b6fd780986a42c78ec9c7f77e6ded13c
"""

from __future__ import annotations

import pytest

from soken_review.adapters.tron.address import (
    TronAddressError,
    b58_to_hex,
    hex_to_b58,
    is_tron_address,
    to_wire_hex,
    tron_h6,
)

# Known good values from plan F24 (USDT TRC20)
USDT_B58 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_INTERNAL = "a614f803b6fd780986a42c78ec9c7f77e6ded13c"
USDT_WIRE = "41" + USDT_INTERNAL

# A second real TRON contract (JustSwap factory, well-known)
JUSTSWAP_B58 = "TXk8rQSAvPvBBNtqSoY6nCfsXWCSSpTVQF"


class TestB58ToHex:
    def test_usdt_decode(self):
        """USDT-TRC20 known vector from plan F24."""
        assert b58_to_hex(USDT_B58) == USDT_INTERNAL

    def test_round_trip(self):
        """Encode then decode returns the same internal hex."""
        encoded = hex_to_b58(USDT_INTERNAL)
        decoded = b58_to_hex(encoded)
        assert decoded == USDT_INTERNAL

    def test_wrong_checksum(self):
        """Flip the last character -> checksum mismatch."""
        # Change last char of valid address
        bad = USDT_B58[:-1] + ("5" if USDT_B58[-1] != "5" else "6")
        with pytest.raises(TronAddressError, match="checksum"):
            b58_to_hex(bad)

    def test_not_base58(self):
        """Reject non-base58 strings (0 and O and I and l are not in alphabet)."""
        with pytest.raises(TronAddressError):
            b58_to_hex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6O")  # O not in b58

    def test_too_short(self):
        with pytest.raises(TronAddressError):
            b58_to_hex("T1234")

    def test_empty(self):
        with pytest.raises(TronAddressError):
            b58_to_hex("")


class TestHexToB58:
    def test_usdt_encode_from_internal(self):
        """Encode 20-byte internal hex -> USDT address."""
        assert hex_to_b58(USDT_INTERNAL) == USDT_B58

    def test_usdt_encode_from_wire(self):
        """Accept 0x41-prefixed 21-byte hex as well."""
        assert hex_to_b58(USDT_WIRE) == USDT_B58

    def test_wrong_length(self):
        with pytest.raises(TronAddressError):
            hex_to_b58("a614f8")  # too short

    def test_invalid_hex(self):
        with pytest.raises((TronAddressError, ValueError)):
            hex_to_b58("z" * 40)  # not valid hex


class TestIssTronAddress:
    def test_valid(self):
        assert is_tron_address(USDT_B58) is True

    def test_not_t_prefix(self):
        assert is_tron_address("0x" + USDT_INTERNAL) is False

    def test_wrong_length(self):
        assert is_tron_address("T" + "1" * 30) is False

    def test_empty(self):
        assert is_tron_address("") is False


class TestToWireHex:
    def test_usdt(self):
        assert to_wire_hex(USDT_INTERNAL) == USDT_WIRE

    def test_wrong_length(self):
        with pytest.raises(TronAddressError):
            to_wire_hex("a614f8")


class TestTronH6:
    def test_usdt_h6(self):
        """First 6 hex chars of USDT internal address."""
        assert tron_h6(USDT_INTERNAL) == "a614f8"

    def test_lowercase(self):
        assert tron_h6("ABCDEF" + "0" * 34) == "abcdef"

    def test_too_short(self):
        with pytest.raises(TronAddressError):
            tron_h6("ab")
