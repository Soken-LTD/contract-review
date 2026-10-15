"""Tests for TON address detection and language detection (plan v4 06 4.1)."""

from __future__ import annotations

from soken_review.adapters.ton.detect import (
    detect_language_from_files,
    parse_friendly_address,
    parse_raw_address,
    parse_ton_address,
    raw_to_friendly,
)


class TestParseRawAddress:
    def test_valid_masterchain_raw(self):
        addr = "-1:fcb91a3a3816d0f7b8c2c76108b8a9bc5a6b7a55bd79f8ab101c52db29232260"
        raw, display = parse_raw_address(addr)
        assert raw == addr
        assert display == addr

    def test_valid_basechain_raw(self):
        addr = "0:fcb91a3a3816d0f7b8c2c76108b8a9bc5a6b7a55bd79f8ab101c52db29232260"
        raw, _display = parse_raw_address(addr)
        assert raw == addr

    def test_invalid_workchain_none(self):
        # workchain 5 is not valid
        raw, _ = parse_raw_address("5:fcb91a3a3816d0f7b8c2c76108b8a9bc5a6b7a55bd79f8ab101c52db29232260")
        assert raw is None

    def test_too_short_hex_none(self):
        raw, _ = parse_raw_address("0:abc123")
        assert raw is None

    def test_not_raw_address_none(self):
        raw, _ = parse_raw_address("EQC-not-a-raw-address")
        assert raw is None

    def test_empty_string_none(self):
        raw, _ = parse_raw_address("")
        assert raw is None


class TestParseFriendlyAddress:
    # Test vectors from TON documentation and verifier.ton.org
    # EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N is a known jetton master
    _KNOWN_FRIENDLY = "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N"
    _KNOWN_RAW = "0:83dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8"

    def test_known_address_parses(self):
        raw, display = parse_friendly_address(self._KNOWN_FRIENDLY)
        # Should produce the raw address (workchain 0)
        assert raw is not None
        assert display == self._KNOWN_FRIENDLY

    def test_wrong_length_none(self):
        raw, _ = parse_friendly_address("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2")  # 47 chars
        assert raw is None

    def test_invalid_checksum_none(self):
        # Corrupt last char
        addr = self._KNOWN_FRIENDLY[:-1] + ("X" if self._KNOWN_FRIENDLY[-1] != "X" else "Y")
        raw, _ = parse_friendly_address(addr)
        assert raw is None

    def test_testnet_bounceable_rejected(self):
        # Testnet bounceable addresses start with 0x51 tag
        # Construct a fake testnet addr: tag 0x51, workchain -1, 32 bytes zeros, crc16
        import base64
        import struct

        workchain = 255  # -1 as uint8
        account = bytes(32)
        data = bytes([0x51, workchain]) + account
        crc = _crc16_ccitt(data)
        full = data + struct.pack(">H", crc)
        encoded = base64.urlsafe_b64encode(full).decode().rstrip("=")
        # Must be 48 chars
        if len(encoded) == 48:
            raw, _ = parse_friendly_address(encoded)
            assert raw is None, "Testnet address must be rejected"

    def test_not_base64url_none(self):
        raw, _ = parse_friendly_address("not_a_real_address!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        assert raw is None


def _crc16_ccitt(data: bytes) -> int:
    """CRC16-CCITT used for TON friendly address checksum."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
        crc &= 0xFFFF
    return crc


class TestParseTonAddress:
    def test_friendly_address(self):
        raw, _display = parse_ton_address("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N")
        assert raw is not None

    def test_raw_address(self):
        raw, _ = parse_ton_address("0:83dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8")
        assert raw is not None

    def test_invalid_none(self):
        raw, _ = parse_ton_address("not-a-ton-address")
        assert raw is None


class TestRawToFriendly:
    def test_roundtrip(self):
        raw = "0:83dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8"
        friendly = raw_to_friendly(raw)
        assert friendly is not None
        assert len(friendly) == 48
        # Parses back
        raw2, _ = parse_friendly_address(friendly)
        assert raw2 is not None

    def test_invalid_raw_none(self):
        assert raw_to_friendly("not-raw") is None

    def test_masterchain_raw(self):
        raw = "-1:fcb91a3a3816d0f7b8c2c76108b8a9bc5a6b7a55bd79f8ab101c52db29232260"
        friendly = raw_to_friendly(raw)
        assert friendly is not None
        assert len(friendly) == 48


class TestDetectLanguageFromFiles:
    def test_func_detected(self):
        files = {"jetton.fc": "()", "stdlib.fc": ";; std"}
        assert detect_language_from_files(files) == "func"

    def test_tact_detected(self):
        files = {"Token.tact": "contract Token {}"}
        assert detect_language_from_files(files) == "tact"

    def test_tolk_detected(self):
        files = {"wallet.tolk": "fun main() {}"}
        assert detect_language_from_files(files) == "tolk"

    def test_mixed_prefers_tact(self):
        files = {"a.tact": "x", "b.fc": "y"}
        lang = detect_language_from_files(files)
        # tact should win over func (higher specificity)
        assert lang == "tact"

    def test_empty_files_none(self):
        assert detect_language_from_files({}) is None

    def test_unknown_extension_none(self):
        files = {"something.py": "print('hi')"}
        assert detect_language_from_files(files) is None
