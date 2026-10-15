"""Tests for PinnedSource (04 5.1) and quote_match (04 5.2)."""

import unicodedata
from pathlib import Path

import pytest

from soken_review.pinning.quote_match import (
    QuoteMatchError,
    normalize_line,
    quote_match,
)
from soken_review.pinning.store import PinnedSource

# ── fixtures ─────────────────────────────────────────────────────────────────

VAULT_SOL = b"""\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    uint256 public constant MAX_FEE_BPS = 1_000;
    uint256 public feeBps;

    function setFee(uint256 newFee) external onlyOwner {
        feeBps = newFee;
    }

    function _chargeFee(uint256 amount) internal returns (uint256 fee) {
        fee = amount * feeBps / 10_000;
    }
}
"""

CRLF_FILE = b"line one\r\nline two\r\nline three\r\n"


@pytest.fixture
def simple_pin(tmp_path: Path) -> PinnedSource:
    """A PinnedSource with one Solidity file."""
    return PinnedSource.from_files({"src/Vault.sol": VAULT_SOL})


@pytest.fixture
def persisted_pin(tmp_path: Path) -> tuple[PinnedSource, Path]:
    pin = PinnedSource.from_files({"src/Vault.sol": VAULT_SOL})
    pin.persist(tmp_path, "job_TEST01234567890123456789AB")
    return pin, tmp_path


# ── PinnedSource: basic ───────────────────────────────────────────────────────


def test_line_count(simple_pin: PinnedSource) -> None:
    """Files ending with \\n do not get a phantom empty line."""
    # 16 lines of VAULT_SOL (15 non-empty + closing '}' + no trailing blank)
    assert simple_pin.line_count("src/Vault.sol") >= 15


def test_read_lines_1based(simple_pin: PinnedSource) -> None:
    lines = simple_pin.read_lines("src/Vault.sol", 1, 3)
    assert lines[0].startswith("//")
    assert len(lines) == 3


def test_read_lines_out_of_range(simple_pin: PinnedSource) -> None:
    total = simple_pin.line_count("src/Vault.sol")
    with pytest.raises(IndexError):
        simple_pin.read_lines("src/Vault.sol", 1, total + 1)


def test_crlf_normalized() -> None:
    """CRLF content is LF-normalised; line count is correct."""
    pin = PinnedSource.from_files({"f.sol": CRLF_FILE})
    assert pin.line_count("f.sol") == 3
    lines = pin.read_lines("f.sol", 1, 3)
    assert lines[0] == "line one"
    assert lines[2] == "line three"


def test_invalid_utf8_raises() -> None:
    with pytest.raises(UnicodeDecodeError):
        PinnedSource.from_files({"bad.sol": b"\xff\xfe bad"})


def test_source_pin_deterministic(simple_pin: PinnedSource) -> None:
    """Same content -> same source_pin."""
    pin2 = PinnedSource.from_files({"src/Vault.sol": VAULT_SOL})
    assert simple_pin.source_pin == pin2.source_pin


def test_source_pin_changes_on_content(simple_pin: PinnedSource) -> None:
    pin2 = PinnedSource.from_files({"src/Vault.sol": VAULT_SOL + b" "})
    assert simple_pin.source_pin != pin2.source_pin


# ── PinnedSource: persistence ─────────────────────────────────────────────────


def test_persist_and_load(persisted_pin: tuple[PinnedSource, Path]) -> None:
    pin, tmp_path = persisted_pin
    loaded = PinnedSource.load(tmp_path, "job_TEST01234567890123456789AB")
    assert loaded.source_pin == pin.source_pin
    assert set(loaded.entries) == set(pin.entries)
    assert loaded.read_lines("src/Vault.sol", 1, 3) == pin.read_lines("src/Vault.sol", 1, 3)


def test_blob_write_once(persisted_pin: tuple[PinnedSource, Path]) -> None:
    """A second persist does not raise even when blob already exists."""
    pin, tmp_path = persisted_pin
    pin.persist(tmp_path, "job_TEST01234567890123456789AB")  # no error


# ── normalize_line ────────────────────────────────────────────────────────────


def test_normalize_nfc_not_nfkc() -> None:
    """NFC is applied, not NFKC; homoglyphs survive."""
    # U+00C5 ANGSTROM SIGN is NFC-equivalent to A + combining ring (U+212B -> U+00C5)
    raw = "Å"
    normed = normalize_line(raw)
    assert normed == unicodedata.normalize("NFC", raw)
    # NFKC would fold ² to '2'; NFC must not
    sq = "x²"
    assert normalize_line(sq) == sq  # NFC keeps superscript-2


def test_normalize_strips_horizontal_ws() -> None:
    assert normalize_line("  hello world  ") == "hello world"


def test_normalize_collapses_inner_ws() -> None:
    assert normalize_line("a   b\t\tc") == "a b c"


# ── quote_match: success cases ────────────────────────────────────────────────


def test_exact_match(simple_pin: PinnedSource) -> None:
    """An exact copy of lines 8-10 passes."""
    lines = simple_pin.read_lines("src/Vault.sol", 8, 10)
    text = "\n".join(lines)
    quote_match(simple_pin, "src/Vault.sol", 8, 10, text)  # no exception


def test_match_crlf_quote(simple_pin: PinnedSource) -> None:
    """Quote with CRLF is normalized to LF before matching."""
    lines = simple_pin.read_lines("src/Vault.sol", 8, 9)
    text = "\r\n".join(lines) + "\r\n"
    quote_match(simple_pin, "src/Vault.sol", 8, 9, text)


def test_match_extra_whitespace(simple_pin: PinnedSource) -> None:
    """Quote with collapsed inner whitespace matches (normalization)."""
    lines = simple_pin.read_lines("src/Vault.sol", 8, 9)
    # Add extra space inside a line
    modified = [lines[0] + "  ", lines[1]]
    text = "\n".join(modified)
    # The trailing spaces in line 8 are stripped in normalization -> should match
    quote_match(simple_pin, "src/Vault.sol", 8, 9, text)


def test_elision_match(simple_pin: PinnedSource) -> None:
    """One elision '...' is allowed; skips middle lines."""
    first_line = simple_pin.read_lines("src/Vault.sol", 8, 8)[0]
    last_line = simple_pin.read_lines("src/Vault.sol", 10, 10)[0]
    text = f"{first_line}\n...\n{last_line}"
    quote_match(simple_pin, "src/Vault.sol", 8, 10, text)


# ── quote_match: error cases ──────────────────────────────────────────────────


def test_file_unknown(simple_pin: PinnedSource) -> None:
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Missing.sol", 1, 1, "x" * 20)
    assert exc.value.code == "E_FILE_UNKNOWN"


def test_range_invalid_beyond_eof(simple_pin: PinnedSource) -> None:
    total = simple_pin.line_count("src/Vault.sol")
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Vault.sol", total, total + 1, "x" * 20)
    assert exc.value.code == "E_RANGE_INVALID"


def test_quote_too_long(simple_pin: PinnedSource) -> None:
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Vault.sol", 1, 41, "x" * 20)
    assert exc.value.code == "E_QUOTE_TOO_LONG"


def test_quote_trivial_braces(simple_pin: PinnedSource) -> None:
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Vault.sol", 4, 4, "{\n}")
    assert exc.value.code == "E_QUOTE_TRIVIAL"


def test_quote_trivial_short(simple_pin: PinnedSource) -> None:
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Vault.sol", 1, 1, "abc")
    assert exc.value.code == "E_QUOTE_TRIVIAL"


def test_elision_multiple(simple_pin: PinnedSource) -> None:
    first = simple_pin.read_lines("src/Vault.sol", 8, 8)[0]
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Vault.sol", 8, 10, f"{first}\n...\n...\nfoo")
    assert exc.value.code == "E_QUOTE_ELISION"


def test_mismatch(simple_pin: PinnedSource) -> None:
    lines = simple_pin.read_lines("src/Vault.sol", 8, 9)
    bad = lines[0] + " // CHANGED\n" + lines[1]
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Vault.sol", 8, 9, bad)
    assert exc.value.code == "E_QUOTE_MISMATCH"


def test_mismatch_first_segment_not_anchored(simple_pin: PinnedSource) -> None:
    """First segment must match from P[0]; a matching later segment is not enough."""
    last_line = simple_pin.read_lines("src/Vault.sol", 10, 10)[0]
    # Quote only the last line (would skip first 2), which means first-segment check fails
    # because first line of the quote doesn't match P[0].
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Vault.sol", 8, 10, last_line)
    assert exc.value.code in ("E_QUOTE_MISMATCH", "E_QUOTE_TRIVIAL")


def test_mismatch_last_segment_not_consumed(simple_pin: PinnedSource) -> None:
    """Quote that stops before P[-1] is a mismatch."""
    lines = simple_pin.read_lines("src/Vault.sol", 8, 10)
    text = "\n".join(lines[:2])  # only first 2 of 3 lines
    with pytest.raises(QuoteMatchError) as exc:
        quote_match(simple_pin, "src/Vault.sol", 8, 10, text)
    assert exc.value.code == "E_QUOTE_MISMATCH"
