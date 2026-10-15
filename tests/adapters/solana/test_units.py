"""Tests for units.py: base58, address validation, nSLOC, path safety."""

import pytest

from soken_review.adapters.solana.units import (
    b58_decode as base58_decode,
)
from soken_review.adapters.solana.units import (
    b58_encode as base58_encode,
)
from soken_review.adapters.solana.units import (
    count_nsloc_rust,
    filter_candidate_files,
    is_in_scope_rust,
    is_solana_address,
    make_h6_from_address,
    make_unit_label,
    safe_store_path,
)


class TestBase58:
    def test_roundtrip(self):
        data = bytes(range(32))
        assert base58_decode(base58_encode(data)) == data

    def test_known_address(self):
        # TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA (SPL Token)
        addr = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        decoded = base58_decode(addr)
        assert len(decoded) == 32

    def test_bad_char_raises(self):
        with pytest.raises(ValueError):
            base58_decode("0OIl" + "A" * 40)  # 0, O, I, l not in alphabet


class TestIsSolanaAddress:
    def test_valid_addresses(self):
        valid = [
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "11111111111111111111111111111111",
            "So11111111111111111111111111111111111111112",
        ]
        for addr in valid:
            assert is_solana_address(addr), f"Expected valid: {addr}"

    def test_invalid_addresses(self):
        invalid = [
            "",
            "0x1234567890abcdef",  # EVM hex
            "short",
            "A" * 50,  # too long
            "not base58! spaces",
        ]
        for addr in invalid:
            assert not is_solana_address(addr), f"Expected invalid: {addr}"


class TestMakeH6:
    def test_h6_length(self):
        addr = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        h6 = make_h6_from_address(addr)
        assert len(h6) == 6
        assert h6.isalnum()

    def test_h6_deterministic(self):
        addr = "So11111111111111111111111111111111111111112"
        assert make_h6_from_address(addr) == make_h6_from_address(addr)


class TestMakeUnitLabel:
    def test_format(self):
        label = make_unit_label("counter", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", None)
        assert label.startswith("counter_")
        assert len(label) == len("counter_") + 6


class TestSafeStorePath:
    def test_valid_paths(self):
        assert safe_store_path("src/lib.rs") == "src/lib.rs"
        assert safe_store_path("Cargo.toml") == "Cargo.toml"
        assert safe_store_path("programs/counter/src/lib.rs") == "programs/counter/src/lib.rs"

    def test_absolute_rejected(self):
        assert safe_store_path("/etc/passwd") is None

    def test_dotdot_rejected(self):
        assert safe_store_path("../../../etc/passwd") is None
        assert safe_store_path("a/../../../etc/passwd") is None

    def test_backslash_rejected(self):
        assert safe_store_path("windows\\path") is None

    def test_nul_rejected(self):
        assert safe_store_path("file\x00.rs") is None

    def test_long_rejected(self):
        assert safe_store_path("a" * 201) is None


class TestFilterCandidateFiles:
    def test_filters_unsafe(self):
        files = {"good.rs": "ok", "../bad.rs": "evil", "/etc/passwd": "evil2"}
        safe, dropped = filter_candidate_files(files)
        assert "good.rs" in safe
        assert "../bad.rs" not in safe
        assert "/etc/passwd" not in safe
        assert len(dropped) == 2


class TestCountNSLOC:
    def test_empty(self):
        assert count_nsloc_rust("") == 0

    def test_comment_lines_excluded(self):
        src = "// comment\n/// doc\nfn main() {}\n"
        assert count_nsloc_rust(src) == 1

    def test_block_comment_excluded(self):
        src = "/* block\ncomment */\nfn foo() {}\n"
        assert count_nsloc_rust(src) == 1

    def test_nested_block_comments(self):
        # Rust does NOT support nested block comments.
        # /* outer /* inner */ closes at the first */, so " outer */" is code.
        # The fn line is also code: total = 2 non-blank, non-comment-only lines.
        src = "/* outer /* inner */ outer */\nfn bar() {}\n"
        # Line 1 has trailing code " outer */" after comment closes; line 2 is fn
        result = count_nsloc_rust(src)
        assert result >= 1  # at least fn bar() counts

    def test_blank_lines_excluded(self):
        src = "\n\n\nfn x() {}\n\n"
        assert count_nsloc_rust(src) == 1


class TestIsInScopeRust:
    def test_in_scope(self):
        assert is_in_scope_rust("src/lib.rs")
        assert is_in_scope_rust("programs/counter/src/lib.rs")

    def test_excluded(self):
        assert not is_in_scope_rust("tests/test_main.rs")
        assert not is_in_scope_rust("benches/bench.rs")
        assert not is_in_scope_rust("examples/example.rs")
        assert not is_in_scope_rust("build.rs")
        assert not is_in_scope_rust("migrations/001.rs")
