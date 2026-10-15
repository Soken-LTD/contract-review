"""Security tests for safe_store_path path validation (attacker-controlled verified source).

Verified source file paths come from Sourcify, eth-bytecode-db and IPFS — all of which
a contract author controls. A malicious path like ../../.ssh/authorized_keys must be
rejected before any file write.
"""

from __future__ import annotations

from soken_review.adapters.evm.units import filter_candidate_files, safe_store_path


class TestSafeStorePath:
    # --- Must reject ---

    def test_rejects_absolute_path(self):
        assert safe_store_path("/etc/passwd") is None

    def test_rejects_dotdot_traversal(self):
        assert safe_store_path("../../.ssh/authorized_keys") is None

    def test_rejects_dotdot_in_subdir(self):
        assert safe_store_path("contracts/../../../etc/shadow") is None

    def test_rejects_null_byte(self):
        assert safe_store_path("foo\x00.sol") is None

    def test_rejects_backslash(self):
        assert safe_store_path("contracts\\evil.sol") is None

    def test_rejects_empty_string(self):
        assert safe_store_path("") is None

    def test_rejects_double_slash(self):
        # posixpath.normpath collapses // → / but empty segment check should catch bare //
        # After normpath: "foo//bar" → "foo/bar" which is fine; "//etc" → "/etc" is absolute
        assert safe_store_path("//etc/passwd") is None

    def test_rejects_too_long(self):
        assert safe_store_path("a" * 201) is None

    def test_rejects_special_chars(self):
        assert safe_store_path("contracts/my contract$.sol") is None
        assert safe_store_path("contracts/evil;rm.sol") is None
        assert safe_store_path("contracts/x\nsol") is None

    def test_rejects_windows_absolute(self):
        # Colon is not in the allowlist
        assert safe_store_path("C:/Windows/System32/cmd.exe") is None

    # --- Must accept ---

    def test_accepts_simple_path(self):
        assert safe_store_path("contracts/Token.sol") == "contracts/Token.sol"

    def test_accepts_dotfile_in_path(self):
        assert safe_store_path("src/types/Asset.sol") == "src/types/Asset.sol"

    def test_accepts_path_with_dot_in_name(self):
        assert safe_store_path("lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol") is not None

    def test_accepts_single_file(self):
        assert safe_store_path("FiatTokenProxy.sol") == "FiatTokenProxy.sol"

    def test_normalizes_dot_segment(self):
        # ./foo.sol → foo.sol
        result = safe_store_path("./contracts/Token.sol")
        # posixpath.normpath("./contracts/Token.sol") = "contracts/Token.sol"
        assert result == "contracts/Token.sol"

    def test_accepts_hyphen_and_underscore(self):
        assert safe_store_path("lib/openzeppelin-contracts/ERC20_v2.sol") is not None

    def test_accepts_numbers(self):
        assert safe_store_path("v2/UniswapV2Factory.sol") is not None


class TestFilterCandidateFiles:
    def test_drops_malicious_paths(self):
        files = {
            "contracts/Token.sol": "contract Token {}",
            "../../etc/passwd": "root:x:0:0",
            "/etc/shadow": "root:!",
            "normal.sol": "contract Normal {}",
        }
        safe, dropped = filter_candidate_files(files)
        assert "contracts/Token.sol" in safe
        assert "normal.sol" in safe
        assert "../../etc/passwd" not in safe
        assert "/etc/shadow" not in safe
        assert "../../etc/passwd" in dropped
        assert "/etc/shadow" in dropped

    def test_all_safe_paths_kept(self):
        files = {
            "src/GBLIN.sol": "contract GBLIN {}",
            "src/types/Asset.sol": "struct Asset {}",
            "lib/ERC20.sol": "contract ERC20 {}",
        }
        safe, dropped = filter_candidate_files(files)
        assert len(safe) == 3
        assert dropped == []

    def test_empty_input(self):
        safe, dropped = filter_candidate_files({})
        assert safe == {}
        assert dropped == []

    def test_null_byte_in_path_dropped(self):
        files = {"foo\x00.sol": "content"}
        safe, dropped = filter_candidate_files(files)
        assert safe == {}
        assert "foo\x00.sol" in dropped

    def test_records_all_dropped(self):
        """All dropped paths must be recorded, never silently lost."""
        files = {
            "../a.sol": "c1",
            "../../b.sol": "c2",
            "valid.sol": "c3",
        }
        safe, dropped = filter_candidate_files(files)
        assert len(dropped) == 2
        assert "valid.sol" in safe
