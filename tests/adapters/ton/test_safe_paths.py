"""Security tests for TON path safety gate (plan v4 06, RULES.md §3).

File paths in TON verifier bundles are attacker-controlled (the contract author
controls what files the verifier stores). These tests verify that unsafe paths
are rejected before any file write.
"""

from __future__ import annotations

from soken_review.adapters.ton.units import filter_candidate_files, safe_store_path


class TestSafeStorePath:
    # ── Must reject ────────────────────────────────────────────────────────

    def test_rejects_absolute_path(self):
        assert safe_store_path("/etc/passwd") is None

    def test_rejects_dotdot_traversal(self):
        assert safe_store_path("../../.ssh/authorized_keys") is None

    def test_rejects_dotdot_in_subdir(self):
        assert safe_store_path("contracts/../../../etc/shadow") is None

    def test_rejects_null_byte(self):
        assert safe_store_path("foo\x00.fc") is None

    def test_rejects_backslash(self):
        assert safe_store_path("contracts\\evil.fc") is None

    def test_rejects_empty_string(self):
        assert safe_store_path("") is None

    def test_rejects_double_slash_absolute(self):
        assert safe_store_path("//etc/passwd") is None

    def test_rejects_too_long(self):
        assert safe_store_path("a" * 201) is None

    def test_rejects_special_chars_semicolon(self):
        assert safe_store_path("contracts/evil;rm.fc") is None

    def test_rejects_special_chars_dollar(self):
        assert safe_store_path("contracts/my contract$.fc") is None

    def test_rejects_newline(self):
        assert safe_store_path("contracts/x\nfc") is None

    def test_rejects_windows_absolute_colon(self):
        assert safe_store_path("C:/Windows/System32/cmd.exe") is None

    # ── Must accept ────────────────────────────────────────────────────────

    def test_accepts_func_file(self):
        assert safe_store_path("jetton_minter.fc") == "jetton_minter.fc"

    def test_accepts_tact_file(self):
        assert safe_store_path("contracts/Token.tact") == "contracts/Token.tact"

    def test_accepts_tolk_file(self):
        assert safe_store_path("src/wallet.tolk") == "src/wallet.tolk"

    def test_accepts_json_config(self):
        assert safe_store_path("tact.config.json") == "tact.config.json"

    def test_accepts_hyphen_and_underscore(self):
        assert safe_store_path("jetton-wallet_v2.fc") is not None

    def test_normalizes_dot_segment(self):
        # ./foo.fc → foo.fc
        result = safe_store_path("./contracts/Token.fc")
        assert result == "contracts/Token.fc"

    def test_accepts_nested_path(self):
        result = safe_store_path("contracts/jetton/JettonMaster.tact")
        assert result is not None

    def test_accepts_max_length(self):
        # Exactly 200 chars
        path = "a/" + "b" * 195 + ".fc"
        assert len(path) <= 200
        assert safe_store_path(path) is not None


class TestFilterCandidateFiles:
    def test_drops_malicious_paths_keeps_safe(self):
        files = {
            "jetton.fc": "() recv_internal()",
            "../../etc/passwd": "root:x:0:0",
            "/etc/shadow": "root:!",
            "stdlib.fc": ";; stdlib",
        }
        safe, dropped = filter_candidate_files(files)
        assert "jetton.fc" in safe
        assert "stdlib.fc" in safe
        assert "../../etc/passwd" not in safe
        assert "/etc/shadow" not in safe
        assert set(dropped) == {"../../etc/passwd", "/etc/shadow"}

    def test_all_safe_kept(self):
        files = {
            "contracts/Token.tact": "contract Token {}",
            "contracts/Message.tact": "message M {}",
        }
        safe, dropped = filter_candidate_files(files)
        assert len(safe) == 2
        assert dropped == []

    def test_empty_input(self):
        safe, dropped = filter_candidate_files({})
        assert safe == {}
        assert dropped == []

    def test_null_byte_dropped(self):
        files = {"foo\x00.fc": "content"}
        safe, dropped = filter_candidate_files(files)
        assert safe == {}
        assert "foo\x00.fc" in dropped

    def test_all_dropped_recorded(self):
        files = {
            "../a.fc": "c1",
            "../../b.fc": "c2",
            "valid.tact": "c3",
        }
        safe, dropped = filter_candidate_files(files)
        assert len(dropped) == 2
        assert "valid.tact" in safe
