"""Tests for TRON compiler cache security gates (05 section 6.3).

Covers strict tag validation, path confinement, pinned-sha256 enforcement,
and rejection of malicious version strings.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from soken_review.adapters.tron.build import _resolve_tag
from soken_review.adapters.tron.compiler import _TAG_RE, TronCompilerCacheError, TronSolcCache

# ---------------------------------------------------------------------------
# Tag regex (strict format gate)
# ---------------------------------------------------------------------------


class TestTagRegex:
    def test_valid_tags(self):
        valid = [
            "tv_0.8.31",
            "tv_0.8.18",
            "tv_0.5.4",
            "tv_0.4.25_Odyssey_v3.2.3",
            "tv_0.4.25_Plato_v4.2",
        ]
        for tag in valid:
            assert _TAG_RE.match(tag), f"should match: {tag}"

    def test_invalid_tags(self):
        invalid = [
            "tv_../../../etc/passwd",
            "../tv_0.8.31",
            "tv_0.8.31/../../",
            "tv_0.8.31\x00evil",
            "0.8.31",
            "",
            "tv_",
            "TV_0.8.31",
            "tv_0.8.31 extra",
            "tv_x.y.z",
        ]
        for tag in invalid:
            assert not _TAG_RE.match(tag), f"should not match: {tag!r}"


# ---------------------------------------------------------------------------
# _resolve_tag (build.py)
# ---------------------------------------------------------------------------


class TestResolveTag:
    def test_already_a_tag(self):
        assert _resolve_tag("tv_0.8.31") == "tv_0.8.31"

    def test_tron_prefix(self):
        assert _resolve_tag("tron-0.8.18") == "tv_0.8.18"

    def test_plain_version(self):
        assert _resolve_tag("0.8.31") == "tv_0.8.31"

    def test_version_with_commit(self):
        assert _resolve_tag("0.8.31+commit.abc") == "tv_0.8.31"

    def test_odyssey_tag(self):
        result = _resolve_tag("tv_0.4.25_Odyssey_v3.2.3")
        assert result == "tv_0.4.25_Odyssey_v3.2.3"

    def test_path_traversal_rejected(self):
        assert _resolve_tag("../../../etc/passwd") is None

    def test_traversal_in_tv_prefix(self):
        assert _resolve_tag("tv_../../../etc") is None

    def test_null_bytes(self):
        assert _resolve_tag("tv_0.8.31\x00evil") is None

    def test_empty_string(self):
        assert _resolve_tag("") is None

    def test_too_long(self):
        assert _resolve_tag("tv_" + "0" * 80) is None

    def test_spaces(self):
        assert _resolve_tag("tv_0.8.31 ") is None

    def test_non_numeric_version(self):
        assert _resolve_tag("tv_x.y.z") is None


# ---------------------------------------------------------------------------
# TronSolcCache security gates
# ---------------------------------------------------------------------------


class TestTronSolcCacheGates:
    def _make_cache(self, tmp: Path) -> TronSolcCache:
        """Build a TronSolcCache with a temp dir."""
        return TronSolcCache(cache_dir=tmp)

    def test_malformed_tag_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = TronSolcCache(cache_dir=Path(tmp))
            with pytest.raises(TronCompilerCacheError) as exc_info:
                cache.binary("../../../etc/passwd")
            assert exc_info.value.reason_detail == "compiler_binary_missing"

    def test_backslash_tag_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = TronSolcCache(cache_dir=Path(tmp))
            with pytest.raises(TronCompilerCacheError):
                cache.binary("tv_0.8.31\\evil")

    def test_null_sha256_in_table_fails_closed(self):
        """Tag in table but sha256 = null -> compiler_binary_missing (not a download attempt)."""
        null_releases = {
            "tv_0.8.31": {
                "asset": "solc-static-linux",
                "sha256": None,  # not yet pinned
                "source_url": "https://github.com/tronprotocol/solidity/releases/tag/tv_0.8.31",
                "checked_at": "2026-10-09",
                "note": "UV5-31 pending",
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            cache = TronSolcCache(cache_dir=Path(tmp))
            with (
                patch("soken_review.adapters.tron.compiler._load_releases", return_value=null_releases),
                pytest.raises(TronCompilerCacheError) as exc_info,
            ):
                cache.binary("tv_0.8.31")
            assert exc_info.value.reason_detail == "compiler_binary_missing"

    def test_unknown_tag_returns_unmapped(self):
        """A well-formed tag not in the pinned table -> tron_compiler_unmapped."""
        with tempfile.TemporaryDirectory() as tmp:
            cache = TronSolcCache(cache_dir=Path(tmp))
            with pytest.raises(TronCompilerCacheError) as exc_info:
                cache.binary("tv_9.9.9")
            assert exc_info.value.reason_detail == "tron_compiler_unmapped"

    def test_wrong_sha256_binary_rejected(self):
        """Even with a pinned sha256, a tampered binary is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            fake_releases = {
                "tv_0.8.31": {
                    "asset": "solc-static-linux",
                    "sha256": "0x" + "a" * 64,  # 64 hex chars = valid sha256 format
                    "source_url": "https://github.com",
                    "checked_at": "2026-10-09",
                }
            }
            cache = TronSolcCache(cache_dir=Path(tmp))
            # Patch _load_releases to return fake table
            with patch("soken_review.adapters.tron.compiler._load_releases", return_value=fake_releases):
                # Mock the HTTP download to return a tampered binary
                tampered = b"\x7fELF fake binary content"
                with patch("soken_review.adapters.tron.compiler._http_get", return_value=tampered):
                    # sha256 of tampered != "0x" + "a"*64 -> rejected
                    with pytest.raises(TronCompilerCacheError) as exc_info:
                        cache.binary("tv_0.8.31")
                    assert exc_info.value.reason_detail == "compiler_binary_missing"

    def test_correct_sha256_binary_accepted(self):
        """A binary with correct sha256 is written to cache."""
        with tempfile.TemporaryDirectory() as tmp:
            binary_content = b"\x7fELF correct binary"
            correct_sha256 = "0x" + hashlib.sha256(binary_content).hexdigest()
            fake_releases = {
                "tv_0.8.31": {
                    "asset": "solc-static-linux",
                    "sha256": correct_sha256,
                    "source_url": "https://github.com",
                    "checked_at": "2026-10-09",
                }
            }
            cache = TronSolcCache(cache_dir=Path(tmp))
            with patch("soken_review.adapters.tron.compiler._load_releases", return_value=fake_releases), \
                 patch("soken_review.adapters.tron.compiler._http_get", return_value=binary_content):
                binary_path = cache.binary("tv_0.8.31")
            assert binary_path.exists()
            assert binary_path.read_bytes() == binary_content

    def test_path_confinement(self):
        """Path confinement: resolve()+is_relative_to() blocks traversal."""
        with tempfile.TemporaryDirectory() as tmp:
            cache = TronSolcCache(cache_dir=Path(tmp))
            # The tag regex blocks traversal before we even get to path logic,
            # but let's verify the regex catches it
            with pytest.raises(TronCompilerCacheError):
                cache.binary("tv_0.8.31/../../../etc")
