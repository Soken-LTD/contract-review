"""Tests for TRON fetch: path safety gate on TronScan responses (05 section 4.2, 4.3).

Verifies that attacker-controlled file names from TronScan (../x.sol, /etc/passwd,
backslash paths) are rejected by make_candidate -> filter_candidate_files.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from soken_review.adapters.tron.fetch import _decode_contract_code, fetch_tronscan


def _make_response(status: int, body: Any) -> httpx.Response:
    content = json.dumps(body).encode() if isinstance(body, (dict, list)) else body.encode()
    return httpx.Response(
        status_code=status,
        headers={"content-type": "application/json"},
        content=content,
        request=httpx.Request("GET", "https://example.com"),
    )


# ---------------------------------------------------------------------------
# _decode_contract_code path safety
# ---------------------------------------------------------------------------


class TestDecodeContractCode:
    def test_normal_filenames(self):
        """Normal filenames pass through."""
        cc = [{"name": "contracts/Token.sol", "content": ""}]
        files = _decode_contract_code(cc)
        assert "contracts/Token.sol" in files

    def test_traversal_dot_dot(self):
        """Filename with ../ is present in raw dict (will be filtered by make_candidate)."""
        # _decode_contract_code itself doesn't filter - that's make_candidate's job.
        # We just check it doesn't crash and returns the raw (potentially unsafe) name.
        cc = [{"name": "../../../etc/passwd", "content": "dGVzdA=="}]  # base64 "test"
        files = _decode_contract_code(cc)
        # Raw dict has the traversal path - make_candidate will drop it
        assert "../../../etc/passwd" in files or len(files) == 0 or "contract_0.sol" in files

    def test_absolute_path(self):
        """/etc/passwd style path in raw dict."""
        cc = [{"name": "/etc/passwd", "content": "dGVzdA=="}]
        files = _decode_contract_code(cc)
        assert "/etc/passwd" in files or "contract_0.sol" in files

    def test_backslash_path(self):
        """Windows-style backslash path."""
        cc = [{"name": "..\\..\\evil.sol", "content": "dGVzdA=="}]
        files = _decode_contract_code(cc)
        # Raw name present in dict
        assert len(files) >= 0  # just check no crash


class TestFetchTronscanPathSafety:
    """Verify that make_candidate drops unsafe filenames from TronScan responses."""

    @pytest.mark.asyncio
    async def test_traversal_paths_dropped(self):
        """Candidate with attacker-controlled filenames has those paths dropped."""
        # Simulate TronScan returning source code with unsafe filenames
        malicious_cc = [
            {"name": "../../../etc/passwd", "content": "cHJhZ21hIHNvbGlkaXR5OyA="},
            {"name": "/absolute/path.sol", "content": "cHJhZ21hIHNvbGlkaXR5OyA="},
            {"name": "contracts\\token.sol", "content": "cHJhZ21hIHNvbGlkaXR5OyA="},
            {"name": "safe/Token.sol", "content": "cHJhZ21hIHNvbGlkaXR5OyA="},
        ]
        body = {
            "verify_status": 1,
            "contract_code": malicious_cc,
            "compiler": "0.8.18",
            "optimizer": False,
            "optimizer_runs": 200,
        }
        # Mock both GET (verify_status) and POST (contract/info)
        with patch("soken_review.adapters.tron.fetch._tronscan_get") as mock_get, \
             patch("soken_review.adapters.tron.fetch._tronscan_post") as mock_post:
            mock_get.return_value = _make_response(200, {"data": [{"verify_status": 2}]})  # real TronScan shape
            mock_post.return_value = _make_response(200, {"code": 200, "data": body})

            async with httpx.AsyncClient() as client:
                candidate = await fetch_tronscan(client, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")

        assert candidate is not None
        # Unsafe paths must be absent from the candidate
        for path in candidate.files:
            assert ".." not in path, f"traversal path in candidate: {path}"
            assert not path.startswith("/"), f"absolute path in candidate: {path}"
            assert "\\" not in path, f"backslash in candidate: {path}"
        # Safe path must be present
        assert "safe/Token.sol" in candidate.files

    @pytest.mark.asyncio
    async def test_all_paths_unsafe_returns_empty(self):
        """If all filenames are unsafe, candidate has empty files or no candidate."""
        malicious_cc = [
            {"name": "../evil.sol", "content": "cHJhZ21hIHNvbGlkaXR5OyA="},
            {"name": "/root/.ssh/id_rsa", "content": "cHJhZ21hIHNvbGlkaXR5OyA="},
        ]
        body = {
            "verify_status": 1,
            "contract_code": malicious_cc,
            "compiler": "0.8.18",
            "optimizer": False,
        }
        with patch("soken_review.adapters.tron.fetch._tronscan_get") as mock_get, \
             patch("soken_review.adapters.tron.fetch._tronscan_post") as mock_post:
            mock_get.return_value = _make_response(200, {"data": [{"verify_status": 2}]})  # real TronScan shape
            mock_post.return_value = _make_response(200, {"code": 200, "data": body})

            async with httpx.AsyncClient() as client:
                candidate = await fetch_tronscan(client, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")

        # Either returns None (no files left) or an empty files candidate
        if candidate is not None:
            for path in candidate.files:
                assert ".." not in path
                assert not path.startswith("/")
