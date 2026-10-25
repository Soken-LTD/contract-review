"""Tests for TRON fetch: path safety gate on TronScan responses (05 section 4.2, 4.3).

Verifies that attacker-controlled file names from TronScan (../x.sol, /etc/passwd,
backslash paths) are rejected by make_candidate -> filter_candidate_files.

Also contains a fixture-based regression test for the verified CRSToken contract at
TRegosVaS1o3DHG85nnW8xYzczPm3xL76K (recorded live 2026-10-25), which was the contract
used in the TRON stuck-job incident.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from soken_review.adapters.tron.fetch import _decode_contract_code, fetch_source_tron, fetch_tronscan

_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "tron"


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


# ---------------------------------------------------------------------------
# Fixture-based regression test: verified TRC-20 contract CRSToken
# (recorded live 2026-10-25, TRegosVaS1o3DHG85nnW8xYzczPm3xL76K)
# ---------------------------------------------------------------------------


class TestFetchSourceTronFixture:
    """fetch_source_tron with fixture responses — no network.

    Covers the root cause of the 2026-10-25 stuck-job incident: the supervisor
    routed TRON jobs to the EVM fetch path (no chain_id → 'not a deployed job'
    branch) instead of calling fetch_source_tron, so no pin was written.
    """

    @pytest.mark.asyncio
    async def test_verified_contract_returns_candidate_with_source(self):
        """fetch_source_tron with a verified CRSToken fixture → one candidate with source files."""
        verify_fixture = json.loads(
            (_FIXTURES / "tronscan_verify_status_CRSToken.json").read_text()
        )
        info_fixture = json.loads(
            (_FIXTURES / "tronscan_contract_info_CRSToken.json").read_text()
        )

        with patch("soken_review.adapters.tron.fetch._tronscan_get") as mock_get, \
             patch("soken_review.adapters.tron.fetch._tronscan_post") as mock_post, \
             patch("soken_review.adapters.tron.fetch.fetch_tron_runtime",
                   return_value=("0xdeadbeef", None)):

            mock_get.return_value = _make_response(200, verify_fixture)
            mock_post.return_value = _make_response(200, info_fixture)

            candidates, runtime_hex, _creation = await fetch_source_tron(
                "TRegosVaS1o3DHG85nnW8xYzczPm3xL76K"
            )

        assert len(candidates) >= 1, "Expected at least one candidate from TronScan fixture"
        cand = candidates[0]
        assert cand.provider == "tronscan"
        assert cand.explorer_verified is True
        # Files must be populated (the pin step needs files to write manifest.json)
        assert len(cand.files) >= 1, "Candidate has no files — pin would be empty"
        # No path-traversal filenames
        for fname in cand.files:
            assert ".." not in fname, f"traversal path in candidate file: {fname}"
            assert not fname.startswith("/"), f"absolute path in candidate file: {fname}"
        # Compiler version recorded
        assert cand.compiler is not None
        assert "0.6" in cand.compiler.version or "tron" in cand.compiler.version.lower()
        assert runtime_hex == "0xdeadbeef"

    @pytest.mark.asyncio
    async def test_unverified_contract_returns_empty_candidates(self):
        """fetch_source_tron for an unverified contract → empty list, no crash."""
        # verify_status=0 → TronScan returns not verified
        unverified_fixture = {
            "status": {"code": 0, "message": "SUCCESS"},
            "data": [{"address": "TFakeAddr", "verify_status": 0}],
        }

        with patch("soken_review.adapters.tron.fetch._tronscan_get") as mock_get, \
             patch("soken_review.adapters.tron.fetch._tronscan_post") as mock_post, \
             patch("soken_review.adapters.tron.fetch.fetch_tron_runtime",
                   return_value=(None, None)):

            mock_get.return_value = _make_response(200, unverified_fixture)
            mock_post.return_value = _make_response(200, {"code": 200, "data": {}})

            candidates, _runtime, _creation = await fetch_source_tron("TFakeAddr000000000001")

        assert candidates == [], f"Expected empty candidates for unverified contract, got: {candidates}"
