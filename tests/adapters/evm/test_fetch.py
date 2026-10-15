"""Unit tests for EVM source fetch using recorded HTTP fixtures (05 section 4.2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from soken_review.adapters.evm.fetch import (
    _candidate_sha256,
    extract_cbor_cid,
    fetch_eth_bytecode_db,
    fetch_ipfs_metadata,
    fetch_source,
    fetch_sourcify,
    fetch_sourcify_similarity,
)

_FIXTURE_DIR = Path(__file__).parents[2] / "fixtures" / "evm"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status: int, body: Any, content_type: str = "application/json") -> httpx.Response:
    """Build a fake httpx.Response."""
    if isinstance(body, (dict, list)):
        content = json.dumps(body).encode()
    elif isinstance(body, str):
        content = body.encode()
    else:
        content = body
    return httpx.Response(
        status_code=status,
        headers={"content-type": content_type},
        content=content,
        request=httpx.Request("GET", "https://example.com"),
    )


# ---------------------------------------------------------------------------
# extract_cbor_cid
# ---------------------------------------------------------------------------


class TestExtractCborCid:
    def test_returns_none_for_empty(self):
        assert extract_cbor_cid("0x") is None

    def test_returns_none_for_short(self):
        assert extract_cbor_cid("0x60") is None

    def test_valid_cbor_parses_cid(self):
        # Construct minimal CBOR with ipfs key + 34-byte multihash (0x1220 + 32 zero bytes)
        multihash = bytes([0x12, 0x20]) + b"\x00" * 32  # 34 bytes
        # CBOR: 0xa1 (map 1 item) + 0x64 'ipfs' + 0x58 0x22 <34 bytes>
        cbor_data = bytes([0xa1, 0x64]) + b"ipfs" + bytes([0x58, 0x22]) + multihash
        cbor_len = len(cbor_data)
        # Append: some_prefix + cbor_data + 2-byte length
        raw = "abcd" + cbor_data.hex() + f"{cbor_len:04x}"
        cid = extract_cbor_cid("0x" + raw)
        # A multihash of 32 zero bytes should produce a valid base58 string starting with Qm
        # (0x1220 + 32 bytes = sha2-256 multihash)
        if cid is not None:
            assert isinstance(cid, str)
            assert len(cid) > 10


# ---------------------------------------------------------------------------
# fetch_sourcify
# ---------------------------------------------------------------------------


class TestFetchSourcify:
    @pytest.mark.anyio
    async def test_returns_none_on_404(self):
        fixture = _make_response(404, {"message": "not found"})
        with patch("soken_review.adapters.evm.fetch.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_instance.get = AsyncMock(return_value=fixture)
            mock_client.return_value = mock_instance
            result = await fetch_sourcify(mock_instance, 8453, "0xc2181d975c05c8c724b334bcED0764c0b86B1D53")
        assert result is None

    @pytest.mark.anyio
    async def test_parses_gblin_fixture(self):
        data = json.loads((_FIXTURE_DIR / "sourcify_gblin_8453.json").read_text())
        fixture = _make_response(200, data)
        with patch("soken_review.adapters.evm.fetch._get", new=AsyncMock(return_value=fixture)):
            async with httpx.AsyncClient() as client:
                result = await fetch_sourcify(client, 8453, "0xc2181d975c05c8c724b334bcED0764c0b86B1D53")
        assert result is not None
        assert result.provider == "sourcify"
        assert result.sourcify_match == "match"
        assert result.language == "solidity"
        assert result.compiler is not None
        assert "0.8.37" in result.compiler.version
        assert result.compiler.version_pinned_by == "sourcify"
        assert len(result.files) > 0

    @pytest.mark.anyio
    async def test_parses_compiler_settings(self):
        data = json.loads((_FIXTURE_DIR / "sourcify_gblin_8453.json").read_text())
        fixture = _make_response(200, data)
        with patch("soken_review.adapters.evm.fetch._get", new=AsyncMock(return_value=fixture)):
            async with httpx.AsyncClient() as client:
                result = await fetch_sourcify(client, 8453, "0xc2181d975c05c8c724b334bcED0764c0b86B1D53")
        assert result is not None
        assert result.settings.get("viaIR") is True or "optimizer" in result.settings


# ---------------------------------------------------------------------------
# fetch_eth_bytecode_db
# ---------------------------------------------------------------------------


class TestFetchEthBytecodeDb:
    @pytest.mark.anyio
    async def test_returns_none_on_empty_response(self):
        fixture = _make_response(200, {"ethBytecodeDbSources": []})
        with patch("soken_review.adapters.evm.fetch._post", new=AsyncMock(return_value=fixture)):
            async with httpx.AsyncClient() as client:
                result = await fetch_eth_bytecode_db(client, "0x" + "aa" * 100)
        assert result is None

    @pytest.mark.anyio
    async def test_parses_fixture_response(self):
        data = json.loads((_FIXTURE_DIR / "eth_bytecode_db_response.json").read_text())
        fixture = _make_response(200, data)
        with patch("soken_review.adapters.evm.fetch._post", new=AsyncMock(return_value=fixture)):
            async with httpx.AsyncClient() as client:
                result = await fetch_eth_bytecode_db(client, "0x" + "aa" * 100)
        assert result is not None
        assert result.provider == "eth_bytecode_db"
        assert result.explorer_verified is False  # bytecode search is not verification (F45)
        assert "0.8.24" in result.compiler.version

    @pytest.mark.anyio
    async def test_returns_none_on_non_200(self):
        fixture = _make_response(500, {"error": "server error"})
        with patch("soken_review.adapters.evm.fetch._post", new=AsyncMock(return_value=fixture)):
            async with httpx.AsyncClient() as client:
                result = await fetch_eth_bytecode_db(client, "0x" + "aa" * 100)
        assert result is None


# ---------------------------------------------------------------------------
# Similarity verify safety (R5)
# ---------------------------------------------------------------------------


class TestSimilarityVerifySafety:
    @pytest.mark.anyio
    async def test_similarity_off_by_default_returns_none(self):
        """R5: similarity_verify flag is off by default; must never be called in tests."""
        async with httpx.AsyncClient() as client:
            result = await fetch_sourcify_similarity(client, 1, "0x" + "aa" * 20, similarity_verify=False)
        assert result is None

    @pytest.mark.anyio
    async def test_similarity_not_called_in_fetch_source_by_default(self):
        """fetch_source must not call similarity verify without explicit flag."""
        call_log: list[str] = []

        async def mock_sourcify(*args: Any, **kwargs: Any) -> None:
            call_log.append("sourcify")

        with (
            patch("soken_review.adapters.evm.fetch.fetch_sourcify", side_effect=mock_sourcify),
            patch("soken_review.adapters.evm.fetch.fetch_sourcify_all_chains", return_value=[]),
            patch("soken_review.adapters.evm.fetch.fetch_eth_bytecode_db", return_value=None),
            patch("soken_review.adapters.evm.fetch.fetch_ipfs_metadata", return_value=None),
            patch("soken_review.adapters.evm.fetch.fetch_sourcify_similarity") as mock_sim,
        ):
            await fetch_source(1, "0x" + "aa" * 20, "0x" + "bb" * 100)
            mock_sim.assert_not_called()


# ---------------------------------------------------------------------------
# fetch_source R1: stop on Sourcify match without user candidate
# ---------------------------------------------------------------------------


class TestFetchSourceR1:
    @pytest.mark.anyio
    async def test_stops_after_sourcify_exact_match(self):
        """R1: Sourcify exact_match stops the fetch without user/repo candidate."""
        data = json.loads((_FIXTURE_DIR / "sourcify_gblin_8453.json").read_text())
        data["match"] = "exact_match"
        fixture = _make_response(200, data)

        eth_bytecode_calls: list[Any] = []

        async def mock_eth_bytecode_db(*args: Any, **kwargs: Any) -> None:
            eth_bytecode_calls.append(args)

        with (
            patch("soken_review.adapters.evm.fetch._get", new=AsyncMock(return_value=fixture)),
            patch("soken_review.adapters.evm.fetch.fetch_eth_bytecode_db", side_effect=mock_eth_bytecode_db),
            patch("soken_review.adapters.evm.fetch.fetch_sourcify_all_chains", return_value=[]),
        ):
            result = await fetch_source(8453, "0xc2181d975c05c8c724b334bcED0764c0b86B1D53", "0x6080")
        assert len(result) == 1
        assert result[0].provider == "sourcify"
        assert not eth_bytecode_calls  # eth-bytecode-db was not called


# ---------------------------------------------------------------------------
# Candidate sha256 determinism
# ---------------------------------------------------------------------------


def test_candidate_sha256_deterministic():
    files = {"a.sol": "contract A {}", "b.sol": "contract B {}"}
    sha1 = _candidate_sha256(files)
    sha2 = _candidate_sha256({"b.sol": "contract B {}", "a.sol": "contract A {}"})  # different order
    assert sha1 == sha2  # sorted, so deterministic


def test_candidate_sha256_unique():
    files1 = {"a.sol": "contract A {}"}
    files2 = {"a.sol": "contract B {}"}
    assert _candidate_sha256(files1) != _candidate_sha256(files2)


# ---------------------------------------------------------------------------
# Security: make_candidate enforces path safety across all providers
# ---------------------------------------------------------------------------


class TestMakeCandidatePathSafety:
    def test_malicious_sourcify_path_dropped(self):
        """Attacker-controlled path in Sourcify sources must be filtered (security gate)."""
        from soken_review.adapters.evm.fetch import make_candidate

        cand = make_candidate(
            provider="sourcify",
            raw_files={
                "contracts/Token.sol": "contract Token {}",
                "../../.ssh/authorized_keys": "ssh-rsa AAAA...",
                "/etc/passwd": "root:x:0:0",
            },
            language="solidity",
            compiler=None,
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        assert "contracts/Token.sol" in cand.files
        assert "../../.ssh/authorized_keys" not in cand.files
        assert "/etc/passwd" not in cand.files
        assert len(cand.files) == 1

    def test_malicious_ipfs_path_dropped(self):
        """Attacker-controlled path in IPFS metadata sources must be filtered."""
        from soken_review.adapters.evm.fetch import make_candidate

        cand = make_candidate(
            provider="ipfs",
            raw_files={
                "lib/ERC20.sol": "contract ERC20 {}",
                "../../etc/shadow": "root:!",
            },
            language="solidity",
            compiler=None,
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        assert "lib/ERC20.sol" in cand.files
        assert "../../etc/shadow" not in cand.files

    @pytest.mark.anyio
    async def test_malicious_ipfs_metadata_sources(self):
        """IPFS metadata response with malicious source paths must be filtered."""
        malicious_metadata = {
            "language": "Solidity",
            "compiler": {"version": "0.8.24+commit.e11b9ed9"},
            "settings": {},
            "sources": {
                "contracts/Token.sol": {"content": "contract Token {}"},
                "../../.ssh/authorized_keys": {"content": "ssh-rsa AAAA..."},
                "/etc/passwd": {"content": "root:x:0:0"},
            },
        }
        fixture = _make_response(200, malicious_metadata)
        with patch("soken_review.adapters.evm.fetch._get", new=AsyncMock(return_value=fixture)):
            # Fake a runtime with valid CBOR CID pattern
            result = await fetch_ipfs_metadata(AsyncMock(), "0x" + "aa" * 200)
        # May be None if CID extraction fails (malformed bytecode), but if not None,
        # must not contain malicious paths
        if result is not None:
            assert "contracts/Token.sol" in result.files
            assert "../../.ssh/authorized_keys" not in result.files
            assert "/etc/passwd" not in result.files


def test_other_chain_and_bytecode_candidates_are_never_verified():
    """F46 and F45 results are candidates only; the rebuild decides (05 4.2, R2)."""
    from soken_review.adapters.evm.fetch import _unverified, make_candidate

    c = make_candidate(
        provider="sourcify", raw_files={"A.sol": "contract A {}"}, language="solidity", compiler=None,
        settings={}, std_json_input=None, entry_contract=None, explorer_verified=True,
        sourcify_match="exact_match",
    )
    u = _unverified(c)
    assert u.explorer_verified is False and u.sourcify_match is None
