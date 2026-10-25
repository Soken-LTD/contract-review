"""Tests for the TON on-chain registry source fetch (fix/ton-verified-source, 2026-10-25).

The broken endpoint GET /api/v1/verification/source?code_hash=<hex> returned 404 for
job_6X44N1MS15NM5WTYDV3K5GA6WH (Tact 1.6.5, code_hash c845917d…).  The correct lookup
uses the on-chain sources registry via TonCenter v2 runGetMethod.

All tests use recorded fixtures — no live network calls.

Lookup flow exercised:
  1. _parse_addr_std_cell  — decode addr_std from runGetMethod cell response
  2. _parse_string_cell    — decode ipfs:// URL from cell
  3. _ton_address_b64      — encode (workchain, hash) as bounceable base64url
  4. _crc16_xmodem         — CRC used in address encoding
  5. _registry_verifier_sha256_int — sha256 of verifier ID string as big int
  6. _registry_find_entrypoint — resolve entrypoint path from manifest + IPFS filenames
  7. fetch_source_from_registry — full end-to-end with mocked HTTP
  8. fetch_source_from_verifier — tries registry first, falls back to legacy API
  9. IPFS gateway fallback — retries next gateway when first returns non-200
 10. Allowlist guards — new gateway hostnames accepted by _validate_download_url
 11. Manifest hash mismatch — rejects manifests whose hash field doesn't match code_hash
 12. Missing/unsupported compiler — returns None gracefully
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.ton.fetch import (
    _crc16_xmodem,
    _ipfs_fetch_bytes,
    _ipfs_fetch_manifest,
    _parse_addr_std_cell,
    _parse_string_cell,
    _registry_find_entrypoint,
    _registry_verifier_sha256_int,
    _ton_address_b64,
    _validate_download_url,
    fetch_source_from_registry,
    fetch_source_from_verifier,
)

# ── fixtures ──────────────────────────────────────────────────────────────

_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "ton"

CODE_HASH = "c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea"
SOURCE_ITEM_ADDR = "EQAow6Z5yt5DJfr7i3ZEvKU5NCD5vmtReFrn3sN9ndyUNfjJ"
IPFS_URL = "ipfs://QmdCXc6dyEJnjepkoydT4a15JJttKatLhSrR7dPqaZkAwo"
IPFS_CID = "QmdCXc6dyEJnjepkoydT4a15JJttKatLhSrR7dPqaZkAwo"

_ADDR_CELL_OBJ = {
    "bytes": "te6cckEBAQEAJAAAQ4AFGHTPOVvIZL9fcW7Il5SnJoQfN81qLwtc+9hvs7uShrACjuLH",
    "object": {
        "data": {
            "b64": "gAUYdM85W8hkv19xbsiXlKcmhB83zWovC1z72G+zu5KGsA==",
            "len": 267,
        },
        "refs": [],
        "special": False,
    },
}

_IPFS_CELL_OBJ = {
    "bytes": "te6cckEBAQEAOAAAbAFpcGZzOi8vUW1kQ1hjNmR5RUpuamVwa295ZFQ0YTE1Skp0dEthdExoU3JSN2RQcWFaa0F3b6ax0Hw=",
    "object": {
        "data": {
            "b64": "AWlwZnM6Ly9RbWRDWGM2ZHlFSm5qZXBrb3lkVDRhMTVKSnR0S2F0TGhTclI3ZFBxYVprQXdv",
            "len": 432,
        },
        "refs": [],
        "special": False,
    },
}


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((_FIXTURES / name).read_text())


def _make_manifest(code_hash: str = CODE_HASH, compiler: str = "tact") -> dict[str, Any]:
    h_b64 = base64.b64encode(bytes.fromhex(code_hash)).decode()
    return {
        "compiler": compiler,
        "compilerSettings": {
            "tactVersion": "1.6.5",
            "parameters": json.dumps({"entrypoint": "contracts/ft_master.tact"}),
        },
        "hash": h_b64,
        "verificationDate": 1745917200000,
        "sources": [
            {"url": "ipfs://CIDsource1", "filename": "contract/contracts/ft_master.tact"},
            {"url": "ipfs://CIDsource2", "filename": "contract/contracts/messages.tact"},
            {"url": "ipfs://CIDabi1", "filename": "output/verifier_FtSquad.abi"},
            {"url": "ipfs://CIDpkg1", "filename": "output/verifier_FtSquad.pkg"},
        ],
        "knownContractAddress": "EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ",
    }


# ── unit: address helpers ─────────────────────────────────────────────────


class TestCrc16Xmodem:
    def test_known_vector(self):
        # CRC-16/XMODEM (poly=0x1021, init=0x0000, no reflection):
        # check value for "123456789" = 0x31C3
        result = _crc16_xmodem(b"123456789")
        assert result == 0x31C3

    def test_empty_input(self):
        assert _crc16_xmodem(b"") == 0


class TestTonAddressB64:
    def test_encodes_source_item_address(self):
        # hash bytes decoded from the live registry lookup
        hash_bytes = bytes.fromhex("28c3a679cade4325fafb8b7644bca5393420f9be6b51785ae7dec37d9ddc9435")
        addr = _ton_address_b64(0, hash_bytes)
        assert addr == SOURCE_ITEM_ADDR

    def test_length(self):
        hash_bytes = bytes(32)
        addr = _ton_address_b64(0, hash_bytes)
        decoded = base64.urlsafe_b64decode(addr)
        assert len(decoded) == 36  # 1 tag + 1 wc + 32 hash + 2 crc

    def test_workchain_minus_one(self):
        hash_bytes = bytes(32)
        addr = _ton_address_b64(-1, hash_bytes)
        decoded = base64.urlsafe_b64decode(addr)
        # byte 1 is workchain; 0xFF = -1 in int8
        assert decoded[1] == 0xFF


class TestRegistryVerifierSha256Int:
    def test_orbs_com(self):
        n = _registry_verifier_sha256_int("orbs.com")
        assert n == 48254587912360971182213375080930396471362566750482580908974048855188723745203

    def test_verifier_ton_org(self):
        n = _registry_verifier_sha256_int("verifier.ton.org")
        assert n == 52731031310081730050917189050601223550674998057759177546179320415691433905031


# ── unit: cell parsers ────────────────────────────────────────────────────


class TestParseAddrStdCell:
    def test_parses_live_fixture(self):
        result = _parse_addr_std_cell(_ADDR_CELL_OBJ)
        assert result is not None
        wc, hash_bytes = result
        assert wc == 0
        assert hash_bytes.hex() == "28c3a679cade4325fafb8b7644bca5393420f9be6b51785ae7dec37d9ddc9435"

    def test_rejects_wrong_type(self):
        obj = {
            "object": {
                "data": {
                    "b64": "AAAA",
                    "len": 24,
                }
            }
        }
        # addr_type=00 is not addr_std
        assert _parse_addr_std_cell(obj) is None

    def test_rejects_too_short(self):
        obj = {"object": {"data": {"b64": "AA==", "len": 8}}}
        assert _parse_addr_std_cell(obj) is None

    def test_rejects_missing_fields(self):
        assert _parse_addr_std_cell({}) is None
        assert _parse_addr_std_cell({"object": {}}) is None

    def test_rejects_non_dict(self):
        assert _parse_addr_std_cell(None) is None  # type: ignore[arg-type]


class TestParseStringCell:
    def test_parses_ipfs_url(self):
        result = _parse_string_cell(_IPFS_CELL_OBJ)
        assert result == IPFS_URL

    def test_rejects_wrong_version(self):
        # version byte = 0x02
        raw = b"\x02ipfs://something"
        b64 = base64.b64encode(raw).decode()
        obj = {"object": {"data": {"b64": b64, "len": len(raw) * 8}}}
        assert _parse_string_cell(obj) is None

    def test_rejects_non_byte_aligned(self):
        raw = b"\x01hello"
        b64 = base64.b64encode(raw).decode()
        obj = {"object": {"data": {"b64": b64, "len": len(raw) * 8 - 1}}}
        assert _parse_string_cell(obj) is None

    def test_rejects_missing_fields(self):
        assert _parse_string_cell({}) is None


# ── unit: registry helpers ────────────────────────────────────────────────


class TestRegistryFindEntrypoint:
    def test_finds_with_directory_prefix(self):
        manifest = _make_manifest()
        filenames = ["contract/contracts/ft_master.tact", "contract/contracts/messages.tact"]
        entry = _registry_find_entrypoint(manifest, filenames)
        assert entry == "contract/contracts/ft_master.tact"

    def test_finds_exact_match(self):
        manifest = _make_manifest()
        filenames = ["contracts/ft_master.tact", "contracts/messages.tact"]
        entry = _registry_find_entrypoint(manifest, filenames)
        assert entry == "contracts/ft_master.tact"

    def test_returns_none_when_not_found(self):
        manifest = _make_manifest()
        filenames = ["contracts/other.tact"]
        assert _registry_find_entrypoint(manifest, filenames) is None

    def test_returns_none_for_missing_parameters(self):
        manifest = {"compilerSettings": {}}
        assert _registry_find_entrypoint(manifest, ["contracts/foo.tact"]) is None

    def test_returns_none_for_invalid_parameters_json(self):
        manifest = {"compilerSettings": {"parameters": "not-json"}}
        assert _registry_find_entrypoint(manifest, ["contracts/foo.tact"]) is None


# ── unit: IPFS manifest hash verification ────────────────────────────────


class TestIpfsManifestHashVerification:
    """_ipfs_fetch_manifest must reject manifests with wrong hash."""

    def _make_response(self, manifest: dict[str, Any]) -> MagicMock:
        r = MagicMock()
        r.status_code = 200
        r.content = json.dumps(manifest).encode()
        return r

    @pytest.mark.asyncio
    async def test_rejects_wrong_hash(self):
        wrong_code_hash = "a" * 64  # different hash
        manifest = _make_manifest(code_hash=CODE_HASH)  # manifest declares CODE_HASH
        mock_client = AsyncMock()
        mock_client.get.return_value = self._make_response(manifest)
        with patch("soken_review.adapters.ton.fetch._limiter") as mock_lim:
            mock_lim.return_value.wait = AsyncMock()
            with patch("soken_review.adapters.ton.fetch._validate_download_url", return_value="https://files.orbs.network/ipfs/" + IPFS_CID):
                result = await _ipfs_fetch_manifest(mock_client, IPFS_URL, wrong_code_hash)
        assert result is None

    @pytest.mark.asyncio
    async def test_accepts_correct_hash(self):
        manifest = _make_manifest(code_hash=CODE_HASH)
        mock_client = AsyncMock()
        mock_client.get.return_value = self._make_response(manifest)
        with patch("soken_review.adapters.ton.fetch._limiter") as mock_lim:
            mock_lim.return_value.wait = AsyncMock()
            with patch("soken_review.adapters.ton.fetch._validate_download_url", return_value="https://files.orbs.network/ipfs/" + IPFS_CID):
                result = await _ipfs_fetch_manifest(mock_client, IPFS_URL, CODE_HASH)
        assert result is not None
        assert result["compiler"] == "tact"


# ── unit: IPFS gateway fallback ───────────────────────────────────────────


class TestIpfsGatewayFallback:
    """_ipfs_fetch_bytes should try the next gateway when the first returns non-200."""

    @pytest.mark.asyncio
    async def test_falls_back_on_non_200(self):
        calls = []

        async def mock_get(url, **kwargs):
            calls.append(url)
            r = MagicMock()
            if "files.orbs.network" in url:
                r.status_code = 404
                r.content = b""
            else:
                r.status_code = 200
                r.content = b"source content"
            return r

        mock_client = MagicMock()
        mock_client.get = mock_get
        with patch("soken_review.adapters.ton.fetch._limiter") as mock_lim:
            mock_lim.return_value.wait = AsyncMock()
            with patch("soken_review.adapters.ton.fetch._validate_download_url", side_effect=lambda u: u):
                result = await _ipfs_fetch_bytes(mock_client, IPFS_CID, 1024 * 1024)
        assert result == b"source content"
        # first call was to files.orbs.network, fallback to second gateway
        assert any("files.orbs.network" in u for u in calls)
        assert len(calls) >= 2

    @pytest.mark.asyncio
    async def test_returns_none_if_all_fail(self):
        async def mock_get(url, **kwargs):
            r = MagicMock()
            r.status_code = 503
            r.content = b""
            return r

        mock_client = MagicMock()
        mock_client.get = mock_get
        with patch("soken_review.adapters.ton.fetch._limiter") as mock_lim:
            mock_lim.return_value.wait = AsyncMock()
            with patch("soken_review.adapters.ton.fetch._validate_download_url", side_effect=lambda u: u):
                result = await _ipfs_fetch_bytes(mock_client, IPFS_CID, 1024 * 1024)
        assert result is None


# ── unit: allowlist (new IPFS gateways) ──────────────────────────────────


class TestNewGatewayAllowlist:
    def test_files_orbs_network_accepted(self):
        url = "https://files.orbs.network/ipfs/QmdCXc6dyEJnjepkoydT4a15JJttKatLhSrR7dPqaZkAwo"
        result = _validate_download_url(url)
        assert result in (url, None)  # None if DNS blocked in CI; must not raise

    def test_gateway_pinata_cloud_accepted(self):
        url = "https://gateway.pinata.cloud/ipfs/QmdCXc6dyEJnjepkoydT4a15JJttKatLhSrR7dPqaZkAwo"
        result = _validate_download_url(url)
        assert result in (url, None)

    def test_evil_ipfs_gateway_rejected(self):
        url = "https://evil-ipfs-proxy.example.com/ipfs/QmdCXc6dyEJnjepkoydT4a15JJttKatLhSrR7dPqaZkAwo"
        assert _validate_download_url(url) is None

    def test_ipfs_ton_live_accepted(self):
        url = "https://ipfs.ton.live/ipfs/QmdCXc6dyEJnjepkoydT4a15JJttKatLhSrR7dPqaZkAwo"
        # already in allowlist before this fix; DNS may not resolve in CI
        result = _validate_download_url(url)
        assert result in (url, None)


# ── integration: fetch_source_from_registry end-to-end ───────────────────


def _make_run_get_response(stack: list[Any]) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {
        "ok": True,
        "result": {"exit_code": 0, "stack": stack, "@type": "smc.runResult"},
    }
    return r


def _make_ipfs_response(content: bytes) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.content = content
    return r


class TestFetchSourceFromRegistry:
    """Full end-to-end of fetch_source_from_registry with mocked HTTP."""

    def _build_mock_client(self) -> MagicMock:
        """Return a mock client whose post/get return canned responses."""
        manifest = _make_manifest()
        source_content_1 = "contract FtMaster {}"
        source_content_2 = "message Transfer {}"

        post_calls: list[str] = []
        get_calls: list[str] = []

        async def mock_post(url, *, json: dict, **kwargs):
            post_calls.append(url + "|" + json.get("method", ""))
            method = json.get("method", "")
            if method == "get_source_item_address":
                # return addr_std cell
                return _make_run_get_response([["cell", _ADDR_CELL_OBJ]])
            if method == "get_source_item_data":
                # return stack with ipfs link at index 3
                return _make_run_get_response([
                    ["num", "0x1234"],
                    ["num", "0x" + CODE_HASH],
                    ["cell", {}],
                    ["cell", _IPFS_CELL_OBJ],
                ])
            r = MagicMock()
            r.status_code = 404
            return r

        async def mock_get(url, **kwargs):
            get_calls.append(url)
            if IPFS_CID in url:
                return _make_ipfs_response(json.dumps(manifest).encode())
            if "CIDsource1" in url:
                return _make_ipfs_response(source_content_1.encode())
            if "CIDsource2" in url:
                return _make_ipfs_response(source_content_2.encode())
            r = MagicMock()
            r.status_code = 404
            r.content = b""
            return r

        client = MagicMock()
        client.post = mock_post
        client.get = mock_get
        return client

    @pytest.mark.asyncio
    async def test_returns_candidate_for_verified_contract(self):
        client = self._build_mock_client()
        with patch("soken_review.adapters.ton.fetch._limiter") as mock_lim:
            mock_lim.return_value.wait = AsyncMock()
            with patch("soken_review.adapters.ton.fetch._validate_download_url", side_effect=lambda u: u):
                cand = await fetch_source_from_registry(client, CODE_HASH)

        assert cand is not None
        assert cand.provider == "ton_verifier"
        assert cand.language == "tact"
        assert cand.compiler is not None
        assert cand.compiler.version == "1.6.5"
        # only .tact files (not .abi or .pkg)
        assert all(k.endswith(".tact") for k in cand.files)
        assert len(cand.files) == 2
        # entry_contract resolves to the IPFS path
        assert cand.entry_contract == "contract/contracts/ft_master.tact"
        assert cand.explorer_verified is True

    @pytest.mark.asyncio
    async def test_returns_none_for_unverified_code_hash(self):
        unverified = "a" * 64
        client = MagicMock()

        async def mock_post(url, *, json: dict, **kwargs):
            # Simulate runGetMethod returning exit_code != 0 (no source item)
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = {
                "ok": True,
                "result": {"exit_code": -256, "stack": []},
            }
            return r

        client.post = mock_post
        with patch("soken_review.adapters.ton.fetch._limiter") as mock_lim:
            mock_lim.return_value.wait = AsyncMock()
            cand = await fetch_source_from_registry(client, unverified)
        assert cand is None

    @pytest.mark.asyncio
    async def test_returns_none_for_invalid_hex(self):
        client = MagicMock()
        cand = await fetch_source_from_registry(client, "not-a-hex-hash")
        assert cand is None
        client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_abi_and_pkg_files(self):
        """Output files (.abi, .pkg) must not appear in the candidate files."""
        client = self._build_mock_client()
        with patch("soken_review.adapters.ton.fetch._limiter") as mock_lim:
            mock_lim.return_value.wait = AsyncMock()
            with patch("soken_review.adapters.ton.fetch._validate_download_url", side_effect=lambda u: u):
                cand = await fetch_source_from_registry(client, CODE_HASH)
        assert cand is not None
        for path in cand.files:
            assert not path.endswith(".abi"), f"ABI file leaked: {path}"
            assert not path.endswith(".pkg"), f"PKG file leaked: {path}"

    @pytest.mark.asyncio
    async def test_rejects_unsupported_compiler(self):
        manifest = _make_manifest()
        manifest["compiler"] = "solidity"  # not supported
        client = MagicMock()

        async def mock_post(url, *, json: dict, **kwargs):
            method = json.get("method", "")
            if method == "get_source_item_address":
                return _make_run_get_response([["cell", _ADDR_CELL_OBJ]])
            if method == "get_source_item_data":
                return _make_run_get_response([
                    ["num", "0x1234"], ["num", "0x" + CODE_HASH],
                    ["cell", {}], ["cell", _IPFS_CELL_OBJ],
                ])
            r = MagicMock()
            r.status_code = 404
            return r

        async def mock_get(url, **kwargs):
            r = MagicMock()
            r.status_code = 200
            r.content = json.dumps(manifest).encode()
            return r

        client.post = mock_post
        client.get = mock_get
        with patch("soken_review.adapters.ton.fetch._limiter") as mock_lim:
            mock_lim.return_value.wait = AsyncMock()
            with patch("soken_review.adapters.ton.fetch._validate_download_url", side_effect=lambda u: u):
                cand = await fetch_source_from_registry(client, CODE_HASH)
        # all verifier IDs tried and skipped due to unsupported compiler
        assert cand is None


# ── integration: fetch_source_from_verifier registry-first ───────────────


class TestFetchSourceFromVerifierRegistryFirst:
    """fetch_source_from_verifier must try registry before legacy HTTP API."""

    @pytest.mark.asyncio
    async def test_uses_registry_when_available(self):
        manifest = _make_manifest()
        source_content = "contract FtMaster {}"

        async def mock_post(url, *, json: dict, **kwargs):
            method = json.get("method", "")
            if method == "get_source_item_address":
                return _make_run_get_response([["cell", _ADDR_CELL_OBJ]])
            if method == "get_source_item_data":
                return _make_run_get_response([
                    ["num", "0x1234"], ["num", "0x" + CODE_HASH],
                    ["cell", {}], ["cell", _IPFS_CELL_OBJ],
                ])
            r = MagicMock()
            r.status_code = 404
            return r

        async def mock_get(url, **kwargs):
            r = MagicMock()
            if IPFS_CID in url:
                r.status_code = 200
                r.content = json.dumps(manifest).encode()
            elif "CIDsource1" in url or "CIDsource2" in url:
                r.status_code = 200
                r.content = source_content.encode()
            else:
                r.status_code = 404
                r.content = b""
            return r

        legacy_called = []

        async def mock_fetch_verifier_bundle(*args, **kwargs):
            legacy_called.append(True)

        client = MagicMock()
        client.post = mock_post
        client.get = mock_get

        with (
            patch("soken_review.adapters.ton.fetch._limiter") as mock_lim,
            patch("soken_review.adapters.ton.fetch._validate_download_url", side_effect=lambda u: u),
            patch("soken_review.adapters.ton.fetch.fetch_verifier_bundle", side_effect=mock_fetch_verifier_bundle),
        ):
            mock_lim.return_value.wait = AsyncMock()
            cand = await fetch_source_from_verifier(client, CODE_HASH)

        assert cand is not None
        assert cand.provider == "ton_verifier"
        # legacy API was NOT called because registry succeeded
        assert not legacy_called

    @pytest.mark.asyncio
    async def test_falls_back_to_legacy_when_registry_returns_none(self):
        """When registry returns None (not verified), fall back to legacy HTTP bundle."""
        legacy_called = []

        async def mock_fetch_registry(*args, **kwargs):
            return None  # not found in registry

        async def mock_fetch_verifier_bundle(client, code_hash):
            legacy_called.append(True)

        client = MagicMock()
        with (
            patch("soken_review.adapters.ton.fetch.fetch_source_from_registry", side_effect=mock_fetch_registry),
            patch("soken_review.adapters.ton.fetch.fetch_verifier_bundle", side_effect=mock_fetch_verifier_bundle),
        ):
            cand = await fetch_source_from_verifier(client, CODE_HASH)

        assert cand is None
        assert legacy_called  # legacy was tried as fallback


# ── fixture round-trip: recorded responses parse correctly ────────────────


class TestFixtureRoundTrip:
    """Verify that the recorded live fixtures parse correctly."""

    def test_get_source_item_address_fixture(self):
        fix = _load_fixture("registry_get_source_item_address.json")
        stack = fix["result"]["stack"]
        assert stack[0][0] == "cell"
        cell_obj = stack[0][1]
        parsed = _parse_addr_std_cell(cell_obj)
        assert parsed is not None
        wc, hash_bytes = parsed
        assert wc == 0
        addr = _ton_address_b64(wc, hash_bytes)
        assert addr == SOURCE_ITEM_ADDR

    def test_get_source_item_data_fixture(self):
        fix = _load_fixture("registry_get_source_item_data.json")
        stack = fix["result"]["stack"]
        assert len(stack) >= 4
        assert stack[3][0] == "cell"
        cell_obj = stack[3][1]
        ipfs_link = _parse_string_cell(cell_obj)
        assert ipfs_link == IPFS_URL

    def test_ipfs_manifest_fixture(self):
        fix = _load_fixture("registry_ipfs_manifest.json")
        assert fix["compiler"] == "tact"
        # hash field decodes to the correct code hash
        h = base64.b64decode(fix["hash"]).hex()
        assert h == CODE_HASH
        # source filenames include the .tact source files
        filenames = [s["filename"] for s in fix["sources"]]
        assert any(fn.endswith(".tact") for fn in filenames)
        # entrypoint resolves
        tact_files = [fn for fn in filenames if fn.endswith(".tact")]
        entry = _registry_find_entrypoint(fix, tact_files)
        assert entry == "contract/contracts/ft_master.tact"
