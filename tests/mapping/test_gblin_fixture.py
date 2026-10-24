"""Regression tests for the three GBLIN-discovered bugs (fix/related-state-real-data).

All tests run fully offline using fixtures recorded from Base mainnet at block 53027085:
  - tests/fixtures/evm/gblin_abi.json      — verified GBLIN ABI (106 items, src/GBLIN.sol)
  - tests/fixtures/evm/gblin_eth_calls.json — recorded eth_call responses

Bug 1: related_contracts missed ABI-provided zero-arg address-returning getters (WETH).
Bug 2: state_parameter_facts decoded int256/bytes32/low-entropy-address as uint.
Bug 3: suggested_context_items included GitHub URLs from lib/ dependency files.

No network requests are made; all eth_call responses are replayed from the fixture.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "evm"
_ABI_PATH = _FIXTURES / "gblin_abi.json"
_CALLS_PATH = _FIXTURES / "gblin_eth_calls.json"

GBLIN_ADDRESS = "0xc2181d975c05c8c724b334bcED0764c0b86B1D53"
GBLIN_BLOCK = 53027085


@pytest.fixture(scope="module")
def gblin_abi() -> list[dict]:
    return json.loads(_ABI_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def gblin_calls() -> dict:
    return json.loads(_CALLS_PATH.read_text(encoding="utf-8"))


def _make_rpc(calls_fixture: dict) -> AsyncMock:
    """Return an AsyncMock RPC whose eth_call_probe replays the recorded fixture values.

    Matches calls by the first 10 chars (0x + 8-hex selector).  Calls whose selector
    is not in the fixture return None (simulating a revert), which is the correct
    fallback for internal-state getters such as fillAgent/sequencerFeed.
    """
    selector_map: dict[str, str] = {}
    for entry in calls_fixture["calls"].values():
        sel = entry["selector"][:10].lower()
        selector_map[sel] = entry["raw"]

    async def eth_call_probe(address, data, block=None, **_limits):
        sel = (data or "")[:10].lower()
        raw = selector_map.get(sel)
        if raw is None:
            return None
        # Simulate the capped-probe semantics: must be 0x + >= 64 hex chars
        if not raw.startswith("0x") or len(raw) - 2 < 64:
            return None
        return raw

    rpc = AsyncMock(spec=["get_code", "eth_call_probe"])
    # get_code: GBLIN itself is a real contract; owner is an EOA
    async def get_code(address, block=None):
        # owner address from fixture → EOA
        if address.lower() == "0x6abec8716ffeecf7c3d6e68255b4797113e8e5dd":
            return "0x"
        # WETH on Base is a contract
        if address.lower() == "0x4200000000000000000000000000000000000006":
            return "0x6080604052"
        return "0x"

    rpc.get_code = AsyncMock(side_effect=get_code)
    rpc.eth_call_probe = eth_call_probe
    return rpc


# ---------------------------------------------------------------------------
# Bug 1: related_contracts must include WETH() from ABI
# ---------------------------------------------------------------------------

class TestRelatedContractsBug1:
    """WETH() is a zero-arg view function returning address.  It was missing from
    related_contracts before this fix because it is not in HOLDER_GETTERS and
    the old code only probed HOLDER_GETTERS on the target contract."""

    @pytest.mark.asyncio
    async def test_weth_appears_in_related_contracts(self, gblin_abi, gblin_calls):
        from soken_review.mapping.related import classify_related_contracts

        rpc = _make_rpc(gblin_calls)
        # onchain_facts already supply owner; the ABI probe should surface WETH
        onchain_facts = [
            {"key": "onchain.owner",
             "value": "0x6abec8716ffeecf7c3d6e68255b4797113e8e5dd"},
        ]
        results = await classify_related_contracts(
            rpc,
            GBLIN_BLOCK,
            onchain_facts,
            abi_list=gblin_abi,
            target_address=GBLIN_ADDRESS,
        )
        addresses = {r["address"].lower() for r in results}
        assert "0x4200000000000000000000000000000000000006" in addresses, (
            f"WETH address missing from related_contracts: {results}"
        )

    @pytest.mark.asyncio
    async def test_weth_role_label_is_getter_name(self, gblin_abi, gblin_calls):
        from soken_review.mapping.related import classify_related_contracts

        rpc = _make_rpc(gblin_calls)
        onchain_facts = [
            {"key": "onchain.owner",
             "value": "0x6abec8716ffeecf7c3d6e68255b4797113e8e5dd"},
        ]
        results = await classify_related_contracts(
            rpc,
            GBLIN_BLOCK,
            onchain_facts,
            abi_list=gblin_abi,
            target_address=GBLIN_ADDRESS,
        )
        weth_entry = next(
            (r for r in results
             if r["address"].lower() == "0x4200000000000000000000000000000000000006"),
            None,
        )
        assert weth_entry is not None
        # Role must be the getter name (never None or empty)
        assert weth_entry["role"] == "WETH", (
            f"Expected role='WETH', got role={weth_entry['role']!r}"
        )

    @pytest.mark.asyncio
    async def test_owner_still_present(self, gblin_abi, gblin_calls):
        """The pre-existing owner from onchain_facts must survive alongside WETH."""
        from soken_review.mapping.related import classify_related_contracts

        rpc = _make_rpc(gblin_calls)
        onchain_facts = [
            {"key": "onchain.owner",
             "value": "0x6abec8716ffeecf7c3d6e68255b4797113e8e5dd"},
        ]
        results = await classify_related_contracts(
            rpc,
            GBLIN_BLOCK,
            onchain_facts,
            abi_list=gblin_abi,
            target_address=GBLIN_ADDRESS,
        )
        roles = {r["role"] for r in results}
        assert "owner" in roles, f"owner missing: {roles}"
        assert len(results) >= 2, f"Expected owner + WETH at minimum, got {results}"


# ---------------------------------------------------------------------------
# Bug 2: state_parameter_facts must decode types correctly
# ---------------------------------------------------------------------------

class TestStateFactsTypeBug2:
    """Before the fix, three type-specific bugs caused wrong values:
    - auctionPremiumBps (int256, -100): decoded as a huge positive uint.
    - DOMAIN_SEPARATOR (bytes32): decoded as a huge uint.
    - WETH (address, low-entropy 0x4200...0006): failed entropy check → absent.
    """

    @pytest.mark.asyncio
    async def test_auction_premium_bps_is_negative_int(self, gblin_abi, gblin_calls):
        """auctionPremiumBps() returns int256 = -100; must not appear as a large uint."""
        from soken_review.mapping.related import state_parameter_facts

        rpc = _make_rpc(gblin_calls)
        facts = await state_parameter_facts(
            rpc, GBLIN_ADDRESS, GBLIN_BLOCK, None, None,
            abi_list=gblin_abi,
        )
        f = next((x for x in facts if x["key"] == "state.auction_premium_bps"), None)
        assert f is not None, f"state.auction_premium_bps missing; facts={[x['key'] for x in facts]}"
        assert f["value"] == "-100", (
            f"Expected '-100' (int256 two's complement), got {f['value']!r}. "
            f"If this is a huge positive number the int256 sign bit was ignored."
        )
        # The ABI type must be recorded so downstream consumers know it's signed
        assert f.get("type") == "int256", f"Expected type='int256', got {f.get('type')!r}"

    @pytest.mark.asyncio
    async def test_domain_separator_is_hex_not_uint(self, gblin_abi, gblin_calls):
        """DOMAIN_SEPARATOR() returns bytes32; must be stored as 0x<hex>, not as a decimal uint."""
        from soken_review.mapping.related import state_parameter_facts

        rpc = _make_rpc(gblin_calls)
        facts = await state_parameter_facts(
            rpc, GBLIN_ADDRESS, GBLIN_BLOCK, None, None,
            abi_list=gblin_abi,
        )
        f = next((x for x in facts if x["key"] == "state.domain_separator"), None)
        assert f is not None, (
            f"state.domain_separator missing; facts={[x['key'] for x in facts]}"
        )
        assert f["value"].startswith("0x"), (
            f"Expected 0x-prefixed hex for bytes32, got {f['value']!r}. "
            f"If this is a large decimal the bytes32 type was misidentified as uint."
        )
        assert f["value"] == "0x07f5b29d4ae7d4529ef4b1185b7e4afbbc4b525aa29f56522cacf3aa9916a2d3", (
            f"Unexpected DOMAIN_SEPARATOR value: {f['value']!r}"
        )
        assert f.get("type") == "bytes32"

    @pytest.mark.asyncio
    async def test_weth_address_decoded_despite_low_entropy(self, gblin_abi, gblin_calls):
        """WETH on Base (0x4200...0006) has only 2 non-zero bytes.

        Before the fix, the heuristic entropy check (nonzero_count >= 4) caused this
        address to be silently dropped.  With ABI-type-aware decoding the entropy check
        is bypassed entirely for type='address'.
        """
        from soken_review.mapping.related import state_parameter_facts

        rpc = _make_rpc(gblin_calls)
        facts = await state_parameter_facts(
            rpc, GBLIN_ADDRESS, GBLIN_BLOCK, None, None,
            abi_list=gblin_abi,
        )
        f = next((x for x in facts if x["key"] == "state.weth"), None)
        assert f is not None, (
            f"state.weth missing; facts={[x['key'] for x in facts]}. "
            f"Low-entropy address 0x4200...0006 was dropped by entropy check."
        )
        assert f["value"] == "0x4200000000000000000000000000000000000006", (
            f"Unexpected WETH value: {f['value']!r}"
        )
        assert f.get("type") == "address"

    @pytest.mark.asyncio
    async def test_is_nav_reliable_is_bool(self, gblin_abi, gblin_calls):
        """isNavReliable() returns bool = true; must be stored as 'true'."""
        from soken_review.mapping.related import state_parameter_facts

        rpc = _make_rpc(gblin_calls)
        facts = await state_parameter_facts(
            rpc, GBLIN_ADDRESS, GBLIN_BLOCK, None, None,
            abi_list=gblin_abi,
        )
        f = next((x for x in facts if x["key"] == "state.is_nav_reliable"), None)
        assert f is not None, f"state.is_nav_reliable missing; facts={[x['key'] for x in facts]}"
        assert f["value"] == "true", f"Expected 'true', got {f['value']!r}"
        assert f.get("type") == "bool"

    @pytest.mark.asyncio
    async def test_current_drift_eth_is_uint(self, gblin_abi, gblin_calls):
        """currentDriftEth() returns uint256; must be a non-zero decimal string."""
        from soken_review.mapping.related import state_parameter_facts

        rpc = _make_rpc(gblin_calls)
        facts = await state_parameter_facts(
            rpc, GBLIN_ADDRESS, GBLIN_BLOCK, None, None,
            abi_list=gblin_abi,
        )
        f = next((x for x in facts if x["key"] == "state.current_drift_eth"), None)
        assert f is not None, (
            f"state.current_drift_eth missing; facts={[x['key'] for x in facts]}"
        )
        # Must be a plain decimal integer string, not 0x-prefixed
        assert not f["value"].startswith("0x"), (
            f"uint256 must not be 0x-prefixed: {f['value']!r}"
        )
        assert int(f["value"]) > 0
        assert f.get("type") == "uint256"

    @pytest.mark.asyncio
    async def test_already_read_getters_not_in_state_facts(self, gblin_abi, gblin_calls):
        """owner/pendingOwner/decimals/totalSupply must never appear as state.* facts."""
        from soken_review.mapping.related import state_parameter_facts

        rpc = _make_rpc(gblin_calls)
        facts = await state_parameter_facts(
            rpc, GBLIN_ADDRESS, GBLIN_BLOCK, None, None,
            abi_list=gblin_abi,
        )
        forbidden_keys = {"state.owner", "state.pending_owner", "state.decimals",
                          "state.total_supply", "state.name", "state.symbol"}
        found = {f["key"] for f in facts} & forbidden_keys
        assert not found, (
            f"already-read getters must not appear in state facts: {found}"
        )


# ---------------------------------------------------------------------------
# Bug 3: suggested_context_items must not include library dependency URLs
# ---------------------------------------------------------------------------

class TestSuggestedContextBug3:
    """Before the fix, GitHub URLs from lib/solady, lib/openzeppelin-contracts etc.
    polluted the suggested_context_items list even though they are standard library
    dependencies, not project URLs.

    Post-fix rules:
    1. Files under lib/, node_modules/, etc. are skipped entirely.
    2. Well-known library GitHub repos are filtered even if found in project files.
    """

    def test_lib_dependency_files_produce_no_suggestions(self):
        """Simulate GBLIN pinned files: lib/* with well-known GitHub URLs → empty list."""
        from soken_review.mapping.project_url import discover_project_urls

        # Reproduce the exact GitHub URLs found in GBLIN lib/ files
        lib_files = {
            "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol": (
                "// SPDX-License-Identifier: MIT\n"
                "// Based on https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md\n"
                "interface IERC20 {}\n"
            ),
            "lib/solady/src/tokens/ERC20.sol": (
                "// Inspired by https://github.com/OpenZeppelin/openzeppelin-contracts\n"
                "// and https://github.com/transmissions11/solmate\n"
                "// and https://github.com/Uniswap/permit2\n"
                "// and https://github.com/vectorized/solady\n"
                "abstract contract ERC20 {}\n"
            ),
            "lib/solady/src/utils/SafeTransferLib.sol": (
                "// https://github.com/Uniswap/permit2\n"
                "// https://github.com/transmissions11/solmate\n"
                "// https://github.com/vectorized/solady\n"
                "library SafeTransferLib {}\n"
            ),
        }
        result = discover_project_urls(lib_files)
        assert result == [], (
            f"lib/ dependency files must produce no suggestions, got: {result}"
        )

    def test_project_src_files_without_urls_produce_no_suggestions(self):
        """GBLIN src/ files contain no NatSpec @custom:website or GitHub project URLs."""
        from soken_review.mapping.project_url import discover_project_urls

        # GBLIN's src/ files have no website annotations
        src_files = {
            "src/GBLIN.sol": (
                "// SPDX-License-Identifier: BUSL-1.1\n"
                "pragma solidity ^0.8.24;\n"
                "contract GBLIN {}\n"
            ),
            "src/interfaces/IGBLIN.sol": (
                "// SPDX-License-Identifier: BUSL-1.1\n"
                "pragma solidity ^0.8.24;\n"
                "interface IGBLIN {}\n"
            ),
        }
        result = discover_project_urls(src_files)
        assert result == [], f"Unexpected suggestions: {result}"

    def test_mixed_lib_and_src_only_src_scanned(self):
        """With both lib/ and src/ files, only src/ is scanned; lib/ URLs must not leak."""
        from soken_review.mapping.project_url import discover_project_urls

        # lib/ has well-known URLs; src/ has a project URL
        files = {
            "lib/solady/src/tokens/ERC20.sol": (
                "// https://github.com/vectorized/solady\n"
            ),
            "src/Vault.sol": (
                "/// @custom:website https://example-gblin-project.xyz\n"
                "contract Vault {}\n"
            ),
        }
        result = discover_project_urls(files)
        urls = [r["url"] for r in result]
        # The lib/ URL must be absent; the project URL must be present
        assert not any("vectorized/solady" in u for u in urls), (
            f"Library URL leaked into suggestions: {urls}"
        )
        assert any("example-gblin-project" in u for u in urls), (
            f"Project URL missing from suggestions: {urls}"
        )

    def test_well_known_library_url_in_src_is_also_filtered(self):
        """Even if a src/ file references a well-known library URL it must be dropped."""
        from soken_review.mapping.project_url import discover_project_urls

        files = {
            "src/GBLIN.sol": (
                "// Inherits from https://github.com/OpenZeppelin/openzeppelin-contracts\n"
                "contract GBLIN {}\n"
            ),
        }
        result = discover_project_urls(files)
        assert result == [], f"Well-known library URL in src/ must be filtered: {result}"


# ---------------------------------------------------------------------------
# _decode_by_abi_type unit tests
# ---------------------------------------------------------------------------

class TestDecodeByAbiType:
    """Unit tests for the new _decode_by_abi_type helper (no mocking needed)."""

    def test_int256_negative(self):
        from soken_review.mapping.related import _decode_by_abi_type

        # -100 in two's complement (256-bit)
        word = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9c"
        assert _decode_by_abi_type(word, "int256") == "-100"

    def test_int256_positive(self):
        from soken_review.mapping.related import _decode_by_abi_type

        word = format(500, "064x")
        assert _decode_by_abi_type(word, "int256") == "500"

    def test_int256_zero_returns_none(self):
        from soken_review.mapping.related import _decode_by_abi_type

        assert _decode_by_abi_type("0" * 64, "int256") is None

    def test_bytes32_returns_0x_hex(self):
        from soken_review.mapping.related import _decode_by_abi_type

        word = "07f5b29d4ae7d4529ef4b1185b7e4afbbc4b525aa29f56522cacf3aa9916a2d3"
        result = _decode_by_abi_type(word, "bytes32")
        assert result == "0x" + word

    def test_bytes32_all_zero_returns_none(self):
        from soken_review.mapping.related import _decode_by_abi_type

        assert _decode_by_abi_type("0" * 64, "bytes32") is None

    def test_address_low_entropy_decoded(self):
        """0x4200...0006 has only 2 non-zero bytes — must decode as address, not be dropped."""
        from soken_review.mapping.related import _decode_by_abi_type

        word = "0000000000000000000000004200000000000000000000000000000000000006"
        result = _decode_by_abi_type(word, "address")
        assert result == "0x4200000000000000000000000000000000000006"

    def test_address_zero_returns_none(self):
        from soken_review.mapping.related import _decode_by_abi_type

        assert _decode_by_abi_type("0" * 64, "address") is None

    def test_address_malformed_returns_none(self):
        """Top 12 bytes non-zero → malformed address encoding."""
        from soken_review.mapping.related import _decode_by_abi_type

        word = "0001000000000000000000004200000000000000000000000000000000000006"
        assert _decode_by_abi_type(word, "address") is None

    def test_bool_true(self):
        from soken_review.mapping.related import _decode_by_abi_type

        assert _decode_by_abi_type("0" * 63 + "1", "bool") == "true"

    def test_bool_false(self):
        from soken_review.mapping.related import _decode_by_abi_type

        assert _decode_by_abi_type("0" * 64, "bool") == "false"

    def test_bool_invalid_returns_none(self):
        from soken_review.mapping.related import _decode_by_abi_type

        assert _decode_by_abi_type("0" * 63 + "2", "bool") is None

    def test_uint256_non_zero(self):
        from soken_review.mapping.related import _decode_by_abi_type

        word = format(12749053741674902, "064x")
        result = _decode_by_abi_type(word, "uint256")
        assert result == "12749053741674902"

    def test_uint256_zero_returns_none(self):
        from soken_review.mapping.related import _decode_by_abi_type

        assert _decode_by_abi_type("0" * 64, "uint256") is None

    def test_uint8(self):
        from soken_review.mapping.related import _decode_by_abi_type

        word = format(18, "064x")
        assert _decode_by_abi_type(word, "uint8") == "18"
