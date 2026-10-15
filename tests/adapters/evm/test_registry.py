"""Unit tests for EVM chain registry (05 section 4.1)."""

from __future__ import annotations

import pytest

from soken_review.adapters.evm.registry import all_chains, enabled_chains, get_chain, reload_registry


@pytest.fixture(autouse=True)
def _reload() -> None:
    reload_registry()


def test_ethereum_present():
    chain = get_chain(1)
    assert chain is not None
    assert chain.name == "Ethereum Mainnet"
    assert chain.family == "evm"
    assert chain.address_format == "evm_checksum"
    assert chain.native_symbol == "ETH"
    assert chain.sourcify_supported is True


def test_base_present():
    chain = get_chain(8453)
    assert chain is not None
    assert chain.chain_id == 8453
    assert chain.family == "evm"


def test_hyperevm_present():
    chain = get_chain(999)
    assert chain is not None
    assert chain.family == "hyperevm"
    assert chain.chain_id == 999
    assert "CLZ" in chain.inactive_opcodes


def test_all_target_chains_present():
    """All 7 planned chains must be in registry (05 4.1)."""
    expected = {1, 8453, 42161, 10, 56, 137, 999}
    found = {c.chain_id for c in all_chains()}
    assert expected.issubset(found)


def test_enabled_chains_returns_enabled_only():
    chains = enabled_chains()
    assert all(c.enabled for c in chains)
    assert len(chains) >= 7  # our 7 chains are all enabled


def test_unknown_chain_returns_none():
    assert get_chain(999999) is None


def test_rpc_entries_have_required_fields():
    chain = get_chain(1)
    assert chain is not None
    assert len(chain.rpc) >= 1
    rpc = chain.rpc[0]
    assert rpc.url.startswith("https://")
    assert isinstance(rpc.log_window, int)
    assert isinstance(rpc.archive, bool)
    assert rpc.source_url
    assert rpc.checked_at


def test_evm_chains_have_evm_checksum_format():
    for cid in (1, 8453, 42161, 10, 56, 137):
        chain = get_chain(cid)
        assert chain is not None
        assert chain.address_format == "evm_checksum"


def test_selfdestruct_semantics_recorded():
    eth = get_chain(1)
    assert eth is not None
    assert eth.selfdestruct_semantics == "eip6780"

    bnb = get_chain(56)
    assert bnb is not None
    assert bnb.selfdestruct_semantics == "legacy"
