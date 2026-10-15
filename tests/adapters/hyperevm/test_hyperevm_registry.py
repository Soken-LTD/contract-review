"""Tests for HyperEVM chain 999 registry entry (plan-v4 05 section 4.1).

Verifies: chain_id, family, inactive_opcodes, Sourcify support, and RPC.
"""

from __future__ import annotations

from soken_review.adapters.evm.registry import get_chain, reload_registry


def setup_function():
    reload_registry()


def test_hyperevm_chain_present():
    chain = get_chain(999)
    assert chain is not None, "chain 999 (HyperEVM) must be in registry"


def test_hyperevm_family():
    chain = get_chain(999)
    assert chain.family == "hyperevm"


def test_hyperevm_clz_inactive():
    """CLZ must be in inactive_opcodes: measured via eth_call state-override 2026-10-07 (F18)."""
    chain = get_chain(999)
    assert "CLZ" in chain.inactive_opcodes, "CLZ must be listed as inactive on HyperEVM (F18)"


def test_hyperevm_sourcify_supported():
    """Sourcify must support chain 999 (F9)."""
    chain = get_chain(999)
    assert chain.sourcify_supported is True, "Sourcify must support HyperEVM chain 999 (F9)"


def test_hyperevm_has_rpc():
    """Chain 999 must have at least one RPC endpoint (F13: rpc.hyperliquid.xyz/evm)."""
    chain = get_chain(999)
    assert len(chain.rpc) >= 1
    urls = [r.url for r in chain.rpc]
    assert any("hyperliquid" in u for u in urls), "Expected hyperliquid.xyz RPC for chain 999 (F13)"


def test_hyperevm_address_format():
    chain = get_chain(999)
    assert chain.address_format == "evm_checksum"


def test_hyperevm_native_symbol():
    chain = get_chain(999)
    assert chain.native_symbol == "HYPE"


def test_hyperevm_enabled():
    chain = get_chain(999)
    assert chain.enabled is True, "chain 999 must be enabled in the registry"
