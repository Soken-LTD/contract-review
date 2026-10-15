"""Tests for the HyperEVM adapter (plan-v4 05 sections 2, 10, 12.1).

Tests without requiring Docker or live network access.
"""

from __future__ import annotations

import json
from pathlib import Path


def test_adapter_family_and_chains():
    from soken_review.adapters.hyperevm.adapter import HyperEvmAdapter
    adapter = HyperEvmAdapter()
    assert adapter.family == "hyperevm"
    assert "hyperevm" in adapter.chains


def test_adapter_checklists():
    from soken_review.adapters.hyperevm.adapter import HyperEvmAdapter
    adapter = HyperEvmAdapter()
    items = adapter.checklists("solidity")
    assert "evm.hyperevm.corewriter" in items
    assert "evm.hyperevm.precompile" in items
    assert "evm.hyperevm.bridge_decimals" in items
    assert "evm.hyperevm.linking" in items


def test_rule_map_hl_loads():
    """HL rule_map extension file must be valid JSON and contain HL-* entries."""
    rmap_path = Path(__file__).parents[3] / "src" / "soken_review" / "adapters" / "hyperevm" / "data" / "rule_map_hl.json"
    assert rmap_path.exists()
    data = json.loads(rmap_path.read_text())
    slither_map = data.get("slither", {})
    for rule_id in ("hl-cw-01", "hl-cw-04", "hl-pc-01", "hl-pc-02", "hl-br-01", "hl-lk-02"):
        assert rule_id in slither_map, f"{rule_id} missing from HL rule_map"


def test_rule_map_hl_categories():
    """HL rule_map categories must match enums.yaml IDs."""
    rmap_path = Path(__file__).parents[3] / "src" / "soken_review" / "adapters" / "hyperevm" / "data" / "rule_map_hl.json"
    data = json.loads(rmap_path.read_text())
    slither_map = data.get("slither", {})
    expected = {
        "hl-cw-01": "evm.hyperevm.corewriter",
        "hl-cw-04": "evm.hyperevm.corewriter",
        "hl-pc-01": "evm.hyperevm.precompile",
        "hl-pc-02": "evm.hyperevm.precompile",
        "hl-br-01": "evm.hyperevm.bridge_decimals",
        "hl-lk-02": "evm.hyperevm.linking",
    }
    for rule_id, expected_cat in expected.items():
        assert slither_map[rule_id] == expected_cat


def test_upstream_corewriter_has_delay_note():
    """Upstream CoreWriter snapshot must include delay_note (F15)."""
    snap = Path(__file__).parents[3] / "src" / "soken_review" / "adapters" / "hyperevm" / "data" / "upstream" / "hyperevm_corewriter.json"
    data = json.loads(snap.read_text())
    assert "delay_note" in data["values"]
    assert "delayed" in data["values"]["delay_note"]


def test_upstream_precompiles_has_0x810():
    """Upstream precompile snapshot must list coreUserExists at 0x810 (F16)."""
    snap = Path(__file__).parents[3] / "src" / "soken_review" / "adapters" / "hyperevm" / "data" / "upstream" / "hyperevm_precompiles.json"
    data = json.loads(snap.read_text())
    precompiles = data["values"]["precompiles"]
    addr_0x810 = "0x0000000000000000000000000000000000000810"
    assert addr_0x810 in precompiles
    assert "UserExists" in precompiles[addr_0x810]["name"]


def test_upstream_blocks_has_small_block():
    """Upstream block snapshot must document small-block gas limit (F13)."""
    snap = Path(__file__).parents[3] / "src" / "soken_review" / "adapters" / "hyperevm" / "data" / "upstream" / "hyperevm_blocks.json"
    data = json.loads(snap.read_text())
    assert "small_block" in data["values"]
    assert data["values"]["small_block"]["gas_limit"] == 2000000


def test_evm_rule_map_includes_hl_rules():
    """EVM rule_map.json must include HL-* rule IDs added for HyperEVM (05 8.3)."""
    rmap_path = Path(__file__).parents[3] / "src" / "soken_review" / "adapters" / "evm" / "data" / "rule_map.json"
    data = json.loads(rmap_path.read_text())
    slither_map = data.get("slither", {})
    for rule_id in ("hl-cw-01", "hl-cw-04", "hl-pc-01", "hl-pc-02", "hl-br-01", "hl-lk-02"):
        assert rule_id in slither_map, f"{rule_id} missing from EVM rule_map (needed for HyperEVM analyze)"


def test_adapter_precompile_read_plan():
    """Adapter should emit a precompile_read entry for coreTokenInfo (0x80c) in read_plan."""
    from soken_review.adapters.hyperevm.adapter import HyperEvmAdapter
    adapter = HyperEvmAdapter()
    entries = adapter._precompile_read_plan_entries()
    assert len(entries) >= 1
    kinds = [e["kind"] for e in entries]
    assert "precompile_read" in kinds


def test_images_lock_has_hyperevm_analyze():
    """images.lock.json must contain a hyperevm-analyze entry (05 8.2)."""
    lock_path = Path(__file__).parents[3] / "images.lock.json"
    data = json.loads(lock_path.read_text())
    assert "hyperevm-analyze" in data["images"], "images.lock.json must have hyperevm-analyze entry"


def test_merged_rule_map_loads_evm_and_hl_rows():
    """Regression: the EVM rule_map path was wrong and the error was only logged."""
    from soken_review.adapters.hyperevm.adapter import _load_merged_rule_map

    slither_rows = _load_merged_rule_map()["slither"]
    assert "reentrancy-eth" in slither_rows and any(k.lower().startswith("hl-") for k in slither_rows)
