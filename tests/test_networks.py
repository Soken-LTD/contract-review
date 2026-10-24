"""Tests for soken_review.networks: is_mainnet, publication_outcome, auto_publish_enabled,
and the invariant that every RPC-backed chain ID in chains.json is classified.

No DB required — all unit tests.
"""

from __future__ import annotations

from soken_review.networks import (
    _EVM_MAINNET_CHAIN_IDS,
    _SOLANA_NON_MAINNET,
    auto_publish_enabled,
    is_mainnet,
    publication_outcome,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _job(**kwargs):
    """Build a minimal job dict for is_mainnet / publication_outcome tests."""
    defaults: dict = {
        "source_kind": "deployed",
        "has_deployment": True,
        "chain": "evm",
        "chain_id": 8453,
        "source_args": {},
        "context_items": [],
        "ownership_proven": False,
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# auto_publish_enabled
# ---------------------------------------------------------------------------


class TestAutoPublishEnabled:
    def test_default_on(self, monkeypatch):
        monkeypatch.delenv("SOKEN_AUTOPUBLISH", raising=False)
        assert auto_publish_enabled() is True

    def test_explicit_on(self, monkeypatch):
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "on")
        assert auto_publish_enabled() is True

    def test_off_lowercase(self, monkeypatch):
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "off")
        assert auto_publish_enabled() is False

    def test_off_uppercase(self, monkeypatch):
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "OFF")
        assert auto_publish_enabled() is False

    def test_zero(self, monkeypatch):
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "0")
        assert auto_publish_enabled() is False

    def test_false(self, monkeypatch):
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "false")
        assert auto_publish_enabled() is False

    def test_false_titlecase(self, monkeypatch):
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "False")
        assert auto_publish_enabled() is False

    def test_whitespace_trimmed(self, monkeypatch):
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "  off  ")
        assert auto_publish_enabled() is False


# ---------------------------------------------------------------------------
# is_mainnet — EVM family
# ---------------------------------------------------------------------------


class TestIsMainnetEvm:
    def test_base_mainnet(self):
        assert is_mainnet(_job(chain="evm", chain_id=8453)) is True

    def test_ethereum_mainnet(self):
        assert is_mainnet(_job(chain="evm", chain_id=1)) is True

    def test_arbitrum_mainnet(self):
        assert is_mainnet(_job(chain="evm", chain_id=42161)) is True

    def test_op_mainnet(self):
        assert is_mainnet(_job(chain="evm", chain_id=10)) is True

    def test_bsc_mainnet(self):
        assert is_mainnet(_job(chain="evm", chain_id=56)) is True

    def test_polygon_mainnet(self):
        assert is_mainnet(_job(chain="evm", chain_id=137)) is True

    def test_unknown_chain_id(self):
        assert is_mainnet(_job(chain="evm", chain_id=11155111)) is False  # Sepolia

    def test_no_chain_id(self):
        assert is_mainnet(_job(chain="evm", chain_id=None)) is False

    def test_hyperevm_mainnet(self):
        assert is_mainnet(_job(chain="hyperevm", chain_id=999)) is True

    def test_tron_mainnet(self):
        assert is_mainnet(_job(chain="tron", chain_id=728126428)) is True

    def test_tron_unknown_chain_id(self):
        # chain_id=99999 is not in _EVM_MAINNET_CHAIN_IDS (the allowlist is flat across families)
        assert is_mainnet(_job(chain="tron", chain_id=99999)) is False


# ---------------------------------------------------------------------------
# is_mainnet — Solana
# ---------------------------------------------------------------------------


class TestIsMainnetSolana:
    def test_no_cluster_defaults_mainnet(self):
        assert is_mainnet(_job(chain="solana", chain_id=None, source_args={})) is True

    def test_mainnet_beta(self):
        assert is_mainnet(_job(chain="solana", chain_id=None, source_args={"cluster": "mainnet-beta"})) is True

    def test_devnet_private(self):
        assert is_mainnet(_job(chain="solana", chain_id=None, source_args={"cluster": "devnet"})) is False

    def test_testnet_private(self):
        assert is_mainnet(_job(chain="solana", chain_id=None, source_args={"cluster": "testnet"})) is False

    def test_localnet_private(self):
        assert is_mainnet(_job(chain="solana", chain_id=None, source_args={"cluster": "localnet"})) is False

    def test_source_args_as_json_string(self):
        """source_args may be a JSON string when read from DB without row_factory."""
        import json
        sa = json.dumps({"cluster": "devnet"})
        assert is_mainnet(_job(chain="solana", chain_id=None, source_args=sa)) is False

    def test_source_args_none(self):
        assert is_mainnet(_job(chain="solana", chain_id=None, source_args=None)) is True


# ---------------------------------------------------------------------------
# is_mainnet — chains that only support mainnet
# ---------------------------------------------------------------------------


class TestIsMainnetAlwaysMainnet:
    def test_ton(self):
        assert is_mainnet(_job(chain="ton", chain_id=None)) is True

    def test_aptos(self):
        assert is_mainnet(_job(chain="aptos", chain_id=None)) is True

    def test_sui(self):
        assert is_mainnet(_job(chain="sui", chain_id=None)) is True

    def test_starknet(self):
        assert is_mainnet(_job(chain="starknet", chain_id=None)) is True


# ---------------------------------------------------------------------------
# is_mainnet — edge cases
# ---------------------------------------------------------------------------


class TestIsMainnetEdgeCases:
    def test_no_chain(self):
        assert is_mainnet({}) is False

    def test_none_chain(self):
        assert is_mainnet({"chain": None}) is False

    def test_unknown_chain_family(self):
        assert is_mainnet(_job(chain="cosmos", chain_id=1)) is False


# ---------------------------------------------------------------------------
# publication_outcome — the six required test cases (CEO 2026-10-24)
# ---------------------------------------------------------------------------


class TestPublicationOutcome:
    def test_deployed_mainnet_base_automatic(self):
        """deployed mainnet (Base 8453) → automatic."""
        job = _job(source_kind="deployed", has_deployment=True, chain="evm", chain_id=8453)
        out = publication_outcome(job)
        assert out["outcome"] == "automatic"
        assert out["reason"]

    def test_repo_without_deployment_private(self):
        """repo without deployment → private."""
        job = _job(source_kind="repo", has_deployment=False, chain=None, chain_id=None)
        out = publication_outcome(job)
        assert out["outcome"] == "private"
        assert "deployment" in out["reason"]

    def test_repo_with_mainnet_deployment_automatic(self):
        """repo + mainnet deployment → automatic."""
        job = _job(source_kind="repo", has_deployment=True, chain="evm", chain_id=8453)
        out = publication_outcome(job)
        assert out["outcome"] == "automatic"

    def test_solana_devnet_private(self):
        """Solana devnet → private."""
        job = _job(source_kind="deployed", has_deployment=True, chain="solana", chain_id=None,
                   source_args={"cluster": "devnet"})
        out = publication_outcome(job)
        assert out["outcome"] == "private"
        assert "mainnet" in out["reason"]

    def test_files_with_deployment_private(self):
        """files source kind → private regardless of deployment."""
        job = _job(source_kind="files", has_deployment=True, chain="evm", chain_id=8453)
        out = publication_outcome(job)
        assert out["outcome"] == "private"

    def test_unknown_network_private(self):
        """unknown/testnet chain ID → private."""
        job = _job(source_kind="deployed", has_deployment=True, chain="evm", chain_id=99999)
        out = publication_outcome(job)
        assert out["outcome"] == "private"
        assert "mainnet" in out["reason"]


# ---------------------------------------------------------------------------
# publication_outcome — additional cases
# ---------------------------------------------------------------------------


class TestPublicationOutcomeExtended:
    def test_upload_source_kind_private(self):
        job = _job(source_kind="upload", has_deployment=True, chain="evm", chain_id=8453)
        out = publication_outcome(job)
        assert out["outcome"] == "private"

    def test_owner_profile_private(self):
        job = _job(source_kind="deployed", has_deployment=True, chain="evm", chain_id=8453)
        out = publication_outcome(job, profile="owner")
        assert out["outcome"] == "private"
        assert "owner" in out["reason"]

    def test_inline_context_item_private(self):
        """A pasted context item (url=None) makes the report private."""
        job = _job(source_kind="deployed", has_deployment=True, chain="evm", chain_id=8453,
                   context_items=[{"url": None, "kind": "text"}])
        out = publication_outcome(job)
        assert out["outcome"] == "private"
        assert "document" in out["reason"]

    def test_url_context_item_does_not_block(self):
        """A URL-based context item (url present) does not block auto-publication."""
        job = _job(source_kind="deployed", has_deployment=True, chain="evm", chain_id=8453,
                   context_items=[{"url": "https://docs.example.com", "kind": "website"}])
        out = publication_outcome(job)
        assert out["outcome"] == "automatic"

    def test_autopublish_off_returns_private(self, monkeypatch):
        """SOKEN_AUTOPUBLISH=off → private regardless of network."""
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "off")
        job = _job(source_kind="deployed", has_deployment=True, chain="evm", chain_id=8453)
        out = publication_outcome(job)
        assert out["outcome"] == "private"
        assert "paused" in out["reason"]

    def test_autopublish_on_mainnet_automatic(self, monkeypatch):
        """SOKEN_AUTOPUBLISH=on (explicit) + mainnet → automatic."""
        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "on")
        job = _job(source_kind="deployed", has_deployment=True, chain="evm", chain_id=8453)
        out = publication_outcome(job)
        assert out["outcome"] == "automatic"


# ---------------------------------------------------------------------------
# Invariant: every RPC-backed chain ID in chains.json must be classified
# ---------------------------------------------------------------------------


def test_every_rpc_backed_chain_classified():
    """Every enabled, RPC-backed chain ID in chains.json must be in _EVM_MAINNET_CHAIN_IDS.

    Fails CI whenever chains.json gains a new mainnet entry that was not added to the
    explicit allowlist, preventing silent 'not mainnet' classification for live chains.
    """
    from soken_review.adapters.evm.registry import all_chains, reload_registry

    reload_registry()
    unclassified = []
    for chain in all_chains():
        if chain.family not in ("evm", "hyperevm", "tron"):
            continue
        has_live_rpc = any(not r.disabled for r in chain.rpc)
        if has_live_rpc and chain.chain_id not in _EVM_MAINNET_CHAIN_IDS:
            unclassified.append(f"{chain.name} (id={chain.chain_id}, family={chain.family})")
    assert not unclassified, (
        "The following RPC-backed chains are not in _EVM_MAINNET_CHAIN_IDS in networks.py:\n"
        + "\n".join(f"  - {c}" for c in unclassified)
    )


# ---------------------------------------------------------------------------
# Invariant: _SOLANA_NON_MAINNET covers the known non-mainnet cluster names
# ---------------------------------------------------------------------------


def test_solana_non_mainnet_set():
    assert "devnet" in _SOLANA_NON_MAINNET
    assert "testnet" in _SOLANA_NON_MAINNET
    assert "localnet" in _SOLANA_NON_MAINNET
    assert "mainnet-beta" not in _SOLANA_NON_MAINNET
