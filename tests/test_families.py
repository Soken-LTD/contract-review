"""The family launch switch (soken_review.families)."""

from __future__ import annotations

import pytest

from soken_review import families as F
from soken_review.errors import ReviewError


def test_nothing_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SOKEN_DISABLED_FAMILIES", raising=False)
    assert F.family_disabled(chain="starknet") is None and F.family_disabled(language="cairo") is None
    assert "starknet" in F.enabled_chains()
    F.require_enabled(chain="starknet")


def test_starknet_off_by_chain_and_language(monkeypatch):
    monkeypatch.setenv("SOKEN_DISABLED_FAMILIES", " Starknet , ")
    assert F.family_disabled(chain="starknet") == "starknet"
    assert F.family_disabled(language="cairo") == "starknet"
    assert F.family_disabled(chain="sui") is None and F.family_disabled(language="move_aptos") is None
    assert F.family_disabled(chain="evm") is None and F.family_disabled(language="solidity") is None
    assert F.enabled_chains() == ["aptos", "evm", "hyperevm", "solana", "sui", "ton", "tron"]
    with pytest.raises(ReviewError) as e:
        F.require_enabled(language="cairo")
    assert e.value.code == "E_CHAIN_DISABLED"


def test_sui_off_by_chain_keeps_aptos(monkeypatch):
    monkeypatch.setenv("SOKEN_DISABLED_FAMILIES", "starknet,sui")
    assert F.family_disabled(chain="sui") == "sui" and F.family_disabled(language="move_sui") == "sui"
    assert F.family_disabled(chain="aptos") is None and F.family_disabled(language="move_aptos") is None
    assert F.family_disabled(chain="starknet") == "starknet"
    assert F.enabled_chains() == ["aptos", "evm", "hyperevm", "solana", "ton", "tron"]
    with pytest.raises(ReviewError) as e:
        F.require_enabled(chain="sui")
    assert e.value.code == "E_CHAIN_DISABLED"


def test_every_contract_chain_and_language_has_a_family():
    from soken_review.contract import bundle_tools, load_release

    doc = bundle_tools(load_release())

    def enums(node, key, out):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == key and isinstance(v, dict) and "enum" in v:
                    out.update(v["enum"])
                enums(v, key, out)
        elif isinstance(node, list):
            for v in node:
                enums(v, key, out)
        return out

    chains, langs = enums(doc, "chain", set()), enums(doc, "language", set())
    assert {"starknet", "sui", "ton"} <= chains and "cairo" in langs
    assert chains <= set(F.FAMILY_OF_CHAIN) and langs <= set(F.FAMILY_OF_LANGUAGE)
