"""Unit tests for the retail-token profile classifier (semantic_evm.detect_token_review).

The profile (04 §7.4 token_review) must fire only for a contract that DECLARES the ERC-20 external
surface AND has an owner-gated supply/transfer control, and must stay off for an immutable token or
a protocol that merely transacts in tokens. These boundaries drive the owner-is-threat severity
escalation in the client-facing report, so they are pinned here.
"""

from __future__ import annotations

from soken_review.mapping.semantic_evm import detect_token_review

_ERC20_ENTRIES = [
    {"span": "Tok.transfer(address,uint256)", "visibility": "external", "is_entry": True, "guards": []},
    {"span": "Tok.transferFrom(address,address,uint256)", "visibility": "external", "is_entry": True, "guards": []},
    {"span": "Tok.approve(address,uint256)", "visibility": "external", "is_entry": True, "guards": []},
    {"span": "Tok.balanceOf(address)", "visibility": "public", "is_entry": True, "guards": []},
    {"span": "Tok.totalSupply()", "visibility": "public", "is_entry": True, "guards": []},
]


def test_erc20_with_owner_gated_mint_is_token_review():
    semantic = {
        "roles": [{"name": "onlyOwner", "holder_kind": "unknown",
                   "gated_functions": ["Tok.mint(address,uint256)"]}],
        "functions": [
            *_ERC20_ENTRIES,
            {"span": "Tok.mint(address,uint256)", "visibility": "external", "is_entry": True,
             "guards": [{"class": "caller_check", "line": 10}]},
        ],
    }
    assert detect_token_review(semantic) is True


def test_owner_gate_via_role_without_inline_caller_check_still_counts():
    # The mint has no inline caller_check guard, but a role lists it as gated -> owner-controlled.
    semantic = {
        "roles": [{"name": "MINTER_ROLE", "holder_kind": "unknown",
                   "gated_functions": ["Tok.mint(address,uint256)"]}],
        "functions": [
            *_ERC20_ENTRIES,
            {"span": "Tok.mint(address,uint256)", "visibility": "external", "is_entry": True, "guards": []},
        ],
    }
    assert detect_token_review(semantic) is True


def test_immutable_erc20_without_supply_control_is_not_token_review():
    # Full ERC-20 surface, but the only owner-gated function is transferOwnership (not a supply or
    # transfer control over holder balances). Nothing to escalate: owner is not the balance threat.
    semantic = {
        "roles": [],
        "functions": [
            *_ERC20_ENTRIES,
            {"span": "Tok.transferOwnership(address)", "visibility": "external", "is_entry": True,
             "guards": [{"class": "caller_check", "line": 5}]},
        ],
    }
    assert detect_token_review(semantic) is False


def test_protocol_calling_tokens_is_not_token_review():
    # A vault transacts in tokens (and has an owner-gated pause) but does NOT declare the ERC-20
    # external surface, so it is not a retail token.
    semantic = {
        "roles": [{"name": "onlyOwner", "holder_kind": "unknown", "gated_functions": ["Vault.pause()"]}],
        "functions": [
            {"span": "Vault.deposit(uint256)", "visibility": "external", "is_entry": True, "guards": []},
            {"span": "Vault.withdraw(uint256)", "visibility": "external", "is_entry": True, "guards": []},
            {"span": "Vault.pause()", "visibility": "external", "is_entry": True,
             "guards": [{"class": "caller_check", "line": 3}]},
        ],
    }
    assert detect_token_review(semantic) is False


def test_unguarded_mint_does_not_qualify():
    # An ERC-20 with a mint that is NOT owner-gated is a different (public-mint) problem, not the
    # owner-is-threat profile; detect_token_review requires the mutator to be privileged.
    semantic = {
        "roles": [],
        "functions": [
            *_ERC20_ENTRIES,
            {"span": "Tok.mint(address,uint256)", "visibility": "external", "is_entry": True, "guards": []},
        ],
    }
    assert detect_token_review(semantic) is False


def test_empty_or_missing_semantic_is_false():
    assert detect_token_review(None) is False
    assert detect_token_review({}) is False
    assert detect_token_review({"functions": [], "roles": []}) is False
