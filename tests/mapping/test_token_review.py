"""Unit tests for the retail-token profile classifier (semantic_evm.detect_token_review).

The profile (04 §7.4 token_review) must fire only for a contract that DECLARES the ERC-20 external
surface AND has an owner-gated supply/transfer control, must follow inheritance (the common case:
an OpenZeppelin token inherits transfer/approve/... from base ERC20 and declares only mint), and
must stay off an immutable token or a protocol that merely transacts in tokens. These boundaries
drive the owner-is-threat severity escalation in the client-facing report, so they are pinned here.
"""

from __future__ import annotations

from soken_review.mapping.semantic_evm import detect_token_review


def _entry(span, *, guards=()):
    return {"span": span, "visibility": "external", "is_entry": True, "guards": list(guards)}


def _erc20_entries(contract="Tok"):
    return [_entry(f"{contract}.transfer(address,uint256)"),
            _entry(f"{contract}.transferFrom(address,address,uint256)"),
            _entry(f"{contract}.approve(address,uint256)"),
            {"span": f"{contract}.balanceOf(address)", "visibility": "public", "is_entry": True, "guards": []},
            {"span": f"{contract}.totalSupply()", "visibility": "public", "is_entry": True, "guards": []}]


def _doc(functions, *, roles=(), unit="Tok", bases=None):
    uid = f"src/{unit}.sol:{unit}"
    return {
        "units": [{"id": uid, "name": unit, "kind": "contract", "file": f"src/{unit}.sol",
                   "start": 1, "end": 99}],
        "functions": list(functions),
        "roles": list(roles),
        "chain_extras": {"evm": {"units": {uid: {"bases": bases or [unit]}}}},
    }


def test_erc20_with_owner_gated_mint_is_token_review():
    doc = _doc(
        [*_erc20_entries(), _entry("Tok.mint(address,uint256)", guards=[{"class": "caller_check", "line": 10}])],
        roles=[{"name": "onlyOwner", "holder_kind": "unknown", "gated_functions": ["Tok.mint(address,uint256)"]}],
    )
    assert detect_token_review(doc) is True


def test_inherited_oz_token_with_owner_mint_is_token_review():
    # The common real shape: MyToken inherits the ERC-20 surface from base ERC20 and declares only
    # mint itself (owner-gated). The surface + mutator must be aggregated across the linearized bases.
    functions = [*_erc20_entries("ERC20"),
                 _entry("MyToken.mint(address,uint256)", guards=[{"class": "caller_check", "line": 7}])]
    doc = _doc(functions,
               roles=[{"name": "Ownable", "holder_kind": "unknown", "gated_functions": ["MyToken.mint(address,uint256)"]}],
               unit="MyToken", bases=["MyToken", "ERC20", "Ownable", "Context"])
    assert detect_token_review(doc) is True


def test_owner_gate_via_role_without_inline_caller_check_still_counts():
    doc = _doc(
        [*_erc20_entries(), _entry("Tok.mint(address,uint256)")],
        roles=[{"name": "MINTER_ROLE", "holder_kind": "unknown", "gated_functions": ["Tok.mint(address,uint256)"]}],
    )
    assert detect_token_review(doc) is True


def test_immutable_erc20_without_supply_control_is_not_token_review():
    # Full ERC-20 surface, but the only owner-gated function is transferOwnership (not a supply or
    # transfer control over holder balances). Nothing to escalate: owner is not the balance threat.
    doc = _doc([*_erc20_entries(),
                _entry("Tok.transferOwnership(address)", guards=[{"class": "caller_check", "line": 5}])])
    assert detect_token_review(doc) is False


def test_protocol_calling_tokens_is_not_token_review():
    # A vault transacts in tokens (and has an owner-gated pause) but does NOT declare the ERC-20
    # external surface, so it is not a retail token.
    doc = _doc(
        [_entry("Vault.deposit(uint256)"), _entry("Vault.withdraw(uint256)"),
         _entry("Vault.pause()", guards=[{"class": "caller_check", "line": 3}])],
        roles=[{"name": "onlyOwner", "holder_kind": "unknown", "gated_functions": ["Vault.pause()"]}],
        unit="Vault",
    )
    assert detect_token_review(doc) is False


def test_unguarded_mint_does_not_qualify():
    # An ERC-20 with a mint that is NOT owner-gated is a different (public-mint) problem, not the
    # owner-is-threat profile; detect_token_review requires the mutator to be privileged.
    doc = _doc([*_erc20_entries(), _entry("Tok.mint(address,uint256)")])
    assert detect_token_review(doc) is False


def test_empty_or_missing_semantic_is_false():
    assert detect_token_review(None) is False
    assert detect_token_review({}) is False
    assert detect_token_review({"units": [], "functions": [], "roles": []}) is False


# ── per-finding profile (2026-10-23): the unit holding the location decides ──────────────

def _masterchef_semantic() -> dict:
    import gzip
    from pathlib import Path

    from soken_review.mapping.build import build_map
    from soken_review.mapping.step import family_categories

    fix = Path(__file__).resolve().parents[1] / "fixtures" / "map" / "masterchef_crlf"
    crlf = (fix / "MasterChef.crlf.sol").read_bytes().decode("utf-8")
    with gzip.open(fix / "solc_output.sources.json.gz", "rt", encoding="utf-8") as fh:
        out = __import__("json").load(fh)
    return build_map({"MasterChef.sol": crlf.replace("\r\n", "\n")}, out, list(family_categories("evm")),
                     compiled_texts={"MasterChef.sol": crlf}).doc["semantic"]


def test_flattened_source_token_profile_is_per_unit():
    """SushiToken (owner mint) sits next to MasterChef in one flattened file: a finding inside
    MasterChef must not get the retail-token profile (K1 owner cap skipped -> Critical migrator)."""
    from soken_review.mapping.semantic_evm import detect_token_review, units_holding

    sem = _masterchef_semantic()
    assert detect_token_review(sem) is True                                   # job-wide legacy verdict
    farm = units_holding(sem, [{"file": "MasterChef.sol", "start": 1497, "end": 1506}])   # migrate()
    token = units_holding(sem, [{"file": "MasterChef.sol", "start": 1300, "end": 1300}])  # SushiToken
    assert farm == {"MasterChef.sol:MasterChef"} and token == {"MasterChef.sol:SushiToken"}
    assert detect_token_review(sem, farm) is False
    assert detect_token_review(sem, token) is True
    assert units_holding(sem, []) is None and units_holding(None, [{"file": "x", "start": 1, "end": 1}]) is None
