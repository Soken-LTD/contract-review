"""Declared vs observed (spec section 6): every claim, every status, pure function."""

from __future__ import annotations

from soken_review.context.compare import STATUSES, compare
from soken_review.context.facts import fact
from soken_review.mapping.facts import fact as plain_fact

ADDR = "0xc2edad668740f1aa35e4d8f227fb8e17dca888cd"
JOB = {"job_id": "job_X", "chain": "evm", "chain_id": 1, "address": ADDR}
WP = "context/whitepaper-1.md"


def _rows(facts, map_doc=None, job=JOB):
    rows = compare(facts, map_doc, job)
    for r in rows:
        assert set(r) == {"claim", "declared", "declared_source", "observed", "observed_source", "status"}
        assert r["status"] in STATUSES
    return {r["claim"]: r for r in rows}


def test_no_declarations_no_rows() -> None:
    assert compare([plain_fact("onchain.total_supply", 10**27, source="eth_call totalSupply() at block 1")], {}, JOB) == []


def test_reviewed_address_referenced() -> None:
    yes = [fact("context.website.mentions_reviewed_address", "true", source="context/website-1.md:9"),
           fact("context.docs.mentions_reviewed_address", "false", source="context/docs-1.md:1")]
    row = _rows(yes)["Reviewed contract referenced by the project documents"]
    assert row["status"] == "matches" and "website" in row["declared"] and row["observed"] == ADDR
    assert row["declared_source"] == "context/website-1.md:9"
    no = [fact("context.docs.mentions_reviewed_address", "false", source="context/docs-1.md:1")]
    row = _rows(no)["Reviewed contract referenced by the project documents"]
    assert row["status"] == "differs" and "docs" in row["declared"]
    row = _rows(no, job={"job_id": "j"})["Reviewed contract referenced by the project documents"]
    assert row["status"] == "not_checkable"


def test_total_supply_scaled_by_decimals() -> None:
    declared = [fact("context.whitepaper.total_supply", "1000000000", unit="tokens", source=f"{WP}:8")]
    chain = [plain_fact("onchain.total_supply", 10**27, unit="token_units", source="eth_call totalSupply() at block 5"),
             plain_fact("onchain.decimals", 18, source="eth_call decimals() at block 5")]
    row = _rows(declared + chain)["Total supply"]
    assert row["status"] == "matches" and row["observed"] == "1000000000 tokens (18 decimals)"
    assert row["observed_source"] == "eth_call totalSupply() at block 5"
    off = [plain_fact("onchain.total_supply", 5 * 10**26, source="eth_call totalSupply() at block 5"),
           plain_fact("onchain.decimals", 18, source="eth_call decimals() at block 5")]
    assert _rows(declared + off)["Total supply"]["status"] == "differs"
    assert _rows(declared)["Total supply"]["status"] == "not_checkable"
    # declared decimals stand in when the chain read of decimals is missing
    ctx_dec = [fact("context.whitepaper.decimals", 18, source=f"{WP}:8")]
    only_supply = [plain_fact("onchain.total_supply", 10**27, source="eth_call totalSupply() at block 5")]
    assert _rows(declared + ctx_dec + only_supply)["Total supply"]["status"] == "matches"
    assert _rows(declared + only_supply)["Total supply"]["status"] == "not_checkable"
    maxs = [fact("context.docs.max_supply", "21000000", unit="tokens", source="context/docs-1.md:3")]
    assert _rows(maxs)["Max supply"]["status"] == "not_checkable"


def test_fees_against_folded_constants() -> None:
    declared = [fact("context.whitepaper.fee_pct", "0.3", unit="percent", source=f"{WP}:12", label="fee 0.3%"),
                fact("context.whitepaper.fee_pct", "25", unit="bps", source=f"{WP}:13", label="25 bps")]
    constants = {"constants": [{"name": "SWAP_FEE_BPS", "decl_ref": "src/Pool.sol:10", "folded_value": "30", "unit": "bps"},
                               {"name": "MAX_SUPPLY", "decl_ref": "src/Pool.sol:11", "folded_value": "1000"}]}
    row = _rows(declared, constants)["Fee figures"]
    assert row["status"] == "matches" and row["observed_source"] == "src/Pool.sol:10"
    assert row["declared"] == "0.3 %, 25 bps"
    other = {"constants": [{"name": "FEE", "decl_ref": "src/Pool.sol:10", "folded_value": "1", "unit": "percent"}]}
    assert _rows(declared, other)["Fee figures"]["status"] == "differs"
    assert _rows(declared, {"constants": []})["Fee figures"]["status"] == "not_checkable"
    assert _rows(declared, None)["Fee figures"]["status"] == "not_checkable"


def _admin(claim: str) -> list[dict]:
    return [fact("context.whitepaper.admin_claims", claim, source=f"{WP}:20", phrase=claim)]


def test_admin_claims_renounced_and_multisig() -> None:
    zero = [plain_fact("onchain.owner", "0x" + "0" * 40, source="eth_call owner() at block 5")]
    assert _rows(_admin("renounced") + zero)["Ownership renounced"]["status"] == "matches"
    owned = [plain_fact("onchain.owner", "0x" + "1" * 40, source="eth_call owner() at block 5")]
    assert _rows(_admin("renounced") + owned)["Ownership renounced"]["status"] == "differs"
    assert _rows(_admin("renounced"))["Ownership renounced"]["status"] == "not_checkable"
    contract = [plain_fact("onchain.owner_is_contract", "true", source="eth_getCode owner at block 5")]
    assert _rows(_admin("multisig") + contract)["Owner is a multisig"]["status"] == "matches"
    eoa = [plain_fact("onchain.owner_is_contract", "false", source="eth_getCode owner at block 5")]
    assert _rows(_admin("timelock") + eoa)["Owner is a timelock"]["status"] == "differs"
    assert _rows(_admin("timelock"))["Owner is a timelock"]["status"] == "not_checkable"


def test_admin_claims_upgradeable_immutable() -> None:
    uups = {"semantic": {"upgrade_surface": [{"unit": "src/A.sol:A", "mechanism": "uups", "authority_fact_key": "onchain.owner"}]}}
    plain = {"semantic": {"upgrade_surface": []}}
    assert _rows(_admin("upgradeable"), uups)["Contract is upgradeable"]["status"] == "matches"
    assert _rows(_admin("upgradeable"), plain)["Contract is upgradeable"]["status"] == "differs"
    assert _rows(_admin("immutable"), uups)["Contract is immutable"]["status"] == "differs"
    row = _rows(_admin("immutable"), plain)["Contract is immutable"]
    assert row["status"] == "matches" and row["observed"] == "upgrade surface: none"
    assert _rows(_admin("immutable"), {"spans": []})["Contract is immutable"]["status"] == "not_checkable"


def test_admin_claims_pausable_blacklist_mint_from_function_names() -> None:
    spans = {"spans": [{"id": "src/T.sol:pause", "name": "pause", "kind": "function", "file": "src/T.sol", "start": 1, "end": 2},
                       {"id": "src/T.sol:mint", "name": "mint", "kind": "function", "file": "src/T.sol", "start": 3, "end": 4},
                       {"id": "src/T.sol:T", "name": "T", "kind": "contract", "file": "src/T.sol", "start": 1, "end": 9}]}
    rows = _rows(_admin("pausable") + _admin("blacklist") + _admin("mint"), spans)
    assert rows["Contract is pausable"]["status"] == "matches" and "pause" in rows["Contract is pausable"]["observed"]
    assert rows["Contract can mint"]["status"] == "matches"
    assert rows["Contract has a blacklist"]["status"] == "differs"
    assert _rows(_admin("mint"), {})["Contract can mint"]["status"] == "not_checkable"


def test_chains_against_job() -> None:
    declared = [fact("context.website.chains", "Ethereum Mainnet", source="context/website-1.md:4", chain_id=1),
                fact("context.website.chains", "Solana", source="context/website-1.md:5", chain="solana")]
    row = _rows(declared)["Declared chains"]
    assert row["status"] == "matches" and row["observed"] == "chain_id 1" and row["declared"] == "Ethereum Mainnet, Solana"
    bsc = [fact("context.website.chains", "BNB Smart Chain", source="context/website-1.md:4", chain_id=56)]
    assert _rows(bsc)["Declared chains"]["status"] == "differs"
    sol = dict(JOB, chain="solana", chain_id=None)
    assert _rows(declared, job=sol)["Declared chains"]["status"] == "matches"
    assert _rows(declared, job={"job_id": "j"})["Declared chains"]["status"] == "not_checkable"


def test_row_order_follows_the_spec() -> None:
    facts = [fact("context.website.chains", "Ethereum Mainnet", source="context/website-1.md:4", chain_id=1),
             fact("context.whitepaper.admin_claims", "renounced", source=f"{WP}:20", phrase="renounced"),
             fact("context.whitepaper.fee_pct", "1", unit="percent", source=f"{WP}:12", label="fee 1%"),
             fact("context.whitepaper.total_supply", "10", unit="tokens", source=f"{WP}:8"),
             fact("context.website.mentions_reviewed_address", "true", source="context/website-1.md:9")]
    claims = [r["claim"] for r in compare(facts, {}, JOB)]
    assert claims == ["Reviewed contract referenced by the project documents", "Total supply", "Fee figures",
                      "Ownership renounced", "Declared chains"]
