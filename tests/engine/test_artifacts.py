"""Facts and map feeding the number check and V7.5 (04 6.3, 7.5, 16). Pure: Artifacts in, results out."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.engine.artifacts import (
    Artifacts,
    a1_literals,
    entry_functions_for,
    number_context,
    references,
    word_set,
)
from soken_review.engine.numbers import lex_numbers
from soken_review.mapping.build import build_map
from soken_review.mapping.facts import fact
from soken_review.mapping.step import family_categories

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map"
VAULT = (FIX / "Vault.sol").read_text()
UNIT = "src/Vault.sol:Vault"


@pytest.fixture(scope="module")
def art() -> Artifacts:
    m = build_map({"src/Vault.sol": VAULT}, json.loads((FIX / "vault_solc_output.json").read_text()),
                  list(family_categories("evm")))
    facts = [
        fact("chain.block", 52383163, unit="block", source="eth_blockNumber at pin, minus one"),
        fact("onchain.balance", 10**21, unit="wei", unit_id=UNIT, source="eth_getBalance at block 52383163"),
        fact("compiler.version", "0.8.26", source="source candidate (sourcify)"),
    ]
    return Artifacts(map=m.doc, map_status=m.status, tokens=m.tokens, facts=facts, flags=[])


Q_SETFEE = [{"file": "src/Vault.sol", "start": 36, "end": 38, "role": "location"},
            {"file": "src/Vault.sol", "start": 19, "end": 19, "role": "context"}]


def test_fact_tags_from_units_yaml():
    assert fact("onchain.balance", 1, source="x")["tags"] == ["amount_at_risk"]
    assert fact("onchain.owner", "0x00", source="x")["tags"] == []
    with pytest.raises(ValueError):
        fact("Bad.Key", 1, source="x")


def test_a1_literals_include_folded_constant(art):
    values, units = a1_literals(art, Q_SETFEE)
    assert "1_000" in values          # literal token on quoted line 19
    assert not units
    q = [{"file": "src/Vault.sol", "start": 55, "end": 57, "role": "location"}]
    values, _ = a1_literals(art, q)
    assert "10_000" in values
    q_delay = [{"file": "src/Vault.sol", "start": 20, "end": 20, "role": "context"}]
    assert a1_literals(art, q_delay)[1] is True       # `2 days`: A2 applies


def test_number_check_worked_example_16(art):
    ctx = number_context(art, Q_SETFEE, magnitude="unbounded", component=UNIT)
    assert lex_numbers("`MAX_FEE_BPS` is declared at line 19 and is 1,000 bps.", ctx) == []
    assert lex_numbers("The fee can exceed {{calc:bps_to_pct(1000)|0}}%.", ctx) == []
    bad = lex_numbers("The cap is 2,000.", ctx)
    assert [v.code for v in bad] == ["E_NUMBER_UNSOURCED"]


def test_amount_at_risk_meaning_rule(art):
    ok = number_context(art, Q_SETFEE, magnitude="unbounded", component=UNIT)
    assert lex_numbers("The vault holds {{fact:onchain.balance}} wei.", ok) == []
    bounded = number_context(art, Q_SETFEE, magnitude="bounded", component=UNIT)
    assert [v.code for v in lex_numbers("It holds {{fact:onchain.balance}} wei.", bounded)] == ["E_NUMBER_CONTEXT"]
    other_unit = number_context(art, Q_SETFEE, magnitude="unbounded", component="src/Vault.sol:Owned")
    assert [v.code for v in lex_numbers("It holds {{fact:onchain.balance}} wei.", other_unit)] == ["E_NUMBER_CONTEXT"]
    calc = lex_numbers("{{calc:wei_to_ether(fact:onchain.balance)|2}} ETH", bounded)
    assert [v.code for v in calc] == ["E_NUMBER_CONTEXT"]
    section = number_context(art, [], is_finding=False)
    assert [v.code for v in lex_numbers("Balance {{fact:onchain.balance}} wei.", section)] == ["E_NUMBER_CONTEXT"]


def test_unknown_fact_key_rejected_when_facts_loaded(art):
    ctx = number_context(art, Q_SETFEE)
    assert [v.code for v in lex_numbers("At block {{fact:chain.blok}}.", ctx)] == ["E_NUMBER_UNSOURCED"]
    assert lex_numbers("At block {{fact:chain.block}}.", ctx) == []


def test_word_set_and_references(art):
    ws = word_set(art)
    assert {"MAX_FEE_BPS", "setFee", "uint256", "Vault"} <= ws
    assert references(art, "MAX_FEE_BPS") == []
    assert references(art, "feeBps", {"src/Vault.sol"}) == ["src/Vault.sol:37", "src/Vault.sol:56"]


def test_entry_functions_reaching_a_line(art):
    # line 56 is inside _chargeFee, reached only through deposit (7.5 call graph)
    assert entry_functions_for(art, "src/Vault.sol", 56) == ["Vault.deposit()"]
    # line 14 is in _checkOwner, reached through the onlyOwner modifier of setFee
    assert entry_functions_for(art, "src/Vault.sol", 9) == ["Vault.setFee(uint256)"]
    # a state-variable declaration resolves to the entry functions that write it
    assert entry_functions_for(art, "src/Vault.sol", 21) == ["Vault.setFee(uint256)"]


def test_no_semantic_layer_is_map_unavailable():
    m = build_map({"src/Vault.sol": VAULT}, None, list(family_categories("evm")), build_ok=False)
    a = Artifacts(map=m.doc, map_status=m.status, tokens=m.tokens, facts=[], flags=[])
    assert entry_functions_for(a, "src/Vault.sol", 56) is None
    # lexical layer still serves A1 and references (04 1.3 row 1)
    assert "1_000" in a1_literals(a, Q_SETFEE)[0]
    assert references(a, "feeBps") == ["src/Vault.sol:37", "src/Vault.sol:56"]


def test_a1_literals_constant_initializer_and_percent_scale():
    """r5 revert: "10 percent" of `MAX_LIQUIDATION_PENALTY_X32 = uint32(Q32 / 10)` quoted at a
    use site was rejected as unsourced. The initializer literals and the scaled percent count."""
    src = (
        "contract V {\n"
        "    uint256 constant Q32 = 2**32;\n"
        "    uint32 public constant MAX_PENALTY_X32 = uint32(Q32 / 10);\n"
        "    uint32 public constant FEE_X32 = 429496729;\n"
        "    function f(uint32 p) external { require(p <= MAX_PENALTY_X32); }\n"
        "    function g(uint32 p) external { require(p <= FEE_X32); }\n"
        "}\n"
    )
    m = build_map({"src/V.sol": src}, None, list(family_categories("evm")))
    a = Artifacts(map=m.doc, map_status=m.status, tokens=m.tokens, facts=[], flags=[])
    q = [{"file": "src/V.sol", "start": 5, "end": 5, "role": "location"}]
    values, _ = a1_literals(a, q)
    assert "10" in values                       # literal of the MAX_PENALTY_X32 initializer
    ctx = number_context(a, q)
    assert lex_numbers("The penalty cap is 10 percent.", ctx) == []
    assert [v.code for v in lex_numbers("The penalty cap is 25 percent.", ctx)] == ["E_NUMBER_UNSOURCED"]
    # a folded constant used on the line: its Q32 percent is a code value
    q_fee = [{"file": "src/V.sol", "start": 6, "end": 6, "role": "location"}]
    assert "10" in a1_literals(a, q_fee)[0]
