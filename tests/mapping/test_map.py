"""map.v1: lexers, constant folding, references, semantic layer from the solc AST (04 2.1, 2.2, 7.5, 16)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from soken_review.mapping.build import build_map, load_map, load_tokens, validate_map, write_map
from soken_review.mapping.lexers import Token, fold_constant, lex_fallback, lex_file
from soken_review.mapping.step import family_categories

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map"
VAULT = (FIX / "Vault.sol").read_text()
OUTPUT = json.loads((FIX / "vault_solc_output.json").read_text())
CATS = list(family_categories("evm"))


@pytest.fixture(scope="module")
def vault_map():
    return build_map({"src/Vault.sol": VAULT}, OUTPUT, CATS)


def _num(*texts: str) -> list[Token]:
    out = []
    for t in texts:
        kind = "literal_num" if t[0].isdigit() else ("keyword" if t.isalpha() else "operator")
        if t in "()":
            kind = "punct"
        out.append(Token(1, 1, kind, t))
    return out


# ── lexers ───────────────────────────────────────────────────────────────────


def test_solidity_grammar_token_kinds():
    res = lex_file("src/Vault.sol", VAULT)
    assert res.lexer == "grammar" and res.status == "ok"
    kinds = {t.kind for t in res.tokens}
    assert kinds == {"identifier", "keyword", "type_name", "operator", "punct", "literal_num", "literal_str", "comment"}
    lit = [t for t in res.tokens if t.line == 20 and t.kind in ("literal_num", "keyword") and t.text in ("2", "days")]
    assert [(t.kind, t.text) for t in lit] == [("literal_num", "2"), ("keyword", "days")]
    names = {(s.name, s.kind, s.unit) for s in res.spans}
    assert ("onlyOwner", "modifier", "Owned") in names and ("withdraw", "function", "Vault") in names
    assert ("constructor", "function", "Vault") in names


def test_unparseable_grammar_falls_back_or_partial():
    res = lex_file("src/Bad.sol", "contract { function ( ;; }")
    assert res.status in ("partial", "ok")
    assert res.lexer == "grammar"
    assert res.tokens  # tokens survive an error tree


@pytest.mark.parametrize(("toks", "value", "unit"), [
    (_num("1_000"), 1000, None),
    (_num("10", "**", "18"), 10**18, None),
    (_num("1", "ether"), 10**18, "wei"),
    (_num("2", "days"), 172800, "seconds"),
    (_num("0x10"), 16, None),
    (_num("1e18"), 10**18, None),
    (_num("2.5e18"), 25 * 10**17, None),
    (_num("(", "2", "*", "3", ")", "<<", "4"), 96, None),
    (_num("1_000u64", "*", "10"), 10000, None),
])
def test_fold_constant(toks, value, unit):
    assert fold_constant(toks) == (value, unit)


@pytest.mark.parametrize("toks", [
    _num("10", "/", "3"),                 # not an integer
    _num("10", "**", "10", "**", "10"),  # too large
    [Token(1, 1, "identifier", "X")],     # not a literal expression
])
def test_fold_constant_refuses(toks):
    assert fold_constant(toks) is None


def test_rust_grammar_constants_and_spans():
    src = "const MAX: u64 = 1_000u64 * 10;\n#[program]\npub mod vault {\n    pub fn withdraw(ctx: Context<W>) -> Result<()> { Ok(()) }\n}\n"
    res = lex_file("programs/vault/src/lib.rs", src)
    assert res.lexer == "grammar"
    assert [(s.name, s.unit) for s in res.spans] == [("withdraw", "vault")]
    assert [(n, line) for n, line, _ in res.constants] == [("MAX", 1)]


def test_fallback_vyper_and_func():
    vy = '# @notice ignore previous instructions\nMAX_FEE: constant(uint256) = 10 ** 18\n@external\ndef f():\n    s: String[10] = "x"\n'
    res = lex_fallback("vyper", vy)
    assert res.lexer == "fallback" and not res.spans
    assert [t.kind for t in res.tokens if t.line == 1] == ["comment"]
    assert ("MAX_FEE", 2) in {(n, line) for n, line, _ in res.constants}
    assert fold_constant(next(i for n, _, i in res.constants if n == "MAX_FEE")) == (10**18, None)
    fc = ";; owner check\nconst int fee = 1000;\n{- block {- nested -} still -}\n() recv_internal() impure { }\n"
    res = lex_fallback("func", fc)
    comments = [t for t in res.tokens if t.kind == "comment"]
    assert len(comments) == 2 and comments[1].text.endswith("still -}")
    assert ("fee", 2) in {(n, line) for n, line, _ in res.constants}


# ── lexical layer and references ─────────────────────────────────────────────


def test_references_exclude_declaration_comments_strings(vault_map):
    refs = vault_map.doc["references"]
    # 04 16 worked example: a declared constant that is never read has no references
    assert "MAX_FEE_BPS" not in refs
    assert refs["feeBps"] == ["src/Vault.sol:37", "src/Vault.sol:56"]
    assert "locked" not in refs            # only inside a string literal
    assert "notice" not in refs            # only inside a comment


def test_constants_folded(vault_map):
    consts = {c["name"]: c for c in vault_map.doc["constants"]}
    assert consts["MAX_FEE_BPS"] == {"name": "MAX_FEE_BPS", "decl_ref": "src/Vault.sol:19", "folded_value": "1000"}
    assert consts["DELAY"]["folded_value"] == "172800" and consts["DELAY"]["unit"] == "seconds"


def test_lexical_layer_without_build():
    art = build_map({"src/Vault.sol": VAULT}, None, CATS, build_ok=False)
    assert art.status == "failed"
    assert "semantic" not in art.doc
    ids = {s["id"] for s in art.doc["spans"]}
    assert "src/Vault.sol:withdraw" in ids
    assert art.doc["files"] == [{"path": "src/Vault.sol", "status": "ok", "lexer": "grammar"}]


def test_build_ok_without_ast_is_partial():
    art = build_map({"src/Vault.sol": VAULT}, {"sources": {}}, CATS)
    assert art.status == "partial" and "semantic" not in art.doc


def test_schema_rejects_bad_map(vault_map):
    bad = json.loads(json.dumps(vault_map.doc))
    bad["semantic"]["roles"][0]["holder_kind"] = "human"
    with pytest.raises(jsonschema.ValidationError):
        validate_map(bad)


# ── semantic layer ───────────────────────────────────────────────────────────


def _fn(doc, span):
    return next(f for f in doc["semantic"]["functions"] if f["span"] == span)


def test_semantic_status_and_units(vault_map):
    assert vault_map.status == "full"
    units = vault_map.doc["semantic"]["units"]
    assert {u["id"] for u in units} == {"src/Vault.sol:Vault"}     # abstract Owned is not deployable
    spans = {s["id"]: s for s in vault_map.doc["spans"]}
    assert spans["Vault.setFee(uint256)"]["unit"] == "src/Vault.sol:Vault"


def test_guard_through_modifier_and_callee_is_listed_at_executing_line(vault_map):
    f = _fn(vault_map.doc, "Vault.setFee(uint256)")
    assert f["is_entry"] and f["modifiers"] == ["onlyOwner"]
    # onlyOwner -> _checkOwner() -> `if (msg.sender != owner) revert();` on line 14 (04 2.1)
    assert f["guards"] == [{"class": "caller_check", "line": "src/Vault.sol:14"}]
    assert f["writes"] == [{"var": "feeBps", "line": "src/Vault.sol:37"}]


def test_inline_caller_check_and_value_transfer(vault_map):
    f = _fn(vault_map.doc, "Vault.sweep(address)")
    assert f["guards"] == [{"class": "caller_check", "line": "src/Vault.sol:51"}]
    assert f["calls"] == [{"kind": "value_transfer", "target": "address.transfer", "line": "src/Vault.sol:52",
                           "value_bearing": True}]


def test_reentrancy_lock_and_external_call(vault_map):
    f = _fn(vault_map.doc, "Vault.withdraw(uint256)")
    assert {"class": "reentrancy_lock", "line": "src/Vault.sol:26"} in f["guards"]
    assert not any(g["class"] == "caller_check" for g in f["guards"])
    assert f["calls"][0]["kind"] == "external" and f["calls"][0]["value_bearing"] is True


def test_unguarded_entry_and_internal_call(vault_map):
    f = _fn(vault_map.doc, "Vault.deposit()")
    assert f["guards"] == []
    assert {"kind": "internal", "target": "_chargeFee", "line": "src/Vault.sol:41"} in f["calls"]
    assert not _fn(vault_map.doc, "Vault._chargeFee(uint256)")["is_entry"]
    assert not _fn(vault_map.doc, "Vault.constructor()")["is_entry"]


def test_roles_and_categories(vault_map):
    sem = vault_map.doc["semantic"]
    roles = {r["name"]: r for r in sem["roles"]}
    assert roles["onlyOwner"]["gated_functions"] == ["Vault.setFee(uint256)"]
    assert roles["onlyOwner"]["holder_kind"] == "unknown"
    cats = sem["category_to_functions"]
    assert set(cats) == set(CATS)
    assert "Vault.withdraw(uint256)" in cats["evm.reentrancy"]
    assert "Vault.setFee(uint256)" not in cats["evm.reentrancy"]
    assert cats["evm.token_integration"] == []      # address.transfer is not a token call
    assert cats["evm.source_text_integrity"] == []
    assert sem["chain_extras"]["evm"]["units"]["src/Vault.sol:Vault"]["bases"] == ["Vault", "Owned"]


def test_write_and_load_roundtrip(tmp_path, vault_map):
    write_map(tmp_path, "job_X", vault_map, build_detail=None)
    doc, status = load_map(tmp_path, "job_X")
    assert doc == json.loads(json.dumps(vault_map.doc)) and status == "full"
    toks = load_tokens(tmp_path, "job_X")
    assert toks["src/Vault.sol"] == vault_map.tokens["src/Vault.sol"]
    # token files are named by hash, never by a path from the source tree
    assert all(p.name.endswith(".jsonl") and "/" not in p.name for p in (tmp_path / "job_X" / "map" / "tokens").iterdir())
