"""TON trust scan (06 3.3.4): allowlist of asm tokens, comment lexer, include and file gates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.adapters.ton.trust_scan import scan_files, scan_params, strip_comments

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ton"


def _usdt_files() -> dict[str, str]:
    bundle = json.loads((FIXTURES / "usdt_master_verifier_bundle.json").read_text())["bundle"]
    return {f["path"]: f["content"] for f in bundle["files"]}


def _func(body: str) -> dict[str, str]:
    return {"a.fc": f'cell f() asm "{body}";\n() recv_internal() impure {{ }}\n'}


def test_standard_jetton_stays_trusted() -> None:
    assert scan_files(_usdt_files()) == []


@pytest.mark.parametrize("body", ["DUP SWAP", "s0 s1 XCHG", "2 1 BLKSWAP", "0xf8a7ea5 PUSHINT",
                                  "x{8_} PUSHSLICE", "<b 0 2 u, b> <s PUSHSLICE", "<b b> PUSHREF",
                                  "<{ ACCEPT }> PUSHCONT", "-ROT"])
def test_clean_bodies_trusted(body: str) -> None:
    assert scan_files(_func(body)) == []


@pytest.mark.parametrize("word", ["<b", "b>", "u,", "i,", "s,", "ref,", "B,", "$,", "file>B",
                                  "base64>B", "s>c", "<s", "B>boc", "boc>"])
def test_fift_words_untrusted(word: str) -> None:
    reasons = scan_files(_func(f"1 {word} PUSHREF"))
    assert any("not a TVM mnemonic" in r for r in reasons), reasons


def test_big_literal_untrusted() -> None:
    assert scan_files(_func("12345678901234567890 PUSHINT"))
    assert scan_files(_func("0x123456789 PUSHINT"))


def test_long_cell_literal_untrusted() -> None:
    assert scan_files(_func("B{" + "ab" * 33 + "} PUSHSLICE"))


def test_too_many_literals_untrusted() -> None:
    files = {"a.fc": "".join(f'slice s{i}() asm "x{{0{i}}} PUSHSLICE";\n' for i in range(9))}
    assert any("literals" in r for r in scan_files(files))


@pytest.mark.parametrize("src", [
    'cell f() asm {- note -} "1 u, PUSHREF";',
    'cell f() asm {- outer {- nested -} still -} "1 u, PUSHREF";',
    'cell f() asm ;; note\n "1 u, PUSHREF";',
])
def test_comment_between_asm_and_body_func(src: str) -> None:
    assert any("not a TVM mnemonic" in r for r in scan_files({"a.fc": src}))


@pytest.mark.parametrize("src", [
    'fun f(): cell asm /* note */ "1 u, PUSHREF"',
    'fun f(): cell asm // note\n "1 u, PUSHREF"',
])
def test_comment_between_asm_and_body_tolk(src: str) -> None:
    assert any("not a TVM mnemonic" in r for r in scan_files({"a.tolk": src}))


@pytest.mark.parametrize("src", [
    "asm /* c */ fun f(): Cell { <b 1 u, b> PUSHREF }",
    "asm // c\n fun f(): Cell { <b b> 7 u, PUSHREF }",
])
def test_comment_between_asm_and_body_tact(src: str) -> None:
    assert any("not a TVM mnemonic" in r for r in scan_files({"a.tact": src}))


def test_commented_out_clean_asm_stays_trusted() -> None:
    assert scan_files({"a.fc": ';;() buy_gas(int amount) impure asm "BUYGAS";\n'}) == []
    assert scan_files({"a.tolk": '// fun f() asm "DUP"\n'}) == []


def test_commented_out_bad_asm_flagged_by_raw_pass() -> None:
    # the raw-text pass never trusts the lexer: a disallowed body anywhere in the text counts
    assert scan_files({"a.fc": ';; cell f() asm "1 u, PUSHREF";\n'})
    assert scan_files({"a.tolk": '/* fun f() asm "1 u," */\n'})


@pytest.mark.parametrize("path,src", [
    ("a.tact", 'const Q: String = "\\""; asm fun f(): Cell { <b 1 u, b> PUSHREF } const R: String = "\\"";'),
    ("a.tolk", 'const q = "\\""\nfun f(): cell asm "1 u, PUSHREF"\nconst r = "\\""\n'),
])
def test_escaped_quote_cannot_hide_asm(path: str, src: str) -> None:
    assert any("not a TVM mnemonic" in r for r in scan_files({path: src}))


@pytest.mark.parametrize("path,src", [
    ("a.fc", '{- open\n cell f() asm "DUP";'),
    ("a.tolk", '/* open\nfun f() asm "DUP"'),
    ("a.tact", 'const s: String = "open'),
])
def test_unterminated_string_or_comment_untrusted(path: str, src: str) -> None:
    assert any("unterminated" in r for r in scan_files({path: src}))


def test_asm_word_without_body_untrusted() -> None:
    assert any("asm keywords" in r for r in scan_files({"a.fc": ";; we use asm here\n"}))


def test_comment_markers_inside_strings_kept() -> None:
    assert strip_comments('x = ";; not a comment"; ;; real', "func").startswith('x = ";; not a comment";')


def test_unrecognised_asm_fails_closed() -> None:
    # `asm` followed by something the scanner cannot read as a body
    assert any("asm bodies recognised" in r for r in scan_files({"a.fc": "cell f() asm 'ABC';"}))


@pytest.mark.parametrize("inc", ["x.inc", "x.txt", "x", "x.fif", "x.boc"])
def test_func_include_outside_source_untrusted(inc: str) -> None:
    assert any("includes" in r for r in scan_files({"a.fc": f'#include "{inc}";\n'}))


def test_source_includes_trusted() -> None:
    assert scan_files({"a.fc": '#include "stdlib.fc";\n#include "imports/op.func";\n'}) == []
    assert scan_files({"a.tolk": 'import "@stdlib/tvm-dicts"\nimport "lib.tolk"\n'}) == []
    assert scan_files({"a.tact": 'import "@stdlib/deploy";\nimport "./messages";\nimport "./x.fc";\n'}) == []
    assert any("includes" in r for r in scan_files({"a.tolk": 'import "data.bin"\n'}))
    assert any("includes" in r for r in scan_files({"a.tact": 'import "./code.boc";\n'}))


def test_non_source_file_is_scanned() -> None:
    assert any("not a TVM mnemonic" in r for r in scan_files({"helpers.inc": 'cell f() asm "1 u, PUSHREF";'}))
    assert any("includes" in r for r in scan_files({"notes.txt": '#include "x.fc";'}))


def test_tact_config_entries_must_be_tact() -> None:
    ok = {"tact.config.json": json.dumps({"projects": [{"path": "./src/main.tact"}]})}
    bad = {"tact.config.json": json.dumps({"projects": [{"path": "./src/main.boc"}]})}
    assert scan_files(ok) == []
    assert scan_files(bad)


def test_long_tact_asm_untrusted() -> None:
    body = " ".join(["DUP DROP"] * 9)
    assert any("instructions" in r for r in scan_files({"a.tact": f"asm fun f() {{ {body} }}"}))


def test_params_allowlist() -> None:
    assert scan_params({"compiler_version": "0.4.4"}) == []
    assert scan_params({"compiler_version": "0.4.4", "extra_args": "-x"})


# ── code carried as data (review finding 6) ─────────────────────────────────


def test_jetton_with_blob_and_bless_untrusted() -> None:
    files = _usdt_files()
    blob = "ab" * 200
    files["jetton-minter.fc"] += (
        f'\n() run_blob() impure {{ cont c = bless("{blob}"s); }}\n'
    )
    reasons = scan_files(files)
    assert any("data literal of 200 bytes" in r for r in reasons), reasons
    assert any("'bless' is referenced" in r for r in reasons), reasons


def test_declared_but_unused_bless_stays_trusted() -> None:
    # standard stdlib.fc declares `cont bless(slice s) impure asm "BLESS";` and never calls it
    assert scan_files(_usdt_files()) == []


def test_upgradeable_set_code_stays_trusted() -> None:
    files = _usdt_files()
    files["jetton-minter.fc"] += (
        "\n() upgrade(cell new_code) impure { set_code(new_code); }\n"
    )
    assert scan_files(files) == []


@pytest.mark.parametrize("path,src", [
    ("a.tolk", 'const BLOB = stringHexToSlice("' + "cd" * 40 + '")\n'),
    ("a.tolk", 'const BLOB = stringToBase256("' + "x" * 40 + '")\n'),
    ("a.tact", 'const C: Cell = cell("' + "A" * 60 + '");\n'),
    ("a.tact", 'const S: Slice = rawSlice("' + "ef" * 40 + '");\n'),
    ("a.fc", "const int K = 123456789012345678901234567890;\n"),
    ("a.fc", "const int K = 0x123456789abcdef0123;\n"),
])
def test_large_data_literals_untrusted(path: str, src: str) -> None:
    assert scan_files({path: src})


@pytest.mark.parametrize("path,src", [
    ("a.fc", 'slice op = "7362d09c"s; int x = 0xf8a7ea5; int ton = 1000000000;\n'),
    ("a.tolk", 'const ADDR = stringHexToSlice("8000000000000000000000000000000000000000000000000000000000000000")\n'),
])
def test_small_data_literals_trusted(path: str, src: str) -> None:
    assert scan_files({path: src}) == []


@pytest.mark.parametrize("path,src", [
    ("a.fc", 'cont my_exec(slice s) impure asm "BLESS";\n() f(slice s) impure { my_exec(s); }\n'),
    ("a.tolk", 'fun run(c: continuation) asm "EXECUTE"\nfun f(c: continuation) { run(c); }\n'),
    ("a.tact", "asm fun run(c: Slice) { BLESS EXECUTE }\nfun f(s: Slice) { run(s); }\n"),
    ("a.tolk", "fun f(s: slice) { transformSliceToContinuation(s); }\n"),
])
def test_code_from_data_calls_untrusted(path: str, src: str) -> None:
    assert any("code taken from data" in r or "is referenced" in r for r in scan_files({path: src}))


# ── exact-token allowlist (commit review) ──────────────────────────────────


@pytest.mark.parametrize("body", [
    "x{<b} PUSHSLICE",            # literal content must be plain hex
    "b{012} PUSHSLICE",           # binary literal with a 2
    "B{zz} PUSHREF",
    "foox{00} PUSHSLICE",         # literal glued to another word is one unknown token
    "x{00}<b PUSHSLICE",
    "dup DUP",                    # mnemonics are case-sensitive
    "PUSHINTXX 1",                # suffix form that is not a mnemonic
    "-0x10 PUSHINT",
    "1e9 PUSHINT",
    "1_000 PUSHINT",
])
def test_asm_tokens_exact(body: str) -> None:
    assert scan_files(_func(body)), body


@pytest.mark.parametrize("src", [
    "const int K = 1_000_000_000_000_000_000_000;\n",       # 22 digits with separators
    "const K = 0x1234_5678_9abc_def0_1;\n",                 # 17 hex digits
    "const K = 0b" + "1" * 65 + ";\n",
])
def test_numeric_forms_over_cap(src: str) -> None:
    assert any("digit cap" in r for r in scan_files({"a.tolk": src}))


def test_exec_in_non_source_file_scanned_in_two_views_still_untrusted() -> None:
    # a non-source file is lexed with FunC and C rules plus raw: more views can only add reasons
    files = {
        "lib.inc": 'cont run(slice s) impure asm "BLESS";\ncont run(slice s) impure asm "BLESS";\n',
        "a.fc": '#include "stdlib.fc";\n() recv_internal() impure { }\n',
        "stdlib.fc": 'cont bless(slice s) impure asm "BLESS";\n',
    }
    assert any("code taken from data" in r for r in scan_files(files))


@pytest.mark.parametrize("src", [
    'cont my_bless(slice s) impure asm "BLESS";\n',          # any non-standard exec asm, even unused
    'cont bless(slice s) impure asm "BLESS";\n() f(slice s) impure { bless(s); }\n',
    'cont bless(slice s) impure asm "BLESS";\ncont bless(slice s) impure asm "BLESS";\n;; bless\n',
    '() f() impure asm "EXECUTE";\n',
])
def test_any_exec_mention_untrusted(src: str) -> None:
    assert scan_files({"a.fc": src})
