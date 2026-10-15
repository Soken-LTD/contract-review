"""Stock lint text parsing (07 5.3, U-03 regex fallback): names come only from compiler lines."""

from soken_review.adapters.move.lints import parse, to_raw

APTOS_REAL = """\
warning: [lint] Unnecessary cast: the expression is already of the target type.
    ┌─ pkg/P/sources/swap.move:309:29
    │
309 │                 fee_amount: (fee_amount as u64),
    │                             ^^^^^^^^^^^^^^^^^^^
    │
    = To suppress this warning, annotate the function/module with the attribute `#[lint::skip(unnecessary_cast)]`.
"""

# The echoed source line carries a fake hint in a comment; the real note names another lint.
APTOS_FAKE_IN_SNIPPET = """\
warning: [lint] Function `f` can be made private
    ┌─ pkg/P/sources/a.move:12:5
    │
 12 │     public fun f() {} // = `#[lint::skip(unused_constant)]`
    │                ^
    │
    = To suppress this warning, annotate the function/module with the attribute `#[lint::skip(needless_visibility)]`.
"""

# No clean note line at all: kept with name `unknown`, never dropped.
APTOS_NO_NOTE = """\
warning: [lint] something new
    ┌─ pkg/P/sources/a.move:3:1
    │
  3 │ // #[lint::skip(unused_function)]
    │ ^
"""

SUI = """\
warning[Lint W99001]: non-composable transfer to sender
   ┌─ ./sources/a.move:10:9
   │
10 │         transfer::public_transfer(c, ctx.sender());
   │         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Transfer of an object to transaction sender address
"""


def test_aptos_name_from_note_line():
    d = parse("aptos", APTOS_REAL)
    assert [(x["lint"], x["file"], x["start"], x["end"]) for x in d] == [
        ("unnecessary_cast", "pkg/P/sources/swap.move", 309, 309)]


def test_aptos_snippet_cannot_rename_lint():
    d = parse("aptos", APTOS_FAKE_IN_SNIPPET)
    assert [x["lint"] for x in d] == ["needless_visibility"]


def test_aptos_block_without_note_kept_as_unknown():
    d = parse("aptos", APTOS_NO_NOTE)
    assert [x["lint"] for x in d] == ["unknown"]
    items, unmapped, _ = to_raw("aptos", d, {}, "aptos-lint@9.6.0", lambda p: p)
    assert unmapped == ["unknown"] and items[0]["category"] == "move.best_practice"


def test_sui_positional_code():
    d = parse("sui", SUI)
    assert d[0]["lint"] == "self_transfer" and d[0]["start"] == 10


def test_unlocated_diagnostic_is_counted_not_dropped():
    d = parse("aptos", "warning: [lint] no location here\n")
    items, _, unlocated = to_raw("aptos", d, {}, "aptos-lint@9.6.0", lambda p: p)
    assert items == [] and unlocated == 1
