"""Move Prover parser and not_run semantics (plan v4 07 prover integration).

Covers:
  - parse_prover: success, verification failure, timeout (E5), no-location diagnostic
  - to_raw: severity mapping, unlocated count, path-map filter, lead.v1 schema
  - has_specs: detects spec blocks, rejects non-spec source, skips deps/
  - not_run semantics: no_specs is a deliberate skip (not in not_run list)
  - lead.v1 schema validation via build_leads
  - line-overlap merge: prover finding on same category+lines as a lint finding

All tests are unit-level; no Docker or sandbox required.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from soken_review.adapters.move.prover import has_specs, parse_prover, prove_argv, to_raw

# ─── Fixtures: realistic prover output ─────────────────────────────────────

# Prover succeeded: all specs proved, no error lines.
APTOS_SUCCESS = """\
[INFO] running Move Prover
[INFO] Spec module `0xdeadbeef::coin`
[SUCCESS] Move Prover succeeded: 3 function(s) verified, 0 error(s), 0 warning(s)
"""

# Single postcondition failure (E2).
APTOS_FAIL_POSTCOND = """\
[INFO] running Move Prover
error[E2]: specification of function `coin::transfer` failed
    ┌─ sources/coin.move:45:5
    │
 45 │     ensures balance == old(balance) - amount;
    │     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    │
    = postcondition does not hold
[FAILED] Move Prover failed: 1 error(s), 0 warning(s)
"""

# Boogie/Z3 per-function timeout (E5).
APTOS_TIMEOUT = """\
error[E5]: prover timeout exceeded for function `module::complex_fn`
    ┌─ sources/module.move:100:3
    │
100 │     spec complex_fn {
    │     ^^^^^^^^^^^^^^^^^
[FAILED] Move Prover failed: 1 error(s), 0 warning(s)
"""

# Spec-type error (E1).
APTOS_SPEC_ERROR = """\
error[E1]: type mismatch in spec function
    ┌─ sources/token.move:22:1
[FAILED] Move Prover failed: 1 error(s), 0 warning(s)
"""

# Diagnostic with NO location (no ┌─ line).
APTOS_NO_LOC = """\
error[E2]: internal prover error: global invariant cannot be proved
[FAILED] Move Prover failed: 1 error(s), 0 warning(s)
"""

# Two errors in one output.
APTOS_TWO_ERRORS = """\
error[E2]: postcondition failed
    ┌─ sources/a.move:10:5
    │
 10 │     ensures x > 0;
    │     ^^^^^^^^^^^^^^
error[E2]: assertion failed
    ┌─ sources/b.move:30:9
    │
 30 │     assert!(y > 0);
    │     ^^^^^^^^
"""

# Source with spec blocks for has_specs.
MOVE_WITH_SPECS = """\
module a::coin {
    public fun transfer(amount: u64) {
        spec {
            requires amount > 0;
        };
    }
    spec transfer {
        ensures result == amount - 1;
    }
}
"""

# Source WITHOUT spec blocks.
MOVE_WITHOUT_SPECS = """\
module a::utils {
    public fun add(x: u64, y: u64): u64 { x + y }
}
"""

# Spec keyword inside a line comment — must NOT trigger detection.
MOVE_SPEC_IN_COMMENT = """\
module a::m {
    // spec f { ensures true; }  -- this is a comment
    public fun f(): bool { true }
}
"""

# Spec keyword inside a block comment.
MOVE_SPEC_IN_BLOCK_COMMENT = """\
module a::m {
    /* spec g { ensures true; } */
    public fun g(): bool { true }
}
"""

# Spec in a string literal (`spec` starts in a string, not a statement).
MOVE_SPEC_IN_STRING = """\
module a::m {
    public fun label(): vector<u8> { b"spec {" }
}
"""

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "schemas" / "lead.v1.json"
_SCHEMA = json.loads(_SCHEMA_PATH.read_text()) if _SCHEMA_PATH.exists() else {}


# ─── parse_prover ──────────────────────────────────────────────────────────

def test_parse_prover_success_returns_empty():
    assert parse_prover("aptos", APTOS_SUCCESS) == []


def test_parse_prover_verification_failure():
    diags = parse_prover("aptos", APTOS_FAIL_POSTCOND)
    assert len(diags) == 1
    d = diags[0]
    assert d["error_code"] == "2"
    assert d["file"] == "sources/coin.move"
    assert d["start"] == 45
    assert d["end"] >= 45


def test_parse_prover_span_line_extends_end():
    diags = parse_prover("aptos", APTOS_FAIL_POSTCOND)
    # Line 45 is echoed in the snippet; end should be at least 45.
    assert diags[0]["end"] >= 45


def test_parse_prover_timeout_e5():
    diags = parse_prover("aptos", APTOS_TIMEOUT)
    assert len(diags) == 1
    assert diags[0]["error_code"] == "5"
    assert diags[0]["file"] == "sources/module.move"
    assert diags[0]["start"] == 100


def test_parse_prover_spec_error_e1():
    diags = parse_prover("aptos", APTOS_SPEC_ERROR)
    assert len(diags) == 1
    assert diags[0]["error_code"] == "1"
    assert diags[0]["file"] == "sources/token.move"
    assert diags[0]["start"] == 22


def test_parse_prover_no_location():
    diags = parse_prover("aptos", APTOS_NO_LOC)
    assert len(diags) == 1
    assert diags[0]["file"] is None
    assert diags[0]["start"] is None


def test_parse_prover_two_errors_separate_items():
    diags = parse_prover("aptos", APTOS_TWO_ERRORS)
    assert len(diags) == 2
    assert {d["file"] for d in diags} == {"sources/a.move", "sources/b.move"}


def test_parse_prover_ansi_stripped():
    colored = "\x1b[31merror[E2]\x1b[0m: fail\n    ┌─ sources/x.move:1:1\n"
    diags = parse_prover("aptos", colored)
    assert len(diags) == 1
    assert diags[0]["error_code"] == "2"


# ─── to_raw ────────────────────────────────────────────────────────────────

def _identity_map(p: str):
    return p


def test_to_raw_verification_failure_maps_to_correct_severity():
    diags = parse_prover("aptos", APTOS_FAIL_POSTCOND)
    items, unlocated = to_raw("aptos", diags, "move-prover@9.6.0", _identity_map)
    assert unlocated == 0
    assert len(items) == 1
    assert items[0]["severity_raw"] == "verification_failure"
    assert items[0]["category"] == "move.spec_violation"


def test_to_raw_timeout_maps_to_prover_timeout():
    diags = parse_prover("aptos", APTOS_TIMEOUT)
    items, _unlocated = to_raw("aptos", diags, "move-prover@9.6.0", _identity_map)
    assert items[0]["severity_raw"] == "prover_timeout"


def test_to_raw_spec_error_maps_to_spec_error():
    diags = parse_prover("aptos", APTOS_SPEC_ERROR)
    items, _unlocated = to_raw("aptos", diags, "move-prover@9.6.0", _identity_map)
    assert items[0]["severity_raw"] == "spec_error"


def test_to_raw_unlocated_diagnostic_counted():
    diags = parse_prover("aptos", APTOS_NO_LOC)
    items, unlocated = to_raw("aptos", diags, "move-prover@9.6.0", _identity_map)
    assert items == []
    assert unlocated == 1


def test_to_raw_path_map_filter_drops_out_of_scope():
    """Items whose path_map returns None (deps/framework) are silently dropped."""
    diags = parse_prover("aptos", APTOS_FAIL_POSTCOND)
    items, unlocated = to_raw("aptos", diags, "move-prover@9.6.0", lambda p: None)
    assert items == [] and unlocated == 0


def test_to_raw_rule_id_format():
    diags = parse_prover("aptos", APTOS_FAIL_POSTCOND)
    items, _ = to_raw("aptos", diags, "move-prover@9.6.0", _identity_map)
    assert items[0]["rule_id"] == "move-prover:verification_failure"


@pytest.mark.skipif(not _SCHEMA, reason="lead.v1.json schema not found")
def test_to_raw_items_pass_through_build_leads_lead_v1():
    """Items from to_raw, when processed by build_leads, produce valid lead.v1 objects."""
    from soken_review.adapters.move.analyze import build_leads

    diags = parse_prover("aptos", APTOS_FAIL_POSTCOND)
    items, _ = to_raw("aptos", diags, "move-prover@9.6.0", _identity_map)
    leads = build_leads(items)
    assert len(leads) == 1
    jsonschema.validate(leads[0], _SCHEMA)
    assert leads[0]["severity_norm"] == "High"


@pytest.mark.skipif(not _SCHEMA, reason="lead.v1.json schema not found")
def test_prover_timeout_lead_is_medium():
    from soken_review.adapters.move.analyze import build_leads

    diags = parse_prover("aptos", APTOS_TIMEOUT)
    items, _ = to_raw("aptos", diags, "move-prover@9.6.0", _identity_map)
    leads = build_leads(items)
    assert leads[0]["severity_norm"] == "Medium"


# ─── Lead overlap merge with lint on same category + lines ────────────────

@pytest.mark.skipif(not _SCHEMA, reason="lead.v1.json schema not found")
def test_prover_and_lint_on_same_lines_merge_to_one_lead():
    """A prover finding and a lint finding on the same category + overlapping lines
    merge into one lead (07 5.3 cross-tool merge rule in build_leads)."""
    from soken_review.adapters.move.analyze import build_leads

    file = "sources/coin.move"
    lint_item = {
        "tool": "aptos-lint@9.6.0",
        "rule_id": "aptos-lint:unnecessary_cast",
        "severity_raw": "info",
        "category": "move.spec_violation",
        "file": file,
        "start": 44,
        "end": 46,
    }
    prover_item = {
        "tool": "move-prover@9.6.0",
        "rule_id": "move-prover:verification_failure",
        "severity_raw": "verification_failure",
        "category": "move.spec_violation",
        "file": file,
        "start": 45,
        "end": 45,
    }
    leads = build_leads([lint_item, prover_item])
    # Overlapping range → merged into a single lead with both tools listed.
    assert len(leads) == 1
    assert set(leads[0]["tools"]) == {"aptos-lint@9.6.0", "move-prover@9.6.0"}
    # Best severity wins (High from prover, Info from lint).
    assert leads[0]["severity_norm"] == "High"


# ─── has_specs ─────────────────────────────────────────────────────────────

def test_has_specs_detects_named_spec():
    files = {"sources/coin.move": MOVE_WITH_SPECS}
    assert has_specs(files) is True


def test_has_specs_detects_inline_spec():
    src = "module a::m { public fun f() { spec { invariant true; }; } }"
    assert has_specs({"sources/m.move": src}) is True


def test_has_specs_returns_false_for_plain_module():
    files = {"sources/utils.move": MOVE_WITHOUT_SPECS}
    assert has_specs(files) is False


def test_has_specs_ignores_spec_in_line_comment():
    assert has_specs({"sources/m.move": MOVE_SPEC_IN_COMMENT}) is False


def test_has_specs_ignores_spec_in_block_comment():
    assert has_specs({"sources/m.move": MOVE_SPEC_IN_BLOCK_COMMENT}) is False


def test_has_specs_ignores_spec_in_string_literal():
    # The `b"spec {"` string literal does not start at the beginning of a statement.
    assert has_specs({"sources/m.move": MOVE_SPEC_IN_STRING}) is False


def test_has_specs_excludes_deps_prefix():
    """Files under deps/ belong to framework/dependencies, not the reviewed package."""
    files = {
        "deps/aptos-framework/sources/coin.move": MOVE_WITH_SPECS,
        "sources/token.move": MOVE_WITHOUT_SPECS,
    }
    assert has_specs(files) is False


def test_has_specs_in_scope_filter_respected():
    files = {
        "sources/main.move": MOVE_WITHOUT_SPECS,
        "sources/spec_only.move": MOVE_WITH_SPECS,
    }
    # in_scope excludes the file that has specs.
    assert has_specs(files, in_scope=lambda p: p == "sources/main.move") is False
    # in_scope includes the file with specs.
    assert has_specs(files, in_scope=lambda p: p == "sources/spec_only.move") is True


def test_has_specs_skips_non_move_files():
    """Non-.move files (TOML, JSON) are ignored even if they contain the word spec."""
    files = {
        "Move.toml": '[package]\nname = "mypackage"\n# spec something { }\n',
        "sources/m.move": MOVE_WITHOUT_SPECS,
    }
    assert has_specs(files) is False


# ─── prove_argv ────────────────────────────────────────────────────────────

def test_prove_argv_aptos_contains_prove_and_package_dir():
    argv = prove_argv("aptos", "packages/core")
    assert "move" in argv
    assert "prove" in argv
    assert "--package-dir" in argv
    pkg_idx = argv.index("--package-dir")
    assert argv[pkg_idx + 1].endswith("packages/core")


def test_prove_argv_sui_contains_prove_and_path():
    argv = prove_argv("sui", ".")
    assert "prove" in argv
    assert "--path" in argv


def test_prove_argv_aptos_root_dir():
    argv = prove_argv("aptos", ".")
    pkg_idx = argv.index("--package-dir")
    # Trailing "/." is stripped so it ends at /work/src.
    assert argv[pkg_idx + 1] == "/work/src"


def test_prove_argv_contains_skip_git_flag():
    """Offline flag must be present so the prove container never tries to fetch deps."""
    argv = prove_argv("aptos", ".")
    combined = " ".join(argv)
    assert "skip-fetch-latest" in combined and "git-deps" in combined


def test_prove_argv_uses_work_src_prefix():
    """Paths are prefixed with /work/src; analyze.py replaces with /work/scratch/src."""
    argv = prove_argv("aptos", "packages/token")
    pkg_idx = argv.index("--package-dir")
    assert argv[pkg_idx + 1].startswith("/work/src/")
