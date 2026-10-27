"""A challenge item never lists more scope ranges than an answer may carry refs (blind run
2026-10-26: 16 ranges against a 12-ref cap), and the caps agree across the schema, the answer
checker and invariant_walks."""

from __future__ import annotations

import json
from pathlib import Path

from soken_review.tools import walks
from soken_review.tools.challenge import (
    ANSWER_REFS_MAX,
    SCOPE_RANGES_MAX,
    _item_to_output,
    _merge_scope_ranges,
    _parse_range_ref,
)

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "contract" / "mcp" / "tools.v1.json").read_text())
TOOLS = {t["name"]: t for t in SCHEMA["tools"]}


def _covers(merged: list[str], original: list[str]) -> bool:
    spans = [_parse_range_ref(r) for r in merged]
    for ref in original:
        path, s, e = _parse_range_ref(ref)
        if not any(p == path and ms <= s and me >= e for p, ms, me in spans):
            return False
    return True


def test_adjacent_and_overlapping_ranges_group():
    out = _merge_scope_ranges(["a.sol:10-20", "a.sol:21-30", "a.sol:25-28", "a.sol:40-50", "b.sol:1-5"])
    assert out == ["a.sol:10-30", "a.sol:40-50", "b.sol:1-5"]


def test_many_same_file_ranges_stay_within_the_cap_and_still_cover_every_range():
    original = [f"Vault.sol:{i * 50 + 1}-{i * 50 + 12}" for i in range(16)]
    out = _merge_scope_ranges(original)
    assert len(out) <= SCOPE_RANGES_MAX
    assert _covers(out, original)


def test_ranges_in_distinct_files_cannot_merge_but_still_fit_an_answer():
    original = [f"f{i:02d}.sol:1-10" for i in range(14)]
    out = _merge_scope_ranges(original)
    assert out == original  # one range per file: nothing to merge
    assert len(out) <= ANSWER_REFS_MAX


def test_a_malformed_ref_leaves_the_list_as_built():
    original = ["a.sol:1-10", "not-a-ref"]
    assert _merge_scope_ranges(original) == original


def test_item_output_uses_the_merged_ranges(monkeypatch):
    import soken_review.tools.challenge as ch

    many = [f"Vault.sol:{i * 50 + 1}-{i * 50 + 12}" for i in range(16)]
    monkeypatch.setattr(ch, "_resolve_scope", lambda *a, **k: (many, False, "semantic"))
    out = _item_to_output({"id": "K1", "kind": "kill", "condition": "q"}, "evm", {}, [])
    assert len(out["scope"]["ranges"]) <= SCOPE_RANGES_MAX
    assert _covers(out["scope"]["ranges"], many)


def test_caps_are_consistent_across_schema_answer_and_walks():
    answer_refs = TOOLS["review_answer_challenge"]["inputSchema"]["properties"]["answers"]["items"]["properties"]["refs"]
    walk_refs = (TOOLS["review_set_section"]["inputSchema"]["properties"]["invariant_walks"]["properties"]
                 ["rows"]["items"]["properties"]["refs"])
    assert answer_refs["maxItems"] == ANSWER_REFS_MAX
    assert walk_refs["maxItems"] == walks._REFS_MAX == ANSWER_REFS_MAX
    assert SCOPE_RANGES_MAX <= ANSWER_REFS_MAX
