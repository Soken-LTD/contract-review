"""analyze: Slither on candidates without an entry contract (repo, files) and lead scoping.

Before this, `_run_slither` returned None for every repo candidate (no entry file), so repo
reviews had zero analyzer leads (blind run 2026-10-25). Leads are dropped only for files the host
knows are outside the review in this run; a lead in a reviewed (pinned) file is always kept.
"""

from __future__ import annotations

from soken_review.adapters.evm import analyze


def _tree(tmp_path, rels):
    src = tmp_path / "src"
    for rel in rels:
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text("contract C {}")
    return src


def test_aggregate_entry_imports_the_scope(tmp_path):
    src = _tree(tmp_path, ["contracts/Vault.sol", "lib/X.sol", "node_modules/@oz/c/A.sol"])
    name = analyze._write_aggregate_entry(src, {"contracts/Vault.sol", "lib/X.sol"})
    body = (src / name).read_text()
    assert 'import "./contracts/Vault.sol";' in body and 'import "./lib/X.sol";' in body
    assert "node_modules" not in body


def test_aggregate_entry_never_takes_a_repo_file_name(tmp_path):
    src = _tree(tmp_path, ["contracts/Vault.sol", "soken_review_entry.sol"])
    name = analyze._write_aggregate_entry(src, {"contracts/Vault.sol", "soken_review_entry.sol"})
    assert name == "soken_review_entry_1.sol"
    assert (src / "soken_review_entry.sol").read_text() == "contract C {}"   # repo file untouched


def test_reviewed_file_under_lib_keeps_its_leads():
    scope = {"lib/X.sol", "contracts/V.sol"}
    excluded = {"lib/forge-std/src/Test.sol", "node_modules/@oz/c/A.sol"}
    assert not analyze._outside_review("lib/X.sol", scope, excluded, "soken_review_entry.sol")
    assert analyze._outside_review("node_modules/@oz/c/A.sol", scope, excluded, None)
    assert analyze._outside_review("lib/forge-std/src/Test.sol", scope, excluded, None)


def test_repo_file_named_like_the_aggregate_keeps_its_leads():
    scope = {"soken_review_entry.sol"}
    # the host wrote soken_review_entry_1.sol this run; the repo's own file stays reviewed
    assert not analyze._outside_review("soken_review_entry.sol", scope, set(), "soken_review_entry_1.sol")
    assert analyze._outside_review("soken_review_entry_1.sol", scope, set(), "soken_review_entry_1.sol")
    # even if names collided, a scope file is never dropped
    assert not analyze._outside_review("soken_review_entry.sol", scope, set(), "soken_review_entry.sol")


def test_unknown_files_are_kept_without_host_knowledge():
    assert not analyze._outside_review("node_modules/x/A.sol", None, None, None)
    assert not analyze._outside_review("lib/Y.sol", {"contracts/V.sol"}, set(), None)
