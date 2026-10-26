"""analyze: Slither on candidates without an entry contract (repo, files) and lead scoping.

Before this, `_run_slither` returned None for every repo candidate (no entry file), so repo
reviews had zero analyzer leads (blind run 2026-10-25). Leads located in vendored dependencies
are not review leads.
"""

from __future__ import annotations


def test_aggregate_entry_imports_reviewed_sources_only(tmp_path):
    from soken_review.adapters.evm import analyze

    src = tmp_path / "src"
    for rel in ("contracts/Vault.sol", "contracts/mocks/M.sol", "node_modules/@oz/c/A.sol", "lib/x/B.sol"):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text("contract C {}")
    name = analyze._write_aggregate_entry(src)
    body = (src / name).read_text()
    assert 'import "./contracts/Vault.sol";' in body and 'import "./contracts/mocks/M.sol";' in body
    assert "node_modules" not in body and "lib/" not in body
    assert analyze._write_aggregate_entry(src) is None          # never overwrites an existing file
    assert analyze._outside_review("node_modules/@oz/c/A.sol") and analyze._outside_review("lib/x/B.sol")
    assert analyze._outside_review(name) and not analyze._outside_review("contracts/Vault.sol")
