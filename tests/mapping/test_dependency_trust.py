"""`dependency_trust`: which unpinned files may credit a guard (security review of PR #84)."""

from __future__ import annotations

from soken_review.mapping.step import dependency_trust

DEPS = {"manager": "npm", "lockfile": "package-lock.json", "pinned_by": "lockfile", "packages": [
    {"name": "@openzeppelin/contracts", "pinned_by": "lockfile", "files": 226, "version": "5.6.1",
     "integrity": "sha512-" + "A" * 86 + "=="},
    {"name": "solady", "pinned_by": "lockfile_version", "files": 10, "version": "0.1.0", "integrity": "sha512-" + "B" * 86 + "=="},
    {"name": "@uniswap/v3-core", "pinned_by": "registry_range", "files": 30, "version": "1.0.1",
     "integrity": "sha512-" + "C" * 86 + "=="},
    {"name": "unverified", "pinned_by": "lockfile", "files": 3, "version": "1.0.0"},
    {"name": "../escape", "pinned_by": "lockfile", "integrity": "sha512-" + "D" * 86 + "=="},
]}


def test_only_lockfile_integrity_pinned_packages_are_trusted():
    trust = dependency_trust(DEPS, {"scope_excluded": [{"path": "contracts/mocks/MockUSDC.sol", "reason": "test_or_mock_dir"}]})
    assert trust["trusted_prefixes"] == ("node_modules/@openzeppelin/contracts/", "node_modules/solady/")
    assert trust["untrusted_paths"] == frozenset({"contracts/mocks/MockUSDC.sol"})


def test_no_record_means_nothing_is_trusted():
    assert dependency_trust(None, None) == {"trusted_prefixes": (), "untrusted_paths": frozenset()}
    assert dependency_trust({"packages": "garbage"}, {"scope_excluded": ["x"]})["trusted_prefixes"] == ()
