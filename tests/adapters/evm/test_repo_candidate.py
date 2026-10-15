"""Unit tests for adapters/evm/repo_candidate.py (05 4.2 step 6, 09 5.2).

Tests every fail-closed branch:
  - npm-only repo → insufficient_source
  - submodule on a non-allowlisted host → stays in manifest refused list, candidate succeeds
  - remapping escaping the tree → dropped silently (sanitize_remapping rejects it)
  - ffi=true → untrusted_inputs = True
  - missing ref (no Solidity sources) → no_solidity_sources
  - in-tree deps present → candidate succeeds
  - pragma version guess when no explorer candidate
"""

from __future__ import annotations

import json
from pathlib import Path

from soken_review.adapters.evm.repo_candidate import (
    _has_ffi_or_hooks,
    _npm_only_reason,
    _recheck_path,
    _select_scope_files,
    repo_candidate_from_manifest,
)

# Default source_url used in all tests (supervisor always supplies one).
_REPO_URL = "https://github.com/example/repo@" + "a" * 40


def _rcfm(src: Path, manifest: dict, **kw: object) -> tuple:
    """Thin wrapper: always pass source_url so tests exercise the production path."""
    kw.setdefault("source_url", _REPO_URL)
    return repo_candidate_from_manifest(src, manifest, **kw)  # type: ignore[arg-type]

# ---------------------------------------------------------------------------
# Fixtures: minimal materialized tree
# ---------------------------------------------------------------------------

_SIMPLE_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Counter {
    uint256 public count;
    function increment() external { count++; }
}
"""

_FOUNDRY_TOML_BASIC = """\
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
optimizer = true
optimizer_runs = 200
evm_version = "paris"
"""

_FOUNDRY_TOML_FFI = """\
[profile.default]
src = "src"
ffi = true
"""

_FOUNDRY_TOML_HOOK = """\
[profile.default]
src = "src"
build_command = "make all"
"""


def _make_src(tmp_path: Path, files: dict[str, str]) -> tuple[Path, dict]:
    """Write files to tmp_path/src and return (src_dir, manifest)."""
    src = tmp_path / "src"
    src.mkdir()
    written = []
    for rel, content in files.items():
        full = src / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        written.append({"path": rel, "size": len(content), "sha256": "aa" * 32})
    manifest = {
        "schema": "soken-fetch.v1",
        "resolved_commit": "a" * 40,
        "files": written,
        "submodules": [],
        "too_large": [],
        "refused": [],
    }
    return src, manifest


# ---------------------------------------------------------------------------
# _recheck_path
# ---------------------------------------------------------------------------

class TestRecheckPath:
    def test_safe_path(self):
        assert _recheck_path("src/Counter.sol") == "src/Counter.sol"

    def test_absolute_rejected(self):
        assert _recheck_path("/etc/passwd") is None

    def test_dot_dot_rejected(self):
        assert _recheck_path("../escape.sol") is None

    def test_dotgit_rejected(self):
        assert _recheck_path(".git/config") is None

    def test_null_byte_rejected(self):
        assert _recheck_path("src/\x00evil.sol") is None

    def test_dash_leading_segment_rejected(self):
        assert _recheck_path("-evil/file.sol") is None

    def test_nested_dotdot_rejected(self):
        assert _recheck_path("a/../b/c.sol") is None

    def test_empty_rejected(self):
        assert _recheck_path("") is None


# ---------------------------------------------------------------------------
# _has_ffi_or_hooks
# ---------------------------------------------------------------------------

class TestFfiOrHooks:
    def test_no_ffi(self):
        cfg = {"profile": {"default": {"src": "src", "optimizer": True}}}
        assert _has_ffi_or_hooks(cfg) is False

    def test_ffi_true(self):
        import tomllib
        cfg = tomllib.loads(_FOUNDRY_TOML_FFI)
        assert _has_ffi_or_hooks(cfg) is True

    def test_build_hook(self):
        import tomllib
        cfg = tomllib.loads(_FOUNDRY_TOML_HOOK)
        assert _has_ffi_or_hooks(cfg) is True

    def test_empty_cfg(self):
        assert _has_ffi_or_hooks({}) is False

    def test_ffi_false_explicit(self):
        cfg = {"profile": {"default": {"ffi": False}}}
        assert _has_ffi_or_hooks(cfg) is False


# ---------------------------------------------------------------------------
# _npm_only_reason
# ---------------------------------------------------------------------------

class TestNpmOnlyReason:
    def test_no_package_json(self):
        files = {"src/A.sol": _SIMPLE_CONTRACT}
        assert _npm_only_reason(files, {}) is None

    def test_package_json_with_oz_no_in_tree_deps(self):
        files = {
            "src/A.sol": _SIMPLE_CONTRACT,
            "package.json": json.dumps({"dependencies": {"@openzeppelin/contracts": "^5.0.0"}}),
        }
        reason = _npm_only_reason(files, {"submodules": []})
        assert reason == "npm_only_deps"

    def test_package_json_with_intree_lib(self):
        files = {
            "src/A.sol": _SIMPLE_CONTRACT,
            "package.json": json.dumps({"dependencies": {"@openzeppelin/contracts": "^5.0.0"}}),
            "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol": "// openzeppelin",
        }
        assert _npm_only_reason(files, {"submodules": []}) is None

    def test_package_json_with_fetched_submodule(self):
        files = {
            "src/A.sol": _SIMPLE_CONTRACT,
            "package.json": json.dumps({"dependencies": {"@openzeppelin/contracts": "^5.0.0"}}),
        }
        manifest = {"submodules": [{"path": "lib/oz", "status": "fetched", "url": "https://github.com/oz/oz"}]}
        assert _npm_only_reason(files, manifest) is None

    def test_package_json_unrelated_no_npm_sol(self):
        # package.json that doesn't reference solidity/contracts/hardhat/foundry
        files = {
            "src/A.sol": _SIMPLE_CONTRACT,
            "package.json": json.dumps({"dependencies": {"lodash": "^4.0.0"}}),
        }
        # Should not be flagged as npm_only since no solidity-related deps
        assert _npm_only_reason(files, {}) is None

    def test_package_json_oz_test_helpers_not_sol_dep(self):
        # @openzeppelin/test-helpers is JavaScript (not Solidity source) → not npm-only.
        # Mirrors Uniswap v2-core pattern: description mentions "contracts" but the
        # actual devDependency is a JS testing helper, not a Solidity compile-time dep.
        files = {
            "contracts/Token.sol": _SIMPLE_CONTRACT,
            "package.json": json.dumps({
                "name": "@project/core",
                "description": "Core smart contracts of the protocol",
                "devDependencies": {"@openzeppelin/test-helpers": "^0.5.16", "truffle": "^5.0.0"},
            }),
        }
        assert _npm_only_reason(files, {"submodules": []}) is None

    def test_package_json_oz_contracts_still_npm_only(self):
        # @openzeppelin/contracts IS a Solidity source dep → npm-only (unchanged from before).
        files = {
            "src/A.sol": _SIMPLE_CONTRACT,
            "package.json": json.dumps({"dependencies": {"@openzeppelin/contracts": "^5.0.0"}}),
        }
        assert _npm_only_reason(files, {"submodules": []}) == "npm_only_deps"

    def test_package_json_oz_upgradeable_npm_only(self):
        # @openzeppelin/contracts-upgradeable is a Solidity source dep → npm-only.
        files = {
            "src/A.sol": _SIMPLE_CONTRACT,
            "package.json": json.dumps({"dependencies": {"@openzeppelin/contracts-upgradeable": "^5.0.0"}}),
        }
        assert _npm_only_reason(files, {"submodules": []}) == "npm_only_deps"


# ---------------------------------------------------------------------------
# _select_scope_files
# ---------------------------------------------------------------------------

class TestSelectScopeFiles:
    def test_src_only(self):
        import tomllib
        cfg = tomllib.loads(_FOUNDRY_TOML_BASIC)
        files = {
            "src/Counter.sol": _SIMPLE_CONTRACT,
            "test/Counter.t.sol": "// test",
            "script/Deploy.s.sol": "// script",
            "lib/oz/ERC20.sol": "// dep",
        }
        scope = _select_scope_files(files, cfg)
        assert "src/Counter.sol" in scope
        assert "test/Counter.t.sol" not in scope
        assert "script/Deploy.s.sol" not in scope
        assert "lib/oz/ERC20.sol" not in scope

    def test_no_foundry_cfg(self):
        files = {
            "contracts/Token.sol": _SIMPLE_CONTRACT,
            "test/Token.t.sol": "// test",
        }
        scope = _select_scope_files(files, {})
        assert "contracts/Token.sol" in scope
        assert "test/Token.t.sol" not in scope

    def test_node_modules_excluded(self):
        files = {"node_modules/@oz/ERC20.sol": "// dep", "src/A.sol": _SIMPLE_CONTRACT}
        scope = _select_scope_files(files, {})
        assert "node_modules/@oz/ERC20.sol" not in scope


# ---------------------------------------------------------------------------
# Integration: repo_candidate_from_manifest
# ---------------------------------------------------------------------------

class TestRepoCandidateFromManifest:
    def test_basic_foundry_repo(self, tmp_path):
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": _FOUNDRY_TOML_BASIC,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.provider == "repo"
        assert cand.untrusted_inputs is False
        assert "src/Counter.sol" in cand.files

    def test_ffi_true_sets_untrusted(self, tmp_path):
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": _FOUNDRY_TOML_FFI,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.untrusted_inputs is True

    def test_npm_only_repo_gives_insufficient_source(self, tmp_path):
        pkg = json.dumps({"dependencies": {"@openzeppelin/contracts": "^5.0.0",
                                            "hardhat": "^2.0.0"}})
        src, manifest = _make_src(tmp_path, {
            "src/Counter.sol": _SIMPLE_CONTRACT,
            "package.json": pkg,
        })
        cand, reason = _rcfm(src, manifest)
        assert cand is None
        assert reason == "npm_only_deps"

    def test_remapping_escaping_tree_dropped(self, tmp_path):
        """Remappings with absolute or .. targets are silently dropped (fail closed)."""
        foundry_with_bad_remap = """\
[profile.default]
src = "src"
remappings = [
    "@oz/=lib/oz/",
    "evil/=/etc/contracts/",
    "traversal/=../../outside/",
]
"""
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": foundry_with_bad_remap,
            "src/Counter.sol": _SIMPLE_CONTRACT,
            "lib/oz/ERC20.sol": "// dep",
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        # Only the safe remapping should survive
        remaps = cand.settings.get("remappings", [])
        assert any("@oz/" in r for r in remaps)
        assert all("/etc/" not in r for r in remaps)
        assert all("../../" not in r for r in remaps)

    def test_no_sol_files_gives_insufficient_source(self, tmp_path):
        src, manifest = _make_src(tmp_path, {
            "README.md": "# Hello",
            "foundry.toml": _FOUNDRY_TOML_BASIC,
        })
        cand, reason = _rcfm(src, manifest)
        assert cand is None
        assert reason in ("no_solidity_sources", "compiler_version_unknown")

    def test_submodule_refused_host_does_not_block_candidate(self, tmp_path):
        """A submodule on a non-allowlisted host appears in manifest.refused but the
        repo candidate still succeeds for the in-tree source (fail open for the repo
        source itself, fail closed only for the refused submodule)."""
        src, manifest = _make_src(tmp_path, {
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        # Inject a refused submodule (as git_materializer would record)
        manifest["submodules"] = [{
            "path": "lib/evil",
            "commit": "a" * 40,
            "url": "https://bitbucket.org/evil/repo",
            "status": "refused_host",
        }]
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None

    def test_in_tree_deps_not_npm_only(self, tmp_path):
        pkg = json.dumps({"dependencies": {"@openzeppelin/contracts": "^5.0.0"}})
        src, manifest = _make_src(tmp_path, {
            "src/Counter.sol": _SIMPLE_CONTRACT,
            "package.json": pkg,
            "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol": "// openzeppelin",
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None

    def test_explorer_candidate_supplies_compiler(self, tmp_path):
        """When an explorer candidate is given, its compiler version is used (plan 05 13.3)."""
        from soken_review.adapters.base import Candidate as Cand
        from soken_review.adapters.base import Compiler as Comp
        src, manifest = _make_src(tmp_path, {
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        explorer = Cand(
            provider="sourcify",
            files={},
            sha256="aa" * 32,
            language="solidity",
            compiler=Comp(version="0.8.24+commit.e11b9ed9", version_pinned_by="sourcify"),
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        cand, reason = _rcfm(src, manifest, explorer_candidate=explorer)
        assert reason is None
        assert cand is not None
        assert cand.compiler is not None
        assert "0.8.24" in cand.compiler.version

    def test_no_files_in_manifest(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        manifest = {"schema": "soken-fetch.v1", "resolved_commit": "a" * 40,
                    "files": [], "submodules": [], "too_large": [], "refused": []}
        cand, reason = _rcfm(src, manifest)
        assert cand is None
        assert reason == "no_files"

    def test_missing_ref_from_manifest_file(self, tmp_path):
        """A path in the manifest that doesn't exist on disk is silently skipped."""
        src = tmp_path / "src"
        src.mkdir()
        manifest = {
            "schema": "soken-fetch.v1",
            "resolved_commit": "a" * 40,
            "files": [{"path": "src/Missing.sol", "size": 100, "sha256": "aa" * 32}],
            "submodules": [],
        }
        # File is listed but not written — should not crash, just get no_files
        cand, reason = _rcfm(src, manifest)
        assert cand is None
        assert reason in ("no_files", "no_solidity_sources", "compiler_version_unknown")

    def test_symlinked_dir_in_middle_of_path_is_refused(self, tmp_path):
        """A symlink that replaces a directory component is refused (O_NOFOLLOW on dirs).

        Attack: attacker writes lib -> /etc so src_dir/lib/oz/ERC20.sol reads from /etc.
        The safe reader opens every component with O_NOFOLLOW, so the symlink is
        detected at the directory level and the entry is refused (not read).
        This is the TOCTOU/symlink-in-middle-of-path attack the coordinator flagged.
        """
        src = tmp_path / "repo"
        src.mkdir()
        (src / "src").mkdir()
        (src / "src" / "Counter.sol").write_text(_SIMPLE_CONTRACT, encoding="utf-8")
        # lib -> /etc (or any existing dir): simulates git clone output tampered after
        # the materializer ran, or a materializer that doesn't strip symlinks.
        (src / "lib").symlink_to("/etc")
        manifest = {
            "schema": "soken-fetch.v1",
            "resolved_commit": "a" * 40,
            "files": [
                {"path": "src/Counter.sol", "size": len(_SIMPLE_CONTRACT), "sha256": "aa" * 32},
                # This path passes through the symlinked 'lib' directory
                {"path": "lib/oz/ERC20.sol", "size": 10, "sha256": "bb" * 32},
            ],
            "submodules": [],
        }
        # Must not raise; the lib/oz/ERC20.sol entry is refused but src/Counter.sol is read.
        # The candidate should still succeed for the in-scope source.
        cand, reason = _rcfm(src, manifest)
        # src/Counter.sol is readable → candidate succeeds
        assert cand is not None, f"Expected candidate, got reason={reason!r}"
        # The symlinked lib path must NOT appear in the files
        assert not any("lib" in p for p in (cand.files or {})), \
            "lib/ files should have been refused (symlink)"

    def test_symlink_as_last_component_is_refused(self, tmp_path):
        """A symlink as the last component of a file path is refused.

        The safe reader uses O_NOFOLLOW on the file open itself, so even a symlink
        to a legitimate file is refused.
        """
        src = tmp_path / "repo"
        src.mkdir()
        (src / "src").mkdir()
        # Write the real file elsewhere
        real = tmp_path / "real_contract.sol"
        real.write_text(_SIMPLE_CONTRACT, encoding="utf-8")
        # Create symlink as the .sol file
        (src / "src" / "Counter.sol").symlink_to(real)
        manifest = {
            "schema": "soken-fetch.v1",
            "resolved_commit": "a" * 40,
            "files": [
                {"path": "src/Counter.sol", "size": len(_SIMPLE_CONTRACT), "sha256": "aa" * 32},
            ],
            "submodules": [],
        }
        # The symlink file is refused → no readable .sol → no_files or no_solidity_sources
        cand, reason = _rcfm(src, manifest)
        assert cand is None, "Symlink file should be refused, candidate should be None"
        assert reason in ("no_files", "no_solidity_sources", "compiler_version_unknown")

    # ------------------------------------------------------------------
    # Provenance / trust label tests (coordinator fix 2)
    # ------------------------------------------------------------------

    def test_refused_sol_paths_recorded_in_candidate(self, tmp_path):
        """Refused .sol paths are stored in cand.refused_paths, not silently dropped."""
        src = tmp_path / "repo"
        src.mkdir()
        (src / "src").mkdir()
        (src / "src" / "Counter.sol").write_text(_SIMPLE_CONTRACT, encoding="utf-8")
        # Add a symlink that would be a .sol file
        real = tmp_path / "real.sol"
        real.write_text("// dep", encoding="utf-8")
        (src / "src" / "Evil.sol").symlink_to(real)
        manifest = {
            "schema": "soken-fetch.v1",
            "resolved_commit": "a" * 40,
            "files": [
                {"path": "src/Counter.sol", "size": len(_SIMPLE_CONTRACT), "sha256": "aa" * 32},
                {"path": "src/Evil.sol", "size": 6, "sha256": "bb" * 32},
            ],
            "submodules": [],
        }
        cand, reason = _rcfm(src, manifest)
        # Counter.sol is still readable → candidate succeeds
        assert cand is not None, f"Expected candidate, got reason={reason!r}"
        # The refused symlink path must appear in refused_paths
        assert cand.refused_paths, "refused_paths should be non-empty"
        assert any("Evil.sol" in p or "symlink" in p for p in cand.refused_paths)

    def test_compiler_from_foundry_toml_solc_pin(self, tmp_path):
        """When foundry.toml has `solc = `, version_pinned_by is 'config', not 'pragma_guess'."""
        foundry_with_solc = _FOUNDRY_TOML_BASIC + '\nsolc = "0.8.24"\n'
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": foundry_with_solc,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.compiler is not None
        assert cand.compiler.version_pinned_by == "config"
        assert "0.8.24" in cand.compiler.version

    def test_pragma_guess_does_not_give_tier_a_label(self, tmp_path):
        """Without a pinned compiler, version_pinned_by is 'pragma_guess' (no tier A)."""
        # No foundry.toml solc pin, no explorer candidate
        src, manifest = _make_src(tmp_path, {
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.compiler is not None
        assert cand.compiler.version_pinned_by == "pragma_guess"

    def test_source_url_set_from_param(self, tmp_path):
        """source_url is set from the supervisor-supplied repo_url@sha (not None)."""
        src, manifest = _make_src(tmp_path, {
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        url = "https://github.com/example/repo@" + "a" * 40
        cand, reason = _rcfm(src, manifest, source_url=url)
        assert reason is None
        assert cand is not None
        assert cand.source_url == url

    def test_explorer_verified_false_without_deployment_comparison(self, tmp_path):
        """explorer_verified is always False for a repo candidate (no 13.1 comparison done)."""
        from soken_review.adapters.base import Candidate as Cand
        from soken_review.adapters.base import Compiler as Comp
        src, manifest = _make_src(tmp_path, {"src/Counter.sol": _SIMPLE_CONTRACT})
        explorer = Cand(
            provider="sourcify",
            files={},
            sha256="aa" * 32,
            language="solidity",
            compiler=Comp(version="0.8.24+commit.e11b9ed9", version_pinned_by="sourcify"),
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        cand, reason = _rcfm(src, manifest, explorer_candidate=explorer)
        assert reason is None
        assert cand is not None
        # A repo candidate never claims explorer_verified=True (that is only set after 13.1)
        assert cand.explorer_verified is False

    def test_untrusted_ffi_repo_never_tier_a(self, tmp_path):
        """A repo with ffi=true sets untrusted_inputs=True, which blocks tier A."""
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": _FOUNDRY_TOML_FFI,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, _reason = _rcfm(src, manifest)
        assert cand is not None
        assert cand.untrusted_inputs is True
        # untrusted_inputs=True means tier B at most (provenance.py checks this)

    def test_source_url_none_fails(self, tmp_path):
        """source_url=None must return (None, 'source_url_required') — no silent unknown provenance."""
        src, manifest = _make_src(tmp_path, {"src/Counter.sol": _SIMPLE_CONTRACT})
        cand, reason = repo_candidate_from_manifest(src, manifest, source_url=None)
        assert cand is None
        assert reason == "source_url_required"

    def test_range_version_in_foundry_toml_gives_pragma_guess(self, tmp_path):
        """A semver range in foundry.toml solc does NOT give version_pinned_by='config'."""
        foundry_range = _FOUNDRY_TOML_BASIC + '\nsolc = "^0.8.0"\n'
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": foundry_range,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.compiler is not None
        # A range is not a pin — must fall back to pragma_guess
        assert cand.compiler.version_pinned_by == "pragma_guess", \
            f"Expected pragma_guess, got {cand.compiler.version_pinned_by!r}"

    def test_explorer_verified_never_true_for_repo_candidate(self, tmp_path):
        """explorer_verified is always False for provider=repo regardless of inputs."""
        from soken_review.adapters.base import Candidate as Cand
        from soken_review.adapters.base import Compiler as Comp
        src, manifest = _make_src(tmp_path, {"src/Counter.sol": _SIMPLE_CONTRACT})
        explorer = Cand(
            provider="sourcify", files={}, sha256="aa" * 32,
            language="solidity",
            compiler=Comp(version="0.8.24+commit.e11b9ed9", version_pinned_by="sourcify"),
            settings={}, std_json_input=None, entry_contract=None,
            explorer_verified=True,  # explorer itself is verified — repo candidate must NOT be
        )
        cand, reason = _rcfm(src, manifest, explorer_candidate=explorer)
        assert reason is None
        assert cand is not None
        assert cand.explorer_verified is False, "Repo candidate must never set explorer_verified=True"


# ---------------------------------------------------------------------------
# Forge compiler trust-issue tests (coordinator security finding 2026-10-13)
# ---------------------------------------------------------------------------

class TestForgeCompilerTrustIssues:
    """Repos that could substitute the compiler must get untrusted_inputs=True.

    Three distinct attack surfaces:
      1. .env file containing FOUNDRY_* keys → env-var override of solc path/settings
      2. auto_detect_solc = true in foundry.toml → forge would download/pick a compiler
      3. solc = "./bin/solc" in foundry.toml → forge would use a repo-committed binary
    Each is tested independently so regressions in any one are immediately visible.
    """

    def test_env_foundry_key_sets_untrusted(self, tmp_path):
        """A .env file with FOUNDRY_* keys can override the compiler path → untrusted."""
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": _FOUNDRY_TOML_BASIC,
            "src/Counter.sol": _SIMPLE_CONTRACT,
            ".env": "FOUNDRY_SOLC=/usr/bin/solc-attacker\nFOO=bar\n",
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.untrusted_inputs is True, (
            ".env with FOUNDRY_* key must set untrusted_inputs=True"
        )

    def test_env_foundry_key_case_insensitive(self, tmp_path):
        """FOUNDRY_ detection is case-insensitive (env vars are uppercase but belt-and-braces)."""
        env_content = "foundry_profile=attack\n"
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": _FOUNDRY_TOML_BASIC,
            "src/Counter.sol": _SIMPLE_CONTRACT,
            ".env": env_content,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.untrusted_inputs is True

    def test_auto_detect_solc_sets_untrusted(self, tmp_path):
        """auto_detect_solc = true lets forge download/auto-select a compiler → untrusted."""
        foundry_toml = _FOUNDRY_TOML_BASIC + "\nauto_detect_solc = true\n"
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": foundry_toml,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.untrusted_inputs is True, (
            "auto_detect_solc=true must set untrusted_inputs=True"
        )

    def test_solc_path_sets_untrusted(self, tmp_path):
        """solc = './bin/solc' in foundry.toml points to a repo-committed binary → untrusted."""
        foundry_toml = _FOUNDRY_TOML_BASIC + '\nsolc = "./bin/fake-solc"\n'
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": foundry_toml,
            "src/Counter.sol": _SIMPLE_CONTRACT,
            "bin/fake-solc": "#!/bin/sh\nexec /bin/false",
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.untrusted_inputs is True, (
            "solc path value in foundry.toml must set untrusted_inputs=True"
        )

    def test_clean_repo_not_untrusted(self, tmp_path):
        """A clean repo with no trust issues must NOT be flagged untrusted by the new checks."""
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": _FOUNDRY_TOML_BASIC,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.untrusted_inputs is False, (
            "Clean repo with no trust issues must have untrusted_inputs=False"
        )

    def test_solc_range_sets_untrusted(self, tmp_path):
        """Finding 4 allow-list: solc = '^0.8.0' is a range, not a bare semver → untrusted."""
        foundry_toml = _FOUNDRY_TOML_BASIC + '\nsolc = "^0.8.0"\n'
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": foundry_toml,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, reason = _rcfm(src, manifest)
        assert reason is None
        assert cand is not None
        assert cand.untrusted_inputs is True, (
            "solc range '^0.8.0' must set untrusted_inputs=True (allow-list fix)"
        )

    def test_solc_ge_range_sets_untrusted(self, tmp_path):
        """solc = '>=0.7.0 <0.9.0' → untrusted (allow-list)."""
        foundry_toml = _FOUNDRY_TOML_BASIC + '\nsolc = ">=0.7.0 <0.9.0"\n'
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": foundry_toml,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, _reason = _rcfm(src, manifest)
        assert cand is not None
        assert cand.untrusted_inputs is True

    def test_solc_exact_semver_trusted(self, tmp_path):
        """solc = '0.8.24' (exact semver, no prefix) → trusted (allow-list)."""
        foundry_toml = _FOUNDRY_TOML_BASIC + '\nsolc = "0.8.24"\n'
        src, manifest = _make_src(tmp_path, {
            "foundry.toml": foundry_toml,
            "src/Counter.sol": _SIMPLE_CONTRACT,
        })
        cand, _reason = _rcfm(src, manifest)
        assert cand is not None
        assert cand.untrusted_inputs is False, (
            "Exact semver '0.8.24' must NOT set untrusted (allow-list)"
        )
