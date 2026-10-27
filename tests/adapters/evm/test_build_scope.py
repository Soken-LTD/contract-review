"""Build scope of repo candidates (Lambo.win run 2026-10-27, code-423n4/2024-12-lambowin).

The vendored, unused `src/libraries/1inchV6.sol` (`pragma solidity 0.8.23`, library bundle with
a few base contracts) failed the whole src/ build at 0.8.24: no map, no analyzers, 0 leads, and
the report subject said "1inchV6". These tests use the same tree shape."""

from __future__ import annotations

import subprocess

from soken_review.adapters.evm import build_scope as bs
from soken_review.adapters.evm import solc_select as sel

OZ = "lib/openzeppelin-contracts/contracts"
REMAPS = ["@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"]

LAMBO_TREE = {
    f"{OZ}/access/Ownable.sol": "// SPDX\npragma solidity ^0.8.20;\nabstract contract Ownable {}\n",
    f"{OZ}/token/ERC20/IERC20.sol": "pragma solidity ^0.8.20;\ninterface IERC20 {}\n",
    # OpenZeppelin 5.x files at ^0.8.24: with them no single release satisfies every pragma
    f"{OZ}/utils/ReentrancyGuardTransient.sol": "pragma solidity ^0.8.24;\nabstract contract ReentrancyGuardTransient {}\n",
    "src/LamboFactory.sol": (
        "pragma solidity ^0.8.20;\n"
        'import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";\n'
        'import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";\n'
        'import {LamboToken} from "./LamboToken.sol";\n'
        'import {UniswapV2Library} from "./libraries/UniswapV2Library.sol";\n'
        "contract LamboFactory is Ownable {\n" + "    uint256 a;\n" * 40 + "}\n"
    ),
    "src/LamboToken.sol": (
        "pragma solidity ^0.8.20;\n"
        'import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";\n'
        'import {LaunchPadUtils} from "./Utils/LaunchPadUtils.sol";\n'
        "contract LamboToken is IERC20 {}\n"
    ),
    "src/Utils/LaunchPadUtils.sol": "pragma solidity ^0.8.20;\nlibrary LaunchPadUtils {}\n",
    "src/libraries/UniswapV2Library.sol": "pragma solidity ^0.8.20;\nlibrary UniswapV2Library {}\n",
    # vendored, imported by nothing, exact pin, the largest file of the scope
    "src/libraries/1inchV6.sol": (
        "/* 1inch aggregation router v6 */\npragma solidity 0.8.23;\n"
        "library MakerTraitsLib {}\ninterface IOrderMixin {}\n"
        "contract PredicateHelper {}\nabstract contract EthReceiver {}\n" + "// filler\n" * 400
    ),
    "src/interfaces/Curve/IStableNGPool.sol": "pragma solidity ^0.8.23;\ninterface IStableNGPool {}\n",
}
SCOPE = {p: t for p, t in LAMBO_TREE.items() if p.startswith("src/")}


def test_deployable_contracts_skip_abstract_libraries_interfaces_comments_and_strings():
    text = ('pragma solidity ^0.8.0;\n// contract InComment {}\n/* contract InBlock {} */\n'
            'string constant S = "contract InString";\nabstract contract Base {}\nlibrary L {}\n'
            'interface I {}\ncontract Real is Base {}\n')
    assert bs.deployable_contracts(text) == ["Real"]


def test_roots_and_closure_of_the_lambo_tree():
    assert bs.deployable_roots(SCOPE) == ["src/LamboFactory.sol", "src/LamboToken.sol", "src/libraries/1inchV6.sol"]
    closure = bs.closure_files(SCOPE, LAMBO_TREE, REMAPS)
    # the unused Curve interface leaves the build; the reviewed contracts' imports stay
    assert sorted(closure) == ["src/LamboFactory.sol", "src/LamboToken.sol", "src/Utils/LaunchPadUtils.sol",
                               "src/libraries/1inchV6.sol", "src/libraries/UniswapV2Library.sol"]


def test_closure_of_a_library_only_scope_is_the_scope():
    scope = {"src/L.sol": "pragma solidity ^0.8.0;\nlibrary L {}\n", "src/I.sol": "interface I {}\n"}
    assert bs.closure_files(scope, scope, []) == scope


def test_failing_files_from_error_locations_and_pragma_conflicts():
    closure = bs.closure_files(SCOPE, LAMBO_TREE, REMAPS)
    assert bs.failing_files({}, closure, "0.8.24+commit.e11b9ed9") == {"src/libraries/1inchV6.sol"}
    # error locations count only for build files; a dependency is never excluded
    notes = {"error_sources": ["src/LamboToken.sol", f"{OZ}/access/Ownable.sol"]}
    assert bs.failing_files(notes, closure, "0.8.23") == {"src/LamboToken.sol"}
    assert bs.failing_files(None, closure, None) == set()


def test_unused_failing_file_is_excluded_and_the_rest_builds():
    closure = bs.closure_files(SCOPE, LAMBO_TREE, REMAPS)
    plan = bs.plan_exclusion(closure, {"src/libraries/1inchV6.sol"}, LAMBO_TREE, REMAPS)
    assert plan is not None
    kept, excluded = plan
    assert excluded == ["src/libraries/1inchV6.sol"]
    assert "src/libraries/1inchV6.sol" not in kept and "src/LamboFactory.sol" in kept
    # with the vendored file gone the pragmas agree again: one release builds the rest
    exprs = sel.pragma_exprs(sel.closure_sources(kept, LAMBO_TREE, REMAPS))
    assert sel.floor_version(exprs) == "0.8.24"
    assert sel.newest_satisfying(exprs, [{"version": "0.8.28"}]) == "0.8.28"


def test_a_failing_file_a_reviewed_file_imports_is_never_excluded():
    tree = dict(LAMBO_TREE)
    tree["src/LamboToken.sol"] = tree["src/LamboToken.sol"].replace(
        "contract LamboToken", 'import "./libraries/1inchV6.sol";\ncontract LamboToken')
    scope = {p: t for p, t in tree.items() if p.startswith("src/")}
    closure = bs.closure_files(scope, tree, REMAPS)
    assert bs.plan_exclusion(closure, {"src/libraries/1inchV6.sol"}, tree, REMAPS) is None
    # indirect: Factory -> Token -> 1inchV6 is a dependency too
    assert bs.plan_exclusion(closure, {"src/LamboToken.sol"}, tree, REMAPS) is None


def test_nothing_to_exclude_or_nothing_left():
    closure = bs.closure_files(SCOPE, LAMBO_TREE, REMAPS)
    assert bs.plan_exclusion(closure, set(), LAMBO_TREE, REMAPS) is None
    assert bs.plan_exclusion(closure, {"lib/x.sol"}, LAMBO_TREE, REMAPS) is None
    assert bs.plan_exclusion(closure, set(closure), LAMBO_TREE, REMAPS) is None


def test_subject_unit_is_the_main_deployable_contract_never_the_vendored_bundle():
    assert bs.subject_unit(SCOPE) == "src/LamboFactory.sol"
    assert bs.subject_unit(SCOPE, {"src/LamboFactory.sol"}) == "src/LamboToken.sol"
    assert bs.subject_unit({"src/libraries/L.sol": "library L {}\n"}) is None


def test_pragma_choice_when_the_scope_pragmas_conflict():
    exprs = ["^0.8.20", "0.8.23", "^0.8.24"]
    builds = [{"version": v, "longVersion": f"{v}+commit.0000000{i}"} for i, v in enumerate(["0.8.23", "0.8.24", "0.8.28"])]
    # no release satisfies all three: the newest one satisfying most of them, labelled as such
    assert sel.choose_pragma_version(exprs, builds) == ("0.8.28+commit.00000002", "pragma_partial")
    assert "conflict" in sel.pinned_by_text("pragma_partial")
    # without a release list the floor that satisfies every pragma, not the highest literal
    assert sel.floor_version(["^0.8.20", "0.8.23"]) == "0.8.23"
    assert sel.floor_version([">=0.8.0 <0.8.25", "^0.8.20"]) == "0.8.20"
    assert sel.floor_version(["^0.8.0", ">=0.8.4"]) == "0.8.4"


def test_forge_builds_only_the_given_paths_after_the_options(monkeypatch, tmp_path):
    import soken_review.adapters.evm.build as build_mod

    monkeypatch.setattr(build_mod, "_BUILD_IMAGE", "soken/evm-analyze:test")
    monkeypatch.setattr(build_mod, "sandbox_writable_dir", lambda p: (p.mkdir(parents=True, exist_ok=True), p)[1])
    captured: dict = {}

    def fake_docker_argv(**kw):
        captured.update(kw)
        return ["true"]
    monkeypatch.setattr(build_mod, "docker_argv", fake_docker_argv)
    proc_mock = type("P", (), {"communicate": lambda self, timeout=None: (b"", b""), "returncode": 1})()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: proc_mock)
    (tmp_path / "src").mkdir()

    class _FakeCache:
        _root = tmp_path / "cache"
    paths = ["src/LamboFactory.sol", "../etc/passwd.sol", "src/LamboToken.sol"]
    build_mod.forge_build_repo(str(tmp_path / "src"), tmp_path / "out", tmp_path / "linux-amd64" / "solc-0.8.28",
                               _FakeCache(), paths=paths)  # type: ignore[arg-type]
    cmd = captured["command"]
    assert cmd[cmd.index("--"):] == ["--", "src/LamboFactory.sol", "src/LamboToken.sol"]
    captured.clear()
    build_mod.forge_build_repo(str(tmp_path / "src"), tmp_path / "out", tmp_path / "linux-amd64" / "solc-0.8.28",
                               _FakeCache())  # type: ignore[arg-type]
    assert "--" not in captured["command"]
