"""solc version choice (held-out friction 2026-10-27): config pins first, then the newest release
satisfying every pragma of the scope and its imports, never the floor; files mode honours
review_start remappings, compiler_version and npm-style paths (Wallitelli six-file set)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.adapters.evm import solc_select as sel
from soken_review.adapters.evm.build import _prepare_std_input
from soken_review.adapters.evm.files import files_candidate
from soken_review.adapters.evm.npm_deps import import_closure
from soken_review.adapters.evm.repo_candidate import repo_candidate_from_manifest

BUILDS = [
    {"version": v, "longVersion": f"{v}+commit.{i:08d}"}
    for i, v in enumerate(["0.7.6", "0.8.0", "0.8.4", "0.8.12", "0.8.17", "0.8.19", "0.8.24", "0.9.0"])
] + [{"version": "0.8.30", "longVersion": "0.8.30-nightly", "prerelease": "nightly"}]

CUSTOM_ERRORS = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Farm {
    error ZeroAddress();
    address public owner;
    function set(address a) external { if (a == address(0)) revert ZeroAddress(); owner = a; }
}
"""

HH_OBJECT = """require('hardhat-deploy');
module.exports = {
    solidity: {
        version: '0.8.17',
        settings: { optimizer: { enabled: true, runs: 1000000 } },
    },
    networks: {},
};
"""


def _manifest(files: dict[str, str]) -> dict:
    return {"version": "soken-fetch.v1", "files": [{"path": p, "sha256": "0" * 64} for p in files]}


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    src = tmp_path / "src"
    for rel, text in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text, encoding="utf-8")
    return src


def _repo(tmp_path: Path, files: dict[str, str], **kw):
    src = _tree(tmp_path, files)
    kw.setdefault("source_url", "https://github.com/example/repo@" + "a" * 40)
    kw.setdefault("builds", BUILDS)
    return repo_candidate_from_manifest(src, _manifest(files), **kw)


# ── config pins ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize(("name", "text", "want"), [
    ("hardhat.config.js", "module.exports = { solidity: '0.8.12', networks: {} };", [("0.8.12", "hardhat.config.js")]),
    ("hardhat.config.js", HH_OBJECT, [("0.8.17", "hardhat.config.js")]),
    ("hardhat.config.ts", 'const config: HardhatUserConfig = {\n solidity: {\n compilers: [{ version: "0.8.19" }, { version: "0.7.6" }],\n },\n};\n',
     [("0.8.19", "hardhat.config.ts"), ("0.7.6", "hardhat.config.ts")]),
    ("truffle-config.js", 'module.exports = { compilers: { solc: { version: "0.8.4", settings: {} } } };', [("0.8.4", "truffle-config.js")]),
    ("hardhat.config.js", "module.exports = { solidity: '^0.8.0' };", []),   # a range is not a pin
])
def test_config_versions(name, text, want):
    assert sel.config_versions({name: text}) == want


def test_nested_config_is_not_the_project_pin():
    assert sel.config_versions({"packages/x/hardhat.config.js": "module.exports = { solidity: '0.8.12' };"}) == []


def test_pick_config_version_prefers_one_that_satisfies_the_pragmas():
    config = [("0.8.19", "hardhat.config.ts"), ("0.7.6", "hardhat.config.ts")]
    assert sel.pick_config_version(config, ["^0.8.0"]) == ("0.8.19", "hardhat.config.ts")
    # none fits: the newest pin still wins (the build retry then finds a satisfying release)
    assert sel.pick_config_version([("0.7.6", "truffle-config.js")], ["^0.8.4"]) == ("0.7.6", "truffle-config.js")


# ── pragma rule ──────────────────────────────────────────────────────────────

def test_newest_satisfying_never_the_floor():
    assert sel.newest_satisfying(["^0.8.0"], BUILDS) == "0.8.24+commit.00000006"
    assert sel.newest_satisfying(["^0.8.0", ">=0.8.4 <0.8.20"], BUILDS) == "0.8.19+commit.00000005"
    assert sel.newest_satisfying(["0.6.12"], BUILDS) is None
    assert sel.floor_version(["^0.8.0", ">=0.8.4"]) == "0.8.4"


def test_choose_pragma_version_falls_back_to_floor_without_release_list():
    assert sel.choose_pragma_version(["^0.8.0"], BUILDS) == ("0.8.24+commit.00000006", "pragma")
    assert sel.choose_pragma_version(["^0.8.0"], []) == ("0.8.0", "pragma_guess")
    assert sel.choose_pragma_version(["^0.8.0"], None) == ("0.8.0", "pragma_guess")


def test_is_parse_error():
    assert sel.is_parse_error("ParserError: Expected identifier but got 'error'\n --> contracts/Farm.sol:5:5")
    assert not sel.is_parse_error("TypeError: Member \"x\" not found")
    assert not sel.is_parse_error(None)


def test_pinned_by_text_names_the_source():
    assert "pragma" in sel.pinned_by_text("pragma") and "config" in sel.pinned_by_text("config")
    assert sel.pinned_by_text("user").startswith("compiler_version")


# ── repo candidate ───────────────────────────────────────────────────────────

def test_repo_caret_pragma_with_custom_errors_gets_newest_satisfying_release(tmp_path):
    cand, reason = _repo(tmp_path, {"contracts/Farm.sol": CUSTOM_ERRORS})
    assert reason is None and cand is not None
    assert cand.compiler.version == "0.8.24+commit.00000006"
    assert cand.compiler.version_pinned_by == "pragma"


def test_repo_hardhat_config_pin_wins(tmp_path):
    cand, _ = _repo(tmp_path, {"contracts/Farm.sol": CUSTOM_ERRORS, "hardhat.config.js": HH_OBJECT})
    assert cand.compiler.version == "0.8.17" and cand.compiler.version_pinned_by == "config"


def test_repo_truffle_pin(tmp_path):
    cand, _ = _repo(tmp_path, {"contracts/Farm.sol": CUSTOM_ERRORS,
                               "truffle-config.js": 'module.exports = { compilers: { solc: { version: "0.8.12" } } };'})
    assert cand.compiler.version == "0.8.12" and cand.compiler.version_pinned_by == "config"


def test_repo_import_closure_pragmas_narrow_the_choice(tmp_path):
    files = {
        "contracts/Farm.sol": 'pragma solidity ^0.8.0;\nimport "@oz/Lib.sol";\ncontract Farm is Lib {}\n',
        "node_modules/@oz/Lib.sol": "pragma solidity >=0.8.4 <0.8.20;\ncontract Lib {}\n",
        "package.json": json.dumps({"dependencies": {"@oz": "1.0.0"}}),
    }
    cand, _ = _repo(tmp_path, files, extra_remappings=["@oz/=node_modules/@oz/"])
    assert cand.compiler.version == "0.8.19+commit.00000005"
    assert sorted(cand.files) == ["contracts/Farm.sol"]   # the dependency is not scope


def test_repo_without_release_list_uses_the_floor_as_pragma_guess(tmp_path):
    cand, _ = _repo(tmp_path, {"contracts/Farm.sol": CUSTOM_ERRORS}, builds=[])
    assert cand.compiler.version == "0.8.0" and cand.compiler.version_pinned_by == "pragma_guess"


# ── files mode: Wallitelli six-file shape ────────────────────────────────────

OZ = "lib/openzeppelin-contracts/contracts"
WALLITELLI = {
    "contracts/WallitelliToken.sol": (
        "// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.28;\n\n"
        'import "@openzeppelin/contracts/token/ERC20/ERC20.sol";\n\n'
        "contract WallitelliToken is ERC20 {\n    string public constant VERSION = \"Wallitelli-v1\";\n"
        "    constructor() ERC20(\"Wallitelli\", \"WALLI\") {\n        _mint(msg.sender, 1_000_000_000 * 10 ** decimals());\n    }\n}\n"),
    f"{OZ}/token/ERC20/ERC20.sol": (
        "pragma solidity ^0.8.20;\n"
        'import {IERC20} from "./IERC20.sol";\nimport {IERC20Metadata} from "./extensions/IERC20Metadata.sol";\n'
        'import {Context} from "../../utils/Context.sol";\nimport {IERC20Errors} from "../../interfaces/draft-IERC6093.sol";\n'
        "abstract contract ERC20 is Context, IERC20, IERC20Metadata, IERC20Errors { mapping(address => uint256) private _balances; }\n"),
    f"{OZ}/token/ERC20/IERC20.sol": "pragma solidity ^0.8.20;\ninterface IERC20 { function totalSupply() external view returns (uint256); }\n",
    f"{OZ}/token/ERC20/extensions/IERC20Metadata.sol": (
        'pragma solidity ^0.8.20;\nimport {IERC20} from "../IERC20.sol";\ninterface IERC20Metadata is IERC20 { function decimals() external view returns (uint8); }\n'),
    f"{OZ}/utils/Context.sol": "pragma solidity ^0.8.20;\nabstract contract Context { function _msgSender() internal view virtual returns (address) { return msg.sender; } }\n",
    f"{OZ}/interfaces/draft-IERC6093.sol": "pragma solidity ^0.8.20;\ninterface IERC20Errors { error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed); }\n",
}
REMAP = "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"
BUILDS_28 = BUILDS + [{"version": "0.8.28", "longVersion": "0.8.28+commit.7893614a"}]


def _as_files(mapping: dict[str, str]) -> list[dict[str, str]]:
    return [{"path": p, "content": c} for p, c in mapping.items()]


def test_files_mode_honours_review_start_remappings_and_compiler_version():
    cand = files_candidate(_as_files(WALLITELLI), builds=BUILDS_28, remappings=[REMAP], compiler_version="0.8.28")
    assert cand is not None and len(cand.files) == 6
    assert cand.settings["remappings"] == [REMAP]
    assert cand.compiler.version == "0.8.28+commit.7893614a" and cand.compiler.version_pinned_by == "user"
    # every import resolves through the remapping: nothing is left for E_DEPENDENCY_UNRESOLVED
    visited, missing = import_closure(["contracts/WallitelliToken.sol"], cand.files, cand.settings["remappings"])
    assert missing == [] and visited == set(cand.files)
    # and the solc Standard JSON carries the remapping with all six sources
    std = _prepare_std_input(cand)
    assert std["settings"]["remappings"] == [REMAP] and len(std["sources"]) == 6


def test_files_mode_accepts_npm_style_paths_without_remappings():
    npm = {("@openzeppelin/contracts" + p[len(OZ):] if p.startswith(OZ) else p): c for p, c in WALLITELLI.items()}
    cand = files_candidate(_as_files(npm), builds=BUILDS_28)
    assert cand is not None and "@openzeppelin/contracts/token/ERC20/ERC20.sol" in cand.files
    _visited, missing = import_closure(["contracts/WallitelliToken.sol"], cand.files, [])
    assert missing == []
    assert cand.compiler.version == "0.8.28+commit.7893614a" and cand.compiler.version_pinned_by == "pragma"


def test_files_mode_node_modules_paths_resolve_like_solc():
    nm = {("node_modules/@openzeppelin/contracts" + p[len(OZ):] if p.startswith(OZ) else p): c for p, c in WALLITELLI.items()}
    cand = files_candidate(_as_files(nm), builds=BUILDS_28)
    _visited, missing = import_closure(["contracts/WallitelliToken.sol"], cand.files, [])
    assert missing == []


def test_files_mode_compiler_version_outside_the_pragmas_is_not_used():
    cand = files_candidate(_as_files(WALLITELLI), builds=BUILDS_28, remappings=[REMAP], compiler_version="0.8.19")
    assert cand.compiler.version == "0.8.28+commit.7893614a" and cand.compiler.version_pinned_by == "pragma"


def test_files_mode_hardhat_config_among_pasted_files_is_a_config_pin():
    files = _as_files({"contracts/Farm.sol": CUSTOM_ERRORS, "hardhat.config.js": HH_OBJECT})
    cand = files_candidate(files, builds=BUILDS)
    assert cand.compiler.version == "0.8.17+commit.00000004" and cand.compiler.version_pinned_by == "config"


def test_files_mode_caret_pragma_never_builds_at_the_floor():
    cand = files_candidate(_as_files({"contracts/Farm.sol": CUSTOM_ERRORS}), builds=BUILDS)
    assert cand.compiler.version == "0.8.24+commit.00000006"
