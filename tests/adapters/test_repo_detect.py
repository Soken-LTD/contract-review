"""adapters/repo_detect: family of a repo tree that holds no Solidity (road-to-prod item 4)."""

from __future__ import annotations

import pytest

from soken_review.adapters.repo_detect import RepoFamily, Undetected, detect_repo_family

SUI_MANIFEST = """[package]
name = "counter"
edition = "2024.beta"

[dependencies]
Sui = { git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "framework/mainnet" }

[addresses]
counter = "0x0"
"""

APTOS_MANIFEST = """[package]
name = "vault"
version = "1.0.0"

[dependencies]
AptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git", subdir = "aptos-move/framework/aptos-framework", rev = "mainnet" }

[addresses]
vault = "_"
"""

SCARB_MANIFEST = """[package]
name = "token"
version = "0.1.0"

[dependencies]
starknet = "2.13.1"
"""


def test_scarb_at_root_is_starknet():
    found = detect_repo_family({"Scarb.toml": SCARB_MANIFEST, "src/lib.cairo": "mod token;"})
    assert found == RepoFamily("starknet", "", "Scarb.toml")


def test_scarb_in_one_subdir_picks_that_dir():
    files = {"README.md": "x", "contracts/Scarb.toml": SCARB_MANIFEST, "contracts/src/lib.cairo": ""}
    assert detect_repo_family(files) == RepoFamily("starknet", "contracts", "contracts/Scarb.toml")


def test_scarb_workspace_root_wins_over_members():
    files = {
        "Scarb.toml": "[workspace]\nmembers = [\"packages/a\", \"packages/b\"]\n",
        "packages/a/Scarb.toml": SCARB_MANIFEST, "packages/b/Scarb.toml": SCARB_MANIFEST,
    }
    assert detect_repo_family(files).package_dir == ""


def test_several_scarb_members_without_workspace_scope_the_tree_root():
    files = {"packages/a/Scarb.toml": SCARB_MANIFEST, "packages/b/Scarb.toml": SCARB_MANIFEST}
    found = detect_repo_family(files)
    assert isinstance(found, RepoFamily) and found.chain == "starknet" and found.package_dir == ""


def test_requested_subdir_must_hold_the_manifest():
    files = {"packages/a/Scarb.toml": SCARB_MANIFEST, "packages/b/Scarb.toml": SCARB_MANIFEST}
    assert detect_repo_family(files, "packages/b/").package_dir == "packages/b"
    assert detect_repo_family(files, "packages/c") == Undetected(
        "ambiguous_package", ("packages/a/Scarb.toml", "packages/b/Scarb.toml"))


def test_dependency_and_build_dirs_are_ignored():
    files = {"deps/openzeppelin/Scarb.toml": SCARB_MANIFEST, "target/dev/Scarb.toml": SCARB_MANIFEST,
             ".git/Scarb.toml": SCARB_MANIFEST, "node_modules/x/Move.toml": SUI_MANIFEST}
    assert detect_repo_family(files) == Undetected("no_manifest")


def test_sui_manifest_by_dependency_name():
    assert detect_repo_family({"Move.toml": SUI_MANIFEST, "sources/counter.move": ""}) == RepoFamily("sui", "", "Move.toml")


def test_aptos_manifest_by_framework_dependency():
    assert detect_repo_family({"Move.toml": APTOS_MANIFEST}) == RepoFamily("aptos", "", "Move.toml")


def test_sui_by_git_url_when_the_dependency_name_is_local():
    text = '[package]\nname = "p"\n[dependencies]\nFramework = { git = "https://github.com/MystenLabs/sui.git", rev = "x" }\n'
    assert detect_repo_family({"Move.toml": text}).chain == "sui"


def test_aptos_move_stdlib_from_aptos_core():
    text = '[package]\nname = "p"\n[dependencies]\nMoveStdlib = { git = "https://github.com/aptos-labs/aptos-core.git", subdir = "aptos-move/framework/move-stdlib", rev = "main" }\n'
    assert detect_repo_family({"Move.toml": text}).chain == "aptos"


def test_move_2024_edition_without_framework_dependency_is_sui():
    text = '[package]\nname = "p"\nedition = "2024.beta"\n[dependencies]\n'
    assert detect_repo_family({"Move.toml": text}).chain == "sui"


@pytest.mark.parametrize("text", [
    '[package]\nname = "p"\n[dependencies]\nMoveStdlib = { local = "../stdlib" }\n',
    '[package]\nname = "p"\n[dependencies]\nSui = { local = "x" }\nAptosFramework = { local = "y" }\n',
    "not = toml = at all",
    'package = "scalar"\ndependencies = ["list"]\n',          # wrong shapes: no crash, undecided
])
def test_unknown_or_contradicting_flavour_is_reported(text: str):
    assert detect_repo_family({"Move.toml": text}) == Undetected("unknown_move_flavour", ("Move.toml",))


def test_several_move_packages_need_a_subdir():
    files = {"a/Move.toml": SUI_MANIFEST, "b/Move.toml": SUI_MANIFEST}
    assert detect_repo_family(files) == Undetected("ambiguous_package", ("a/Move.toml", "b/Move.toml"))
    assert detect_repo_family(files, "b") == RepoFamily("sui", "b", "b/Move.toml")


def test_scarb_beats_move_when_both_exist():
    files = {"Scarb.toml": SCARB_MANIFEST, "Move.toml": SUI_MANIFEST}
    assert detect_repo_family(files).chain == "starknet"


def test_oversized_manifest_is_not_parsed():
    text = SUI_MANIFEST + "\n# " + "x" * (70 * 1024)
    assert detect_repo_family({"Move.toml": text}) == Undetected("unknown_move_flavour", ("Move.toml",))
