import pytest

from soken_review.adapters.evm.files import files_candidate, pick_solc, satisfies

BUILDS = [
    {"version": v, "longVersion": f"{v}+commit.0000000{i}"}
    for i, v in enumerate(["0.7.6", "0.8.0", "0.8.19", "0.8.20", "0.8.24", "0.9.0"])
] + [{"version": "0.8.30", "longVersion": "0.8.30-nightly", "prerelease": "nightly"}]


@pytest.mark.parametrize(
    ("expr", "version", "ok"),
    [
        ("^0.8.0", (0, 8, 24), True),
        ("^0.8.0", (0, 9, 0), False),
        (">=0.8.0 <0.8.20", (0, 8, 19), True),
        (">=0.8.0 <0.8.20", (0, 8, 20), False),
        ("0.8.19", (0, 8, 19), True),
        ("=0.8.19", (0, 8, 20), False),
        ("~0.8.19", (0, 8, 24), True),
        ("0.7.6 || ^0.8.20", (0, 7, 6), True),
        ("0.8.x", (0, 8, 24), True),
    ],
)
def test_satisfies(expr, version, ok):
    assert satisfies(expr, version) is ok


def test_newest_release_meeting_every_pragma():
    sources = {"A.sol": "pragma solidity ^0.8.0;", "B.sol": "pragma solidity >=0.8.0 <0.8.21;"}
    assert pick_solc(sources, BUILDS) == "0.8.20+commit.00000003"


def test_no_release_satisfies():
    assert pick_solc({"A.sol": "pragma solidity 0.6.12;"}, BUILDS) is None


def test_candidate_sources_and_remappings():
    cand = files_candidate(
        [
            {"path": "src/A.sol", "content": 'pragma solidity 0.8.19;\nimport "oz/B.sol";'},
            {"path": "lib/oz/B.sol", "content": "pragma solidity ^0.8.0;"},
            {"path": "remappings.txt", "content": "oz/B.sol=lib/oz/B.sol\n"},
        ],
        builds=BUILDS,
    )
    assert sorted(cand.files) == ["lib/oz/B.sol", "src/A.sol"]
    assert cand.settings == {"remappings": ["oz/B.sol=lib/oz/B.sol"]}
    assert cand.compiler.version == "0.8.19+commit.00000002" and cand.compiler.version_pinned_by == "pragma"
    assert cand.provider == "user"


def test_foundry_toml_settings_and_pinned_solc():
    toml = '[profile.default]\noptimizer = true\noptimizer_runs = 1_000\nsolc_version = "0.8.19"\nvia-ir=true\n'
    cand = files_candidate(
        [{"path": "src/A.sol", "content": "pragma solidity ^0.8.0;"}, {"path": "foundry.toml", "content": toml}],
        builds=BUILDS,
    )
    assert cand.settings == {"optimizer": {"enabled": True, "runs": 1000}, "viaIR": True}
    # a pasted foundry.toml pin is a project config pin ("config"); "user" is compiler_version
    assert cand.compiler.version == "0.8.19+commit.00000002" and cand.compiler.version_pinned_by == "config"


def test_foundry_solc_outside_pragma_ignored():
    toml = '[profile.default]\nsolc_version = "0.7.6"\n'
    cand = files_candidate(
        [{"path": "src/A.sol", "content": "pragma solidity ^0.8.0;"}, {"path": "foundry.toml", "content": toml}],
        builds=BUILDS,
    )
    assert cand.compiler.version == "0.8.24+commit.00000004" and cand.compiler.version_pinned_by == "pragma"


def test_entry_is_unimported_root():
    cand = files_candidate(
        [
            {"path": "src/Lib.sol", "content": "pragma solidity ^0.8.0;\nlibrary L {}\nabstract contract Base {}\n"},
            {"path": "src/Vault.sol", "content": 'pragma solidity ^0.8.0;\nimport "./Lib.sol";\n'
                                                 "abstract contract X {}\ncontract Vault is Base {}\n"},
        ],
        builds=BUILDS,
    )
    assert cand.entry_contract == "src/Vault.sol:Vault"


def test_no_solidity_files():
    assert files_candidate([{"path": "README.md", "content": "x"}], builds=BUILDS) is None
