"""Repo mode pins the dependency files the scope imports as out-of-scope `dependency` entries:
searchable and readable, never a location, never mapped or counted (1inch run 2026-10-27)."""

from __future__ import annotations

from soken_review.adapters.base import Candidate, Compiler
from soken_review.report.assemble import _dependency_package
from soken_review.worker.supervisor import _DEP_PIN_MAX_FILES, _dependency_closure

SCOPE = {"contracts/Farm.sol": 'pragma solidity ^0.8.0;\nimport "@1inch/erc20-pods/contracts/Pod.sol";\ncontract Farm is Pod {}\n'}
TREE = {
    **SCOPE,
    "node_modules/@1inch/erc20-pods/contracts/Pod.sol": 'pragma solidity ^0.8.0;\nimport "./interfaces/IPod.sol";\nabstract contract Pod is IPod { uint256 public podCallGasLimit; }\n',
    "node_modules/@1inch/erc20-pods/contracts/interfaces/IPod.sol": "pragma solidity ^0.8.0;\ninterface IPod {}\n",
    "node_modules/@1inch/erc20-pods/README.md": "not a source",
    "node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol": "pragma solidity ^0.8.20;\ncontract ERC20 {}\n",  # not imported
    "test/Farm.t.sol": "pragma solidity ^0.8.0;\ncontract FarmTest {}\n",
}


def _cand(provider: str = "repo", tree: dict | None = TREE) -> Candidate:
    c = Candidate(provider=provider, files=dict(SCOPE), sha256="ab" * 32, language="solidity",
                  compiler=Compiler(version="0.8.24", version_pinned_by="pragma"),
                  settings={"remappings": ["@1inch/erc20-pods/=node_modules/@1inch/erc20-pods/"]},
                  std_json_input=None, entry_contract=None)
    c._full_tree = tree  # type: ignore[attr-defined]
    return c


def test_closure_pins_only_the_imported_dependency_sources():
    deps = _dependency_closure(_cand())
    assert sorted(deps) == ["node_modules/@1inch/erc20-pods/contracts/Pod.sol",
                            "node_modules/@1inch/erc20-pods/contracts/interfaces/IPod.sol"]
    assert "podCallGasLimit" in deps["node_modules/@1inch/erc20-pods/contracts/Pod.sol"]


def test_closure_is_repo_only_and_capped():
    assert _dependency_closure(_cand(provider="user")) == {}
    assert _dependency_closure(_cand(tree=None)) == {}
    big = dict(SCOPE)
    big["contracts/Farm.sol"] = "pragma solidity ^0.8.0;\n" + "".join(f'import "lib/d/D{i}.sol";\n' for i in range(120))
    for i in range(120):
        big[f"lib/d/D{i}.sol"] = f"pragma solidity ^0.8.0;\ncontract D{i} {{}}\n"
    c = _cand(tree=big)
    c.files = {"contracts/Farm.sol": big["contracts/Farm.sol"]}
    c.settings = {}
    assert len(_dependency_closure(c)) == _DEP_PIN_MAX_FILES


def test_dependency_package_groups_report_rows():
    assert _dependency_package("node_modules/@1inch/erc20-pods/contracts/Pod.sol") == "node_modules/@1inch/erc20-pods"
    assert _dependency_package("node_modules/solmate/src/Auth.sol") == "node_modules/solmate"
    assert _dependency_package("lib/openzeppelin-contracts/contracts/utils/Context.sol") == "lib/openzeppelin-contracts"
