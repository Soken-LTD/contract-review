import copy
from pathlib import Path

import pytest
import yaml

from soken_review.evals.cli import main
from soken_review.evals.corpus import check_case

FIX = Path(__file__).parent / "fixtures" / "corpus" / "sol-seed-0007"
BASE = yaml.safe_load((FIX / "case.yaml").read_text())


def write(tmp_path, **changes):
    case = copy.deepcopy(BASE)
    for dotted, value in changes.items():
        node = case
        *head, last = dotted.split("__")
        for key in head:
            node = node[int(key)] if isinstance(node, list) else node[key]
        node[last] = value
    path = tmp_path / "case.yaml"
    path.write_text(yaml.safe_dump(case))
    return path


def test_schema_example_passes_with_tree():
    report = check_case(FIX / "case.yaml", tree=FIX / "tree")
    assert report.ok, report.errors


@pytest.mark.parametrize(
    ("changes", "needle"),
    [
        ({"chain": "bsc"}, "chain"),
        ({"ground_truth__0__category": "evm.reentrancy"}, "family evm"),
        ({"ground_truth__0__category": "solana.nope"}, "not in rubric"),
        ({"source__commit": "abc"}, "40-hex"),
        ({"input_mode": "repo"}, "delivered by upload"),
        ({"seeded": None}, "seeded block"),
        ({"case_id": "Sol_7"}, "case_id"),
    ],
)
def test_rule_violations(tmp_path, changes, needle):
    report = check_case(write(tmp_path, **changes))
    assert any(needle in e for e in report.errors), report.errors


def test_line_range_past_end(tmp_path):
    path = write(tmp_path, ground_truth__0__root_cause_lines=[{"file": "src/lib.rs", "start": 120, "end": 999}])
    assert any("past end" in e for e in check_case(path, tree=FIX / "tree").errors)


def test_licence_rules_warn_in_development(tmp_path):
    path = write(tmp_path, origin="own_audit", seeded=None, input_mode="upload", consent="not_needed")
    dev = check_case(path)
    assert dev.ok and any("consent" in w for w in dev.warnings)
    assert any("consent" in e for e in check_case(path, enforce_licences=True).errors)


def test_evmbench_tempo_refused(tmp_path):
    path = write(tmp_path, source__repo="https://github.com/evmbench-org/2026-01-tempo-feeamm")
    assert any("Tempo" in e for e in check_case(path).errors)


def test_missing_licence_warns_in_development(tmp_path):
    path = write(tmp_path, source__license="none")
    dev = check_case(path)
    assert dev.ok and any("licence" in w for w in dev.warnings)
    assert any("licence" in e for e in check_case(path, enforce_licences=True).errors)


def test_cli_trees_refuses_missing_checkout(tmp_path, capsys):
    assert main(["corpus", "check", str(FIX / "case.yaml"), "--trees", str(tmp_path)]) == 1
    assert "no checkout" in capsys.readouterr().out


def test_cli_exit_codes(tmp_path, capsys):
    assert main(["corpus", "check", str(FIX.parent)]) == 0
    assert main(["corpus", "check", str(write(tmp_path, chain="bsc"))]) == 1
