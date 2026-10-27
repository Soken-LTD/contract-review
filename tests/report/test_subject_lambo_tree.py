"""Report subject on the Lambo.win tree shape (run 2026-10-27): the PDF said "1inchV6", the
largest scope file (a vendored, unused library bundle), because the repo name was read from a
`source_args` key review_start never stores. The subject comes from the repository name, or the
main deployable contract, never from a vendored library file."""

from __future__ import annotations

from soken_review.pinning.store import PinnedSource
from soken_review.report.assemble import _project_name, pick_subject, scope_excluded_rows, subject_candidates
from soken_review.report.kit.build import kit_texts
from tests.adapters.evm.test_build_scope import SCOPE

REPO = "https://github.com/code-423n4/2024-12-lambowin"
COMMIT = "874fafc7b27042c59bdd765073f5e412a3b79192"


def _pin(out_of_scope: set[str] = frozenset()) -> PinnedSource:
    return PinnedSource.from_files({p: t.encode() for p, t in SCOPE.items()},
                                   in_scope={p: p not in out_of_scope for p in SCOPE})


def test_repo_job_subject_is_the_project_name():
    job = {"source_args": {"repo_url": REPO, "commit": COMMIT}, "resolved_commit": COMMIT, "address": None}
    cands = subject_candidates(job, [{"entry_contract": None}], _pin())
    assert cands[0] == {"source": "repo_name", "value": "lambowin"}
    assert {"source": "repo_at_commit", "value": "code-423n4/2024-12-lambowin@874fafc"} in cands
    assert pick_subject(cands)["value"] == "lambowin"


def test_without_a_repo_name_the_subject_is_the_main_deployable_contract():
    job = {"source_args": {}, "address": None}
    cands = subject_candidates(job, [], _pin())
    assert {"source": "largest_unit", "value": "LamboFactory"} in cands
    assert all(c["value"] != "1inchV6" for c in cands)
    # the build-excluded file is out of scope and never a candidate
    cands = subject_candidates(job, [], _pin({"src/libraries/1inchV6.sol", "src/LamboFactory.sol"}))
    assert {"source": "largest_unit", "value": "LamboToken"} in cands


def test_project_name_drops_only_a_contest_date_prefix():
    assert _project_name("2024-12-lambowin") == "lambowin"
    assert _project_name("2023-07-pooltogether") == "pooltogether"
    assert _project_name("v4-core") == "v4-core"
    assert _project_name("2024-12") == "2024-12"
    assert _project_name("2024-13-x") == "2024-13-x"


def test_build_excluded_file_is_listed_out_of_scope_with_its_reason():
    rows = scope_excluded_rows([{"scope_excluded": [{"path": "src/libraries/1inchV6.sol", "reason": "build_excluded"}]}])
    assert rows == [{"path": "src/libraries/1inchV6.sol", "reason": kit_texts()["scope_reasons"]["build_excluded"],
                     "by": "server"}]
