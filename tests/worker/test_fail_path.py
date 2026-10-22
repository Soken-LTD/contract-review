"""A job that dies before `fetching` must still reach `failed` along the 03 3.1 graph."""

from soken_review.db.job_repo import assert_transition
from soken_review.worker.supervisor import fail_path


def test_every_fail_path_is_legal():
    for state in ("awaiting_upload", "queued", "fetching", "building", "analyzing"):
        path = fail_path(state)
        assert path and path[-1] == "failed"
        current = state
        for nxt in path:
            assert_transition("job_X", current, nxt)   # raises on an illegal edge
            current = nxt


def test_states_without_a_path_give_empty():
    for state in ("ready", "rendered", "failed", "deleted", "expired"):
        assert fail_path(state) == []
