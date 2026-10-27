"""DB-level tests for JobRepo and migration runner (plan-v4 part 03 sections 3.1, 3.4, 3.6).

Requires Docker (Postgres 16); skipped otherwise.
"""

from __future__ import annotations

import pytest

from soken_review.db.job_repo import JobRepo, JobStateError, assert_transition, new_job_id

ASYNC = pytest.mark.asyncio(loop_scope="session")   # the db_pool loop (tests/conftest.py)


# ---------------------------------------------------------------------------
# new_job_id format
# ---------------------------------------------------------------------------

def test_job_id_format():
    import re
    for _ in range(20):
        jid = new_job_id()
        assert re.match(r"^job_[0-9A-HJKMNP-TV-Z]{26}$", jid), jid


def test_job_id_uniqueness():
    ids = {new_job_id() for _ in range(1000)}
    assert len(ids) == 1000


# ---------------------------------------------------------------------------
# State graph (no DB needed)
# ---------------------------------------------------------------------------

def test_legal_transitions():
    assert_transition("j", "queued", "fetching")
    assert_transition("j", "awaiting_upload", "queued")
    assert_transition("j", "ready", "finalized")
    assert_transition("j", "rendering", "rendered")
    assert_transition("j", "rendering", "render_queued")  # retry


def test_illegal_transitions():
    with pytest.raises(JobStateError):
        assert_transition("j", "queued", "ready")
    with pytest.raises(JobStateError):
        assert_transition("j", "rendered", "queued")
    with pytest.raises(JobStateError):
        assert_transition("j", "deleted", "queued")


# ---------------------------------------------------------------------------
# DB tests (require docker fixture from conftest)
# ---------------------------------------------------------------------------

def _default_create_kwargs(job_id: str, **overrides) -> dict:
    base = {
        "job_id": job_id,
        "principal_key": "testprincipal01",
        "surface": "connector",
        "state": "queued",
        "requester_role": "third_party_public_code",
        "source_kind": "deployed",
        "source_args": {"kind": "deployed", "chain": "evm", "address": "0xabcd"},
        "has_deployment": True,
    }
    base.update(overrides)
    return base


@pytest.mark.skipif(
    __import__("subprocess").run(
        ["docker", "info"], capture_output=True
    ).returncode != 0,
    reason="docker unavailable",
)
class TestJobRepoWithDB:
    """All tests in this class need a live Postgres 16 connection."""

    @ASYNC
    async def test_create_and_get(self, db_conn):
        repo = JobRepo(db_conn)
        jid = new_job_id()
        row = await repo.create(**_default_create_kwargs(jid))
        assert row["job_id"] == jid
        assert row["state"] == "queued"

        fetched = await repo.get(jid)
        assert fetched is not None
        assert fetched["state"] == "queued"

    @ASYNC
    async def test_get_nonexistent(self, db_conn):
        repo = JobRepo(db_conn)
        assert await repo.get("job_" + "0" * 26) is None

    @ASYNC
    async def test_transition_legal(self, db_conn):
        repo = JobRepo(db_conn)
        jid = new_job_id()
        await repo.create(**_default_create_kwargs(jid))

        updated = await repo.transition(jid, "fetching")
        assert updated["state"] == "fetching"

        fetched = await repo.get(jid)
        assert fetched["state"] == "fetching"

    @ASYNC
    async def test_transition_illegal_raises(self, db_conn):
        repo = JobRepo(db_conn)
        jid = new_job_id()
        await repo.create(**_default_create_kwargs(jid))

        with pytest.raises(JobStateError):
            await repo.transition(jid, "ready")  # queued -> ready is illegal

    @ASYNC
    async def test_get_and_lock_returns_row(self, db_conn):
        repo = JobRepo(db_conn)
        jid = new_job_id()
        await repo.create(**_default_create_kwargs(jid))
        locked = await repo.get_and_lock(jid)
        assert locked is not None
        assert locked["job_id"] == jid

    @ASYNC
    async def test_awaiting_upload_flow(self, db_conn):
        repo = JobRepo(db_conn)
        jid = new_job_id()
        await repo.create(
            **_default_create_kwargs(
                jid,
                state="awaiting_upload",
                source_kind="upload",
                has_deployment=False,
                upload_id="abcdefghijklmnopqrstuvwxyz"[:26],
            )
        )
        updated = await repo.transition(jid, "queued")
        assert updated["state"] == "queued"

    @ASYNC
    async def test_terminal_states_not_deleted(self, db_conn):
        repo = JobRepo(db_conn)
        for terminal in ("failed", "insufficient_source"):
            jid = new_job_id()
            await repo.create(**_default_create_kwargs(jid))
            # Simulate: queued -> fetching -> <terminal>
            await repo.transition(jid, "fetching")
            updated = await repo.transition(jid, terminal)
            assert updated["state"] == terminal
            # Can only go to deleted from here
            assert_transition(jid, terminal, "deleted")
            with pytest.raises(JobStateError):
                assert_transition(jid, terminal, "queued")

    @ASYNC
    async def test_full_pipeline_happy_path(self, db_conn):
        repo = JobRepo(db_conn)
        jid = new_job_id()
        await repo.create(**_default_create_kwargs(jid))
        states = ["fetching", "building", "analyzing", "ready", "finalized",
                  "render_queued", "rendering", "rendered"]
        for s in states:
            await repo.transition(jid, s)
        final = await repo.get(jid)
        assert final["state"] == "rendered"


def test_plan_31_edges_present():
    """Edges of 03 3.1 that are easy to miss: tier D after builds, internal step errors."""
    from soken_review.db.job_repo import assert_transition

    for src, dst in [("building", "insufficient_source"), ("building", "failed"), ("analyzing", "failed"),
                     ("awaiting_upload", "expired"), ("rendering", "render_failed"), ("ready", "expired")]:
        assert_transition("job_x", src, dst)
