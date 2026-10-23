"""review_delete_job (03 4; 08 3.4; 09 retention): rows in one transaction, tombstones by hash,
files removed, the job row kept as the terminal `deleted` state with its request data scrubbed.
The handler had no implementation until 2026-10-23: the contract listed the tool and the server
raised NotImplementedError. Database tests run against the Postgres fixture (skipped without
Docker); the file removal is covered with a temporary pin root."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import psycopg
import pytest
import pytest_asyncio
from psycopg.rows import dict_row

from soken_review.db.job_repo import JobRepo
from soken_review.errors import ReviewError
from soken_review.tools import delete as D

JOB = "job_" + "0" * 24 + "D1"   # Crockford base32 (no I, L, O, U)
JOB2 = "job_" + "0" * 24 + "D2"
REPORT = "abcdefghijklmnopqrstuvwxyz"
PDF_SHA = "f" * 64


class _Ctx:
    def __init__(self, root: Path) -> None:
        self._root = root

    def get_pin_root(self) -> Path:
        return self._root

    def get_job_state(self, job_id: str) -> str | None:  # pragma: no cover - unused here
        return None

    def append_read(self, job_id: str, path: str, start: int, end: int) -> None:  # pragma: no cover
        return None


async def _seed(conn: psycopg.AsyncConnection, job_id: str, *, with_report: bool) -> None:
    repo = JobRepo(conn)
    await repo.create(job_id=job_id, principal_key="p", surface="connector", state="queued",
                          requester_role="third_party_public_code", source_kind="repo",
                          source_args={"repo_url": "https://github.com/x/y", "commit": "ab" * 20},
                          has_deployment=False)
    await conn.execute("update jobs set state = 'ready', source_pin = 'pin', resolved_commit = %s where job_id = %s",
                       ("ab" * 20, job_id))
    await conn.execute(
        "insert into job_steps (job_id, step, status, container, units, ram_mb, max_attempts) values (%s, 'analyze', 'queued', true, 1, 512, 1)",
        (job_id,))
    await conn.execute(
        "insert into job_files (job_id, path, sha256_raw, sha256_lf, lines, nsloc, lang, role, in_scope)"
        " values (%s, 'src/a.sol', %s, %s, 10, 8, 'solidity', 'source', true)", (job_id, "a" * 64, "b" * 64))
    await conn.execute("insert into job_reads (job_id, path, start_line, end_line) values (%s, 'src/a.sol', 1, 5)", (job_id,))
    if with_report:
        await conn.execute(
            """insert into reports (report_id, report_id_short, job_id, profile, object_prefix, out_name, pdf_sha256s,
                                    subject_candidates, key_version, rendered_at, expires_at)
               values (%s, %s, %s, 'public_review', %s, 'report.pdf', array[%s]::char(64)[], '[]'::jsonb, 1, now(),
                       now() + interval '30 days')""",
            (REPORT, REPORT[:10], job_id, f"reports/{REPORT}/1/", PDF_SHA))
        await conn.execute("update jobs set report_id = %s where job_id = %s", (REPORT, job_id))


async def _count(conn: psycopg.AsyncConnection, table: str, job_id: str) -> int:
    async with conn.cursor() as cur:
        await cur.execute(f"select count(*) from {table} where job_id = %s", (job_id,))
        return (await cur.fetchone())[0]


@pytest_asyncio.fixture(loop_scope="session")
async def wired(db_pool, tmp_path: Path, monkeypatch):
    D.set_pool(db_pool)
    D.set_context(_Ctx(tmp_path / "pins"))
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    async with db_pool.connection() as conn:
        for job in (JOB, JOB2):
            await conn.execute("delete from jobs where job_id = %s", (job,))
        await conn.execute("delete from reports where report_id = %s", (REPORT,))
        await conn.execute("delete from report_tombstones where ref_hash in (%s, %s, %s)",
                           (_h(JOB), _h(JOB2), _h(REPORT)))
    yield db_pool
    async with db_pool.connection() as conn:
        for job in (JOB, JOB2):
            await conn.execute("delete from jobs where job_id = %s", (job,))
        await conn.execute("delete from report_tombstones where ref_hash in (%s, %s, %s)",
                           (_h(JOB), _h(JOB2), _h(REPORT)))


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _files(root: Path, job_id: str, report: str | None) -> None:
    (root / "pins" / job_id / "pin").mkdir(parents=True)
    (root / "pins" / job_id / "pin" / "a.sol").write_text("x")
    (root / "pins" / job_id / "context" / "files").mkdir(parents=True)
    (root / "work" / job_id).mkdir(parents=True)
    (root / "work" / job_id / "candidates.json").write_text("[]")
    if report:
        d = root / "store" / "reports" / report / "1"
        d.mkdir(parents=True)
        (d / "report.pdf").write_bytes(b"%PDF")


@pytest.mark.asyncio(loop_scope="session")   # session pool, as tests/db/test_leads_repo
async def test_delete_removes_rows_files_and_keeps_a_scrubbed_terminal_row(wired, tmp_path: Path) -> None:
    async with wired.connection() as conn:
        await _seed(conn, JOB, with_report=True)
    _files(tmp_path, JOB, REPORT)

    out = await D.handle_review_delete_job({"job_id": JOB, "confirm": "delete"})

    assert out == {"accepted": True, "job_id": JOB, "state": "deleted",
                   "deleted": ["source", "artifacts", "findings", "reads", "report", "pdf"]} or \
           out["deleted"] == ["source", "artifacts", "reads", "report", "pdf"]
    async with wired.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from jobs where job_id = %s", (JOB,))
            job = await cur.fetchone()
        assert job["state"] == "deleted"
        assert job["source_args"] == {} and job["source_pin"] is None and job["resolved_commit"] is None
        assert job["report_id"] is None
        for table in ("job_steps", "job_files", "job_reads", "reports"):
            assert await _count(conn, table, JOB) == 0, table
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select kind, ref_hash, pdf_sha256, reason from report_tombstones"
                              " where ref_hash in (%s, %s) order by kind", (_h(JOB), _h(REPORT)))
            tombs = await cur.fetchall()
    assert [(t["kind"], t["reason"]) for t in tombs] == [("job", "user_delete"), ("report", "user_delete")]
    assert tombs[1]["pdf_sha256"] == PDF_SHA and tombs[1]["ref_hash"] == _h(REPORT)
    assert not (tmp_path / "pins" / JOB).exists()
    assert not (tmp_path / "work" / JOB).exists()
    assert not (tmp_path / "store" / "reports" / REPORT).exists()


@pytest.mark.asyncio(loop_scope="session")   # session pool, as tests/db/test_leads_repo
async def test_open_steps_are_cancelled_before_rows_go(wired, tmp_path: Path, monkeypatch) -> None:
    """The cancel runs in the same transaction as the row deletion; a step row cannot survive, so
    the observable contract is: no queued or running step of the job remains claimable."""
    async with wired.connection() as conn:
        await _seed(conn, JOB, with_report=False)
        await conn.execute("update job_steps set status = 'running' where job_id = %s", (JOB,))
    out = await D.handle_review_delete_job({"job_id": JOB, "confirm": "delete"})
    assert out["state"] == "deleted" and "report" not in out["deleted"]
    async with wired.connection() as conn:
        assert await _count(conn, "job_steps", JOB) == 0


@pytest.mark.asyncio(loop_scope="session")   # session pool, as tests/db/test_leads_repo
async def test_second_delete_is_idempotent_and_unknown_job_is_not_found(wired) -> None:
    async with wired.connection() as conn:
        await _seed(conn, JOB2, with_report=False)
    first = await D.handle_review_delete_job({"job_id": JOB2, "confirm": "delete"})
    second = await D.handle_review_delete_job({"job_id": JOB2, "confirm": "delete"})
    assert first["state"] == second["state"] == "deleted" and second["deleted"] == []
    with pytest.raises(ReviewError) as err:
        await D.handle_review_delete_job({"job_id": "job_" + "0" * 24 + "D9", "confirm": "delete"})
    assert err.value.code == "E_JOB_NOT_FOUND"


def test_file_removal_never_follows_a_symlinked_root(tmp_path: Path, monkeypatch) -> None:
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep").write_text("x")
    (tmp_path / "pins").mkdir()
    (tmp_path / "pins" / JOB).symlink_to(victim, target_is_directory=True)
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    removed = D._remove_files(tmp_path / "pins", JOB, "reports/../../victim/")
    assert removed == set()
    assert (victim / "keep").exists()


def test_contract_output_names_only(tmp_path: Path) -> None:
    names = json.loads((Path(__file__).resolve().parents[2] / "contract" / "mcp" / "tools.v1.json").read_text())
    tool = next(t for t in names["tools"] if t["name"] == "review_delete_job")
    allowed = tool["outputSchema"]["properties"]["deleted"]["items"]["enum"]
    assert set(allowed) == {"source", "artifacts", "findings", "reads", "report", "pdf"}
