"""worker/retention: one idempotent sweep over the 09 retention rules against Postgres. Before
it, nothing expired (jobs got `expires_at` only at render, no code produced `expired`)."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from psycopg.rows import dict_row

from soken_review.db.job_repo import JobRepo
from soken_review.worker import retention as R

ASYNC = pytest.mark.asyncio(loop_scope="session")
PDF_SHA = "e" * 64


def _jid(n: int) -> str:
    return "job_" + "0" * 22 + f"R{n:03d}"[-4:].rjust(4, "0")


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def _job(conn, jid: str, state: str, *, age: timedelta, idle: timedelta | None = None) -> None:
    await JobRepo(conn).create(job_id=jid, principal_key="p", surface="connector", state="queued",
                               requester_role="third_party_public_code", source_kind="repo",
                               source_args={"repo_url": "https://github.com/x/y"}, has_deployment=False)
    await conn.execute("update jobs set state = %s, created_at = now() - %s, last_call_at = now() - %s,"
                       " source_pin = 'pin' where job_id = %s",
                       (state, age, idle if idle is not None else age, jid))


async def _report(conn, jid: str, rid: str, *, expires: timedelta) -> None:
    await conn.execute(
        """insert into reports (report_id, report_id_short, job_id, profile, object_prefix, out_name, pdf_sha256s,
                                subject_candidates, key_version, rendered_at, expires_at)
           values (%s, %s, %s, 'public_review', %s, 'r.pdf', array[%s]::char(64)[], '[]'::jsonb, 1, now(), now() + %s)""",
        (rid, rid[:10], jid, f"reports/{rid}/1/", PDF_SHA, expires))
    await conn.execute("update jobs set report_id = %s where job_id = %s", (rid, jid))


def _dirs(root: Path, jid: str, rid: str | None = None) -> None:
    (root / "pins" / jid / "pin").mkdir(parents=True, exist_ok=True)
    (root / "work" / jid).mkdir(parents=True, exist_ok=True)
    if rid:
        (root / "store" / "reports" / rid / "1").mkdir(parents=True, exist_ok=True)
        (root / "store" / "reports" / rid / "1" / "report.pdf").write_bytes(b"%PDF")


@pytest.fixture()
def roots(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    (tmp_path / "pins").mkdir()
    (tmp_path / "work").mkdir()
    (tmp_path / "store" / "reports").mkdir(parents=True)
    return tmp_path


@ASYNC
async def test_sweep_applies_every_rule_once(db_pool, roots: Path) -> None:
    ids = {n: _jid(n) for n in range(1, 8)}
    rids = {5: "r" * 26, 6: "s" * 26}
    async with db_pool.connection() as conn:
        for rid in rids.values():
            await conn.execute("delete from reports where report_id = %s", (rid,))
        for j in ids.values():
            await conn.execute("delete from jobs where job_id = %s", (j,))
        await conn.execute("delete from report_tombstones where ref_hash = any(%s)",
                           ([_h(j) for j in ids.values()] + [_h(r) for r in rids.values()],))
        await _job(conn, ids[1], "failed", age=timedelta(days=8))                       # terminal, old -> deleted
        await _job(conn, ids[2], "failed", age=timedelta(days=2))                       # terminal, young -> kept
        await _job(conn, ids[3], "ready", age=timedelta(days=3), idle=timedelta(hours=30))   # idle -> expired
        await _job(conn, ids[4], "ready", age=timedelta(days=3), idle=timedelta(hours=2))    # active -> kept
        await _job(conn, ids[5], "rendered", age=timedelta(days=40))
        await _report(conn, ids[5], rids[5], expires=timedelta(days=-1))                 # past -> expired
        await _job(conn, ids[6], "rendered", age=timedelta(days=3))
        await _report(conn, ids[6], rids[6], expires=timedelta(days=20))                 # live -> kept
        await _job(conn, ids[7], "fetching", age=timedelta(days=9))                     # stuck -> deleted
        await conn.execute("insert into build_cache (cache_key, source_tree_hash, inputs, provenance, expires_at)"
                           " values ('k-old', 'h', '{}', '{}', now() - interval '1 day')"
                           " on conflict (cache_key) do update set expires_at = excluded.expires_at")
        await conn.execute("insert into build_cache (cache_key, source_tree_hash, inputs, provenance, expires_at)"
                           " values ('k-new', 'h', '{}', '{}', now() + interval '1 day')"
                           " on conflict (cache_key) do update set expires_at = excluded.expires_at")
    for n, j in ids.items():
        _dirs(roots, j, rids.get(n))
    _dirs(roots, "job_" + "0" * 24 + "ZZ")                    # orphan dir, no row
    (roots / "store" / "reports" / ("t" * 26) / "1").mkdir(parents=True)   # orphan report dir

    async with db_pool.connection() as conn:
        out = await R.sweep(conn, roots / "pins", idle_hours=24)
    assert out.errors == []
    assert set(out.purged_terminal) == {ids[1], ids[7]}
    assert out.expired_idle == [ids[3]] and out.expired_reports == [ids[5]]
    assert out.build_cache_rows == 1

    async with db_pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("select job_id, state, source_pin from jobs where job_id = any(%s) order by job_id",
                          (list(ids.values()),))
        rows = {r["job_id"]: r for r in await cur.fetchall()}
        await cur.execute("select kind, reason from report_tombstones where ref_hash = any(%s)",
                          ([_h(ids[1]), _h(ids[3]), _h(ids[5]), _h(ids[7]), _h(rids[5])],))
        tombs = await cur.fetchall()
        await cur.execute("select report_id from reports where report_id = any(%s)", (list(rids.values()),))
        kept_reports = {r["report_id"] for r in await cur.fetchall()}
        await cur.execute("select cache_key from build_cache where cache_key in ('k-old', 'k-new')")
        cache = {r["cache_key"] for r in await cur.fetchall()}
    assert {j: rows[j]["state"] for j in ids.values()} == {
        ids[1]: "deleted", ids[2]: "failed", ids[3]: "expired", ids[4]: "ready", ids[5]: "expired",
        ids[6]: "rendered", ids[7]: "deleted"}
    assert rows[ids[1]]["source_pin"] is None and rows[ids[4]]["source_pin"] == "pin"
    assert sorted((t["kind"], t["reason"]) for t in tombs) == [("job", "expiry")] * 4 + [("report", "expiry")]
    assert kept_reports == {rids[6]} and cache == {"k-new"}
    for n in (1, 3, 5, 7):
        assert not (roots / "pins" / ids[n]).exists() and not (roots / "work" / ids[n]).exists(), n
    for n in (2, 4, 6):
        assert (roots / "pins" / ids[n]).exists() and (roots / "work" / ids[n]).exists(), n
    assert not (roots / "store" / "reports" / rids[5]).exists() and (roots / "store" / "reports" / rids[6]).exists()
    assert not (roots / "pins" / ("job_" + "0" * 24 + "ZZ")).exists()
    assert not (roots / "store" / "reports" / ("t" * 26)).exists()

    # idempotent: a second pass finds nothing
    async with db_pool.connection() as conn:
        again = await R.sweep(conn, roots / "pins", idle_hours=24)
    assert again.as_dict() == {"purged_terminal": [], "expired_idle": [], "expired_reports": [], "build_cache_rows": 0,
                               "orphan_dirs": [], "errors": []}
    async with db_pool.connection() as conn:
        for rid in rids.values():
            await conn.execute("delete from reports where report_id = %s", (rid,))
        for j in ids.values():
            await conn.execute("delete from jobs where job_id = %s", (j,))
        await conn.execute("delete from report_tombstones where ref_hash = any(%s)",
                           ([_h(j) for j in ids.values()] + [_h(r) for r in rids.values()],))
        await conn.execute("delete from build_cache where cache_key = 'k-new'")


@ASYNC
async def test_dry_run_changes_nothing(db_pool, roots: Path) -> None:
    jid = _jid(21)
    async with db_pool.connection() as conn:
        await conn.execute("delete from jobs where job_id = %s", (jid,))
        await _job(conn, jid, "failed", age=timedelta(days=30))
    _dirs(roots, jid)
    async with db_pool.connection() as conn:
        out = await R.sweep(conn, roots / "pins", dry_run=True, idle_hours=24)
        state = (await (await conn.execute("select state from jobs where job_id = %s", (jid,))).fetchone())[0]
        await conn.execute("delete from jobs where job_id = %s", (jid,))
    assert out.purged_terminal == [jid] and state == "failed" and (roots / "pins" / jid).exists()


def test_cli_reports_a_summary(monkeypatch, capsys, tmp_path: Path) -> None:
    async def fake_run(dsn, pin_root, *, dry_run):
        assert dsn == "postgresql://x" and dry_run
        return R.SweepReport(purged_terminal=["job_a"], build_cache_rows=2)

    monkeypatch.setattr(R, "run", fake_run)
    assert R.main(["--dsn", "postgresql://x", "--pin-root", str(tmp_path), "--dry-run", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"purged_terminal": ["job_a"], "expired_idle": [], "expired_reports": [],
                                                   "build_cache_rows": 2, "orphan_dirs": [], "errors": []}


def test_ready_idle_hours_comes_from_limits_yaml() -> None:
    assert R.ready_idle_hours() == 24


def test_limits_yaml_has_no_duplicate_keys() -> None:
    """yaml.safe_load keeps the last of two equal keys silently: a second `build:` block dropped
    evm.timeout_s until 2026-10-23."""
    import yaml

    class Strict(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        seen: set = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                raise ValueError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep)

    Strict.construct_mapping = mapping  # type: ignore[assignment]
    path = Path(__file__).resolve().parents[2] / "contract" / "ops" / "limits.yaml"
    data = yaml.load(path.read_text(encoding="utf-8"), Loader=Strict)
    assert data["build"]["evm"]["timeout_s"] == 300 and data["build"]["move"]["wall_s"] == 900


def test_expired_report_is_gone_for_review_report_before_the_sweep() -> None:
    from soken_review.tools import report as T

    src = Path(T.__file__).read_text()
    assert 'rep["expires_at"] <= datetime.now(UTC)' in src and '_status_only("expired", job)' in src
