"""Job repository: create, state transitions, locking (plan-v4 part 03 sections 3.1, 3.4, 3.6).

All write operations lock the job row first with ``SELECT ... FOR UPDATE`` before any update
(03 section 3.4). ``JobStateError`` is raised for illegal transitions (03 section 3.1 graph).

Job id format: ``job_`` + 26 Crockford base32 characters (03 section 1).
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row

# ---------------------------------------------------------------------------
# Crockford base32 alphabet (excludes I, L, O, U to avoid confusion)
# ---------------------------------------------------------------------------
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _crockford_encode(n: int, length: int = 26) -> str:
    """Encode *n* as a zero-padded Crockford base-32 string of *length* chars."""
    chars: list[str] = []
    for _ in range(length):
        chars.append(_CROCKFORD[n & 0x1F])
        n >>= 5
    return "".join(reversed(chars))


def new_job_id() -> str:
    """Generate ``job_`` + 26 Crockford base32 from 130 random bits (03 section 1)."""
    n = secrets.randbits(130)
    return "job_" + _crockford_encode(n, 26)


# ---------------------------------------------------------------------------
# State graph (03 section 3.1)
# ---------------------------------------------------------------------------
_TRANSITIONS: dict[str, set[str]] = {
    "awaiting_upload": {"queued", "expired", "deleted"},
    "queued": {"fetching", "deleted"},
    "fetching": {"building", "insufficient_source", "failed", "deleted"},
    "building": {"analyzing", "insufficient_source", "failed", "deleted"},  # tier D after builds (06 2.4)
    "analyzing": {"ready", "failed", "deleted"},  # failed = internal step error only
    "ready": {"finalized", "expired", "deleted"},
    "finalized": {"render_queued", "deleted"},
    "render_queued": {"rendering", "deleted"},
    "rendering": {"rendered", "render_failed", "render_queued", "deleted"},
    "rendered": {"expired", "deleted"},
    "render_failed": {"render_queued", "deleted"},  # operator rerender
    "insufficient_source": {"deleted"},
    "failed": {"deleted"},
    "expired": {"deleted"},
    "deleted": set(),  # terminal
}


class JobStateError(Exception):
    """Raised when a state transition is not in the graph (03 section 3.1)."""

    def __init__(self, job_id: str, from_state: str, to_state: str) -> None:
        self.job_id = job_id
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"job {job_id}: illegal transition {from_state!r} -> {to_state!r}")


def assert_transition(job_id: str, from_state: str, to_state: str) -> None:
    """Raise ``JobStateError`` if the transition is not in the graph."""
    allowed = _TRANSITIONS.get(from_state, set())
    if to_state not in allowed:
        raise JobStateError(job_id, from_state, to_state)


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class JobRepo:
    """All database operations that touch the ``jobs`` table.

    Every write method acquires a ``FOR UPDATE`` row lock inside a transaction
    (03 section 3.4).  The caller provides a live ``psycopg.AsyncConnection``.
    """

    def __init__(self, conn: psycopg.AsyncConnection) -> None:
        self._conn = conn

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get(self, job_id: str) -> dict[str, Any] | None:
        """Return the full job row or None if not found."""
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from jobs where job_id = %s", (job_id,))
            return await cur.fetchone()  # type: ignore[return-value]

    async def get_and_lock(self, job_id: str) -> dict[str, Any] | None:
        """Lock the row (``FOR UPDATE``) and return it; None if not found.

        Must be called inside an open transaction.  The write lock is held until
        the transaction commits or rolls back (03 section 3.4).
        """
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from jobs where job_id = %s for update",
                (job_id,),
            )
            return await cur.fetchone()  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    async def create(
        self,
        *,
        job_id: str,
        principal_key: str,
        surface: str,
        state: str,
        requester_role: str,
        source_kind: str,
        source_args: dict[str, Any],
        has_deployment: bool,
        chain: str | None = None,
        chain_id: int | None = None,
        address: str | None = None,
        previous_report_id: str | None = None,
        previous_snapshot: dict[str, Any] | None = None,
        upload_id: str | None = None,
        guide_version: str = "v0",
        rubric_version: str = "v0",
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Insert a new job row and return it.

        ``state`` must be ``queued`` or ``awaiting_upload`` (the two legal start states).
        """
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                insert into jobs (
                  job_id, principal_key, surface, state,
                  requester_role, source_kind, source_args, has_deployment,
                  chain, chain_id, address,
                  previous_report_id, previous_snapshot, upload_id,
                  guide_version, rubric_version, expires_at
                ) values (
                  %(job_id)s, %(principal_key)s, %(surface)s, %(state)s,
                  %(requester_role)s, %(source_kind)s, %(source_args)s, %(has_deployment)s,
                  %(chain)s, %(chain_id)s, %(address)s,
                  %(previous_report_id)s, %(previous_snapshot)s, %(upload_id)s,
                  %(guide_version)s, %(rubric_version)s, %(expires_at)s
                )
                returning *
                """,
                {
                    "job_id": job_id,
                    "principal_key": principal_key,
                    "surface": surface,
                    "state": state,
                    "requester_role": requester_role,
                    "source_kind": source_kind,
                    "source_args": psycopg.types.json.Jsonb(source_args),
                    "has_deployment": has_deployment,
                    "chain": chain,
                    "chain_id": chain_id,
                    "address": address,
                    "previous_report_id": previous_report_id,
                    "previous_snapshot": psycopg.types.json.Jsonb(previous_snapshot) if previous_snapshot else None,
                    "upload_id": upload_id,
                    "guide_version": guide_version,
                    "rubric_version": rubric_version,
                    "expires_at": expires_at,
                },
            )
            row = await cur.fetchone()
            assert row is not None
            return row  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # State transition (03 section 3.1 + 3.4)
    # ------------------------------------------------------------------

    async def transition(
        self,
        job_id: str,
        to_state: str,
        *,
        error_code: str | None = None,
        error_detail: dict[str, Any] | None = None,
        touch: bool = True,
    ) -> dict[str, Any]:
        """Lock, check the graph, and advance the state.

        Returns the updated job row.  Must be called inside an open transaction.
        """
        job = await self.get_and_lock(job_id)
        if job is None:
            raise KeyError(job_id)

        assert_transition(job_id, job["state"], to_state)

        extra_sets = ""
        params: dict[str, Any] = {"job_id": job_id, "state": to_state}

        if touch:
            extra_sets += ", last_call_at = now()"
        if error_code is not None:
            extra_sets += ", error_code = %(error_code)s"
            params["error_code"] = error_code
        if error_detail is not None:
            extra_sets += ", error_detail = %(error_detail)s"
            params["error_detail"] = psycopg.types.json.Jsonb(error_detail)
        if to_state == "finalized":
            extra_sets += ", finalized_at = now()"

        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"update jobs set state = %(state)s{extra_sets} where job_id = %(job_id)s returning *",
                params,
            )
            row = await cur.fetchone()
            assert row is not None
            return row  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Touch last_call_at (read tools, 03 section 3.4 note: reads never lock)
    # ------------------------------------------------------------------

    async def touch(self, job_id: str) -> None:
        """Update last_call_at without locking (used by read tools)."""
        await self._conn.execute(
            "update jobs set last_call_at = now() where job_id = %s",
            (job_id,),
        )

    # ------------------------------------------------------------------
    # Step helpers (09 section 3.3, worker workstream)
    # ------------------------------------------------------------------

    async def insert_step(
        self,
        *,
        job_id: str,
        step: str,
        seq: int = 0,
        tool: str | None = None,
        container: bool,
        units: int,
        ram_mb: int,
        priority: int = 100,
        max_attempts: int = 1,
        affinity: str | None = None,
        not_before_secs: float = 0.0,
    ) -> dict[str, Any]:
        """Insert a new job_steps row and return it (09 section 3.3).

        ``not_before_secs > 0`` delays the step (retry backoff).
        """
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                insert into job_steps
                  (job_id, step, seq, tool, container, units, ram_mb, priority,
                   max_attempts, affinity, not_before)
                values (
                  %(job_id)s, %(step)s, %(seq)s, %(tool)s, %(container)s, %(units)s, %(ram_mb)s,
                  %(priority)s, %(max_attempts)s, %(affinity)s,
                  now() + make_interval(secs => %(delay)s)
                )
                returning *
                """,
                {
                    "job_id": job_id,
                    "step": step,
                    "seq": seq,
                    "tool": tool,
                    "container": container,
                    "units": units,
                    "ram_mb": ram_mb,
                    "priority": priority,
                    "max_attempts": max_attempts,
                    "affinity": affinity,
                    "delay": not_before_secs,
                },
            )
            row = await cur.fetchone()
            assert row is not None
            return row  # type: ignore[return-value]

    async def complete_step(
        self,
        step_id: int,
        status: str,
        *,
        exit_code: int | None = None,
        error_code: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> None:
        """Mark a step_id as done/failed/timeout with timing and provenance (09 section 3.5)."""
        params: dict[str, Any] = {
            "id": step_id,
            "status": status,
            "exit_code": exit_code,
            "error_code": error_code,
            "provenance": psycopg.types.json.Jsonb(provenance) if provenance else None,
        }
        async with self._conn.cursor() as cur:
            await cur.execute(
                """
                update job_steps
                set status = %(status)s, finished_at = now(),
                    exit_code = %(exit_code)s,
                    error_code = %(error_code)s,
                    provenance = %(provenance)s
                where id = %(id)s
                """,
                params,
            )

    async def retry_step(self, step_id: int, delay_secs: float) -> None:
        """Reset a step back to `queued` with a not_before delay (09 3.6 transient retry).

        Clears finished_at and error_code so the step looks fresh for the claim query.
        ``attempt`` is NOT reset: the claim query increments it again on the next claim,
        so the supervisor can detect ``attempt >= max_attempts`` and stop retrying.
        """
        await self._conn.execute(
            """
            update job_steps
            set status = 'queued',
                not_before = now() + make_interval(secs => %s),
                finished_at = null,
                error_code = null
            where id = %s
            """,
            (delay_secs, step_id),
        )

    async def get_steps(self, job_id: str) -> list[dict[str, Any]]:
        """Return all job_steps rows for *job_id* ordered by enqueued_at (09 progress)."""
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select * from job_steps where job_id = %s order by enqueued_at",
                (job_id,),
            )
            return await cur.fetchall()  # type: ignore[return-value]

    async def update_job_fields(
        self,
        job_id: str,
        **fields: Any,
    ) -> None:
        """UPDATE arbitrary allowed columns on the job row (no state-graph check).

        Allowed: source_pin, tier, code_hash, map_status, analyzer_degraded, upload_sha256.
        This is a low-level helper; state transitions still go through ``transition()``.
        """
        _ALLOWED = frozenset(
            {"source_pin", "tier", "code_hash", "map_status", "analyzer_degraded",
             "upload_sha256", "resolved_commit"}
        )
        bad = set(fields) - _ALLOWED
        if bad:
            raise ValueError(f"update_job_fields: disallowed columns {bad}")
        set_parts = ", ".join(f"{k} = %({k})s" for k in fields)
        params = dict(fields)
        params["job_id"] = job_id
        await self._conn.execute(
            f"update jobs set {set_parts} where job_id = %(job_id)s",
            params,
        )

    async def find_unseeded_jobs(self) -> list[dict[str, Any]]:
        """Return queued jobs that have no job_steps rows yet (supervisor seed loop, 09 3.3)."""
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                select j.*
                from jobs j
                where j.state = 'queued'
                  and not exists (select 1 from job_steps s where s.job_id = j.job_id)
                order by j.created_at
                limit 20
                """,
            )
            return await cur.fetchall()  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Worker claim (09 section 3.3, ops.sql claim query)
    # ------------------------------------------------------------------

    async def claim_step(
        self,
        host: str,
        free_units: int,
        lease_secs: int,
        free_ram_mb: int,
        max_units_idle: int,
        max_ram_idle: int,
        render: bool,
    ) -> dict[str, Any] | None:
        """Claim the next eligible step row per the 09 claim query.

        Returns the claimed ``job_steps`` row (all columns) or None if nothing is ready.
        ``render=True`` claims render-class rows; ``render=False`` claims all others.
        """
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                update job_steps s
                set status='running', lease_owner=%(host)s, lease_until=now()+make_interval(secs => %(lease_secs)s),
                    started_at=now(), attempt=attempt+1
                where s.id = (
                  select q.id from job_steps q
                  where q.status='queued' and q.not_before <= now()
                    and (q.affinity is null or q.affinity = %(host)s)
                    and ((q.step = 'render') = %(render)s) and q.step not in ('purge','proof')
                    and q.units <= %(free_units)s and q.ram_mb <= %(free_ram_mb)s
                    and not exists (
                      select 1 from job_steps h
                      where h.status='queued' and h.not_before <= now()
                        and (h.affinity is null or h.affinity = %(host)s)
                        and ((h.step = 'render') = %(render)s) and h.step not in ('purge','proof')
                        and h.enqueued_at < now() - interval '120 seconds'
                        and (h.units > %(free_units)s or h.ram_mb > %(free_ram_mb)s) and h.units <= %(max_units_idle)s and h.ram_mb <= %(max_ram_idle)s
                        and (h.priority, h.enqueued_at) < (q.priority, q.enqueued_at))
                    and not exists (
                      select 1 from job_steps p
                      where p.job_id = q.job_id and p.id <> q.id and p.status in ('queued','running')
                        and p.step <> 'render' and q.step <> 'render' and p.enqueued_at < q.enqueued_at)
                  order by q.priority, q.enqueued_at
                  for update skip locked limit 1)
                returning s.*
                """,
                {
                    "host": host, "free_units": free_units, "lease_secs": lease_secs, "free_ram_mb": free_ram_mb,
                    "max_units_idle": max_units_idle, "max_ram_idle": max_ram_idle, "render": render,
                },
            )
            return await cur.fetchone()  # type: ignore[return-value]


    # ------------------------------------------------------------------
    # Server drafts (04 12) and status reads (03 4.2)
    # ------------------------------------------------------------------

    async def create_server_drafts(self, job_id: str, family: str, flags: list[dict[str, Any]]) -> int:
        """One `srv-<signal>-<nnnn>` draft per J2 or J4 flag, status needs_text (04 12; 03 3.6).

        Revision 0 holds the fixed category and quote, severity Informational, no matrix, null
        title and body. Idempotent: an existing key is left as it is. Locks the job row (03 3.4).
        """
        if not flags:
            return 0
        job = await self.get_and_lock(job_id)
        if job is None:
            raise KeyError(job_id)
        next_no = int(job["next_finding_no"])
        counters: dict[str, int] = {}
        created = 0
        category = f"{family}.source_text_integrity"
        for flag in flags:
            signal = flag["rule"].lower()
            counters[signal] = counters.get(signal, 0) + 1
            key = f"srv-{signal}-{counters[signal]:04d}"
            async with self._conn.cursor() as cur:
                await cur.execute(
                    """insert into finding_drafts (job_id, draft_key, finding_no, origin, status,
                         current_revision, severity)
                       values (%s, %s, %s, 'server_needs_text', 'needs_text', 0, 'Informational')
                       on conflict (job_id, draft_key) do nothing""",
                    (job_id, key, next_no),
                )
                if cur.rowcount != 1:
                    continue
            content = {
                "draft_key": key, "category": category, "title": None, "body": None,
                "server_flag": {"rule": flag["rule"], "file": flag["file"], "line": flag["line"],
                                "detail": flag.get("detail")},
                "quotes": [{"file": flag["file"], "start": flag["line"], "end": flag["line"], "role": "location"}],
            }
            await self._conn.execute(
                """insert into finding_revisions (job_id, draft_key, revision, content, content_hash, category,
                     category_family, impact_class, computed_severity, severity_rule)
                   values (%s, %s, 0, %s, %s, %s, %s, 'none', 'Informational', 'server_draft')""",
                (job_id, key, psycopg.types.json.Jsonb(content),
                 _sha256_json(content), category, family),
            )
            await self._conn.execute(
                """insert into finding_quote_ranges (job_id, draft_key, revision, ord, role, path, start_line, end_line)
                   values (%s, %s, 0, 0, 'location', %s, %s, %s)""",
                (job_id, key, flag["file"], flag["line"], flag["line"]),
            )
            next_no += 1
            created += 1
        await self._conn.execute("update jobs set next_finding_no = %s where job_id = %s", (next_no, job_id))
        return created

    async def list_drafts(self, job_id: str) -> list[dict[str, Any]]:
        """Every draft with its current revision's title, location quote and server flag (03 4.2)."""
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """select d.draft_key, d.finding_no, d.status, d.severity, d.carried_from,
                          r.content->>'title' as title, r.content->'server_flag' as server_flag,
                          q.path as loc_path, q.start_line as loc_start, q.end_line as loc_end
                   from finding_drafts d
                   left join finding_revisions r
                     on r.job_id = d.job_id and r.draft_key = d.draft_key and r.revision = d.current_revision
                   left join finding_quote_ranges q
                     on q.job_id = d.job_id and q.draft_key = d.draft_key and q.revision = d.current_revision
                        and q.role = 'location' and q.ord = (
                          select min(q2.ord) from finding_quote_ranges q2
                          where q2.job_id = d.job_id and q2.draft_key = d.draft_key
                            and q2.revision = d.current_revision and q2.role = 'location')
                   where d.job_id = %s
                   order by d.finding_no""",
                (job_id,),
            )
            return await cur.fetchall()  # type: ignore[return-value]

    async def step_medians(self, chain: str | None, limit_jobs: int = 50) -> dict[str, float]:
        """Median seconds per step over the last `limit_jobs` finished jobs of the chain (03 3.1 ETA)."""
        async with self._conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """with recent as (
                     select j.job_id from jobs j
                     where j.chain is not distinct from %s
                       and exists (select 1 from job_steps s where s.job_id = j.job_id and s.status = 'done')
                     order by j.created_at desc limit %s)
                   select s.step, percentile_cont(0.5) within group (
                            order by extract(epoch from (s.finished_at - s.started_at))) as median_s
                   from job_steps s join recent r on r.job_id = s.job_id
                   where s.status = 'done' and s.started_at is not null and s.finished_at is not null
                   group by s.step""",
                (chain, limit_jobs),
            )
            rows = await cur.fetchall()
        return {r["step"]: float(r["median_s"]) for r in rows if r["median_s"] is not None}


def _sha256_json(doc: Any) -> str:
    import hashlib
    import json

    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Module-level helper: build a repo from the ambient pool
# ---------------------------------------------------------------------------

def make_repo(conn: psycopg.AsyncConnection) -> JobRepo:
    """Convenience factory: wraps *conn* in a ``JobRepo``."""
    return JobRepo(conn)


# ---------------------------------------------------------------------------
# DSN from environment (fall-through for local dev)
# ---------------------------------------------------------------------------

def db_dsn() -> str:
    """Return the Postgres DSN from ``SOKEN_DATABASE_URL``."""
    dsn = os.environ.get("SOKEN_DATABASE_URL")
    if not dsn:
        raise RuntimeError("SOKEN_DATABASE_URL not set")
    return dsn
