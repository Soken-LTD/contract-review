"""PgJobContext: Postgres implementation of JobContext (plan-v4 03 sections 3.4, 4.4).

Uses a synchronous psycopg connection pool so it satisfies the sync JobContext protocol
even when called from within async tool handlers.

Also provides the ``create_app`` app factory that wires the pool and context before
returning the ASGI app from server.create_app() (09 workstream).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import psycopg_pool

from .context import JobContext  # noqa: F401 (re-exported for callers)

# Verify at import that PgJobContext will satisfy the protocol at runtime.
# (The check runs when the class is first instantiated, not at import time,
#  because it uses @runtime_checkable.)


class PgJobContext:
    """JobContext backed by a synchronous psycopg connection pool (03 sections 3.4, 4.4).

    All methods are intentionally synchronous; they are called from sync helper
    functions that are themselves called from async tool handlers.  Opening a
    fresh sync connection per call is acceptable (single-row queries, infrequent).
    """

    def __init__(
        self,
        pool: psycopg_pool.ConnectionPool,
        pin_root: Path,
    ) -> None:
        self._pool = pool
        self._pin_root = pin_root

    # ── JobContext protocol ──────────────────────────────────────────────────

    def get_pin_root(self) -> Path:
        """Return the root directory for job pin stores (04 5.1)."""
        return self._pin_root

    def get_job_state(self, job_id: str) -> str | None:
        """Return current job state or None if not found (03 3.5)."""
        with self._pool.connection() as conn:
            row = conn.execute(
                "select state from jobs where job_id = %s",
                (job_id,),
            ).fetchone()
        return row[0] if row else None

    def append_read(self, job_id: str, path: str, start: int, end: int) -> None:
        """Insert a job_reads row (03 4.4); never called for search hits (03 4.5)."""
        with self._pool.connection() as conn:
            conn.execute(
                "insert into job_reads (job_id, path, start_line, end_line) values (%s, %s, %s, %s)",
                (job_id, path, start, end),
            )
            # psycopg autocommit=False by default; commit explicitly.
            conn.commit()


# ---------------------------------------------------------------------------
# Application factory (09 workstream deliverable)
# ---------------------------------------------------------------------------

class _LifespanWrapper:
    """ASGI middleware: open DB pools on startup, close on shutdown (09 workstream).

    The inner Starlette app has its own lifespan (the MCP SDK starts its session manager task
    group there); it runs inside ours, after the pools are open.
    """

    def __init__(self, inner: Any, dsn: str, pin_root: Path) -> None:
        self._inner = inner
        self._dsn = dsn
        self._pin_root = pin_root
        self._async_pool: psycopg_pool.AsyncConnectionPool | None = None
        self._sync_pool: psycopg_pool.ConnectionPool | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
        else:
            await self._inner(scope, receive, send)

    async def _lifespan(self, receive: Any, send: Any) -> None:
        event = await receive()
        if event["type"] != "lifespan.startup":
            return
        starlette_app = getattr(self._inner, "app", self._inner)  # http.ProtocolRules wraps Starlette
        try:
            await self._startup()
            inner_lifespan = starlette_app.router.lifespan_context(starlette_app)
            await inner_lifespan.__aenter__()
        except Exception as exc:  # noqa: BLE001
            await send({"type": "lifespan.startup.failed", "message": str(exc)})
            return
        await send({"type": "lifespan.startup.complete"})

        event = await receive()
        if event["type"] == "lifespan.shutdown":
            await inner_lifespan.__aexit__(None, None, None)
            await self._shutdown()
            await send({"type": "lifespan.shutdown.complete"})

    async def _startup(self) -> None:
        # Async pool (used by review_start / review_status handlers)
        self._async_pool = psycopg_pool.AsyncConnectionPool(
            self._dsn, min_size=2, max_size=10, open=False
        )
        await self._async_pool.open()

        # Inject into start_status and db.pool
        from ..db import pool as _pool_mod
        from ..tools import start_status as _ss_mod
        _ss_mod.set_pool(self._async_pool)
        from ..tools import report as _report_mod
        _report_mod.set_pool(self._async_pool)
        _pool_mod.set_pool(self._async_pool)

        # Sync pool (used by PgJobContext for read tool handlers)
        self._sync_pool = psycopg_pool.ConnectionPool(
            self._dsn, min_size=1, max_size=5, open=False
        )
        self._sync_pool.open()

        ctx = PgJobContext(self._sync_pool, self._pin_root)
        from ..tools import read as _read_mod
        _read_mod.set_context(ctx)

    async def _shutdown(self) -> None:
        if self._async_pool:
            await self._async_pool.close()
        if self._sync_pool:
            self._sync_pool.close()


def create_app() -> Any:
    """App factory for uvicorn --factory: wraps the MCP server with DB pool lifespan.

    Called as ``uvicorn --factory soken_review.app:create_app``.
    If ``SOKEN_DATABASE_URL`` is not set, returns the bare server app (useful in
    unit tests that mock the DB at the tool level).
    """
    from ..server import create_app as _create_server_app

    dsn = os.environ.get("SOKEN_DATABASE_URL", "")
    pin_root = Path(os.environ.get("SOKEN_PIN_ROOT", "/srv/sbx"))
    inner = _create_server_app()
    if not dsn:
        return inner
    return _LifespanWrapper(inner, dsn, pin_root)
