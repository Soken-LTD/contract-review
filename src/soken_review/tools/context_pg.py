"""PgJobContext: Postgres implementation of JobContext (plan-v4 03 sections 3.4, 4.4).

Uses a synchronous psycopg connection pool so it satisfies the sync JobContext protocol
even when called from within async tool handlers.

Also provides the ``create_app`` app factory that wires the pool and context before
returning the ASGI app from server.create_app() (09 workstream).
"""

from __future__ import annotations

import json
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
        elif scope["type"] == "http" and scope.get("path", "").rstrip("/") == "/healthz":
            await self._healthz(scope, send)
        else:
            await self._inner(scope, receive, send)

    async def _healthz(self, scope: Any, send: Any) -> None:
        """GET /healthz for the monitor (09 O5): 200 when the database answers and a worker
        heartbeat is fresh (`worker_hosts.last_seen`, every 15 s), 503 with the reason otherwise.
        No job data, no auth, no caching."""
        if scope.get("method") != "GET":
            body, status = b'{"error":"method"}', 405
        else:
            payload, ok = await health_payload(self._async_pool)
            body, status = json.dumps(payload, separators=(",", ":")).encode(), (200 if ok else 503)
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

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
        # A real deployment never signs report links with a per-process random key.
        from .report import require_report_keys

        require_report_keys()
        # Async pool (used by review_start / review_status handlers)
        self._async_pool = psycopg_pool.AsyncConnectionPool(
            self._dsn, min_size=2, max_size=10, open=False
        )
        await self._async_pool.open()

        from ..db import pool as _pool_mod
        from ..tools import (
            chain,
            challenge,
            context_tool,
            dismiss,
            finalize,
            read,
            report,
            set_section,
            start_status,
            submit,
            verify_fork,
            withdraw,
        )
        from . import delete

        # Wire async pool into every module that needs it.
        # One loop: adding a new tool module here is the only change needed.
        _POOL_MODULES = [start_status, report, submit, finalize, challenge, dismiss, withdraw, set_section,
                         context_tool, delete, chain, verify_fork]
        for mod in _POOL_MODULES:
            if hasattr(mod, "set_pool"):
                mod.set_pool(self._async_pool)
        _pool_mod.set_pool(self._async_pool)

        # Sync pool (used by PgJobContext for read tool handlers and all write tools)
        self._sync_pool = psycopg_pool.ConnectionPool(
            self._dsn, min_size=1, max_size=5, open=False
        )
        self._sync_pool.open()

        ctx = PgJobContext(self._sync_pool, self._pin_root)

        # Wire context into every module that reads pins/maps.
        _CTX_MODULES = [read, submit, finalize, challenge, dismiss, withdraw, set_section, context_tool, delete, chain, verify_fork]
        for mod in _CTX_MODULES:
            if hasattr(mod, "set_context"):
                mod.set_context(ctx)

    async def _shutdown(self) -> None:
        if self._async_pool:
            await self._async_pool.close()
        if self._sync_pool:
            self._sync_pool.close()


WORKER_STALE_S = 90   # six missed 15 s heartbeats


async def health_payload(pool: Any) -> tuple[dict[str, Any], bool]:
    """(payload, healthy): database reachable and at least one worker seen within WORKER_STALE_S."""
    out: dict[str, Any] = {"db": "down", "worker_age_s": None, "workers": 0}
    if pool is None:
        return out, False
    try:
        async with pool.connection() as conn:
            row = await (await conn.execute(
                "select count(*), extract(epoch from now() - max(last_seen)) from worker_hosts")).fetchone()
        out["db"] = "ok"
        out["workers"] = int(row[0] or 0)
        out["worker_age_s"] = round(float(row[1]), 1) if row[1] is not None else None
    except Exception as exc:  # noqa: BLE001  # the monitor sees the class, never the DSN
        out["db"] = f"error: {type(exc).__name__}"
        return out, False
    ok = out["worker_age_s"] is not None and out["worker_age_s"] <= WORKER_STALE_S
    return out, ok


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
