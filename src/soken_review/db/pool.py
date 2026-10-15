"""Async connection pool wrapper (plan-v4 part 03 section 3.3, 09 topology).

The pool is module-level and shared across requests (stateless HTTP, one process per replica).
`set_pool` lets tests inject a pool over a test database; `open_pool` creates one from a DSN.

Environment variable ``SOKEN_DATABASE_URL`` is read at import if the pool has not been set.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import psycopg_pool
from psycopg import AsyncConnection

_pool: psycopg_pool.AsyncConnectionPool | None = None


def set_pool(pool: psycopg_pool.AsyncConnectionPool) -> None:
    """Inject a pool (used by tests and the application lifespan)."""
    global _pool
    _pool = pool


def get_pool() -> psycopg_pool.AsyncConnectionPool:
    """Return the active pool; raise if not yet configured."""
    if _pool is None:
        raise RuntimeError("DB pool not initialised; call set_pool() or open_pool() first")
    return _pool


@asynccontextmanager
async def open_pool(
    dsn: str | None = None,
    min_size: int = 2,
    max_size: int = 10,
) -> AsyncIterator[psycopg_pool.AsyncConnectionPool]:
    """Context manager: open a pool, set it as the module default, close on exit."""
    global _pool
    dsn = dsn or os.environ["SOKEN_DATABASE_URL"]
    pool = psycopg_pool.AsyncConnectionPool(dsn, min_size=min_size, max_size=max_size, open=False)
    await pool.open()
    _pool = pool
    try:
        yield pool
    finally:
        await pool.close()
        if _pool is pool:
            _pool = None


@asynccontextmanager
async def acquire() -> AsyncIterator[AsyncConnection]:
    """Borrow a connection from the active pool."""
    async with get_pool().connection() as conn:
        yield conn
