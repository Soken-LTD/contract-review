"""Migration runner (plan-v4 part 03 section 3.6).

Applies SQL files in `migrations/` in lexicographic order, tracking applied migrations in a
`schema_migrations` table (created on first run). Each migration runs in its own transaction;
already-applied migrations are skipped. The runner is idempotent.

Usage::

    from soken_review.db.migrate import run_migrations
    await run_migrations(dsn)

Or from the CLI::

    python -m soken_review.db.migrate postgres://...
"""

from __future__ import annotations

import logging
from pathlib import Path

import psycopg

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parents[3] / "migrations"

_TRACKING_DDL = """
create table if not exists schema_migrations (
  name text primary key,
  applied_at timestamptz not null default now()
);
"""


async def run_migrations(dsn: str, migrations_dir: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply unapplied migrations; return list of newly applied names."""
    applied: list[str] = []

    async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
        await conn.execute(_TRACKING_DDL)

        files = sorted(migrations_dir.glob("*.sql"))
        for path in files:
            name = path.name
            row = await (await conn.execute("select 1 from schema_migrations where name = %s", (name,))).fetchone()
            if row:
                log.debug("migration %s already applied", name)
                continue

            sql = path.read_text()
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute("insert into schema_migrations (name) values (%s)", (name,))
            log.info("migration %s applied", name)
            applied.append(name)

    return applied


if __name__ == "__main__":  # pragma: no cover
    import asyncio
    import os
    import sys

    logging.basicConfig(level=logging.INFO)
    # `python -m soken_review.db.migrate [dsn]`; a service unit passes the DSN through the
    # environment instead (SOKEN_DATABASE_URL), never on a command line visible in `ps`.
    dsn = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SOKEN_DATABASE_URL")
    if not dsn:
        sys.exit("usage: python -m soken_review.db.migrate [dsn]  (or set SOKEN_DATABASE_URL)")
    asyncio.run(run_migrations(dsn))
