"""Migration 009 (context) applies after 008 on an empty database and on one that already ran 008."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import psycopg
import pytest

from soken_review.db.migrate import MIGRATIONS_DIR, run_migrations

pytestmark = pytest.mark.asyncio(loop_scope="session")


def _scratch_dsn(pg_dsn: str, name: str) -> str:
    base, _, _db = pg_dsn.rpartition("/")
    return f"{base}/{name}"


async def test_009_applies_on_a_db_that_already_ran_008(pg_dsn, tmp_path: Path) -> None:
    name = "soken_mig_ctx_test"
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(f"drop database if exists {name}")
        conn.execute(f"create database {name}")
    dsn = _scratch_dsn(pg_dsn, name)
    try:
        upto8 = tmp_path / "upto8"
        upto8.mkdir()
        for p in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if p.name < "009":
                shutil.copy(p, upto8 / p.name)
        first = await run_migrations(dsn, upto8)
        assert first[-1] == "008_sections_context_notes.sql" and "009_context.sql" not in first
        second = await run_migrations(dsn)                 # the full directory on the 008 database
        later = sorted(p.name for p in MIGRATIONS_DIR.glob("*.sql") if p.name >= "009")
        assert second == later and second[0] == "009_context.sql"
        assert await run_migrations(dsn) == []             # idempotent
        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            cols = await (await conn.execute(
                "select column_name from information_schema.columns where table_name = 'jobs' and column_name = 'context_items'"
            )).fetchone()
            assert cols is not None
            steps = await (await conn.execute(
                "select pg_get_constraintdef(oid) from pg_constraint where conname = 'job_steps_step_check'")).fetchone()
            assert "context" in steps[0]
            sections = await (await conn.execute(
                "select pg_get_constraintdef(oid) from pg_constraint where conname = 'sections_section_check'")).fetchone()
            assert "context_notes" in sections[0]
    finally:
        await asyncio.sleep(0)
        with psycopg.connect(pg_dsn, autocommit=True) as conn:
            conn.execute(f"drop database if exists {name} with (force)")
