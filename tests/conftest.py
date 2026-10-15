"""Shared fixtures: live marker (05 live fetch tests); Postgres 16 via docker (03): Postgres 16 via docker, psycopg3 pool injection.

DB tests are skipped when docker is unavailable or SKIP_DB_TESTS is set.
The sandbox dir is ``<repo>/.sbx/`` (gitignored) so bind-mounts work under $HOME
on Docker Desktop / Colima (09 topology note).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path

import psycopg
import psycopg_pool
import pytest
import pytest_asyncio

from soken_review.db.migrate import run_migrations

# ---------------------------------------------------------------------------
# Docker availability check
# ---------------------------------------------------------------------------


def _docker_ok() -> bool:
    if os.environ.get("SKIP_DB_TESTS"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=10)
        return True
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


_DOCKER_AVAILABLE = _docker_ok()

# ---------------------------------------------------------------------------
# Postgres 16 container fixture (session-scoped)
# ---------------------------------------------------------------------------

_SBX_DIR = Path(__file__).resolve().parents[1] / ".sbx" / "pg16"
_PG_IMAGE = "postgres:16"
_PG_NAME = "soken-test-pg16"
_PG_PORT = 15432  # avoid collision with any local postgres
_PG_PASSWORD = "testpass"
_PG_DSN = f"postgresql://postgres:{_PG_PASSWORD}@127.0.0.1:{_PG_PORT}/postgres"


@pytest.fixture(scope="session")
def pg_dsn():
    """Start Postgres 16 in Docker, run migrations, yield DSN, stop on teardown.

    Skipped if Docker is unavailable. `SOKEN_TEST_PG_DSN` points the tests at an existing, empty
    Postgres 16 database instead (parallel worktrees share the fixed container name otherwise).
    """
    external = os.environ.get("SOKEN_TEST_PG_DSN")
    if external:
        asyncio.run(run_migrations(external))
        yield external
        return
    if not _DOCKER_AVAILABLE:
        pytest.skip("Docker unavailable; set SKIP_DB_TESTS=1 to suppress")

    _SBX_DIR.mkdir(parents=True, exist_ok=True)

    # Stop+remove any leftover container from a previous run
    subprocess.run(["docker", "rm", "-f", _PG_NAME], capture_output=True, check=False)

    cmd = [
        "docker", "run", "-d",
        "--name", _PG_NAME,
        "-e", f"POSTGRES_PASSWORD={_PG_PASSWORD}",
        "-p", f"127.0.0.1:{_PG_PORT}:5432",
        "-v", f"{_SBX_DIR}:/var/lib/postgresql/data",
        _PG_IMAGE,
    ]
    subprocess.run(cmd, check=True, capture_output=True)

    # Wait for Postgres to accept connections
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with psycopg.connect(_PG_DSN, connect_timeout=2):
                break
        except psycopg.OperationalError:
            time.sleep(0.5)
    else:
        subprocess.run(["docker", "rm", "-f", _PG_NAME], check=False)
        pytest.fail("Postgres 16 did not start within 60 s")

    # Run migrations
    asyncio.run(run_migrations(_PG_DSN))

    yield _PG_DSN

    subprocess.run(["docker", "rm", "-f", _PG_NAME], capture_output=True, check=False)


@pytest.fixture(scope="session")
def event_loop_policy():
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture(scope="session")
def anyio_backend():
    """Session-scoped anyio backend so session-scoped async fixtures work."""
    return "asyncio"


@pytest_asyncio.fixture(scope="session")
async def db_pool(pg_dsn):
    """Async connection pool over the test database (session-scoped)."""
    pool = psycopg_pool.AsyncConnectionPool(pg_dsn, min_size=2, max_size=5, open=False)
    await pool.open()
    yield pool
    await pool.close()


@pytest_asyncio.fixture()
async def db_conn(db_pool):
    """Single async connection, auto-rollback after each test for isolation."""
    async with db_pool.connection() as conn, conn.transaction():
        yield conn
        raise psycopg.Rollback()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "live: mark a test as requiring live network access (skipped by default; run with -m live)",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip @pytest.mark.live tests unless '-m live' is explicitly passed."""
    # Only skip when the user has NOT selected the live marker explicitly
    marker_expr = config.getoption("-m", default="", skip=True)
    if "live" in str(marker_expr):
        return  # user asked for live tests — do not skip
    skip_live = pytest.mark.skip(reason="live test; run with: uv run pytest -m live")
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(skip_live)


@pytest.fixture(autouse=True)
def _sandbox_dev_perms(monkeypatch):
    """Tests run as a non-root user: allow the dev-only 0o777 fallback of sandbox_writable_dir."""
    monkeypatch.setenv("SOKEN_SANDBOX_DEV_PERMS", "1")
