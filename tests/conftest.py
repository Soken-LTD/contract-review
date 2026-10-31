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


@pytest.fixture(autouse=True)
def _host_capacity_is_known():
    """Container admission (sandbox.profile) must not depend on the test runner's RAM: every test
    sees a 64 GiB host with the default budget unless it configures its own (the admission tests)."""
    from soken_review.sandbox import profile

    previous = profile._HOST
    profile.configure_host_capacity(14336, physical_mb=65536)
    yield
    profile._HOST = previous

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


@pytest_asyncio.fixture(loop_scope="session")
async def db_conn(db_pool):
    """Single async connection, auto-rollback after each test for isolation.

    Runs on the session loop that owns `db_pool`: a pool used from another loop (a function-scoped
    fixture loop, or the anyio plugin's runner) hangs on its loop-bound primitives (PoolTimeout) and
    tears async fixtures down in another task (anyio "exit cancel scope in a different task"), as
    CI run 40501752418 showed. Every DB test is `pytest.mark.asyncio(loop_scope="session")`."""
    async with db_pool.connection() as conn, conn.transaction():
        yield conn
        raise psycopg.Rollback()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "live: mark a test as requiring live network access (skipped by default; run with -m live)",
    )
    config.addinivalue_line(
        "markers",
        "output_schema_violation_expected: the test builds a non-conforming structured result on purpose",
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


# ---------------------------------------------------------------------------
# Output-schema guard: every structured result the suite produces must match the tool's outputSchema
# ---------------------------------------------------------------------------
#
# Claude Code 2.1.309 drops a tool result whose structuredContent breaks the declared outputSchema.
# Two live failures (review_report links on mcp.soken.dev, review_dismiss_lead rejected[] items) had
# no test because nothing compared handler output to the contract. This guard wraps every registered
# control-tool handler (HANDLERS and the module attributes tests import) and SokenServer.call_tool,
# records every violation, and fails the test that produced it.

_OUTPUT_VIOLATIONS: list[str] = []


def _install_output_schema_guard() -> None:
    import functools
    import sys

    from soken_review import server as srv

    def check(name: str, body, where: str) -> None:
        bad = srv.output_violations(name, body)
        if bad:
            _OUTPUT_VIOLATIONS.append(f"{name} ({where}): " + "; ".join(bad[:10]))

    def guard(name: str, fn):
        if name not in srv._output_validators() or getattr(fn, "_schema_guarded", False):
            return fn

        @functools.wraps(fn)
        async def guarded(*args, **kwargs):
            result = await fn(*args, **kwargs)
            check(name, result, "handler")
            return result

        guarded._schema_guarded = True
        return guarded

    class GuardedHandlers(dict):
        """Wraps every handler stored in it, including late registrations and monkeypatched fakes."""

        def __setitem__(self, name, fn):
            super().__setitem__(name, guard(name, fn))

    def handler(name: str):
        def register(fn):
            wrapped = guard(name, fn)
            srv.HANDLERS[name] = wrapped
            return wrapped   # the module attribute a test imports is the guarded one too

        return register

    already = dict(srv.HANDLERS)
    srv.HANDLERS = GuardedHandlers()
    srv.handler = handler
    for name, fn in already.items():
        srv.HANDLERS[name] = fn
    import soken_review.tools  # noqa: F401  (registers every handler through the guarded decorator)

    for name, wrapped in list(srv.HANDLERS.items()):   # handlers registered before the guard existed
        fn = getattr(wrapped, "__wrapped__", None)
        if fn is None:
            continue
        for mod in list(sys.modules.values()):
            if getattr(mod, "__name__", "").startswith("soken_review") and getattr(mod, fn.__name__, None) is fn:
                setattr(mod, fn.__name__, wrapped)

    original = srv.SokenServer.call_tool
    if getattr(original, "_schema_guarded", False):
        return

    @functools.wraps(original)
    async def call_tool(self, name, arguments, context=None):
        res = await original(self, name, arguments, context)
        if res.structured_content is not None:
            check(name, res.structured_content, "call_tool")
        return res

    call_tool._schema_guarded = True
    srv.SokenServer.call_tool = call_tool


_install_output_schema_guard()


@pytest.fixture(autouse=True)
def _structured_results_match_output_schema(request):
    _OUTPUT_VIOLATIONS.clear()
    yield
    found, _OUTPUT_VIOLATIONS[:] = list(_OUTPUT_VIOLATIONS), []
    if found and request.node.get_closest_marker("output_schema_violation_expected") is None:
        pytest.fail("structured result breaks the tool's outputSchema:\n" + "\n".join(dict.fromkeys(found)),
                    pytrace=False)
