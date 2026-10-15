#!/usr/bin/env python3
"""Local dev runner: Postgres (docker), migrations, HTTP app, one worker (09 workstream).

Usage::

    python scripts/run_local.py [--port 8000]

Environment variables (all optional for local dev):
  SOKEN_DATABASE_URL   Postgres DSN (default: local docker container)
  SOKEN_PIN_ROOT       Pin store root (default: .sbx/pins)
  SOKEN_RPC_<id>       RPC URL for chain id, e.g. SOKEN_RPC_1, SOKEN_RPC_8453
  SOKEN_SANDBOX_RUNTIME  runc (default for local) or runsc-none
  SOKEN_IMAGE_EVM_ANALYZE  Docker image id for evm-analyze sandbox
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DSN = "postgresql://soken:soken@127.0.0.1:5434/soken"
PG_CONTAINER = "soken-pg-local"
PG_IMAGE = "postgres:16"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("run_local")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Soken local dev runner")
    p.add_argument("--port", type=int, default=8000, help="HTTP port (default 8000)")
    p.add_argument("--no-docker", action="store_true", help="Skip docker; assume Postgres is up")
    p.add_argument("--no-worker", action="store_true", help="Skip worker; only start HTTP server")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Docker Postgres helpers
# ---------------------------------------------------------------------------

def _pg_running() -> bool:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", PG_CONTAINER],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def start_postgres() -> None:
    if _pg_running():
        logger.info("Postgres container %s already running", PG_CONTAINER)
        return

    # Remove a stopped container if it exists
    subprocess.run(["docker", "rm", PG_CONTAINER], capture_output=True)

    logger.info("Starting Postgres container %s", PG_CONTAINER)
    subprocess.run([
        "docker", "run", "--name", PG_CONTAINER,
        "-e", "POSTGRES_USER=soken",
        "-e", "POSTGRES_PASSWORD=soken",
        "-e", "POSTGRES_DB=soken",
        "-p", "5434:5432",
        "-d", PG_IMAGE,
    ], check=True)

    # Wait for PG to be ready
    for attempt in range(30):
        result = subprocess.run(
            ["docker", "exec", PG_CONTAINER, "pg_isready", "-U", "soken"],
            capture_output=True,
        )
        if result.returncode == 0:
            logger.info("Postgres ready after %ds", attempt + 1)
            return
        time.sleep(1)
    raise RuntimeError("Postgres failed to start in 30s")


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------

async def run_migrations(dsn: str) -> None:
    import soken_review.db.migrate as migrate_mod
    applied = await migrate_mod.run_migrations(dsn)
    if applied:
        logger.info("Applied migrations: %s", applied)
    else:
        logger.info("All migrations already applied")


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

async def run_worker(dsn: str, pin_root: Path) -> None:
    import psycopg_pool
    from soken_review.worker.supervisor import Supervisor

    logger.info("Starting worker (pin_root=%s)", pin_root)
    pool = psycopg_pool.AsyncConnectionPool(dsn, min_size=2, max_size=5, open=False)
    await pool.open()
    try:
        sup = Supervisor(pool, pin_root, host_name="local-worker-1")
        await sup.run()
    finally:
        await pool.close()


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

async def run_server(dsn: str, pin_root: Path, port: int) -> None:
    import uvicorn
    from soken_review.tools.context_pg import create_app

    os.environ.setdefault("SOKEN_DATABASE_URL", dsn)
    os.environ.setdefault("SOKEN_PIN_ROOT", str(pin_root))

    logger.info("Starting HTTP server on port %d", port)
    config = uvicorn.Config(
        app=create_app(),
        host="127.0.0.1",
        port=port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    await server.serve()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main_async(args: argparse.Namespace) -> None:
    dsn = os.environ.get("SOKEN_DATABASE_URL", DEFAULT_DSN)
    sbx_root = REPO_ROOT / ".sbx"
    pin_root = Path(os.environ.get("SOKEN_PIN_ROOT", str(sbx_root / "pins")))
    pin_root.mkdir(parents=True, exist_ok=True)
    (sbx_root / "work").mkdir(parents=True, exist_ok=True)

    if not args.no_docker:
        start_postgres()
        # Small delay to ensure PG is fully up
        await asyncio.sleep(1)

    await run_migrations(dsn)

    tasks: list[asyncio.Task] = []
    tasks.append(asyncio.create_task(run_server(dsn, pin_root, args.port)))
    if not args.no_worker:
        tasks.append(asyncio.create_task(run_worker(dsn, pin_root)))

    try:
        await asyncio.gather(*tasks)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down")
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    args = parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main() or 0)
