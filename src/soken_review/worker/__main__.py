"""`python -m soken_review.worker`: run the supervisor as a service (09 1, 3.3).

Configuration comes from the environment only (systemd `EnvironmentFile=` / `LoadCredential=`),
so the unit file is the whole contract:

    SOKEN_DATABASE_URL    Postgres DSN of the worker role (required)
    SOKEN_PIN_ROOT        pin store root, absolute (default /srv/sbx/pins)
    SOKEN_WORKER_HOST     name recorded in worker_hosts (default: the hostname)
    SOKEN_WORKER_UNITS    concurrent step units this host offers (default 7)
    SOKEN_WORKER_RAM_MB   RAM budget for step containers (default 14336)
    SOKEN_WORKER_POLL_S   queue poll interval in seconds (default 1.0)

Sandbox settings (`SOKEN_SANDBOX_RUNTIME`, `SOKEN_IMAGE_*`, provider keys) are read where they are
used; see the adapters and `sandbox/profile.py`.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from psycopg_pool import AsyncConnectionPool

from .supervisor import Supervisor

log = logging.getLogger("soken_review.worker")


@dataclass(frozen=True)
class Settings:
    dsn: str
    pin_root: Path
    host_name: str | None
    total_units: int
    total_ram_mb: int
    poll_interval: float


def _positive_int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise SystemExit(f"{key} must be a positive integer, got {raw!r}") from None
    if value <= 0:
        raise SystemExit(f"{key} must be a positive integer, got {raw!r}")
    return value


def settings_from_env(env: Mapping[str, str]) -> Settings:
    """Validate the service environment; a bad value is a startup error, never a default."""
    dsn = env.get("SOKEN_DATABASE_URL")
    if not dsn:
        raise SystemExit("SOKEN_DATABASE_URL is required")
    pin_root = Path(env.get("SOKEN_PIN_ROOT") or "/srv/sbx/pins")
    if not pin_root.is_absolute():
        raise SystemExit(f"SOKEN_PIN_ROOT must be absolute, got {pin_root}")
    raw_poll = env.get("SOKEN_WORKER_POLL_S")
    try:
        poll = float(raw_poll) if raw_poll else 1.0
    except ValueError:
        raise SystemExit(f"SOKEN_WORKER_POLL_S must be a positive number, got {raw_poll!r}") from None
    if poll <= 0:
        raise SystemExit(f"SOKEN_WORKER_POLL_S must be a positive number, got {raw_poll!r}")
    return Settings(
        dsn=dsn, pin_root=pin_root, host_name=env.get("SOKEN_WORKER_HOST") or None,
        total_units=_positive_int(env, "SOKEN_WORKER_UNITS", 7),
        total_ram_mb=_positive_int(env, "SOKEN_WORKER_RAM_MB", 14336),
        poll_interval=poll,
    )


async def run(settings: Settings) -> None:
    """Open the pool, run the supervisor loop until cancelled, close the pool."""
    settings.pin_root.mkdir(parents=True, exist_ok=True)
    pool = AsyncConnectionPool(settings.dsn, min_size=2, max_size=5, open=False)
    await pool.open()
    try:
        sup = Supervisor(pool, settings.pin_root, host_name=settings.host_name,
                         poll_interval=settings.poll_interval,
                         total_units=settings.total_units, total_ram_mb=settings.total_ram_mb)
        log.info("worker %s: units=%d ram_mb=%d pin_root=%s", settings.host_name or "<hostname>",
                 settings.total_units, settings.total_ram_mb, settings.pin_root)
        await sup.run()
    finally:
        await pool.close()


def main(argv: list[str] | None = None) -> int:
    if argv:
        raise SystemExit("python -m soken_review.worker takes no arguments; configure it through the environment")
    logging.basicConfig(level=os.environ.get("SOKEN_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        asyncio.run(run(settings_from_env(os.environ)))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
