"""`python -m soken_review.worker`: the supervisor as a service process (09 1, 3.3).

Everything comes from the environment (systemd EnvironmentFile / LoadCredential), nothing from
argv, so the unit file is the whole contract. Sizing defaults match the Supervisor defaults
(seven units, 14 GiB) and are overridden per host.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.worker import __main__ as entry


def test_settings_require_the_dsn(monkeypatch):
    monkeypatch.delenv("SOKEN_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit) as exc:
        entry.settings_from_env({})
    assert "SOKEN_DATABASE_URL" in str(exc.value)


def test_settings_defaults(monkeypatch):
    s = entry.settings_from_env({"SOKEN_DATABASE_URL": "postgresql://u:p@h/db"})
    assert s.dsn == "postgresql://u:p@h/db"
    assert s.pin_root == Path("/srv/sbx/pins")
    assert s.host_name is None                      # Supervisor falls back to the hostname
    assert (s.total_units, s.total_ram_mb, s.poll_interval) == (7, 14336, 1.0)


def test_settings_from_a_full_environment():
    s = entry.settings_from_env({
        "SOKEN_DATABASE_URL": "postgresql://u:p@h/db", "SOKEN_PIN_ROOT": "/srv/soken/pins",
        "SOKEN_WORKER_HOST": "mcp-staging-1", "SOKEN_WORKER_UNITS": "4", "SOKEN_WORKER_RAM_MB": "6144",
        "SOKEN_WORKER_POLL_S": "0.5",
    })
    assert s.pin_root == Path("/srv/soken/pins") and s.host_name == "mcp-staging-1"
    assert (s.total_units, s.total_ram_mb, s.poll_interval) == (4, 6144, 0.5)


@pytest.mark.parametrize("key,value", [
    ("SOKEN_WORKER_UNITS", "0"), ("SOKEN_WORKER_UNITS", "x"), ("SOKEN_WORKER_RAM_MB", "-1"),
    ("SOKEN_WORKER_POLL_S", "0"), ("SOKEN_PIN_ROOT", "relative/path"),
])
def test_settings_reject_bad_values(key, value):
    env = {"SOKEN_DATABASE_URL": "postgresql://u:p@h/db", key: value}
    with pytest.raises(SystemExit) as exc:
        entry.settings_from_env(env)
    assert key in str(exc.value)


@pytest.mark.asyncio
async def test_run_opens_pool_builds_supervisor_and_closes_pool(tmp_path):
    pool = MagicMock()
    pool.open = AsyncMock()
    pool.close = AsyncMock()
    sup = MagicMock()
    sup.run = AsyncMock(side_effect=RuntimeError("stop"))
    settings = entry.Settings(dsn="postgresql://u:p@h/db", pin_root=tmp_path / "pins", host_name="w1",
                              total_units=3, total_ram_mb=4096, poll_interval=0.2)
    with patch.object(entry, "AsyncConnectionPool", return_value=pool) as pool_cls, \
         patch.object(entry, "Supervisor", return_value=sup) as sup_cls, pytest.raises(RuntimeError):
        await entry.run(settings)
    pool_cls.assert_called_once()
    assert pool_cls.call_args.args[0] == settings.dsn and pool_cls.call_args.kwargs["open"] is False
    sup_cls.assert_called_once_with(pool, tmp_path / "pins", host_name="w1", poll_interval=0.2,
                                    total_units=3, total_ram_mb=4096)
    pool.open.assert_awaited_once()
    pool.close.assert_awaited_once()                 # closed even when the loop raises
    assert (tmp_path / "pins").is_dir()               # pin root created before the first job
