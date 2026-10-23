"""Worker side of the host memory admission (09 3.3 budgets against physical memory).

The Supervisor measures the host once at start and records it in worker_hosts.ram_mb_total; a
step the sandbox refuses (HostCapacityError) fails its job with E_HOST_CAPACITY and the numbers,
never E_INTERNAL; the Starknet build runner turns a `host_capacity` build result into the same
job failure before any analyze step is queued."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.sandbox import profile as P
from soken_review.sandbox.profile import HostCapacityError
from soken_review.worker import starknet_steps as S
from soken_review.worker.supervisor import Supervisor


def _conn_ctx() -> AsyncMock:
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    return conn


def test_supervisor_measures_the_host_once_at_start(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(P, "physical_memory_mb", lambda _m=None: 3915)
    sup = Supervisor(MagicMock(), tmp_path, host_name="stand", total_ram_mb=14336)
    assert sup._host_capacity == P.HostCapacity(physical_mb=3915, budget_mb=14336)
    assert P.host_capacity() is sup._host_capacity
    # The claim budget stays the configured one: a budget clamped to the host would leave an
    # 8 GiB step queued forever; the admission fails it with a reason instead.
    assert sup._total_ram_mb == sup._free_ram_mb == 14336


@pytest.mark.asyncio
async def test_heartbeat_records_physical_memory_and_updates_it(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(P, "physical_memory_mb", lambda _m=None: 3915)
    sup = Supervisor(MagicMock(), tmp_path, host_name="stand", total_units=2, total_ram_mb=14336)
    conn = _conn_ctx()
    sup._pool.connection = MagicMock(return_value=conn)

    async def stop(_s: float) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        await sup._heartbeat_loop()
    sql, params = conn.execute.call_args[0]
    assert params == ("stand", 2, 3915)
    assert "ram_mb_total = excluded.ram_mb_total" in sql


@pytest.mark.asyncio
async def test_refused_step_fails_the_job_with_e_host_capacity(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(P, "physical_memory_mb", lambda _m=None: 3915)
    sup = Supervisor(MagicMock(), tmp_path, host_name="stand")
    step = {"id": 7, "job_id": "job_STK00001", "step": "build", "seq": 0, "container": True, "units": 4,
            "ram_mb": 8192, "attempt": 1, "max_attempts": 1, "lease_owner": "stand"}
    job = {"job_id": "job_STK00001", "chain": "starknet", "state": "building", "address": "0x1"}
    repo = AsyncMock()
    repo.get = AsyncMock(return_value=job)
    conn = _conn_ctx()
    sup._pool.connection = MagicMock(return_value=conn)

    async def refused(_sup, _step, _job):
        raise HostCapacityError(step="build", need_mb=8192, host_mb=3915, cap_mb=3523)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo), \
         patch("soken_review.worker.starknet_steps.run_step", new=refused), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job)):
        await sup._run_step(step)

    repo.complete_step.assert_awaited_once_with(7, "failed", error_code="E_HOST_CAPACITY")
    repo.transition.assert_awaited()
    args, kwargs = repo.transition.call_args
    assert args[:2] == ("job_STK00001", "failed") and kwargs["error_code"] == "E_HOST_CAPACITY"
    assert kwargs["error_detail"] == {"reason": "insufficient_host_memory", "stage": "build", "need_mb": 8192,
                                      "host_mb": 3915, "cap_mb": 3523}
    assert sup._free_ram_mb == 14336 and sup._free_units == 7           # budget released


def _cand() -> Candidate:
    return Candidate(provider="repo", files={"Scarb.toml": "[package]\nname='p'\nversion='0.1.0'\n"}, sha256="0" * 64,
                     language="cairo", compiler=Compiler("2.13.1", "sierra_program"), settings={"package_dir": ""},
                     std_json_input=None, entry_contract=None)


@pytest.mark.asyncio
async def test_starknet_build_runner_fails_the_job_on_host_capacity(tmp_path: Path, monkeypatch) -> None:
    sup = MagicMock()
    sup._job_dir = lambda _j: tmp_path
    detail = {"reason": "insufficient_host_memory", "stage": "build", "need_mb": 8192, "host_mb": 3915, "cap_mb": 3523}
    refused = BuildResult(candidate=_cand(), status="failed", reason="host_capacity",
                          stderr_head="insufficient_host_memory (need 8192 MiB, host 3915 MiB)",
                          build_notes={"host_capacity": detail})
    finished: list[dict] = []

    async def fake_finish(_sup, _step, **kw):
        finished.append(kw)

    monkeypatch.setattr(S, "_candidate", lambda _s, _j: _cand())
    monkeypatch.setattr(S, "_finish", fake_finish)
    monkeypatch.setattr("soken_review.adapters.starknet.build.build", lambda _c, _w, _v: refused)
    step = {"id": 7, "job_id": "job_STK00001", "step": "build", "seq": 0, "lease_owner": "stand"}
    await S._build(sup, step, {"job_id": "job_STK00001", "address": "0x1"})

    (kw,) = finished
    assert kw["step_status"] == "failed" and kw["to_state"] == "failed"
    assert kw["error_code"] == "E_HOST_CAPACITY" and kw["detail"] == detail
    assert "next_step" not in kw                                        # no analyze step on a refused build
    written = json.loads((tmp_path / "build_result.json").read_text())
    assert written["reason"] == "host_capacity" and written["deps_unverified"] == []
    assert not (tmp_path / "provenance.json").exists()


@pytest.mark.asyncio
async def test_starknet_build_result_names_unverified_deps(tmp_path: Path, monkeypatch) -> None:
    sup = MagicMock()
    sup._job_dir = lambda _j: tmp_path
    (tmp_path / "build" / "host").mkdir(parents=True)
    (tmp_path / "build" / "host" / "trust_scan.json").write_text(
        json.dumps({"untrusted": True, "reasons": ["deps_unverified:alexandria_math@0.1.0", "git_dependency:alexandria_math"]}))
    ok = BuildResult(candidate=_cand(), status="ok", nsloc=10, work_dir=str(tmp_path / "build"),
                     build_notes={"deps_unverified": ["alexandria_math@0.1.0"]})
    finished: list[dict] = []

    async def fake_finish(_sup, _step, **kw):
        finished.append(kw)

    monkeypatch.setattr(S, "_candidate", lambda _s, _j: _cand())
    monkeypatch.setattr(S, "_finish", fake_finish)
    monkeypatch.setattr("soken_review.adapters.starknet.build.build", lambda _c, _w, _v: ok)
    await S._build(sup, {"id": 8, "job_id": "job_STK00002", "step": "build", "seq": 0}, {"job_id": "job_STK00002"})

    written = json.loads((tmp_path / "build_result.json").read_text())
    assert written["status"] == "ok" and written["deps_unverified"] == ["alexandria_math@0.1.0"]
    prov = json.loads((tmp_path / "provenance.json").read_text())
    assert prov["untrusted_inputs"] is True and "deps_unverified:alexandria_math@0.1.0" in prov["trust_reasons"]
    (kw,) = finished
    assert kw["to_state"] == "analyzing" and kw["next_step"]["step"] == "analyze"
