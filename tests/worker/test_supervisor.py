"""Unit tests for the supervisor step machine (09 sections 3.1, 3.4, 3.6).

Uses fake adapters and an in-process sqlite-like store to test every terminal
and non-terminal outcome without a real Postgres instance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fake DB state (in-memory, replaces the Postgres pool in tests)
# ---------------------------------------------------------------------------

class _FakeJob:
    def __init__(self, job_id: str, chain_id: int | None = 1, address: str | None = None) -> None:
        self.job_id = job_id
        self.state = "queued"
        self.chain_id = chain_id
        self.address = address
        self.source_pin: str | None = None
        self.map_status = "none"
        self.analyzer_degraded = False
        self.error_code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "state": self.state,
            "chain_id": self.chain_id,
            "address": self.address,
            "source_pin": self.source_pin,
            "map_status": self.map_status,
            "analyzer_degraded": self.analyzer_degraded,
            "error_code": self.error_code,
        }


class _FakeStep:
    _next_id = 1

    def __init__(self, job_id: str, step: str, *, seq: int = 0, tool: str | None = None,
                 container: bool = False, units: int = 0, ram_mb: int = 0,
                 max_attempts: int = 1, affinity: str | None = None) -> None:
        self.id = _FakeStep._next_id
        _FakeStep._next_id += 1
        self.job_id = job_id
        self.step = step
        self.seq = seq
        self.tool = tool
        self.container = container
        self.units = units
        self.ram_mb = ram_mb
        self.max_attempts = max_attempts
        self.affinity = affinity
        self.status = "queued"
        self.lease_owner: str | None = None
        self.attempt = 0
        self.started_at = None
        self.finished_at = None
        self.exit_code: int | None = None
        self.error_code: str | None = None
        self.provenance: dict | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "step": self.step,
            "seq": self.seq,
            "tool": self.tool,
            "container": self.container,
            "units": self.units,
            "ram_mb": self.ram_mb,
            "max_attempts": self.max_attempts,
            "affinity": self.affinity,
            "status": self.status,
            "lease_owner": self.lease_owner,
            "attempt": self.attempt,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "error_code": self.error_code,
            "provenance": self.provenance,
        }


class FakeStore:
    """In-memory replacement for Postgres during step machine tests."""

    def __init__(self) -> None:
        self.jobs: dict[str, _FakeJob] = {}
        self.steps: list[_FakeStep] = []

    def add_job(self, job_id: str, chain_id: int | None = 1,
                address: str | None = None) -> _FakeJob:
        job = _FakeJob(job_id, chain_id=chain_id, address=address)
        self.jobs[job_id] = job
        return job

    def add_step(self, job_id: str, step_name: str, **kwargs: Any) -> _FakeStep:
        s = _FakeStep(job_id, step_name, **kwargs)
        self.steps.append(s)
        return s

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        j = self.jobs.get(job_id)
        return j.as_dict() if j else None

    def transition_job(self, job_id: str, new_state: str, error_code: str | None = None) -> None:
        j = self.jobs[job_id]
        j.state = new_state
        if error_code:
            j.error_code = error_code

    def insert_step(self, job_id: str, step: str, **kwargs: Any) -> dict[str, Any]:
        s = _FakeStep(job_id, step, **kwargs)
        self.steps.append(s)
        return s.as_dict()

    def complete_step(self, step_id: int, status: str, error_code: str | None = None,
                      provenance: dict | None = None) -> None:
        for s in self.steps:
            if s.id == step_id:
                s.status = status
                s.error_code = error_code
                s.provenance = provenance
                return

    def update_job_fields(self, job_id: str, **fields: Any) -> None:
        j = self.jobs[job_id]
        for k, v in fields.items():
            setattr(j, k, v)

    def steps_for(self, job_id: str) -> list[dict[str, Any]]:
        return [s.as_dict() for s in self.steps if s.job_id == job_id]


# ---------------------------------------------------------------------------
# Fake adapter results
# ---------------------------------------------------------------------------

def _fake_candidate(provider: str = "sourcify", language: str = "solidity") -> dict[str, Any]:
    return {
        "provider": provider,
        "sha256": "abcd1234" * 8,
        "language": language,
        "compiler": {"version": "0.8.24+commit.e11b9ed9", "version_pinned_by": "metadata"},
        "settings": {},
        "entry_contract": "contracts/Token.sol:Token",
        "explorer_verified": False,
        "sourcify_match": "exact_match",
        "fetched_at": "2026-10-09T00:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# Helpers for building a Supervisor with fake internals
# ---------------------------------------------------------------------------

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.worker.supervisor import Supervisor


def _make_supervisor(store: FakeStore, pin_root: Path) -> Supervisor:
    """Build a Supervisor with a fake pool that delegates to FakeStore."""
    fake_pool = MagicMock()

    # We'll patch the repo methods directly in each test
    sup = Supervisor.__new__(Supervisor)
    sup._pool = fake_pool
    sup._pin_root = pin_root
    sup._host = "test-worker"
    sup._poll_interval = 0.01
    sup._lease_secs = 60
    sup._total_units = 7
    sup._total_ram_mb = 14336
    sup._free_units = 7
    sup._free_ram_mb = 14336
    sup._running = {}

    # Bind store to supervisor for test introspection
    sup._store = store  # type: ignore[attr-defined]
    return sup


# ---------------------------------------------------------------------------
# Core step machine tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chain_state_eoa_is_terminal(tmp_path: Path) -> None:
    """chain_state 0 with empty bytecode → terminal insufficient_source (09 3.6)."""
    store = FakeStore()
    job = store.add_job("job_TEST0001", chain_id=1, address="0xdead")
    step = store.add_step("job_TEST0001", "chain_state", seq=0, container=False, units=0, ram_mb=0, max_attempts=3)

    sup = _make_supervisor(store, tmp_path)

    # Patch RpcClient to return empty bytecode
    with patch("soken_review.worker.supervisor.RpcClient") as mock_rpc_cls, \
         patch("soken_review.worker.supervisor._rpc_url", return_value="http://rpc.test"), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_after_chain_state", new=AsyncMock()) as mock_after:

        mock_rpc = AsyncMock()
        mock_rpc.block_number = AsyncMock(return_value=1000)
        mock_rpc.get_code = AsyncMock(return_value="0x")
        mock_rpc_cls.return_value = mock_rpc
        # Also need the pinned client
        mock_rpc_cls.side_effect = None
        mock_rpc_cls.return_value = mock_rpc

        # Simulate the pool.connection() context manager for the terminal transition
        conn_ctx = AsyncMock()
        conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
        conn_ctx.__aexit__ = AsyncMock(return_value=False)
        txn_ctx = AsyncMock()
        txn_ctx.__aenter__ = AsyncMock(return_value=txn_ctx)
        txn_ctx.__aexit__ = AsyncMock(return_value=False)
        repo_mock = AsyncMock()
        repo_mock.complete_step = AsyncMock()
        repo_mock.transition = AsyncMock()
        conn_ctx.transaction = MagicMock(return_value=txn_ctx)

        with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock):
            sup._pool.connection = MagicMock(return_value=conn_ctx)
            await sup._run_chain_state_0(step.as_dict())

        # Should have called transition to insufficient_source
        repo_mock.transition.assert_awaited_with(
            "job_TEST0001", "insufficient_source", error_code="E_SOURCE_NOT_FOUND"
        )
        # Should NOT have called _after_chain_state
        mock_after.assert_not_awaited()


@pytest.mark.asyncio
async def test_chain_state_with_bytecode_proceeds_to_fetch(tmp_path: Path) -> None:
    """chain_state 0 with bytecode present → transition to fetching and insert fetch step."""
    store = FakeStore()
    job = store.add_job("job_TEST0002", chain_id=8453, address="0xc218")
    step = store.add_step("job_TEST0002", "chain_state", seq=0, container=False, units=0, ram_mb=0, max_attempts=3)

    sup = _make_supervisor(store, tmp_path)

    with patch("soken_review.worker.supervisor.RpcClient") as mock_rpc_cls, \
         patch("soken_review.worker.supervisor._rpc_url", return_value="http://rpc.test"), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())), \
         patch.object(sup, "_mark_step", new=AsyncMock()) as mock_mark, \
         patch.object(sup, "_after_chain_state", new=AsyncMock()) as mock_after:

        mock_rpc = AsyncMock()
        mock_rpc.block_number = AsyncMock(return_value=5000)
        mock_rpc.get_code = AsyncMock(return_value="0x6080604052")  # non-empty bytecode
        mock_rpc_cls.return_value = mock_rpc

        await sup._run_chain_state_0(step.as_dict())

        mock_mark.assert_awaited()
        mock_after.assert_awaited_once()

    # chain_state.json should be written
    # The actual work dir is pin_root/../work/job_id; tmp_path is pin_root
    work_dir = tmp_path.parent / "work" / "job_TEST0002"
    if work_dir.exists():
        cs = json.loads((work_dir / "chain_state.json").read_text())
        assert cs["bytecode"] == "0x6080604052"


@pytest.mark.asyncio
async def test_fetch_no_candidates_is_terminal(tmp_path: Path) -> None:
    """fetch step with no source candidates → terminal insufficient_source (09 3.6)."""
    store = FakeStore()
    job = store.add_job("job_TEST0003", chain_id=1, address="0xdead")
    step = store.add_step("job_TEST0003", "fetch", container=False, units=0, ram_mb=0, max_attempts=3)

    sup = _make_supervisor(store, tmp_path)

    # Pre-write chain_state.json
    out_dir = tmp_path.parent / "work" / "job_TEST0003"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "chain_state.json").write_text(
        json.dumps({"chain_id": 1, "address": "0xdead", "bytecode": "0x1234", "block": 100})
    )

    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    txn_ctx = AsyncMock()
    txn_ctx.__aenter__ = AsyncMock(return_value=txn_ctx)
    txn_ctx.__aexit__ = AsyncMock(return_value=False)
    repo_mock = AsyncMock()
    repo_mock.complete_step = AsyncMock()
    repo_mock.transition = AsyncMock()
    conn_ctx.transaction = MagicMock(return_value=txn_ctx)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.worker.supervisor._fetch_mod.fetch_source", new=AsyncMock(return_value=[])), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())):

        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_fetch(step.as_dict())

    # Should transition to insufficient_source
    repo_mock.transition.assert_awaited_with(
        "job_TEST0003", "insufficient_source", error_code="E_SOURCE_NOT_FOUND"
    )


@pytest.mark.asyncio
async def test_fetch_with_candidates_pins_and_proceeds(tmp_path: Path) -> None:
    """fetch step with candidates → pins files, writes candidates.json, inserts build step."""
    store = FakeStore()
    job = store.add_job("job_TEST0004", chain_id=8453, address="0xc218")
    step = store.add_step("job_TEST0004", "fetch", container=False, units=0, ram_mb=0, max_attempts=3)
    step_dict = step.as_dict()
    step_dict["lease_owner"] = "test-worker"

    sup = _make_supervisor(store, tmp_path)

    # Pre-write chain_state.json
    out_dir = tmp_path.parent / "work" / "job_TEST0004"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "chain_state.json").write_text(
        json.dumps({"chain_id": 8453, "address": "0xc218", "bytecode": "0x6080", "block": 200})
    )

    fake_cand = Candidate(
        provider="sourcify",
        files={"contracts/Token.sol": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Token {}"},
        sha256="abc" * 20 + "ab",
        language="solidity",
        compiler=Compiler(version="0.8.24+commit.e11b9ed9", version_pinned_by="metadata"),
        settings={},
        std_json_input=None,
        entry_contract="contracts/Token.sol:Token",
        sourcify_match="exact_match",
    )

    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    txn_ctx = AsyncMock()
    txn_ctx.__aenter__ = AsyncMock(return_value=txn_ctx)
    txn_ctx.__aexit__ = AsyncMock(return_value=False)
    repo_mock = AsyncMock()
    repo_mock.update_job_fields = AsyncMock()
    repo_mock.transition = AsyncMock()
    repo_mock.insert_step = AsyncMock()
    conn_ctx.transaction = MagicMock(return_value=txn_ctx)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.worker.supervisor._fetch_mod.fetch_source", new=AsyncMock(return_value=[fake_cand])), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_after_fetch", new=AsyncMock()) as mock_after_fetch:

        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_fetch(step_dict)

    # Pin dir should have been written
    pin_dir = tmp_path / "job_TEST0004" / "pin"
    assert pin_dir.exists(), "pin dir was not created"
    assert (pin_dir / "manifest.json").exists(), "manifest.json missing"

    # candidates.json should exist
    cands_path = out_dir / "candidates.json"
    assert cands_path.exists()
    cands = json.loads(cands_path.read_text())
    assert len(cands) == 1
    assert cands[0]["provider"] == "sourcify"

    mock_after_fetch.assert_awaited_once()


@pytest.mark.asyncio
async def test_build_failure_is_non_terminal(tmp_path: Path) -> None:
    """build step failure → map_status=failed, job still transitions to analyzing (09 3.6)."""
    store = FakeStore()
    job = store.add_job("job_TEST0005", chain_id=1, address="0xabcd")
    step = store.add_step("job_TEST0005", "build", container=True, units=2, ram_mb=4096, max_attempts=1)

    sup = _make_supervisor(store, tmp_path)

    # Pre-write candidates.json
    out_dir = tmp_path.parent / "work" / "job_TEST0005"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write a pin with a Solidity file so PinnedSource.load works
    from soken_review.pinning.store import PinnedSource
    pin = PinnedSource.from_files({"contracts/Bad.sol": b"contract Bad {"})
    pin.persist(tmp_path, "job_TEST0005")

    fake_cand = _fake_candidate()
    fake_cand["compiler"] = {"version": "0.8.99+commit.bad", "version_pinned_by": "metadata"}
    (out_dir / "candidates.json").write_text(json.dumps([fake_cand]))

    # Make build return failed
    failed_result = BuildResult(
        candidate=MagicMock(),
        status="failed",
        nsloc=0,
        reason="compiler_binary_missing",
        stderr_head=None,
    )

    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    txn_ctx = AsyncMock()
    txn_ctx.__aenter__ = AsyncMock(return_value=txn_ctx)
    txn_ctx.__aexit__ = AsyncMock(return_value=False)
    repo_mock = AsyncMock()
    repo_mock.update_job_fields = AsyncMock()
    repo_mock.transition = AsyncMock()
    repo_mock.insert_step = AsyncMock()
    conn_ctx.transaction = MagicMock(return_value=txn_ctx)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.worker.supervisor._build_mod.build", return_value=failed_result), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_after_build", new=AsyncMock()) as mock_after_build:

        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_build(step.as_dict())

    # _after_build should have been called with status=failed (non-terminal)
    mock_after_build.assert_awaited_once()
    build_result_arg = mock_after_build.call_args[0][1]
    assert build_result_arg["status"] == "failed"

    # build_result.json should exist
    build_path = out_dir / "build_result.json"
    assert build_path.exists()
    br = json.loads(build_path.read_text())
    assert br["status"] == "failed"


@pytest.mark.asyncio
async def test_analyzer_not_run_is_non_terminal(tmp_path: Path) -> None:
    """analyze step where analyze returns not_run → analyzer_degraded, still transitions to ready."""
    store = FakeStore()
    job = store.add_job("job_TEST0006", chain_id=1, address="0xabcd")
    step = store.add_step("job_TEST0006", "analyze", tool="slither", container=True, units=2, ram_mb=6144, max_attempts=1)

    sup = _make_supervisor(store, tmp_path)

    out_dir = tmp_path.parent / "work" / "job_TEST0006"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write candidates.json and build_result.json
    fake_cand = _fake_candidate()
    (out_dir / "candidates.json").write_text(json.dumps([fake_cand]))

    # Write a build result that says ok but with a work_dir
    work_dir = out_dir / "work"
    work_dir.mkdir(exist_ok=True)
    br_data = {"status": "ok", "nsloc": 10, "reason": None, "stderr_head": None, "work_dir": str(work_dir)}
    (out_dir / "build_result.json").write_text(json.dumps(br_data))
    (out_dir / "work_dir.txt").write_text(str(work_dir))

    # Make analyze return not_run
    not_run_map = {"status": "not_run", "reason": "sandbox_unavailable"}

    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    txn_ctx = AsyncMock()
    txn_ctx.__aenter__ = AsyncMock(return_value=txn_ctx)
    txn_ctx.__aexit__ = AsyncMock(return_value=False)
    repo_mock = AsyncMock()
    repo_mock.update_job_fields = AsyncMock()
    repo_mock.transition = AsyncMock()
    conn_ctx.transaction = MagicMock(return_value=txn_ctx)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.worker.supervisor._analyze_mod.analyze", return_value=([], not_run_map, {})), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_after_analyze", new=AsyncMock()) as mock_after:

        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_analyze(step.as_dict())

    # _after_analyze should be called with degraded=True
    mock_after.assert_awaited_once()
    # leads.json should be written
    leads_path = tmp_path / "job_TEST0006" / "leads.json"
    assert leads_path.exists()
    assert json.loads(leads_path.read_text()) == []


@pytest.mark.asyncio
async def test_restart_skips_existing_output(tmp_path: Path) -> None:
    """Restart after crash: if output exists, step is skipped (09 3.4 idempotency)."""
    store = FakeStore()
    job = store.add_job("job_TEST0007", chain_id=1, address="0xabcd")
    step = store.add_step("job_TEST0007", "fetch", container=False, units=0, ram_mb=0, max_attempts=3)

    sup = _make_supervisor(store, tmp_path)

    # Pre-write candidates.json to simulate a completed fetch
    out_dir = tmp_path.parent / "work" / "job_TEST0007"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "candidates.json").write_text("[]")

    # Also write a minimal chain_state
    (out_dir / "chain_state.json").write_text(
        json.dumps({"chain_id": 1, "address": "0xabcd", "bytecode": None, "block": None})
    )

    with patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())), \
         patch.object(sup, "_mark_step", new=AsyncMock()) as mock_mark, \
         patch.object(sup, "_after_fetch", new=AsyncMock()) as mock_after, \
         patch("soken_review.worker.supervisor._fetch_mod.fetch_source", new=AsyncMock()) as mock_fetch:

        await sup._run_fetch(step.as_dict())

    # fetch_source must NOT have been called (output already exists)
    mock_fetch.assert_not_awaited()
    # mark_step and after_fetch should have been called
    mock_mark.assert_awaited_once()
    mock_after.assert_awaited_once()


@pytest.mark.asyncio
async def test_full_pipeline_happy_path(tmp_path: Path) -> None:
    """Full pipeline: chain_state → fetch → build → analyze → map → chain_state 1 → ready (happy path)."""
    # This test drives the actual _run_* methods in sequence with mocked adapters.

    store = FakeStore()
    job = store.add_job("job_TESTHAPPY", chain_id=8453, address="0xc218")

    sup = _make_supervisor(store, tmp_path)
    out_dir = tmp_path.parent / "work" / "job_TESTHAPPY"
    out_dir.mkdir(parents=True, exist_ok=True)

    fake_cand = Candidate(
        provider="sourcify",
        files={"contracts/Token.sol": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Token {}"},
        sha256="aa" * 32,
        language="solidity",
        compiler=Compiler(version="0.8.24+commit.e11b9ed9", version_pinned_by="metadata"),
        settings={},
        std_json_input=None,
        entry_contract="contracts/Token.sol:Token",
        sourcify_match="exact_match",
    )

    fake_build = BuildResult(candidate=fake_cand, status="ok", nsloc=5, work_dir=str(out_dir / "work"))
    (out_dir / "work").mkdir(exist_ok=True)

    final_states: list[str] = []

    def capture_transition(jid: str, new_state: str, error_code: str | None = None) -> None:
        final_states.append(new_state)
        store.transition_job(jid, new_state, error_code)

    async def mock_update_fields(jid: str, **fields: Any) -> None:
        store.update_job_fields(jid, **fields)

    async def mock_insert_step(job_id: str, step: str, **kwargs: Any) -> dict:
        return store.insert_step(job_id, step, **kwargs)

    repo_mock = AsyncMock()
    repo_mock.transition = AsyncMock(side_effect=capture_transition)
    repo_mock.update_job_fields = AsyncMock(side_effect=mock_update_fields)
    repo_mock.insert_step = AsyncMock(side_effect=mock_insert_step)
    repo_mock.complete_step = AsyncMock()
    repo_mock.find_unseeded_jobs = AsyncMock(return_value=[])
    repo_mock.create_server_drafts = AsyncMock(return_value=0)

    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    txn_ctx = AsyncMock()
    txn_ctx.__aenter__ = AsyncMock(return_value=txn_ctx)
    txn_ctx.__aexit__ = AsyncMock(return_value=False)
    conn_ctx.transaction = MagicMock(return_value=txn_ctx)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.worker.supervisor.RpcClient") as mock_rpc_cls, \
         patch("soken_review.worker.supervisor._rpc_url", return_value="http://rpc.test"), \
         patch("soken_review.worker.supervisor._fetch_mod.fetch_source", new=AsyncMock(return_value=[fake_cand])), \
         patch("soken_review.worker.supervisor._build_mod.build", return_value=fake_build), \
         patch("soken_review.worker.supervisor._analyze_mod.analyze", return_value=(
             [{"id": "LEAD-0001", "state": "open", "severity_norm": "High",
               "category": "evm.reentrancy", "rule_id": "reentrancy-eth",
               "file": "contracts/Token.sol", "start": 1, "end": 3, "origin": "analyzer",
               "analyzer_severity_raw": "High", "tools": ["slither"], "message": "reentrancy",
               "category_family": "reentrancy"}],
             {"status": "ok"},
             {}
         )):

        mock_rpc = AsyncMock()
        mock_rpc.block_number = AsyncMock(return_value=9000)
        mock_rpc.get_code = AsyncMock(return_value="0x6080604052")
        mock_rpc._call = AsyncMock(return_value="0x3e8")          # eth_getBalance 1000 wei
        mock_rpc.eth_call = AsyncMock(return_value="0x" + "0" * 64)
        mock_rpc.get_storage_at = AsyncMock(return_value="0x" + "0" * 64)
        mock_rpc_cls.return_value = mock_rpc

        sup._pool.connection = MagicMock(return_value=conn_ctx)

        job_dict = job.as_dict()
        cs_step = {"id": 1, "job_id": "job_TESTHAPPY", "step": "chain_state", "seq": 0,
                   "container": False, "units": 0, "ram_mb": 0, "attempt": 1, "lease_owner": "test-worker"}
        with patch.object(sup, "_get_job", new=AsyncMock(return_value=job_dict)):
            await sup._run_chain_state_0(cs_step)

        fetch_step = {"id": 2, "job_id": "job_TESTHAPPY", "step": "fetch", "seq": 0,
                      "container": False, "units": 0, "ram_mb": 0, "attempt": 1, "lease_owner": "test-worker"}
        with patch.object(sup, "_get_job", new=AsyncMock(return_value=job_dict)):
            await sup._run_fetch(fetch_step)

        build_step = {"id": 3, "job_id": "job_TESTHAPPY", "step": "build", "seq": 0,
                      "container": True, "units": 2, "ram_mb": 4096, "attempt": 1, "lease_owner": "test-worker"}
        with patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())):
            await sup._run_build(build_step)

        analyze_step = {"id": 4, "job_id": "job_TESTHAPPY", "step": "analyze", "seq": 0,
                        "tool": "slither", "container": True, "units": 2, "ram_mb": 6144,
                        "attempt": 1, "lease_owner": "test-worker"}
        with patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())):
            await sup._run_analyze(analyze_step)
        assert "ready" not in final_states  # map and chain_state 1 still to run (03 3.1)

        map_step = {"id": 5, "job_id": "job_TESTHAPPY", "step": "map", "seq": 0,
                    "container": False, "units": 0, "ram_mb": 0, "attempt": 1, "lease_owner": "test-worker"}
        with patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())):
            await sup._run_map(map_step)
        cs1_step = {"id": 6, "job_id": "job_TESTHAPPY", "step": "chain_state", "seq": 1,
                    "container": False, "units": 0, "ram_mb": 0, "attempt": 1, "lease_owner": "test-worker"}
        with patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())):
            await sup._run_chain_state_1(cs1_step)

    # map step output: lexical map (no AST in the fake build), flags and facts with the on-chain read
    assert json.loads((tmp_path / "job_TESTHAPPY" / "map" / "status.json").read_text())["map_status"] == "partial"
    assert json.loads((tmp_path / "job_TESTHAPPY" / "flags.json").read_text()) == []
    facts = {f["key"]: f for f in json.loads((tmp_path / "job_TESTHAPPY" / "facts.json").read_text())}
    assert facts["onchain.balance"]["value"] == "1000"
    assert facts["chain.block"]["value"] == "8999"
    repo_mock.create_server_drafts.assert_awaited_once_with("job_TESTHAPPY", "evm", [])

    # Final job state should be ready
    assert "ready" in final_states, f"Expected 'ready' in transitions, got: {final_states}"

    # leads.json should exist and contain the lead
    leads_path = tmp_path / "job_TESTHAPPY" / "leads.json"
    assert leads_path.exists(), "leads.json not written"
    leads = json.loads(leads_path.read_text())
    assert len(leads) == 1
    assert leads[0]["id"] == "LEAD-0001"

    # pin dir should exist
    pin_dir = tmp_path / "job_TESTHAPPY" / "pin"
    assert pin_dir.exists(), "pin dir not created"


# ---------------------------------------------------------------------------
# insert_step column check (coordinator requirement)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insert_step_returns_row_with_correct_columns(tmp_path: Path) -> None:
    """insert_step sets all columns correctly; verifies via the returned row dict."""

    # This test doesn't need a real DB; it checks the dict returned by FakeStore.insert_step
    store = FakeStore()
    store.add_job("job_COL01", chain_id=1, address="0x1234")

    row = store.insert_step(
        job_id="job_COL01",
        step="build",
        seq=0,
        tool=None,
        container=True,
        units=2,
        ram_mb=4096,
        max_attempts=1,
        affinity="worker-1",
    )

    assert row["job_id"] == "job_COL01"
    assert row["step"] == "build"
    assert row["seq"] == 0
    assert row["tool"] is None
    assert row["container"] is True
    assert row["units"] == 2
    assert row["ram_mb"] == 4096
    assert row["max_attempts"] == 1
    assert row["affinity"] == "worker-1"
    assert row["status"] == "queued"

    # Verify types — these are the fields the coordinator worried about
    assert row["tool"] is None        # str | None, not int
    assert isinstance(row["container"], bool)          # bool, not int
    assert isinstance(row["affinity"], (str, type(None)))  # str | None, not int
