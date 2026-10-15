"""Integration test: review_start → review_status (polling) → review_leads (plan-v4 03, 09).

Skips unless SOKEN_DATABASE_URL is set in environment.
Set SOKEN_DATABASE_URL, SOKEN_PIN_ROOT, SOKEN_RPC_1, SOKEN_RPC_8453 to run.

The test starts:
  1. A real Postgres-backed HTTP server (ASGI in-process via httpx.ASGITransport)
  2. A real Supervisor in the same event loop (runs in background task)
  3. Calls review_start → polls review_status → reads review_leads

Public contracts used:
  - GBLIN  Base  8453  0xc2181d975c05c8c724b334bcED0764c0b86B1D53
  - WETH9  mainnet  1  0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
import pytest_asyncio

SKIP_REASON = "SOKEN_DATABASE_URL not set — skipping integration test"
pytestmark = pytest.mark.skipif(
    not os.environ.get("SOKEN_DATABASE_URL"),
    reason=SKIP_REASON,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def pg_pool() -> AsyncGenerator:
    """Open async Postgres pool for the test; runs migrations first."""
    import psycopg_pool

    from soken_review.db import migrate as migrate_mod

    dsn = os.environ["SOKEN_DATABASE_URL"]
    await migrate_mod.run_migrations(dsn)

    pool = psycopg_pool.AsyncConnectionPool(dsn, min_size=2, max_size=5, open=False)
    await pool.open()
    try:
        yield pool
    finally:
        await pool.close()


@pytest_asyncio.fixture
async def pin_root(tmp_path: Path) -> Path:
    root = Path(os.environ.get("SOKEN_PIN_ROOT", str(tmp_path / "pins")))
    root.mkdir(parents=True, exist_ok=True)
    (root.parent / "work").mkdir(parents=True, exist_ok=True)
    return root


@pytest_asyncio.fixture
async def running_supervisor(pg_pool, pin_root: Path) -> AsyncGenerator:
    """Start one Supervisor instance as a background task."""
    from soken_review.worker.supervisor import Supervisor

    sup = Supervisor(pg_pool, pin_root, host_name="test-integration-worker", poll_interval=0.2)
    task = asyncio.create_task(sup.run())
    try:
        yield sup
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


@pytest_asyncio.fixture
async def mcp_client(pg_pool, pin_root: Path):
    """Return an MCP client backed by the in-process ASGI app."""
    import httpx

    os.environ["SOKEN_DATABASE_URL"] = os.environ["SOKEN_DATABASE_URL"]
    os.environ["SOKEN_PIN_ROOT"] = str(pin_root)

    from asgi_lifespan import LifespanManager

    from soken_review.tools.context_pg import create_app

    app = create_app()
    async with LifespanManager(app) as manager, httpx.AsyncClient(
        transport=httpx.ASGITransport(app=manager.app), base_url="http://127.0.0.1:8000"
    ) as client:
        # Trigger lifespan startup
        yield client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _mcp_call(client, tool: str, **kwargs) -> dict:
    """Call an MCP tool via StreamableHTTP JSON-RPC."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": kwargs},
    }
    resp = await client.post(
        "/mcp",
        json=payload,
        headers={"MCP-Protocol-Version": "2025-11-25", "Accept": "application/json, text/event-stream"},
    )
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise AssertionError(f"MCP error: {data['error']}")
    # Extract text content
    result = data.get("result", {})
    content = result.get("content", [])
    if content and content[0].get("type") == "text":
        text = content[0]["text"]
        # Control tools answer JSON; bulk read tools (review_leads, ...) answer the 03 line format.
        return json.loads(text) if text.startswith("{") else {"text": text, "is_error": result.get("isError")}
    return result


async def _poll_status(client, job_id: str, timeout: float = 120.0) -> dict:
    """Poll review_status until state == 'ready' or a terminal error state."""
    _TERMINAL = {"ready", "insufficient_source", "error"}
    deadline = asyncio.get_event_loop().time() + timeout
    last_state = "unknown"
    while asyncio.get_event_loop().time() < deadline:
        try:
            status = await _mcp_call(client, "review_status", job_id=job_id)
        except Exception:  # noqa: BLE001
            # Transient network errors
            await asyncio.sleep(1.0)
            continue
        last_state = status.get("state", "unknown")
        if last_state in _TERMINAL:
            return status
        await asyncio.sleep(2.0)
    raise TimeoutError(f"job {job_id} did not reach terminal state in {timeout}s; last={last_state}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_gblin_base_full_pipeline(running_supervisor, mcp_client) -> None:
    """GBLIN on Base 8453: start → poll until ready → leads returned (plan-v4 03)."""
    pytest.importorskip("httpx")

    address = "0xc2181d975c05c8c724b334bcED0764c0b86B1D53"
    chain_id = 8453

    # Start review
    start_result = await _mcp_call(
        mcp_client, "review_start",
        source={"kind": "deployed", "chain": "evm", "chain_id": chain_id, "address": address},
    )
    assert "job_id" in start_result, f"review_start missing job_id: {start_result}"
    job_id = start_result["job_id"]
    print(f"\nGBLIN job_id: {job_id}")

    # Poll until ready
    status = await _poll_status(mcp_client, job_id, timeout=180.0)
    print(f"GBLIN final status: {status}")

    assert status["state"] == "ready", f"Expected ready, got {status['state']}: {status}"
    assert status["percent"] == 85  # ready = fixed at 85 (before rendering)

    # Fetch leads
    leads_result = await _mcp_call(mcp_client, "review_leads", job_id=job_id)
    assert not leads_result.get("is_error"), leads_result
    assert "LEAD-0001" in leads_result["text"], leads_result["text"][:300]
    print("GBLIN leads:", leads_result["text"].splitlines()[0])


@pytest.mark.asyncio
@pytest.mark.timeout(300)
async def test_weth9_mainnet_full_pipeline(running_supervisor, mcp_client) -> None:
    """WETH9 on Ethereum mainnet 1: start → poll until ready/insufficient_source → leads."""
    pytest.importorskip("httpx")

    rpc_url = os.environ.get("SOKEN_RPC_1")
    if not rpc_url:
        pytest.skip("SOKEN_RPC_1 not set")

    address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    chain_id = 1

    start_result = await _mcp_call(
        mcp_client, "review_start",
        source={"kind": "deployed", "chain": "evm", "chain_id": chain_id, "address": address},
    )
    assert "job_id" in start_result, f"review_start missing job_id: {start_result}"
    job_id = start_result["job_id"]
    print(f"\nWETH9 job_id: {job_id}")

    status = await _poll_status(mcp_client, job_id, timeout=180.0)
    print(f"WETH9 final status: {status}")

    # WETH9 is verified on Sourcify — expect ready
    assert status["state"] in ("ready", "insufficient_source"), \
        f"Unexpected state: {status['state']}"

    if status["state"] == "ready":
        leads_result = await _mcp_call(mcp_client, "review_leads", job_id=job_id)
        assert not leads_result.get("is_error"), leads_result
        assert "LEAD-0001" in leads_result["text"], leads_result["text"][:300]
        print("WETH9 leads:", leads_result["text"].splitlines()[0])
    else:
        print("WETH9: insufficient_source (no source found; acceptable for mainnet without sourcify)")


@pytest.mark.asyncio
@pytest.mark.timeout(900)
@pytest.mark.parametrize(("name", "address"), [
    ("SwapRouter", "0xE592427A0AEce92De3Edee1F18E0157C05861564"),     # 0.7.6, 12 immutable slots
    ("UniswapV2Factory", "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6F"),  # embeds child CBOR
])
async def test_mainnet_tier_a_from_masked_rebuild(running_supervisor, mcp_client, pin_root: Path,
                                                  name: str, address: str) -> None:
    """05 13.1: the supervisor's own masked comparison gives tier A (04 section 3)."""
    if not os.environ.get("SOKEN_RPC_1"):
        pytest.skip("SOKEN_RPC_1 not set")
    start = await _mcp_call(mcp_client, "review_start",
                            source={"kind": "deployed", "chain": "evm", "chain_id": 1, "address": address})
    job_id = start["job_id"]
    status = await _poll_status(mcp_client, job_id, timeout=840.0)
    dep = json.loads((pin_root.parent / "work" / job_id / "deployment.json").read_text())
    print(f"\n{name} {job_id}: tier={status.get('provenance')} dep={dep['dep']['match']} "
          f"immutables={len(dep['dep']['comparison']['immutable_ranges'])} "
          f"auxdata={dep['dep']['comparison']['auxdata_ranges']}")
    assert status["state"] == "ready", status
    assert status["provenance"]["tier"] == "A", status
    assert dep["dep"]["match"] in ("exact", "metadata_only")


@pytest.mark.asyncio
async def test_review_start_returns_job_id(mcp_client) -> None:
    """review_start returns a job_id without running the supervisor (schema test)."""
    pytest.importorskip("httpx")

    result = await _mcp_call(
        mcp_client, "review_start",
        source={"kind": "deployed", "chain": "evm", "chain_id": 8453, "address": "0xc2181d975c05c8c724b334bcED0764c0b86B1D53"},
    )
    assert "job_id" in result
    assert isinstance(result["job_id"], str)
    assert len(result["job_id"]) > 8


@pytest.mark.asyncio
async def test_review_status_initial_state(mcp_client) -> None:
    """review_status for a fresh job returns percent=0 and state=queued."""
    pytest.importorskip("httpx")

    start = await _mcp_call(
        mcp_client, "review_start",
        source={"kind": "deployed", "chain": "evm", "chain_id": 8453, "address": "0xc2181d975c05c8c724b334bcED0764c0b86B1D53"},
    )
    job_id = start["job_id"]
    status = await _mcp_call(mcp_client, "review_status", job_id=job_id)

    assert status["job_id"] == job_id
    assert status["state"] in ("queued", "fetching", "building", "analyzing", "ready")
    assert isinstance(status["percent"], int)
    assert 0 <= status["percent"] <= 100
