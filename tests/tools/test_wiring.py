"""Tests for production wiring: context_pg._startup() must wire all write tools (item 1c/1d).

Uses pg_dsn from conftest (Docker PG) — no separate SOKEN_DATABASE_URL needed.
Both tests run in the normal `uv run pytest` suite.

1c — Wiring assertion: every write tool module has pool+context set after lifespan startup.
1d — Live MCP e2e over ASGITransport: ready job -> review_submit_finding (Informational) ->
     review_finalize -> accepted=True, state=render_queued, final_ids present.
"""

from __future__ import annotations

import json
import os

import pytest

_VAULT_SOL = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.0;\n"
    "contract Vault {\n"
    "    mapping(address => uint256) balances;\n"
    "    function withdraw(uint256 a) external {\n"
    '        (bool ok, ) = msg.sender.call{value: a}("");\n'
    "        balances[msg.sender] -= a;\n"
    "    }\n"
    "}\n"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_ready_job(pool, pin_root) -> str:
    """Create a ready EVM job via JobRepo (real schema columns) + PinnedSource."""
    from soken_review.db.job_repo import JobRepo, new_job_id
    from soken_review.pinning.store import PinnedSource
    from soken_review.tools.report import principal_of

    jid = new_job_id()
    async with pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(
            job_id=jid,
            principal_key=principal_of(jid),
            surface="plugin",
            state="queued",
            requester_role="third_party_public_code",
            source_kind="deployed",
            source_args={},
            has_deployment=True,
            chain="evm",
        )
        await conn.execute(
            "update jobs set state = 'ready', tier = 'A' where job_id = %s", (jid,)
        )

    pin = PinnedSource.from_files({"src/Vault.sol": _VAULT_SOL.encode()})
    pin.persist(pin_root, jid)
    return jid


async def _mcp_call(client, tool: str, **kwargs) -> dict:
    """Call an MCP tool via StreamableHTTP JSON-RPC over ASGITransport."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": kwargs},
    }
    resp = await client.post(
        "/mcp",
        json=payload,
        headers={
            "MCP-Protocol-Version": "2025-11-25",
            "Accept": "application/json, text/event-stream",
        },
    )
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise AssertionError(f"MCP JSON-RPC error: {data['error']}")
    result = data.get("result", {})
    content = result.get("content", [])
    if content and content[0].get("type") == "text":
        text = content[0]["text"]
        return json.loads(text) if text.startswith("{") else {"text": text}
    return result


# ---------------------------------------------------------------------------
# 1c: Wiring assertion test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_write_tools_wired_after_lifespan(pg_dsn, tmp_path):
    """create_app() lifespan startup wires pool+ctx on every write tool module (item 1c)."""
    from asgi_lifespan import LifespanManager

    from soken_review.tools.context_pg import create_app

    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    os.environ["SOKEN_DATABASE_URL"] = pg_dsn
    os.environ["SOKEN_PIN_ROOT"] = str(pin_root)

    app = create_app()

    async with LifespanManager(app):
        from soken_review.tools import (
            challenge,
            dismiss,
            finalize,
            read,
            set_section,
            submit,
            withdraw,
        )

        _WRITE_TOOLS = [submit, finalize, challenge, dismiss, withdraw, set_section]
        for mod in _WRITE_TOOLS:
            assert mod._pool is not None, f"{mod.__name__} _pool not set after startup"
            assert mod._ctx is not None, f"{mod.__name__} _ctx not set after startup"

        assert read._ctx is not None, "read._ctx not set after startup"


# ---------------------------------------------------------------------------
# 1d: Live MCP e2e test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_submit_finding_and_finalize(pg_dsn, tmp_path):
    """Informational finding submitted + finalized through real wired MCP app (item 1d).

    Opens its own function-scoped pool so it never contends with the session db_pool.
    Flow: ready job (JobRepo) -> review_submit_finding (Informational, no challenge needed)
          -> review_finalize -> accepted=True, state=render_queued, final_ids present.
    """
    import httpx
    import psycopg_pool
    from asgi_lifespan import LifespanManager

    from soken_review.tools.context_pg import create_app

    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    os.environ["SOKEN_DATABASE_URL"] = pg_dsn
    os.environ["SOKEN_PIN_ROOT"] = str(pin_root)

    # Function-scoped pool so we don't share with the session pool.
    pool = psycopg_pool.AsyncConnectionPool(pg_dsn, min_size=1, max_size=3, open=False)
    await pool.open()
    try:
        job_id = await _make_ready_job(pool, pin_root)
    finally:
        await pool.close()

    app = create_app()

    try:
        await _submit_and_finalize_over_mcp(create_app_instance=app, job_id=job_id,
                                            LifespanManager=LifespanManager, httpx=httpx)
    finally:
        # The finalize queues a render step in the shared test DB; remove it so it cannot be
        # claimed by tests/report/test_render_flow.py (they claim from the global queue).
        cleanup = psycopg_pool.AsyncConnectionPool(pg_dsn, min_size=1, max_size=1, open=False)
        await cleanup.open()
        try:
            async with cleanup.connection() as conn:
                await conn.execute("delete from job_steps where job_id = %s", (job_id,))
        finally:
            await cleanup.close()


async def _submit_and_finalize_over_mcp(*, create_app_instance, job_id, LifespanManager, httpx):
    app = create_app_instance
    async with LifespanManager(app) as manager, httpx.AsyncClient(
        transport=httpx.ASGITransport(app=manager.app),
        base_url="http://127.0.0.1:8000",
    ) as client:
        # Quote lines 1-3: SPDX + pragma + contract declaration
        quote_text = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "contract Vault {"
        )

        # best_practice -> Informational (rank 0) -> status=accepted, no challenge
        submit_result = await _mcp_call(
            client,
            "review_submit_finding",
            job_id=job_id,
            draft_key="draft-wiring-e2e",
            category="evm.reentrancy",
            quotes=[{"file": "src/Vault.sol", "start": 1, "end": 3,
                     "role": "location", "text": quote_text}],
            matrix={
                "impact_class": "best_practice",
                "magnitude": "unbounded",
                "trigger": "anyone",
                "precondition": "none",
                "reversibility": "irreversible",
            },
            lead_ids=[],
            title="Reentrancy guard missing on withdraw",
            body={
                "description": [{"p": (
                    "The withdraw function calls an external contract before"
                    " updating the sender balance, following the unsafe"
                    " interaction-effects-checks ordering pattern."
                )}],
                "impact": [{"p": "Best-practice concern only; funds are at risk."}],
                "recommendation": [{"p": "Apply the checks-effects-interactions pattern"
                                    " and add a reentrancy guard modifier."}],
            },
        )
        assert submit_result.get("accepted") is True, (
            f"review_submit_finding failed: {submit_result}"
        )
        assert submit_result.get("computed_severity") == "Informational", (
            f"Expected Informational, got: {submit_result.get('computed_severity')}"
        )
        assert submit_result.get("status") == "accepted", (
            f"Expected status=accepted (no challenge needed), got: {submit_result.get('status')}"
        )

        # Finalize: single Informational on tier=A job — all checks must pass
        fin_result = await _mcp_call(client, "review_finalize", job_id=job_id)
        assert fin_result.get("accepted") is True, (
            f"review_finalize did not return accepted=True: {fin_result}"
        )
        assert fin_result.get("state") == "render_queued", (
            f"Expected state=render_queued, got: {fin_result.get('state')}"
        )
        assert fin_result.get("final_ids"), (
            f"Expected final_ids present: {fin_result}"
        )
