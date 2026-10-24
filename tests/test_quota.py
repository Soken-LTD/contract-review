"""Daily report quota and target key (soken_review.quota, CEO 2026-10-24)."""

from __future__ import annotations

import json

import httpx
import pytest

from soken_review import quota as Q
from soken_review.errors import ReviewError


def test_target_key_normalises_evm_and_repo():
    assert Q.target_key(chain="evm", address="0xAbC", repo_url=None) == "evm:0xabc"
    # Base58 is case-sensitive: kept as given.
    assert Q.target_key(chain="solana", address="So1aNa", repo_url=None) == "solana:So1aNa"
    for url in ("https://GitHub.com/Org/Repo.git", "https://github.com/org/repo/", "git@github.com:org/repo.git"):
        assert Q.target_key(chain=None, address=None, repo_url=url) == "repo:github.com/org/repo"
    assert Q.target_key(chain=None, address=None, repo_url="https://github.com/o/r", subdir="/pkg/") == "repo:github.com/o/r/pkg"
    assert Q.target_key(chain=None, address=None, repo_url=None) is None


def test_limit_key_direct_relay_exempt(monkeypatch):
    monkeypatch.delenv("SOKEN_RELAY_CIDRS", raising=False)
    monkeypatch.setenv("SOKEN_QUOTA_EXEMPT_CIDRS", "10.0.0.0/8")
    tok = Q.CLIENT_IP.set("95.47.113.11")
    try:
        direct = Q.limit_key(target="evm:0xabc", job_id="j1")
        assert direct.startswith("ip:") and "95.47" not in direct          # hashed, not the raw IP
        assert Q.limit_key(target="evm:0xdef", job_id="j2") == direct      # per user, not per target
        Q.CLIENT_IP.set("2001:db8:1:2::a")
        v6 = Q.limit_key(target=None, job_id="j3")
        Q.CLIENT_IP.set("2001:db8:1:2:ffff::1")                             # same /64, rotated host
        assert Q.limit_key(target=None, job_id="j4") == v6
        Q.CLIENT_IP.set("2001:db8:1:3::a")
        assert Q.limit_key(target=None, job_id="j5") != v6
        Q.CLIENT_IP.set("::ffff:95.47.113.11")                              # IPv4-mapped = the IPv4 user
        assert Q.limit_key(target=None, job_id="j6") == direct
        Q.CLIENT_IP.set("160.79.106.164")                                   # Anthropic relay
        relay = Q.limit_key(target="evm:0xabc", job_id="j1")
        assert relay.startswith("relay:") and relay != Q.limit_key(target="evm:0xdef", job_id="j1")
        Q.CLIENT_IP.set("160.79.106.18")                                    # rotated egress IP, same target
        assert Q.limit_key(target="evm:0xabc", job_id="j9") == relay
        Q.CLIENT_IP.set("10.1.2.3")
        assert Q.limit_key(target="evm:0xabc", job_id="j1") is None
        Q.CLIENT_IP.set(None)
        assert Q.limit_key(target=None, job_id="j1") is None
    finally:
        Q.CLIENT_IP.reset(tok)


async def _job_with_report(conn, key: str, hours_ago: float) -> str:
    from soken_review.db.job_repo import JobRepo, new_job_id

    jid = new_job_id()
    await JobRepo(conn).create(job_id=jid, principal_key="p", surface="plugin", state="queued",
                               requester_role="third_party_public_code", source_kind="deployed",
                               source_args={}, has_deployment=True, chain="evm")
    await conn.execute(
        "update jobs set limit_key = %s, report_at = now() - make_interval(secs => %s) where job_id = %s",
        (key, hours_ago * 3600, jid))
    return jid


@pytest.mark.asyncio(loop_scope="session")   # session pool, as tests/db/test_leads_repo
async def test_check_counts_rolling_24h_and_relay_cap(db_pool, monkeypatch):
    async with db_pool.connection() as conn:
        tx = conn.transaction(force_rollback=True)
        async with tx:
            await _check_scenario(conn, monkeypatch)


async def _check_scenario(db_conn, monkeypatch):
    monkeypatch.setenv("SOKEN_DAILY_REPORTS_PER_USER", "2")
    monkeypatch.setenv("SOKEN_DAILY_REPORTS_RELAY_TOTAL", "3")
    await _job_with_report(db_conn, "ip:aaa", 1)
    await _job_with_report(db_conn, "ip:aaa", 30)            # outside the window
    await Q.check(db_conn, "ip:aaa")
    second = await _job_with_report(db_conn, "ip:aaa", 2)
    with pytest.raises(ReviewError) as e:
        await Q.check(db_conn, "ip:aaa", lock=True)
    assert e.value.code == "E_DAILY_REPORT_LIMIT"
    await Q.check(db_conn, "ip:aaa", job_id=second)          # the job's own report does not count twice
    await Q.check(db_conn, "ip:bbb")
    await Q.check(db_conn, None)
    for k in ("relay:x", "relay:y", "relay:z"):
        await _job_with_report(db_conn, k, 1)
    with pytest.raises(ReviewError):
        await Q.check(db_conn, "relay:new")                   # shared relay cap reached


@pytest.mark.asyncio
async def test_x_real_ip_reaches_the_handler(monkeypatch):
    """The ContextVar set in http.ProtocolRules is visible inside the SDK's tool call."""
    from soken_review import server

    seen: list[str | None] = []

    async def probe(_args):
        seen.append(Q.CLIENT_IP.get())
        return "ok"

    from asgi_lifespan import LifespanManager

    monkeypatch.setitem(server.HANDLERS, "review_get_guide", probe)
    app = server.create_app()
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 5555))
    async with LifespanManager(app), httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "review_get_guide", "arguments": {"topic": "checklist"}}}
        hdr = {"MCP-Protocol-Version": "2025-11-25", "Accept": "application/json, text/event-stream"}
        for extra in ({"X-Real-IP": "203.0.113.7"}, {}):
            r = await client.post("/mcp", content=json.dumps(body), headers={**hdr, **extra,
                                                                             "Content-Type": "application/json"})
            assert r.status_code == 200, r.text
    # With the header: the client; without it, the loopback peer is the proxy, not a user.
    assert seen == ["203.0.113.7", None]


def test_relay_cidrs_file_is_read_and_reloaded(monkeypatch, tmp_path):
    f = tmp_path / "relay.txt"
    f.write_text("# openai: 1\n20.0.0.0/24\nnot-a-cidr\n", encoding="utf-8")
    monkeypatch.setenv("SOKEN_RELAY_CIDRS_FILE", str(f))
    monkeypatch.delenv("SOKEN_RELAY_CIDRS", raising=False)
    tok = Q.CLIENT_IP.set("20.0.0.9")
    try:
        assert Q.limit_key(target="evm:0xabc", job_id="j").startswith("relay:")
        import os
        f.write_text("21.0.0.0/24\n", encoding="utf-8")
        os.utime(f, (1, 1))                                   # new mtime: reloaded
        assert Q.limit_key(target="evm:0xabc", job_id="j").startswith("ip:")
        Q.CLIENT_IP.set("160.79.106.1")                       # Anthropic default still relay
        assert Q.limit_key(target="evm:0xabc", job_id="j").startswith("relay:")
    finally:
        Q.CLIENT_IP.reset(tok)
