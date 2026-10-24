"""Daily report quota (CEO 2026-10-24: two reports per user per day) and the reviewed-target key.

There is no user account on the connector, so "user" is approximated:
  - a direct client (Claude Code, Cursor, any MCP client) is its IP address: `ip:<addr>`;
  - a request relayed by Anthropic's claude.ai infrastructure (SOKEN_RELAY_CIDRS) carries an
    Anthropic egress IP shared by every claude.ai user and rotating between calls, so the key is
    the reviewed target instead: `relay:<target_key>`, and all relayed reports together share one
    daily cap (SOKEN_DAILY_REPORTS_RELAY_TOTAL).

The client IP comes from nginx's `X-Real-IP` (uvicorn listens on 127.0.0.1 only, so the header
cannot be forged from outside) and is put in `CLIENT_IP` by `http.ProtocolRules` per request.
The quota is checked at `review_start` (early refusal) and enforced under an advisory lock at
`review_finalize`, where the report is issued; the window is a rolling 24 hours.

`target_key` is also the publication key: one published report per target (publish_worker).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
from contextvars import ContextVar
from typing import Any

import psycopg

from .errors import ReviewError

CLIENT_IP: ContextVar[str | None] = ContextVar("soken_client_ip", default=None)

_EVM_CHAINS = {"evm", "hyperevm"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _cidrs(name: str, default: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out = []
    for part in os.environ.get(name, default).split(","):
        part = part.strip()
        if part:
            try:
                out.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
    return out


def _in(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def per_user_limit() -> int:
    return _int_env("SOKEN_DAILY_REPORTS_PER_USER", 2)


def relay_total_limit() -> int:
    return _int_env("SOKEN_DAILY_REPORTS_RELAY_TOTAL", 50)


def target_key(*, chain: str | None, address: str | None, repo_url: str | None,
               subdir: str | None = None) -> str | None:
    """Stable identity of what was reviewed: `<chain>:<address>` or `repo:<host/owner/repo>[/<subdir>]`."""
    if chain and address:
        addr = address.strip()
        if chain in _EVM_CHAINS or addr.lower().startswith("0x"):
            addr = addr.lower()
        return f"{chain}:{addr}"
    if repo_url:
        url = repo_url.strip().lower()
        for prefix in ("https://", "http://", "git://", "ssh://"):
            url = url.removeprefix(prefix)
        url = url.removeprefix("git@").replace(":", "/", 1) if url.startswith("git@") else url
        url = url.rstrip("/").removesuffix(".git").rstrip("/")
        sub = (subdir or "").strip("/").lower()
        return f"repo:{url}/{sub}" if sub else f"repo:{url}"
    return None


def _h(value: str) -> str:
    """Keyed hash: a plain SHA of an IPv4 address or a public contract is reversible by search.
    Key: SOKEN_QUOTA_SECRET, else report key V1 (both outside the database)."""
    from .tools.report import key as report_key

    secret = os.environ.get("SOKEN_QUOTA_SECRET", "").encode() or report_key(1)
    return hmac.new(secret, b"soken-quota:" + value.encode(), hashlib.sha256).hexdigest()[:32]


def _user_of(ip: str) -> str:
    """One quota user per IPv4 address or IPv6 /64 (a host can rotate inside its /64 for free)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def limit_key(*, target: str | None, job_id: str) -> str | None:
    """Quota key for the current request, or None when the caller is exempt (SOKEN_QUOTA_EXEMPT_CIDRS).

    The IP or target is stored hashed: the key outlives review_delete_job (no quota refund) and
    must not keep the address or IP the delete scrubs."""
    ip = CLIENT_IP.get()
    if ip and _in(ip, _cidrs("SOKEN_QUOTA_EXEMPT_CIDRS", "")):
        return None
    if ip and _in(ip, _cidrs("SOKEN_RELAY_CIDRS", "160.79.104.0/21")):
        return f"relay:{_h(target or 'job:' + job_id)}"
    if ip:
        return f"ip:{_h(_user_of(ip))}"
    return f"target:{_h(target)}" if target else None


async def _count(conn: psycopg.AsyncConnection, where: str, value: str, job_id: str | None) -> int:
    async with conn.cursor() as cur:
        await cur.execute(
            f"select count(*) from jobs where {where} and report_at > now() - interval '24 hours'"
            " and job_id is distinct from %s",
            (value, job_id),
        )
        row = await cur.fetchone()
        return int(row[0]) if row else 0


async def check(conn: psycopg.AsyncConnection, key: str | None, *, job_id: str | None = None,
                lock: bool = False) -> None:
    """Raise E_DAILY_REPORT_LIMIT when `key` already holds its reports for the last 24 hours."""
    if not key:
        return
    if lock:
        await conn.execute("select pg_advisory_xact_lock(hashtext('soken-quota:' || %s))", (key,))
    limit = per_user_limit()
    used = await _count(conn, "limit_key = %s", key, job_id)
    if used >= limit:
        raise ReviewError("E_DAILY_REPORT_LIMIT", count=str(used), limit=str(limit))
    if key.startswith("relay:"):
        total = relay_total_limit()
        if lock:
            await conn.execute("select pg_advisory_xact_lock(hashtext('soken-quota:relay'))")
        used_all = await _count(conn, "limit_key like %s", "relay:%", job_id)
        if used_all >= total:
            raise ReviewError("E_DAILY_REPORT_LIMIT", count=str(used_all), limit=str(total))


def job_target(job: dict[str, Any]) -> str | None:
    """`target_key` of a stored job row (stored at review_start; recomputed for older rows)."""
    if job.get("target_key"):
        return job["target_key"]
    args = job.get("source_args") or {}
    return target_key(chain=job.get("chain"), address=job.get("address"),
                      repo_url=args.get("repo_url") if isinstance(args, dict) else None,
                      subdir=args.get("subdir") if isinstance(args, dict) else None)
