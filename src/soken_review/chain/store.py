"""Read budget and cache of the chain tools (chain access design 2.2 and 4; migration 018).

Budget: read units (RU) are charged to the job (`chain_job_ru`) and to the quota key of the
caller (`chain_key_ru`, rolling 24 hours, the hashed key of `quota.limit_key`). A call reserves
its estimate up front under row and advisory locks, so two concurrent calls cannot both pass the
cap; items that failed because of a provider (5xx, 429, no archive) are refunded afterwards.
Running out of RU returns E_CHAIN_BUDGET for that call only: it never touches the report quota
and never blocks a finding or finalize (CEO never-worse rule).

Cache: see `Cache` (job-scoped by default; shared across jobs only once two distinct hosts agreed
or an operator-configured host answered). Results never say whether they came from the cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from ..errors import ReviewError

_LIMITS = Path(__file__).resolve().parents[3] / "contract" / "ops" / "limits.yaml"


@lru_cache(maxsize=1)
def limits() -> dict[str, Any]:
    data = yaml.safe_load(_LIMITS.read_text(encoding="utf-8")).get("chain_access") or {}
    out = dict(data)
    for env, key in (("SOKEN_CHAIN_JOB_RU", "job_ru"), ("SOKEN_CHAIN_KEY_RU_PER_DAY", "key_ru_per_day")):
        try:
            if os.environ.get(env):
                out[key] = int(os.environ[env])
        except ValueError:
            pass
    return out


class Budget:
    """RU accounting for one tool call. Without a pool (unit tests, local dev) it counts in memory."""

    def __init__(self, pool: Any | None, job_id: str, limit_key: str | None) -> None:
        self._pool = pool
        self.job_id = job_id
        self.limit_key = limit_key
        self.reserved = 0
        self.used_after: int | None = None
        self.left_after: int | None = None

    async def reserve(self, ru: int) -> None:
        lim = limits()
        job_cap, key_cap = int(lim.get("job_ru", 2000)), int(lim.get("key_ru_per_day", 6000))
        if self._pool is None:
            self.reserved = ru
            self.used_after, self.left_after = ru, job_cap - ru
            return
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute("insert into chain_job_ru (job_id) values (%s) on conflict do nothing", (self.job_id,))
            row = await (await conn.execute("select ru_used from chain_job_ru where job_id = %s for update",
                                            (self.job_id,))).fetchone()
            used = int(row[0]) if row else 0
            if used + ru > job_cap:
                raise ReviewError("E_CHAIN_BUDGET", scope="job", used=str(used), cap=str(job_cap), need=str(ru))
            if self.limit_key:
                await conn.execute("select pg_advisory_xact_lock(hashtext('soken-chain-ru:' || %s))", (self.limit_key,))
                krow = await (await conn.execute(
                    "select coalesce(sum(ru), 0) from chain_key_ru where limit_key = %s and at > now() - interval '24 hours'",
                    (self.limit_key,))).fetchone()
                kused = int(krow[0]) if krow else 0
                if kused + ru > key_cap:
                    raise ReviewError("E_CHAIN_BUDGET", scope="day", used=str(kused), cap=str(key_cap), need=str(ru))
                await conn.execute("insert into chain_key_ru (limit_key, ru) values (%s, %s)", (self.limit_key, ru))
                await conn.execute("delete from chain_key_ru where at < now() - interval '2 days'")
            await conn.execute("update chain_job_ru set ru_used = ru_used + %s, updated_at = now() where job_id = %s",
                               (ru, self.job_id))
        self.reserved = ru
        self.used_after, self.left_after = used + ru, job_cap - used - ru

    async def refund(self, ru: int) -> None:
        ru = max(0, min(ru, self.reserved))
        if not ru:
            return
        self.reserved -= ru
        if self.used_after is not None:
            self.used_after -= ru
            self.left_after = (self.left_after or 0) + ru
        if self._pool is None:
            return
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute("update chain_job_ru set ru_used = greatest(0, ru_used - %s), updated_at = now() "
                               "where job_id = %s", (ru, self.job_id))
            if self.limit_key:
                await conn.execute("insert into chain_key_ru (limit_key, ru) values (%s, %s)", (self.limit_key, -ru))

    def as_dict(self) -> dict[str, int]:
        return {"charged": self.reserved, "used": int(self.used_after or 0), "left": int(self.left_after or 0)}


_MEM: dict[tuple[str, str], tuple[float, float, Any]] = {}   # (scope, key) -> (stored_at, ttl_s, value)
_MEM_MAX = 4096
_JOB_DURABLE_TTL_S = 3600.0


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Cache:
    """Job-scoped first, shared only when proven.

    Every answer is cached for the job that read it (`latest_cache_s` for recent blocks, an hour
    for final ones). An answer at a final block becomes shared (other jobs, Postgres) only when it
    came from an operator-configured host, or when a second, distinct host later returned the same
    answer for the same request; a different answer from another host removes the entry. Shared
    entries expire after `shared_cache_days` (security review 2026-10-28: one lying free endpoint
    must not poison the facts of every later job)."""

    def __init__(self, pool: Any | None, job_id: str = "") -> None:
        self._pool = pool
        self._job = job_id or "-"

    async def get(self, key: str) -> Any | None:
        for scope in (self._job, "*"):
            hit = _MEM.get((scope, key))
            if hit is not None:
                at, ttl, value = hit
                if time.monotonic() - at <= ttl:
                    return value
                _MEM.pop((scope, key), None)
        if self._pool is None:
            return None
        days = int(limits().get("shared_cache_days", 30))
        async with self._pool.connection() as conn:
            row = await (await conn.execute(
                "select result from chain_cache where key = %s and (trusted or confirmed_host is not null)"
                " and created_at > now() - make_interval(days => %s)", (key, days))).fetchone()
        if row is None:
            return None
        value = row[0] if not isinstance(row[0], str) else json.loads(row[0])
        _remember("*", key, value, _JOB_DURABLE_TTL_S)
        return value

    async def put(self, key: str, value: Any, durable: bool, host: str = "", trusted: bool = False) -> None:
        _remember(self._job, key, value, _JOB_DURABLE_TTL_S if durable else float(limits().get("latest_cache_s", 12)))
        if not durable or self._pool is None or not host:
            return
        h = _hash(value)
        async with self._pool.connection() as conn, conn.transaction():
            row = await (await conn.execute(
                "select result_hash, host, trusted, confirmed_host from chain_cache where key = %s for update",
                (key,))).fetchone()
            if row is None:
                await conn.execute(
                    "insert into chain_cache (key, result, result_hash, host, trusted) values (%s, %s::jsonb, %s, %s, %s)"
                    " on conflict do nothing", (key, json.dumps(value), h, host, trusted))
                return
            old_hash, old_host, old_trusted, confirmed = row
            if old_hash == h:
                if not confirmed and not old_trusted and host != old_host:
                    await conn.execute("update chain_cache set confirmed_host = %s where key = %s", (host, key))
                elif trusted and not old_trusted:
                    await conn.execute("update chain_cache set trusted = true where key = %s", (key,))
                return
            if trusted and not old_trusted:   # an operator-configured host replaces a free host's answer
                await conn.execute("update chain_cache set result = %s::jsonb, result_hash = %s, host = %s, trusted = true,"
                                   " confirmed_host = null, created_at = now() where key = %s",
                                   (json.dumps(value), h, host, key))
            elif not old_trusted:              # two hosts disagree: nothing is shared for this request
                await conn.execute("delete from chain_cache where key = %s", (key,))
                _MEM.pop(("*", key), None)


def _remember(scope: str, key: str, value: Any, ttl: float) -> None:
    if len(_MEM) >= _MEM_MAX:
        for k in list(_MEM)[: _MEM_MAX // 4]:
            _MEM.pop(k, None)
    _MEM[(scope, key)] = (time.monotonic(), ttl, value)
