"""Read budget and cache of the chain tools (chain access design 2.2 and 4; migration 016).

Budget: read units (RU) are charged to the job (`chain_job_ru`) and to the quota key of the
caller (`chain_key_ru`, rolling 24 hours, the hashed key of `quota.limit_key`). A call reserves
its estimate up front under row and advisory locks, so two concurrent calls cannot both pass the
cap; items that failed because of a provider (5xx, 429, no archive) are refunded afterwards.
Running out of RU returns E_CHAIN_BUDGET for that call only: it never touches the report quota
and never blocks a finding or finalize (CEO never-worse rule).

Cache: answers at a final block live in `chain_cache` for every job (public data, keyed by a hash
of family, chain, method and params; no job id and no quota key). Answers at a recent block live
in process for `latest_cache_s`. Results never say whether they came from the cache.
"""

from __future__ import annotations

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


_MEM: dict[str, tuple[float, Any]] = {}
_MEM_MAX = 4096


class Cache:
    """`get(key)` / `put(key, value, durable)`; durable answers go to Postgres when a pool is set."""

    def __init__(self, pool: Any | None) -> None:
        self._pool = pool

    async def get(self, key: str) -> Any | None:
        hit = _MEM.get(key)
        ttl = float(limits().get("latest_cache_s", 12))
        if hit is not None:
            at, value = hit
            if at < 0 or time.monotonic() - at <= ttl:
                return value
            _MEM.pop(key, None)
        if self._pool is None:
            return None
        async with self._pool.connection() as conn:
            row = await (await conn.execute("select result from chain_cache where key = %s", (key,))).fetchone()
        if row is None:
            return None
        value = row[0] if not isinstance(row[0], str) else json.loads(row[0])
        _remember(key, value, durable=True)
        return value

    async def put(self, key: str, value: Any, durable: bool) -> None:
        _remember(key, value, durable)
        if durable and self._pool is not None:
            async with self._pool.connection() as conn:
                await conn.execute("insert into chain_cache (key, result) values (%s, %s::jsonb) on conflict do nothing",
                                   (key, json.dumps(value)))


def _remember(key: str, value: Any, durable: bool) -> None:
    if len(_MEM) >= _MEM_MAX:
        for k in list(_MEM)[: _MEM_MAX // 4]:
            _MEM.pop(k, None)
    _MEM[key] = (-1.0 if durable else time.monotonic(), value)
