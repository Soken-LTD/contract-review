"""LISTEN/NOTIFY long-poll for `review_status` (03 section 4.2; trigger in migrations/002_ops.sql).

One listener connection per process: `LISTEN job_changed`; the trigger sends
`sha256(job_id)[:12]` on every job state change and step insert or status change. Waiters
subscribe by that hash and get an `asyncio.Event`. If the listener connection drops, it reconnects
with backoff; callers also re-read the job row every `RECHECK_S`, so a lost notification costs
latency, never a missed change.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging

import psycopg

logger = logging.getLogger(__name__)

CHANNEL = "job_changed"
RECHECK_S = 5.0


def job_hash(job_id: str) -> str:
    return hashlib.sha256(job_id.encode("utf-8")).hexdigest()[:12]


class JobChangeListener:
    """One per conninfo and process. Its task, ready flag and waiter events belong to the event
    loop that first subscribed; when a later subscriber runs on another loop (a new loop per
    test session, a restarted server loop) the listener starts over on that loop instead of
    touching primitives bound to a dead one ("Event bound to a different event loop")."""

    def __init__(self, conninfo: str) -> None:
        self._conninfo = conninfo
        self._waiters: dict[str, set[asyncio.Event]] = {}
        self._task: asyncio.Task | None = None
        self._ready = asyncio.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self.notifications = 0

    def _bind_loop(self) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is loop:
            return
        if self._task is not None and not self._task.done() and self._loop is not None and not self._loop.is_closed():
            self._task.cancel()
        self._task = None
        self._waiters = {}
        self._ready = asyncio.Event()
        self._loop = loop

    def subscribe(self, h: str) -> asyncio.Event:
        self._bind_loop()
        ev = asyncio.Event()
        self._waiters.setdefault(h, set()).add(ev)
        self._ensure()
        return ev

    def unsubscribe(self, h: str, ev: asyncio.Event) -> None:
        group = self._waiters.get(h)
        if group is not None:
            group.discard(ev)
            if not group:
                self._waiters.pop(h, None)

    async def wait_ready(self, timeout: float) -> bool:
        self._bind_loop()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._ready.wait(), timeout)
        return self._ready.is_set()

    def _ensure(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._run())

    async def _run(self) -> None:
        backoff = 0.5
        while self._waiters:
            try:
                async with await psycopg.AsyncConnection.connect(self._conninfo, autocommit=True) as conn:
                    await conn.execute(f"LISTEN {CHANNEL}")
                    self._ready.set()
                    backoff = 0.5
                    while self._waiters:
                        async for n in conn.notifies(timeout=30.0):
                            self.notifications += 1
                            for ev in list(self._waiters.get(n.payload, ())):
                                ev.set()
            except Exception:  # reconnect; waiters re-read the row every RECHECK_S
                logger.warning("job_changed listener lost; reconnecting", exc_info=True)
            finally:
                self._ready.clear()
            if self._waiters:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 10.0)


_listeners: dict[str, JobChangeListener] = {}


def listener_for(conninfo: str) -> JobChangeListener:
    lst = _listeners.get(conninfo)
    if lst is None:
        lst = _listeners[conninfo] = JobChangeListener(conninfo)
    return lst
