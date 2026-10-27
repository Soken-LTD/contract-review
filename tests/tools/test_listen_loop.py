"""The job-change listener survives a change of event loop (one listener per process; test
sessions and a restarted server loop create new loops)."""

from __future__ import annotations

import asyncio

from soken_review.tools.listen import JobChangeListener


def test_listener_rebinds_to_a_new_loop_instead_of_reusing_dead_primitives():
    lst = JobChangeListener("postgresql://127.0.0.1:1/none")   # never reached: no await on the task

    async def first() -> asyncio.Event:
        ev = lst.subscribe("abc")
        assert lst._task is not None and not lst._task.done()
        lst._task.cancel()
        return ev

    async def second() -> bool:
        ev = lst.subscribe("abc")           # a new loop: state is rebuilt, nothing from the old loop is touched
        assert ev in lst._waiters["abc"] and len(lst._waiters["abc"]) == 1
        lst._task.cancel()
        return await lst.wait_ready(0.01)   # no connection: not ready, but no cross-loop error

    old_ev = asyncio.run(first())
    assert asyncio.run(second()) is False
    assert old_ev not in lst._waiters.get("abc", set())
