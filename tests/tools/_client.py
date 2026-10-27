"""An MCP client for DB-wired tool tests on the session event loop.

pytest-asyncio runs the setup and the teardown of an async-generator fixture as two tasks on the
loop. `Client(SokenServer())` owns an anyio task group, and anyio refuses to exit a cancel scope
from a task other than the one that entered it ("Attempted to exit cancel scope in a different
task", CI run 40501752418). `task_scoped_client` enters and exits the client inside one dedicated
task and hands the session to the fixture; tool calls from the test task only use the client's
streams, never its cancel scopes.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

from mcp.client.client import Client

from soken_review.server import SokenServer


@contextlib.asynccontextmanager
async def task_scoped_client() -> AsyncIterator[Client]:
    started: asyncio.Future[Client] = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def run() -> None:
        try:
            async with Client(SokenServer()) as c:
                started.set_result(c)
                await stop.wait()
        except BaseException as exc:
            if not started.done():
                started.set_exception(exc)
            raise

    task = asyncio.create_task(run())
    try:
        yield await started
    finally:
        stop.set()
        with contextlib.suppress(asyncio.CancelledError):
            await task
