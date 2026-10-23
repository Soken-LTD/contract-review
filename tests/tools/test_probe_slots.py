"""`git ls-remote` probes run at most MAX_CONCURRENT_PROBES at a time in the API process (item 8)."""

from __future__ import annotations

import asyncio

import pytest

from soken_review.tools import git_probe as G


@pytest.mark.asyncio
async def test_concurrent_probes_are_bounded(monkeypatch):
    running = 0
    peak = 0

    async def fake(argv, timeout):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.02)
        running -= 1
        return 0, ""

    monkeypatch.setattr(G, "_ls_remote", fake)
    monkeypatch.setattr(G, "_probe_slots", None)
    results = await asyncio.gather(*(G.ls_remote("https://github.com/a/b", ["HEAD"]) for _ in range(20)))
    assert all(r == (0, "") for r in results)
    assert peak == G.MAX_CONCURRENT_PROBES


@pytest.mark.asyncio
async def test_invalid_url_never_takes_a_slot(monkeypatch):
    async def fail(argv, timeout):
        raise AssertionError("must not run")

    monkeypatch.setattr(G, "_ls_remote", fail)
    assert await G.ls_remote("https://evil.example/a/b", ["HEAD"]) == (2, "")
