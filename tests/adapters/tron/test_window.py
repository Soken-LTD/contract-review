"""Tests for TRON window logic (05 section 12.5).

Uses a fake TronGridClient to simulate stable and unstable reads.
"""

from __future__ import annotations

from typing import Any

import pytest

from soken_review.adapters.tron.rpc import TronGridWindowError, read_with_window


class FakeTronGridClient:
    """Fake TronGridClient that returns preset block numbers."""

    def __init__(self, blocks: list[int]) -> None:
        self._blocks = iter(blocks)

    async def eth_block_number(self) -> int:
        return next(self._blocks)


@pytest.mark.asyncio
async def test_window_stable_reads():
    """When both batches return the same values, window = (first, last) block."""
    call_count = 0

    async def reads_fn() -> dict[str, Any]:
        nonlocal call_count
        call_count += 1
        return {"runtime": "0xdeadbeef", "creation": "0xcafe"}

    # Blocks: before_batch1=100, mid_batch1=101, before_batch2=101, mid_batch2=102, last=103
    fake_client = FakeTronGridClient([100, 101, 102])
    values, (b_first, b_last) = await read_with_window(reads_fn, fake_client)
    assert values == {"runtime": "0xdeadbeef", "creation": "0xcafe"}
    assert b_first == 100
    assert b_last == 102
    assert call_count == 2  # called twice


@pytest.mark.asyncio
async def test_window_mismatch_exhausted():
    """When batches disagree on every retry, raise TronGridWindowError."""
    counter = 0

    async def reads_fn() -> dict[str, Any]:
        nonlocal counter
        counter += 1
        # Alternate values so they never match
        if counter % 2 == 1:
            return {"runtime": "0xaaaaaaaa"}
        return {"runtime": "0xbbbbbbbb"}

    # Supply enough block numbers for 3 retries * 3 reads each
    fake_client = FakeTronGridClient(list(range(100, 130)))

    with pytest.raises(TronGridWindowError):
        await read_with_window(reads_fn, fake_client)


@pytest.mark.asyncio
async def test_window_recovers_after_retry():
    """Values stabilize on the second attempt -> window returned."""
    attempt = 0

    async def reads_fn() -> dict[str, Any]:
        nonlocal attempt
        attempt += 1
        # First two calls (first batch attempt) differ, subsequent calls agree
        if attempt <= 2:
            # First attempt: values differ between the two reads
            return {"val": str(attempt)}
        return {"val": "stable"}

    fake_client = FakeTronGridClient(list(range(100, 120)))
    values, _ = await read_with_window(reads_fn, fake_client)
    assert values == {"val": "stable"}


@pytest.mark.asyncio
async def test_window_empty_reads():
    """Empty reads dict is treated as stable (vacuous equality)."""
    async def reads_fn() -> dict[str, Any]:
        return {}

    fake_client = FakeTronGridClient([1, 2, 3])
    values, (b1, b2) = await read_with_window(reads_fn, fake_client)
    assert values == {}
    assert b1 == 1
    assert b2 == 3
