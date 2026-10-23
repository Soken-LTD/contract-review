"""A job deleted by review_delete_job while work was in flight: the step dispatcher cancels a
row it claims for a deleted job before any runner writes, and the render step discards its output
instead of landing a PDF for a job that no longer exists (security review, 2026-10-23)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.worker.supervisor import Supervisor


@pytest.mark.asyncio
async def test_dispatcher_cancels_a_step_of_a_deleted_job(tmp_path: Path) -> None:
    sup = object.__new__(Supervisor)
    sup._pin_root = tmp_path
    sup._free_units, sup._free_ram_mb = 4, 4096
    sup._get_job = AsyncMock(return_value={"job_id": "job_" + "0" * 24 + "D1", "state": "deleted", "chain": None})
    sup._mark_step = AsyncMock()
    sup._run_fetch = AsyncMock()
    step = {"id": 5, "job_id": "job_" + "0" * 24 + "D1", "step": "fetch", "seq": 0, "units": 1, "ram_mb": 512}
    await sup._run_step(step)
    sup._mark_step.assert_awaited_once_with(5, "cancelled")
    sup._run_fetch.assert_not_awaited()
    assert (sup._free_units, sup._free_ram_mb) == (4, 4096)          # resources handed back


@pytest.mark.asyncio
async def test_render_output_is_discarded_when_the_job_was_deleted(monkeypatch, tmp_path: Path) -> None:
    from soken_review.report import render as R

    uploads: list[Any] = []
    monkeypatch.setattr(R, "_upload", lambda *a, **k: uploads.append(a) or "reports/x/1/")
    monkeypatch.setattr(R, "_job_deleted", AsyncMock(return_value=True))
    monkeypatch.setattr(R, "assemble_report", AsyncMock(return_value=({"meta": {"report_id": "a" * 26}}, {})))
    monkeypatch.setattr(R, "_render_no", AsyncMock(return_value=1))
    monkeypatch.setattr(R, "fresh_render_dir", lambda b: tmp_path / "rd")
    monkeypatch.setattr(R, "render_image", lambda: "img")
    outcome = R.RenderOutcome("ok", "", pages=1, pdf_sha256="c" * 64, out_dir=tmp_path, result={"compact": False},
                              files={"report.pdf": b"%PDF"})
    monkeypatch.setattr(R, "run_container", lambda *a, **k: outcome)
    monkeypatch.setattr(R, "build_screen_html", lambda *a, **k: b"<html>")

    executed: list[tuple] = []
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    conn.execute = AsyncMock(side_effect=lambda q, p=None: executed.append((q, p)))
    pool = MagicMock()
    pool.connection = MagicMock(return_value=conn)
    with patch.object(R, "JobRepo") as repo_cls:
        repo_cls.return_value.transition = AsyncMock()
        result = await R.run_render_step(pool, {"id": 9, "job_id": "job_" + "0" * 24 + "D1"}, tmp_path)
    assert result is outcome
    assert uploads == []
    assert any("status = 'cancelled'" in q for q, _ in executed)
