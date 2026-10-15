"""review_report before the render exists: the E_JOB_NOT_READY envelope names the state (03 4.15).

Seen on the first local end-to-end run: a `ready` job answered "Job is , eta  s." because the
handler raised the catalogued error without its template fields.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from soken_review.errors import ReviewError
from soken_review.tools import report


@pytest.mark.parametrize("state", ["queued", "fetching", "building", "analyzing", "ready"])
@pytest.mark.asyncio
async def test_not_ready_envelope_names_the_state(monkeypatch, state):
    monkeypatch.setattr(report, "_load", AsyncMock(return_value=({"job_id": "job_X", "state": state}, None, None)))
    with pytest.raises(ReviewError) as exc:
        await report.handle_review_report({"job_id": "job_X", "wait_seconds": 0})
    env = exc.value.envelope()
    assert env["code"] == "E_JOB_NOT_READY"
    assert env["what"] == f"Job is {state}, eta 0 s."
    assert "{" not in env["what"] and " , " not in env["what"]
