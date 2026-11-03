"""Thin or legacy client flow (thin server design 2026-11-03, CEO decision 2026-11-01).

`SOKEN_FLOW=thin` (the default) is the data-and-report server: no analyzer leads, no challenge, no
sections, no severity matrix, no text or number gates; the only check on a finding is that its quotes
exist in the pinned source. `SOKEN_FLOW=legacy` restores the previous behaviour for one release.

Two scopes, on purpose:

- The server flag (`server_flow`) decides how the tools answer: submit, withdraw, finalize, status and
  the guide. A job that was in flight at deploy therefore runs the thin checks, which are never stricter.
- The job's own `jobs.flow` column (migration 022, `job_flow`) decides what the job's data looks like:
  the analyze step, the server drafts and the report assembly. Rows older than migration 022 read
  `legacy`, so their re-renders print exactly the sections they printed before.
"""

from __future__ import annotations

import os
from typing import Any

THIN = "thin"
LEGACY = "legacy"
FLOWS = (THIN, LEGACY)


def server_flow() -> str:
    """The flow new jobs get and the tools answer in; anything but `legacy` is thin."""
    return LEGACY if os.environ.get("SOKEN_FLOW", THIN).strip().lower() == LEGACY else THIN


def thin_tools() -> bool:
    return server_flow() == THIN


def job_flow(job: dict[str, Any] | None) -> str:
    """The flow a job was created in; a row without the column (or a test double) is legacy."""
    value = (job or {}).get("flow")
    return value if value in FLOWS else LEGACY


def thin_job(job: dict[str, Any] | None) -> bool:
    return job_flow(job) == THIN
