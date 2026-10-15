"""JobContext protocol: seam between tool handlers and the job store (03 section 3.4).

`JobContext` is the minimal interface handlers need.  The Postgres implementation
lives in the DB workstream; `MemoryJobContext` is used in tests and local dev.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class JobContext(Protocol):
    """Minimal interface tool handlers depend on."""

    def get_pin_root(self) -> Path:
        """Root directory under which <job_id>/pin/ directories are stored."""
        ...

    def get_job_state(self, job_id: str) -> str | None:
        """Return the current job state, or None when the job does not exist."""
        ...

    def append_read(self, job_id: str, path: str, start: int, end: int) -> None:
        """Log that lines [start, end] of path were returned to the session.

        Writes to job_reads (03 section 3.6, 4.4). Called by review_read_code;
        never called for search hits (03 4.5: search hits are not reads).
        """
        ...


class MemoryJobContext:
    """In-memory implementation of JobContext for tests and local dev."""

    def __init__(self, pin_root: Path) -> None:
        self._pin_root = pin_root
        self._states: dict[str, str] = {}
        self.reads: list[tuple[str, str, int, int]] = []

    # ── state helpers ───────────────────────────────────────────────────────

    def set_state(self, job_id: str, state: str) -> None:
        """Register a job with the given state."""
        self._states[job_id] = state

    # ── JobContext impl ─────────────────────────────────────────────────────

    def get_pin_root(self) -> Path:
        return self._pin_root

    def get_job_state(self, job_id: str) -> str | None:
        return self._states.get(job_id)

    def append_read(self, job_id: str, path: str, start: int, end: int) -> None:
        self.reads.append((job_id, path, start, end))
