"""Application factory re-export (plan-v4 09 workstream).

``uvicorn --factory soken_review.app:create_app`` is the canonical entry point.
The factory lives in tools/context_pg.py; this module re-exports it so the
README command ``uvicorn --factory soken_review.server:create_app`` (bare server,
no DB lifespan) continues to work unchanged.
"""

from .tools.context_pg import create_app as create_app  # noqa: PLC0414
