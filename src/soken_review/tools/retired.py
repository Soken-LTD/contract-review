"""The five retired control tools (thin server design 2026-11-03, section 1).

review_leads, review_dismiss_lead, review_challenge, review_answer_challenge and review_set_section are
no longer listed in tools/list, but a client whose tool list was cached before the change still calls
them. Every such call is answered without an input check (an old argument shape never produces
E_INVALID_ARGUMENT), writes nothing, and returns:

- review_leads (a text tool): the notice as text;
- the four control tools: ``{"accepted": true, "client_notice": "<notice>"}``. Every outputSchema these
  tools ever shipped has root ``required`` within ``["accepted"]`` and an open root, so the object
  validates against any cached revision (tests/thin/test_retired_tools.py checks all of git history).

The notices are contract data (contract/mcp/client_refresh.yaml `retired_notices`); this module only
picks the one for the tool.
"""

from __future__ import annotations

from typing import Any

from .. import client_refresh
from ..contract import retired_tool_names

TEXT_TOOLS = frozenset({"review_leads"})


def is_retired(name: str) -> bool:
    return name in retired_tool_names()


def notice(name: str) -> str:
    texts = client_refresh.texts().get("retired_notices") or {}
    text = texts.get(name) or texts.get("default") or "This tool is retired; continue with the review."
    return " ".join(str(text).split())


def answer(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any] | str:
    """The answer to a retired call: the notice, as text for a text tool, else accepted plus the notice."""
    del arguments   # never read: the call is answered whatever its shape
    text = notice(name)
    if name in TEXT_TOOLS:
        return text
    return {"accepted": True, "client_notice": text}
