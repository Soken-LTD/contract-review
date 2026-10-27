"""Number-check violations as catalogued errors (04 section 6; contract/errors.yaml).

One place for the three write-time callers (submit, set_section, finalize), so every number
rejection names the token, the field, the rule and what to write instead.
"""

from __future__ import annotations

from typing import Any

from ..engine.numbers import NumberContext
from ..engine.text_gate import Violation
from ..errors import ReviewError

_MAX_VALUES = 6


def nearest_allowed(ctx: NumberContext | None) -> str:
    """The `values` field of E_NUMBER_UNSOURCED: literals the finding may use bare (A1), else a
    plain statement that none is available in this string."""
    allowed = sorted(ctx.allowed_literals, key=lambda v: (len(v), v)) if ctx and ctx.allowed_literals else []
    if not allowed:
        return "none (no literal on the quoted lines)"
    return ", ".join(allowed[:_MAX_VALUES])


def number_error(v: Violation, field: str, ctx: NumberContext | None = None, **extra: Any) -> dict[str, Any]:
    """ReviewError envelope for one number violation."""
    match = v.match or ""
    return ReviewError(
        v.code, rule=v.rule_id, match=match[:80], token=match[:40], field=field, cp=match[:5],
        pos=v.span[0], values=nearest_allowed(ctx), **extra,
    ).envelope()
