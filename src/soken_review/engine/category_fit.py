"""Category fit notices (rubric/category_fit.yaml, r5 blind run 2026-10-31).

The finding category picks the disproof checklist, and a kill item of the wrong checklist can
withdraw a true finding. These helpers fill the yaml templates: which checklist applies and what
it fits (`notice`), which category to use instead when a kill item fired (`kill_fired`), and the
category guide rows. All wording lives in the yaml; this module only fills the slots.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml

_FILE = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "category_fit.yaml"


@cache
def _doc() -> dict[str, Any]:
    return yaml.safe_load(_FILE.read_text(encoding="utf-8")) or {}


def _row(category: str) -> dict[str, Any] | None:
    row = (_doc().get("categories") or {}).get(category)
    return row if isinstance(row, dict) and row.get("fits") else None


def checklist_notice(category: str, kill_ids: list[str], *, generic: bool) -> str | None:
    """One sentence naming the checklist the category uses, its kill items and what it fits."""
    row = _row(category)
    if row is None or not kill_ids:
        return None
    tpl = _doc()["templates"]
    kills = ", ".join(kill_ids)
    if row.get("alternative") and row.get("not_for") and not generic:
        return tpl["notice"].format(category=category, kills=kills, fits=row["fits"],
                                    not_for=row["not_for"], alternative=row["alternative"])
    return tpl["notice_generic"].format(category=category, kills=kills, fits=row["fits"])


def kill_hint(category: str, item_id: str) -> str | None:
    """When a kill item fired: the category whose checklist fits a near-miss issue, if any."""
    row = _row(category)
    if row is None or not row.get("alternative") or not row.get("not_for"):
        return None
    return _doc()["templates"]["kill_fired"].format(item=item_id, category=category,
                                                    not_for=row["not_for"], alternative=row["alternative"])


def guide_lines(family: str) -> list[str]:
    """Category guide rows for one family (`categories` topic)."""
    tpl = _doc().get("templates") or {}
    rows = []
    for cat, row in (_doc().get("categories") or {}).items():
        if not cat.startswith(f"{family}.") or not isinstance(row, dict) or not row.get("fits"):
            continue
        if row.get("alternative") and row.get("not_for"):
            rows.append(tpl["guide_row"].format(category=cat, fits=row["fits"], not_for=row["not_for"],
                                                alternative=row["alternative"]))
        else:
            rows.append(tpl["guide_row_generic"].format(category=cat, fits=row["fits"]))
    return [tpl["guide_header"], *rows] if rows else []
