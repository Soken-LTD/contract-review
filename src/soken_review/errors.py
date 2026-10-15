"""Errors from `contract/errors.yaml` (03 section 7). Server text is template only."""

from __future__ import annotations

import string
from typing import Any

from .contract import load_errors

_CATALOG = load_errors()


class ReviewError(Exception):
    """A catalogued error. `fields` fill the `what` and `fix` templates; values are data."""

    def __init__(self, code: str, **fields: Any) -> None:
        if code not in _CATALOG:
            raise KeyError(f"{code} is not in contract/errors.yaml")
        self.code = code
        self.fields = fields
        self.row = _CATALOG[code]
        super().__init__(code)

    @property
    def channel(self) -> str:
        return self.row["channel"]

    def envelope(self) -> dict[str, str]:
        out = {"code": self.code, "what": _fill(self.row["what"], self.fields), "fix": _fill(self.row["fix"], self.fields)}
        if "field" in self.fields:
            out["field"] = str(self.fields["field"])
        return out


def _fill(template: str, fields: dict[str, Any]) -> str:
    names = {name for _, name, _, _ in string.Formatter().parse(template) if name}
    return template.format(**{name: fields.get(name, "") for name in names})
