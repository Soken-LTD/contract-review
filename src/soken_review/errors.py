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
        if code == "E_TEXT_GATE" and fields.get("rule") and "rule_text" not in fields:
            # Every text-gate rejection prints the rule text and the allowed rewording
            # (text_gate.yaml rule_help), whichever tool raised it.
            from .engine.text_gate import rule_help

            text, reword = rule_help(str(fields["rule"]))
            self.fields = {**fields, "rule_text": text, "reword": reword}
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
