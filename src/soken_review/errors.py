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
        if code == "E_JOB_NOT_READY" and "eta_text" not in self.fields:
            # Most callers know only the state, and sent eta 0: "eta 0 s" read as "nearly done" while a
            # Solana build had ten minutes left (MetaDAO blind run 2026-10-31). An unknown ETA says so.
            eta = self.fields.get("eta_s")
            text = f"about {int(eta)} s left" if isinstance(eta, (int, float)) and eta > 0 \
                else "review_status shows the time left"
            self.fields = {**self.fields, "eta_text": text}
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
