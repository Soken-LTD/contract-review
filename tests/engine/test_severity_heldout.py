"""Held-out calibration gate (tests/fixtures/severity/heldout.yaml, 40 public findings, none from the
2026-10-26 matrix targets). Numbers measured 2026-10-27 with scripts/severity_heldout.py:

  matrix only          before f18aa1f: strict 15/40, scale-adjusted 17/40, within one step 37/40
                       after:          strict 16/40, scale-adjusted 18/40, within one step 37/40
  with the reviewer's  before:         strict 15/40 (claimed_severity was advisory)
  claimed_severity     after:          strict 32/40 (5 held by K3/K6/K7 caps, 3 confirm round trips)

The matrix alone brackets the published severity within one step on 37 of 40 but names the exact
cell on 16; the reviewer-first path prints the published value on 32. These thresholds hold the
line: a change that lowers any of them needs a new measurement in the fixture header.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from soken_review.engine.severity import SeverityContext, compute_severity

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "severity" / "heldout.yaml"
_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_TOP = {"c4": "High"}
_REASON = "published severity of the source report, recorded for the held-out run"


def _cases() -> list[dict]:
    return yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))["cases"]


def _score(claimed: bool) -> tuple[int, int, int, int]:
    strict = scaled = within = n = 0
    for c in _cases():
        kw = {"claimed_severity": c["published"], "claimed_reason": _REASON} if claimed else {}
        r = compute_severity(dict(c["matrix"]), "submit", SeverityContext(**kw))
        sev = r.computed if r.confirm_needed else r.severity
        top = _TOP.get(c["scale"])
        adj = top if top and _RANK[sev] > _RANK[top] else sev
        n += 1
        strict += sev == c["published"]
        scaled += adj == c["published"]
        within += abs(_RANK[sev] - _RANK[c["published"]]) <= 1
    return n, strict, scaled, within


def test_fixture_is_large_enough_and_excludes_the_matrix_targets():
    cases = _cases()
    assert len(cases) >= 20
    banned = ("lock", "loan", "forton", "ftmaster", "crs", "anttime", "apyee")
    for c in cases:
        assert not any(b in c["id"].lower() for b in banned), c["id"]
        assert c["published"] in _RANK and set(c["matrix"]) == {
            "impact_class", "magnitude", "trigger", "precondition", "reversibility"}


def test_matrix_only_agreement_holds_the_measured_line():
    n, strict, scaled, within = _score(claimed=False)
    assert n == 40
    assert strict >= 16 and scaled >= 18 and within >= 37, (strict, scaled, within)


def test_reviewer_first_agreement_holds_the_measured_line():
    _, strict, scaled, within = _score(claimed=True)
    assert strict >= 32 and within >= 37, (strict, scaled, within)


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["id"])
def test_every_case_computes_and_the_reviewer_is_never_overruled_silently(case):
    r = compute_severity(dict(case["matrix"]), "submit",
                         SeverityContext(claimed_severity=case["published"], claimed_reason=_REASON))
    if r.severity != case["published"]:
        # the client sees one of: a named cap (set_by cap, rule ids) or a confirmation round trip
        assert r.confirm_needed or (r.set_by == "cap" and r.caps_applied), (case["id"], r)
