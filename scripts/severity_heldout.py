"""Held-out agreement of the severity engine, before and after a change.

Runs `tests/fixtures/severity/heldout.yaml` through the engine at a git revision (`--before`, default
f18aa1f, the engine before reviewer-first) and through the working tree, with the classifications an
honest reviewer would pick, and prints strict and scale-adjusted agreement with the published
severity. With `--claimed` the published severity is also passed as the reviewer's claimed_severity
with a reason, which is the client path after 2026-10-27 (RV1: one step stands).

    uv run python scripts/severity_heldout.py [--before f18aa1f] [--claimed]
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import types
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "severity" / "heldout.yaml"
ENGINE = "src/soken_review/engine/severity.py"
_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_TOP = {"c4": "High"}   # scales without a Critical level


def _load_engine_at(rev: str) -> types.ModuleType:
    src = subprocess.run(["git", "-C", str(ROOT), "show", f"{rev}:{ENGINE}"], check=True,
                         capture_output=True, text=True).stdout
    spec = importlib.util.spec_from_loader(f"severity_{rev}", loader=None)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules[mod.__name__] = mod              # dataclasses resolve annotations through sys.modules
    exec(compile(src, f"<{rev}:{ENGINE}>", "exec"), mod.__dict__)  # noqa: S102  (our own file at a git revision)
    return mod


def _load_engine_tree() -> types.ModuleType:
    sys.path.insert(0, str(ROOT / "src"))
    from soken_review.engine import severity
    return severity


def run(engine: types.ModuleType, cases: list[dict], claimed: bool) -> list[dict]:
    rows = []
    for c in cases:
        kw = {}
        if claimed and "claimed_severity" in engine.SeverityContext.__dataclass_fields__:
            kw = {"claimed_severity": c["published"],
                  "claimed_reason": "published severity of the source report, recorded for the held-out run"}
        ctx = engine.SeverityContext(phase="submit", **kw)
        try:
            r = engine.compute_severity(dict(c["matrix"]), "submit", ctx)
            sev, rule = r.severity, r.severity_rule
            if getattr(r, "confirm_needed", False):
                sev, rule = r.computed, rule + " (E_SEVERITY_CONFIRM)"
        except (KeyError, ValueError) as e:
            sev, rule = "n/a", f"unsupported: {e}"
        top = _TOP.get(c["scale"])
        adjusted = sev
        if top and sev in _RANK and _RANK[sev] > _RANK[top]:
            adjusted = top
        rows.append({"id": c["id"], "published": c["published"], "severity": sev, "adjusted": adjusted,
                     "strict": sev == c["published"], "scaled": adjusted == c["published"],
                     "within_one": sev in _RANK and abs(_RANK[sev] - _RANK[c["published"]]) <= 1, "rule": rule})
    return rows


def summary(label: str, rows: list[dict]) -> str:
    n = len(rows)
    s = sum(r["strict"] for r in rows)
    a = sum(r["scaled"] for r in rows)
    w = sum(r["within_one"] for r in rows)
    return f"{label}: strict {s}/{n}, scale-adjusted {a}/{n}, within one step {w}/{n}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", default="f18aa1f")
    ap.add_argument("--claimed", action="store_true")
    ap.add_argument("--rows", action="store_true", help="print every case")
    args = ap.parse_args()
    cases = yaml.safe_load(FIXTURE.read_text())["cases"]
    before = run(_load_engine_at(args.before), cases, args.claimed)
    after = run(_load_engine_tree(), cases, args.claimed)
    print(f"held-out cases: {len(cases)}  (claimed={'published' if args.claimed else 'none'})")
    print(summary(f"before {args.before}", before))
    print(summary("after  worktree", after))
    if args.rows:
        for b, a in zip(before, after, strict=True):
            mark = "" if b["severity"] == a["severity"] else "  <- changed"
            print(f"{a['id']:28} published {a['published']:13} before {b['severity']:13} after {a['severity']:13} {a['rule']}{mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
