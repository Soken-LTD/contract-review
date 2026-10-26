"""Solana repo job proof: fetch -> build -> analyze -> map on a repo subdir, the worker's own path.

    uv run python scripts/e2e_solana_repo_map.py [name ...]
    uv run python scripts/e2e_solana_repo_map.py --versions     # image versions the targets need

Per target, through the functions worker/solana_steps.py runs for a repo job:
  1. fetch.fetch_source with repo_url, commit and subdir: the subdir is the pin (review scope), the
     repo tree around it is kept for the build (fetch.attach_build_workspace)
  2. build with solana_steps.build_files (pinned scope inside its Cargo workspace), the image of the
     program's Solana version or the nearest published one; deps fetched online, build offline
  3. analyze: clippy and cargo-audit on the built tree, soken-solana-rules on the pin; without a build
     the source-only path (analyze_source_only)
  4. map: build_map with the parsed Solana semantic layer
Prints one JSON row per target: build status, image, nSLOC, functions, entries, leads and rule ids.
A target states what it must reach (`expect`); the run fails when any row differs.

Needs the same environment as scripts/e2e_solana_adapter.py: SOKEN_IMAGE_GIT_FETCH,
SOKEN_IMAGE_SOLANA_BUILD_<x_y_z>, SOKEN_IMAGE_SOLANA_ANALYZE, SOKEN_SANDBOX_RUNTIME, the solana egress
network and a fetched RustSec snapshot. SOKEN_SOLANA_DIRECT must be unset.
"""

from __future__ import annotations

import collections
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.solana import SolanaAdapter
from soken_review.adapters.solana.analyze import analyze_source_only
from soken_review.adapters.solana.build import sandbox_layout
from soken_review.adapters.solana.fetch import fetch_source
from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories
from soken_review.worker.solana_steps import build_files, pin_nsloc

TARGETS: list[dict[str, Any]] = [
    # Lock & Loan locker (blind matrix 2026-10-25): Anchor 0.31.1 / solana-program 2.2.1 workspace,
    # path dependency merkle-verify outside the subdir, committed .so fixture (untrusted, never tier A).
    {"name": "lock-and-loan", "repo_url": "https://github.com/fraserbrownirl/agent-loans",
     "commit": "4f400beb3a7b912888fba214d8553f5368eab18c", "subdir": "programs/locker",
     "address": "Fvm8Z25vd1Yauj6GB4jsrW7jJyUdNYGeDCWYqcuTtDek", "versions": ["3.1.8"],
     "expect": {"build": "ok", "min_functions": 50, "min_entries": 10, "min_leads": 1, "min_nsloc": 1000}},
]


def run(t: dict[str, Any], root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"name": t["name"]}
    t0 = time.time()
    job = {"address": t["address"], "repo_url": t["repo_url"], "commit": t["commit"], "subdir": t["subdir"],
           "work_dir": str(root / t["name"])}
    bundles = fetch_source(job, {})
    if not bundles or not bundles[0].candidates:
        return {**out, "stage": "fetch", "ok": False}
    cand = bundles[0].candidates[0]
    scope = dict(cand.files)
    out.update(pin_files=len(scope), workspace_files=len(cand._full_tree or {}),
               library_name=cand.settings.get("library_name"), fetch_s=round(time.time() - t0))

    with tempfile.TemporaryDirectory() as tmp:
        ws = Path(tmp) / "build_workspace.json"
        if cand._full_tree:
            ws.write_text(json.dumps({"subdir": cand.settings["subdir"], "files": cand._full_tree}))
        settings = dict(cand.settings)
        build_cand = Candidate(provider=cand.provider, files=build_files(scope, ws, settings), sha256=cand.sha256,
                               language=cand.language, compiler=cand.compiler, settings=settings,
                               std_json_input=None, entry_contract=None, source_url=cand.source_url,
                               fetched_at=cand.fetched_at)
    t1 = time.time()
    adapter = SolanaAdapter()
    r = adapter.build(build_cand)
    layout = sandbox_layout(Path(r.work_dir)) if r.work_dir else None
    out.update(build=r.status, build_reason=r.reason, build_s=round(time.time() - t1),
               untrusted=build_cand.untrusted_inputs,
               image=(layout or {}).get("image"), image_version=(layout or {}).get("image_version"),
               image_match=(layout or {}).get("image_match"), program_version=(layout or {}).get("version"))
    if r.status != "ok":
        out["stderr"] = (r.stderr_head or "")[-1500:]

    if r.status == "ok":
        analysis_cand = Candidate(provider=cand.provider, files=scope, sha256=cand.sha256, language=cand.language,
                                  compiler=cand.compiler, settings=settings, std_json_input=None,
                                  entry_contract=None)
        leads, static_map, _ = adapter.analyze(BuildResult(candidate=analysis_cand, status="ok",
                                                           nsloc=r.nsloc, work_dir=r.work_dir))
    else:
        leads, static_map, _ = analyze_source_only(scope, f"build_{r.reason or 'failed'}")
    tools = static_map.get("tools") or {}
    out.update(analyze=static_map.get("status"), degraded_reasons=static_map.get("degraded_reasons"),
               clippy=[(tools.get("clippy") or {}).get(k) for k in ("status", "reason")]
               + [len((tools.get("clippy") or {}).get("items") or [])],
               clippy_tail=(tools.get("clippy") or {}).get("stderr_tail"),
               cargo_audit=[(tools.get("cargo_audit") or {}).get(k) for k in ("status", "reason", "vulnerabilities")])

    pin_text = {p: c if c.endswith("\n") else c + "\n" for p, c in scope.items()}
    art = build_map(pin_text, None, list(family_categories("solana", "solana")), build_ok=r.status == "ok",
                    parsed_family="solana")
    sem = art.doc.get("semantic") or {}
    fns = sem.get("functions") or []
    nsloc = pin_nsloc(scope)
    rule_ids = collections.Counter(lead["rule_id"] for lead in leads)
    out.update(map_status=art.status, semantic=bool(sem), nsloc=nsloc, functions=len(fns),
               entries=sum(1 for f in fns if f["is_entry"]),
               units=dict(collections.Counter(u["kind"] for u in sem.get("units") or [])),
               leads=len(leads), rule_ids=dict(rule_ids.most_common()))
    exp = t["expect"]
    checks = {
        "build": r.status == exp["build"],
        "functions": len(fns) >= exp["min_functions"],
        "entries": out["entries"] >= exp["min_entries"],
        "leads": len(leads) >= exp["min_leads"],
        "nsloc": nsloc >= exp["min_nsloc"],
    }
    out.update(checks=checks, ok=all(checks.values()))
    return out


def main(argv: list[str]) -> int:
    if argv[:1] == ["--versions"]:
        print(" ".join(sorted({v for t in TARGETS for v in t["versions"]})))
        return 0
    if os.environ.get("SOKEN_SOLANA_DIRECT") == "1":
        print("SOKEN_SOLANA_DIRECT must be unset: this run proves the sandbox path", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1] / ".sbx" / "solana-repo-e2e"
    root.mkdir(parents=True, exist_ok=True)
    rows = []
    for t in TARGETS:
        if argv and t["name"] not in argv:
            continue
        try:
            row = run(t, root)
        except Exception as exc:  # noqa: BLE001 - one target's crash is that target's failed row
            row = {"name": t["name"], "stage": "crash", "error": repr(exc)[:500], "ok": False}
        print(json.dumps(row), flush=True)
        rows.append(row)
    return 0 if rows and all(r.get("ok") for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
