"""Corpus driver (10 2.4, W0 agents item): push EVM corpus cases through the local worker and
report per-case recall of the ground truth from analyzer leads alone (no LLM, no paid calls).

    uv run python scripts/eval_driver.py [--cases evm-contest-0004 ...] [--max 8] [--dry-run]

For each `dev` EVM case: the import closure of the GT files is read from the checked-out tree
(.sbx/corpus-src/<case_id>, `soken-eval corpus fetch`), sent as `source.kind = files` (inline
limits apply: 20 files, 60k chars each, 200k total), the in-process Supervisor runs
fetch -> build (solc in the sandbox) -> analyze (Slither, Aderyn) -> ready, then every
`review_leads` page is read through the MCP client. A GT bug counts as found when a lead in
the same file overlaps its root_cause_lines or related_lines within 3 lines (10 3.2 rule 1,
location only: leads carry no reviewed category). Slither leads often span a whole function, so
the driver also reports recall from leads of at most 10 lines (`recall_narrow`). Cases whose closure does not fit the inline
limits or imports code that is not in the tree (dependencies are not vendored) are listed as
skipped with the reason.

Needs Docker (Postgres container `soken-pg-evaldrv` on 127.0.0.1:5436, analyze image via
SOKEN_IMAGE_EVM_ANALYZE).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import posixpath
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[1]
DSN = os.environ.get("SOKEN_EVAL_DSN", "postgresql://soken:soken@127.0.0.1:5436/soken")
PG_CONTAINER = "soken-pg-evaldrv"
MAX_FILES, MAX_FILE_CHARS, MAX_TOTAL_CHARS = 20, 60_000, 200_000   # review_start inline limits
IMPORT = re.compile(r"^\s*import\s+(?:[^;\"']*?\bfrom\s+)?[\"']([^\"']+)[\"']", re.MULTILINE)
PROJECT_MARKERS = ("foundry.toml", "hardhat.config.ts", "hardhat.config.js", "remappings.txt", "package.json")
WINDOW = 3     # 10 3.2: overlap within 3 lines
NARROW = 10    # a lead over more lines is a function-level pointer; reported separately
TERMINAL = {"ready", "failed", "insufficient_source", "expired", "deleted"}


# ── import closure ────────────────────────────────────────────────────────────


def project_root(tree: Path, rel: str) -> Path:
    d = (tree / rel).parent
    while d != tree and not any((d / m).exists() for m in PROJECT_MARKERS):
        d = d.parent
    return d


def remappings(root: Path) -> list[tuple[str, str]]:
    rows: list[str] = []
    if (root / "remappings.txt").is_file():
        rows += (root / "remappings.txt").read_text().splitlines()
    toml = root / "foundry.toml"
    if toml.is_file():
        block = re.search(r"remappings\s*=\s*\[(.*?)\]", toml.read_text(), re.DOTALL)
        if block:
            rows += re.findall(r"[\"']([^\"']+)[\"']", block.group(1))
    out = []
    for row in rows:
        row = row.split(":", 1)[-1].strip() if ":" in row.split("=", 1)[0] else row.strip()
        if "=" in row and not row.startswith("#"):
            a, b = row.split("=", 1)
            out.append((a.strip(), b.strip()))
    return sorted(out, key=lambda r: -len(r[0]))


def resolve(tree: Path, importer: str, spec: str, remaps: list[tuple[str, str]], root: Path) -> str | None:
    cands: list[Path] = []
    if spec.startswith("."):
        cands.append(tree / posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec)))
    else:
        for prefix, target in remaps:
            if spec.startswith(prefix):
                cands.append(root / (target + spec[len(prefix):]))
                break
        cands += [root / spec, root / "node_modules" / spec, tree / spec]
    for c in cands:
        try:
            r = c.resolve()
        except OSError:
            continue
        if r.is_file() and r.is_relative_to(tree.resolve()):
            return r.relative_to(tree.resolve()).as_posix()
    return None


def closure(tree: Path, roots: list[str]) -> tuple[dict[str, str], list[str], list[str]]:
    """(files, remappings for non-relative imports, unresolved imports)."""
    files: dict[str, str] = {}
    remap: dict[str, str] = {}
    missing: list[str] = []
    todo = list(roots)
    while todo:
        rel = todo.pop()
        if rel in files:
            continue
        text = (tree / rel).read_text(errors="replace")
        files[rel] = text
        root = project_root(tree, rel)
        remaps = remappings(root)
        for spec in IMPORT.findall(text):
            dep = resolve(tree, rel, spec, remaps, root)
            if dep is None:
                missing.append(f"{rel}: {spec}")
                continue
            if not spec.startswith(".") and spec != dep:
                remap[spec] = dep
            todo.append(dep)
    return files, [f"{k}={v}" for k, v in sorted(remap.items())], missing


def build_input(case: dict[str, Any], tree: Path) -> tuple[list[dict[str, str]] | None, str]:
    roots = sorted({r["file"] for g in case["ground_truth"] for r in g["root_cause_lines"]})
    files, remap, missing = closure(tree, roots)
    if missing:
        return None, f"imports not in the tree ({len(missing)}), e.g. {missing[0]}"
    inline = [{"path": p, "content": c} for p, c in sorted(files.items())]
    toml = project_root(tree, roots[0]) / "foundry.toml"
    if toml.is_file() and not toml.is_symlink():
        # optimizer / viaIR / solc_version as the project builds (adapters/evm/files.py)
        inline.append({"path": "foundry.toml", "content": toml.read_text()})
    if remap:
        inline.append({"path": "remappings.txt", "content": "\n".join(remap) + "\n"})
    total = sum(len(f["content"]) for f in inline)
    big = [f["path"] for f in inline if len(f["content"]) > MAX_FILE_CHARS]
    if len(inline) > MAX_FILES or total > MAX_TOTAL_CHARS or big:
        return None, f"over inline limits: {len(inline)} files, {total} chars, oversized {big[:2]}"
    return inline, f"{len(inline)} files, {total} chars"


# ── repo route ──────────────────────────────────────────────────────────────


def repo_source(case: dict[str, Any]) -> dict[str, Any]:
    """`review_start` source.kind=repo payload from a case's pinned repo+commit (05 4.2 step 6).

    The repo route clones + builds the whole project in the sandbox, so it carries the cases
    whose import closure is over the files-mode inline caps (the ~11 big contest repos). A case
    "passes the repo route" when it reaches ``ready`` with build_result.json
    ``b4_source == "forge_b4"`` (forge resolved deps+remappings and our solc recompiled); a case
    that reaches ready via the B3 fallback (no foundry.toml) is counted separately, and a
    ``b4_rejected`` build is diagnosed from ``b4_detail``/``forge_rc``/``forge_stderr_head``.
    The commit (40-hex sha, validated supervisor-side) pins the tree; subdir handles monorepos.
    """
    src = case["source"]
    out: dict[str, Any] = {"kind": "repo", "repo_url": src["repo"]}
    if src.get("commit"):
        out["commit"] = src["commit"]
    if src.get("subdir"):
        out["subdir"] = src["subdir"]
    return out


# ── recall ────────────────────────────────────────────────────────────────────


LEAD_LINE = re.compile(r"^(?P<id>\S+) (?P<state>\S+) (?P<cat>\S+) (?P<sev>\S+) (?P<file>.+):(?P<a>\d+)-(?P<b>\d+)")


def matched(gt: dict[str, Any], leads: list[dict[str, Any]], narrow: bool = False) -> list[str]:
    hits = []
    if narrow:
        leads = [lead for lead in leads if lead["b"] - lead["a"] + 1 <= NARROW]
    for rng in gt["root_cause_lines"] + (gt.get("related_lines") or []):
        for lead in leads:
            if lead["file"] == rng["file"] and lead["a"] <= rng["end"] + WINDOW and lead["b"] >= rng["start"] - WINDOW:
                hits.append(lead["id"])
    return sorted(set(hits))


# ── local stack ───────────────────────────────────────────────────────────────


def start_host_postgres() -> None:
    """Homebrew Postgres in .sbx/evaldrv/pgdata (when the Docker VM has no room for a container)."""
    data = REPO / ".sbx" / "evaldrv" / "pgdata"
    if not (data / "PG_VERSION").exists():
        data.mkdir(parents=True, exist_ok=True)
        subprocess.run(["initdb", "-D", str(data), "-U", "soken", "--auth=trust"], check=True, capture_output=True)
    status = subprocess.run(["pg_ctl", "-D", str(data), "status"], capture_output=True, check=False)
    if status.returncode != 0:
        subprocess.run(["pg_ctl", "-D", str(data), "-l", str(data.parent / "pg.log"), "-w",
                        "-o", "-p 5436 -k /tmp -c listen_addresses=127.0.0.1", "start"], check=True)
    subprocess.run(["createdb", "-h", "127.0.0.1", "-p", "5436", "-U", "soken", "soken"],
                   capture_output=True, check=False)


def start_postgres() -> None:
    state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", PG_CONTAINER],
                           capture_output=True, text=True, check=False)
    if state.stdout.strip() != "true":
        subprocess.run(["docker", "rm", "-f", PG_CONTAINER], capture_output=True, check=False)
        subprocess.run(["docker", "run", "-d", "--name", PG_CONTAINER, "-e", "POSTGRES_USER=soken",
                        "-e", "POSTGRES_PASSWORD=soken", "-e", "POSTGRES_DB=soken",
                        "-p", "127.0.0.1:5436:5432", "postgres:16"], check=True, capture_output=True)
    for _ in range(60):
        ok = subprocess.run(["docker", "exec", PG_CONTAINER, "pg_isready", "-U", "soken"],
                            capture_output=True, check=False)
        if ok.returncode == 0:
            time.sleep(1)
            return
        time.sleep(1)
    raise RuntimeError("postgres not ready")


async def drive(cases: list[tuple[dict[str, Any], str, Any]], timeout_s: int) -> list[dict[str, Any]]:
    import psycopg_pool
    from mcp import Client

    import soken_review.tools  # noqa: F401  registers handlers
    from soken_review.db import migrate
    from soken_review.db import pool as pool_mod
    from soken_review.server import SokenServer
    from soken_review.tools import read as read_mod
    from soken_review.tools import start_status
    from soken_review.tools.context_pg import PgJobContext
    from soken_review.worker.supervisor import Supervisor

    pin_root = REPO / ".sbx" / "evaldrv" / "pins"
    pin_root.mkdir(parents=True, exist_ok=True)
    await migrate.run_migrations(DSN)
    apool = psycopg_pool.AsyncConnectionPool(DSN, min_size=2, max_size=8, open=False)
    await apool.open()
    spool = psycopg_pool.ConnectionPool(DSN, min_size=1, max_size=4, open=False)
    spool.open()
    start_status.set_pool(apool)
    pool_mod.set_pool(apool)
    read_mod.set_context(PgJobContext(spool, pin_root))
    worker = asyncio.create_task(Supervisor(apool, pin_root, host_name="evaldrv-1").run())
    results = []
    try:
        async with Client(SokenServer()) as client:
            for case, mode, payload in cases:
                results.append(await run_case(client, case, mode, payload, timeout_s, pin_root))
                print(json.dumps(results[-1]), flush=True)
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
        await apool.close()
        spool.close()
    return results


def _json(result: Any) -> dict[str, Any]:
    if getattr(result, "structured_content", None):
        return result.structured_content
    return json.loads(result.content[0].text)


async def run_case(client: Any, case: dict[str, Any], mode: str, payload: Any, timeout_s: int,
                   pin_root: Path) -> dict[str, Any]:
    t0 = time.monotonic()
    out: dict[str, Any] = {"case_id": case["case_id"], "gt": len(case["ground_truth"]), "mode": mode}
    source = payload if mode == "repo" else {"kind": "files", "language": "solidity", "files": payload}
    start = _json(await client.call_tool("review_start", {
        "source": source,
        "requester_role": "third_party_public_code",
    }))
    if not start.get("accepted"):
        return {**out, "outcome": "rejected", "detail": start.get("errors")}
    job_id = start["job_id"]
    out["job_id"] = job_id[-8:]
    state = start["state"]
    while state not in TERMINAL and time.monotonic() - t0 < timeout_s:
        await asyncio.sleep(2)
        state = _json(await client.call_tool("review_status", {"job_id": job_id})).get("state", state)
    out["state"] = state
    out["wall_s"] = round(time.monotonic() - t0, 1)
    work = pin_root.parent / "work" / job_id
    build = json.loads((work / "build_result.json").read_text()) if (work / "build_result.json").exists() else {}
    out["build"] = build.get("status")
    if build.get("status") != "ok":
        out["build_reason"] = (build.get("reason"), (build.get("stderr_head") or "")[:240])
    if mode == "repo":
        # Repo-route grade (infra criteria): ready + b4_source == "forge_b4" is a forge (B4)
        # build; ready without it is the B3 fallback (counted separately); b4_rejected is read
        # from b4_detail/forge_rc/forge_stderr_head to tell sources_differ from forge_failed.
        out["b4_source"] = build.get("b4_source")
        out["repo_route_ok"] = state == "ready" and build.get("b4_source") == "forge_b4"
        if build.get("b4_rejected"):
            out["b4_rejected"] = (build.get("b4_rejected"), build.get("b4_detail"),
                                  build.get("forge_rc"), (build.get("forge_stderr_head") or "")[:200])
    if state != "ready":
        return {**out, "outcome": "not_ready"}
    leads: list[dict[str, Any]] = []
    cursor = None
    while True:
        args: dict[str, Any] = {"job_id": job_id, "status": "all", "page_size": 30}
        if cursor:
            args["cursor"] = cursor
        res = await client.call_tool("review_leads", args)
        text = res.content[0].text
        if res.is_error:
            return {**out, "outcome": "leads_error", "detail": text[:200]}
        cursor = None
        for line in text.splitlines():
            m = LEAD_LINE.match(line)
            if m:
                leads.append({"id": m["id"], "file": m["file"], "a": int(m["a"]), "b": int(m["b"]), "cat": m["cat"]})
            elif line.startswith("next_cursor "):
                cursor = line.split(" ", 1)[1].strip()
        if not cursor:
            break
    per_gt = {g["gt_id"]: matched(g, leads) for g in case["ground_truth"]}
    narrow = {g["gt_id"]: matched(g, leads, narrow=True) for g in case["ground_truth"]}
    found = sum(1 for v in per_gt.values() if v)
    found_narrow = sum(1 for v in narrow.values() if v)
    return {**out, "outcome": "ready", "leads": len(leads), "found": found,
            "recall": round(found / len(per_gt), 3), "found_narrow": found_narrow,
            "recall_narrow": round(found_narrow / len(per_gt), 3), "matches": per_gt}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", nargs="*", help="case ids (default: every dev EVM case that fits)")
    ap.add_argument("--max", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true", help="only report which cases fit the files input")
    ap.add_argument("--repo", choices=["off", "auto", "only"], default="off",
                    help="off: inline files only (default); auto: repo route for cases over the "
                         "inline limits; only: repo route (source.kind=repo) for every case")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--host-pg", action="store_true", help="Homebrew Postgres instead of a Docker container")
    ap.add_argument("--out", type=Path, default=REPO / ".sbx" / "evaldrv" / "results.json")
    args = ap.parse_args()

    sys.path.insert(0, str(REPO / "src"))
    from soken_review.evals.sources import TREES_DIR, case_tree

    picked: list[tuple[dict[str, Any], str, Any]] = []
    for path in sorted((REPO / "evals" / "corpus" / "evm").glob("evm-*/case.yaml")):
        case = yaml.safe_load(path.read_text())
        if case["split"] != "dev" or (args.cases and case["case_id"] not in args.cases):
            continue
        if args.repo == "only":
            # Repo route for every case: no local checkout needed, the sandbox clones + builds.
            payload = repo_source(case)
            print(f"{case['case_id']}: repo {payload['repo_url']}@{(payload.get('commit') or 'HEAD')[:10]}")
            if len(picked) < args.max:
                picked.append((case, "repo", payload))
            continue
        tree = case_tree(case, TREES_DIR)
        if not tree.exists():
            print(f"{case['case_id']}: skipped, no checkout (soken-eval corpus fetch)")
            continue
        inline, why = build_input(case, tree)
        if inline:
            print(f"{case['case_id']}: fits, {why}")
            mode, payload = "files", inline
        elif args.repo == "auto":
            # Over the inline caps but the repo route can carry it: clone + build the project.
            payload = repo_source(case)
            print(f"{case['case_id']}: repo ({why}) {payload['repo_url']}@{(payload.get('commit') or 'HEAD')[:10]}")
            mode = "repo"
        else:
            print(f"{case['case_id']}: skipped, {why}")
            continue
        if len(picked) < args.max:
            picked.append((case, mode, payload))
    if args.dry_run or not picked:
        return 0
    start_host_postgres() if args.host_pg else start_postgres()
    results = asyncio.run(drive(picked, args.timeout))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2))
    repo_cases = [r for r in results if r.get("mode") == "repo"]
    if repo_cases:
        forge = sum(1 for r in repo_cases if r.get("repo_route_ok"))
        ready_any = sum(1 for r in repo_cases if r.get("state") == "ready")
        print(f"repo-route cases {len(repo_cases)}, ready via forge_b4 {forge}, ready (any) {ready_any}")
    ready = [r for r in results if r.get("outcome") == "ready"]
    gts = sum(r["gt"] for r in ready)
    found = sum(r["found"] for r in ready)
    narrow = sum(r["found_narrow"] for r in ready)
    print(f"cases {len(results)}, ready {len(ready)}, GT {gts}, found {found} (recall {found / gts:.3f}), "
          f"found by leads of <= {NARROW} lines {narrow} (recall {narrow / gts:.3f})"
          if gts else f"cases {len(results)}, ready {len(ready)}")
    return 0 if len(ready) == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
