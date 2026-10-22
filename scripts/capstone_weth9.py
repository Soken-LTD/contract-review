#!/usr/bin/env python3
"""Capstone: a LIVE finalized, branded SOKEN report for WETH9, produced end-to-end on the server.

Uses the real product tools (no seed): create a ready job over the already fetched/built/analyzed
WETH9 case, submit one honest Informational reentrancy finding on the Slither lead, finalize,
assemble report.json, and render it through the soken-render image.

    SOKEN_DATABASE_URL=... SOKEN_PIN_ROOT=... RENDER_IMAGE=soken/soken-render:test \
        .venv/bin/python scripts/capstone_weth9.py /abs/path/to/.sbx/cases/weth9
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import psycopg_pool

from soken_review.db.job_repo import JobRepo, new_job_id
from soken_review.db.migrate import run_migrations
from soken_review.pinning.store import PinnedSource
from soken_review.report.assemble import assemble_report
from soken_review.tools import finalize as finalize_mod
from soken_review.tools import report as report_mod
from soken_review.tools import submit as submit_mod
from soken_review.tools.context import MemoryJobContext
from soken_review.tools.report import principal_of

DSN = os.environ["SOKEN_DATABASE_URL"]
PIN_ROOT = Path(os.environ["SOKEN_PIN_ROOT"]).resolve()
RENDER_IMAGE = os.environ.get("RENDER_IMAGE", "soken/soken-render:test")
WETH9_ADDR = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"


async def main() -> int:
    case = Path(sys.argv[1]).resolve()
    src = (case / "sourcify_0" / "WETH9.sol").read_bytes()
    leads = json.loads((case / "leads.json").read_text())
    lead = leads[0]                       # LEAD-0001 evm.reentrancy WETH9.sol:41-42
    lines = src.decode().splitlines()
    quote_text = "\n".join(lines[lead["start"] - 1:lead["end"]])   # exact pinned lines

    PIN_ROOT.mkdir(parents=True, exist_ok=True)
    await run_migrations(DSN)
    pool = psycopg_pool.AsyncConnectionPool(DSN, min_size=1, max_size=4, open=False)
    await pool.open()
    for mod in (submit_mod, finalize_mod, report_mod):
        mod.set_pool(pool)
    ctx = MemoryJobContext(PIN_ROOT)
    submit_mod.set_context(ctx)
    finalize_mod.set_context(ctx)

    jid = new_job_id()
    async with pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.create(
            job_id=jid, principal_key=principal_of(jid), surface="plugin", state="queued",
            requester_role="third_party_public_code", source_kind="deployed",
            source_args={"chain": "ethereum", "address": WETH9_ADDR}, has_deployment=True,
            chain="evm", chain_id=1, address=WETH9_ADDR,
        )
        await conn.execute("update jobs set state='ready', tier='B', source_pin=%s where job_id=%s",
                           ("0" * 64, jid))

    # Pin the reviewed source under the lead's file name, and place leads.json where assemble reads it.
    PinnedSource.from_files({lead["file"]: src}).persist(PIN_ROOT, jid)
    (PIN_ROOT / jid).mkdir(parents=True, exist_ok=True)
    (PIN_ROOT / jid / "leads.json").write_text(json.dumps(leads))
    work = PIN_ROOT.parent / "work" / jid
    work.mkdir(parents=True, exist_ok=True)
    (work / "chain_state.json").write_text(json.dumps({"address": WETH9_ADDR, "chain": "ethereum"}))

    async with pool.connection() as conn, conn.transaction():
        await conn.execute(
            """insert into leads (job_id, lead_id, rule_id, tools, category, category_family,
               analyzer_severity_raw, severity_norm, path, start_line, end_line, state)
               values (%s,%s,%s,%s,%s,'evm',%s,%s,%s,%s,%s,'open')""",
            (jid, lead["id"], lead["rule_id"], lead["tools"], lead["category"],
             lead["analyzer_severity_raw"], lead["severity_norm"], lead["file"],
             lead["start"], lead["end"]),
        )

    # One honest Informational finding: Slither flags reentrancy, but withdraw applies CEI and uses
    # .transfer (2300 gas), so it is not exploitable. impact_class best_practice -> Informational.
    sub = {
        "job_id": jid, "draft_key": "weth9-reentrancy-note", "category": "evm.reentrancy",
        "quotes": [{"file": lead["file"], "start": lead["start"], "end": lead["end"],
                    "role": "location", "text": quote_text}],
        "matrix": {"impact_class": "best_practice", "magnitude": "unbounded", "trigger": "anyone",
                   "precondition": "none", "reversibility": "irreversible"},
        "lead_ids": [lead["id"]],
        "title": "withdraw updates the caller balance before the value transfer",
        "body": {
            "description": [{"p": "The withdraw function decrements the caller balance before it sends "
                                  "value, and the send forwards only the fixed gas stipend, so a "
                                  "reentrant call cannot change state or withdraw a second time."}],
            "impact": [{"p": "No fund effect: the order of the balance update and the value send, with "
                             "the fixed gas stipend on the send, prevent re-entry."}],
            "recommendation": [{"p": "No change is required; the function already follows the "
                                     "checks-effects-interactions order."}],
        },
        "attack_steps": [],
    }
    r = await submit_mod.handle_review_submit_finding(sub)
    print("submit:", {k: r.get(k) for k in ("accepted", "finding_no", "computed_severity")})
    if not r.get("accepted"):
        print("SUBMIT REJECTED:", json.dumps(r)[:1500])
        await pool.close()
        return 1

    fr = await finalize_mod.handle_review_finalize({"job_id": jid})
    print("finalize:", {k: fr.get(k) for k in ("accepted", "report_id", "error_code")})
    if not fr.get("accepted"):
        print("FINALIZE REJECTED:", json.dumps(fr)[:1500])
        await pool.close()
        return 1

    async with pool.connection() as conn:
        report, _extras = await assemble_report(conn, jid, PIN_ROOT)
    out = Path("out"); out.mkdir(exist_ok=True)
    (out / "weth9.report.json").write_text(json.dumps(report, indent=2))
    n_find = len(report.get("findings") or [])
    print(f"assembled: findings={n_find}, report_id={report.get('meta', {}).get('report_id')}")
    await pool.close()
    return 0


def render_pdf(report_json: Path) -> None:
    """Render the assembled report.json through the soken-render image (same as Stage 1)."""
    d = Path(tempfile.mkdtemp(prefix="weth9-render-"))
    (d / "in").mkdir(); (d / "out").mkdir()
    (d / "in" / "report.json").write_bytes(report_json.read_bytes())
    d.chmod(0o711); (d / "in").chmod(0o755); (d / "out").chmod(0o777)
    rc = subprocess.run(
        ["docker", "run", "--rm", "--network=none", "--read-only", "--tmpfs", "/tmp",
         "--memory=2g", "--shm-size=512m", "--cpus=1.0", "--pids-limit=512", "-u", "10001:10001",
         "-v", f"{d}/in:/work/in:ro", "-v", f"{d}/out:/work/out", "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp",
         RENDER_IMAGE, "python", "-m", "soken_review.report.kit.render_job", "/work"],
        capture_output=True, text=True, timeout=180, check=False)
    print("render:", rc.stdout.strip()[-400:] or rc.stderr.strip()[-400:])
    pdf = d / "out" / "report.pdf"
    if pdf.exists():
        dest = Path("out") / "weth9-soken-branded.pdf"
        dest.write_bytes(pdf.read_bytes())
        print("PDF:", dest, pdf.stat().st_size, "bytes")


if __name__ == "__main__":
    code = asyncio.run(main())
    if code == 0:
        render_pdf(Path("out/weth9.report.json"))
    raise SystemExit(code)
