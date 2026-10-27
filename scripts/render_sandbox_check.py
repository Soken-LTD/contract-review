#!/usr/bin/env python3
"""P0-RENDER (09 UV9-13): render report.json files through the soken-render sandbox, as the worker does.

Usage: uv run python scripts/render_sandbox_check.py --image IMG [--runs N] [--forbid TEXT] report.json...

Each file is staged as in/report.json and rendered with `render.run_container` (no network,
read-only root, uid 10001, 2 GiB, shm 512m). Prints one line per run: pages, wall seconds,
pdf sha256, fonts. `--forbid` fails the run if the PDF text contains that string
(public_review withholding check). Exit 1 on any failure.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from soken_review.report.render import fresh_render_dir, run_container


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--forbid", action="append", default=[])
    ap.add_argument("--keep", type=Path)
    ap.add_argument("reports", nargs="+", type=Path)
    a = ap.parse_args()
    base = Path(tempfile.mkdtemp(prefix="render-check-", dir=Path.cwd() / ".sbx" if (Path.cwd() / ".sbx").exists() else None))
    base.chmod(0o755)  # the sandbox user (uid 10001) must traverse to in/
    failed = 0
    for rep in a.reports:
        for run in range(1, a.runs + 1):
            d = fresh_render_dir(rep.read_bytes())
            t0 = time.monotonic()
            o = run_container(d, compact=False, image=a.image)
            wall = time.monotonic() - t0
            line = f"{rep.name} run {run}: {o.code} {o.detail[:200]} pages={o.pages} wall={wall:.1f}s sha256={o.pdf_sha256}"
            if o.code == "ok":
                pdf = base / f"{rep.stem}-{run}.pdf"
                pdf.write_bytes(o.files["report.pdf"])
                text = subprocess.run(["pdftotext", str(pdf), "-"], capture_output=True, text=True, check=True).stdout
                leaks = [f for f in a.forbid if f in text]
                line += f" fonts={o.result.get('fonts')} leaks={leaks}"
                if leaks:
                    failed += 1
                if a.keep:
                    a.keep.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(pdf, a.keep / pdf.name)
            else:
                failed += 1
                if a.keep and (d / "out" / "layout.json").exists():
                    # Developer record written by render.mjs on a layout failure (page map, paged.js
                    # console); the supervisor never reads it, this check script keeps it beside the PDFs.
                    a.keep.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(d / "out" / "layout.json", a.keep / f"{rep.stem}-{run}.layout.json")
            print(line, flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
