"""soken-render entry point (08 3.2), run inside the render sandbox with no network.

Usage: python -m soken_review.report.kit.render_job <job_dir> [--compact]

Reads `<job_dir>/in/report.json`; writes `<job_dir>/out/{print.html,report.pdf,result.json}`.
Steps: build(print), render.mjs, post-checks. Only report.pdf leaves the sandbox; the supervisor
builds screen.html itself from its own report.json (hosted origin, never sandbox bytes). `result.json` carries `code`
(`ok` or an 08 detail code), `detail`, `pages`, `fonts`, `uses_mono`, `pdf_sha256`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .build import KIT, BuildError, build, kit_texts

RENDER_EXIT = {10: "timeout", 11: "layout_overflow", 12: "empty_page", 14: "chrome_start", 15: "net_request"}
MIN_PAGES, MAX_PAGES = 4, 120
MAX_BYTES = 20 * 1024 * 1024


def fonts_lock() -> dict:
    return json.loads((KIT / "fonts" / "FONTS.lock").read_text(encoding="utf-8"))


def parse_pdffonts(out: str) -> list[dict[str, str]]:
    """pdffonts table rows: name, type, encoding, emb, sub, uni, object id."""
    rows = []
    for line in out.splitlines()[2:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        emb = parts[-5]
        rows.append({"name": parts[0], "emb": emb})
    return rows


def check_fonts(pdf: Path, uses_mono: bool) -> tuple[str | None, list[str]]:
    out = subprocess.run(["pdffonts", str(pdf)], capture_output=True, text=True, timeout=30, check=True).stdout
    rows = parse_pdffonts(out)
    allowed = {f["postscript_name"]: f for f in fonts_lock()["fonts"]}
    names = []
    for r in rows:
        base = re.sub(r"^[A-Z]{6}\+", "", r["name"])
        names.append(base)
        if r["emb"] != "yes":
            return f"font not embedded: {base}", names
        if base not in allowed:
            return f"font not in FONTS.lock: {base}", names
    required = [n for n, f in allowed.items() if f["required"] == "always" or (f["required"] == "mono" and uses_mono)]
    missing = [n for n in required if n not in names]
    if missing:
        return f"required font missing: {missing}", names
    return None, names


def run(job_dir: Path, compact: bool) -> dict:
    inp, out = job_dir / "in", job_dir / "out"
    out.mkdir(parents=True, exist_ok=True)
    report = json.loads((inp / "report.json").read_text(encoding="utf-8"))
    res = {"code": "ok", "detail": "", "compact": compact}
    try:
        printed = build(report, out, mode="print", compact_evidence=compact)
    except BuildError as err:
        return {**res, "code": err.code, "detail": f"{err.detail} {err.path}".strip(),
                "path": err.path or "", "rule": getattr(err, "rule", "") or ""}
    res["uses_mono"] = printed.uses_mono
    pdf = out / "report.pdf"
    proc = subprocess.run(["node", str(KIT / "render.mjs"), str(job_dir), str(printed.html_path), str(pdf)],
                          capture_output=True, text=True, timeout=110, check=False)
    if proc.returncode != 0:
        code = RENDER_EXIT.get(proc.returncode, "chrome_start")
        return {**res, "code": code, "detail": proc.stderr.strip()[-400:]}
    info = subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True, timeout=30, check=True).stdout
    pages = int(re.search(r"^Pages:\s+(\d+)", info, re.MULTILINE).group(1))
    res["pages"] = pages
    if not MIN_PAGES <= pages <= MAX_PAGES:
        return {**res, "code": "page_limit", "detail": f"{pages} pages"}
    problem, names = check_fonts(pdf, printed.uses_mono)
    res["fonts"] = sorted(set(names))
    if problem:
        return {**res, "code": "fonts", "detail": problem}
    if printed.profile == "public_review":
        want = " ".join(kit_texts()["footer_public_review"].split())
        for n in range(1, pages + 1):
            txt = subprocess.run(["pdftotext", "-f", str(n), "-l", str(n), "-layout", str(pdf), "-"],
                                 capture_output=True, text=True, timeout=30, check=True).stdout
            if want not in " ".join(txt.split()):
                return {**res, "code": "banner", "detail": f"footer missing on page {n}"}
    size = pdf.stat().st_size
    if size >= MAX_BYTES:
        return {**res, "code": "size_limit", "detail": f"{size} bytes"}
    res["pdf_sha256"] = hashlib.sha256(pdf.read_bytes()).hexdigest()
    res["bytes"] = size
    return res


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    compact = "--compact" in args
    job_dir = Path(next(a for a in args if a != "--compact"))
    os.environ.setdefault("TMPDIR", "/tmp")
    result = run(job_dir, compact)
    (job_dir / "out" / "result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["code"] == "ok" else 3


if __name__ == "__main__":
    raise SystemExit(main())
