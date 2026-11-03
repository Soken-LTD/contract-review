"""A legacy report (no meta.flow) builds to the same bytes as the kit on origin/main (thin server design,
section 4: legacy rows re-render unchanged), in both modes and both profiles."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from soken_review.report.kit.build import build
from tests.report.fixtures import report, with_profile

REPO = Path(__file__).resolve().parents[2]


def _main_tree(dest: Path) -> Path | None:
    archive = dest / "main.tar"
    try:
        with archive.open("wb") as fh:
            subprocess.run(["git", "-C", str(REPO), "archive", "origin/main", "src", "contract"], stdout=fh,
                           check=True, timeout=120)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    root = dest / "main"
    root.mkdir()
    with tarfile.open(archive) as tar:
        tar.extractall(root, filter="data")
    return root


@pytest.mark.parametrize("profile", ["public_review", "owner"])
@pytest.mark.parametrize("mode", ["print", "screen"])
def test_legacy_report_html_is_byte_equal_to_main(tmp_path, profile, mode):
    main = _main_tree(tmp_path)
    if main is None:
        pytest.skip("origin/main not available")
    rep = with_profile(report(4), profile)
    assert "flow" not in rep["meta"]
    src = tmp_path / "report.json"
    src.write_text(json.dumps(rep), encoding="utf-8")
    out_old = tmp_path / "old"
    env = {**os.environ, "PYTHONPATH": str(main / "src")}
    res = subprocess.run([sys.executable, "-m", "soken_review.report.kit.build", str(src), str(out_old), mode],
                         cwd=main, env=env, capture_output=True, text=True, timeout=300, check=False)
    assert res.returncode == 0, res.stdout + res.stderr
    new = build(json.loads(src.read_text(encoding="utf-8")), tmp_path / "new", mode=mode).html_path.read_bytes()
    old = (out_old / ("print.html" if mode == "print" else "screen.html")).read_bytes()
    assert new == old
