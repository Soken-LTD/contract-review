"""Sandbox output is untrusted (08 3.2, 09 3.5): only a regular, capped, hash-matching PDF is taken."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from soken_review.report import render
from soken_review.report.render import UntrustedOutput, collect_outputs, read_result, read_untrusted
from soken_review.sandbox.profile import StepLimits, docker_argv

PDF = b"%PDF-1.7\n" + b"x" * 100


def _out(tmp_path: Path, pdf: bytes = PDF, **result) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    (out / "report.pdf").write_bytes(pdf)
    body = {"code": "ok", "detail": "", "pages": 5, "pdf_sha256": hashlib.sha256(pdf).hexdigest(), **result}
    (out / "result.json").write_text(json.dumps(body))
    return out


def test_ok_takes_pdf_bytes_only(tmp_path):
    out = _out(tmp_path)
    (out / "screen.html").write_text("<script>evil()</script>")
    o = collect_outputs(out, 0)
    assert o.code == "ok" and o.files == {"report.pdf": PDF}


def test_symlinked_pdf_to_host_file_rejected(tmp_path):
    out = _out(tmp_path)
    (out / "report.pdf").unlink()
    (out / "report.pdf").symlink_to("/etc/passwd")
    o = collect_outputs(out, 0)
    assert o.code == "untrusted_output" and o.files is None


def test_symlinked_result_rejected(tmp_path):
    out = _out(tmp_path)
    (out / "result.json").unlink()
    (out / "result.json").symlink_to("/etc/passwd")
    assert collect_outputs(out, 0).code == "untrusted_output"


def test_fifo_rejected_without_blocking(tmp_path):
    out = _out(tmp_path)
    (out / "report.pdf").unlink()
    os.mkfifo(out / "report.pdf")
    assert collect_outputs(out, 0).code == "untrusted_output"


def test_oversize_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(render, "MAX_PDF_BYTES", 50)
    assert collect_outputs(_out(tmp_path), 0).code == "untrusted_output"


def test_hash_mismatch_rejected(tmp_path):
    out = _out(tmp_path, pdf_sha256="0" * 64)
    assert collect_outputs(out, 0).code == "untrusted_output"


def test_not_a_pdf_rejected(tmp_path):
    assert collect_outputs(_out(tmp_path, pdf=b"<html>"), 0).code == "untrusted_output"


@pytest.mark.parametrize("bad", [{"code": "rm -rf"}, {"pages": "7"}, {"pdf_sha256": "../x"}, {"fonts": [1]}])
def test_result_fields_validated(tmp_path, bad):
    out = _out(tmp_path, **bad)
    with pytest.raises(UntrustedOutput):
        read_result(out)


def test_result_detail_truncated_and_failure_code_passed(tmp_path):
    out = _out(tmp_path, code="layout_overflow", detail="x" * 5000)
    o = collect_outputs(out, 0)
    assert o.code == "layout_overflow" and len(o.detail) == 400


def test_missing_result_maps_exit_code(tmp_path):
    (tmp_path / "out").mkdir()
    assert collect_outputs(tmp_path / "out", 137).code == "timeout"
    assert collect_outputs(tmp_path / "out", 1).code == "chrome_start"


def test_read_untrusted_reads_regular_file(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"abc")
    assert read_untrusted(p, 10) == b"abc"


def test_render_argv_offline_readonly_input(tmp_path):
    argv = docker_argv("render", "img@sha256:" + "a" * 64, tmp_path, None, render.RENDER_LIMITS, env={},
                       command=["python"], mounts=[(tmp_path / "in", "/work/in", True), (tmp_path / "out", "/work/out", False)],
                       shm_size="512m")
    assert "--network=none" in argv and "--read-only" in argv and "--shm-size=512m" in argv
    assert any(a.endswith("dst=/work/in,readonly") for a in argv)
    with pytest.raises(ValueError):
        docker_argv("render", "i", tmp_path, None, StepLimits(1, "1g", 1, 1), env={}, command=[], shm_size="1g;x")


def test_screen_html_built_by_supervisor(tmp_path, monkeypatch):
    from .fixtures import report

    r = report(severities=["Medium"])
    r["findings"][0]["title"] = "Title with <script>alert(1)</script> inside"
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "rr"))
    html = render.build_screen_html(r, False).decode()
    assert "<script" not in html and "&lt;script&gt;" in html and "script-src 'none'" in html


def test_fresh_render_dir_under_supervisor_root(tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "root"))
    d = render.fresh_render_dir(b"{}")
    assert d.parent == tmp_path / "root" and (d / "in" / "report.json").read_bytes() == b"{}"
    assert not (d / "out").exists()
    d2 = render.fresh_render_dir(b"{}")
    assert d2 != d


def test_symlinked_render_root_refused(tmp_path, monkeypatch):
    (tmp_path / "target").mkdir()
    (tmp_path / "root").symlink_to(tmp_path / "target")
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "root"))
    with pytest.raises(RuntimeError):
        render.fresh_render_dir(b"{}")
