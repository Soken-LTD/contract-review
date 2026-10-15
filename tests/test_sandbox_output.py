"""sandbox.output.read_output_files: nothing a container plants is followed (09 3.5)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from soken_review.sandbox.output import UnsafeOutput, read_output_files


def _out(tmp_path: Path) -> Path:
    out = tmp_path / "work" / "out"
    out.mkdir(parents=True)
    return out


def test_reads_regular_files(tmp_path: Path) -> None:
    out = _out(tmp_path)
    (out / "a.code.boc").write_bytes(b"\x01")
    (out / "sub").mkdir()
    (out / "sub" / "b.code.boc").write_bytes(b"\x02")
    (out / "notes.md").write_text("x")
    assert read_output_files(out, "*.code.boc", 8, 16) == {"a.code.boc": b"\x01", "sub/b.code.boc": b"\x02"}


def test_out_dir_symlink_rejected(tmp_path: Path) -> None:
    host = tmp_path / "host"
    host.mkdir()
    (host / "output.boc").write_bytes(b"secret")
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "out").symlink_to(host)
    with pytest.raises(UnsafeOutput):
        read_output_files(tmp_path / "work" / "out", "output.boc", 1, 64)


def test_symlinked_subdir_rejected(tmp_path: Path) -> None:
    out = _out(tmp_path)
    host = tmp_path / "host"
    host.mkdir()
    (host / "x.code.boc").write_bytes(b"secret")
    (out / "sub").symlink_to(host)
    with pytest.raises(UnsafeOutput, match="symlink"):
        read_output_files(out, "*.code.boc", 8, 64)


def test_symlinked_file_rejected(tmp_path: Path) -> None:
    out = _out(tmp_path)
    (tmp_path / "secret").write_bytes(b"s")
    (out / "output.boc").symlink_to(tmp_path / "secret")
    with pytest.raises(UnsafeOutput, match="symlink"):
        read_output_files(out, "output.boc", 1, 64)


def test_fifo_rejected(tmp_path: Path) -> None:
    out = _out(tmp_path)
    os.mkfifo(out / "output.boc")
    with pytest.raises(UnsafeOutput, match="regular"):
        read_output_files(out, "output.boc", 1, 64)


def test_size_and_count_caps(tmp_path: Path) -> None:
    out = _out(tmp_path)
    (out / "output.boc").write_bytes(b"x" * 65)
    with pytest.raises(UnsafeOutput):
        read_output_files(out, "output.boc", 1, 64)
    (out / "output.boc").write_bytes(b"x")
    (out / "a.boc").write_bytes(b"x")
    with pytest.raises(UnsafeOutput, match="too many"):
        read_output_files(out, "*.boc", 1, 64)


def test_missing_dir(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_output_files(tmp_path / "none", "*", 1, 1)
