"""Regression: the fetch container's stderr is captured host-side and read back safely (2026-10-22).

A security review of the first version found two defects: the stderr file lived under ``out/``, which
is bind-mounted writable into the untrusted fetch container, and the tail was re-opened BY PATH after
the run — so a compromised fetch could swap the file for a symlink (host-file disclosure through
``error_detail``) or a FIFO (supervisor hang). The hardened version keeps the file in the job root
(not mounted into the container) and reads the tail from the already-open descriptor, refusing
anything that is not a regular file.
"""

from __future__ import annotations

import os
from pathlib import Path

from soken_review.sandbox import repo_fetch as rf


def test_tail_from_fh_reads_last_bytes_from_the_open_descriptor(tmp_path: Path) -> None:
    p = tmp_path / "stderr.txt"
    with open(p, "w+b") as fh:
        fh.write(b"A" * 3000 + b"TAIL-MARK")
        tail = rf._tail_from_fh(fh, limit=20)
    assert tail.endswith("TAIL-MARK")
    assert len(tail) <= 20


def test_tail_from_fh_refuses_non_regular_file() -> None:
    # A pipe is not a regular file: the S_ISREG guard must return "" instead of reading it
    # (the same guard defeats a FIFO or a symlink swap, which cannot happen through an fd anyway).
    r, w = os.pipe()
    try:
        with os.fdopen(w, "wb") as fh:
            assert rf._tail_from_fh(fh) == ""
    finally:
        os.close(r)


def test_stderr_file_lives_in_the_job_root_not_under_a_container_mount(tmp_path, monkeypatch) -> None:
    job = tmp_path / "job"
    job.mkdir()
    seen: dict[str, Path] = {}

    def fake_run_watched(argv, job_dir, wall_s, kill, stderr=None, **_):
        seen["stderr"] = Path(stderr.name)
        stderr.write(b"fatal: network soken-egress-evm not found\n")
        return 26, None

    monkeypatch.setattr(rf, "run_watched", fake_run_watched)
    monkeypatch.setattr(rf, "locked_image", lambda name: "ghcr.io/x/git-fetch@sha256:" + "a" * 64)
    monkeypatch.setattr(rf, "docker_argv", lambda **kw: ["true"])
    monkeypatch.setattr(rf, "network_name", lambda fam: "soken-egress-evm")
    monkeypatch.setattr(rf, "_read_manifest", lambda p: {})

    res = rf.materialize_repo("https://github.com/x/y", job, "evm", commit="b" * 40)

    # Only src/, out/ and tmp/ are bind-mounted into the untrusted container; the stderr file must
    # live beside them in the job root, never inside out/ where the container could replace it.
    assert seen["stderr"] == job / "fetch.stderr"
    assert not (job / "out" / "fetch.stderr").exists()
    # ...and the captured tail reaches the result so the supervisor can persist it as error_detail.
    assert res.stderr_tail == "fatal: network soken-egress-evm not found"
    assert not res.ok
    assert res.error_code == "E_INTERNAL"
