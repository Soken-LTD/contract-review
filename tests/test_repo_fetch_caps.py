"""Host-side fetch caps (09 3.2): job dir bytes by blocks, inodes, wall; container removed on breach.

The container is stood in for by a shell process writing into the job dir; `kill` records the
call (production: `docker rm -f <name>`).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time

import pytest

from soken_review.sandbox import repo_fetch


def _runner(tmp_path, script):
    proc_box = {}

    def kill():
        proc_box["killed"] = time.monotonic()
        subprocess.run(["pkill", "-KILL", "-f", tmp_path.name], capture_output=True, check=False)

    argv = ["sh", "-c", f": {tmp_path.name}; {script}"]
    return argv, kill, proc_box


def test_many_tiny_files_count_by_blocks(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    # 400 one-byte files: 400 bytes by st_size, >= 1.6 MB by blocks
    argv, kill, box = _runner(tmp_path, f"cd {job}; i=0; while [ $i -lt 400 ]; do echo > f$i; i=$((i+1)); done; sleep 30")
    _, killed_by = repo_fetch.run_watched(argv, job, wall_s=20, kill=kill, max_bytes=200 * 1024,
                                             max_inodes=10_000, poll_s=0.1)
    assert killed_by == "disk" and "killed" in box


def test_inode_cap(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    argv, kill, _box = _runner(tmp_path, f"cd {job}; mkdir a b c d e f g; sleep 30")
    _, killed_by = repo_fetch.run_watched(argv, job, wall_s=20, kill=kill, max_bytes=1 << 30,
                                          max_inodes=5, poll_s=0.1)
    assert killed_by == "disk"


def test_sparse_file_counts_allocated_blocks_not_apparent_size(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    # apparent 10 GiB, allocated ~0: does not hold disk, so it does not count; a dense 2 MiB file does
    argv, kill, _ = _runner(tmp_path, f"cd {job}; dd if=/dev/zero of=s bs=1 count=0 seek=10G 2>/dev/null; "
                                      f"dd if=/dev/urandom of=d bs=1024 count=2048 2>/dev/null; sleep 30")
    _, killed_by = repo_fetch.run_watched(argv, job, wall_s=20, kill=kill, max_bytes=1024 * 1024,
                                          max_inodes=10_000, poll_s=0.1)
    assert killed_by == "disk"


def test_wall_kills_slow_container(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    argv, kill, box = _runner(tmp_path, "while true; do sleep 1; done")
    t0 = time.monotonic()
    _, killed_by = repo_fetch.run_watched(argv, job, wall_s=1, kill=kill, poll_s=0.1)
    assert killed_by == "wall" and time.monotonic() - t0 < 15 and "killed" in box


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads everything")
def test_unreadable_job_dir_is_over_budget(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    argv, kill, _ = _runner(tmp_path, f"mkdir {job}/x; touch {job}/x/y; chmod 0 {job}/x; sleep 30")
    try:
        _, killed_by = repo_fetch.run_watched(argv, job, wall_s=20, kill=kill, poll_s=0.1)
        assert killed_by == "disk"
    finally:
        (job / "x").chmod(0o755)


def test_finished_but_over_budget_counts(tmp_path):
    job = tmp_path / "job"
    job.mkdir()
    argv, kill, _ = _runner(tmp_path, f"dd if=/dev/urandom of={job}/d bs=1024 count=512 2>/dev/null")
    code, killed_by = repo_fetch.run_watched(argv, job, wall_s=20, kill=kill, max_bytes=64 * 1024, poll_s=5)
    assert code == 0 and killed_by == "disk"


def test_manifest_byte_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_fetch, "MANIFEST_MAX_BYTES", 100)
    m = tmp_path / "m.json"
    m.write_text(json.dumps({"resolved_commit": "a" * 40, "files": ["x" * 200]}))
    assert repo_fetch._read_manifest(m) == {}
    m.write_text(json.dumps({"resolved_commit": "a" * 40}))
    assert repo_fetch._read_manifest(m)["resolved_commit"] == "a" * 40


def test_solc_cache_binary_readable_by_sandbox_user(tmp_path, monkeypatch):
    # x86 runsc finding: a 0711 solc fails to load under gVisor ("failed to load ...: permission denied")
    import hashlib
    import stat

    from soken_review.adapters.evm import compiler

    data = b"\x7fELF fake"
    monkeypatch.setattr(compiler, "_http_get", lambda url, timeout=60: data)
    dest = tmp_path / "linux-amd64" / "solc-0.4.19"
    compiler.SolcCache(tmp_path)._download_and_verify("u", dest, "0x" + hashlib.sha256(data).hexdigest(), "0.4.19")
    assert stat.S_IMODE(dest.stat().st_mode) == 0o755


def test_materialize_repo_removes_container_on_wall(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv("SOKEN_SANDBOX_DEV_PERMS", "1")

    def fake_run_watched(argv, job_dir, wall_s, kill, **_kw):
        assert "--name" in argv and "--runtime=runsc-egress" in argv
        kill()
        return -signal.SIGKILL, "wall"

    monkeypatch.setattr(repo_fetch, "run_watched", fake_run_watched)
    def fake_run(a, **k):
        calls.append(a)
        return subprocess.CompletedProcess(a, 1, "", "")

    monkeypatch.setattr(repo_fetch.subprocess, "run", fake_run)
    res = repo_fetch.materialize_repo("https://github.com/a/b", tmp_path / "job", "solana",
                                      commit="a" * 40, image="img@sha256:" + "0" * 64)
    assert res.exit_code == 20 and res.killed_by == "wall" and res.retryable
    assert ["docker", "rm", "-f"] in [c[:3] for c in calls]
