"""Supervisor side of the npm download (EVM repo fetch step, 09 4.3, 5.2).

`run_npm_fetch` runs `soken-npm-fetch` (sandbox/npm_materializer.py, baked into the `git-fetch`
image) on the `evm` egress network, where smokescreen allows `registry.npmjs.org` only
(contract/ops/limits.yaml `egress.evm`). The container gets a plan file (read-only mount) and one
writable output dir; nothing else of the host. Its output is untrusted: each body is read back
with O_NOFOLLOW and a byte cap, and the caller verifies sha512 integrity before using a byte.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from soken_review.sandbox.egress import network_name
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir
from soken_review.sandbox.repo_fetch import _read_manifest, _tail_from_fh, run_watched

NPM_FETCH_LIMITS = StepLimits(cpus=1.0, memory="1g", pids=64, max_file=64 * 1024 * 1024)
NPM_FETCH_WALL_S = 120
NPM_FETCH_MAX_BYTES = 768 * 1024 * 1024
NPM_FETCH_MAX_INODES = 2_000
_ID_SAFE = frozenset("r0123456789")


@dataclass
class NpmFetchOutcome:
    """Bodies by request id plus a status per id. `transient` = worth retrying the step."""

    bodies: dict[str, bytes] = field(default_factory=dict)
    status: dict[str, str] = field(default_factory=dict)
    transient: bool = False
    error: str | None = None
    stderr_tail: str = ""


def _read_body(path: Path, cap: int) -> bytes | None:
    """Read one container-written file without following links; None when unsafe or over cap."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def run_npm_fetch(requests: list[dict], job_dir: Path, image: str | None = None,
                  runtime: str | None = None, wall_s: int = NPM_FETCH_WALL_S) -> NpmFetchOutcome:
    """Download `requests` ([{id, url, kind, max_bytes}]) through the sandbox. Never raises for
    a fetch problem: the outcome carries `error` / `transient` and per-request status."""
    image = image or locked_image("git-fetch")
    if image is None:
        return NpmFetchOutcome(error="git-fetch image not pinned")
    job_dir.mkdir(parents=True, exist_ok=True)
    in_dir = job_dir / "in"
    in_dir.mkdir(exist_ok=True)
    (in_dir / "plan.json").write_text(json.dumps({"requests": requests}), encoding="utf-8")
    out = sandbox_writable_dir(job_dir / "out")
    name = f"soken-npm-{secrets.token_hex(6)}"
    argv = docker_argv(
        step="deps", image=image, work_dir=job_dir, cache_dir=None, limits=NPM_FETCH_LIMITS,
        env={"HOME": "/tmp"},
        command=["soken-npm-fetch", "--plan", "/work/in/plan.json", "--out", "/work/out",
                 "--wall", str(max(wall_s - 10, 10))],
        family_network=network_name("evm"),
        runtime=runtime or os.environ.get("SOKEN_SANDBOX_RUNTIME"), name=name,
        mounts=[(in_dir.resolve(), "/work/in", True), (out.resolve(), "/work/out", False)],
    )

    def kill() -> None:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)

    with open(job_dir / "npm_fetch.stderr", "w+b") as err_fh:
        code, killed_by = run_watched(argv, out, wall_s, kill, max_bytes=NPM_FETCH_MAX_BYTES,
                                      max_inodes=NPM_FETCH_MAX_INODES, stderr=err_fh)
        tail = _tail_from_fh(err_fh)
    if killed_by is not None:
        return NpmFetchOutcome(transient=killed_by == "wall", error=f"killed_by_{killed_by}", stderr_tail=tail)
    manifest = _read_manifest(out / "manifest.json")
    if code == 20:
        return NpmFetchOutcome(transient=True, error="registry_unreachable", stderr_tail=tail)
    if code != 0:
        return NpmFetchOutcome(error=f"npm_fetch_exit_{code}", stderr_tail=tail)
    caps = {r["id"]: int(r["max_bytes"]) for r in requests}
    result = NpmFetchOutcome(stderr_tail=tail)
    rows = manifest.get("results") if isinstance(manifest.get("results"), list) else []
    for row in rows:
        rid = row.get("id") if isinstance(row, dict) else None
        if not isinstance(rid, str) or rid not in caps or not set(rid) <= _ID_SAFE:
            continue
        status = row.get("status") if isinstance(row.get("status"), str) else "network"
        result.status[rid] = status[:32]
        if status == "ok":
            body = _read_body(out / f"{rid}.bin", caps[rid])
            if body is None:
                result.status[rid] = "unreadable"
            else:
                result.bodies[rid] = body
    for rid in caps:
        result.status.setdefault(rid, "missing")
    return result
