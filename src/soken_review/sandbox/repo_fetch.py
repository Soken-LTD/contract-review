"""Supervisor side of the repo fetch step (09 3.6, 5.2): run soken-fetch in the sandbox.

`materialize_repo` runs the `git-fetch` image (digest from images.lock.json) on the family
egress network with the job's `src`, `out` and `tmp` dirs as the only writable mounts, and maps
the exit code to the 09 3.6 outcome. The caps of 09 3.2 hold on the host while the container
runs, whatever happens inside it: the job dir is measured every 0.5 s by allocated blocks and
inode count (unreadable = over), and on a breach or at the wall the named container is removed
with `docker rm -f` (killing `docker run` alone would leave it running). The manifest is
container output: read with a byte cap, treated as data, paths re-checked by the caller.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from soken_review.sandbox.egress import network_name
from soken_review.sandbox.git_materializer import dir_usage
from soken_review.sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir

FETCH_LIMITS = StepLimits(cpus=1.0, memory="1g", pids=128, max_file=256 * 1024 * 1024)  # 09 3.2
FETCH_WALL_S = 90                                                                     # 09 3.2
FETCH_MAX_BYTES = 2 * 1024**3                                                         # 09 3.2, 2 GiB
FETCH_MAX_INODES = 200_000                                                            # 09 3.2
MANIFEST_MAX_BYTES = 32 * 1024 * 1024

# 09 3.6: exit code -> (error code, retryable)
EXIT_CODES: dict[int, tuple[str, bool]] = {
    0: ("", False),
    20: ("E_REPO_UNREACHABLE", True),
    21: ("E_COMMIT_NOT_FOUND", False),
    22: ("E_SIZE_LIMIT", False),
    23: ("E_COMMIT_AMBIGUOUS", False),
    24: ("E_UNPINNED_REF", False),
    25: ("E_INVALID_ARGUMENT", False),
    26: ("E_INTERNAL", False),
}


@dataclass
class FetchResult:
    exit_code: int
    error_code: str            # "" on success
    retryable: bool
    src_dir: Path
    manifest: dict = field(default_factory=dict)
    killed_by: str | None = None   # "wall" or "disk" when the supervisor stopped the container
    stderr_tail: str = ""          # last bytes of the container's stderr (diagnostics only, untrusted)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def run_watched(argv: list[str], job_dir: Path, wall_s: float, kill: Callable[[], None],
                max_bytes: int = FETCH_MAX_BYTES, max_inodes: int = FETCH_MAX_INODES,
                poll_s: float = 0.5, stderr: BinaryIO | None = None) -> tuple[int | None, str | None]:
    """Run argv; every poll, check the wall and the job dir. Returns (returncode, killed_by)."""
    # stderr: the fetch container's diagnostics. Callers pass an open file so a failure keeps a
    # bounded tail for `error_detail` instead of vanishing into DEVNULL (2026-10-22: a missing
    # egress network surfaced as a bare E_INTERNAL with no reason).
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                            stderr=stderr if stderr is not None else subprocess.DEVNULL,
                            start_new_session=True)
    deadline = time.monotonic() + wall_s
    killed_by = None
    try:
        while proc.poll() is None:
            usage = dir_usage(str(job_dir))
            if usage is None or usage[0] > max_bytes or usage[1] > max_inodes:
                killed_by = "disk"
            elif time.monotonic() > deadline:
                killed_by = "wall"
            if killed_by:
                kill()
                break
            time.sleep(poll_s)
    finally:
        if proc.poll() is None:
            kill()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, 9)
                proc.wait(timeout=10)
    if killed_by is None:                       # the final state counts too
        usage = dir_usage(str(job_dir))
        if usage is None or usage[0] > max_bytes or usage[1] > max_inodes:
            killed_by = "disk"
    return proc.returncode, killed_by


def _read_manifest(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MANIFEST_MAX_BYTES + 1)
        if len(raw) > MANIFEST_MAX_BYTES:
            return {}
        data = json.loads(raw)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def materialize_repo(
    url: str, job_dir: Path, family: str, commit: str | None = None, ref: str | None = None,
    image: str | None = None, runtime: str | None = None, wall_s: int = FETCH_WALL_S,
) -> FetchResult:
    """Fetch `url` at `commit` (7 to 40 hex) or `ref` into `job_dir/src` (09 5.2)."""
    image = image or locked_image("git-fetch")
    src = sandbox_writable_dir(job_dir / "src")
    out = sandbox_writable_dir(job_dir / "out")
    tmp = sandbox_writable_dir(job_dir / "tmp")
    if image is None:
        return FetchResult(26, "E_INTERNAL", False, src, {"error": {"detail": "git-fetch image not pinned"}})
    command = ["soken-fetch", "--url", url, "--out", "/work/src", "--manifest", "/work/out/manifest.json",
               "--scratch", "/work/tmp", "--wall", str(max(wall_s - 10, 10))]
    command += ["--commit", commit] if commit else ["--ref", ref or "HEAD"]
    name = f"soken-fetch-{secrets.token_hex(6)}"
    argv = docker_argv(
        step="fetch", image=image, work_dir=job_dir, cache_dir=None, limits=FETCH_LIMITS,
        env={"HOME": "/tmp"}, command=command, family_network=network_name(family),
        runtime=runtime or os.environ.get("SOKEN_SANDBOX_RUNTIME"), name=name,
        mounts=[(src, "/work/src", False), (out, "/work/out", False), (tmp, "/work/tmp", False)],
    )

    def kill() -> None:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=60)

    # stderr goes to a HOST-ONLY file in the job root: only src/out/tmp are bind-mounted into the
    # untrusted container, so it can neither see nor replace this file. The tail is read back from
    # the SAME descriptor — never re-opened by path — so a compromised fetch cannot swap in a
    # symlink (host-file disclosure into error_detail) or a FIFO (supervisor hang).
    stderr_path = job_dir / "fetch.stderr"
    with open(stderr_path, "w+b") as err_fh:
        code, killed_by = run_watched(argv, job_dir, wall_s, kill, stderr=err_fh)
        tail = _tail_from_fh(err_fh)
    manifest = _read_manifest(out / "manifest.json")
    if killed_by == "disk":
        return FetchResult(22, "E_SIZE_LIMIT", False, src, manifest, killed_by, tail)
    if killed_by == "wall":
        return FetchResult(20, "E_REPO_UNREACHABLE", True, src, manifest, killed_by, tail)  # 09 3.6 timeout
    code = code if code is not None else 26
    error_code, retryable = EXIT_CODES.get(code, ("E_INTERNAL", False))
    if code == 0 and not manifest.get("resolved_commit"):
        code, error_code, retryable = 26, "E_INTERNAL", False
    return FetchResult(code, error_code, retryable, src, manifest, None, tail)


STDERR_TAIL_BYTES = 2048


def _tail_from_fh(fh: BinaryIO, limit: int = STDERR_TAIL_BYTES) -> str:
    """Last `limit` bytes of an already-open stderr file, read from its own descriptor.

    Deliberately never re-opens by path: a path re-open is the classic symlink/FIFO TOCTOU, so it
    is avoided on principle even though the file lives outside every container mount. Refuses
    anything but a regular file as defence in depth. Returns "" on any problem.
    """
    try:
        fh.flush()
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            return ""
        fh.seek(max(0, st.st_size - limit))
        return fh.read(limit).decode("utf-8", "replace").strip()
    except (OSError, ValueError):
        return ""
