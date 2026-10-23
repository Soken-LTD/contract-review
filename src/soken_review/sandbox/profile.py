"""Container profile of 09 section 4.2: one function builds the `docker run` argv for a step.

Production runtime is gVisor (`runsc-none` for offline steps, `runsc-egress` for fetch and
deps); local development uses `runc` with the same flags (`SOKEN_SANDBOX_RUNTIME`).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

OFFLINE_STEPS = {"build", "analyze", "map", "verify", "render"}
NETWORK_STEPS = {"fetch", "deps"}
SANDBOX_UID = "10001:10001"
_SYSTEM_ROOTS = frozenset({"", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run",
                           "/sbin", "/sys", "/tmp", "/usr", "/usr/local", "/var"})


@dataclass(frozen=True)
class StepLimits:
    cpus: float
    memory: str          # docker size, e.g. "4g"
    pids: int
    max_file: int        # bytes, ulimit fsize


# --------------------------------------------------------------------------------------------
# Host memory admission (09 3.3 resource budgets, applied to the host's physical memory)
# --------------------------------------------------------------------------------------------
#
# `--memory=8g` on a 3.9 GiB host never engages: the container is not cgroup-limited below the
# host, so the kernel's global OOM killer reaps the step's process after the work is mostly done
# (stand, caracal on oz-account-v3, 2026-10-23: `scarb` killed at 2.8 GiB RSS after 20 minutes,
# the step recorded only `analyzer_failed: exit 1`). A step whose container limit the host cannot
# honour is refused before it starts, with the numbers in the reason.

_MEMINFO = Path("/proc/meminfo")
_ADMISSION_FRACTION = 0.9                 # the kernel, the supervisor and page cache keep the rest
_DEFAULT_BUDGET_MB = 14336                # the worker default (worker/__main__.py SOKEN_WORKER_RAM_MB)
_DOCKER_SIZE_RE = re.compile(r"^\s*(\d+)\s*([bkmgBKMG]?)\s*$")
_SIZE_UNIT_MB = {"": 1 / (1024 * 1024), "b": 1 / (1024 * 1024), "k": 1 / 1024, "m": 1, "g": 1024}


class HostCapacityError(RuntimeError):
    """A container step declares more memory than this host can give it; the step did not run."""

    def __init__(self, *, step: str, need_mb: int, host_mb: int | None, cap_mb: int) -> None:
        self.step = step
        self.need_mb = need_mb
        self.host_mb = host_mb
        self.cap_mb = cap_mb
        super().__init__(self.reason)

    @property
    def reason(self) -> str:
        host = f"host {self.host_mb} MiB" if self.host_mb is not None else f"budget {self.cap_mb} MiB"
        return f"insufficient_host_memory (need {self.need_mb} MiB, {host})"

    def detail(self) -> dict[str, int | str | None]:
        return {"reason": "insufficient_host_memory", "stage": self.step, "need_mb": self.need_mb,
                "host_mb": self.host_mb, "cap_mb": self.cap_mb}


def parse_memory_mb(size: str) -> int:
    """MiB of a docker memory size (`8g`, `512m`, `1048576k`, bytes without a unit); rounded up."""
    m = _DOCKER_SIZE_RE.match(size or "")
    if not m:
        raise ValueError(f"not a docker memory size: {size!r}")
    value, unit = int(m.group(1)), m.group(2).lower()
    mb = value * _SIZE_UNIT_MB[unit]
    return int(mb) if mb == int(mb) else int(mb) + 1


def physical_memory_mb(meminfo: Path = _MEMINFO) -> int | None:
    """MemTotal of `/proc/meminfo` in MiB; `os.sysconf` physical pages where there is no meminfo
    (macOS development hosts); None when neither answers (admission then uses the budget only)."""
    try:
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    try:
        pages, page_size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        return None
    if pages <= 0 or page_size <= 0:
        return None
    return int(pages) * int(page_size) // (1024 * 1024)


@dataclass(frozen=True)
class HostCapacity:
    """What this worker host can give a container step: `physical_mb` measured once at worker
    start (recorded in worker_hosts.ram_mb_total), `budget_mb` the configured worker budget."""

    physical_mb: int | None
    budget_mb: int

    @property
    def admit_mb(self) -> int:
        """Largest container memory limit a step may declare: min(physical * 0.9, budget)."""
        if self.physical_mb is None:
            return self.budget_mb
        return min(int(self.physical_mb * _ADMISSION_FRACTION), self.budget_mb)

    @property
    def recorded_mb(self) -> int:
        """Value for worker_hosts.ram_mb_total: the physical memory, the budget when unmeasured."""
        return self.physical_mb if self.physical_mb is not None else self.budget_mb

    def check(self, limits: StepLimits, step: str) -> None:
        """Raise HostCapacityError when `limits.memory` is above what the host can honour."""
        need = parse_memory_mb(limits.memory)
        if need > self.admit_mb:
            raise HostCapacityError(step=step, need_mb=need, host_mb=self.physical_mb, cap_mb=self.admit_mb)


_HOST: HostCapacity | None = None


def configure_host_capacity(budget_mb: int, *, meminfo: Path = _MEMINFO,
                            physical_mb: int | None = None) -> HostCapacity:
    """Measure the host once (worker start) and keep the result for every container step.
    `physical_mb` injects a measurement (tests); otherwise `/proc/meminfo` then `os.sysconf`."""
    global _HOST
    measured = physical_mb if physical_mb is not None else physical_memory_mb(meminfo)
    _HOST = HostCapacity(physical_mb=measured, budget_mb=int(budget_mb))
    if measured is None:
        logger.warning("host memory unknown: admission uses the %d MiB budget only", budget_mb)
    return _HOST


def host_capacity() -> HostCapacity:
    """The configured capacity; a process that never configured it (scripts, adapters run outside
    the worker) measures on first use with the worker's default budget."""
    if _HOST is None:
        raw = os.environ.get("SOKEN_WORKER_RAM_MB")
        budget = int(raw) if raw and raw.isdigit() and int(raw) > 0 else _DEFAULT_BUDGET_MB
        configure_host_capacity(budget)
    assert _HOST is not None
    return _HOST


def docker_argv(
    step: str,
    image: str,
    work_dir: Path,
    cache_dir: Path | None,
    limits: StepLimits,
    env: dict[str, str],
    command: list[str],
    family_network: str | None = None,
    runtime: str | None = None,
    workdir: str | None = None,
    stdin: bool = False,
    name: str | None = None,
    mounts: list[tuple[Path, str, bool]] | None = None,
    shm_size: str | None = None,
    image_paths: tuple[str, ...] = (),
) -> list[str]:
    """Build docker run argv.

    mounts: optional explicit list of (host_path, container_path, read_only).
      When given, replaces the default /work bind-mount.
      - host_path must be absolute.
      - container_path must start with /work/ or equal /work, or sit under one of image_paths.
      - ".." not allowed in container_path components.
      When None (default), the original /work mount is used (work_dir -> /work).
    image_paths: container roots fixed by a pinned image record, never by a candidate (06 3.3.2: the
      source goes where `solana-verify build` mounts it, the image WorkingDir, and crates under the
      image CARGO_HOME, so a rebuild reproduces paths embedded in the program). Each is absolute,
      without "..", and not a system root.
    """
    for root in image_paths:
        parts = root.split("/")
        if not root.startswith("/") or ".." in parts or root.rstrip("/") in _SYSTEM_ROOTS or "" in parts[1:]:
            raise ValueError(f"image path not allowed: {root!r}")

    def _allowed(path: str) -> bool:
        if path == "/work" or path.startswith("/work/"):
            return True
        return any(path == r or path.startswith(r + "/") for r in image_paths)

    if step not in OFFLINE_STEPS | NETWORK_STEPS:
        raise ValueError(f"unknown step {step}")
    if step in NETWORK_STEPS and not family_network:
        raise ValueError(f"{step} needs the family egress network")
    # Admission: a limit the host cannot honour is refused here, before any `docker run`, so the
    # global OOM killer never decides the outcome of a step (HostCapacityError carries the numbers).
    host_capacity().check(limits, step)
    default_runtime = "runsc-egress" if step in NETWORK_STEPS else "runsc-none"
    runtime = runtime or os.environ.get("SOKEN_SANDBOX_RUNTIME") or default_runtime
    if step in NETWORK_STEPS and runtime == "runsc-none":
        runtime = "runsc-egress"   # runsc-none has loopback only (S3); the family network needs netstack
    network = family_network if step in NETWORK_STEPS else "none"
    if runtime.startswith("runsc") and "@sha256:" not in image:
        # 09 4.4: under gVisor (production) an image runs only by digest, never a floating tag.
        raise ValueError(f"image must be pinned by digest under {runtime}: {image!r}")
    if step in NETWORK_STEPS:
        # 09 4.3, 5.2: the only route out is the family smokescreen; tools read the proxy vars.
        from soken_review.sandbox.egress import proxy_env

        env = {**proxy_env(family_network), **env}

    # Validate explicit mounts
    if mounts is not None:
        for host_path, container_path, _ro in mounts:
            if not host_path.is_absolute():
                raise ValueError(f"mount host_path must be absolute: {host_path}")
            if not _allowed(container_path):
                raise ValueError(f"container_path must be under /work: {container_path!r}")
            if ".." in container_path.split("/"):
                raise ValueError(f"container_path must not contain ..: {container_path!r}")

    argv = [
        "docker", "run", *(["--interactive"] if stdin else []), *(["--name", name] if name else []), "--rm", f"--runtime={runtime}", f"--network={network}",
        "--user", SANDBOX_UID, "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
    ]

    # Add work-dir mounts
    if mounts is not None:
        for host_path, container_path, read_only in mounts:
            ro_suffix = ",readonly" if read_only else ""
            argv += ["--mount", f"type=bind,src={host_path},dst={container_path}{ro_suffix}"]
    else:
        argv += ["--mount", f"type=bind,src={work_dir},dst=/work"]

    if cache_dir is not None:
        argv += ["--mount", f"type=bind,src={cache_dir},dst=/cache,readonly"]
    argv += [
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        f"--pids-limit={limits.pids}", f"--cpus={min(limits.cpus, os.cpu_count() or 1)}",
        f"--memory={limits.memory}", f"--memory-swap={limits.memory}",
        "--ulimit", f"fsize={limits.max_file}:{limits.max_file}",
        "--log-driver", "none",
    ]
    if shm_size is not None:  # render: Chrome shared memory (09 3.1 render row, `--shm-size=512m`)
        if not re.fullmatch(r"[0-9]{1,5}[mg]", shm_size):
            raise ValueError(f"bad shm_size {shm_size!r}")
        argv += [f"--shm-size={shm_size}"]
    for key, value in sorted(env.items()):
        argv += ["--env", f"{key}={value}"]
    if workdir is not None:
        if not _allowed(workdir) or ".." in workdir.split("/"):
            raise ValueError("workdir must stay under /work")
        argv += ["--workdir", workdir]
    return argv + [image, *command]


def locked_image(name: str) -> str | None:
    """Image reference pinned by digest in images.lock.json (09 4.4); `SOKEN_IMAGE_<NAME>` overrides
    it for local development (e.g. a locally built image id). None while the digest is a
    placeholder, so callers fail closed instead of running a floating tag."""
    import json

    override = os.environ.get("SOKEN_IMAGE_" + name.upper().replace("-", "_"))
    if override:
        return override
    lock = Path(__file__).resolve().parents[3] / "images.lock.json"
    entry = json.loads(lock.read_text())["images"].get(name)
    if not entry or set(entry["digest"].removeprefix("sha256:")) <= {"0"}:
        return None
    return f"{entry['repository']}@{entry['digest']}"


def locked_tools(name: str) -> dict[str, str]:
    """The `tools` record of an images.lock.json entry: the versions the image was built with
    (reference data an adapter gates on, never an inline literal). Empty when the entry is absent."""
    import json

    lock = Path(__file__).resolve().parents[3] / "images.lock.json"
    entry = json.loads(lock.read_text())["images"].get(name) or {}
    tools = entry.get("tools") or {}
    return {str(k): str(v) for k, v in tools.items()}


def sandbox_writable_dir(path: Path) -> Path:
    """Create a fresh dir the sandbox user (uid 10001) can write (09 3.3: job dirs belong to it).

    The supervisor runs as root in production and chowns. A non-root dev or CI host may opt in
    to mode 0o777 on this one dir with SOKEN_SANDBOX_DEV_PERMS=1; otherwise this fails (no
    world-writable dir appears on a host by default). Never used for host-only dirs.
    """
    path.mkdir(parents=True, exist_ok=True)
    uid, gid = (int(x) for x in SANDBOX_UID.split(":"))
    try:
        os.chown(path, uid, gid)
    except PermissionError:
        if os.environ.get("SOKEN_SANDBOX_DEV_PERMS") != "1":
            raise
        path.chmod(0o777)
    return path
