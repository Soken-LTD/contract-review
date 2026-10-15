"""Container profile of 09 section 4.2: one function builds the `docker run` argv for a step.

Production runtime is gVisor (`runsc-none` for offline steps, `runsc-egress` for fetch and
deps); local development uses `runc` with the same flags (`SOKEN_SANDBOX_RUNTIME`).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

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
