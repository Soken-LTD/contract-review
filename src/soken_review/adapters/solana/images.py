"""Solana build images per version line (06 3.3.1, 3.3.2; U-S1).

Image choice follows `solana-verify build`: `--base-image` from the owner-linked verify args, else
`[workspace.metadata.cli] solana`, else Cargo.lock. Each version maps to the upstream
`solanafoundation/solana-verifiable-build@<digest>` (F6) and to our derived image built from it by
`docker/solana-build/Dockerfile` (target `build`). A version line (major.minor) may give tier A only
after its U-S1 row passed: our sandbox build equal to the deployed, owner-linked verified program.

    python -m soken_review.adapters.solana.images build-args 1.18.26 3.1.8
        prints "<version> <upstream ref> <active toolchain>" per line, for the image build step.
    python -m soken_review.adapters.solana.images plan 1.18.26 3.1.8 3.1.10 4.3.0
        JSON build-plan entries (the scripts/images.py shape, target `build`) for solana-images.yml.
    python -m soken_review.adapters.solana.images record-digests <results_dir>
        writes the digests the push job recorded (digest-*.json) into image_map.json `soken_image`.

Publishing (`.github/workflows/solana-images.yml`, manual): one derived image per version is built
from the pinned upstream digest, Trivy-gated, pushed to `ghcr.io/soken-ltd/solana-build:<version>`
and its digest written back here, so `build_image()` can run it. images.lock.json is not involved:
its `solana-analyze` entry (same repository, tag `<version>-analyze`) is the analysis stage that
images.yml publishes.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

IMAGE_MAP_PATH = Path(__file__).parent / "data" / "image_map.json"

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_ABS_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
# Container paths an image may claim for W and CH; never a system root (09 4.2).
_FORBIDDEN_ROOTS = frozenset({"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root",
                              "/run", "/sbin", "/sys", "/tmp", "/usr", "/usr/local", "/var", "/work"})


@dataclass(frozen=True)
class BuildImage:
    version: str
    line: str                     # "major.minor"
    ref: str                      # image reference to run (derived image, pinned)
    upstream: str                 # solanafoundation/solana-verifiable-build@sha256:...
    working_dir: str              # W: the source mount, as solana-verify mounts it
    cargo_home: str               # CH: per-candidate crate dir mounted here
    home: str                     # HOME holding the image's platform-tools
    active_toolchain: str         # RUSTUP_TOOLCHAIN, as solana-verify sets it
    arch_values: tuple[str, ...]
    u_s1: str                     # passed | not_run | failed


def load_map() -> dict[str, Any]:
    return json.loads(IMAGE_MAP_PATH.read_text())


def version_line(version: str) -> str:
    major, minor, _ = version.split(".", 2)
    return f"{major}.{minor}"


def _placeholder(digest: str) -> bool:
    return not digest or set(digest.removeprefix("sha256:")) <= {"0"}


def _safe_container_path(value: str) -> bool:
    return bool(_ABS_PATH_RE.match(value)) and ".." not in value.split("/") \
        and value.rstrip("/") not in _FORBIDDEN_ROOTS


def env_override_name(version: str) -> str:
    return "SOKEN_IMAGE_SOLANA_BUILD_" + version.replace(".", "_")


def build_image(version: str) -> BuildImage | None:
    """Derived build image for an exact Solana version, or None (attempt unsupported_toolchain).

    The derived image is `SOKEN_IMAGE_SOLANA_BUILD_<x_y_z>` (a locally built image id, dev and CI)
    or the pinned `soken_image` digest; a placeholder digest is None, never a floating tag.
    """
    if not _VERSION_RE.match(version or ""):
        return None
    data = load_map()
    entry = data["images"].get(version)
    if not entry or "soken_image" not in entry:
        return None
    ref = os.environ.get(env_override_name(version))
    if not ref:
        soken = entry["soken_image"]
        if _placeholder(soken.get("digest", "")):
            return None
        ref = f"{soken['repository']}@{soken['digest']}"
    if not all(_safe_container_path(entry[k]) for k in ("working_dir", "cargo_home")):
        return None
    line = version_line(version)
    row = (data.get("version_lines") or {}).get(line) or {}
    return BuildImage(
        version=version, line=line, ref=ref,
        upstream=f"{entry['repository']}@{entry['digest']}",
        working_dir=entry["working_dir"].rstrip("/"), cargo_home=entry["cargo_home"].rstrip("/"),
        home=entry.get("home", "/root"), active_toolchain=entry["active_toolchain"],
        arch_values=tuple(entry.get("arch_values") or ()), u_s1=str(row.get("u_s1", "not_run")),
    )


def line_passed(version: str | None) -> bool:
    """True only when the U-S1 row of the version's line passed (06 2.4: else never A or C)."""
    if not version or not _VERSION_RE.match(version):
        return False
    row = (load_map().get("version_lines") or {}).get(version_line(version)) or {}
    return row.get("u_s1") == "passed"


def version_from_base_image(base_image: str) -> str | None:
    """`--base-image` from verify args: a digest or a tag of solana-verifiable-build in our map, else None
    (attempt untrusted_base_image)."""
    data = load_map()["images"]
    for version, entry in data.items():
        if _VERSION_RE.match(version) and entry.get("digest") and entry["digest"] in base_image:
            return version
    m = re.fullmatch(r"(?:docker\.io/)?solanafoundation/solana-verifiable-build:v?(\d+\.\d+\.\d+)", base_image.strip())
    if m and m.group(1) in data:
        return m.group(1)
    return None


_DOCKER_DIR = "docker/solana-build"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_BUILD_TARGET = "build"


def plan_images(versions: list[str]) -> list[dict[str, Any]]:
    """Build-plan entries (scripts/images.py shape) for the derived build image of each version.

    Name `solana-build-<version>` keeps the CI artifacts apart; repository and tag are the row's
    `soken_image`; BASE_IMAGE is the upstream digest (never a tag); the stage is `build`, so the
    published image is the one `build_image()` runs (the analyze stage is a different image).
    Raises ValueError for a version with no derived image (upstream-only rows, bpf, unknown).
    """
    data = load_map()["images"]
    plan = []
    for version in versions:
        entry = data.get(version) if _VERSION_RE.match(version or "") else None
        if not entry or "soken_image" not in entry or _placeholder(entry.get("digest", "")):
            raise ValueError(f"no derived build image is defined for Solana {version!r}")
        soken = entry["soken_image"]
        plan.append({
            "name": f"solana-build-{version}", "dir": _DOCKER_DIR, "dockerfile": f"{_DOCKER_DIR}/Dockerfile",
            "repository": soken["repository"], "tag": soken["tag"],
            "build_args": {"BASE_IMAGE": f"{entry['repository']}@{entry['digest']}",
                           "ACTIVE_TOOLCHAIN": entry["active_toolchain"]},
            "deps": [], "dep_refs": [], "target": _BUILD_TARGET,
        })
    return plan


def record_digests(results_dir: Path) -> list[str]:
    """Write pushed digests (image-push `digest-*.json`: name, repository, tag, digest, commit, run_id,
    trivy_critical) into `soken_image` of the row whose soken_image tag and repository match.

    Only `soken_image` changes (digest, tag, built); every other field, row order and the comment
    stay. All results are validated before anything is written, so a bad result writes nothing.
    Returns "<version> <repository>@<digest>" per written row.
    """
    results = [json.loads(p.read_text()) for p in sorted(Path(results_dir).rglob("*.json"))]
    if not results:
        raise ValueError(f"no digest results in {results_dir}")
    data = load_map()
    by_tag = {row["soken_image"]["tag"]: version for version, row in data["images"].items()
              if "soken_image" in row}
    writes = []
    for r in results:
        repo, tag, digest = r.get("repository", ""), r.get("tag", ""), r.get("digest", "")
        version = by_tag.get(tag)
        if version is None:
            raise ValueError(f"result tag {tag!r} is not a published Solana version")
        if repo != data["images"][version]["soken_image"]["repository"]:
            raise ValueError(f"result repository {repo!r} is not the soken_image repository of {version}")
        if not _DIGEST_RE.match(digest) or _placeholder(digest):
            raise ValueError(f"bad digest for {version}: {digest!r}")
        writes.append((version, repo, digest, r))
    changed = []
    for version, repo, digest, r in writes:
        soken = data["images"][version]["soken_image"]
        soken["digest"] = digest
        soken["built"] = {"commit": r.get("commit"), "run_id": r.get("run_id"),
                          "trivy_critical": r.get("trivy_critical")}
        changed.append(f"{version} {repo}@{digest}")
    IMAGE_MAP_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    return changed


def _main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "plan":
        try:
            print(json.dumps(plan_images(argv[1:])))
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1
        return 0
    if len(argv) == 2 and argv[0] == "record-digests":
        try:
            print("\n".join(record_digests(Path(argv[1]))))
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1
        return 0
    if len(argv) < 2 or argv[0] != "build-args":
        print(__doc__, file=sys.stderr)
        return 2
    data = load_map()["images"]
    for version in argv[1:]:
        entry = data.get(version)
        if not entry or _placeholder(entry.get("digest", "")):
            print(f"no upstream image for {version}", file=sys.stderr)
            return 1
        print(f"{version} {entry['repository']}@{entry['digest']} {entry['active_toolchain']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
