"""Solana build images per version line (06 3.3.1, 3.3.2; U-S1).

Image choice follows `solana-verify build`: `--base-image` from the owner-linked verify args, else
`[workspace.metadata.cli] solana`, else Cargo.lock. Each version maps to the upstream
`solanafoundation/solana-verifiable-build@<digest>` (F6) and to our derived image built from it by
`docker/solana-build/Dockerfile` (target `build`). A version line (major.minor) may give tier A only
after its U-S1 row passed: our sandbox build equal to the deployed, owner-linked verified program.

    python -m soken_review.adapters.solana.images build-args 1.18.26 3.1.8
        prints "<version> <upstream ref> <active toolchain>" per line, for the image build step.
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


def _main(argv: list[str]) -> int:
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
