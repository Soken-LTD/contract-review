"""Sandboxed repository fetch for Move sources (plan v4 07 section 4 `fetch`; 09 5.2).

Fetches the repository inside the `git-fetch` image via `repo_fetch.materialize_repo`,
which places the container on the `soken-egress-move` network (where the smokescreen proxy
resolves). A ref (commit, tag or MVR tag) is resolved to a commit id, which is recorded
(07 4: "the tag resolved to a commit"). The checkout is read back with lstat checks; only
Move package files are kept.

Peel check for annotated tags is performed inside the `soken-fetch` binary; for commit
refs the supervisor verifies that `resolved_commit` matches the requested SHA.
"""

from __future__ import annotations

import logging
import os
import re
import stat
from pathlib import Path

from soken_review.adapters.move.units import safe_store_path
from soken_review.sandbox import repo_fetch as _repo_fetch

logger = logging.getLogger(__name__)

REPO_URL_RE = re.compile(r"^https://(?:github\.com|gitlab\.com|codeberg\.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(?:\.git)?/?$")  # the hosts review_start and the materializer admit
REF_RE = re.compile(r"^(?![-/])[A-Za-z0-9._/@-]{1,120}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_KEEP = {".move", ".toml", ".lock"}
_MAX_FILES, _MAX_FILE, _MAX_TOTAL = 4000, 1024 * 1024, 64 * 1024 * 1024
_SKIP_DIRS = {".git", "build", "node_modules", "target", ".github"}


class FetchError(RuntimeError):
    pass


def fetch_repo(repo_url: str, ref: str, work: Path) -> tuple[dict[str, str], str]:
    """(files, resolved commit) for repo at ref.

    Routes through repo_fetch.materialize_repo on the Move egress network so that
    the smokescreen proxy hostname resolves correctly inside the fetch container.
    Raises FetchError on any failure (fail closed, no host fallback).

    Peel check: for annotated tag refs the soken-fetch binary verifies that the tag
    object peels to the fetched commit before writing resolved_commit to the manifest.
    For pinned commit refs (40-hex SHA) the supervisor additionally checks that
    resolved_commit equals the requested SHA (provenance guarantee).
    """
    url = repo_url.strip().rstrip("/")
    if not REPO_URL_RE.match(url):
        raise FetchError("repository url not allowed")
    if not REF_RE.match(ref):
        raise FetchError("ref not allowed")

    is_commit = bool(COMMIT_RE.match(ref))
    result = _repo_fetch.materialize_repo(
        url, work / "matrl", family="move",
        commit=ref if is_commit else None,
        ref=ref if not is_commit else None,
    )
    if not result.ok:
        raise FetchError(f"fetch failed ({result.error_code}): {result.manifest.get('error', {}).get('detail', '')}")

    resolved = result.manifest.get("resolved_commit", "")
    if not COMMIT_RE.match(resolved):
        raise FetchError("resolved_commit missing or invalid in fetch manifest")
    # For pinned commit refs: the supervisor verifies the fetched SHA matches the requested one.
    # This is the supervisor-side counterpart of the peel check: we recorded a specific commit,
    # so resolved_commit must equal exactly what was pinned.
    if is_commit and resolved != ref:
        raise FetchError(f"fetched commit {resolved!r} differs from the requested one {ref!r}")

    files = walk(result.src_dir)
    return files, resolved


def walk(root: Path) -> dict[str, str]:
    """Move package files under root (lstat, no symlinks, caps), keyed by safe store path."""
    files: dict[str, str] = {}
    total = 0
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            st = os.lstat(e.path)
            if stat.S_ISLNK(st.st_mode):
                continue
            if stat.S_ISDIR(st.st_mode):
                if e.name not in _SKIP_DIRS and not e.name.startswith("."):
                    stack.append(Path(e.path))
                continue
            if not stat.S_ISREG(st.st_mode) or Path(e.name).suffix not in _KEEP or st.st_size > _MAX_FILE:
                continue
            rel = safe_store_path(Path(e.path).relative_to(root).as_posix())
            if rel is None:
                continue
            total += st.st_size
            if len(files) >= _MAX_FILES or total > _MAX_TOTAL:
                raise FetchError("repository over the file caps")
            fd = os.open(e.path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as fh:
                files[rel] = fh.read().decode("utf-8", errors="replace")
    return files
