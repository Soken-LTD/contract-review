"""Upstream sources pinned in evals/corpus/sources.lock.yaml, and per-case source trees.

Datasets stay out of git (part 10 section 2.1: the corpus is internal evaluation data). Every
checkout here is a plain `git fetch --depth 1 <commit>` into a gitignored directory, so the
commit in the lock or the case file is the only thing that defines the content.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from ..contract import REPO_ROOT

LOCK_FILE = REPO_ROOT / "evals" / "corpus" / "sources.lock.yaml"
CORPUS_DIR = REPO_ROOT / "evals" / "corpus"
HELDOUT_DIR = REPO_ROOT / "evals" / "heldout"      # gitignored: `gate` cases (held-out ACL, 10 2.1)
UPSTREAM_DIR = REPO_ROOT / ".sbx" / "upstream"
TREES_DIR = REPO_ROOT / ".sbx" / "corpus-src"

# Manifest values (repo, commit, sparse paths) are untrusted: they never reach git as options or
# as a non-https transport (P0-GIT rules): https only via a protocol allow-list, no hooks, no
# fsmonitor, no submodules, `--` before positional values.
GIT_SAFE = (
    "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
    "-c", "http.followRedirects=false", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "submodule.recurse=false",
)
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
# Only github.com repos: the hosts of every pinned source (sources.lock.yaml) and case repo.
REPO_RE = re.compile(r"https://github\.com/[A-Za-z0-9_][A-Za-z0-9._-]*/[A-Za-z0-9_][A-Za-z0-9._-]*")
CASE_ID_RE = re.compile(r"[a-z]+-[a-z_]+-[0-9]{4}")   # case.v1 grammar (corpus.CASE_ID)
SPARSE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]*")


def load_lock(path: Path = LOCK_FILE) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in yaml.safe_load(path.read_text())["sources"]}


def check_repo(repo: Any) -> str:
    if not isinstance(repo, str) or not REPO_RE.fullmatch(repo) or ".." in repo:
        raise ValueError(f"repo must be a plain https:// URL, got {repo!r}")
    return repo


def check_commit(commit: Any) -> str:
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        raise ValueError(f"commit must be a full 40-hex sha, got {commit!r}")
    return commit


def git_run(*args: str, cwd: Path | None = None) -> str:
    proc = subprocess.run(
        ["git", *GIT_SAFE, *args], cwd=cwd, capture_output=True, text=True, timeout=600, check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"},
    )
    if proc.returncode:
        raise RuntimeError(f"git {' '.join(args[:3])}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def checkout(repo: str, commit: str, dest: Path, sparse: list[str] | None = None) -> Path:
    """Shallow checkout of exactly `commit` (no submodules). Idempotent when origin and HEAD match."""
    check_repo(repo)
    check_commit(commit)
    for path in sparse or []:
        if not isinstance(path, str) or not SPARSE_RE.fullmatch(path) or ".." in path:
            raise ValueError(f"sparse path {path!r} not allowed")
    if (dest / ".git").exists():
        try:
            same = git_run("remote", "get-url", "origin", cwd=dest).strip() == repo
            if same and git_run("rev-parse", "HEAD", cwd=dest).strip() == commit:
                return dest
        except RuntimeError:
            pass
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        git_run("init", "-q", cwd=dest)
        git_run("remote", "add", "--", "origin", repo, cwd=dest)
    else:
        git_run("remote", "set-url", "--", "origin", repo, cwd=dest)
    if sparse:
        git_run("sparse-checkout", "set", *sparse, cwd=dest)
    git_run("fetch", "-q", "--no-recurse-submodules", "--depth", "1", "--", "origin", commit, cwd=dest)
    git_run("checkout", "-q", "--force", "FETCH_HEAD", cwd=dest)
    head = git_run("rev-parse", "HEAD", cwd=dest).strip()
    if head != commit:
        raise RuntimeError(f"{repo}: fetched {head}, expected {commit}")
    return dest


def remote_head(repo: str) -> str:
    """Default-branch head of a public repo (recorded in the case when upstream pins nothing)."""
    out = git_run("ls-remote", "--", check_repo(repo), "HEAD")
    return check_commit(out.split()[0] if out.split() else "")


def fetch_upstream(source_id: str) -> Path:
    row = load_lock()[source_id]
    return checkout(row["repo"], row["commit"], UPSTREAM_DIR / source_id,
                    sparse=[row["path"]] if row.get("path") else None)


def case_dir(root: Path, case_id: Any) -> Path:
    """`root / case_id`, only for a case.v1 case_id and only inside `root` (no traversal)."""
    if not isinstance(case_id, str) or not CASE_ID_RE.fullmatch(case_id):
        raise ValueError(f"case_id {case_id!r} breaks <chain>-<origin>-<4 digits>")
    dest = root / case_id
    if dest.is_symlink() or not dest.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"{dest} escapes {root}")
    return dest


def fetch_case_tree(case: dict[str, Any], root: Path = TREES_DIR) -> Path:
    src = case["source"]
    return checkout(src["repo"], src["commit"], case_dir(root, case.get("case_id")))


def case_tree(case: dict[str, Any], root: Path = TREES_DIR) -> Path:
    """Directory that `root_cause_lines` paths are relative to: the checkout plus `subdir`."""
    sub = case["source"].get("subdir")
    if sub is not None and (not isinstance(sub, str) or not SPARSE_RE.fullmatch(sub) or ".." in sub):
        raise ValueError(f"subdir {sub!r} not allowed")
    base = case_dir(root, case.get("case_id"))
    return base / sub if sub else base
