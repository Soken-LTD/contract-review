"""RustSec advisory-db snapshot for cargo-audit (06 3.3.1, 3.4).

The analysis container has no network, so the advisory database is fetched beforehand, pinned to
the commit in data/rustsec_db.json, by a sandboxed git fetch (09 3.1 fetch step, egress network),
then mounted read-only into the cargo-audit container. The supervisor records which snapshot each
analysis used and how old it is.

    python -m soken_review.adapters.solana.rustsec fetch    # fetch the pinned commit, print status
    python -m soken_review.adapters.solana.rustsec status

Layout: <root>/<commit>/ (the git checkout, mounted) and <root>/<commit>.meta.json (supervisor only,
never mounted). root = SOKEN_RUSTSEC_DB or ~/.cache/soken/rustsec-db.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOCK_PATH = Path(__file__).parent / "data" / "rustsec_db.json"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def pin() -> dict[str, Any]:
    data = json.loads(LOCK_PATH.read_text())
    if not _COMMIT_RE.match(data.get("commit", "")):
        raise ValueError("rustsec_db.json: commit must be 40 hex")
    return data


def root_dir() -> Path:
    env = os.environ.get("SOKEN_RUSTSEC_DB")
    return Path(env) if env else Path.home() / ".cache" / "soken" / "rustsec-db"


def db_dir() -> Path:
    return root_dir() / pin()["commit"]


def _meta_path() -> Path:
    return root_dir() / f"{pin()['commit']}.meta.json"


def _advisory_count(path: Path) -> int:
    crates = path / "crates"
    if not crates.is_dir() or crates.is_symlink():
        return 0
    return sum(1 for p in crates.rglob("*.md") if p.is_file() and not p.is_symlink())


def status(now: datetime | None = None) -> dict[str, Any] | None:
    """Snapshot record for the analysis: commit, commit date, fetch time, age, staleness. None when the
    pinned snapshot was not fetched (cargo-audit then does not run: rustsec_db_not_found)."""
    pinned = pin()
    try:
        meta = json.loads(_meta_path().read_text())
    except (OSError, ValueError):
        return None
    if meta.get("commit") != pinned["commit"] or not db_dir().is_dir():
        return None
    now = now or datetime.now(UTC)
    commit_date = datetime.fromisoformat(pinned["commit_date"])
    age_days = (now - commit_date).days
    return {
        "commit": pinned["commit"], "commit_date": pinned["commit_date"], "fetched_at": meta.get("fetched_at"),
        "advisories": meta.get("advisories"), "age_days": age_days,
        "stale": age_days > int(pinned.get("max_age_days", 30)), "path": str(db_dir()),
    }


def fetch() -> dict[str, Any]:
    """Fetch exactly the pinned commit in the git-fetch sandbox; record the snapshot (supervisor side).

    Uses materialize_repo (09 5.2) instead of the removed _run_git_in_sandbox: the soken-fetch
    binary inside the git-fetch container handles init/remote/fetch/checkout in one invocation.
    Result lands in job_dir/src; we rename it to db_dir() and clean up the temp job dir.
    """
    from soken_review.sandbox.repo_fetch import materialize_repo

    pinned = pin()
    if status() is not None:
        return status() or {}
    target = db_dir()
    if target.exists():
        raise RuntimeError(f"{target} exists without a matching record; remove it and fetch again")
    target.parent.mkdir(parents=True, exist_ok=True)
    job_dir = target.parent / f".rustsec-tmp-{os.getpid()}"
    try:
        res = materialize_repo(pinned["repo"], job_dir, "solana", commit=pinned["commit"])
        if not res.ok:
            detail = (res.manifest or {}).get("error") or {}
            raise RuntimeError(
                f"advisory-db fetch failed: {res.error_code}"
                + (f" / {detail}" if detail else "")
            )
        # res.src_dir == job_dir/src (the full checked-out repo); move it into the expected location
        res.src_dir.rename(target)
    finally:
        if job_dir.exists():
            shutil.rmtree(job_dir, ignore_errors=True)
    count = _advisory_count(target)
    if count == 0:
        raise RuntimeError("fetched advisory-db has no crates/*.md advisories")
    meta = {"commit": pinned["commit"], "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "advisories": count, "repo": pinned["repo"]}
    _meta_path().write_text(json.dumps(meta, indent=2))
    return status() or {}


def _main(argv: list[str]) -> int:
    if argv[:1] == ["fetch"]:
        print(json.dumps(fetch(), indent=2))
        return 0
    if argv[:1] == ["status"]:
        st = status()
        print(json.dumps(st, indent=2))
        return 0 if st else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
