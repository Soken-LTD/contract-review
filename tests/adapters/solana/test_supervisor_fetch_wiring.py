"""Regression tests for solana_steps._fetch_program argument wiring (fix/solana-fetch-args).

Root cause: _fetch_program built a plain dict `j` and passed it to SolanaAdapter().fetch_source,
but fetch_source read job fields via hasattr(job, "address") / job.address (attribute access).
Plain dicts do not expose their keys as attributes, so program_id and repo_url were always None
→ "no program_id and no repo_url" warning → every Solana job ended in insufficient_source.

These tests exercise the real supervisor fetch path and assert:
  (a) a deployed Solana job: the adapter receives program_id from the dict
  (b) a repo+deployment Solana job: the adapter receives program_id AND repo_url from the dict
  (c) the repo path fetches at the right commit and honours subdir (local git fixture, no network)
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROGRAM_ID = "Fvm8Z25vd1Yauj6GB4jsrW7jJyUdNYGeDCWYqcuTtDek"
COMMIT = "4f400beb3a7b912888fba214d8553f5368eab18c"
REPO_URL = "https://github.com/fraserbrownirl/agent-loans"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_bundle(program_id: str | None, repo_url: str | None):
    """Return a minimal SourceBundle-like object so _fetch_program records the pin."""
    from soken_review.adapters.base import Candidate, Compiler, SourceBundle, Target

    files = {"src/lib.rs": "// stub\n"}
    cand = Candidate(
        provider="repo",
        files=files,
        sha256="aa" * 32,
        language="rust",
        compiler=Compiler(version="1.75", version_pinned_by="lock"),
        settings={"framework": "native", "unread_paths": []},
        std_json_input=None,
        entry_contract=None,
        source_url=repo_url,
        fetched_at="2026-10-25T00:00:00+00:00",
    )
    target = Target(
        address=None,
        display_address=program_id,
        unit_label="agent-loans",
        repo_url=repo_url,
        commit=COMMIT,
        files=list(files.keys()),
        discovered_by="input",
    )
    return [SourceBundle(target=target, candidates=[cand])]


def _conn_ctx() -> AsyncMock:
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    return conn


def _make_sup(tmp_path: Path) -> Any:
    from soken_review.worker.supervisor import Supervisor

    sup = object.__new__(Supervisor)
    sup._pin_root = tmp_path / "pins"
    sup._pin_root.mkdir(parents=True, exist_ok=True)
    sup._pool = MagicMock()
    sup._pool.connection = MagicMock(return_value=_conn_ctx())
    sup._mark_step = AsyncMock()
    sup._after_fetch = AsyncMock()

    # Stub _job_dir to return a prepared output directory
    def _job_dir(job_id: str) -> Path:
        d = tmp_path / "jobs" / job_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    sup._job_dir = _job_dir
    return sup


def _write_chain_state(job_dir: Path, address: str | None = None) -> None:
    data: dict[str, Any] = {"kind": "program"}
    if address:
        data["address"] = address
    (job_dir / "chain_state.json").write_text(json.dumps(data), encoding="utf-8")


def _make_step(job_id: str) -> dict[str, Any]:
    return {"id": 1, "job_id": job_id, "step": "fetch", "seq": 0,
            "attempt": 1, "max_attempts": 3}


# ---------------------------------------------------------------------------
# (a) Deployed Solana job: adapter receives program_id from dict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_deployed_job_adapter_receives_program_id(tmp_path: Path) -> None:
    """Regression: _fetch_program passes a plain dict to fetch_source; the adapter must read
    job['address'] as program_id.  Before the fix, hasattr(dict, 'address') was always False."""
    job_id = "job_DEPLOYED_TEST"
    job: dict[str, Any] = {
        "job_id": job_id,
        "chain": "solana",
        "address": PROGRAM_ID,
        "source_kind": "deployed",
        "source_args": {},
    }
    sup = _make_sup(tmp_path)
    job_dir = sup._job_dir(job_id)
    _write_chain_state(job_dir, address=PROGRAM_ID)

    captured_j: list[dict] = []

    def _fake_fetch_source(j_arg: Any, cs_arg: Any) -> list:
        captured_j.append(j_arg if isinstance(j_arg, dict) else vars(j_arg))
        return _fake_bundle(PROGRAM_ID, None)

    with patch("soken_review.adapters.solana.SolanaAdapter.fetch_source", side_effect=_fake_fetch_source), \
         patch("soken_review.pinning.store.PinnedSource.from_files") as mock_pin, \
         patch("soken_review.db.job_repo.JobRepo") as mock_repo_cls:
        pin_inst = MagicMock()
        pin_inst.source_pin = "abc123"
        pin_inst.persist = MagicMock()
        mock_pin.return_value = pin_inst
        mock_repo_inst = AsyncMock()
        mock_repo_cls.return_value = mock_repo_inst

        from soken_review.worker import solana_steps
        step = _make_step(job_id)
        await solana_steps._fetch_program(sup, step, job, job_dir)

    assert captured_j, "fetch_source was not called"
    j = captured_j[0]
    # The adapter must have seen the program ID via dict access, not just None
    assert j.get("address") == PROGRAM_ID, (
        f"program_id not wired: address={j.get('address')!r}; "
        f"this is the regression for hasattr(dict,'address') → False"
    )


# ---------------------------------------------------------------------------
# (b) Repo+deployment Solana job: adapter receives program_id AND repo_url
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_repo_deployment_job_adapter_receives_program_id_and_repo_url(tmp_path: Path) -> None:
    """Regression: for a repo+deployment Solana job the adapter must receive both program_id
    (job['address'] set from source_args.deployment.address by review_start) and repo_url/commit
    from source_args.  Before the fix both were None because dict attribute access was used."""
    job_id = "job_REPO_DEPLOY_TEST"
    source_args = {
        "repo_url": REPO_URL,
        "commit": COMMIT,
        "subdir": "programs/locker",
        "deployment": {"chain": "solana", "address": PROGRAM_ID},
    }
    job: dict[str, Any] = {
        "job_id": job_id,
        "chain": "solana",
        # review_start copies deployment.address → jobs.address (start_status.py L281)
        "address": PROGRAM_ID,
        "source_kind": "repo",
        "source_args": source_args,
    }
    sup = _make_sup(tmp_path)
    job_dir = sup._job_dir(job_id)
    _write_chain_state(job_dir, address=PROGRAM_ID)

    captured_j: list[dict] = []

    def _fake_fetch_source(j_arg: Any, cs_arg: Any) -> list:
        captured_j.append(j_arg if isinstance(j_arg, dict) else vars(j_arg))
        return _fake_bundle(PROGRAM_ID, REPO_URL)

    with patch("soken_review.adapters.solana.SolanaAdapter.fetch_source", side_effect=_fake_fetch_source), \
         patch("soken_review.pinning.store.PinnedSource.from_files") as mock_pin, \
         patch("soken_review.db.job_repo.JobRepo") as mock_repo_cls:
        pin_inst = MagicMock()
        pin_inst.source_pin = "def456"
        pin_inst.persist = MagicMock()
        mock_pin.return_value = pin_inst
        mock_repo_inst = AsyncMock()
        mock_repo_cls.return_value = mock_repo_inst

        from soken_review.worker import solana_steps
        step = _make_step(job_id)
        await solana_steps._fetch_program(sup, step, job, job_dir)

    assert captured_j, "fetch_source was not called"
    j = captured_j[0]
    assert j.get("address") == PROGRAM_ID, (
        f"program_id not wired: address={j.get('address')!r}"
    )
    assert j.get("repo_url") == REPO_URL, (
        f"repo_url not wired: repo_url={j.get('repo_url')!r}"
    )
    assert j.get("commit") == COMMIT, (
        f"commit not wired: commit={j.get('commit')!r}"
    )
    assert j.get("subdir") == "programs/locker", (
        f"subdir not wired: subdir={j.get('subdir')!r}"
    )


# ---------------------------------------------------------------------------
# (b2) fetch_source itself accepts dict and reads fields correctly
# ---------------------------------------------------------------------------

def test_fetch_source_accepts_dict_job(tmp_path: Path, monkeypatch) -> None:
    """fetch_source must normalise a plain dict to attribute access (like Aptos/Sui adapters)."""
    from soken_review.adapters.solana import fetch

    clone_calls: list[tuple] = []

    def _fake_clone(repo_url, commit, work_dir, subdir=None):
        clone_calls.append((repo_url, commit, subdir))
        # Return a minimal rust source so _make_candidate succeeds
        files = fetch.SourceFiles({"src/lib.rs": "fn main(){}"})
        return files

    sbx = tmp_path / ".sbx"
    sbx.mkdir()
    monkeypatch.setattr(fetch, "_SBX_ROOT", sbx)
    monkeypatch.setattr(fetch, "_clone_repo", _fake_clone)
    monkeypatch.setattr(fetch, "_fetch_osec_verify", lambda program_id: [])

    job_dict = {
        "address": PROGRAM_ID,
        "repo_url": REPO_URL,
        "commit": COMMIT,
        "subdir": "programs/locker",
    }
    bundles = fetch.fetch_source(job_dict, {})
    assert bundles, "fetch_source returned empty for a dict job with valid repo_url"
    assert clone_calls, "_clone_repo was not called"
    url, commit, subdir = clone_calls[0]
    assert url == REPO_URL
    assert commit == COMMIT
    assert subdir == "programs/locker"


def test_fetch_source_dict_no_program_id_nor_repo_url_returns_empty() -> None:
    """A dict with neither address nor repo_url must return []."""
    from soken_review.adapters.solana import fetch

    bundles = fetch.fetch_source({"address": "not-a-solana-address"}, {})
    assert bundles == []


# ---------------------------------------------------------------------------
# (c) Repo path: fetch and pin at commit, honouring subdir (local git fixture)
# ---------------------------------------------------------------------------

def _make_local_git_repo(root: Path) -> str:
    """Create a minimal local git repo with files in root and in programs/locker/.
    Returns the commit SHA."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", str(root)],
                   capture_output=True, check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@test"],
                   capture_output=True, check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"],
                   capture_output=True, check=True)
    # Root-level file (should NOT appear in subdir-filtered walk)
    (root / "Cargo.toml").write_text('[workspace]\nmembers = ["programs/locker"]\n', encoding="utf-8")
    # Subdir file (should appear in subdir-filtered walk)
    sub = root / "programs" / "locker" / "src"
    sub.mkdir(parents=True)
    (sub / "lib.rs").write_text("// locker program\n", encoding="utf-8")
    (root / "programs" / "locker" / "Cargo.toml").write_text(
        '[package]\nname = "locker"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(root), "add", "."],
                   capture_output=True, check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-m", "init"],
                   capture_output=True, check=True)
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, check=True, text=True)
    return result.stdout.strip()


@pytest.mark.asyncio
async def test_repo_fetch_honours_subdir_with_local_fixture(tmp_path: Path, monkeypatch) -> None:
    """End-to-end: fetch_source in DIRECT mode clones at a pinned commit and scopes
    the file walk to `subdir`.  Files outside subdir must not appear in the candidate."""
    from soken_review.adapters.solana import fetch

    repo_root = tmp_path / "fixture_repo"
    sha = _make_local_git_repo(repo_root)
    repo_url = repo_root.as_uri()  # file:///...

    # Allow file:// scheme in tests (normally blocked in production)
    monkeypatch.setattr(fetch, "_safe_repo_url", lambda url: url)
    monkeypatch.setattr(fetch, "_fetch_osec_verify", lambda program_id: [])
    monkeypatch.setenv("SOKEN_SOLANA_DIRECT", "1")

    # Relax the git protocol restriction for local-file clones (test only)
    _orig_clone_direct = fetch._clone_direct

    def _permissive_clone_direct(src_url: str, commit: str | None, clone_dir: Path,
                                 subdir: str | None = None) -> dict[str, str] | None:
        """Same as _clone_direct but without protocol.file.allow=never."""
        try:
            if commit and fetch._COMMIT_RE.match(commit):
                subprocess.run(
                    ["git", "clone", "-c", "core.hooksPath=/dev/null",
                     "--no-recurse-submodules", "--quiet", "--depth=100",
                     src_url, str(clone_dir)],
                    capture_output=True, timeout=60, check=True,
                )
                subprocess.run(
                    ["git", "-C", str(clone_dir), "-c", "core.hooksPath=/dev/null",
                     "checkout", "--quiet", commit],
                    capture_output=True, timeout=30, check=True,
                )
            else:
                subprocess.run(
                    ["git", "clone", "-c", "core.hooksPath=/dev/null",
                     "--no-recurse-submodules", "--quiet", "--depth=1",
                     src_url, str(clone_dir)],
                    capture_output=True, timeout=60, check=True,
                )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None
        walk_root = clone_dir
        if subdir:
            sub = clone_dir / subdir.strip("/")
            if sub.is_dir():
                walk_root = sub
        return fetch._walk_source_files(walk_root)

    monkeypatch.setattr(fetch, "_clone_direct", _permissive_clone_direct)

    # Re-point _SBX_ROOT so TemporaryDirectory works inside tmp_path
    sbx = tmp_path / ".sbx"
    sbx.mkdir()
    monkeypatch.setattr(fetch, "_SBX_ROOT", sbx)

    bundles = fetch.fetch_source(
        {
            "address": PROGRAM_ID,
            "repo_url": repo_url,
            "commit": sha,
            "subdir": "programs/locker",
        },
        {},
    )

    assert bundles, "fetch_source returned empty for local git fixture"
    files = bundles[0].candidates[0].files
    # Files inside programs/locker/ must be present (paths relative to subdir root)
    assert any("lib.rs" in k for k in files), f"lib.rs not found in files: {list(files.keys())}"
    # The workspace-level Cargo.toml (content: [workspace]) must NOT appear.
    # After subdir scoping, any Cargo.toml is the package-level one ([package]), not the workspace.
    workspace_tomls = [
        k for k, v in files.items()
        if k.endswith("Cargo.toml") and "[workspace]" in v
    ]
    assert not workspace_tomls, (
        f"Workspace-level Cargo.toml leaked into subdir-filtered files: {workspace_tomls}"
    )
    # Pinned commit must match
    assert bundles[0].target.commit == sha, (
        f"commit not pinned: expected {sha!r}, got {bundles[0].target.commit!r}"
    )


def test_subdir_traversal_and_symlink_refused(tmp_path):
    from soken_review.adapters.solana.fetch import _resolve_subdir

    root = tmp_path / "clone"
    (root / "programs" / "locker").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside)
    assert _resolve_subdir(root, None) == root
    assert _resolve_subdir(root, "programs/locker") == root / "programs" / "locker"
    assert _resolve_subdir(root, "../outside") is None
    assert _resolve_subdir(root, "/etc") is None
    assert _resolve_subdir(root, "programs\\locker") is None
    assert _resolve_subdir(root, "link") is None
    assert _resolve_subdir(root, "missing/dir") is None
