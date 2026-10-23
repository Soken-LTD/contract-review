"""Non-EVM repo mode (road-to-prod item 4): a repo-only job whose tree holds Scarb.toml or
Move.toml is handed from the EVM fetch to its family runner on the same step, with the chain
persisted; an unrecognised tree ends in insufficient_source with the reason in error_detail.
Also: the Starknet and Move fetches pin on the supervisor-resolved sha, and the Aptos repo
candidate honours `package_dir`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.sandbox.repo_fetch import FetchResult
from soken_review.worker.supervisor import Supervisor

SHA = "ab" * 20
SUI_MANIFEST = '[package]\nname = "counter"\nedition = "2024.beta"\n[dependencies]\nSui = { git = "https://github.com/MystenLabs/sui.git", rev = "x" }\n'
SCARB_MANIFEST = '[package]\nname = "token"\nversion = "0.1.0"\n'


def _conn_ctx() -> AsyncMock:
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    return conn


def _sup(tmp_path: Path) -> tuple[Supervisor, AsyncMock]:
    sup = object.__new__(Supervisor)
    sup._pin_root = tmp_path / "pins"
    sup._pool = MagicMock()
    sup._pool.connection = MagicMock(return_value=_conn_ctx())
    sup._mark_step = AsyncMock()
    repo_mock = AsyncMock()
    return sup, repo_mock


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    src = tmp_path / "repo_fetch" / "src"
    for rel, text in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return src


def _job(subdir: str | None = None) -> dict[str, Any]:
    args: dict[str, Any] = {"repo_url": "https://github.com/example/repo", "commit": SHA}
    if subdir:
        args["subdir"] = subdir
    return {"job_id": "job_FAMILY01", "chain": None, "address": None, "source_kind": "repo", "source_args": args}


async def _run(tmp_path: Path, files: dict[str, str], job: dict[str, Any], runner_patches: dict[str, Any]):
    sup, repo_mock = _sup(tmp_path)
    src = _tree(tmp_path, files)
    ok = FetchResult(exit_code=0, error_code="", retryable=False, src_dir=src,
                     manifest={"resolved_commit": SHA, "files": sorted(files)})
    step = {"id": 7, "job_id": job["job_id"], "step": "fetch", "seq": 0, "attempt": 1, "max_attempts": 3}
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.sandbox.repo_fetch.materialize_repo", return_value=ok), \
         patch("soken_review.worker.supervisor.repo_candidate_from_manifest", return_value=(None, "no_solidity_sources")), \
         patch.multiple("soken_review.worker.supervisor.Supervisor", **runner_patches):
        result = await sup._fetch_repo(step, job, tmp_path, job["source_args"], None, None, None)
    return result, repo_mock, sup


@pytest.mark.asyncio
async def test_scarb_tree_is_handed_to_the_starknet_runner(tmp_path: Path) -> None:
    calls: list[tuple[dict, dict]] = []

    async def fake_run_step(sup: Any, step: dict, job: dict) -> None:
        calls.append((step, job))

    with patch("soken_review.worker.starknet_steps.run_step", new=fake_run_step):
        result, repo_mock, _ = await _run(
            tmp_path, {"contracts/Scarb.toml": SCARB_MANIFEST, "contracts/src/lib.cairo": "mod a;"}, _job(),
            {"_run_move_step": AsyncMock()})
    assert result is None
    repo_mock.update_job_fields.assert_any_await("job_FAMILY01", chain="starknet")
    assert len(calls) == 1
    step, handed = calls[0]
    assert step["id"] == 7
    assert handed["chain"] == "starknet"
    assert handed["resolved_commit"] == SHA
    assert handed["source_args"]["subdir"] == "contracts"      # detected package dir, request had none
    repo_mock.transition.assert_not_awaited()                   # the family runner owns the outcome


@pytest.mark.asyncio
async def test_move_tree_is_handed_to_the_move_runner_with_its_flavour(tmp_path: Path) -> None:
    move_runner = AsyncMock()
    result, repo_mock, _ = await _run(tmp_path, {"Move.toml": SUI_MANIFEST, "sources/c.move": ""}, _job(),
                                      {"_run_move_step": move_runner})
    assert result is None
    repo_mock.update_job_fields.assert_any_await("job_FAMILY01", chain="sui")
    move_runner.assert_awaited_once()
    handed = move_runner.await_args.args[1]
    assert handed["chain"] == "sui" and handed["resolved_commit"] == SHA
    assert "subdir" not in handed["source_args"]               # root package: nothing to add


@pytest.mark.asyncio
async def test_requested_subdir_is_kept_over_detection(tmp_path: Path) -> None:
    move_runner = AsyncMock()
    files = {"a/Move.toml": SUI_MANIFEST, "b/Move.toml": SUI_MANIFEST}
    await _run(tmp_path, files, _job(subdir="b"), {"_run_move_step": move_runner})
    assert move_runner.await_args.args[1]["source_args"]["subdir"] == "b"


@pytest.mark.asyncio
async def test_unrecognised_tree_ends_in_insufficient_source_with_the_reason(tmp_path: Path) -> None:
    move_runner = AsyncMock()
    with patch("soken_review.worker.starknet_steps.run_step", new=AsyncMock()) as sn:
        result, repo_mock, _ = await _run(tmp_path, {"README.md": "docs only", "lib.rs": "fn main() {}"}, _job(),
                                          {"_run_move_step": move_runner})
    assert result is None
    move_runner.assert_not_awaited()
    sn.assert_not_awaited()
    assert not any(c.kwargs.get("chain") for c in repo_mock.update_job_fields.await_args_list)
    repo_mock.transition.assert_awaited_once()
    kwargs = repo_mock.transition.await_args.kwargs
    assert repo_mock.transition.await_args.args[1] == "insufficient_source"
    assert kwargs["error_code"] == "E_SOURCE_NOT_FOUND"
    assert kwargs["error_detail"] == {"stage": "repo_candidate", "detail": "no_solidity_sources",
                                      "repo_family": "no_manifest"}


@pytest.mark.asyncio
async def test_ambiguous_move_packages_list_the_manifests(tmp_path: Path) -> None:
    files = {"a/Move.toml": SUI_MANIFEST, "b/Move.toml": SUI_MANIFEST}
    _, repo_mock, _ = await _run(tmp_path, files, _job(), {"_run_move_step": AsyncMock()})
    detail = repo_mock.transition.await_args.kwargs["error_detail"]
    assert detail["repo_family"] == "ambiguous_package" and detail["manifests"] == ["a/Move.toml", "b/Move.toml"]


@pytest.mark.asyncio
async def test_detection_is_skipped_for_deployed_jobs(tmp_path: Path) -> None:
    """A repo tied to an EVM deployment stays an EVM failure: no family handoff."""
    move_runner = AsyncMock()
    job = _job()
    job["address"] = "0x" + "11" * 20
    with patch("soken_review.worker.supervisor._fetch_mod.fetch_source", new=AsyncMock(return_value=[])):
        sup, repo_mock = _sup(tmp_path)
        src = _tree(tmp_path, {"Move.toml": SUI_MANIFEST})
        ok = FetchResult(exit_code=0, error_code="", retryable=False, src_dir=src, manifest={"resolved_commit": SHA})
        step = {"id": 8, "job_id": job["job_id"], "step": "fetch", "seq": 0, "attempt": 1, "max_attempts": 3}
        with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
             patch("soken_review.sandbox.repo_fetch.materialize_repo", return_value=ok), \
             patch("soken_review.worker.supervisor.repo_candidate_from_manifest", return_value=(None, "no_solidity_sources")), \
             patch.object(Supervisor, "_run_move_step", move_runner):
            await sup._fetch_repo(step, job, tmp_path, job["source_args"], 1, job["address"], "0x60")
    move_runner.assert_not_awaited()
    assert repo_mock.transition.await_args.args[1] == "insufficient_source"


# ─── family fetches pin on the supervisor-resolved sha ───────────────────────────────────────

@pytest.mark.asyncio
async def test_starknet_fetch_uses_the_resolved_commit_over_a_short_request_commit(tmp_path: Path) -> None:
    from soken_review.worker import starknet_steps as S

    seen: dict[str, Any] = {}

    def fake_clone(repo_url: str, commit: str, out: Path) -> dict[str, str]:
        seen["commit"] = commit
        return {}                                   # empty clone: E_COMMIT_NOT_FOUND, after the pin check

    sup = MagicMock()
    sup._job_dir = MagicMock(return_value=tmp_path)
    finishes: list[dict] = []

    async def fake_finish(sup_: Any, step: dict, **kw: Any) -> None:
        finishes.append(kw)

    job = {"job_id": "job_SN1", "resolved_commit": SHA,
           "source_args": {"repo_url": "https://github.com/x/y", "commit": "abcdef1"}}
    with patch("soken_review.adapters.starknet.fetch.clone_repo", new=fake_clone), \
         patch.object(S, "_finish", new=fake_finish):
        await S._fetch(sup, {"id": 1}, job)
    assert seen["commit"] == SHA
    assert finishes[-1]["error_code"] == "E_COMMIT_NOT_FOUND"


@pytest.mark.asyncio
async def test_starknet_fetch_without_resolved_commit_still_requires_a_full_sha(tmp_path: Path) -> None:
    from soken_review.worker import starknet_steps as S

    finishes: list[dict] = []

    async def fake_finish(sup_: Any, step: dict, **kw: Any) -> None:
        finishes.append(kw)

    sup = MagicMock()
    sup._job_dir = MagicMock(return_value=tmp_path)
    job = {"job_id": "job_SN2", "source_args": {"repo_url": "https://github.com/x/y", "commit": "abcdef1"}}
    with patch.object(S, "_finish", new=fake_finish):
        await S._fetch(sup, {"id": 1}, job)
    assert finishes[-1]["error_code"] == "E_UNPINNED_REF"


def test_move_fetch_passes_the_resolved_commit_and_package_dir(tmp_path: Path) -> None:
    from soken_review.worker import move_steps as M

    seen: dict[str, Any] = {}

    class FakeAdapter:
        def fetch_source(self, j: dict, cs: dict) -> list:
            seen.update(j)
            return []

    job = {"job_id": "job_MV1", "chain": "sui", "source_kind": "repo", "resolved_commit": SHA,
           "source_args": {"repo_url": "https://github.com/x/y", "ref": "main", "subdir": "pkg/"}}
    with patch.object(M, "adapter", return_value=FakeAdapter()):
        assert M.fetch(job, tmp_path, tmp_path / "pins") is None
    assert seen["commit"] == SHA and seen["package_dir"] == "pkg"
    assert json.loads((tmp_path / "candidates.json").read_text()) == []


def test_aptos_repo_candidate_honours_package_dir(tmp_path: Path) -> None:
    from soken_review.adapters.aptos import fetch as F

    files = {"a/Move.toml": '[package]\nname = "a"\n', "a/sources/a.move": "module a::a {}",
             "b/Move.toml": '[package]\nname = "b"\n', "b/sources/b.move": "module b::b {}"}
    with patch.object(F.gitfetch, "fetch_repo", return_value=(files, SHA)):
        cand = F.candidate_from_repo("https://github.com/x/y", SHA, tmp_path, None, None, None, package_dir="b")
        assert cand.settings["units"][0] == {"name": "b", "dir": "b", "modules": None,
                                             "upgrade_policy": None, "upgrade_number": None}
        with pytest.raises(F.gitfetch.FetchError):
            F.candidate_from_repo("https://github.com/x/y", SHA, tmp_path, None, None, None)   # two packages, no hint
