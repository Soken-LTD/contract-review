"""Repo subdir jobs: workspace build input, nearest image, source-only leads (blind run 2026-10-25).

The Lock & Loan job (programs/locker of a Cargo workspace) failed with unsupported_toolchain: the
fetch kept only the subdir (no Cargo.lock, no workspace manifest, no path dependency) and no image
existed for its Solana version 2.2.1. These tests pin each part of the fix.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.adapters.solana import analyze as analyze_mod
from soken_review.adapters.solana import build as build_mod
from soken_review.adapters.solana import fetch, images
from soken_review.worker import solana_steps

ROOT_MANIFEST = '[workspace]\nresolver = "2"\nmembers = ["programs/*", "merkle-verify"]\n'
LOCK = 'version = 4\n\n[[package]]\nname = "solana-program"\nversion = "2.2.1"\n'
CRATE_MANIFEST = ('[package]\nname = "locker"\nversion = "0.5.0"\n\n[lib]\ncrate-type = ["cdylib", "lib"]\n'
                  'name = "locker"\n\n[dependencies]\nanchor-lang = "0.31.1"\n')
LIB_RS = """use anchor_lang::prelude::*;

#[program]
pub mod locker {
    use super::*;
    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let x = ctx.remaining_accounts.len();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(init_if_needed, payer = payer, space = 8)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub payer: Signer<'info>,
}
"""


def _tree(root: Path) -> None:
    files = {
        "Cargo.toml": ROOT_MANIFEST,
        "Cargo.lock": LOCK,
        "programs/locker/Cargo.toml": CRATE_MANIFEST,
        "programs/locker/src/lib.rs": LIB_RS,
        "merkle-verify/Cargo.toml": '[package]\nname = "merkle-verify"\nversion = "0.1.0"\n',
        "merkle-verify/src/lib.rs": "pub fn verify() {}\n",
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    (root / "artifacts").mkdir()
    (root / "artifacts" / "hook.so").write_bytes(b"\x7fELF" + b"\x00" * 60)


def test_walk_scope_keeps_workspace_for_subdir(tmp_path: Path) -> None:
    _tree(tmp_path)
    files = fetch._walk_scope(tmp_path, "programs/locker")
    assert sorted(files) == ["Cargo.toml", "src/lib.rs"]
    ws = files.workspace
    assert {"Cargo.toml", "Cargo.lock", "merkle-verify/src/lib.rs", "programs/locker/src/lib.rs"} <= set(ws)
    assert ws.unread_paths == ["artifacts/hook.so"]
    # no subdir: the walk is the root itself, nothing rides along
    assert fetch._walk_scope(tmp_path, None).workspace is None


def test_fetch_source_attaches_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _tree(tmp_path)
    monkeypatch.setattr(fetch, "_SBX_ROOT", tmp_path / ".sbx")
    monkeypatch.setattr(fetch, "_clone_repo", lambda url, commit, wd, subdir=None: fetch._walk_scope(tmp_path, subdir))
    monkeypatch.setattr(fetch, "_fetch_osec_verify", lambda pid: [])
    bundles = fetch.fetch_source({"repo_url": "https://github.com/o/r", "commit": "a" * 40,
                                  "subdir": "programs/locker"}, {})
    cand = bundles[0].candidates[0]
    assert sorted(cand.files) == ["Cargo.toml", "src/lib.rs"]
    assert cand.settings["subdir"] == "programs/locker"
    assert cand.settings["library_name"] == "locker"
    assert cand.settings["workspace_unread_paths"] == ["artifacts/hook.so"]
    assert "Cargo.lock" in cand._full_tree
    assert (cand.compiler.version, cand.compiler.version_pinned_by) == ("2.2.1", "lock")


def test_build_files_overlays_pin_on_workspace(tmp_path: Path) -> None:
    ws = tmp_path / "build_workspace.json"
    ws.write_text(json.dumps({"subdir": "programs/locker", "files": {
        "Cargo.toml": ROOT_MANIFEST, "Cargo.lock": LOCK,
        "programs/locker/src/lib.rs": "STALE", "programs/locker/src/old.rs": "GONE",
        "merkle-verify/src/lib.rs": "pub fn verify() {}\n"}}))
    pinned = {"Cargo.toml": CRATE_MANIFEST, "src/lib.rs": LIB_RS}
    out = solana_steps.build_files(pinned, ws, {})
    assert out["programs/locker/src/lib.rs"] == LIB_RS          # the reviewed bytes are the built bytes
    assert "programs/locker/src/old.rs" not in out              # nothing from the subdir but the pin
    assert out["Cargo.lock"] == LOCK and "merkle-verify/src/lib.rs" in out
    assert solana_steps.build_files(pinned, tmp_path / "absent.json", {}) is pinned


def test_pin_nsloc_and_build_detail() -> None:
    assert solana_steps.pin_nsloc({"src/lib.rs": "// c\nfn a() {}\n\nfn b() {}\n", "tests/t.rs": "fn t() {}\n"}) == 2
    assert solana_steps.build_detail("deps_failed", "a\nb\nerror: x\n") == "deps_failed: a | b | error: x"
    assert solana_steps.build_detail(None, None) == "failed"


def test_nearest_build_image() -> None:
    assert images.build_image("2.2.1") is None                   # no image of its own
    assert images.nearest_build_image("2.2.1").version == "3.1.8"  # oldest published not older
    assert images.nearest_build_image("9.0.0").version == "4.3.0"  # newer than all: the newest
    assert images.nearest_build_image("1.18.0").version == "1.18.26"
    assert images.nearest_build_image("bad") is None


def _workspace_candidate(**settings: Any) -> Candidate:
    files = {"Cargo.toml": ROOT_MANIFEST, "Cargo.lock": LOCK, "programs/locker/Cargo.toml": CRATE_MANIFEST,
             "programs/locker/src/lib.rs": LIB_RS, "merkle-verify/Cargo.toml": "[package]\nname = \"m\"\n",
             "merkle-verify/src/lib.rs": "pub fn verify() {}\n"}
    return Candidate(provider="repo", files=files, sha256="0" * 64, language="rust",
                     compiler=Compiler(version="2.2.1", version_pinned_by="lock"),
                     settings={"subdir": "programs/locker", "library_name": "locker", **settings},
                     std_json_input=None, entry_contract=None)


def test_do_build_uses_workspace_library_and_nearest_image(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def _fake_docker(candidate, src_dir, output_dir, host_dir, work_dir, image, meta):
        seen.update(meta=meta, src=sorted(p.relative_to(src_dir).as_posix() for p in src_dir.rglob("*") if p.is_file()))
        return BuildResult(candidate=candidate, status="ok", nsloc=1, work_dir=str(work_dir))

    monkeypatch.setattr(build_mod, "_build_docker", _fake_docker)
    monkeypatch.setattr(build_mod, "_DIRECT_BUILD", False)
    cand = _workspace_candidate(workspace_unread_paths=["artifacts/hook.so"])
    r = build_mod._do_build(cand, tmp_path / "w")
    assert r.status == "ok"
    meta = seen["meta"]
    assert meta["version"] == "2.2.1"
    assert (meta["image_match"], meta["image_version"]) == ("nearest", "3.1.8")
    assert (meta["library_name"], meta["crate_rel"], meta["ws_rel"]) == ("locker", "programs/locker", "")
    assert "Cargo.lock" in seen["src"] and "merkle-verify/src/lib.rs" in seen["src"]
    assert cand.untrusted_inputs is True                     # the workspace's committed .so is scanned


def test_declared_base_image_never_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(build_mod, "_DIRECT_BUILD", False)
    monkeypatch.setattr(images, "build_image", lambda v: None)
    cand = _workspace_candidate(verify_args=["--base-image", "solanafoundation/solana-verifiable-build:2.1.21"])
    r = build_mod._do_build(cand, tmp_path / "w")
    assert (r.status, r.reason) == ("failed", "unsupported_toolchain")


def test_analyze_without_build_runs_source_rules() -> None:
    cand = Candidate(provider="repo", files={"Cargo.toml": CRATE_MANIFEST, "src/lib.rs": LIB_RS}, sha256="0" * 64,
                     language="rust", compiler=None, settings={}, std_json_input=None, entry_contract=None)
    leads, static_map, _ = analyze_mod.analyze(BuildResult(candidate=cand, status="failed", reason="deps_failed"))
    assert leads, "source rules must still emit leads without a build"
    assert {lead["file"] for lead in leads} <= {"src/lib.rs", "Cargo.toml"}
    assert static_map["status"] == "degraded"
    assert static_map["not_run"] == ["cargo_audit", "clippy"]
    assert static_map["degraded_reasons"] == ["cargo_audit:build_deps_failed", "clippy:build_deps_failed"]


def test_scope_items_maps_workspace_paths_to_pin() -> None:
    files = {"src/lib.rs": "", "Cargo.toml": ""}
    items = [{"file": "programs/locker/src/lib.rs", "start": 3}, {"file": "merkle-verify/src/lib.rs", "start": 1},
             {"file": "/usr/local/cargo/registry/src/x/lib.rs", "start": 1}, {"file": "Cargo.lock", "start": 1}]
    out = analyze_mod.scope_items(items, files, "programs/locker")
    assert out == [{"file": "src/lib.rs", "start": 3}, {"file": "Cargo.toml", "start": 1}]
    assert analyze_mod.scope_items([{"file": "src/lib.rs"}], files) == [{"file": "src/lib.rs"}]


# ---------------------------------------------------------------------------
# Worker steps (solana_steps): what the job directory holds after fetch, analyze and map
# ---------------------------------------------------------------------------

def _sup(tmp_path: Path) -> Any:
    from unittest.mock import AsyncMock, MagicMock

    from soken_review.worker.supervisor import Supervisor

    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    sup = object.__new__(Supervisor)
    sup._pin_root = tmp_path / "pins"
    sup._pin_root.mkdir(parents=True, exist_ok=True)
    sup._pool = MagicMock()
    sup._pool.connection = MagicMock(return_value=conn)
    for name in ("_mark_step", "_after_fetch", "_after_build", "_after_analyze"):
        setattr(sup, name, AsyncMock())

    def _job_dir(job_id: str) -> Path:
        d = tmp_path / "jobs" / job_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    sup._job_dir = _job_dir
    return sup


@pytest.mark.asyncio
async def test_worker_repo_subdir_job_without_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """fetch keeps the workspace off the pin; a failed build still gives leads, a parsed map, nSLOC."""
    from unittest.mock import AsyncMock, patch

    _tree(tmp_path / "repo")
    monkeypatch.setattr(fetch, "_SBX_ROOT", tmp_path / ".sbx")
    monkeypatch.setattr(fetch, "_clone_repo",
                        lambda url, commit, wd, subdir=None: fetch._walk_scope(tmp_path / "repo", subdir))
    monkeypatch.setattr(fetch, "_fetch_osec_verify", lambda pid: [])
    sup = _sup(tmp_path)
    job_id = "job_REPOSUBDIR"
    job = {"job_id": job_id, "chain": "solana", "source_kind": "repo", "address": None,
           "source_args": {"repo_url": "https://github.com/o/r", "commit": "a" * 40, "subdir": "programs/locker"}}
    out_dir = sup._job_dir(job_id)
    with patch("soken_review.worker.solana_steps.JobRepo") as repo_cls:
        repo_cls.return_value = AsyncMock()
        await solana_steps._fetch_program(sup, {"id": 1, "job_id": job_id}, job, out_dir)
        cand_meta = json.loads((out_dir / "candidates.json").read_text())[0]
        assert "_full_tree" not in cand_meta and "files" not in cand_meta
        ws = json.loads((out_dir / solana_steps._WORKSPACE_FILE).read_text())
        assert ws["subdir"] == "programs/locker" and "Cargo.lock" in ws["files"]

        def _failed_build(self: Any, cand: Candidate) -> BuildResult:
            assert "programs/locker/src/lib.rs" in cand.files and "Cargo.lock" in cand.files
            return BuildResult(candidate=cand, status="failed", reason="deps_failed", stderr_head="error: offline")

        with patch("soken_review.adapters.solana.SolanaAdapter.build", _failed_build):
            await solana_steps._build_program(sup, {"id": 2, "job_id": job_id}, job, out_dir)
        build = json.loads((out_dir / "build_result.json").read_text())
        assert build["status"] == "failed" and build["nsloc"] > 0
        assert build["detail"] == "deps_failed: error: offline"

        await solana_steps._analyze_program(sup, {"id": 3, "job_id": job_id}, job, out_dir,
                                            sup._pin_root / job_id / "leads.json")
        leads = json.loads((sup._pin_root / job_id / "leads.json").read_text())
        assert leads and all(lead["file"] in ("src/lib.rs", "Cargo.toml") for lead in leads)

        with patch("soken_review.worker.solana_steps.persist_leads_from_pin", AsyncMock(return_value=len(leads))):
            await solana_steps._map(sup, {"id": 4, "job_id": job_id}, job)
    status = json.loads((sup._pin_root / job_id / "map" / "status.json").read_text())
    assert status == {"map_status": "partial", "build_detail": "deps_failed: error: offline", "build_status": "failed"}
    doc = json.loads((sup._pin_root / job_id / "map" / "map.json").read_text())
    assert [f["span"] for f in doc["semantic"]["functions"] if f["is_entry"]] == ["locker.claim"]
