"""Solana program provenance: the tier a built program gets, written to deployment.json
(matrix run 2026-10-26, agent-loans Fvm8Z25v...).

Before: the Solana build step wrote `"provenance": null`, never set jobs.tier, and a repo job with a
pinned commit and a deployment sat at tier D with finalize check F1 open. The address-only start
ended E_SOURCE_NOT_FOUND with no detail (no OtterSec entry, no security.txt in the ELF).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from soken_review.adapters.solana import fetch as fetch_mod
from soken_review.adapters.solana import images as solana_images
from soken_review.adapters.solana.map import deployment_doc
from soken_review.adapters.solana.onchain import DeployedProgram, security_txt_fields
from soken_review.worker import solana_steps

PROGRAM_ID = "Fvm8Z25vd1Yauj6GB4jsrW7jJyUdNYGeDCWYqcuTtDek"
BUILT = "4df5668e98342d476205174a1a61675a15d0ca5eee2fdb0279e16462bdb71811"
DEPLOYED = "1cc8d7e93e4ddd05909c8313eb6c7607038413e920b93ad2747b4e5d756d835f"
COMMIT = "4f400beb3a7b912888fba214d8553f5368eab18c"


# ---------------------------------------------------------------------------------- security.txt

def _elf_with_security_txt(**fields: str) -> bytes:
    body = b"".join(k.encode() + b"\x00" + v.encode() + b"\x00" for k, v in fields.items())
    return b"\x7fELF" + b"\x00" * 64 + b"=======BEGIN SECURITY.TXT V1=======" + body + \
        b"=======END SECURITY.TXT V1=======" + b"\x00" * 16


def test_security_txt_fields_parsed_from_the_elf():
    elf = _elf_with_security_txt(name="locker", source_code="https://github.com/fraserbrownirl/agent-loans",
                                 source_revision=COMMIT, contacts="email:x@y.z")
    assert security_txt_fields(elf) == {"name": "locker", "source_code": "https://github.com/fraserbrownirl/agent-loans",
                                        "source_revision": COMMIT, "contacts": "email:x@y.z"}
    assert security_txt_fields(b"\x7fELF" + b"\x00" * 100) is None


def test_chain_state_record_carries_hash_authority_and_security_txt():
    p = DeployedProgram(PROGRAM_ID, "BPFLoaderUpgradeab1e11111111111111111111111", 461620751, hash=DEPLOYED,
                        upgrade_authority="Auth111111111111111111111111111111111111111",
                        security_txt={"source_code": "https://github.com/o/r"})
    cs = p.as_chain_state()
    assert cs["kind"] == "program" and cs["address"] == PROGRAM_ID and cs["slot"] == 461620751
    assert cs["deployed_program_hash"] == DEPLOYED and cs["upgrade_authority"].startswith("Auth")
    assert cs["security_txt"] == {"source_code": "https://github.com/o/r"}


def test_fetch_source_takes_the_repo_from_security_txt(tmp_path: Path, monkeypatch):
    clone_calls: list[tuple] = []

    def _fake_clone(repo_url, commit, work_dir, subdir=None):
        clone_calls.append((repo_url, commit, subdir))
        return fetch_mod.SourceFiles({"src/lib.rs": "fn main(){}"})

    sbx = tmp_path / ".sbx"
    sbx.mkdir()
    monkeypatch.setattr(fetch_mod, "_SBX_ROOT", sbx)
    monkeypatch.setattr(fetch_mod, "_clone_repo", _fake_clone)
    monkeypatch.setattr(fetch_mod, "_fetch_osec_verify", lambda program_id: [])
    cs = {"kind": "program", "address": PROGRAM_ID, "security_txt": {
        "source_code": "https://github.com/fraserbrownirl/agent-loans/", "source_revision": COMMIT}}
    bundles = fetch_mod.fetch_source({"address": PROGRAM_ID}, cs)
    assert bundles and clone_calls == [("https://github.com/fraserbrownirl/agent-loans", COMMIT, None)]
    assert bundles[0].target.commit == COMMIT


def test_fetch_source_ignores_a_security_txt_url_off_the_allowlist(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(fetch_mod, "_fetch_osec_verify", lambda program_id: [])
    monkeypatch.setattr(fetch_mod, "_clone_repo", lambda *a, **k: pytest.fail("must not clone"))
    cs = {"security_txt": {"source_code": "git://evil.example/x", "source_revision": COMMIT}}
    assert fetch_mod.fetch_source({"address": PROGRAM_ID}, cs) == []


# ---------------------------------------------------------------------------------- deployment_doc

def _layout(image_match: str = "nearest", version: str = "2.2.1") -> dict[str, Any]:
    return {"version": version, "line": "3.1", "u_s1": "passed", "image_match": image_match,
            "image_version": "3.1.8" if image_match == "nearest" else version, "library_name": "locker"}


def _cand(untrusted: bool = False) -> dict[str, Any]:
    return {"provider": "repo", "sha256": "4d" * 32, "language": "rust",
            "compiler": {"version": "2.2.1", "version_pinned_by": "lock"},
            "settings": {"framework": "anchor", "subdir": "programs/locker", "library_name": "locker"},
            "untrusted_inputs": untrusted}


def _cs() -> dict[str, Any]:
    return {"kind": "program", "address": PROGRAM_ID, "slot": 461620751, "deployed_program_hash": DEPLOYED,
            "upgrade_authority": None}


class TestDeploymentDoc:
    def test_untrusted_inputs_on_a_nearest_image_is_tier_b_named(self):
        prov = fetch_mod.resolve_provenance(PROGRAM_ID, BUILT, [], None, untrusted_inputs=True,
                                            deployed_hash=DEPLOYED, version_line_passed=False)
        doc = deployment_doc(prov, candidate=_cand(True), chain_state=_cs(), address=PROGRAM_ID,
                             layout=_layout(), build_status="ok")
        assert doc["tier"] == "B"
        assert doc["dep"]["match"] == "not_checkable" and doc["dep"]["reason"] == "build_input_untrusted"
        assert doc["dep"]["contract"] == "locker"
        assert doc["dep"]["comparison"]["image_match"] == "nearest"
        assert any("nearest published image 3.1.8" in n for n in doc["dep"]["notes"])
        assert doc["code_hash"] == f"sha256:{DEPLOYED}" and doc["block"] == 461620751
        assert doc["unit"] == "slot" and doc["chain"] == "solana" and doc["address"] == PROGRAM_ID
        assert doc["candidate"]["untrusted_inputs"] is True

    def test_nearest_image_trusted_build_is_tier_b_not_rebuilt(self):
        prov = fetch_mod.resolve_provenance(PROGRAM_ID, BUILT, [], None, deployed_hash=DEPLOYED,
                                            version_line_passed=False)
        doc = deployment_doc(prov, candidate=_cand(), chain_state=_cs(), address=PROGRAM_ID,
                             layout=_layout(), build_status="ok")
        assert (doc["tier"], doc["dep"]["match"], doc["dep"]["reason"]) == ("B", "not_checkable", "source_not_rebuilt")
        assert "unsupported_toolchain" in doc["dep"]["notes"]

    def test_exact_image_equal_hash_is_tier_a(self):
        prov = fetch_mod.resolve_provenance(PROGRAM_ID, DEPLOYED, [], None, deployed_hash=DEPLOYED,
                                            version_line_passed=True)
        doc = deployment_doc(prov, candidate=_cand(), chain_state=_cs(), address=PROGRAM_ID,
                             layout=_layout("exact"), build_status="ok")
        assert (doc["tier"], doc["dep"]["match"], doc["dep"]["reason"]) == ("A", "exact", "match_rebuild")
        assert doc["dep"]["comparison"]["hash_equal"] is True and doc["dep"]["notes"] == []

    def test_declared_build_that_differs_is_tier_c(self):
        prov = fetch_mod.resolve_provenance(PROGRAM_ID, BUILT, [], None, deployed_hash=DEPLOYED,
                                            version_line_passed=True, build_declared=True)
        doc = deployment_doc(prov, candidate=_cand(), chain_state=_cs(), address=PROGRAM_ID,
                             layout=_layout("exact"), build_status="ok")
        assert (doc["tier"], doc["dep"]["match"]) == ("C", "mismatch")

    def test_no_deployment_is_tier_b_without_dep(self):
        doc = deployment_doc(None, candidate=_cand(), chain_state={"kind": "program"}, address=None,
                             layout=_layout(), build_status="ok")
        assert doc["tier"] == "B" and doc["dep"] is None and doc["code_hash"] is None

    def test_failed_build_with_a_deployment_is_tier_b_not_rebuilt(self):
        doc = deployment_doc(None, candidate=_cand(), chain_state=_cs(), address=PROGRAM_ID, layout=None,
                             build_status="failed")
        assert doc["tier"] == "B" and doc["dep"]["match"] == "not_checkable"
        assert doc["dep"]["notes"] == ["build_failed"] and doc["code_hash"] == f"sha256:{DEPLOYED}"


# ---------------------------------------------------------------------------------- worker steps

def _work(tmp_path: Path, *, image_match: str = "nearest", untrusted: bool = True, built: str = BUILT) -> Path:
    work = tmp_path / "build" / "tmpxyz"
    host = work / "host"
    host.mkdir(parents=True)
    (host / "program_hash.txt").write_text(built)
    (host / "build_meta.json").write_text(json.dumps(_layout(image_match)))
    (host / "so_name.txt").write_text("locker.so")
    if untrusted:
        (host / "untrusted_inputs.txt").write_text("artifacts/transfer_hook_counter.so")
    return work


def _job_dir(tmp_path: Path, *, chain_state: dict[str, Any] | None, cand: dict[str, Any] | None = None,
             no_candidate: bool = False) -> Path:
    out = tmp_path / "work" / "job_SOL0001"
    out.mkdir(parents=True)
    cand = None if no_candidate else (cand or _cand())
    (out / "candidates.json").write_text(json.dumps([cand] if cand else []))
    (out / "solana_kind.json").write_text(json.dumps({"kind": "program"}))
    if chain_state is not None:
        (out / "chain_state.json").write_text(json.dumps(chain_state))
    return out


def _result(work: Path, untrusted: bool = True) -> dict[str, Any]:
    return {"status": "ok", "reason": None, "nsloc": 3418, "work_dir": str(work), "untrusted_inputs": untrusted,
            "provenance": None, "detail": None}


def test_resolve_program_provenance_live_job_shape_is_tier_b(tmp_path: Path):
    """The live job: repo + deployment, nearest image 3.1.8 for 2.2.1, an unread .so in the workspace."""
    work = _work(tmp_path)
    out = _job_dir(tmp_path, chain_state=_cs())
    job = {"job_id": "job_SOL0001", "chain": "solana", "address": PROGRAM_ID, "resolved_commit": COMMIT,
           "source_kind": "repo"}
    doc = solana_steps.resolve_program_provenance(job, out, _result(work))
    assert doc["tier"] == "B" and doc["dep"]["reason"] == "build_input_untrusted"
    assert doc["dep"]["comparison"]["local_hash"] == BUILT and doc["dep"]["comparison"]["onchain_hash"] == DEPLOYED


def test_resolve_program_provenance_exact_image_is_tier_a(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(solana_images, "line_passed", lambda v: True)
    work = _work(tmp_path, image_match="exact", untrusted=False, built=DEPLOYED)
    out = _job_dir(tmp_path, chain_state=_cs())
    job = {"job_id": "job_SOL0001", "chain": "solana", "address": PROGRAM_ID, "source_kind": "deployed"}
    doc = solana_steps.resolve_program_provenance(job, out, _result(work, untrusted=False))
    assert doc["tier"] == "A" and doc["dep"]["match"] == "exact" and doc["code_hash"] == f"sha256:{DEPLOYED}"


def _fake_sup(tmp_path: Path, monkeypatch) -> tuple[Any, dict[str, Any]]:
    fields: dict[str, Any] = {}
    repo = MagicMock()
    repo.update_job_fields = AsyncMock(side_effect=lambda _j, **f: fields.update(f))
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.connection = MagicMock(return_value=conn)
    monkeypatch.setattr(solana_steps, "JobRepo", lambda _c: repo)
    sup = MagicMock()
    sup._pool = pool
    sup._pin_root = tmp_path / "pins"
    sup._job_dir = lambda job_id: tmp_path / "work" / job_id
    sup._mark_step = AsyncMock()
    sup._after_build = AsyncMock()
    sup._after_chain_state = AsyncMock()
    return sup, fields


@pytest.mark.asyncio
async def test_record_provenance_writes_deployment_json_and_sets_tier(tmp_path: Path, monkeypatch):
    sup, fields = _fake_sup(tmp_path, monkeypatch)
    work = _work(tmp_path)
    out = _job_dir(tmp_path, chain_state=_cs())
    job = {"job_id": "job_SOL0001", "chain": "solana", "address": PROGRAM_ID, "code_hash": None}
    prov = await solana_steps.record_provenance(sup, job, out, _result(work))
    doc = json.loads((out / "deployment.json").read_text())
    assert doc["tier"] == "B" and prov == {"tier": "B", "dep_match": "not_checkable", "dep_reason": "build_input_untrusted"}
    assert fields == {"tier": "B", "code_hash": DEPLOYED}


@pytest.mark.asyncio
async def test_build_restart_path_records_the_tier(tmp_path: Path, monkeypatch):
    """build_result.json exists (restart) and deployment.json does not: the tier is still set."""
    sup, fields = _fake_sup(tmp_path, monkeypatch)
    work = _work(tmp_path)
    out = _job_dir(tmp_path, chain_state=_cs())
    (out / "build_result.json").write_text(json.dumps(_result(work)))
    job = {"job_id": "job_SOL0001", "chain": "solana", "address": PROGRAM_ID, "source_kind": "repo"}
    await solana_steps._build(sup, {"id": 3, "job_id": "job_SOL0001", "step": "build", "seq": 0}, job)
    assert (out / "deployment.json").exists() and fields["tier"] == "B"
    sup._after_build.assert_awaited_once()


@pytest.mark.asyncio
async def test_chain_state_of_a_repo_job_with_a_deployment_reads_the_program(tmp_path: Path, monkeypatch):
    sup, _fields = _fake_sup(tmp_path, monkeypatch)
    out = tmp_path / "work" / "job_SOL0002"
    monkeypatch.setattr(solana_steps, "_program_state", lambda a: {**_cs(), "address": a})
    job = {"job_id": "job_SOL0002", "chain": "solana", "address": PROGRAM_ID, "source_kind": "repo"}
    await solana_steps._chain_state(sup, {"id": 1, "job_id": "job_SOL0002", "step": "chain_state", "seq": 0}, job)
    cs = json.loads((out / "chain_state.json").read_text())
    assert cs["kind"] == "program" and cs["deployed_program_hash"] == DEPLOYED and cs["slot"] == 461620751
    assert json.loads((out / "solana_kind.json").read_text()) == {"kind": "program"}
    sup._after_chain_state.assert_awaited_once()


@pytest.mark.asyncio
async def test_fetch_not_found_names_the_sources_checked(tmp_path: Path, monkeypatch):
    sup, _fields = _fake_sup(tmp_path, monkeypatch)
    out = _job_dir(tmp_path, chain_state=_cs(), no_candidate=True)
    terminal = AsyncMock()
    monkeypatch.setattr(solana_steps, "_terminal", terminal)
    from soken_review.adapters.solana import SolanaAdapter

    monkeypatch.setattr(SolanaAdapter, "fetch_source", lambda self, j, cs: [])
    job = {"job_id": "job_SOL0001", "chain": "solana", "address": PROGRAM_ID, "source_kind": "deployed",
           "source_args": {}}
    await solana_steps._fetch_program(sup, {"id": 2, "job_id": "job_SOL0001", "step": "fetch", "seq": 0}, job, out)
    kwargs = terminal.call_args.kwargs
    assert kwargs["error_code"] == "E_SOURCE_NOT_FOUND"
    assert kwargs["error_detail"]["reason"] == "NO_VERIFIED_BUILD"
    assert "OtterSec" in kwargs["error_detail"]["providers"] and kwargs["error_detail"]["security_txt"] is False


@pytest.mark.asyncio
async def test_backfill_tiers_sets_the_tier_of_a_ready_job_without_one(tmp_path: Path, monkeypatch):
    sup, fields = _fake_sup(tmp_path, monkeypatch)
    work = _work(tmp_path)
    out = _job_dir(tmp_path, chain_state={"kind": "program"})     # built before the chain read existed
    (out / "build_result.json").write_text(json.dumps(_result(work)))
    cur = AsyncMock()
    cur.__aenter__ = AsyncMock(return_value=cur)
    cur.__aexit__ = AsyncMock(return_value=False)
    cur.fetchall = AsyncMock(return_value=[("job_SOL0001",)])
    conn = sup._pool.connection.return_value
    conn.cursor = MagicMock(return_value=cur)
    sup._get_job = AsyncMock(return_value={"job_id": "job_SOL0001", "chain": "solana", "address": PROGRAM_ID,
                                           "state": "ready", "tier": None, "code_hash": None})
    monkeypatch.setattr(solana_steps, "_program_state", lambda a: _cs())
    assert await solana_steps.backfill_tiers(sup) == 1
    assert fields["tier"] == "B" and fields["code_hash"] == DEPLOYED
    assert json.loads((out / "chain_state.json").read_text())["deployed_program_hash"] == DEPLOYED
    assert json.loads((out / "deployment.json").read_text())["tier"] == "B"
