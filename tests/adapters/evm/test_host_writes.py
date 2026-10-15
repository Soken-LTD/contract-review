"""EVM-family analyze never follows what a container left in the job dir (09 3.5).

A build or analyze container has /work mounted read-write: any name there may be a planted
symlink to a host path. Records go to `<attempt>.host/`, container output is read through
sandbox/output.py, and Slither gets a host-owned read-only config.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from soken_review.adapters.evm import analyze as ea
from soken_review.adapters.evm.build import host_build_dir, write_host_build_copy, write_no_follow


def _attempt(tmp_path: Path) -> Path:
    work = tmp_path / "attempts" / "0"
    (work / "out").mkdir(parents=True)
    return work


def test_planted_analyze_symlink_is_removed_not_followed(tmp_path):
    work = _attempt(tmp_path)
    victim = tmp_path / "victim"
    victim.mkdir()
    (work / "analyze").symlink_to(victim)  # planted by the build container
    d = ea.prepare_analyze_dir(work)
    assert d.is_dir() and not d.is_symlink()
    (d / "x").write_text("y")
    assert list(victim.iterdir()) == []


def test_records_go_to_host_only_dir(tmp_path):
    work = _attempt(tmp_path)
    victim = tmp_path / "victim"
    victim.mkdir()
    (work / "analyze").symlink_to(victim)
    out = ea.write_records(work, [{"id": "LEAD-0001"}], {"status": "ok"}, {"entries": []})
    assert out == tmp_path / "attempts" / "0.host" / "analyze"
    assert json.loads((out / "leads.json").read_text()) == [{"id": "LEAD-0001"}]
    assert list(victim.iterdir()) == []


def test_symlinked_container_output_is_not_read(tmp_path):
    work = _attempt(tmp_path)
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"success": True, "results": {"detectors": []}}))
    d = ea.prepare_analyze_dir(work)
    (d / "slither_out.json").symlink_to(secret)
    assert ea.read_sandbox_json(d, "slither_out.json") is None
    assert ea._build_static_map(d) == {"status": "not_run"}
    (work / "out" / "input.json").symlink_to(secret)
    assert ea.build_input(work) is None  # work/out is never read; there is no host copy
    assert ea._extract_settings(work) == {}
    assert ea._materialize_sources(work, d / "proj") is False


def test_oversize_container_output_is_not_read(tmp_path):
    work = _attempt(tmp_path)
    d = ea.prepare_analyze_dir(work)
    (d / "slither_out.json").write_text(json.dumps({"success": True, "pad": "x" * 100}))
    assert ea.read_sandbox_json(d, "slither_out.json", cap=10) is None


def test_build_output_write_replaces_planted_link(tmp_path):
    work = _attempt(tmp_path)
    victim = tmp_path / "victim.json"
    victim.write_text("original")
    (work / "out" / "output.json").symlink_to(victim)
    write_no_follow(work / "out", "output.json", b"{}")
    assert victim.read_text() == "original"
    assert (work / "out" / "output.json").read_text() == "{}" and not (work / "out" / "output.json").is_symlink()


def test_build_output_dir_link_refused(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (work / "out").symlink_to(victim)
    with pytest.raises(OSError):
        write_no_follow(work / "out", "output.json", b"{}")
    assert list(victim.iterdir()) == []


def test_tool_config_is_host_owned_and_read_only(tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_SANDBOX_DEV_PERMS", "1")
    work = _attempt(tmp_path)
    mounts = ea.tool_config_mounts(work)
    assert (work.resolve(), "/work", True) in mounts  # the job tree is read-only
    assert (ea.sbx_dir(work).resolve(), ea.SBX_MOUNT, False) in mounts  # the only writable dir
    assert sum(1 for m in mounts if not m[2]) == 1
    cfg = [m for m in mounts if m[1] == ea.TOOL_CONFIG_MOUNT]
    assert cfg and cfg[0][2] is True
    assert cfg[0][0].parent.name == "0.host"
    assert json.loads((cfg[0][0] / "slither.config.json").read_text()) == {}


def test_slither_gets_config_file_and_mounts(tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_SANDBOX_DEV_PERMS", "1")
    work = _attempt(tmp_path)
    write_host_build_copy(work, {"sources": {"A.sol": {"content": "contract A {}"}}}, {})
    d = ea.prepare_analyze_dir(work)
    assert ea._materialize_sources(work, d / "proj")
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(ea, "_DIRECT_TOOLS", False)
    monkeypatch.setattr(ea.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(ea.subprocess, "run", fake_run)
    monkeypatch.setattr(ea, "_solc_cache_root", lambda: tmp_path)
    (tmp_path / "linux-amd64").mkdir()
    ea._run_slither(d / "proj", d, str(tmp_path / "linux-amd64" / "solc-0.8.0"), {}, "A.sol", image="img@sha256:" + "a" * 64)
    argv = seen["argv"]
    assert argv[argv.index("--config-file") + 1] == f"{ea.TOOL_CONFIG_MOUNT}/slither.config.json"
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    assert any(m.endswith(f"dst={ea.TOOL_CONFIG_MOUNT},readonly") for m in mounts)
    assert any(m.endswith("dst=/work,readonly") for m in mounts)
    assert any(m.endswith(f"dst={ea.SBX_MOUNT}") for m in mounts)
    assert argv[argv.index("--json") + 1].startswith(ea.SBX_MOUNT + "/")


@pytest.mark.parametrize("name", ["slither.config.json", "crytic_compile.config.json", "aderyn.toml", "foundry.toml"])
def test_tool_config_files_never_materialized(tmp_path, name):
    work = _attempt(tmp_path)
    write_host_build_copy(work, {"sources": {"A.sol": {"content": ""}, name: {"content": "{}"}}}, {})
    d = ea.prepare_analyze_dir(work)
    ea._materialize_sources(work, d / "proj")
    assert not list((d / "proj").rglob(name))


def test_host_build_copy_is_beside_not_inside_work(tmp_path):
    work = _attempt(tmp_path)
    write_host_build_copy(work, {"sources": {}}, {"contracts": {}})
    assert host_build_dir(work) == tmp_path / "attempts" / "0.host" / "build"
    assert ea.build_input(work) == {"sources": {}} and ea.build_output(work) == {"contracts": {}}
    (host_build_dir(work) / "input.json").unlink()
    (host_build_dir(work) / "input.json").symlink_to(tmp_path / "x.json")
    assert ea.build_input(work) is None


def test_sbx_survives_between_tools_of_one_run(tmp_path, monkeypatch):
    """Slither's report must still be there after Aderyn's mounts are prepared (live bug 2026-10-10:
    the second tool's mount setup wiped analyze/sbx and static_map read not_run)."""
    monkeypatch.setenv("SOKEN_SANDBOX_DEV_PERMS", "1")
    work = _attempt(tmp_path)
    ea.prepare_analyze_dir(work)
    ea.tool_config_mounts(work)
    (ea.sbx_dir(work) / "slither_out.json").write_text(json.dumps({"success": True, "results": {"detectors": []}}))
    ea.tool_config_mounts(work)  # Aderyn
    assert ea._build_static_map(work / "analyze")["status"] == "ok"
    victim = tmp_path / "victim"
    victim.mkdir()
    import shutil

    shutil.rmtree(ea.sbx_dir(work))
    ea.sbx_dir(work).symlink_to(victim)  # a planted link is replaced, never followed
    ea.tool_config_mounts(work)
    assert ea.sbx_dir(work).is_dir() and not ea.sbx_dir(work).is_symlink()
