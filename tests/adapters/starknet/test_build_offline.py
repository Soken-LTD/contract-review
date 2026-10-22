"""Offline Scarb runs must keep the fetched registry index usable (stand, oz-account-v3, 2026-10-22).

Scarb stores the registry index in a redb file under `scarb-cache/registry/cache/` and reopens it
read-write on every run. The supervisor's `scarb metadata` probe used to run under the 1 MiB
`scarb --version` file cap: redb could not write its clean-shutdown state, the next Scarb process
(the build) aborted the repair and recreated an empty index, and offline resolution then failed
with "cannot access the network in offline mode" for the first registry package. These tests pin
the argv the supervisor builds for every container that sees the cache, and caracal's Scarb mode
contract (own target dir, offline through the environment, no silent "nothing analysed").
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.starknet import analyze as A
from soken_review.adapters.starknet import build as B
from soken_review.adapters.starknet import caracal as C

BUILD_IMG = "ghcr.io/soken-ltd/starknet-build@sha256:" + "ab" * 32
CARACAL_IMG = "ghcr.io/soken-ltd/starknet-caracal@sha256:" + "cd" * 32

CARACAL_ALL_SKIPPED = (
    "Compiling with Scarb. Found Scarb.toml.\n"
    "Skipping analysing file /work/tree/packages/presets/target/dev/openzeppelin_presets_AccountUpgradeable"
    ".contract_class.json. Debug info not found. If the file has code ensure in Scarb.toml you have \n"
    "[cairo]\nsierra-replace-ids = true\n\n"
    "Skipping analysing file /work/tree/packages/presets/target/dev/openzeppelin_presets_ERC20Upgradeable"
    ".contract_class.json. Debug info not found. Ensure in Scarb.toml you have \n[cairo]\nsierra-replace-ids = true\n\n"
)
CARACAL_ONE_FINDING = "dead-code Impact: Low Confidence: Medium\nFunction helper defined in erc20::ERC20 is never used\n"


def _capture(monkeypatch: pytest.MonkeyPatch, stdout: bytes = b"{}") -> list[list[str]]:
    """Record every `docker run` argv the build module issues; no container starts."""
    calls: list[list[str]] = []

    def fake_run(argv, **_kw):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(B.subprocess, "run", fake_run)
    monkeypatch.setenv("SOKEN_SANDBOX_RUNTIME", "runc")
    monkeypatch.setenv("SOKEN_SANDBOX_DEV_PERMS", "1")
    return calls


def _env_of(argv: list[str]) -> dict[str, str]:
    pairs = [argv[i + 1] for i, a in enumerate(argv) if a == "--env"]
    return dict(p.split("=", 1) for p in pairs)


def _fsize(argv: list[str]) -> int:
    value = argv[argv.index("--ulimit") + 1]            # fsize=<soft>:<hard>
    assert value.startswith("fsize=")
    soft, hard = value.removeprefix("fsize=").split(":")
    assert soft == hard
    return int(soft)


def _mounts(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]


def _build_result(tmp_path: Path, package_dir: str = "packages/presets") -> BuildResult:
    cand = Candidate(provider="repo", files={}, sha256="0" * 64, language="cairo", compiler=None,
                     settings={"package_dir": package_dir, "profile": "release"}, std_json_input=None,
                     entry_contract=None)
    return BuildResult(candidate=cand, status="ok", work_dir=str(tmp_path))


# ─── the metadata probe: same work class as deps, never the 1 MiB version-probe cap ──────────────

def test_metadata_probe_runs_offline_with_a_writable_registry_index(tmp_path: Path, monkeypatch) -> None:
    calls = _capture(monkeypatch)
    rc, out = B.run_metadata(BUILD_IMG, tmp_path, "/work/tree/packages/presets")
    assert (rc, out) == (0, "{}")
    (argv,) = calls
    assert argv[-5:] == ["scarb", "--offline", "metadata", "--format-version", "1"]
    assert "--network=none" in argv
    # The redb index (3.5 MiB for one registry) is rewritten on every run: the file cap must be the
    # deps cap, not the 1 MiB of `scarb --version`, or the next Scarb run recreates an empty index.
    assert _fsize(argv) == B._DEPS_LIMITS.max_file
    assert _fsize(argv) > 64 * 1024 * 1024
    assert f"type=bind,src={tmp_path / 'scarb-cache'},dst=/work/scarb-cache" in _mounts(argv)   # read-write
    env = _env_of(argv)
    assert env["SCARB_OFFLINE"] == "true"
    assert env["SCARB_CACHE"] == "/work/scarb-cache" and env["CARGO_HOME"] == "/work/cargo-home"


def test_metadata_limits_are_not_the_probe_limits() -> None:
    assert B._METADATA_LIMITS.max_file >= B._DEPS_LIMITS.max_file
    assert B._METADATA_LIMITS.max_file > B._PROBE_LIMITS.max_file


def test_version_probe_keeps_its_small_cap_and_sees_no_cache(tmp_path: Path, monkeypatch) -> None:
    calls = _capture(monkeypatch, stdout=b"scarb 2.13.1 (abc 2026-01-01)\ncairo: 2.13.1 (https://crates.io/crates/cairo-lang-compiler/2.13.1)\nsierra: 1.7.0\n")
    assert B.probe_cairo_version(BUILD_IMG, tmp_path) == "2.13.1"
    (argv,) = calls
    assert _fsize(argv) == B._PROBE_LIMITS.max_file == 1024 * 1024
    assert _mounts(argv) == [f"type=bind,src={tmp_path / 'probe'},dst=/work/probe,readonly"]
    assert "SCARB_CACHE" not in _env_of(argv)


# ─── every offline run: --offline on the command and SCARB_OFFLINE for nested scarb ─────────────

def test_offline_build_command_and_environment(tmp_path: Path, monkeypatch) -> None:
    calls = _capture(monkeypatch)
    cmd = ["scarb", "--offline", "--profile", "release", "build", "--package", "openzeppelin_presets"]
    rc, _log = B.run_offline(BUILD_IMG, tmp_path, "/work/tree/packages/presets", cmd, 10)
    assert rc == 0
    (argv,) = calls
    assert argv[-len(cmd):] == cmd
    assert "--network=none" in argv and argv[argv.index("--workdir") + 1] == "/work/tree/packages/presets"
    env = _env_of(argv)
    assert env["SCARB_OFFLINE"] == "true" and env["SCARB_TARGET_DIR"] == "/work/output"
    assert _fsize(argv) == B._BUILD_LIMITS.max_file
    assert f"type=bind,src={tmp_path / 'output'},dst=/work/output" in _mounts(argv)


def test_offline_env_override_replaces_one_variable_only() -> None:
    env = B._offline_env({"SCARB_TARGET_DIR": "/work/tree/pkg/target"})
    assert env["SCARB_TARGET_DIR"] == "/work/tree/pkg/target"
    assert env["SCARB_OFFLINE"] == "true" and env["SCARB_CACHE"] == "/work/scarb-cache" and env["HOME"] == "/tmp"
    assert B._offline_env()["SCARB_TARGET_DIR"] == "/work/output"


# ─── caracal: own target dir, offline, and "nothing analysed" is not "no findings" ──────────────

def test_caracal_run_targets_its_own_dir_and_stays_offline(tmp_path: Path, monkeypatch) -> None:
    calls = _capture(monkeypatch, stdout=CARACAL_ONE_FINDING.encode())
    monkeypatch.setenv("SOKEN_IMAGE_STARKNET_CARACAL", CARACAL_IMG)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/docker")
    status, findings, reason = A.run_caracal(_build_result(tmp_path))
    assert (status, reason) == ("ok", None) and [f["detector"] for f in findings] == ["dead-code"]
    (argv,) = calls
    assert argv[-3:] == ["caracal", "detect", "."]
    assert argv[argv.index("--workdir") + 1] == "/work/tree/packages/presets"
    env = _env_of(argv)
    assert env["SCARB_TARGET_DIR"] == "/work/tree/packages/presets/target"   # where caracal reads target/dev
    assert env["SCARB_OFFLINE"] == "true"                                     # its `scarb build --workspace` has no --offline
    assert env["SCARB_CACHE"] == "/work/scarb-cache"


def test_caracal_target_dir_for_root_package() -> None:
    assert C.target_dir("/work/tree") == "/work/tree/target"
    assert C.target_dir("/work/tree/packages/presets/") == "/work/tree/packages/presets/target"


def test_caracal_all_classes_skipped_is_not_run(tmp_path: Path, monkeypatch) -> None:
    _capture(monkeypatch, stdout=CARACAL_ALL_SKIPPED.encode())
    monkeypatch.setenv("SOKEN_IMAGE_STARKNET_CARACAL", CARACAL_IMG)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/docker")
    assert A.run_caracal(_build_result(tmp_path)) == ("not_run", [], "sierra_debug_info_missing")


def test_caracal_findings_beside_skipped_classes_still_count(tmp_path: Path, monkeypatch) -> None:
    _capture(monkeypatch, stdout=(CARACAL_ALL_SKIPPED + CARACAL_ONE_FINDING).encode())
    monkeypatch.setenv("SOKEN_IMAGE_STARKNET_CARACAL", CARACAL_IMG)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/docker")
    status, findings, reason = A.run_caracal(_build_result(tmp_path))
    assert (status, reason) == ("ok", None) and len(findings) == 1


def test_skipped_files_counts_lines() -> None:
    assert C.skipped_files(CARACAL_ALL_SKIPPED) == 2
    assert C.skipped_files("") == 0
    assert C.skipped_files("\x1b[33mSkipping analysing file x.json. Debug info not found.\x1b[0m\n") == 1


# ─── a run that hits its wall is removed, not left running behind a dead client ─────────────────

def test_offline_run_names_its_container_and_removes_it_on_the_wall(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv, **kw):
        calls.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(B.subprocess, "run", fake_run)
    monkeypatch.setenv("SOKEN_SANDBOX_RUNTIME", "runc")
    rc, log = B.run_offline(BUILD_IMG, tmp_path, "/work/tree", ["scarb", "--offline", "build"], 1)
    assert (rc, log) == (124, "build_timeout")
    run_argv, rm_argv = calls
    name = run_argv[run_argv.index("--name") + 1]
    assert name.startswith("soken-stk-run-")
    assert rm_argv == ["docker", "rm", "-f", name]


def test_metadata_probe_removes_its_container_on_the_wall(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv, **kw):
        calls.append(list(argv))
        if argv[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(B.subprocess, "run", fake_run)
    monkeypatch.setenv("SOKEN_SANDBOX_RUNTIME", "runc")
    rc, _ = B.run_metadata(BUILD_IMG, tmp_path, "/work/tree")
    assert rc == 1
    run_argv, rm_argv = calls
    assert rm_argv == ["docker", "rm", "-f", run_argv[run_argv.index("--name") + 1]]


def test_caracal_wall_is_a_build_wall() -> None:
    assert A._CARACAL_WALL_S >= B._BUILD_WALL_S
