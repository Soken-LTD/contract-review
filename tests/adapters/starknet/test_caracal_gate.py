"""Caracal compiler-version gate (adapters/starknet/caracal.py supported_sierra, analyze.run_caracal).

caracal v0.2.3 pins cairo-lang-sierra/-starknet 2.5.0 (Sierra 1.4.0) and `.unwrap()`s its
Sierra deserialisation; a class compiled by Cairo 2.13.1 (Sierra 1.7.0) is a panic after caracal's
own 7 to 13 minute workspace rebuild. The gate decides from the build step's artifact copies
(exact Sierra header) or the class's Cairo version before that build is spent, and the host memory
admission turns a refused container into a `not_run` reason beside it."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from soken_review.adapters.base import BuildResult, Candidate, Compiler
from soken_review.adapters.starknet import analyze as A
from soken_review.adapters.starknet import caracal as C
from soken_review.sandbox import profile as P

CARACAL_IMG = "ghcr.io/soken-ltd/starknet-caracal@sha256:" + "cd" * 32
EXPECTED_REASON = "unsupported_cairo_version (caracal 0.2.3 supports Sierra <= 1.4)"


def _result(tmp_path: Path, cairo: str | None) -> BuildResult:
    cand = Candidate(provider="repo", files={}, sha256="0" * 64, language="cairo",
                     compiler=Compiler(cairo, "sierra_program") if cairo else None,
                     settings={"package_dir": "packages/presets", "profile": "release"}, std_json_input=None,
                     entry_contract=None)
    return BuildResult(candidate=cand, status="ok", work_dir=str(tmp_path))


def _artifact(tmp_path: Path, sierra: tuple[int, int, int], cairo: tuple[int, int, int], name: str = "Account") -> None:
    """A supervisor artifact copy whose sierra_program header is (sierra, compiler) VersionIds."""
    host = tmp_path / "host"
    (host / "artifacts").mkdir(parents=True, exist_ok=True)
    header = [hex(n) for n in (*sierra, *cairo)] + ["0x1"] * 6
    (host / "artifacts" / f"{name}.contract_class.json").write_text(json.dumps({"sierra_program": header}))
    (host / "artifacts.json").write_text(json.dumps([{"contract": name, "file": f"artifacts/{name}.contract_class.json"}]))


def _docker(monkeypatch, calls: list[list[str]]) -> None:
    def fake_run(argv, **_kw):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=b"dead-code Impact: Low Confidence: Medium\nFunction helper defined in erc20::ERC20 is never used\n", stderr=b"")

    monkeypatch.setattr("soken_review.adapters.starknet.build.subprocess.run", fake_run)
    monkeypatch.setenv("SOKEN_SANDBOX_RUNTIME", "runc")
    monkeypatch.setenv("SOKEN_IMAGE_STARKNET_CARACAL", CARACAL_IMG)
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/docker")


# ─── reference data and the decision ────────────────────────────────────────────────────────────

def test_support_comes_from_the_image_lock() -> None:
    support = C.supported_sierra()
    assert support == C.SierraSupport(caracal="0.2.3", cairo_lang="2.5.0", sierra_max="1.4.0")
    assert support.reason() == EXPECTED_REASON


def test_support_is_unknown_when_the_lock_lacks_the_ceiling(monkeypatch) -> None:
    monkeypatch.setattr("soken_review.sandbox.profile.locked_tools", lambda _n: {"caracal": "0.2.3"})
    assert C.supported_sierra() is None
    monkeypatch.setattr("soken_review.sandbox.profile.locked_tools", lambda _n: {"caracal": "0.2.3", "cairo-lang": "x", "sierra": "1.4.0"})
    assert C.supported_sierra() is None


@pytest.mark.parametrize("sierra,cairo,verdict", [
    ("1.7.0", "2.13.1", False),      # OZ account v3, Cairo 2.13.1
    ("1.5.0", "2.6.0", False),
    ("1.4.0", "2.5.4", True),
    ("1.3.0", "2.3.1", True),        # older than the pinned crate: same major, lower minor
    ("2.0.0", "3.0.0", False),       # a new Sierra major is never readable by the old crate
    (None, "2.13.1", False),         # no artifact: the Cairo minor decides
    (None, "2.6.0", False),
    (None, "2.5.4", True),
    (None, "2.4.0", True),
    (None, None, None),
    ("not-a-version", "2.5.4", None),
    (None, "two.five", None),
])
def test_sierra_supported(sierra: str | None, cairo: str | None, verdict: bool | None) -> None:
    support = C.SierraSupport(caracal="0.2.3", cairo_lang="2.5.0", sierra_max="1.4.0")
    assert C.sierra_supported(support, sierra=sierra, cairo=cairo) is verdict


def test_built_sierra_version_reads_the_supervisor_copy(tmp_path: Path) -> None:
    assert A.built_sierra_version(tmp_path) is None
    _artifact(tmp_path, (1, 7, 0), (2, 13, 1))
    assert A.built_sierra_version(tmp_path) == "1.7.0"
    (tmp_path / "host" / "artifacts.json").write_text(json.dumps([{"contract": "x", "file": "../../etc/passwd"}]))
    assert A.built_sierra_version(tmp_path) is None


# ─── run_caracal: the gate fires before any container, with the exact reason ───────────────────

def test_sierra_1_7_class_is_not_run_before_caracals_build(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    _docker(monkeypatch, calls)
    _artifact(tmp_path, (1, 7, 0), (2, 13, 1))
    status, findings, reason = A.run_caracal(_result(tmp_path, "2.13.1"))
    assert (status, findings) == ("not_run", [])
    assert reason == EXPECTED_REASON + "; class Sierra 1.7.0"
    assert calls == []                                                   # the 7 to 13 minute build never started


def test_cairo_version_alone_gates_when_no_artifact_is_readable(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    _docker(monkeypatch, calls)
    status, _f, reason = A.run_caracal(_result(tmp_path, "2.13.1"))
    assert status == "not_run" and reason == EXPECTED_REASON + "; Cairo 2.13.1" and calls == []


def test_supported_class_runs_caracal(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    _docker(monkeypatch, calls)
    _artifact(tmp_path, (1, 4, 0), (2, 5, 4))
    status, findings, reason = A.run_caracal(_result(tmp_path, "2.5.4"))
    assert (status, reason) == ("ok", None) and [f["detector"] for f in findings] == ["dead-code"]
    (argv,) = calls
    assert argv[-3:] == ["caracal", "detect", "."]


def test_unknown_support_or_version_fails_closed(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    _docker(monkeypatch, calls)
    assert A.run_caracal(_result(tmp_path, None)) == ("not_run", [], "caracal_support_unknown")
    monkeypatch.setattr("soken_review.sandbox.profile.locked_tools", lambda _n: {})
    assert A.run_caracal(_result(tmp_path, "2.5.4")) == ("not_run", [], "caracal_support_unknown")
    assert calls == []


def test_analyze_records_the_gate_in_the_static_map(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    _docker(monkeypatch, calls)
    _artifact(tmp_path, (1, 7, 0), (2, 13, 1))
    _leads, static_map, _plan = A.analyze(_result(tmp_path, "2.13.1"), None, "2.13.1", run_stock_lint=False,
                                          with_caracal=True)
    tool = static_map["tools"]["caracal"]
    assert tool["status"] == "not_run" and tool["reason"] == EXPECTED_REASON + "; class Sierra 1.7.0"
    assert tool["version"] == "0.2.3" and "caracal" in static_map["not_run"] and static_map["status"] == "degraded"


# ─── host admission in the analyze step: a refused container is a not_run reason, no OOM ──────

def test_lint_and_caracal_report_insufficient_host_memory(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    _docker(monkeypatch, calls)
    _artifact(tmp_path, (1, 4, 0), (2, 5, 4))
    monkeypatch.setenv("SOKEN_IMAGE_STARKNET_BUILD_2_5_4", "ghcr.io/soken-ltd/starknet-build@sha256:" + "ab" * 32)
    P.configure_host_capacity(14336, physical_mb=3915)
    result = _result(tmp_path, "2.5.4")
    assert A.run_lint(result, "2.5.4") == ("not_run", [], "insufficient_host_memory (need 8192 MiB, host 3915 MiB)")
    assert A.run_caracal(result) == ("not_run", [], "insufficient_host_memory (need 8192 MiB, host 3915 MiB)")
    assert calls == []
    _leads, static_map, _plan = A.analyze(result, None, "2.5.4", run_stock_lint=True, with_caracal=True)
    assert static_map["tools"]["scarb-lint"]["reason"] == "insufficient_host_memory (need 8192 MiB, host 3915 MiB)"
    assert static_map["tools"]["caracal"]["reason"] == "insufficient_host_memory (need 8192 MiB, host 3915 MiB)"
    assert static_map["not_run"] == ["scarb-lint", "caracal"]
