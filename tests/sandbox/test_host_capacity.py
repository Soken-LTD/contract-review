"""Host memory admission (sandbox.profile): a container limit the host cannot honour is refused
before `docker run`, with the numbers in the reason, instead of the kernel's global OOM killer
reaping the step after the work is mostly done (stand, caracal on oz-account-v3, 2026-10-23:
`--memory=8g` on a 3915 MiB host, `scarb` killed at 2.8 GiB RSS after 20 minutes)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from soken_review.sandbox import profile as P

STAND_MEMINFO = (
    "MemTotal:        4009872 kB\n"
    "MemFree:         1816432 kB\n"
    "MemAvailable:    2768164 kB\n"
)
BUILD = P.StepLimits(cpus=4, memory="8g", pids=1024, max_file=512 * 1024 * 1024, min_memory="4g")
CEILING_ONLY = P.StepLimits(cpus=2, memory="4g", pids=256, max_file=1)   # evm build shape: ceiling, no floor
DEPS = P.StepLimits(cpus=2, memory="2g", pids=256, max_file=256 * 1024 * 1024)


def _meminfo(tmp_path: Path, text: str = STAND_MEMINFO) -> Path:
    path = tmp_path / "meminfo"
    path.write_text(text)
    return path


# ─── units ──────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("size,mb", [("8g", 8192), ("2g", 2048), ("512m", 512), ("1048576k", 1024),
                                     ("1073741824", 1024), ("1500k", 2), ("8G", 8192), ("256M", 256)])
def test_docker_memory_sizes_in_mib(size: str, mb: int) -> None:
    assert P.parse_memory_mb(size) == mb


@pytest.mark.parametrize("bad", ["", "8gb", "lots", "-1g", "8 gig"])
def test_docker_memory_size_rejects_other_strings(bad: str) -> None:
    with pytest.raises(ValueError):
        P.parse_memory_mb(bad)


def test_physical_memory_from_meminfo(tmp_path: Path) -> None:
    assert P.physical_memory_mb(_meminfo(tmp_path)) == 3915        # 4009872 kB // 1024


def test_physical_memory_falls_back_to_sysconf(tmp_path: Path, monkeypatch) -> None:
    def fake_sysconf(name: str) -> int:
        return {"SC_PHYS_PAGES": 4_000_000, "SC_PAGE_SIZE": 4096}[name]

    monkeypatch.setattr(os, "sysconf", fake_sysconf)
    assert P.physical_memory_mb(tmp_path / "absent") == 4_000_000 * 4096 // (1024 * 1024)


def test_physical_memory_unknown_when_nothing_answers(tmp_path: Path, monkeypatch) -> None:
    def no_sysconf(_name: str) -> int:
        raise ValueError("unknown configuration name")

    monkeypatch.setattr(os, "sysconf", no_sysconf)
    assert P.physical_memory_mb(_meminfo(tmp_path, "MemFree: 1 kB\n")) is None


def test_admission_cap_is_min_of_physical_share_and_budget() -> None:
    assert P.HostCapacity(physical_mb=3915, budget_mb=14336).admit_mb == int(3915 * 0.9) == 3523
    assert P.HostCapacity(physical_mb=65536, budget_mb=14336).admit_mb == 14336
    assert P.HostCapacity(physical_mb=None, budget_mb=14336).admit_mb == 14336      # unknown: budget only
    assert P.HostCapacity(physical_mb=None, budget_mb=14336).recorded_mb == 14336
    assert P.HostCapacity(physical_mb=3915, budget_mb=14336).recorded_mb == 3915


# ─── the gate ───────────────────────────────────────────────────────────────────────────────────

def test_configure_from_fake_meminfo_refuses_the_build_limit(tmp_path: Path) -> None:
    cap = P.configure_host_capacity(14336, meminfo=_meminfo(tmp_path))
    assert (cap.physical_mb, cap.budget_mb, cap.admit_mb) == (3915, 14336, 3523)
    assert cap.check(DEPS, "deps") == DEPS.memory                     # 2048 MiB fits
    assert cap.check(CEILING_ONLY, "build") == "3523m"                 # ceiling above the host: clamped
    with pytest.raises(P.HostCapacityError) as exc:
        cap.check(BUILD, "build")                                      # floor 4096 above the host: refused
    assert exc.value.reason == "insufficient_host_memory (need 8192 MiB, host 3915 MiB)"
    assert exc.value.detail() == {"reason": "insufficient_host_memory", "stage": "build", "need_mb": 8192,
                                  "host_mb": 3915, "cap_mb": 3523}


def test_budget_alone_caps_when_the_host_is_unmeasured(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(P, "physical_memory_mb", lambda _m=None: None)
    cap = P.configure_host_capacity(4096, meminfo=tmp_path / "absent")
    assert cap.check(CEILING_ONLY, "build") == "4g"                    # equal to the budget: untouched
    big = P.StepLimits(cpus=2, memory="6g", pids=256, max_file=1)
    assert cap.check(big, "analyze") == "4096m"                         # clamped to the budget
    assert cap.check(BUILD, "build") == "4096m"                         # floor 4096 fits the budget: clamped
    small = P.configure_host_capacity(2048, meminfo=tmp_path / "absent")
    with pytest.raises(P.HostCapacityError) as exc:
        small.check(BUILD, "build")                                    # floor above the budget: refused
    assert exc.value.reason == "insufficient_host_memory (need 8192 MiB, budget 2048 MiB)"


def test_docker_argv_refuses_before_building_the_command(tmp_path: Path) -> None:
    P.configure_host_capacity(14336, meminfo=_meminfo(tmp_path))
    with pytest.raises(P.HostCapacityError):
        P.docker_argv("build", "img@sha256:" + "ab" * 32, tmp_path, None, BUILD, {}, ["scarb", "build"])
    argv = P.docker_argv("build", "img@sha256:" + "ab" * 32, tmp_path, None, DEPS, {}, ["scarb", "fetch"])
    assert "--memory=2g" in argv
    clamped = P.docker_argv("build", "img@sha256:" + "ab" * 32, tmp_path, None, CEILING_ONLY, {}, ["solc"])
    assert "--memory=3523m" in clamped and "--memory-swap=3523m" in clamped


def test_docker_argv_admits_on_a_host_with_the_memory(tmp_path: Path) -> None:
    P.configure_host_capacity(14336, meminfo=_meminfo(tmp_path, "MemTotal:       16384000 kB\n"))
    argv = P.docker_argv("build", "img@sha256:" + "ab" * 32, tmp_path, None, BUILD, {}, ["scarb", "build"])
    assert "--memory=8g" in argv


def test_unconfigured_process_measures_on_first_use(monkeypatch) -> None:
    """Scripts that call adapters without a Supervisor still get the gate, with the env budget."""
    monkeypatch.setattr(P, "_HOST", None)
    monkeypatch.setenv("SOKEN_WORKER_RAM_MB", "6144")
    monkeypatch.setattr(P, "physical_memory_mb", lambda _m=None: 3915)
    cap = P.host_capacity()
    assert (cap.physical_mb, cap.budget_mb, cap.admit_mb) == (3915, 6144, 3523)
    assert P.host_capacity() is cap                                   # measured once


# ─── reference data for the adapters ───────────────────────────────────────────────────────────

def test_locked_tools_carry_caracals_sierra_ceiling() -> None:
    tools = P.locked_tools("starknet-caracal")
    assert tools["caracal"] == "0.2.3" and tools["cairo-lang"] == "2.5.0" and tools["sierra"] == "1.4.0"
    assert P.locked_tools("no-such-image") == {}
