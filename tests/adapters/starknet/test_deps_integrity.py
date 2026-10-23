"""The fetched Scarb cache is verified against the pinned Scarb.lock before any offline step
(adapters/starknet/deps_integrity.py; design note starknet-scarb-prefetch-design-2026-10-23).

Scarb's lock `checksum` is the sha256 of `registry/dl/<ident>/<name>-<version>.tar.zst` (stand,
oz-account-v3: `snforge_std-0.51.2.tar.zst` hashes to its lock row), so the supervisor can check
the archives the deps container fetched without re-implementing Scarb. A mismatch or a package the
lock does not name closes the build (`deps_integrity`); rows the lock cannot vouch for (git
sources) are named in build_result.json and the trust scan, never silently trusted."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.starknet import build as B
from soken_review.adapters.starknet import deps_integrity as D

IDENT = "scarbs.xyz-9djtpev4jug5q"
STD = b"snforge_std archive bytes"
PLUGIN = b"snforge_scarb_plugin archive bytes"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lock_text(*, std_checksum: str | None = _sha(STD), plugin_checksum: str | None = _sha(PLUGIN),
              git_row: bool = False) -> str:
    member = 'version = 1\n\n[[package]]\nname = "openzeppelin_presets"\nversion = "3.0.0"\ndependencies = [\n "snforge_std",\n]\n'
    rows = [member]
    for name, checksum in (("snforge_scarb_plugin", plugin_checksum), ("snforge_std", std_checksum)):
        row = f'[[package]]\nname = "{name}"\nversion = "0.51.2"\nsource = "registry+https://scarbs.xyz/"\n'
        if checksum is not None:
            row += f'checksum = "sha256:{checksum}"\n'
        rows.append(row)
    if git_row:
        rows.append('[[package]]\nname = "alexandria_math"\nversion = "0.5.1"\n'
                    'source = "git+https://github.com/keep-starknet-strange/alexandria.git?rev=abc123#abc123def"\n')
    return "\n".join(rows)


def make_cache(root: Path, archives: dict[str, bytes] | None = None, src_dirs: tuple[str, ...] = (),
               ident: str = IDENT) -> Path:
    """A scarb-cache like `scarb fetch` leaves it: dl archives, unpacked src dirs, the redb index."""
    archives = {"snforge_std-0.51.2": STD, "snforge_scarb_plugin-0.51.2": PLUGIN} if archives is None else archives
    dl = root / "registry" / "dl" / ident
    dl.mkdir(parents=True)
    for stem, data in archives.items():
        (dl / f"{stem}.tar.zst").write_bytes(data)
    src = root / "registry" / "src" / ident
    src.mkdir(parents=True)
    for stem in src_dirs:
        (src / stem).mkdir()
        (src / stem / ".scarb-ok").write_text("")
    cache = root / "registry" / "cache"
    cache.mkdir(parents=True)
    (cache / f"{ident}.v1.redb").write_bytes(b"\x00" * 64)
    (root / "registry" / "std" / "v2.13.1").mkdir(parents=True)
    (root / ".package-cache.lock").write_text("")
    return root


# ─── the verifier over a fixture cache ──────────────────────────────────────────────────────────

def test_matching_cache_verifies_every_registry_row(tmp_path: Path) -> None:
    cache = make_cache(tmp_path, src_dirs=("snforge_std-0.51.2",))
    v = D.verify_registry_cache(lock_text(), cache)
    assert v.ok and v.unverified == []
    assert v.verified == ["snforge_scarb_plugin@0.51.2", "snforge_std@0.51.2"]
    assert v.as_dict() == {"verified": v.verified, "unverified": [], "failures": []}


def test_checksum_mismatch_closes_the_build(tmp_path: Path) -> None:
    cache = make_cache(tmp_path, archives={"snforge_std-0.51.2": b"tampered", "snforge_scarb_plugin-0.51.2": PLUGIN})
    v = D.verify_registry_cache(lock_text(), cache)
    assert v.failures == ["checksum_mismatch:snforge_std@0.51.2"]
    assert v.verified == ["snforge_scarb_plugin@0.51.2"]


def test_missing_archive_closes_the_build(tmp_path: Path) -> None:
    cache = make_cache(tmp_path, archives={"snforge_scarb_plugin-0.51.2": PLUGIN})
    assert D.verify_registry_cache(lock_text(), cache).failures == ["archive_missing:snforge_std@0.51.2"]


def test_unlisted_archive_and_source_dir_close_the_build(tmp_path: Path) -> None:
    cache = make_cache(tmp_path, archives={"snforge_std-0.51.2": STD, "snforge_scarb_plugin-0.51.2": PLUGIN,
                                           "planted-9.9.9": b"x", "not an archive": b"y"},
                       src_dirs=("snforge_std-0.51.2", "planted-9.9.9"))
    v = D.verify_registry_cache(lock_text(), cache)
    assert v.failures == [f"unlisted_archive:{IDENT}/not an archive.tar.zst",
                          f"unlisted_archive:{IDENT}/planted-9.9.9.tar.zst",
                          f"unlisted_source_dir:{IDENT}/planted-9.9.9"]


def test_symlinked_archive_is_not_a_regular_file(tmp_path: Path) -> None:
    cache = make_cache(tmp_path, archives={"snforge_scarb_plugin-0.51.2": PLUGIN})
    real = tmp_path / "elsewhere.tar.zst"
    real.write_bytes(STD)
    os.symlink(real, cache / "registry" / "dl" / IDENT / "snforge_std-0.51.2.tar.zst")
    assert D.verify_registry_cache(lock_text(), cache).failures == ["archive_not_regular_file:snforge_std@0.51.2"]


def test_git_rows_are_unverified_not_fatal(tmp_path: Path) -> None:
    cache = make_cache(tmp_path)
    v = D.verify_registry_cache(lock_text(git_row=True), cache)
    assert v.ok and v.unverified == ["alexandria_math@0.5.1"]


def test_registry_row_without_checksum_is_unverified(tmp_path: Path) -> None:
    v = D.verify_registry_cache(lock_text(std_checksum=None), make_cache(tmp_path))
    assert v.ok and v.unverified == ["snforge_std@0.51.2"] and v.verified == ["snforge_scarb_plugin@0.51.2"]


def test_unknown_source_kind_closes_the_build(tmp_path: Path) -> None:
    text = lock_text() + '\n[[package]]\nname = "mystery"\nversion = "1.0.0"\nsource = "ftp://somewhere/"\n'
    assert D.verify_registry_cache(text, make_cache(tmp_path)).failures == ["unknown_source:mystery@1.0.0"]


def test_lock_missing_with_fetched_packages_closes_the_build(tmp_path: Path) -> None:
    v = D.verify_registry_cache(None, make_cache(tmp_path))
    assert v.failures[0] == "lock_missing:Scarb.lock"
    assert f"unlisted_archive:{IDENT}/snforge_std-0.51.2.tar.zst" in v.failures


def test_lock_missing_with_an_empty_cache_is_fine(tmp_path: Path) -> None:
    (tmp_path / "registry" / "std" / "v2.13.1").mkdir(parents=True)
    assert D.verify_registry_cache(None, tmp_path).ok
    assert D.verify_registry_cache("not = toml = at all", tmp_path).ok


def test_unparsable_lock_with_fetched_packages_closes_the_build(tmp_path: Path) -> None:
    v = D.verify_registry_cache("[[package]\nname = ", make_cache(tmp_path))
    assert v.failures[0] == "lock_unparsable:Scarb.lock"


def test_parse_lock_rejects_malformed_rows() -> None:
    assert D.parse_lock('[[package]]\nname = "Bad Name"\nversion = "1"\nsource = "registry+x"\n') is None
    assert D.parse_lock(lock_text()) is not None and len(D.parse_lock(lock_text())) == 2


# ─── build(): the check sits between the deps step and the first offline step ──────────────────

FILES = {
    "Scarb.toml": '[package]\nname = "openzeppelin_presets"\nversion = "3.0.0"\n\n[dependencies]\n'
                  'starknet = "2.13.1"\n\n[dev-dependencies]\nsnforge_std = "0.51.2"\n',
    "src/lib.cairo": "mod account;\n",
    "Scarb.lock": lock_text(),
}


def _candidate(files: dict[str, str] = FILES) -> Candidate:
    return Candidate(provider="repo", files=dict(files), sha256="0" * 64, language="cairo",
                     compiler=Compiler("2.13.1", "sierra_program"), settings={"package_dir": "", "profile": "release"},
                     std_json_input=None, entry_contract=None)


def _wire(monkeypatch, work_dir: Path, fetched: dict[str, bytes] | None = None) -> list[str]:
    """Every container run stubbed; `run_deps` populates the cache like `scarb fetch` would."""
    ran: list[str] = []
    monkeypatch.setenv("SOKEN_SANDBOX_DEV_PERMS", "1")
    monkeypatch.setenv("SOKEN_SANDBOX_RUNTIME", "runc")
    monkeypatch.setattr(B.shutil, "which", lambda _n: "/usr/bin/docker")
    monkeypatch.setattr(B, "image_for", lambda _v: "ghcr.io/soken-ltd/starknet-build@sha256:" + "ab" * 32)
    monkeypatch.setattr(B, "probe_cairo_version", lambda _i, _w: "2.13.1")

    def fake_deps(_image, wd, _workdir):
        ran.append("deps")
        make_cache(wd / "scarb-cache", archives=fetched)

    def fake_offline(_image, _wd, _workdir, command, _wall, **_kw):
        ran.append(" ".join(command))
        return 0, "Finished release\n"

    monkeypatch.setattr(B, "run_deps", fake_deps)
    monkeypatch.setattr(B, "run_metadata", lambda *_a: (ran.append("metadata"), (0, "{}"))[1])
    monkeypatch.setattr(B, "run_offline", fake_offline)
    return ran


def test_build_runs_offline_only_on_a_verified_cache(tmp_path: Path, monkeypatch) -> None:
    ran = _wire(monkeypatch, tmp_path)
    result = B.build(_candidate(), tmp_path, "2.13.1")
    assert result.status == "ok" and result.build_notes == {"deps_unverified": []}
    assert ran == ["deps", "metadata", "scarb --offline --profile release build --package openzeppelin_presets"]
    verify = json.loads((tmp_path / "host" / "deps_verify.json").read_text())
    assert verify["verified"] == ["snforge_scarb_plugin@0.51.2", "snforge_std@0.51.2"] and verify["failures"] == []


def test_build_closes_on_a_tampered_archive_before_any_offline_step(tmp_path: Path, monkeypatch) -> None:
    ran = _wire(monkeypatch, tmp_path, fetched={"snforge_std-0.51.2": b"tampered", "snforge_scarb_plugin-0.51.2": PLUGIN})
    result = B.build(_candidate(), tmp_path, "2.13.1")
    assert (result.status, result.reason) == ("failed", "deps_integrity")
    assert result.stderr_head == "checksum_mismatch:snforge_std@0.51.2"
    assert ran == ["deps"]                                              # no metadata probe, no build
    assert json.loads((tmp_path / "host" / "build_status.json").read_text()) == {"status": "failed", "reason": "deps_integrity"}


def test_build_closes_on_a_package_the_lock_does_not_name(tmp_path: Path, monkeypatch) -> None:
    ran = _wire(monkeypatch, tmp_path, fetched={"snforge_std-0.51.2": STD, "snforge_scarb_plugin-0.51.2": PLUGIN,
                                                "planted-9.9.9": b"x"})
    result = B.build(_candidate(), tmp_path, "2.13.1")
    assert (result.status, result.reason) == ("failed", "deps_integrity")
    assert result.stderr_head == f"unlisted_archive:{IDENT}/planted-9.9.9.tar.zst" and ran == ["deps"]


def test_build_flags_unverifiable_rows_and_keeps_the_inputs_untrusted(tmp_path: Path, monkeypatch) -> None:
    files = {**FILES, "Scarb.lock": lock_text(git_row=True),
             "Scarb.toml": FILES["Scarb.toml"] + 'alexandria_math = { git = "https://github.com/keep-starknet-strange/alexandria.git", rev = "abc123" }\n'}
    _wire(monkeypatch, tmp_path)
    cand = _candidate(files)
    result = B.build(cand, tmp_path, "2.13.1")
    assert result.status == "ok" and result.build_notes == {"deps_unverified": ["alexandria_math@0.5.1"]}
    assert cand.untrusted_inputs is True
    trust = json.loads((tmp_path / "host" / "trust_scan.json").read_text())
    assert trust["untrusted"] is True and "deps_unverified:alexandria_math@0.5.1" in trust["reasons"]


def test_build_uses_the_pinned_lock_not_the_tree_copy(tmp_path: Path, monkeypatch) -> None:
    """The deps container may rewrite tree/Scarb.lock; the check reads the pinned text."""
    ran: list[str] = []
    _wire(monkeypatch, tmp_path)

    def deps_rewriting_lock(_image, wd, _workdir):
        ran.append("deps")
        make_cache(wd / "scarb-cache")
        (wd / "tree" / "Scarb.lock").write_text(lock_text(std_checksum="00" * 32))      # container's view

    monkeypatch.setattr(B, "run_deps", deps_rewriting_lock)
    result = B.build(_candidate(), tmp_path, "2.13.1")
    assert result.status == "ok"                                        # pinned lock matches the archives
    trust = json.loads((tmp_path / "host" / "trust_scan.json").read_text())
    assert "lock_changed_by_resolution:after_deps" in trust["reasons"]  # and the rewrite is still recorded


# ─── build(): host admission happens before any container ──────────────────────────────────────

def test_build_is_refused_up_front_on_a_small_host(tmp_path: Path, monkeypatch) -> None:
    from soken_review.sandbox import profile as P

    ran = _wire(monkeypatch, tmp_path)
    P.configure_host_capacity(14336, physical_mb=3915)
    result = B.build(_candidate(), tmp_path, "2.13.1")
    assert (result.status, result.reason) == ("failed", "host_capacity")
    assert result.stderr_head == "insufficient_host_memory (need 8192 MiB, host 3915 MiB)"
    assert result.build_notes["host_capacity"]["need_mb"] == 8192 and ran == []
    status = json.loads((tmp_path / "host" / "build_status.json").read_text())
    assert status["reason"] == "host_capacity" and status["detail"]["host_mb"] == 3915
    assert not (tmp_path / "tree").exists()                             # nothing written for the sandbox


def test_docker_argv_backstop_refuses_a_direct_offline_run(tmp_path: Path, monkeypatch) -> None:
    from soken_review.sandbox import profile as P

    P.configure_host_capacity(14336, physical_mb=3915)
    monkeypatch.setattr(B.subprocess, "run", lambda *_a, **_k: pytest.fail("no container may start"))
    monkeypatch.setenv("SOKEN_SANDBOX_RUNTIME", "runc")
    with pytest.raises(P.HostCapacityError):
        B.run_offline("img@sha256:" + "ab" * 32, tmp_path, "/work/tree", ["scarb", "--offline", "build"], 10)
    # The deps class (2 GiB) still runs on that host.
    monkeypatch.setattr(B.subprocess, "run", lambda argv, **_k: subprocess.CompletedProcess(argv, 0, stdout=b"{}", stderr=b""))
    assert B.run_metadata("img@sha256:" + "ab" * 32, tmp_path, "/work/tree") == (0, "{}")
