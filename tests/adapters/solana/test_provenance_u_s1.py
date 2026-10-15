"""U-S1 build parity plumbing and the tier decision point (06 2.4, 3.3; 09 3.5).

The decision is tested where it is made (map_result -> resolve_provenance), with the inputs the
supervisor actually reads: host/program_hash.txt, host/build_meta.json, the chain-read deployed hash
and the trust flag. Live x86 proof: .github/workflows/solana-e2e.yml.
"""

from __future__ import annotations

import itertools
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from soken_review.adapters.base import BuildResult, Candidate, ChainValue
from soken_review.adapters.solana import images as solana_images
from soken_review.adapters.solana import rustsec
from soken_review.adapters.solana.build import (
    _library_dir,
    _manifests_under,
    _version_from_metadata,
    _workspace_dir,
    parse_verify_args,
)
from soken_review.adapters.solana.fetch import _walk_source_files, resolve_provenance
from soken_review.adapters.solana.map import map_result
from soken_review.adapters.solana.trust_scan import scan_candidate_files
from soken_review.sandbox.profile import StepLimits, docker_argv

H = "a" * 64
OTHER = "b" * 64
AUTH = "Auth111111111111111111111111111111111111111"


# ---------------------------------------------------------------------------
# verify args (06 3.3.3)
# ---------------------------------------------------------------------------

class TestVerifyArgs:
    def test_owner_linked_args_parse(self):
        v, bad = parse_verify_args(["--library-name", "wagon"])
        assert bad is None and v["library_name"] == "wagon" and v["cargo_args"] == []

    def test_base_image_arch_and_cargo_args(self):
        v, bad = parse_verify_args(["--library-name", "x", "--base-image", "solanafoundation/solana-verifiable-build:4.3.0",
                                    "--arch", "v3", "--", "--no-default-features"])
        assert bad is None
        assert (v["base_image"], v["arch"], v["cargo_args"]) == (
            "solanafoundation/solana-verifiable-build:4.3.0", "v3", ["--no-default-features"])

    @pytest.mark.parametrize("args", [
        ["--library-name", "pinocchio_token_program", '--cargo-build-sbf-args="--tools-version v1.54"'],
        ["--library-name", "oft", "--", "--config", "env.OFT_ID='x'"],
        ["--workspace-path", "a"],
        ["--library-name", "a b"],
        ["--mount-path", "../escape", "--library-name", "x"],
        ["--library-name"],
    ])
    def test_off_allowlist_is_untrusted_args(self, args):
        v, bad = parse_verify_args(args)
        assert v is None and bad == "untrusted_args"

    def test_mount_path_dot_is_root(self):
        v, bad = parse_verify_args(["--mount-path", ".", "--library-name", "staking"])
        assert bad is None and v["mount_path"] in ("", ".")


# ---------------------------------------------------------------------------
# library dir, workspace root and version, as solana-verify picks them
# ---------------------------------------------------------------------------

_TREE = {
    "Cargo.toml": '[workspace]\nmembers = ["programs/*"]\n[workspace.metadata.cli]\nsolana = "3.1.8"\n',
    "programs/wagon/Cargo.toml": '[package]\nname = "wagon"\nversion = "0.1.0"\n[lib]\nname = "wagon"\n',
    "programs/other-prog/Cargo.toml": '[package]\nname = "other-prog"\nversion = "0.1.0"\n',
    "Cargo.lock": '[[package]]\nname = "solana-program"\nversion = "1.18.26"\n',
}


def test_library_dir_by_lib_name_and_package_name():
    m = _manifests_under(_TREE, "")
    assert _library_dir(m, "wagon") == "programs/wagon"
    assert _library_dir(m, "other_prog") == "programs/other-prog"
    assert _library_dir(m, "missing") is None


def test_workspace_root_and_metadata_version_win_over_lock():
    m = _manifests_under(_TREE, "")
    assert _workspace_dir(m, "programs/wagon") == ""
    assert _version_from_metadata(m, "") == "3.1.8"   # solana-verify reads metadata before Cargo.lock


# ---------------------------------------------------------------------------
# image per version line
# ---------------------------------------------------------------------------

class TestImages:
    def test_placeholder_digest_is_no_image(self, monkeypatch):
        monkeypatch.delenv(solana_images.env_override_name("1.18.26"), raising=False)
        assert solana_images.build_image("1.18.26") is None

    def test_env_override_selects_derived_image(self, monkeypatch):
        monkeypatch.setenv(solana_images.env_override_name("3.1.8"), "soken/solana-build:3.1.8-ci")
        img = solana_images.build_image("3.1.8")
        assert img is not None and img.ref == "soken/solana-build:3.1.8-ci"
        assert (img.working_dir, img.cargo_home, img.line) == ("/build", "/usr/local/cargo", "3.1")
        assert img.upstream.endswith("8faa93c144f595756148a20fb0e6151eff4d869726e52520119406a944994101")

    def test_versions_without_image(self, monkeypatch):
        assert solana_images.build_image("9.9.9") is None
        assert solana_images.build_image("2.1.21") is None    # upstream only, no derived image
        assert solana_images.build_image("../x") is None

    def test_base_image_resolution(self):
        assert solana_images.version_from_base_image("solanafoundation/solana-verifiable-build:4.3.0") == "4.3.0"
        digest = "sha256:ec2e20e1f80607150a71e4c72adfe64be24347ed0b4fb741c32b34eaf7549a25"
        assert solana_images.version_from_base_image(f"solanafoundation/solana-verifiable-build@{digest}") == "1.18.26"
        assert solana_images.version_from_base_image("quay.io/ottersec/anchor@sha256:" + "0" * 64) is None
        assert solana_images.version_from_base_image("evil/solana-verifiable-build:4.3.0") is None

    def test_every_derived_image_records_paths_and_toolchain(self):
        for version, entry in solana_images.load_map()["images"].items():
            if "soken_image" not in entry:
                continue
            assert entry["working_dir"] == "/build" and entry["cargo_home"] == "/usr/local/cargo", version
            assert entry["active_toolchain"].endswith("-x86_64-unknown-linux-gnu"), version
            assert solana_images.version_line(version) in solana_images.load_map()["version_lines"]


_PINNED_IMG = "soken/solana-build@sha256:12fd4c0a0790f0fc41ef74b0cdb6bccc167ba6137eb1adb749bac649481c86bd"


def test_docker_argv_accepts_only_pinned_image_paths():
    lim = StepLimits(cpus=1, memory="1g", pids=8, max_file=1024)
    argv = docker_argv("build", _PINNED_IMG, Path("/w"), None, lim, {}, ["true"], workdir="/build/programs/x",
                       mounts=[(Path("/s"), "/build", True), (Path("/o"), "/build/target", False),
                               (Path("/c"), "/usr/local/cargo", False)], image_paths=("/build", "/usr/local/cargo"))
    assert "type=bind,src=/s,dst=/build,readonly" in argv and "/build/programs/x" in argv
    for bad_root in ("/usr", "/", "/etc", "/build/../etc", "rel"):
        with pytest.raises(ValueError):
            docker_argv("build", _PINNED_IMG, Path("/w"), None, lim, {}, ["true"],
                        mounts=[(Path("/s"), "/build", True)], image_paths=(bad_root,))
    with pytest.raises(ValueError):   # a path outside /work and outside the image paths
        docker_argv("build", _PINNED_IMG, Path("/w"), None, lim, {}, ["true"],
                    mounts=[(Path("/s"), "/etc/x", True)], image_paths=("/build",))


# ---------------------------------------------------------------------------
# walker: files it does not read still reach the trust scan
# ---------------------------------------------------------------------------

def test_walker_reports_unread_binaries_and_cargo_config(tmp_path):
    (tmp_path / "programs" / "p" / "src").mkdir(parents=True)
    (tmp_path / "programs" / "p" / "src" / "lib.rs").write_text("pub fn f() {}\n")
    (tmp_path / "programs" / "fixture.so").write_bytes(b"\x7fELFxxxx")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "blob.bin").write_bytes(b"\x7fELF\x02")       # ELF without an object extension
    (tmp_path / ".cargo").mkdir()
    (tmp_path / ".cargo" / "config.toml").write_text('[build]\nrustflags = ["-C", "link-arg=evil.o"]\n')
    (tmp_path / "logo.png").write_bytes(b"\x89PNG")
    files = _walk_source_files(tmp_path)
    assert "programs/p/src/lib.rs" in files
    assert sorted(files.unread_paths) == [".cargo/config.toml", "programs/fixture.so", "tests/blob.bin"]
    untrusted, reasons = scan_candidate_files(files, files.unread_paths)
    assert untrusted and len(reasons) == 3


# ---------------------------------------------------------------------------
# the decision point
# ---------------------------------------------------------------------------

def _result(tmp_path: Path, *, built: str | None, version: str = "1.18.26", untrusted: bool = False,
            container_hash: str | None = None, declared: bool = True) -> BuildResult:
    work = tmp_path / "job"
    (work / "host").mkdir(parents=True, exist_ok=True)
    (work / "output" / "deploy").mkdir(parents=True, exist_ok=True)
    if built is not None:
        (work / "host" / "program_hash.txt").write_text(built)
    if container_hash is not None:   # a hash a build container could write: must never count
        (work / "output" / "program_hash.txt").write_text(container_hash)
        (work / "output" / "deploy" / "program_hash.txt").write_text(container_hash)
    (work / "host" / "build_meta.json").write_text(json.dumps({"version": version, "image": "img"}))
    cand = Candidate(provider="repo", files={}, sha256="0", language="rust", compiler=None,
                     settings={"verify_args": ["--library-name", "x"]} if declared else {},
                     std_json_input=None, entry_contract=None, untrusted_inputs=untrusted)
    return BuildResult(candidate=cand, status="ok", work_dir=str(work))


def _passed_lines(monkeypatch, lines: set[str]) -> None:
    data = solana_images.load_map()
    data["version_lines"] = {k: {"u_s1": "passed" if k in lines else "not_run"} for k in data["version_lines"]}
    monkeypatch.setattr(solana_images, "load_map", lambda: data)


def _decide(result: BuildResult, deployed: str | None, items: list | None = None) -> dict:
    cs = {"upgrade_authority": ChainValue(AUTH, "rpc_finalized", block=1)}
    if deployed is not None:
        cs["deployed_program_hash"] = ChainValue(deployed, "rpc_finalized", block=1)
    extras, rows = map_result(result, {"verify_items": items or []}, cs)
    assert rows[0]["tier"] == extras["provenance"]["tier"]
    return extras["provenance"]


class TestDecisionPoint:
    def test_exact_on_passed_line_is_tier_a(self, tmp_path, monkeypatch):
        _passed_lines(monkeypatch, {"1.18"})
        p = _decide(_result(tmp_path, built=H), deployed=H)
        assert (p["tier"], p["match"], p["reason"]) == ("A", "exact", "MATCH_REBUILD")

    def test_untrusted_input_blocks_a_even_on_exact_hash(self, tmp_path, monkeypatch):
        _passed_lines(monkeypatch, {"1.18"})
        p = _decide(_result(tmp_path, built=H, untrusted=True), deployed=H)
        assert (p["tier"], p["reason"], p["hash_equal"]) == ("B", "BUILD_INPUT_UNTRUSTED", True)

    def test_unproven_line_never_a_or_c(self, tmp_path, monkeypatch):
        _passed_lines(monkeypatch, set())
        p = _decide(_result(tmp_path, built=H), deployed=H)
        assert (p["tier"], p["reason"], p["why"]) == ("B", "SOURCE_NOT_REBUILT", "unsupported_toolchain")

    def test_container_written_hash_never_reaches_the_decision(self, tmp_path, monkeypatch):
        _passed_lines(monkeypatch, {"1.18"})
        p = _decide(_result(tmp_path, built=None, container_hash=H), deployed=H)
        assert p.get("tier") != "A"

    def test_registry_hash_never_yields_exact(self, tmp_path, monkeypatch):
        _passed_lines(monkeypatch, {"1.18"})
        items = [{"signer": AUTH, "is_verified": True, "executable_hash": H, "on_chain_hash": H}]
        p = _decide(_result(tmp_path, built=H), deployed=None, items=items)
        assert (p["tier"], p["reason"]) == ("B", "DEPLOYMENT_NOT_HASHABLE")

    def test_differing_rebuild_with_owner_linked_verified_entry_is_b(self, tmp_path, monkeypatch):
        _passed_lines(monkeypatch, {"1.18"})
        items = [{"signer": AUTH, "is_verified": True, "executable_hash": OTHER}]
        p = _decide(_result(tmp_path, built=H), deployed=OTHER, items=items)
        assert (p["tier"], p["match"]) == ("B", "third_party_verified_only")

    def test_differing_declared_build_is_c_undeclared_is_b(self, tmp_path, monkeypatch):
        _passed_lines(monkeypatch, {"1.18"})
        assert _decide(_result(tmp_path, built=H), deployed=OTHER)["tier"] == "C"
        assert _decide(_result(tmp_path, built=H, declared=False), deployed=OTHER)["reason"] == \
            "REBUILD_DIFFERS_UNDECLARED"

    def test_property_a_only_when_every_condition_holds(self):
        for built, deployed, untrusted, passed, declared, linked in itertools.product(
                (None, H), (None, H, OTHER), (False, True), (False, True), (False, True), (False, True)):
            items = [{"signer": AUTH if linked else "x", "is_verified": True, "executable_hash": H}]
            out = resolve_provenance("P", built, items, AUTH, untrusted_inputs=untrusted, deployed_hash=deployed,
                                     version_line_passed=passed, build_declared=declared)
            is_a = out["tier"] == "A"
            assert is_a == (built == H and deployed == H and not untrusted and passed), out
            if untrusted or not passed:
                assert out["tier"] not in ("A", "C"), out


# ---------------------------------------------------------------------------
# RustSec snapshot record
# ---------------------------------------------------------------------------

def test_rustsec_status_records_pin_and_age(tmp_path, monkeypatch):
    monkeypatch.setenv("SOKEN_RUSTSEC_DB", str(tmp_path))
    assert rustsec.status() is None                       # not fetched: cargo-audit does not run
    pin = rustsec.pin()
    (tmp_path / pin["commit"] / "crates" / "x").mkdir(parents=True)
    (tmp_path / f"{pin['commit']}.meta.json").write_text(json.dumps({"commit": pin["commit"], "advisories": 1}))
    commit_date = datetime.fromisoformat(pin["commit_date"])
    fresh = rustsec.status(now=commit_date + timedelta(days=3))
    assert fresh["commit"] == pin["commit"] and fresh["age_days"] == 3 and fresh["stale"] is False
    assert rustsec.status(now=commit_date + timedelta(days=pin["max_age_days"] + 1))["stale"] is True
    (tmp_path / f"{pin['commit']}.meta.json").write_text(json.dumps({"commit": "0" * 40}))
    assert rustsec.status(now=datetime.now(UTC)) is None   # record for another snapshot: not this pin


# ---------------------------------------------------------------------------
# analyzer outputs fail closed
# ---------------------------------------------------------------------------

def test_clippy_without_build_finished_is_not_ok():
    from soken_review.adapters.solana.analyze import _parse_clippy_output
    assert _parse_clippy_output("")["build_finished"] is False
    ok = _parse_clippy_output(json.dumps({"reason": "build-finished", "success": True}), "1.75.0-x")
    assert ok["build_finished"] is True and ok["status"] == "ok"


def test_cargo_audit_json_without_loaded_advisories_is_not_ok():
    from soken_review.adapters.solana.analyze import _parse_audit_output
    empty = {"database": {"advisory-count": 0}, "vulnerabilities": {"list": []}}
    assert _parse_audit_output(json.dumps(empty))["status"] != "ok"
    loaded = {"database": {"advisory-count": 900}, "vulnerabilities": {"list": [
        {"advisory": {"id": "RUSTSEC-2024-0001", "cvss": None}}]}}
    out = _parse_audit_output(json.dumps(loaded))
    assert out["status"] == "ok" and out["advisory_count"] == 900 and out["items"][0]["rule_id"] == \
        "cargo-audit:RUSTSEC-2024-0001"
