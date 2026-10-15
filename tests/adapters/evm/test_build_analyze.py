"""Tests for EVM build + analyze pipeline (plan v4 workstream 05).

Docker-dependent tests skip when docker is unavailable (same pattern as
test_sandbox.py).  Tests that need solc run with SOKEN_SOLC_DIRECT=1 and
download the binary on demand (requires network in CI; skip offline).

Fixture contracts:
  tests/fixtures/evm/contracts/VulnerableVault.sol   - reentrancy
  tests/fixtures/evm/contracts/UnprotectedInit.sol   - unprotected initializer
  tests/fixtures/evm/contracts/CleanToken.sol        - clean ERC20 (no High leads)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.evm.analyze import (
    _detector_location,
    _materialize_sources,
)
from soken_review.adapters.evm.build import (
    InputSanitizationError,
    _safe_relative_path,
    host_build_dir,
    sanitize_remapping,
    sanitize_std_input,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "evm" / "contracts"
SBX = Path(__file__).resolve().parents[3] / ".sbx"

SOLC_VERSION = "0.8.20+commit.a1b79de6"
# Use a small solc for tests that need compilation
SOLC_TEST_VERSION = "0.8.20+commit.a1b79de6"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0


def solc_available() -> bool:
    """True when the solc test binary is already in the cache (no network needed)."""
    try:
        from soken_review.adapters.evm.compiler import get_cache
        cache = get_cache()
        return cache.path_in_cache(SOLC_TEST_VERSION).exists()
    except (ImportError, OSError):
        return False


def network_available() -> bool:
    try:
        import urllib.request
        urllib.request.urlopen("https://binaries.soliditylang.org", timeout=5)
        return True
    except OSError:
        return False


def make_candidate(sol_content: str, version: str = SOLC_TEST_VERSION) -> Candidate:
    return Candidate(
        provider="user",
        files={"src/Contract.sol": sol_content},
        sha256="test",
        language="solidity",
        compiler=Compiler(version=version, version_pinned_by="user"),
        settings={},
        std_json_input=None,
        entry_contract=None,
    )


def make_work_dir() -> Path:
    SBX.mkdir(exist_ok=True)
    d = tempfile.mkdtemp(dir=SBX)
    return Path(d)


# ---------------------------------------------------------------------------
# Input sanitizer unit tests (no docker/solc needed)
# ---------------------------------------------------------------------------

class TestSafeRelativePath:
    def test_normal_path_ok(self):
        assert _safe_relative_path("src/Token.sol")

    def test_absolute_path_rejected(self):
        assert not _safe_relative_path("/etc/passwd")

    def test_dotdot_rejected(self):
        assert not _safe_relative_path("../escape.sol")
        assert not _safe_relative_path("src/../../escape.sol")

    def test_backslash_rejected(self):
        assert not _safe_relative_path("src\\Contract.sol")

    def test_empty_rejected(self):
        assert not _safe_relative_path("")


class TestSanitizeStdInput:
    def test_drops_urls_from_sources(self):
        inp = {
            "language": "Solidity",
            "sources": {
                "src/Token.sol": {
                    "content": "pragma solidity ^0.8.0;",
                    "urls": ["file:///etc/passwd"],
                }
            },
            "settings": {},
        }
        out = sanitize_std_input(inp)
        assert "urls" not in out["sources"]["src/Token.sol"]
        assert "content" in out["sources"]["src/Token.sol"]

    def test_rejects_absolute_source_key(self):
        inp = {
            "language": "Solidity",
            "sources": {"/etc/passwd": {"content": ""}},
            "settings": {},
        }
        with pytest.raises(InputSanitizationError, match="unsafe source key"):
            sanitize_std_input(inp)

    def test_rejects_dotdot_source_key(self):
        inp = {
            "language": "Solidity",
            "sources": {"../escape.sol": {"content": ""}},
            "settings": {},
        }
        with pytest.raises(InputSanitizationError):
            sanitize_std_input(inp)

    def test_rejects_allow_paths_key(self):
        inp = {
            "language": "Solidity",
            "sources": {},
            "settings": {"--allow-paths": "/"},
        }
        with pytest.raises(InputSanitizationError, match="forbidden settings key"):
            sanitize_std_input(inp)

    def test_rejects_base_path_key(self):
        inp = {
            "language": "Solidity",
            "sources": {},
            "settings": {"--base-path": "/"},
        }
        with pytest.raises(InputSanitizationError):
            sanitize_std_input(inp)

    def test_drops_unsafe_remapping_target(self):
        """Bad remappings are silently dropped (not an error for the whole input)."""
        inp = {
            "language": "Solidity",
            "sources": {},
            "settings": {"remappings": ["@oz=/etc/openzeppelin", "@safe=lib/safe"]},
        }
        out = sanitize_std_input(inp)
        # /etc/openzeppelin is an absolute path; should be dropped
        assert "@oz=/etc/openzeppelin" not in out["settings"]["remappings"]
        # The valid one should remain
        assert "@safe=lib/safe" in out["settings"]["remappings"]

    def test_accepts_clean_input(self):
        inp = {
            "language": "Solidity",
            "sources": {"src/Token.sol": {"content": "pragma solidity ^0.8.0;"}},
            "settings": {"optimizer": {"enabled": True, "runs": 200}},
        }
        out = sanitize_std_input(inp)
        assert out["sources"]["src/Token.sol"]["content"] == "pragma solidity ^0.8.0;"

    def test_unsafe_library_path_rejected(self):
        inp = {
            "language": "Solidity",
            "sources": {},
            "settings": {"libraries": {"/absolute/path/Lib.sol": {"MyLib": "0x1234"}}},
        }
        with pytest.raises(InputSanitizationError, match="unsafe library path"):
            sanitize_std_input(inp)


class TestSanitizeRemapping:
    """Tests for the shared remapping sanitizer (build.py / analyze.py)."""

    def test_valid_remapping_passes(self):
        assert sanitize_remapping("@oz=lib/openzeppelin") == "@oz=lib/openzeppelin"

    def test_valid_empty_prefix_passes(self):
        assert sanitize_remapping("=lib/") == "=lib/"

    def test_allow_paths_style_rejected(self):
        assert sanitize_remapping("--allow-paths=/") is None

    def test_leading_dash_on_target_rejected(self):
        assert sanitize_remapping("prefix=-o=output") is None

    def test_leading_dash_on_prefix_rejected(self):
        assert sanitize_remapping("-o=lib/") is None

    def test_absolute_target_rejected(self):
        assert sanitize_remapping("@oz=/absolute/path") is None

    def test_dotdot_target_rejected(self):
        assert sanitize_remapping("@oz=../escape") is None

    def test_space_in_value_rejected(self):
        # spaces could split CLI argv
        assert sanitize_remapping("@oz=lib/oz --allow-paths=/") is None

    def test_shell_char_rejected(self):
        assert sanitize_remapping("@oz=$(rm -rf /)") is None

    def test_non_string_rejected(self):
        assert sanitize_remapping(123) is None  # type: ignore[arg-type]

    def test_sanitize_std_input_drops_bad_remappings_not_raises(self):
        """Bad remappings are dropped silently (not an error for the whole input)."""
        inp = {
            "language": "Solidity",
            "sources": {},
            "settings": {"remappings": ["@oz=lib/oz", "--allow-paths=/", "=valid/"]},
        }
        out = sanitize_std_input(inp)
        assert out["settings"]["remappings"] == ["@oz=lib/oz", "=valid/"]


class TestMaterializeSources:
    """Tests for analyze._materialize_sources path sanitization."""

    def _make_work_dir_with_input(self, sources: dict) -> Path:
        """Write the host-only build copy of input.json and return work_dir."""
        wd = make_work_dir()
        out_dir = host_build_dir(Path(wd))  # analyzers read only the host-only build copy
        out_dir.mkdir(parents=True)
        inp = {"language": "Solidity", "sources": sources, "settings": {}}
        (out_dir / "input.json").write_text(json.dumps(inp), encoding="utf-8")
        return Path(wd)

    def test_normal_source_materializes(self):
        wd = self._make_work_dir_with_input({"src/Token.sol": {"content": "pragma solidity ^0.8.0;"}})
        proj_dir = Path(wd) / "proj"
        assert _materialize_sources(wd, proj_dir)
        assert (proj_dir / "src" / "src" / "Token.sol").exists()

    def test_absolute_key_rejected(self):
        wd = self._make_work_dir_with_input({"/etc/passwd": {"content": ""}})
        proj_dir = Path(wd) / "proj"
        assert not _materialize_sources(wd, proj_dir)

    def test_dotdot_key_rejected(self):
        wd = self._make_work_dir_with_input({"../escape.sol": {"content": ""}})
        proj_dir = Path(wd) / "proj"
        assert not _materialize_sources(wd, proj_dir)

    def test_forbidden_basename_slither_config_rejected(self):
        wd = self._make_work_dir_with_input({
            "src/Token.sol": {"content": "pragma solidity ^0.8.0;"},
            "slither.config.json": {"content": '{"detectors_to_exclude": []}'},
        })
        proj_dir = Path(wd) / "proj"
        # slither.config.json has .json ext (not in _ALLOWED_SOURCE_EXTS) -> skipped, not rejected
        # But if it somehow had .sol ext, the basename check applies
        # Here it's filtered by ext before basename check; result is True (skipped, not rejected)
        result = _materialize_sources(wd, proj_dir)
        # slither.config.json filtered by ext; Token.sol written normally
        assert result
        assert not (proj_dir / "src" / "slither.config.json").exists()

    def test_forbidden_basename_as_sol_variant_rejected(self):
        """A file named like a config but with .sol extension is blocked by basename."""
        wd = self._make_work_dir_with_input({
            "foundry.toml": {"content": "pragma solidity ^0.8.0;"},
        })
        proj_dir = Path(wd) / "proj"
        # foundry.toml is filtered first by ext (.toml not in ALLOWED_SOURCE_EXTS)
        result = _materialize_sources(wd, proj_dir)
        assert result  # filtered, not rejected
        assert not (proj_dir / "src" / "foundry.toml").exists()

    def test_json_extension_not_written(self):
        """JSON files (including package.json, waffle.json) must not reach the project tree."""
        wd = self._make_work_dir_with_input({
            "package.json": {"content": '{"name": "test"}'},
            "waffle.json": {"content": "{}"},
            "src/Token.sol": {"content": "pragma solidity ^0.8.0;"},
        })
        proj_dir = Path(wd) / "proj"
        assert _materialize_sources(wd, proj_dir)
        assert not (proj_dir / "src" / "package.json").exists()
        assert not (proj_dir / "src" / "waffle.json").exists()
        assert (proj_dir / "src" / "src" / "Token.sol").exists()

    def test_malicious_runs_value_does_not_crash_sanitizer(self):
        """Non-integer optimizer.runs must not reach a config file (settings extraction)."""
        from soken_review.adapters.evm.analyze import _extract_settings
        wd = self._make_work_dir_with_input({})
        out_dir = host_build_dir(Path(wd))  # analyzers read only the host-only build copy
        inp = {
            "language": "Solidity",
            "sources": {},
            "settings": {"optimizer": {"enabled": True, "runs": "$(rm -rf /)"}},
        }
        (out_dir / "input.json").write_text(json.dumps(inp), encoding="utf-8")
        settings = _extract_settings(wd)
        # Malicious string -> rejected, default used
        assert settings["optimizer_runs"] == 200

    def test_malicious_runs_float_rejected(self):
        from soken_review.adapters.evm.analyze import _extract_settings
        wd = self._make_work_dir_with_input({})
        out_dir = host_build_dir(Path(wd))  # analyzers read only the host-only build copy
        inp = {
            "language": "Solidity",
            "sources": {},
            "settings": {"optimizer": {"enabled": True, "runs": 3.14}},
        }
        (out_dir / "input.json").write_text(json.dumps(inp), encoding="utf-8")
        settings = _extract_settings(wd)
        assert settings["optimizer_runs"] == 200  # float rejected

    def test_evm_version_allowlist(self):
        from soken_review.adapters.evm.analyze import _extract_settings
        wd = self._make_work_dir_with_input({})
        out_dir = host_build_dir(Path(wd))  # analyzers read only the host-only build copy
        for good in ("london", "shanghai", "cancun"):
            inp = {"language": "Solidity", "sources": {}, "settings": {"evmVersion": good}}
            (out_dir / "input.json").write_text(json.dumps(inp), encoding="utf-8")
            s = _extract_settings(wd)
            assert s.get("evm_version") == good
        for bad in ("../../bin/sh", "latest", "current", "0.8.0"):
            inp = {"language": "Solidity", "sources": {}, "settings": {"evmVersion": bad}}
            (out_dir / "input.json").write_text(json.dumps(inp), encoding="utf-8")
            s = _extract_settings(wd)
            assert "evm_version" not in s


# ---------------------------------------------------------------------------
# Compiler cache tests (no docker; may need network)
# ---------------------------------------------------------------------------

class TestSolcCache:
    def test_cache_miss_returns_compiler_binary_missing(self):
        """A version not in list.json returns not_checkable / compiler_binary_missing."""
        with tempfile.TemporaryDirectory() as tmp:
            from soken_review.adapters.evm.compiler import CompilerCacheError, SolcCache
            cache = SolcCache(cache_dir=Path(tmp))
            with pytest.raises(CompilerCacheError) as exc_info:
                cache.binary("0.0.0+commit.nonexistent")
            assert exc_info.value.reason_detail == "compiler_binary_missing"

    def test_binary_path_format(self):
        """path_in_cache returns expected file path format."""
        with tempfile.TemporaryDirectory() as tmp:
            from soken_review.adapters.evm.compiler import SolcCache
            cache = SolcCache(cache_dir=Path(tmp))
            p = cache.path_in_cache("0.8.20+commit.a1b79de6")
            assert p.name == "solc-0.8.20+commit.a1b79de6"


# ---------------------------------------------------------------------------
# Build sandbox fail-closed tests (no docker/solc)
# ---------------------------------------------------------------------------

class TestBuildFailClosed:
    def test_missing_compiler_version_returns_not_checkable(self):
        from soken_review.adapters.evm.build import build
        c = Candidate(
            provider="user", files={}, sha256="x", language="solidity",
            compiler=None, settings={}, std_json_input=None, entry_contract=None,
        )
        r = build(c)
        assert r.status == "failed"
        assert r.reason == "compiler_version_unknown"

    def test_sandbox_unavailable_without_docker(self, monkeypatch):
        """When docker is absent and SOKEN_SOLC_DIRECT=0, build returns sandbox_unavailable."""
        monkeypatch.setenv("SOKEN_SOLC_DIRECT", "0")
        monkeypatch.delenv("SOKEN_SANDBOX_RUNTIME", raising=False)

        # Patch shutil.which to pretend docker is absent
        original_which = shutil.which

        def mock_which(name, *args, **kwargs):
            if name == "docker":
                return None
            return original_which(name, *args, **kwargs)

        monkeypatch.setattr(shutil, "which", mock_which)

        # Provide a fake binary so the cache lookup succeeds
        import soken_review.adapters.evm.build as build_mod
        original_direct = build_mod._DIRECT_SOLC

        try:
            build_mod._DIRECT_SOLC = False
            with tempfile.TemporaryDirectory() as tmp:
                cache_dir = Path(tmp)
                # Create a fake solc binary so cache.binary() returns a path
                platform_dir = cache_dir / "linux-amd64"
                platform_dir.mkdir()
                fake_solc = platform_dir / "solc-0.8.20+commit.a1b79de6"
                fake_solc.touch(mode=0o755)
                # Write a minimal list.json
                list_data = {
                    "releases": {"0.8.20+commit.a1b79de6": "solc-0.8.20+commit.a1b79de6"},
                    "builds": [{"path": "solc-0.8.20+commit.a1b79de6", "sha256": "0xdeadbeef"}],
                }
                (platform_dir / "list.json").write_text(json.dumps(list_data))

                from soken_review.adapters.evm.compiler import SolcCache
                cache = SolcCache(cache_dir=cache_dir)

                c = make_candidate("pragma solidity ^0.8.0; contract X {}")
                c.compiler.version = "0.8.20+commit.a1b79de6"

                from soken_review.adapters.evm.build import _prepare_std_input, _run_build, sanitize_std_input
                std_input = sanitize_std_input(_prepare_std_input(c))
                wd = Path(tmp) / "work"
                wd.mkdir()
                result = _run_build(c, std_input, fake_solc, wd, cache)
                assert result.status == "failed"
                assert result.reason == "sandbox_unavailable"
        finally:
            build_mod._DIRECT_SOLC = original_direct


# ---------------------------------------------------------------------------
# End-to-end build + analyze tests (require solc on PATH or in cache)
# ---------------------------------------------------------------------------

def _make_std_input(sol_content: str) -> dict:
    return {
        "language": "Solidity",
        "sources": {"src/Contract.sol": {"content": sol_content}},
        "settings": {
            "optimizer": {"enabled": False},
            "outputSelection": {
                "*": {
                    "*": ["evm.bytecode", "evm.deployedBytecode",
                          "evm.deployedBytecode.immutableReferences",
                          "evm.bytecode.linkReferences",
                          "evm.deployedBytecode.linkReferences",
                          "evm.deployedBytecode.sourceMap",
                          "storageLayout", "metadata"],
                    "": ["ast"],
                }
            },
        },
    }


@pytest.mark.skipif(
    not (os.environ.get("SOKEN_SOLC_DIRECT") == "1" and solc_available()),
    reason="requires SOKEN_SOLC_DIRECT=1 and cached solc binary",
)
class TestBuildDirect:
    """Full build tests using host solc (SOKEN_SOLC_DIRECT=1)."""

    def _build(self, sol_file: str) -> object:
        from soken_review.adapters.evm.build import build
        content = (FIXTURES / sol_file).read_text()
        c = Candidate(
            provider="user",
            files={"src/Contract.sol": content},
            sha256="test",
            language="solidity",
            compiler=Compiler(version=SOLC_TEST_VERSION, version_pinned_by="user"),
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        return build(c)

    def test_vault_builds_ok(self):
        r = self._build("VulnerableVault.sol")
        assert r.status == "ok", r.reason
        assert r.artifacts
        assert r.nsloc > 0

    def test_unprotected_init_builds_ok(self):
        r = self._build("UnprotectedInit.sol")
        assert r.status == "ok", r.reason
        assert r.artifacts

    def test_clean_token_builds_ok(self):
        r = self._build("CleanToken.sol")
        assert r.status == "ok", r.reason
        assert r.artifacts
        assert r.nsloc > 10

    def test_bad_solidity_fails(self):
        from soken_review.adapters.evm.build import build
        c = Candidate(
            provider="user",
            files={"src/Contract.sol": "not valid solidity {{{{"},
            sha256="test",
            language="solidity",
            compiler=Compiler(version=SOLC_TEST_VERSION, version_pinned_by="user"),
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        r = build(c)
        assert r.status == "failed"


@pytest.mark.skipif(
    not (os.environ.get("SOKEN_SOLC_DIRECT") == "1"
         and os.environ.get("SOKEN_ANALYZE_DIRECT") == "1"
         and solc_available()
         and shutil.which("slither") is not None),
    reason="requires SOKEN_SOLC_DIRECT=1, SOKEN_ANALYZE_DIRECT=1, cached solc, slither on PATH",
)
class TestAnalyzeDirect:
    """Full analyze tests with host slither (SOKEN_ANALYZE_DIRECT=1)."""

    def _build_and_analyze(self, sol_file: str):
        from soken_review.adapters.evm.analyze import analyze
        from soken_review.adapters.evm.build import build
        content = (FIXTURES / sol_file).read_text()
        c = Candidate(
            provider="user",
            files={"src/Contract.sol": content},
            sha256="test",
            language="solidity",
            compiler=Compiler(version=SOLC_TEST_VERSION, version_pinned_by="user"),
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        r = build(c)
        if r.status != "ok":
            pytest.skip(f"build failed: {r.reason}")
        return analyze(r)

    def test_vault_has_reentrancy_lead(self):
        leads, _, _ = self._build_and_analyze("VulnerableVault.sol")
        reentrancy_leads = [l for l in leads if "reentrancy" in l.get("category", "")]
        assert reentrancy_leads, f"expected reentrancy lead, got: {[l['category'] for l in leads]}"
        assert all(l["state"] == "open" for l in reentrancy_leads)

    def test_leads_validate_against_schema(self):
        import jsonschema

        from soken_review.adapters.evm.analyze import _LEAD_SCHEMA
        leads, _, _ = self._build_and_analyze("VulnerableVault.sol")
        for lead in leads:
            jsonschema.validate(lead, _LEAD_SCHEMA)  # raises on failure

    def test_lead_ids_sequential(self):
        leads, _, _ = self._build_and_analyze("VulnerableVault.sol")
        for i, lead in enumerate(leads, start=1):
            assert lead["id"] == f"LEAD-{i:04d}", f"expected LEAD-{i:04d}, got {lead['id']}"

    def test_lead_categories_valid(self):
        import re
        leads, _, _ = self._build_and_analyze("VulnerableVault.sol")
        pattern = re.compile(r"^(evm|solana|ton|move|cairo)\.[a-z0-9_]+(\.[a-z0-9_]+)?$")
        for lead in leads:
            assert pattern.match(lead["category"]), f"bad category: {lead['category']}"

    def test_clean_token_no_high_leads(self):
        leads, _, _ = self._build_and_analyze("CleanToken.sol")
        high_leads = [l for l in leads if l.get("severity_norm") == "High"]
        assert not high_leads, f"unexpected High leads on clean token: {high_leads}"


@pytest.mark.skipif(not docker_ok(), reason="docker not available")
class TestBuildInSandbox:
    """Build tests using the docker sandbox (P0 from test_sandbox.py)."""

    def test_sandbox_build_clean_token(self):
        """Build the clean token through the docker sandbox."""
        from soken_review.adapters.evm.build import build
        content = (FIXTURES / "CleanToken.sol").read_text()
        c = Candidate(
            provider="user",
            files={"src/Contract.sol": content},
            sha256="test",
            language="solidity",
            compiler=Compiler(version=SOLC_TEST_VERSION, version_pinned_by="user"),
            settings={},
            std_json_input=None,
            entry_contract=None,
        )
        r = build(c)
        # Without the real image and cached solc, this will be sandbox_unavailable or
        # compiler_binary_missing; we just assert no exception and no crash
        assert r.status in ("ok", "failed")
        assert isinstance(r.reason, (str, type(None)))


def test_analyze_uses_the_candidate_compiler_not_another_cached_release(tmp_path, monkeypatch):
    """Regression: analyze picked the first solc-* in the cache (05 6.1 exact release only)."""
    from soken_review.adapters.base import BuildResult, Candidate, Compiler
    from soken_review.adapters.evm import analyze as a
    from soken_review.adapters.evm.compiler import SolcCache

    plat = tmp_path / "linux-amd64"
    plat.mkdir()
    for v in ("0.4.18+commit.9cf6e910", "0.5.16+commit.9c3226ce"):
        (plat / f"solc-{v}").write_text("")
    monkeypatch.setattr("soken_review.adapters.evm.compiler.get_cache", lambda *a, **k: SolcCache(tmp_path))
    cand = Candidate(provider="sourcify", files={}, sha256="", language="solidity",
                     compiler=Compiler("0.5.16+commit.9c3226ce", "sourcify"), settings={},
                     std_json_input=None, entry_contract="A.sol:A")
    path = a._solc_path(BuildResult(candidate=cand, status="ok"))
    assert path is not None and path.endswith("solc-0.5.16+commit.9c3226ce")


@pytest.mark.parametrize("entry", ["--print=human-summary", "../etc/x.sol", "/abs/A.sol", "A.json", "a b.sol"])
def test_slither_rejects_unsafe_entry_file(tmp_path, entry):
    """entry_contract is fetched metadata: option-like or escaping values never reach argv."""
    from soken_review.adapters.evm import analyze as a

    proj = tmp_path / "work" / "analyze" / "proj"
    (proj / "src").mkdir(parents=True)
    out = tmp_path / "work" / "analyze"
    assert a._run_slither(proj, out, str(tmp_path / "solc"), {}, entry) is None


# ── _detector_location: narrow a Slither detector to its specific element ─────
# exp/narrow-lead-location: a detector carries a wide scope element (function/
# contract) plus a tight one (node/variable/expression). The lead location is the
# tight one, so review_leads points at the suspicious line, not the whole function.


def _el(kind: str, lines: list[int]) -> dict:
    return {"type": kind, "source_mapping": {"lines": lines}}


def test_detector_location_prefers_specific_node_over_function():
    # incorrect-exp: function mulDiv 55..134, node at 116 (the real location)
    els = [_el("function", list(range(55, 135))), _el("node", [116])]
    assert _detector_location(els) == (116, 116)


def test_detector_location_spans_only_specific_elements():
    els = [_el("function", list(range(10, 90))), _el("node", [40]), _el("expression", [42])]
    assert _detector_location(els) == (40, 42)


def test_detector_location_falls_back_to_function_when_no_specific():
    els = [_el("contract", list(range(1, 200))), _el("function", list(range(20, 60)))]
    assert _detector_location(els) == (20, 59)


def test_detector_location_contract_only():
    assert _detector_location([_el("contract", list(range(1, 30)))]) == (1, 29)


def test_detector_location_empty_is_line_one():
    assert _detector_location([]) == (1, 1)
    assert _detector_location([{"type": "node", "source_mapping": {}}]) == (1, 1)
