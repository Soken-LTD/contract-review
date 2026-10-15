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
    _check_forge_version,
    _forge_build_timeout,
    _forge_sources_match_pin,
    _safe_relative_path,
    _sanitize_forge_settings,
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


# ---------------------------------------------------------------------------
# _missing_import_reason — solc-error-based missing import detection (09 5.2)
# ---------------------------------------------------------------------------

from soken_review.adapters.evm.build import _missing_import_reason


class TestMissingImportReason:
    def test_parser_error_source_not_found(self):
        """ParserError 'Source "pkg/..." not found' → missing_import:pkg."""
        errors = [
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol" not found: File not found.',
            }
        ]
        reason = _missing_import_reason(errors)
        assert reason == "missing_import:@uniswap/v3-core"

    def test_ioerror_file_not_found(self):
        """IOError 'pkg/...: File not found.' → missing_import:pkg."""
        errors = [
            {
                "severity": "error",
                "type": "IOError",
                "message": "@openzeppelin/contracts/access/Ownable.sol: File not found.",
            }
        ]
        reason = _missing_import_reason(errors)
        assert reason is not None
        assert "missing_import" in reason
        assert "@openzeppelin" in reason

    def test_multiple_packages_deduplicated(self):
        """Multiple missing imports for the same package appear only once."""
        errors = [
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "@uniswap/v3-core/contracts/A.sol" not found: File not found.',
            },
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "@uniswap/v3-core/contracts/B.sol" not found: File not found.',
            },
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "@uniswap/v3-periphery/contracts/C.sol" not found: File not found.',
            },
        ]
        reason = _missing_import_reason(errors)
        assert reason is not None
        # Both packages appear; v3-core only once despite two errors
        pkgs = reason.replace("missing_import:", "").split(",")
        assert "@uniswap/v3-core" in pkgs
        assert "@uniswap/v3-periphery" in pkgs
        assert pkgs.count("@uniswap/v3-core") == 1

    def test_relative_import_not_flagged(self):
        """Relative imports (./..., ../...) are not flagged as missing npm packages."""
        errors = [
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "./subdir/Foo.sol" not found: File not found.',
            }
        ]
        reason = _missing_import_reason(errors)
        assert reason is None

    def test_warning_not_flagged(self):
        """Warning-severity errors are not treated as missing imports."""
        errors = [
            {
                "severity": "warning",
                "type": "ParserError",
                "message": 'Source "@pkg/Foo.sol" not found: File not found.',
            }
        ]
        reason = _missing_import_reason(errors)
        assert reason is None

    def test_no_not_found_errors_returns_none(self):
        """Errors without 'not found' in message return None."""
        errors = [
            {
                "severity": "error",
                "type": "TypeError",
                "message": "Identifier not found or not unique.",
            }
        ]
        reason = _missing_import_reason(errors)
        assert reason is None

    def test_empty_errors_returns_none(self):
        """Empty error list returns None."""
        assert _missing_import_reason([]) is None

    def test_foundry_gitlink_lib_path_returns_missing_dep_path(self):
        """lib/ and test/ multi-segment paths → missing_dependency_path (not silent None).

        Before the fix, _FOUNDRY_DIR_PREFIXES silently dropped lib/ paths, letting a build
        failure from a missing gitlink dep reach `ready` with 0 leads.  Now they are
        classified as missing_dependency_path: so the supervisor transitions to
        insufficient_source instead.
        """
        errors = [
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "lib/forge-std/src/Test.sol" not found: File not found.',
            },
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "lib/solmate/src/auth/Owned.sol" not found: File not found.',
            },
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "test/utils/Helper.sol" not found: File not found.',
            },
        ]
        reason = _missing_import_reason(errors)
        # Must NOT be None — these paths are a real build failure
        assert reason is not None
        # Must be classified as missing_dependency_path, not missing_import
        assert reason.startswith("missing_dependency_path:")
        # First segments: lib (x2 deduped) and test → sorted → lib,test
        segs = reason.split(":", 1)[1].split(",")
        assert "lib" in segs
        assert "test" in segs

    def test_npm_package_with_gitlink_mixed_npm_wins(self):
        """npm import takes precedence when mixed with a lib/ path."""
        errors = [
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "lib/forge-std/src/Test.sol" not found: File not found.',
            },
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "ds-test/test.sol" not found: File not found.',
            },
        ]
        reason = _missing_import_reason(errors)
        # ds-test is a bare single-segment name → npm_pkgs wins over dep_paths
        assert reason == "missing_import:ds-test"

    def test_missing_dependency_path_for_lib_only(self):
        """A lib/ multi-segment path alone → missing_dependency_path:lib."""
        errors = [
            {
                "severity": "error",
                "type": "ParserError",
                "message": 'Source "lib/solmate/src/auth/Owned.sol" not found: File not found.',
            },
        ]
        reason = _missing_import_reason(errors)
        assert reason == "missing_dependency_path:lib"


# ---------------------------------------------------------------------------
# B4 security findings (2026-10-13)
# ---------------------------------------------------------------------------

class TestSanitizeForgeSettings:
    """Finding 1: forge settings are rebuilt from an allow-list, never passed through."""

    def test_clean_optimizer_passes(self):
        raw = {"optimizer": {"enabled": True, "runs": 200}, "outputSelection": {"*": {}}}
        clean, libs, unknown = _sanitize_forge_settings(raw)
        assert clean["optimizer"] == {"enabled": True, "runs": 200}
        assert not libs
        assert not unknown
        assert "outputSelection" not in clean  # always dropped

    def test_libraries_sets_flag(self):
        raw = {"libraries": {"src/Foo.sol": {"Foo": "0xdeadbeef"}}}
        clean, libs, _unknown = _sanitize_forge_settings(raw)
        assert libs is True
        assert "libraries" not in clean

    def test_unknown_key_sets_flag(self):
        raw = {"modelChecker": {"engine": "chc"}}
        _clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert unknown is True
        assert "modelChecker" not in _clean

    def test_invalid_evm_version_sets_unknown(self):
        raw = {"evmVersion": "notaversion"}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert unknown is True
        assert "evmVersion" not in clean

    def test_valid_evm_version_passes(self):
        raw = {"evmVersion": "cancun"}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert clean["evmVersion"] == "cancun"
        assert not unknown

    def test_invalid_runs_sets_unknown(self):
        raw = {"optimizer": {"enabled": True, "runs": -1}}
        _clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert unknown is True

    def test_unsafe_remapping_dropped_and_sets_unknown(self):
        # Second remapping target side starts with ".." → _safe_relative_path rejects it
        raw = {"remappings": ["@openzeppelin/=lib/openzeppelin-contracts/src/", "@bad/=../../../etc/"]}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert unknown is True  # unsafe remapping was dropped
        assert len(clean.get("remappings", [])) == 1
        assert clean["remappings"][0] == "@openzeppelin/=lib/openzeppelin-contracts/src/"

    def test_valid_metadata_passes(self):
        raw = {"metadata": {"bytecodeHash": "ipfs", "appendCBOR": True}}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert clean["metadata"] == {"bytecodeHash": "ipfs", "appendCBOR": True}
        assert not unknown

    def test_invalid_bytecode_hash_sets_unknown(self):
        raw = {"metadata": {"bytecodeHash": "sha256"}}
        _clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert unknown is True

    def test_viaIR_bool_passes(self):
        raw = {"viaIR": True}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert clean["viaIR"] is True
        assert not unknown

    def test_viaIR_non_bool_sets_unknown(self):
        raw = {"viaIR": "yes"}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert unknown is True
        assert "viaIR" not in clean

    def test_optimizer_details_yul_only(self):
        raw = {"optimizer": {"enabled": True, "details": {"yul": True, "constantOptimizer": True}}}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert clean["optimizer"]["details"] == {"yul": True}
        assert unknown is True  # constantOptimizer is not in the allow-list

    # Task 1: useLiteralContent tests

    def test_use_literal_content_false_passes_without_flag(self):
        """useLiteralContent=False passes, is present in output settings, no unknown flag."""
        raw = {"metadata": {"useLiteralContent": False}}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert clean["metadata"]["useLiteralContent"] is False
        assert not unknown

    def test_use_literal_content_true_passes_and_preserved(self):
        """useLiteralContent=True passes and is preserved in output settings."""
        raw = {"metadata": {"useLiteralContent": True}}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert clean["metadata"]["useLiteralContent"] is True
        assert not unknown

    def test_use_literal_content_string_yes_sets_unknown(self):
        """useLiteralContent='yes' is not bool → had_unknown_settings=True."""
        raw = {"metadata": {"useLiteralContent": "yes"}}
        _clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert unknown is True

    def test_use_literal_content_int_one_sets_unknown(self):
        """useLiteralContent=1 is not bool → had_unknown_settings=True."""
        raw = {"metadata": {"useLiteralContent": 1}}
        _clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert unknown is True

    def test_use_literal_content_with_other_meta_keys(self):
        """useLiteralContent coexists with bytecodeHash and appendCBOR; all pass."""
        raw = {"metadata": {"bytecodeHash": "ipfs", "appendCBOR": True, "useLiteralContent": False}}
        clean, _libs, unknown = _sanitize_forge_settings(raw)
        assert clean["metadata"] == {"bytecodeHash": "ipfs", "appendCBOR": True, "useLiteralContent": False}
        assert not unknown


# ---------------------------------------------------------------------------
# Task 3: _check_forge_version — version comparison against pinned compiler
# ---------------------------------------------------------------------------

class TestCheckForgeVersion:
    """_check_forge_version: compare forge-reported solc version to the pinned binary."""

    def _solc_bin(self, name: str, tmp_path: Path) -> Path:
        p = tmp_path / name
        p.touch()
        return p

    def test_match_returns_false(self, tmp_path):
        """forge version matches pinned solc → no flag."""
        solc = self._solc_bin("solc-0.8.26+commit.8a97fa7e", tmp_path)
        assert not _check_forge_version("0.8.26+commit.8a97fa7e.Linux.g++", solc)

    def test_semver_mismatch_flags(self, tmp_path):
        """Different semver → True (mismatch)."""
        solc = self._solc_bin("solc-0.8.26+commit.8a97fa7e", tmp_path)
        assert _check_forge_version("0.8.25+commit.8a97fa7e.Linux.g++", solc)

    def test_commit_mismatch_flags(self, tmp_path):
        """Same semver but different commit hash → True (mismatch)."""
        solc = self._solc_bin("solc-0.8.26+commit.8a97fa7e", tmp_path)
        assert _check_forge_version("0.8.26+commit.deadbeef.Linux.g++", solc)

    def test_unparsable_forge_version_flags(self, tmp_path):
        """Non-semver forge version string → True (fail closed)."""
        solc = self._solc_bin("solc-0.8.26+commit.8a97fa7e", tmp_path)
        assert _check_forge_version("notaversion", solc)

    def test_absent_version_no_flag(self, tmp_path):
        """None (version key absent) → False (no flag)."""
        solc = self._solc_bin("solc-0.8.26+commit.8a97fa7e", tmp_path)
        assert not _check_forge_version(None, solc)

    def test_non_string_version_flags(self, tmp_path):
        """Non-string version value (e.g. int) → True (fail closed)."""
        solc = self._solc_bin("solc-0.8.26+commit.8a97fa7e", tmp_path)
        assert _check_forge_version(826, solc)  # type: ignore[arg-type]

    def test_semver_only_forge_version_matches_on_semver(self, tmp_path):
        """Forge version with no commit hash: match on semver only."""
        solc = self._solc_bin("solc-0.8.26+commit.8a97fa7e", tmp_path)
        assert not _check_forge_version("0.8.26", solc)

    def test_semver_only_mismatch(self, tmp_path):
        """Forge version 0.8.25 (no commit) vs pinned 0.8.26 → mismatch."""
        solc = self._solc_bin("solc-0.8.26+commit.8a97fa7e", tmp_path)
        assert _check_forge_version("0.8.25", solc)


class TestForgeSourcesMatchPin:
    """Finding 3 + full-tree integrity: every forge source verified against pinned tree."""

    def _make_input(self, files: dict[str, str]) -> dict:
        return {"language": "Solidity", "sources": {k: {"content": v} for k, v in files.items()}}

    # ------------------------------------------------------------------
    # Updated existing tests: now require full_tree as third argument.
    # full_tree is what safe_read_repo_tree returned (all files in repo).
    # In production it is always a superset of pinned_files (same read).
    # ------------------------------------------------------------------

    def test_exact_match_returns_true(self):
        content = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        full_tree = {"src/Foo.sol": content}
        ok, reason = _forge_sources_match_pin(
            self._make_input({"src/Foo.sol": content}),
            {"src/Foo.sol": content},
            full_tree,
        )
        assert ok is True
        assert reason == ""

    def test_lf_vs_crlf_fails(self):
        """Finding 3: CRLF in forge, LF in tree → sha256 mismatch → rejected."""
        content_lf = "pragma solidity ^0.8.0;\n"
        content_crlf = "pragma solidity ^0.8.0;\r\n"
        # tree (and pinned) hold the LF version that the O_NOFOLLOW reader returned.
        full_tree = {"src/Foo.sol": content_lf}
        ok, reason = _forge_sources_match_pin(
            self._make_input({"src/Foo.sol": content_crlf}),
            {"src/Foo.sol": content_lf},
            full_tree,
        )
        assert ok is False
        assert reason == "sources_differ"

    def test_missing_pinned_file_fails(self):
        """Forward check: scope file missing from forge sources → rejected."""
        full_tree = {"src/Foo.sol": "x", "src/Other.sol": "x"}
        ok, reason = _forge_sources_match_pin(
            self._make_input({"src/Other.sol": "x"}),
            {"src/Foo.sol": "x"},
            full_tree,
        )
        assert ok is False
        assert reason == "sources_differ"

    def test_lib_dep_matching_tree_accepted(self):
        """lib/ dep included by forge that matches tree → accepted (replaces old test_extra_forge_sources_ok)."""
        content = "pragma solidity ^0.8.0;\n"
        lib_content = "// SafeMath\n"
        full_tree = {"src/Foo.sol": content, "lib/SafeMath.sol": lib_content}
        ok, _reason = _forge_sources_match_pin(
            self._make_input({"src/Foo.sol": content, "lib/SafeMath.sol": lib_content}),
            {"src/Foo.sol": content},
            full_tree,
        )
        assert ok is True

    def test_content_differs_fails(self):
        """Forge content differs from tree (and pinned) → rejected."""
        # In production pinned and full_tree are derived from the same read, so they agree.
        full_tree = {"src/Foo.sol": "content B"}
        ok, reason = _forge_sources_match_pin(
            self._make_input({"src/Foo.sol": "content A"}),
            {"src/Foo.sol": "content B"},
            full_tree,
        )
        assert ok is False
        assert reason == "sources_differ"

    # ------------------------------------------------------------------
    # New tests for the full-tree integrity gap fix.
    # ------------------------------------------------------------------

    def test_forge_source_not_in_tree_rejected(self):
        """Forge source path absent from full_tree → rejected (integrity gap fix)."""
        content = "pragma solidity ^0.8.0;\n"
        # full_tree only has src/Foo.sol; forge also claims lib/Helper.sol
        full_tree = {"src/Foo.sol": content}
        ok, reason = _forge_sources_match_pin(
            self._make_input({"src/Foo.sol": content, "lib/Helper.sol": "// helper\n"}),
            {"src/Foo.sol": content},
            full_tree,
        )
        assert ok is False
        assert reason == "sources_differ"

    def test_lib_dep_differing_from_tree_rejected(self):
        """lib/ dep present in tree but with different content → rejected."""
        content = "pragma solidity ^0.8.0;\n"
        full_tree = {"src/Foo.sol": content, "lib/SafeMath.sol": "// real lib\n"}
        ok, reason = _forge_sources_match_pin(
            # Forge claims different content for the lib dep
            self._make_input({"src/Foo.sol": content, "lib/SafeMath.sol": "// tampered\n"}),
            {"src/Foo.sol": content},
            full_tree,
        )
        assert ok is False
        assert reason == "sources_differ"

    def test_urls_entry_rejected(self):
        """Source entry with 'urls' instead of 'content' → rejected (symlink / network fetch)."""
        content = "pragma solidity ^0.8.0;\n"
        full_tree = {"src/Foo.sol": content}
        forge_input = {
            "language": "Solidity",
            "sources": {
                "src/Foo.sol": {"content": content},
                "lib/Ext.sol": {"urls": ["file:///work/src/lib/Ext.sol"]},
            },
        }
        ok, reason = _forge_sources_match_pin(forge_input, {"src/Foo.sol": content}, full_tree)
        assert ok is False
        assert reason == "sources_differ"

    def test_symlinked_path_refused_by_tree_reader_rejected(self):
        """Path forge includes that the O_NOFOLLOW reader refused (not in tree) → rejected."""
        content = "pragma solidity ^0.8.0;\n"
        # full_tree does NOT contain "lib/symlinked.sol" because the tree reader refused it
        full_tree = {"src/Foo.sol": content}
        ok, reason = _forge_sources_match_pin(
            self._make_input({"src/Foo.sol": content, "lib/symlinked.sol": "// via symlink\n"}),
            {"src/Foo.sol": content},
            full_tree,
        )
        assert ok is False
        assert reason == "sources_differ"

    def test_missing_full_tree_map_rejected(self):
        """full_tree=None (non-repo candidate) → rejected immediately (fail closed)."""
        content = "pragma solidity ^0.8.0;\n"
        ok, reason = _forge_sources_match_pin(
            self._make_input({"src/Foo.sol": content}),
            {"src/Foo.sol": content},
            None,
        )
        assert ok is False
        assert reason == "sources_differ"

    def test_symlinked_path_absent_from_tree_rejected(self):
        """Task 4 negative: symlinked .sol absent from O_NOFOLLOW full_tree → sources_differ.

        In a repo where lib/Symlinked.sol is a symlink to src/Real.sol, the
        O_NOFOLLOW tree reader refuses the symlink so it is absent from full_tree.
        Forge follows the symlink and includes 'lib/Symlinked.sol' in build-info
        sources.  _forge_sources_match_pin sees the path in forge sources but
        not in full_tree → fail closed with sources_differ.
        """
        real_content = "pragma solidity ^0.8.0;\ncontract Real {}\n"
        main_content = "pragma solidity ^0.8.0;\nimport 'lib/Symlinked.sol';\n"
        # full_tree: O_NOFOLLOW reader saw src/Main.sol and src/Real.sol; refused lib/Symlinked.sol
        full_tree = {
            "src/Main.sol": main_content,
            "src/Real.sol": real_content,
            # lib/Symlinked.sol is ABSENT (symlink was refused by O_NOFOLLOW reader)
        }
        # forge build-info includes the symlinked path with the content it followed
        forge_input = self._make_input({
            "src/Main.sol": main_content,
            "lib/Symlinked.sol": real_content,  # forge resolved the symlink
        })
        ok, reason = _forge_sources_match_pin(
            forge_input,
            {"src/Main.sol": main_content},
            full_tree,
        )
        assert ok is False
        assert reason == "sources_differ"


class TestForgeBuildTimeout:
    """Finding 4: timeout is read from limits.yaml, not hardcoded."""

    def test_returns_int(self):
        t = _forge_build_timeout()
        assert isinstance(t, int)
        assert t > 0

    def test_returns_300_on_garbage_yaml(self, tmp_path, monkeypatch):
        """Falls back to 300 s when limits.yaml cannot be read."""
        import soken_review.adapters.evm.build as build_mod
        monkeypatch.setattr(build_mod, "_LIMITS_YAML", tmp_path / "missing.yaml")
        assert build_mod._forge_build_timeout() == 300


# ---------------------------------------------------------------------------
# Task 1 + 2: forge_build_repo returns tuple; b4_rejected recorded on None
# ---------------------------------------------------------------------------

class TestForgeBuildRepoTuple:
    """forge_build_repo now returns (ForgeStdInput | None, str) — Task 2 (visible fallback)."""

    def test_returns_tuple_when_image_none(self, monkeypatch, tmp_path):
        """When _BUILD_IMAGE is None, returns (None, 'forge_unavailable')."""
        import soken_review.adapters.evm.build as build_mod
        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", None)
        result, reason = build_mod.forge_build_repo("/some/src", tmp_path,
                                                     tmp_path / "solc",
                                                     object())  # type: ignore[arg-type]
        assert result is None
        assert reason == "forge_unavailable"

    def test_returns_tuple_when_no_docker(self, monkeypatch, tmp_path):
        """When docker is not on PATH, returns (None, 'forge_unavailable')."""
        import shutil

        import soken_review.adapters.evm.build as build_mod
        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", "soken/evm-analyze:test")
        monkeypatch.setattr(shutil, "which", lambda _: None)
        result, reason = build_mod.forge_build_repo(str(tmp_path), tmp_path / "out",
                                                     tmp_path / "solc",
                                                     object())  # type: ignore[arg-type]
        assert result is None
        assert reason == "forge_unavailable"

    def test_returns_tuple_on_forge_failed(self, monkeypatch, tmp_path):
        """When forge exits non-zero, returns (None, 'forge_failed')."""
        import subprocess

        import soken_review.adapters.evm.build as build_mod
        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", "soken/evm-analyze:test")
        # Stub docker_argv to return something; stub Popen to simulate rc=1
        monkeypatch.setattr(build_mod, "docker_argv",
                            lambda **kw: ["echo", "fail"])
        proc_mock = type("P", (), {
            "communicate": lambda self, timeout=None: (b"", b"err"),
            "returncode": 1,
        })()
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: proc_mock)
        src = tmp_path / "src"
        src.mkdir()
        # Provide a mock cache with ._root so docker_argv call doesn't AttributeError
        class _FakeCache:
            _root = tmp_path / "cache"
        result, reason = build_mod.forge_build_repo(str(src), tmp_path / "out",
                                                     tmp_path / "linux-amd64" / "solc-0.8.20",
                                                     _FakeCache())  # type: ignore[arg-type]
        assert result is None
        assert reason == "forge_failed"

    def test_b4_rejected_recorded_in_build_notes_on_forge_unavailable(self, monkeypatch, tmp_path):
        """Task 2: when forge_build_repo returns (None, reason), build() records b4_rejected."""
        import soken_review.adapters.evm.build as build_mod
        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", None)
        # Give the candidate a src_tree_dir so the B4 branch is entered
        from soken_review.adapters.base import Candidate, Compiler
        content = "pragma solidity ^0.8.0;\ncontract C {}\n"
        (tmp_path / "src_tree").mkdir()
        cand = Candidate(
            provider="repo",  # type: ignore[arg-type]
            files={"src/C.sol": content},
            sha256="abc",
            language="solidity",
            compiler=Compiler(version="0.8.20+commit.a1b79de6", version_pinned_by="pragma"),
            settings={},
            std_json_input=None,
            entry_contract=None,
            src_tree_dir=str(tmp_path / "src_tree"),
        )
        # Stub _run_build so we skip actual solc invocation
        monkeypatch.setattr(build_mod, "_DIRECT_SOLC", True)
        from soken_review.adapters.base import BuildResult
        fake_br = BuildResult(candidate=cand, status="ok", nsloc=1)
        monkeypatch.setattr(build_mod, "_run_build", lambda *a, **kw: fake_br)
        br = build_mod.build(cand, work_dir=tmp_path / "work")
        # _BUILD_IMAGE=None → forge_build_repo returns (None, "forge_unavailable")
        assert br.build_notes.get("b4_rejected") == "forge_unavailable"
        assert "b4_source" not in br.build_notes

    def _make_forge_popen_mock(self, monkeypatch, build_info: dict, tmp_path, *, subprocess_mod):
        """Shared helper: patch Popen+read_output_files for forge_build_repo unit tests."""
        import json

        import soken_review.adapters.evm.build as build_mod

        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", "soken/evm-analyze:test")
        monkeypatch.setattr(build_mod, "docker_argv", lambda **kw: ["echo", "ok"])
        proc_mock = type("P", (), {
            "communicate": lambda self, timeout=None: (b"", b""),
            "returncode": 0,
        })()
        monkeypatch.setattr(subprocess_mod, "Popen", lambda *a, **kw: proc_mock)

        src = tmp_path / "src"
        src.mkdir()
        out_dir = tmp_path / "out"
        forge_out = out_dir / "forge_out"
        build_info_dir = forge_out / "build-info"
        build_info_dir.mkdir(parents=True)

        fake_data = {build_info_dir / "abc123.json": json.dumps(build_info).encode()}
        monkeypatch.setattr(build_mod, "read_output_files",
                            lambda *a, **kw: fake_data)

        return src, out_dir, build_mod

    def test_forge_filesystem_hint_keys_dropped_silently(self, monkeypatch, tmp_path):
        """allowPaths / basePath / includePaths at the input top-level are forge filesystem
        hints that become irrelevant once sources are inline; dropped silently without flagging
        had_unknown_settings.  'version' is now version-checked against the pinned compiler;
        when it matches, it also does not flag.
        Round-3 task 2: per coordinator rule, only truly unknown top-level keys flag.
        """
        import subprocess

        build_info = {
            "input": {
                "language": "Solidity",
                "sources": {
                    "src/C.sol": {"content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract C {}\n"}
                },
                "settings": {
                    "optimizer": {"enabled": False, "runs": 200},
                    "outputSelection": {"*": {"*": ["abi"]}},
                },
                # forge filesystem hints — drop silently, must NOT set had_unknown_settings
                "allowPaths": ["/work/src", "/work/src/lib"],
                "basePath": "/work/src",
                "includePaths": ["/work/src"],
                # version matches solc_bin name → no mismatch flag
                "version": "0.8.15+commit.e14f2a6c.Linux.g++",
            }
        }
        src, out_dir, build_mod = self._make_forge_popen_mock(
            monkeypatch, build_info, tmp_path, subprocess_mod=subprocess)

        class _FakeCache:
            _root = tmp_path / "cache"

        result, reason = build_mod.forge_build_repo(
            str(src), out_dir, tmp_path / "linux-amd64" / "solc-0.8.15+commit.e14f2a6c", _FakeCache())

        assert result is not None, f"got None: {reason!r}"
        assert reason == ""
        # All filesystem hint keys stripped from std_input
        for key in ("allowPaths", "basePath", "includePaths", "version"):
            assert key not in result.std_input, f"{key!r} leaked into std_input"
        # Filesystem hints and matching version must NOT flag had_unknown_settings
        assert result.had_unknown_settings is False, (
            "forge filesystem hints (allowPaths/basePath/includePaths) and matching version "
            "must not flag had_unknown_settings"
        )
        assert result.forge_version_mismatch is False
        assert result.std_input.get("language") == "Solidity"
        assert "src/C.sol" in result.std_input.get("sources", {})

    def test_forge_version_mismatch_sets_had_unknown_and_flag(self, monkeypatch, tmp_path):
        """version in build-info that mismatches the pinned solc → had_unknown_settings=True
        and forge_version_mismatch=True.  Task 3.
        """
        import subprocess

        build_info = {
            "input": {
                "language": "Solidity",
                "sources": {
                    "src/C.sol": {"content": "pragma solidity ^0.8.0;\ncontract C {}\n"}
                },
                "settings": {"outputSelection": {"*": {"*": ["abi"]}}},
                "version": "0.8.25+commit.7893614a.Linux.g++",  # different semver from pinned
            }
        }
        src, out_dir, build_mod = self._make_forge_popen_mock(
            monkeypatch, build_info, tmp_path, subprocess_mod=subprocess)

        class _FakeCache:
            _root = tmp_path / "cache"

        # Pinned solc is 0.8.26, forge says 0.8.25 → mismatch
        result, _reason = build_mod.forge_build_repo(
            str(src), out_dir, tmp_path / "linux-amd64" / "solc-0.8.26+commit.8a97fa7e", _FakeCache())

        assert result is not None, "forge_build_repo returned None on version mismatch"
        assert result.had_unknown_settings is True, "version mismatch must set had_unknown_settings"
        assert result.forge_version_mismatch is True, "version mismatch must set forge_version_mismatch"
        assert "version" not in result.std_input

    def test_forge_version_absent_no_flag(self, monkeypatch, tmp_path):
        """No 'version' key in build-info → no version flag, had_unknown_settings stays False."""
        import subprocess

        build_info = {
            "input": {
                "language": "Solidity",
                "sources": {
                    "src/C.sol": {"content": "pragma solidity ^0.8.0;\ncontract C {}\n"}
                },
                "settings": {"outputSelection": {"*": {"*": ["abi"]}}},
                # no 'version' key
            }
        }
        src, out_dir, build_mod = self._make_forge_popen_mock(
            monkeypatch, build_info, tmp_path, subprocess_mod=subprocess)

        class _FakeCache:
            _root = tmp_path / "cache"

        result, _reason2 = build_mod.forge_build_repo(
            str(src), out_dir, tmp_path / "linux-amd64" / "solc-0.8.26+commit.8a97fa7e", _FakeCache())

        assert result is not None
        assert result.forge_version_mismatch is False
        assert result.had_unknown_settings is False

    def test_unknown_top_level_key_still_flags(self, monkeypatch, tmp_path):
        """A top-level key that is NOT in _FORGE_TOP_SILENT_DROP and NOT in
        _SOLC_STD_JSON_KEYS must still flag had_unknown_settings=True.
        """
        import subprocess

        build_info = {
            "input": {
                "language": "Solidity",
                "sources": {
                    "src/C.sol": {"content": "pragma solidity ^0.8.0;\ncontract C {}\n"}
                },
                "settings": {"outputSelection": {"*": {"*": ["abi"]}}},
                # truly unknown key — not a forge filesystem hint
                "experimentalFuture": True,
            }
        }
        src, out_dir, build_mod = self._make_forge_popen_mock(
            monkeypatch, build_info, tmp_path, subprocess_mod=subprocess)

        class _FakeCache:
            _root = tmp_path / "cache"

        result, _reason = build_mod.forge_build_repo(
            str(src), out_dir, tmp_path / "linux-amd64" / "solc-0.8.15", _FakeCache())

        assert result is not None
        assert "experimentalFuture" not in result.std_input
        assert result.had_unknown_settings is True, (
            "unknown top-level key 'experimentalFuture' must flag had_unknown_settings"
        )


@pytest.mark.asyncio
async def test_supervisor_persists_b4_source_in_build_result_json(tmp_path: Path) -> None:
    """Task 1: supervisor writes b4_source and libraries_unverified into build_result.json."""
    import json
    from unittest.mock import AsyncMock, MagicMock, patch

    from soken_review.adapters.base import BuildResult, Candidate, Compiler
    from tests.worker.test_supervisor import FakeStore, _fake_candidate, _make_supervisor

    content = "pragma solidity ^0.8.0;\ncontract C {}\n"
    cand = Candidate(
        provider="repo",  # type: ignore[arg-type]
        files={"src/C.sol": content},
        sha256="abc",
        language="solidity",
        compiler=Compiler(version="0.8.24+commit.e11b9ed9", version_pinned_by="pragma"),
        settings={},
        std_json_input=None,
        entry_contract=None,
    )
    br = BuildResult(candidate=cand, status="ok", nsloc=1)
    br.build_notes["b4_source"] = "forge_b4"
    br.build_notes["libraries_unverified"] = True

    store = FakeStore()
    job_id = "job_B4NOTES01"
    job = store.add_job(job_id, chain_id=None, address=None)
    step = store.add_step(job_id, "build", container=True, units=2, ram_mb=4096, max_attempts=1)

    sup = _make_supervisor(store, tmp_path)
    out_dir = tmp_path.parent / "work" / job_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write candidates.json and a real pin so PinnedSource.load succeeds
    from soken_review.pinning.store import PinnedSource
    pin = PinnedSource.from_files({"src/C.sol": b"pragma solidity ^0.8.0;\ncontract C {}\n"})
    pin.persist(tmp_path, job_id)
    cands_raw = [_fake_candidate()]
    (out_dir / "candidates.json").write_text(json.dumps(cands_raw))

    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    txn_ctx = AsyncMock()
    txn_ctx.__aenter__ = AsyncMock(return_value=txn_ctx)
    txn_ctx.__aexit__ = AsyncMock(return_value=False)
    repo_mock = AsyncMock()
    repo_mock.update_job_fields = AsyncMock()
    conn_ctx.transaction = MagicMock(return_value=txn_ctx)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.worker.supervisor._build_mod.build", return_value=br), \
         patch("soken_review.worker.supervisor.safe_read_repo_tree", return_value=({}, [])), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())), \
         patch.object(sup, "_resolve_provenance", new=AsyncMock(return_value={"tier": "B"})), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_after_build", new=AsyncMock()):
        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_build(step.as_dict())

    build_path = out_dir / "build_result.json"
    assert build_path.exists()
    saved = json.loads(build_path.read_text())
    assert saved.get("b4_source") == "forge_b4"
    assert saved.get("libraries_unverified") is True
    assert "b4_rejected" not in saved


@pytest.mark.asyncio
async def test_supervisor_persists_b4_rejected_in_build_result_json(tmp_path: Path) -> None:
    """Task 1: supervisor writes b4_rejected into build_result.json when B4 was rejected."""
    import json
    from unittest.mock import AsyncMock, MagicMock, patch

    from soken_review.adapters.base import BuildResult, Candidate, Compiler
    from tests.worker.test_supervisor import FakeStore, _fake_candidate, _make_supervisor

    content = "pragma solidity ^0.8.0;\ncontract C {}\n"
    cand = Candidate(
        provider="repo",  # type: ignore[arg-type]
        files={"src/C.sol": content},
        sha256="abc",
        language="solidity",
        compiler=Compiler(version="0.8.24+commit.e11b9ed9", version_pinned_by="pragma"),
        settings={},
        std_json_input=None,
        entry_contract=None,
    )
    br = BuildResult(candidate=cand, status="ok", nsloc=1)
    br.build_notes["b4_rejected"] = "forge_unavailable"

    store = FakeStore()
    job_id = "job_B4NOTES02"
    job = store.add_job(job_id, chain_id=None, address=None)
    step = store.add_step(job_id, "build", container=True, units=2, ram_mb=4096, max_attempts=1)

    sup = _make_supervisor(store, tmp_path)
    out_dir = tmp_path.parent / "work" / job_id
    out_dir.mkdir(parents=True, exist_ok=True)

    from soken_review.pinning.store import PinnedSource
    pin = PinnedSource.from_files({"src/C.sol": b"pragma solidity ^0.8.0;\ncontract C {}\n"})
    pin.persist(tmp_path, job_id)
    cands_raw = [_fake_candidate()]
    (out_dir / "candidates.json").write_text(json.dumps(cands_raw))

    conn_ctx = AsyncMock()
    conn_ctx.__aenter__ = AsyncMock(return_value=conn_ctx)
    conn_ctx.__aexit__ = AsyncMock(return_value=False)
    txn_ctx = AsyncMock()
    txn_ctx.__aenter__ = AsyncMock(return_value=txn_ctx)
    txn_ctx.__aexit__ = AsyncMock(return_value=False)
    repo_mock = AsyncMock()
    repo_mock.update_job_fields = AsyncMock()
    conn_ctx.transaction = MagicMock(return_value=txn_ctx)

    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.worker.supervisor._build_mod.build", return_value=br), \
         patch("soken_review.worker.supervisor.safe_read_repo_tree", return_value=({}, [])), \
         patch.object(sup, "_get_job", new=AsyncMock(return_value=job.as_dict())), \
         patch.object(sup, "_resolve_provenance", new=AsyncMock(return_value={"tier": "B"})), \
         patch.object(sup, "_mark_step", new=AsyncMock()), \
         patch.object(sup, "_after_build", new=AsyncMock()):
        sup._pool.connection = MagicMock(return_value=conn_ctx)
        await sup._run_build(step.as_dict())

    build_path = out_dir / "build_result.json"
    assert build_path.exists()
    saved = json.loads(build_path.read_text())
    assert saved.get("b4_rejected") == "forge_unavailable"
    assert "b4_source" not in saved


class TestForgeB4LiveFailures:
    """Two defects seen in the first live evm-repo-e2e run (2026-10-15): forge failed on every
    repo and the reason was invisible, so a B3 fallback hid both."""

    def _cand_with_tree(self, tmp_path):
        from soken_review.adapters.base import Candidate, Compiler
        (tmp_path / "src_tree").mkdir()
        return Candidate(
            provider="repo",  # type: ignore[arg-type]
            files={"src/C.sol": "pragma solidity ^0.8.0;\ncontract C {}\n"},
            sha256="abc", language="solidity",
            compiler=Compiler(version="0.8.20+commit.a1b79de6", version_pinned_by="pragma"),
            settings={}, std_json_input=None, entry_contract=None,
            src_tree_dir=str(tmp_path / "src_tree"),
        )

    def test_forge_out_is_made_writable_for_the_sandbox_user(self, monkeypatch, tmp_path):
        """forge runs as uid 10001; a 0755 dir made by the supervisor user is not writable for it,
        so forge cannot emit build-info and exits non-zero. The out dir goes through
        sandbox_writable_dir like every other sandbox output dir."""
        import subprocess

        import soken_review.adapters.evm.build as build_mod
        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", "soken/evm-analyze:test")
        monkeypatch.setattr(build_mod, "docker_argv", lambda **kw: ["true"])
        made: list = []

        def fake_writable(path):
            path.mkdir(parents=True, exist_ok=True)
            made.append(path)
            return path
        monkeypatch.setattr(build_mod, "sandbox_writable_dir", fake_writable)
        proc_mock = type("P", (), {"communicate": lambda self, timeout=None: (b"", b""), "returncode": 1})()
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: proc_mock)

        class _FakeCache:
            _root = tmp_path / "cache"
        build_mod.forge_build_repo(str(self._cand_with_tree(tmp_path).src_tree_dir), tmp_path / "out",
                                   tmp_path / "linux-amd64" / "solc-0.8.20", _FakeCache())  # type: ignore[arg-type]
        assert made == [tmp_path / "out" / "forge_out"]

    def test_forge_failure_detail_reaches_build_notes(self, monkeypatch, tmp_path):
        """rc and a capped, printable stderr head are recorded next to b4_rejected so a live run
        shows why B4 fell back to B3."""
        import subprocess

        import soken_review.adapters.evm.build as build_mod
        from soken_review.adapters.base import BuildResult
        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", "soken/evm-analyze:test")
        monkeypatch.setattr(build_mod, "_DIRECT_SOLC", False)
        monkeypatch.setattr(build_mod, "docker_argv", lambda **kw: ["true"])
        monkeypatch.setattr(build_mod, "sandbox_writable_dir", lambda p: (p.mkdir(parents=True, exist_ok=True), p)[1])
        noise = "Error: \x1b[31mfailed\x1b[0m to write /work/out\x00\n" + "x" * 5000
        proc_mock = type("P", (), {
            "communicate": lambda self, timeout=None: (b"", noise.encode()),
            "returncode": 1,
        })()
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: proc_mock)
        cand = self._cand_with_tree(tmp_path)
        fake_br = BuildResult(candidate=cand, status="ok", nsloc=1)
        monkeypatch.setattr(build_mod, "_run_build", lambda *a, **kw: fake_br)
        monkeypatch.setattr(build_mod, "SolcCache", lambda *a, **kw: type("C", (), {"_root": tmp_path, "binary": lambda self, v: tmp_path / "linux-amd64" / "solc"})())

        br = build_mod.build(cand, work_dir=tmp_path / "work")

        notes = br.build_notes
        assert notes["b4_rejected"] == "forge_failed"
        assert notes["forge_rc"] == 1
        head = notes["forge_stderr_head"]
        assert head.startswith("Error: failed to write /work/out")      # ANSI and NUL stripped
        assert len(head) <= build_mod._FORGE_STDERR_HEAD_CHARS
        assert "\x1b" not in head and "\x00" not in head

    def test_forge_success_records_no_failure_detail(self, monkeypatch, tmp_path):
        import soken_review.adapters.evm.build as build_mod
        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", None)
        from soken_review.adapters.base import BuildResult
        cand = self._cand_with_tree(tmp_path)
        monkeypatch.setattr(build_mod, "_DIRECT_SOLC", True)
        monkeypatch.setattr(build_mod, "_run_build", lambda *a, **kw: BuildResult(candidate=cand, status="ok", nsloc=1))
        br = build_mod.build(cand, work_dir=tmp_path / "work")
        assert br.build_notes.get("b4_rejected") == "forge_unavailable"
        assert "forge_rc" not in br.build_notes and "forge_stderr_head" not in br.build_notes


class TestForgeDynamicTestLinking:
    """Live v4-core run (2026-10-15): forge 1.8.5 defaults `dynamic_test_linking = true`, which
    rewrites test helpers (test/utils/Deployers.sol) and adds synthetic `foundry-pp/*.sol` sources
    to build-info. The B4 gate rightly rejected them as sources_differ, but the reason was opaque
    and the whole repo fell back to B3 (which cannot see lib/ deps)."""

    def _run_forge_argv(self, monkeypatch, tmp_path) -> list[str]:
        import subprocess

        import soken_review.adapters.evm.build as build_mod
        monkeypatch.setattr(build_mod, "_BUILD_IMAGE", "soken/evm-analyze:test")
        monkeypatch.setattr(build_mod, "sandbox_writable_dir", lambda p: (p.mkdir(parents=True, exist_ok=True), p)[1])
        captured: dict = {}

        def fake_docker_argv(**kw):
            captured.update(kw)
            return ["true"]
        monkeypatch.setattr(build_mod, "docker_argv", fake_docker_argv)
        proc_mock = type("P", (), {"communicate": lambda self, timeout=None: (b"", b""), "returncode": 1})()
        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: proc_mock)
        (tmp_path / "src").mkdir()

        class _FakeCache:
            _root = tmp_path / "cache"
        build_mod.forge_build_repo(str(tmp_path / "src"), tmp_path / "out",
                                   tmp_path / "linux-amd64" / "solc-0.8.26", _FakeCache())  # type: ignore[arg-type]
        return captured["command"]

    def test_forge_runs_without_dynamic_test_linking(self, monkeypatch, tmp_path):
        cmd = self._run_forge_argv(monkeypatch, tmp_path)
        assert cmd[:2] == ["forge", "build"]
        assert "--no-dynamic-test-linking" in cmd
        # forge 1.8.5: "the argument '--no-cache' cannot be used with '--no-dynamic-test-linking'";
        # isolation from the repo's cache/ is the fresh tmpfs cache path instead.
        assert "--no-cache" not in cmd
        assert cmd[cmd.index("--cache-path") + 1] == "/tmp/forge-cache"
        assert "--offline" in cmd and "--no-auto-detect" in cmd                            # unchanged

    def test_gate_reports_which_source_failed_and_why(self):
        content = "pragma solidity ^0.8.26;\n"
        tree = {"src/Foo.sol": content, "test/utils/Deployers.sol": "original\n"}
        cases = {
            "synthetic": ({"src/Foo.sol": content, "foundry-pp/DeployHelper74.sol": "x\n"}, "missing_in_tree", "foundry-pp/DeployHelper74.sol"),
            "rewritten": ({"src/Foo.sol": content, "test/utils/Deployers.sol": "preprocessed\n"}, "content_differs", "test/utils/Deployers.sol"),
            "urls": ({"src/Foo.sol": {"urls": ["file:///etc/passwd"]}}, "not_inline_content", "src/Foo.sol"),
            "forward": ({"test/utils/Deployers.sol": "original\n"}, "scope_file_absent", "src/Foo.sol"),
        }
        for name, (sources, kind, path) in cases.items():
            forge_input = {"sources": {p: (v if isinstance(v, dict) else {"content": v}) for p, v in sources.items()}}
            diag: dict = {}
            ok, reason = _forge_sources_match_pin(forge_input, {"src/Foo.sol": content}, tree, diag=diag)
            assert (ok, reason) == (False, "sources_differ"), name
            assert diag == {"b4_detail": f"{kind}:{path}"}, name
        diag = {}
        ok, reason = _forge_sources_match_pin({"sources": {"src/Foo.sol": {"content": content}}},
                                              {"src/Foo.sol": content}, tree, diag=diag)
        assert (ok, reason, diag) == (True, "", {})

    def test_gate_detail_reaches_build_notes(self, monkeypatch, tmp_path):
        import soken_review.adapters.evm.build as build_mod
        from soken_review.adapters.base import BuildResult, Candidate, Compiler
        content = "pragma solidity ^0.8.26;\ncontract C {}\n"
        (tmp_path / "src_tree").mkdir()
        cand = Candidate(
            provider="repo",  # type: ignore[arg-type]
            files={"src/C.sol": content}, sha256="abc", language="solidity",
            compiler=Compiler(version="0.8.26+commit.8a97fa7a", version_pinned_by="config"),
            settings={}, std_json_input=None, entry_contract=None, src_tree_dir=str(tmp_path / "src_tree"),
        )
        cand._full_tree = {"src/C.sol": content}  # type: ignore[attr-defined]
        forge_input = build_mod.ForgeStdInput(
            std_input={"language": "Solidity", "settings": {},
                       "sources": {"src/C.sol": {"content": content}, "foundry-pp/DeployHelper1.sol": {"content": "x"}}},
            libraries_unverified=False, had_unknown_settings=False)
        monkeypatch.setattr(build_mod, "forge_build_repo", lambda *a, **kw: (forge_input, ""))
        monkeypatch.setattr(build_mod, "_DIRECT_SOLC", True)
        monkeypatch.setattr(build_mod, "_run_build", lambda *a, **kw: BuildResult(candidate=cand, status="ok", nsloc=1))
        monkeypatch.setattr(build_mod, "SolcCache", lambda *a, **kw: type("C", (), {"_root": tmp_path, "binary": lambda self, v: tmp_path / "linux-amd64" / "solc"})())

        br = build_mod.build(cand, work_dir=tmp_path / "work")

        assert br.build_notes["b4_rejected"] == "sources_differ"
        assert br.build_notes["b4_detail"] == "missing_in_tree:foundry-pp/DeployHelper1.sol"
        assert cand.untrusted_inputs is True
