"""TON verifier settings normalisation and downstream behaviour (fix/ton-build-verifier-settings).

Covers:
  1. _normalise_verifier_compiler — both fetch paths produce {"name", "version", "params"} dict
  2. scan_params — accepts Tact params (entrypoint + options) and rejects unknowns
  3. _run_build defensive path — non-dict compiler never raises AttributeError
  4. _build_tact options propagation — verifier params options reach the tact.config.json
  5. End-to-end rebuild (skipped unless SOKEN_TON_BUILD_DIRECT=1 or ton-build image is locked)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from soken_review.adapters.base import Candidate
from soken_review.adapters.ton import build as b
from soken_review.adapters.ton.fetch import _normalise_verifier_compiler
from soken_review.adapters.ton.trust_scan import scan_params

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ton"
CODE_HASH = "c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea"

# ── helpers ───────────────────────────────────────────────────────────────

_DIRECT = os.environ.get("SOKEN_TON_BUILD_DIRECT", "0") == "1"
_IMAGE_LOCKED = b._BUILD_IMAGE is not None


def _tact_candidate(settings: dict, files: dict[str, str] | None = None) -> Candidate:
    return Candidate(
        provider="ton_verifier",
        files=files or {"contracts/ft_master.tact": "contract FtMaster {}"},
        sha256="0" * 64,
        language="tact",
        compiler=None,
        settings=settings,
        std_json_input=None,
        entry_contract="contracts/ft_master.tact",
    )


# ── 1. _normalise_verifier_compiler ──────────────────────────────────────


class TestNormaliseVerifierCompiler:
    def test_registry_manifest_string_compiler(self):
        """Registry path: manifest["compiler"] is a bare string; parameters is a JSON string."""
        params_raw = json.dumps({"entrypoint": "contracts/ft_master.tact", "options": {"debug": False}})
        result = _normalise_verifier_compiler("tact", "1.6.5", params_raw)
        assert result == {
            "name": "tact",
            "version": "1.6.5",
            "params": {"entrypoint": "contracts/ft_master.tact", "options": {"debug": False}},
        }

    def test_registry_fixture_manifest(self):
        """Exactly matches the fixture file used by the live job."""
        manifest = json.loads((FIXTURES / "registry_ipfs_manifest.json").read_text())
        cs = manifest.get("compilerSettings") or {}
        result = _normalise_verifier_compiler(
            name=manifest.get("compiler"),
            version=cs.get("tactVersion") or cs.get("compilerVersion"),
            params_raw=cs.get("parameters"),
        )
        assert isinstance(result, dict)
        assert result["name"] == "tact"
        assert result["version"] == "1.6.5"
        params = result["params"]
        assert isinstance(params, dict)
        assert params["entrypoint"] == "contracts/ft_master.tact"
        assert params["options"] == {"debug": False}

    def test_legacy_dict_params(self):
        """Legacy path: compiler.params is already a dict (FunC compiler_version)."""
        result = _normalise_verifier_compiler("func", "0.4.4", {"compiler_version": "0.4.4"})
        assert result["name"] == "func"
        assert result["version"] == "0.4.4"
        assert result["params"] == {"compiler_version": "0.4.4"}

    def test_invalid_json_string_is_marked_invalid(self):
        result = _normalise_verifier_compiler("tact", "1.6.5", "not-valid-json{{{")
        assert "__invalid__" in result["params"]

    def test_oversized_json_string_is_marked_invalid(self):
        big = json.dumps({"entrypoint": "a.tact", "data": "x" * 5000})
        result = _normalise_verifier_compiler("tact", "1.6.5", big)
        assert "__invalid__" in result["params"]

    def test_non_dict_json_is_marked_invalid(self):
        result = _normalise_verifier_compiler("tact", "1.6.5", json.dumps(["list", "not", "dict"]))
        assert "__invalid__" in result["params"]

    def test_name_is_lowercased(self):
        result = _normalise_verifier_compiler("TACT", "1.6.5", None)
        assert result["name"] == "tact"

    def test_none_version_preserved(self):
        result = _normalise_verifier_compiler("func", None, None)
        assert result["version"] is None

    def test_empty_string_version_is_none(self):
        result = _normalise_verifier_compiler("func", "", None)
        assert result["version"] is None


# ── 2. scan_params — Tact params ─────────────────────────────────────────


class TestScanParamsTact:
    def test_entrypoint_and_debug_option_trusted(self):
        params = {"entrypoint": "contracts/ft_master.tact", "options": {"debug": False}}
        assert scan_params(params) == []

    def test_full_tact_options_trusted(self):
        params = {
            "entrypoint": "contracts/main.tact",
            "options": {
                "debug": False,
                "external": True,
                "ipfsAbiGetter": False,
                "interfacesGetter": False,
                "enableLazyDeploymentCompletedGetter": False,
                "experimental": {"inline": False},
                "safety": {"nullChecks": True},
                "optimizations": {
                    "alwaysSaveContractData": False,
                    "internalExternalReceiversOutsideMethodsMap": True,
                },
            },
        }
        assert scan_params(params) == []

    def test_entrypoint_only_trusted(self):
        assert scan_params({"entrypoint": "contracts/main.tact"}) == []

    def test_func_compiler_version_still_trusted(self):
        assert scan_params({"compiler_version": "0.4.4"}) == []

    def test_unknown_top_level_key_untrusted(self):
        reasons = scan_params({"entrypoint": "a.tact", "extra_flag": True})
        assert any("outside the allowlist" in r for r in reasons)

    def test_non_tact_entrypoint_untrusted(self):
        reasons = scan_params({"entrypoint": "contracts/main.fc"})
        assert any("not a .tact file" in r for r in reasons)

    def test_entrypoint_not_string_untrusted(self):
        reasons = scan_params({"entrypoint": 42})
        assert any("not a string" in r for r in reasons)

    def test_options_not_dict_untrusted(self):
        reasons = scan_params({"entrypoint": "a.tact", "options": "debug"})
        assert any("not an object" in r for r in reasons)

    def test_unknown_option_key_untrusted(self):
        reasons = scan_params({"entrypoint": "a.tact", "options": {"masterchain": True}})
        assert any("outside the allowlist" in r for r in reasons)

    def test_option_non_bool_scalar_untrusted(self):
        reasons = scan_params({"entrypoint": "a.tact", "options": {"debug": "yes"}})
        assert any("not a boolean" in r for r in reasons)

    def test_nested_option_unknown_sub_key_untrusted(self):
        reasons = scan_params({"entrypoint": "a.tact", "options": {"experimental": {"newFeature": True}}})
        assert any("outside the allowlist" in r for r in reasons)

    def test_nested_option_not_dict_untrusted(self):
        reasons = scan_params({"entrypoint": "a.tact", "options": {"experimental": True}})
        assert any("not an object" in r for r in reasons)

    def test_nested_sub_key_not_bool_untrusted(self):
        reasons = scan_params({"entrypoint": "a.tact", "options": {"safety": {"nullChecks": 1}}})
        assert any("not a boolean" in r for r in reasons)

    def test_none_and_empty_are_trusted(self):
        assert scan_params(None) == []
        assert scan_params({}) == []

    def test_non_dict_is_untrusted(self):
        reasons = scan_params("tact")
        assert reasons


# ── 3. _run_build defensive: non-dict compiler never raises AttributeError ──


class TestBuildDefensiveCompilerShape:
    """Regression: bare string in settings["verifier"]["compiler"] must not crash build.py."""

    def _build_with_compiler_value(self, compiler_val, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> b.BuildResult:
        cand = _tact_candidate(
            settings={"entry": "contracts/ft_master.tact", "verifier": {"compiler": compiler_val}},
        )
        # Prevent actual docker/node execution; scan_params failure raises untrusted_args early.
        # We just need _run_build to not AttributeError before it returns.
        def fake_run(script, args, work_dir, timeout):
            return "", 0
        monkeypatch.setattr(b, "_run", fake_run)
        monkeypatch.setattr(b, "_read_output", lambda *a, **k: ({}, ""))
        work = tmp_path / "attempt"
        work.mkdir()
        (work / "src").mkdir()
        return b._run_build(cand, "tact", work)

    def test_bare_string_compiler_fails_with_untrusted_args_not_attribute_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The pre-fix crash: settings["verifier"]["compiler"] = "tact" → AttributeError."""
        result = self._build_with_compiler_value("tact", tmp_path, monkeypatch)
        assert result.reason == "untrusted_args", f"expected untrusted_args, got {result.reason!r}"

    def test_none_compiler_ok(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._build_with_compiler_value(None, tmp_path, monkeypatch)
        # None = no params to scan; should not crash (may fail for other reasons like no output)
        assert result.reason != "untrusted_args"

    def test_dict_compiler_no_params_ok(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._build_with_compiler_value({"name": "tact", "version": "1.6.13", "params": None}, tmp_path, monkeypatch)
        assert result.reason != "untrusted_args"


# ── 4. _build_tact options propagation ───────────────────────────────────


class TestBuildTactOptionsFromVerifierParams:
    """_build_tact should embed verifier params options in the generated tact.config.json."""

    def _run_tact_build_capture_cfg(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        settings: dict,
        source_files: dict[str, str] | None = None,
    ) -> dict:
        work = tmp_path / "attempt"
        (work / "src" / "contracts").mkdir(parents=True)
        for rel, content in (source_files or {"contracts/ft_master.tact": "contract FtMaster {}"}).items():
            (work / "src" / rel).write_text(content)
        seen: dict = {}

        def fake_run(script, args, work_dir, timeout):
            seen.update(json.loads((work_dir / "tact.config.json").read_text()))
            return "stop", 1

        monkeypatch.setattr(b, "_run", fake_run)
        cand = Candidate(
            provider="ton_verifier",
            files=source_files or {"contracts/ft_master.tact": "contract FtMaster {}"},
            sha256="0" * 64,
            language="tact",
            compiler=None,
            settings=settings,
            std_json_input=None,
            entry_contract="contracts/ft_master.tact",
        )
        b._build_tact(cand, "1.6.13", work)
        return seen

    def test_debug_option_propagated_from_verifier_params(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = {
            "entry": "contracts/ft_master.tact",
            "verifier": {
                "compiler": {
                    "name": "tact",
                    "version": "1.6.5",
                    "params": {
                        "entrypoint": "contracts/ft_master.tact",
                        "options": {"debug": False},
                    },
                }
            },
        }
        cfg = self._run_tact_build_capture_cfg(tmp_path, monkeypatch, settings)
        assert cfg["projects"][0].get("options") == {"debug": False}

    def test_all_tact_options_propagated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opts = {
            "debug": True,
            "external": False,
            "experimental": {"inline": True},
            "safety": {"nullChecks": False},
        }
        settings = {
            "entry": "contracts/ft_master.tact",
            "verifier": {
                "compiler": {
                    "name": "tact",
                    "version": "1.6.5",
                    "params": {"entrypoint": "contracts/ft_master.tact", "options": opts},
                }
            },
        }
        cfg = self._run_tact_build_capture_cfg(tmp_path, monkeypatch, settings)
        assert cfg["projects"][0].get("options") == opts

    def test_no_params_builds_minimal_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = {"entry": "contracts/ft_master.tact", "verifier": {}}
        cfg = self._run_tact_build_capture_cfg(tmp_path, monkeypatch, settings)
        proj = cfg["projects"][0]
        assert "options" not in proj

    def test_unknown_option_key_not_propagated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Options with unknown keys fail check_config; nothing is added to the project."""
        settings = {
            "entry": "contracts/ft_master.tact",
            "verifier": {
                "compiler": {
                    "name": "tact",
                    "version": "1.6.5",
                    "params": {
                        "entrypoint": "contracts/ft_master.tact",
                        "options": {"unknownFlag": True},
                    },
                }
            },
        }
        cfg = self._run_tact_build_capture_cfg(tmp_path, monkeypatch, settings)
        # check_config returns a reason; options block is not added
        proj = cfg["projects"][0]
        assert "options" not in proj


# ── 5. End-to-end rebuild ─────────────────────────────────────────────────
#
# Rebuilds the live FtSquad contract from the fixture sources using the
# recorded registry manifest.  Skipped unless ton-build image is locked in
# images.lock.json OR SOKEN_TON_BUILD_DIRECT=1 (local node install).
#
# Expected: rebuilt hash == c845917da4a4ce1cb22aa00f65a82c3775e4c6a3c74453f9352e96d8d14fbfea

_REBUILD_SKIP = pytest.mark.skipif(
    not (_DIRECT or _IMAGE_LOCKED),
    reason="ton-build image not available and SOKEN_TON_BUILD_DIRECT not set",
)


@_REBUILD_SKIP
def test_registry_manifest_rebuild_matches_deployed_hash(tmp_path: Path) -> None:
    """Full rebuild from fixture sources using normalised verifier settings.

    Verifies that:
    - Settings normalisation produces params with entrypoint + options.
    - scan_params passes (no untrusted_args).
    - _build_tact applies the options and produces a BoC whose hash matches the deployed contract.
    - provenance tier would be A (MATCH_REBUILD).
    """
    from soken_review.adapters.ton.fetch import _normalise_verifier_compiler
    from soken_review.adapters.ton.provenance import MATCH_REBUILD, Attempt, Dep, resolve_provenance

    manifest = json.loads((FIXTURES / "registry_ipfs_manifest.json").read_text())
    cs = manifest.get("compilerSettings") or {}
    compiler_norm = _normalise_verifier_compiler(
        name=manifest.get("compiler"),
        version=cs.get("tactVersion") or cs.get("compilerVersion"),
        params_raw=cs.get("parameters"),
    )
    assert scan_params(compiler_norm.get("params")) == [], "params must be trusted"

    # Source files from the fixture manifest (only .tact files present in the fixture)
    sources: dict[str, str] = {
        "contract/contracts/ft_master.tact": (FIXTURES / "ft_master.tact").read_text()
        if (FIXTURES / "ft_master.tact").exists()
        else "// placeholder — provide real sources for rebuild test",
        "contract/contracts/messages.tact": (FIXTURES / "messages.tact").read_text()
        if (FIXTURES / "messages.tact").exists()
        else "",
    }

    # If source fixtures are not available we can't rebuild; skip gracefully
    if "placeholder" in sources.get("contract/contracts/ft_master.tact", ""):
        pytest.skip("source fixture files (ft_master.tact, messages.tact) not present")

    settings = {
        "entry": "contract/contracts/ft_master.tact",
        "verifier": {
            "compiler": compiler_norm,
            "code_hash": CODE_HASH,
        },
    }
    cand = Candidate(
        provider="ton_verifier",
        files=sources,
        sha256="0" * 64,
        language="tact",
        compiler=None,
        settings=settings,
        std_json_input=None,
        entry_contract="contract/contracts/ft_master.tact",
    )

    result = b.build(cand, work_dir=tmp_path / "attempt")
    assert result.status == "ok", f"build failed: {result.reason} {result.stderr_head}"

    hashes = {a.runtime for a in result.artifacts}
    assert CODE_HASH in hashes, (
        f"rebuilt hash not in {hashes}; expected {CODE_HASH}"
    )

    # Provenance resolves to tier A
    dep = Dep(address="EQAvJuEln0lP8c2YMZ4sKGwQRt_kmxmC494v8Y4TTHgOasKJ", hash=CODE_HASH, status="active")

    def attempt_fn(i: int, c: Candidate) -> Attempt:
        return Attempt(
            cand_index=i,
            provider=c.provider,
            status=result.status,
            hashes={a.contract: a.runtime for a in result.artifacts},
            build_config=c.settings.get("tact_build_config"),
            untrusted_inputs=c.untrusted_inputs or False,
        )

    out = resolve_provenance(dep, [cand], attempt_fn)
    assert out.reason == MATCH_REBUILD, f"expected MATCH_REBUILD, got {out.reason}"


def test_unparseable_params_fail_closed():
    from soken_review.adapters.ton.fetch import _normalise_verifier_compiler
    from soken_review.adapters.ton.trust_scan import scan_params

    for raw in ("{not json", "[1,2]", "x" * 5000, 42):
        params = _normalise_verifier_compiler("tact", "1.6.5", raw)["params"]
        assert scan_params(params), raw  # rejected, never treated as "no params"
    assert _normalise_verifier_compiler("tact", "1.6.5", None)["params"] is None
    assert _normalise_verifier_compiler("tact", "1.6.5", "")["params"] is None
