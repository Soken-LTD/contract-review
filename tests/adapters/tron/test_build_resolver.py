"""TRON compiler choice (adapters/tron/build.py resolve_tron_solc).

Exact tron-solc tag first; when no pinned tron-solc exists for the explorer field (most Tronscan
fields, e.g. "tron_0.6.2_Plato_v4.2"), the upstream solc of the same version, or the newest one
every pragma allows. Before this the supervisor built TRON with the EVM path and every such job
ended `compiler_binary_missing` (matrix run 2026-10-25, CRS Token).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from soken_review.adapters.base import Candidate, Compiler
from soken_review.adapters.tron import build as tron_build
from soken_review.adapters.tron.compiler import TronCompilerCacheError

_BUILDS = [
    {"version": "0.6.2", "longVersion": "0.6.2+commit.bacdbe57", "path": "solc-linux-amd64-v0.6.2", "sha256": "0x1"},
    {"version": "0.6.12", "longVersion": "0.6.12+commit.27d51765", "path": "solc-0.6.12", "sha256": "0x2"},
    {"version": "0.8.20", "longVersion": "0.8.20+commit.a1b79de6", "path": "solc-0.8.20", "sha256": "0x3"},
    {"version": "0.8.21", "longVersion": "0.8.21-nightly", "path": "solc-n", "sha256": "0x4", "prerelease": "n"},
]
_SRC_06 = {"Token.sol": "// SPDX\npragma solidity ^0.6.0;\ncontract T {}\n"}


class _FakeSolcCache:
    def __init__(self, root: Path) -> None:
        self._root = root
        self.asked: list[str] = []

    def _load_list(self) -> dict:
        return {"builds": _BUILDS}

    def binary(self, version: str) -> Path:
        self.asked.append(version)
        return self._root / "linux-amd64" / f"solc-{version}"


class _NoTronCache:
    def binary(self, tag: str) -> Path:
        raise TronCompilerCacheError("tron_compiler_unmapped")


@pytest.fixture
def fake_caches(tmp_path):
    solc = _FakeSolcCache(tmp_path)
    with patch.object(tron_build, "get_tron_cache", lambda cache_dir=None: _NoTronCache()), \
            patch("soken_review.adapters.evm.compiler.get_cache", lambda cache_dir=None: solc):
        yield solc


def test_tronscan_field_without_pinned_tron_solc_uses_upstream_same_version(fake_caches):
    solc, reason = tron_build.resolve_tron_solc("tron_0.6.2_Plato_v4.2", _SRC_06)
    assert reason == ""
    assert solc is not None and solc.kind == "upstream_solc"
    assert solc.version == "0.6.2+commit.bacdbe57"
    assert solc.path.name == "solc-0.6.2+commit.bacdbe57"
    assert solc.cache is fake_caches          # mounted as /cache; binary path is relative to it


def test_explorer_version_rejected_by_pragma_falls_back_to_pragma_pick(fake_caches):
    # 0.8.20 does not satisfy ^0.6.0: never compile with a version a pragma rejects.
    solc, _ = tron_build.resolve_tron_solc("tron_0.8.20_GreatVoyage", _SRC_06)
    assert solc is not None and solc.version == "0.6.12+commit.27d51765"


def test_no_explorer_version_uses_newest_pragma_release(fake_caches):
    solc, _ = tron_build.resolve_tron_solc(None, {"A.sol": "pragma solidity >=0.8.0 <0.9.0;\n"})
    assert solc is not None and solc.version == "0.8.20+commit.a1b79de6"   # prerelease skipped


def test_nothing_satisfies_pragma_returns_reason(fake_caches):
    solc, reason = tron_build.resolve_tron_solc("tron_0.4.24_Odyssey", {"A.sol": "pragma solidity 0.4.24;\n"})
    assert solc is None
    assert reason == "tron_compiler_unmapped"


def test_pinned_tron_solc_wins(tmp_path, fake_caches):
    binary = tmp_path / "tron" / "tv_0.8.18" / "solc-static-linux"

    class _TronCache:
        def binary(self, tag: str) -> Path:
            assert tag == "tv_0.8.18"
            return binary

    with patch.object(tron_build, "get_tron_cache", lambda cache_dir=None: _TronCache()):
        solc, _ = tron_build.resolve_tron_solc("tron_v0.8.18+commit.abc", {"A.sol": "pragma solidity ^0.8.0;\n"})
    assert solc is not None and solc.kind == "tron_solc" and solc.version == "tv_0.8.18"
    assert solc.cache._root == tmp_path / "tron"     # /cache/<tag>/solc-static-linux in the sandbox
    assert fake_caches.asked == []


def test_malicious_version_string_never_reaches_a_cache(fake_caches):
    solc, _ = tron_build.resolve_tron_solc("../../etc/passwd", {"A.sol": "pragma solidity 0.6.2;\n"})
    # The tag gate rejects it; the upstream pick comes from the pragma only, by list.json entry.
    assert solc is not None and solc.version == "0.6.2+commit.bacdbe57"
    assert all("/" not in v for v in fake_caches.asked)


def test_build_tron_records_compiler_kind(fake_caches, tmp_path):
    cand = Candidate(provider="tronscan", files=_SRC_06, sha256="0" * 64, language="solidity",
                     compiler=Compiler("tron_0.6.2_Plato_v4.2", "tronscan"), settings={},
                     std_json_input=None, entry_contract="Token.sol:T")
    seen = {}

    def fake_run_build(candidate, std_input, solc_bin, work_dir, cache):
        from soken_review.adapters.base import BuildResult

        seen["bin"] = solc_bin
        return BuildResult(candidate=candidate, status="ok", work_dir=str(work_dir))

    with patch.object(tron_build, "_run_build", fake_run_build):
        br = tron_build.build_tron(cand, work_dir=tmp_path / "w")
    assert br.status == "ok"
    assert br.build_notes == {"compiler_kind": "upstream_solc", "compiler_used": "0.6.2+commit.bacdbe57"}
    assert seen["bin"].name == "solc-0.6.2+commit.bacdbe57"


def test_build_tron_fails_closed_without_compiler(fake_caches):
    cand = Candidate(provider="tronscan", files={"A.sol": "pragma solidity 0.4.24;\n"}, sha256="0" * 64,
                     language="solidity", compiler=Compiler("tron_0.4.24_Odyssey", "tronscan"), settings={},
                     std_json_input=None, entry_contract=None)
    br = tron_build.build_tron(cand)
    assert br.status == "failed" and br.reason == "tron_compiler_unmapped"


def test_pathological_pragma_file_is_linear_and_bounded(fake_caches):
    import time

    # 200k pragma lines with no ';' plus one huge line: the old `[^;]+` rescanned to the end per line.
    text = "pragma solidity ^0.6.0\n" * 200_000 + "pragma solidity " + "x" * 2_000_000 + "\n"
    t0 = time.monotonic()
    exprs, reason = tron_build.pragma_exprs({"A.sol": text})
    assert time.monotonic() - t0 < 5
    assert exprs == [] and reason == ""


def test_too_many_pragmas_fail_closed_with_a_reason(fake_caches):
    src = {"A.sol": "pragma solidity ^0.6.0;\n" * (tron_build._MAX_PRAGMA_LINES + 1)}
    solc, reason = tron_build.resolve_tron_solc("tron_0.6.2_Plato", src)
    assert solc is None and reason == "pragma_limit_exceeded"
    cand = Candidate(provider="tronscan", files=src, sha256="0" * 64, language="solidity",
                     compiler=Compiler("tron_0.6.2_Plato", "tronscan"), settings={},
                     std_json_input=None, entry_contract=None)
    br = tron_build.build_tron(cand)
    assert br.status == "failed" and br.reason == "pragma_limit_exceeded"   # honest status, sources kept
    assert br.candidate.files == src
