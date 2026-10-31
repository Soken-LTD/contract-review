"""BakerFi repo job 2026-10-31 (blind A/B round 5b, job_0YGC70PBPPG80ZXP2EDNZ74XXJ): the build first
tried solc 0.4.21 and Slither produced nothing, so the reviewer got lifecycle leads only.

Root causes, both reproduced against code-423n4/2024-12-bakerfi@0daf8a05:
  1. hardhat.config.ts lists six compilers in `solidity.compilers` (0.4.21 first, for legacy WETH);
     the config regex stopped at the first `},` + newline (the end of compilers[0].settings.optimizer),
     saw only 0.4.21, and `pick_config_version` returned a pin no reviewed pragma (^0.8.24) accepts.
  2. Slither's aggregate entry used `import "./p";` for every reviewed file; two reviewed files
     declare `IVault` (interfaces/core and interfaces/balancer), so solc failed with "Identifier
     already declared", crytic-compile raised JSONDecodeError and the static map said only
     `analyzer_failed`.
No network: fixtures are inline; the one real-compile check runs only where a solc binary exists.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from soken_review.adapters.evm import analyze
from soken_review.adapters.evm import solc_select as sel
from soken_review.adapters.evm.repo_candidate import repo_candidate_from_manifest
from soken_review.mapping.analyzer_note import details_of, note_from

# Shape of BakerFi's hardhat.config.ts `solidity` block (nested settings objects, six compilers).
BAKERFI_HARDHAT = """import { HardhatUserConfig } from 'hardhat/config';
import 'solidity-coverage';

const config: HardhatUserConfig = {
  defaultNetwork: 'hardhat',
  // the team's note: don't bump the legacy compilers { they build WETH9 }
  solidity: {
    compilers: [
      {
        version: '0.4.21',
        settings: {
          optimizer: {
            enabled: true,
            runs: 0,
          },
        },
      },
      {
        version: '0.6.12',
        settings: { optimizer: { enabled: true, runs: 0 } },
      },
      {
        version: '0.4.24',
        settings: { optimizer: { enabled: true, runs: 0 } },
      },
      {
        version: '0.5.17',
        settings: { optimizer: { enabled: true, runs: 0 } },
      },
      {
        version: '0.8.24',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
          outputSelection: {
            '*': {
              '*': ['storageLayout'],
            },
          },
        },
      },
      {
        version: '0.8.15',
        settings: { optimizer: { enabled: true, runs: 200 } },
      },
    ],
  },
  docgen: { outputDir: 'doc', pages: 'files' },
};

export default config;
"""

BUILDS = [{"version": v, "longVersion": f"{v}+commit.{i:08d}"}
          for i, v in enumerate(["0.4.21", "0.5.17", "0.6.12", "0.8.15", "0.8.24", "0.8.28"])]

CORE_IVAULT = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ninterface IVault { function totalAssets() external view returns (uint256); }\n"
BALANCER_IVAULT = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\ninterface IVault { function flashLoan() external; }\n"
VAULT = ('// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\nimport { IVault } from "../interfaces/core/IVault.sol";\n'
         "contract Vault { IVault public v; }\n")
LENDER = ('// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\n'
          'import { IVault } from "../../interfaces/balancer/IVault.sol";\n'
          "contract BalancerFlashLender { IVault public balancer; }\n")
WETH = "// SPDX-License-Identifier: MIT\npragma solidity ^0.4.18;\ncontract WETH9 { uint public x; }\n"

BAKERFI_TREE = {
    "hardhat.config.ts": BAKERFI_HARDHAT,
    "contracts/core/Vault.sol": VAULT,
    "contracts/core/flashloan/BalancerFlashLender.sol": LENDER,
    "contracts/interfaces/core/IVault.sol": CORE_IVAULT,
    "contracts/interfaces/balancer/IVault.sol": BALANCER_IVAULT,
    "contracts/mocks/WETH9.sol": WETH,
}

# The Slither stderr of the failed analyze step (stand journal, condensed to its shape).
SLITHER_STDERR = """Traceback (most recent call last):
  File "/usr/local/bin/slither", line 8, in <module>
    sys.exit(main())
  File "/usr/local/lib/python3.12/json/decoder.py", line 355, in raw_decode
    raise JSONDecodeError("Expecting value", s, err.value) from None
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
Warning: "error" will be promoted to keyword in the future and will not be allowed as an identifier anymore.
  --> node_modules/@openzeppelin/contracts/utils/X.sol:10:5:

Error: Identifier already declared.
  --> soken_review_entry.sol:13:1:
   |
13 | import "./contracts/core/flashloan/BalancerFlashLender.sol";
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Note: The previous declaration is here:
  --> contracts/interfaces/core/IVault.sol:18:1:
"""


# ── 1. compiler choice follows the hardhat compilers list and the in-scope pragmas ──────────────

def test_hardhat_compilers_list_is_read_whole():
    got = sel.config_versions({"hardhat.config.ts": BAKERFI_HARDHAT})
    assert [v for v, _ in got] == ["0.4.21", "0.6.12", "0.4.24", "0.5.17", "0.8.24", "0.8.15"]


def test_hardhat_block_ignores_braces_in_strings_and_comments():
    text = ("module.exports = {\n  solidity: {\n    // a } in a comment, and it's fine\n"
            "    compilers: [{ version: '0.7.6', settings: { a: '}' } },\n"
            "      /* } */ { version: \"0.8.20\" }],\n  },\n};\n")
    assert [v for v, _ in sel.config_versions({"hardhat.config.js": text})] == ["0.7.6", "0.8.20"]


def test_bakerfi_pin_is_the_listed_compiler_the_pragmas_accept():
    got = sel.config_versions({"hardhat.config.ts": BAKERFI_HARDHAT})
    assert sel.pick_config_version(got, ["^0.8.24"]) == ("0.8.24", "hardhat.config.ts")


def _repo(tmp_path: Path, files: dict[str, str]):
    src = tmp_path / "src"
    for rel, text in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text, encoding="utf-8")
    manifest = {"version": "soken-fetch.v1", "files": [{"path": p, "sha256": "0" * 64} for p in files]}
    return repo_candidate_from_manifest(src, manifest, source_url="https://github.com/example/bakerfi@" + "a" * 40,
                                        builds=BUILDS)


def test_bakerfi_repo_candidate_builds_with_0_8_24_not_the_legacy_pin(tmp_path):
    cand, reason = _repo(tmp_path, BAKERFI_TREE)
    assert reason is None and cand is not None
    assert cand.compiler.version == "0.8.24" and cand.compiler.version_pinned_by == "config"
    # the legacy mock that the 0.4.21 entry exists for is not a reviewed file
    assert "contracts/mocks/WETH9.sol" not in cand.files


def test_config_pin_no_pragma_accepts_falls_to_the_pragma_rule(tmp_path):
    tree = {"hardhat.config.js": "module.exports = { solidity: '0.4.21' };\n",
            "contracts/core/Vault.sol": VAULT, "contracts/interfaces/core/IVault.sol": CORE_IVAULT}
    cand, _ = _repo(tmp_path, tree)
    assert cand.compiler.version == "0.8.28+commit.00000005" and cand.compiler.version_pinned_by == "pragma"


# ── 2. Slither runs on the in-scope compilation; a failure carries its reason ───────────────────

def test_aggregate_entry_imports_each_file_into_its_own_namespace(tmp_path):
    src = tmp_path / "src"
    for rel, text in BAKERFI_TREE.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    scope = {p for p in BAKERFI_TREE if p.endswith(".sol") and "/mocks/" not in p}
    name = analyze._write_aggregate_entry(src, scope)
    lines = [ln for ln in (src / name).read_text().splitlines() if ln.startswith("import")]
    assert len(lines) == len(scope)
    assert all(ln.startswith('import "./') and f'" as {analyze._AGGREGATE_ALIAS}' in ln for ln in lines)
    assert len({ln.rsplit(" as ", 1)[1] for ln in lines}) == len(lines)   # unique aliases
    assert "mocks" not in (src / name).read_text()


@pytest.mark.skipif(shutil.which("solc") is None, reason="no local solc binary")
def test_aggregate_entry_compiles_with_two_same_named_interfaces(tmp_path):
    """Real compile where a solc binary exists: the aliased entry compiles; the old global
    imports fail with "Identifier already declared"."""
    src = tmp_path / "src"
    tree = {k: v.replace("^0.8.24", ">=0.8.0") for k, v in BAKERFI_TREE.items() if k.endswith(".sol") and "mocks" not in k}
    for rel, text in tree.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    version = subprocess.run(["solc", "--version"], capture_output=True, text=True, check=False).stdout
    if "0.8." not in version:
        pytest.skip("local solc is not 0.8.x")
    name = analyze._write_aggregate_entry(src, set(tree))
    ok = subprocess.run(["solc", name], cwd=src, capture_output=True, text=True, check=False)
    assert ok.returncode == 0, ok.stderr
    (src / "old.sol").write_text("".join(f'import "./{p}";\n' for p in sorted(tree)))
    old = subprocess.run(["solc", "old.sol"], cwd=src, capture_output=True, text=True, check=False)
    assert old.returncode != 0 and "Identifier already declared" in old.stderr


def test_slither_failure_names_the_first_solc_error_not_the_json_decode():
    reason, detail = analyze.slither_failure(SLITHER_STDERR, 1)
    assert reason == "compile_failed"
    assert detail == "Error: Identifier already declared. at soken_review_entry.sol:13"


@pytest.mark.parametrize(("stderr", "rc", "timed_out", "produced", "want"), [
    ("Traceback (most recent call last):\n  File \"/x.py\", line 1\nslither.exceptions.SlitherError: bad ast\n",
     1, False, False, ("internal_error", "SlitherError")),
    # a Python TypeError at the end of a traceback is not a solc diagnostic (no location line)
    ("Traceback (most recent call last):\nTypeError: 'NoneType' object is not iterable\n",
     1, False, False, ("internal_error", "TypeError")),
    ("TypeError: Member \"x\" not found.\n  --> contracts/core/Vault.sol:7:3:\n", 1, False, False,
     ("compile_failed", 'TypeError: Member "x" not found. at contracts/core/Vault.sol:7')),
    ("", None, True, False, ("timeout", None)),
    ("", 0, False, False, ("no_output", None)),
    ("killed", 137, False, False, ("analyzer_failed", "exit code 137")),
])
def test_slither_failure_codes(stderr, rc, timed_out, produced, want):
    assert analyze.slither_failure(stderr, rc, timed_out, produced) == want


def test_detail_never_carries_a_host_path():
    stderr = "Error: Source \"/opt/soken/x.sol\" not found: File outside of allowed directories.\n  --> /work/analyze/proj/src/e.sol:2:1:\n"
    reason, detail = analyze.slither_failure(stderr, 1)
    assert reason == "compile_failed" and "/opt" not in (detail or "") and "/work" not in (detail or "")


def _slither_proj(tmp_path: Path) -> tuple[Path, Path]:
    out = tmp_path / "work" / "analyze"
    proj = out / "proj"
    (proj / "src").mkdir(parents=True)
    (out / "sbx").mkdir(parents=True)
    (proj / "src" / "soken_review_entry.sol").write_text('import "./A.sol" as soken_review_unit_0;\n')
    return proj, out


def test_run_slither_records_the_failure_reason(tmp_path, monkeypatch):
    proj, out = _slither_proj(tmp_path)

    def fake_sandboxed(work_dir, command, **kw):
        kw["diag"].update(returncode=1, stderr=SLITHER_STDERR)
        return True                       # completed, but no slither_out.json written

    monkeypatch.setattr(analyze, "_DIRECT_TOOLS", False)
    monkeypatch.setattr(analyze, "_run_sandboxed", fake_sandboxed)
    monkeypatch.setattr(analyze, "_solc_cache_root", lambda: tmp_path)
    diag: dict[str, Any] = {}
    assert analyze._run_slither(proj, out, str(tmp_path / "solc"), {}, "soken_review_entry.sol", diag=diag) is None
    assert diag == {"reason": "compile_failed",
                    "detail": "Error: Identifier already declared. at soken_review_entry.sol:13"}


def test_run_slither_reads_the_error_slither_wrote_into_its_json(tmp_path, monkeypatch):
    proj, out = _slither_proj(tmp_path)

    def fake_sandboxed(work_dir, command, **kw):
        kw["diag"].update(returncode=255, stderr="")
        (out / "sbx" / "slither_out.json").write_text(json.dumps(
            {"success": False, "error": "Error: Identifier already declared.\n  --> soken_review_entry.sol:4:1:\n",
             "results": {}}))
        return True

    monkeypatch.setattr(analyze, "_DIRECT_TOOLS", False)
    monkeypatch.setattr(analyze, "_run_sandboxed", fake_sandboxed)
    monkeypatch.setattr(analyze, "_solc_cache_root", lambda: tmp_path)
    diag: dict[str, Any] = {}
    assert analyze._run_slither(proj, out, str(tmp_path / "solc"), {}, "soken_review_entry.sol", diag=diag) is None
    assert diag["reason"] == "compile_failed" and "soken_review_entry.sol:4" in diag["detail"]


def test_analyze_never_returns_a_silent_zero_lead_run(tmp_path, monkeypatch):
    """analyze(): Slither gave nothing -> static_map not_run with tool, reason and detail; the
    reviewer-facing analyzer_note names the cause."""
    from soken_review.adapters.base import BuildResult, Candidate, Compiler

    def fake_slither(proj_dir, out_dir, solc_path, settings, entry, image=None, diag=None):
        diag.update(reason="compile_failed", detail="Error: Identifier already declared. at soken_review_entry.sol:13")

    monkeypatch.setattr(analyze, "_DIRECT_TOOLS", True)
    monkeypatch.setattr(analyze, "_materialize_sources", lambda *a, **k: True)
    monkeypatch.setattr(analyze, "_solc_path", lambda r: str(tmp_path / "solc"))
    monkeypatch.setattr(analyze, "_write_aggregate_entry", lambda *a, **k: "soken_review_entry.sol")
    monkeypatch.setattr(analyze, "_extract_settings", lambda w: {})
    monkeypatch.setattr(analyze, "_run_slither", fake_slither)
    cand = Candidate(provider="repo", files={}, sha256="", language="solidity",  # type: ignore[arg-type]
                     compiler=Compiler("0.8.24", "config"), settings={}, std_json_input=None, entry_contract=None)
    (tmp_path / "work").mkdir()
    leads, static_map, _ = analyze.analyze(BuildResult(candidate=cand, status="ok", work_dir=str(tmp_path / "work")),
                                           scope_files={"contracts/core/Vault.sol"})
    assert leads == []
    assert static_map == {"status": "not_run", "tool": "slither", "reason": "compile_failed",
                          "detail": "Error: Identifier already declared. at soken_review_entry.sol:13"}
    note = note_from(static_map)
    assert note.startswith("slither did not run fully: the compiler run it drives over the reviewed files failed")
    assert "Cause: Error: Identifier already declared. at soken_review_entry.sol:13." in note
    assert details_of(static_map) == {"slither": "Error: Identifier already declared. at soken_review_entry.sol:13"}
    assert "—" not in note


def test_old_static_map_without_detail_keeps_its_sentence():
    assert note_from({"status": "not_run", "reason": "analyzer_failed"}) == \
        "slither did not run fully: it stopped with an internal error."
