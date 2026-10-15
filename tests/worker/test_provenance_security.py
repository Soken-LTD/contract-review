"""Security review 2026-10-10 of the provenance path: each test is a planted file or crafted
input that reached tier A (or would build code the reviewer does not read) before the fix."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import Artifact, BuildResult, Candidate, Compiler
from soken_review.adapters.evm.build import InputSanitizationError, sanitize_std_input
from soken_review.adapters.evm.compare import compare_runtime
from soken_review.engine.provenance import evm_dep_match, evm_deployment_check, resolve_provenance
from soken_review.worker.supervisor import _std_input_for_build
from tests.adapters.evm.test_compare import IMM, local_runtime, onchain_runtime, x2_for
from tests.worker.test_supervisor import FakeStore, _make_supervisor
from tests.worker.test_supervisor_provenance import _conn, _run_build_with

# ---------------------------------------------------------------------------
# Finding 1: parser differential between the pinned text and what solc compiles
# ---------------------------------------------------------------------------


def _std(content: str, **extra) -> dict:
    return {"language": "Solidity", "sources": {"A.sol": {"content": content, **extra}}, "settings": {}}


def _write(tmp_path: Path, std: dict) -> None:
    (tmp_path / "std_input_0.json").write_text(json.dumps({"std_json_input": std}))


def test_lone_cr_source_is_not_built(tmp_path: Path) -> None:
    """solc ends a `//` comment only at LF; the pin turns a lone CR into LF, so the reviewer
    would read `selfdestruct` as code while solc compiles it as a comment (or the reverse)."""
    _write(tmp_path, _std("contract A { function f() public { // note\r selfdestruct(payable(0)); } }"))
    assert _std_input_for_build(tmp_path, {"A.sol": "contract A { function f() public { // note\n selfdestruct(payable(0)); } }"}) is None


def test_crlf_and_trailing_newline_still_accepted(tmp_path: Path) -> None:
    std = _std("contract A {}\r\n// x\r\n")
    _write(tmp_path, std)
    assert _std_input_for_build(tmp_path, {"A.sol": "contract A {}\n// x"}) == std


@pytest.mark.parametrize("language", ["SolidityAST", "EVMAssembly", "Yul"])
def test_non_solidity_language_is_not_built(tmp_path: Path, language: str) -> None:
    """With language SolidityAST solc compiles `ast` and ignores `content`, so a benign content
    equal to the pin could carry any AST."""
    std = _std("contract A {}", ast={"nodeType": "SourceUnit"})
    std["language"] = language
    _write(tmp_path, std)
    assert _std_input_for_build(tmp_path, {"A.sol": "contract A {}"}) is None
    with pytest.raises(InputSanitizationError):
        sanitize_std_input(std)


def test_source_entry_with_extra_keys_is_not_built(tmp_path: Path) -> None:
    std = _std("contract A {}", ast={"nodeType": "SourceUnit"})
    _write(tmp_path, std)
    assert _std_input_for_build(tmp_path, {"A.sol": "contract A {}"}) is None
    with pytest.raises(InputSanitizationError):
        sanitize_std_input(std)


# ---------------------------------------------------------------------------
# Finding 2: a sandbox-writable file read as verdict input on restart
# ---------------------------------------------------------------------------


async def _restart(tmp_path: Path, job_id: str) -> dict:
    sup = _make_supervisor(FakeStore(), tmp_path)
    mark = AsyncMock()
    with patch("soken_review.worker.supervisor.JobRepo", return_value=AsyncMock()), \
         patch.object(sup, "_mark_step", new=mark), \
         patch.object(sup, "_after_build", new=AsyncMock()):
        sup._pool.connection = MagicMock(return_value=_conn())
        await sup._run_build({"id": 97, "job_id": job_id, "step": "build", "seq": 0})
    return mark.call_args.kwargs["provenance"]


def _plant_output(work: Path, runtime: bytes) -> None:
    (work / "out").mkdir(parents=True, exist_ok=True)
    output = {"contracts": {"contracts/Token.sol": {"Token": {"evm": {
        "bytecode": {"object": ""},
        "deployedBytecode": {"object": runtime.hex(), "immutableReferences": IMM}}}}}}
    (work / "out" / "output.json").write_text(json.dumps(output))


@pytest.mark.asyncio
async def test_planted_output_json_on_restart_is_not_tier_a(tmp_path: Path) -> None:
    """work/ is mounted read-write into build and analyze containers. A container that rewrites
    out/output.json to the tampered chain runtime must not get tier A on a restart."""
    bad = bytearray(onchain_runtime())
    bad[60] ^= 1
    prov, _, out_dir = await _run_build_with(tmp_path, "job_SEC00001", bytes(bad))
    assert prov["tier"] == "C"
    (out_dir / "deployment.json").unlink()  # crash before the decision was stored
    forged = bytearray(local_runtime())
    forged[60] ^= 1  # local "build" now equals the tampered chain code
    _plant_output(out_dir / "work", bytes(forged))
    assert (await _restart(tmp_path, "job_SEC00001"))["tier"] != "A"


@pytest.mark.asyncio
async def test_restart_with_untouched_output_recomputes(tmp_path: Path) -> None:
    prov, _, out_dir = await _run_build_with(tmp_path, "job_SEC00002", onchain_runtime(), write_output=True)
    assert prov["tier"] == "A"
    (out_dir / "deployment.json").unlink()
    assert (await _restart(tmp_path, "job_SEC00002"))["tier"] == "A"


@pytest.mark.asyncio
async def test_build_result_hash_is_of_output(tmp_path: Path) -> None:
    _, _, out_dir = await _run_build_with(tmp_path, "job_SEC00003", onchain_runtime(), write_output=True)
    br = json.loads((out_dir / "build_result.json").read_text())
    data = (out_dir / "work" / "out" / "output.json").read_bytes()
    assert br["output_sha256"] == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Finding 6: provenance logic
# ---------------------------------------------------------------------------


def _cand(entry: str | None) -> Candidate:
    return Candidate(provider="sourcify", files={}, sha256="0" * 64, language="solidity",
                     compiler=Compiler("0.8.24", "sourcify"), settings={}, std_json_input=None,
                     entry_contract=entry)


def test_named_entry_missing_does_not_fall_back_to_any_artifact() -> None:
    """The candidate names the deployed contract; another contract in the set that happens to
    match the chain is not the reviewed unit."""
    loc = local_runtime()
    art = Artifact(contract="Other.sol:Other", creation="", runtime=loc.hex(), immutable_refs=IMM,
                   link_refs={}, source_map="", storage_layout=None)
    c = _cand("Token.sol:Token")
    build = BuildResult(candidate=c, status="ok", artifacts=[art], auxdata_ranges={art.contract: x2_for(loc)})
    dep = evm_deployment_check(family="evm", build=build, onchain_runtime=onchain_runtime().hex())
    assert resolve_provenance(candidate=c, address="0x1", dep=dep)["tier"] != "A"


def test_x2_partial_difference_is_not_checkable() -> None:
    loc = local_runtime()
    chain = bytearray(onchain_runtime())
    chain[50:54] = b"\xde\xad\xbe\xef"
    cmp = compare_runtime(loc.hex(), bytes(chain).hex(), immutable_refs=IMM, x2_ranges=[(50, 54)] + x2_for(loc))
    dep = evm_dep_match(family="evm", candidate=_cand("A.sol:A"), build_status="ok", build_reason=None, comparison=cmp)
    assert (dep.match, dep.reason) == ("not_checkable", "auxdata_rule_missing")


@pytest.mark.asyncio
async def test_unknown_chain_is_not_tier_a(tmp_path: Path) -> None:
    """No registry entry means no family rules; fail closed instead of assuming EVM."""
    prov, _, _ = await _run_build_with(tmp_path, "job_SEC00004", onchain_runtime(), chain_id=424242)
    assert prov["tier"] != "A"


@pytest.mark.asyncio
async def test_map_step_reads_the_job_dir_copy_not_work(tmp_path: Path) -> None:
    """The analyze container shares work/; a rewrite of out/output.json after the build must not
    reach the map step, which reads the job-dir copy taken right after the build."""
    from soken_review.worker.supervisor import _solc_output_copy

    _, _, out_dir = await _run_build_with(tmp_path, "job_SEC00005", onchain_runtime(), write_output=True)
    original = (out_dir / "work" / "out" / "output.json").read_bytes()
    _plant_output(out_dir / "work", b"\x60\x00")
    br = json.loads((out_dir / "build_result.json").read_text())
    copy = _solc_output_copy(out_dir, br)
    assert copy is not None and copy.parent == out_dir
    assert copy.read_bytes() == original


def test_symlinked_solc_output_is_not_copied(tmp_path: Path) -> None:
    from soken_review.worker.supervisor import _snapshot_solc_output

    out_dir, work = tmp_path / "job", tmp_path / "job" / "work"
    (work / "out").mkdir(parents=True)
    secret = tmp_path / "host_secret.json"
    secret.write_text("{}")
    (work / "out" / "output.json").symlink_to(secret)
    assert _snapshot_solc_output(out_dir, str(work)) is None
    assert not (out_dir / "solc_output.json").exists()
