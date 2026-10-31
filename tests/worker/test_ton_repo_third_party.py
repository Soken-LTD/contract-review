"""A third party can review a public repository in any enabled family (Hipo blind run 2026-10-27).

The run: a public TON FunC Blueprint repo (HipoFinance/contract) could not be reviewed at all. Repo
mode assumed Solidity (`no_solidity_sources`), review_start had no chain field for repo mode, a repo
with the TON treasury as deployment ended tier D SOURCE_NOT_OWNER_LINKED, every fix text told the
client to resend the input that had failed, and the start hint asked for review_set_section, which
the job rejected before ready. Covered here, layer by layer:

  * repo_detect: TON, Solana and EVM trees, and `family` (review_start source.chain) forcing a rule
  * supervisor: a TON or Solana tree, or a chain hint, hands the fetch step to that family's runner
  * TON provenance: the requester's repo or files with an unmatched deployment is tier B, never D
  * TON repo candidate: a Blueprint tree pins the FunC sources, not package.json / tsconfig.json
  * TON fetch: an inactive account with a repo still reviews the repo
  * review_status fix texts: a repo job is never told to start again with repo and commit
  * documents hint: before ready it never presents review_set_section as accepted
  * review_start: source.chain is accepted, checked against deployment.chain and the family switch
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.adapters.base import Candidate
from soken_review.adapters.repo_detect import RepoFamily, Undetected, detect_repo_family
from soken_review.adapters.ton.provenance import (
    NO_DEPLOYMENT_GIVEN,
    SOURCE_NOT_OWNER_LINKED,
    SOURCE_UNLINKED,
    Attempt,
    Dep,
    resolve_provenance,
    unlinked_reason,
)
from soken_review.sandbox.repo_fetch import FetchResult
from soken_review.worker.supervisor import Supervisor

SHA = "91291c5bfc5da61467d065c6ccd121f0308490e4"
DEP_HASH = "36179377e9cbc69dd7259a76ce67a7a2021ea577a850c8719ef940b6b8f0a9cf"
OTHER = "ab" * 32

# The shape of HipoFinance/contract at SHA: a Blueprint project, FunC under contracts/
HIPO_TREE = {
    "package.json": '{"name": "hipo", "devDependencies": {"@ton/blueprint": "^0.15.0"}}',
    "tsconfig.json": '{"compilerOptions": {}}',
    "contracts/treasury.fc": '#include "imports/stdlib.fc";\n() recv_internal(cell in_msg, slice s) impure { }\n',
    "contracts/wallet.fc": '#include "imports/stdlib.fc";\n() recv_internal() impure { }\n',
    "contracts/imports/stdlib.fc": "forall X -> X null() asm \"PUSHNULL\";\n",
    "contracts/schema.tlb": "storage#_ = Storage;\n",
    "wrappers/Treasury.compile.ts": "export const compile = { lang: 'func', targets: ['contracts/treasury.fc'] };\n",
    "tests/Wallet.spec.ts": "describe('w', () => {});\n",
    "node_modules/@ton/core/dist/x.fc": ";; vendored, never a source\n",
}
ANCHOR_TREE = {
    "Anchor.toml": "[programs.mainnet]\nlocker = \"Fvm8\"\n",
    "Cargo.toml": "[workspace]\nmembers = [\"programs/*\"]\n",
    "programs/locker/Cargo.toml": "[package]\nname = \"locker\"\n[dependencies]\nanchor-lang = \"0.30.1\"\n",
    "programs/locker/src/lib.rs": "use anchor_lang::prelude::*;\n",
}


# ── repo_detect ──────────────────────────────────────────────────────────────────────────────


def test_blueprint_funC_tree_is_ton_at_the_root():
    found = detect_repo_family(HIPO_TREE)
    assert found == RepoFamily("ton", "", "contracts/imports/stdlib.fc")


def test_subdir_with_funC_is_kept_as_the_package_dir():
    assert detect_repo_family(HIPO_TREE, "contracts/") == RepoFamily("ton", "contracts", "contracts/imports/stdlib.fc")


def test_tact_and_tolk_trees_are_ton():
    assert detect_repo_family({"tact.config.json": "{}", "src/main.tact": "contract A {}"}).chain == "ton"
    assert detect_repo_family({"contracts/jetton.tolk": "fun main() {}"}).chain == "ton"


def test_vendored_funC_alone_is_not_a_ton_tree():
    assert detect_repo_family({"node_modules/x/a.fc": ";;", "README.md": "x"}) == Undetected("no_manifest")


def test_anchor_workspace_with_one_program_picks_the_program_crate():
    assert detect_repo_family(ANCHOR_TREE) == RepoFamily("solana", "programs/locker", "programs/locker/Cargo.toml")


def test_native_solana_crate_is_solana():
    files = {"Cargo.toml": "[package]\nname = \"p\"\n[dependencies]\nsolana-program = \"2.0\"\n", "src/lib.rs": ""}
    assert detect_repo_family(files) == RepoFamily("solana", "", "Cargo.toml")


def test_plain_rust_crate_is_not_solana():
    files = {"Cargo.toml": "[package]\nname = \"p\"\n[dependencies]\nserde = \"1\"\n", "src/lib.rs": ""}
    assert detect_repo_family(files) == Undetected("no_manifest")


def test_solidity_tree_is_evm():
    assert detect_repo_family({"foundry.toml": "", "src/A.sol": "contract A {}"}).chain == "evm"


def test_family_hint_runs_that_rule_only():
    assert detect_repo_family(HIPO_TREE, family="ton").chain == "ton"
    assert detect_repo_family(HIPO_TREE, family="solana") == Undetected("no_solana_sources")
    assert detect_repo_family(ANCHOR_TREE, family="ton") == Undetected("no_ton_sources")
    assert detect_repo_family(HIPO_TREE, "wrappers", family="ton") == Undetected("no_ton_sources")


def test_family_hint_names_the_move_flavour_the_manifest_does_not():
    files = {"Move.toml": "[package]\nname = \"m\"\n", "sources/m.move": "module m::m {}"}
    assert detect_repo_family(files) == Undetected("unknown_move_flavour", ("Move.toml",))
    assert detect_repo_family(files, family="aptos") == RepoFamily("aptos", "", "Move.toml")


# ── supervisor handoff ───────────────────────────────────────────────────────────────────────


def _conn_ctx() -> AsyncMock:
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    return conn


def _sup(tmp_path: Path) -> Supervisor:
    sup = object.__new__(Supervisor)
    sup._pin_root = tmp_path / "pins"
    sup._work_root = tmp_path / "work"
    sup._pool = MagicMock()
    sup._pool.connection = MagicMock(return_value=_conn_ctx())
    sup._mark_step = AsyncMock()
    sup._job_dir = lambda job_id: tmp_path / "work" / job_id      # type: ignore[method-assign]
    return sup


def _job(**args: Any) -> dict[str, Any]:
    source = {"kind": "repo", "repo_url": "https://github.com/HipoFinance/contract", "commit": SHA, **args}
    return {"job_id": "job_HIPO0001", "chain": None, "address": None, "source_kind": "repo", "source_args": source}


async def _fetch_repo(tmp_path: Path, files: dict[str, str], job: dict[str, Any], candidate: Any):
    sup = _sup(tmp_path)
    src = tmp_path / "repo_fetch" / "src"
    for rel, text in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text, encoding="utf-8")
    ok = FetchResult(exit_code=0, error_code="", retryable=False, src_dir=src,
                     manifest={"resolved_commit": SHA, "files": sorted(files)})
    repo_mock = AsyncMock()
    step = {"id": 11, "job_id": job["job_id"], "step": "fetch", "seq": 0, "attempt": 1, "max_attempts": 3}
    with patch("soken_review.worker.supervisor.JobRepo", return_value=repo_mock), \
         patch("soken_review.sandbox.repo_fetch.materialize_repo", return_value=ok), \
         patch("soken_review.worker.supervisor.repo_candidate_from_manifest", new=candidate), \
         patch.object(Supervisor, "_resolve_npm_deps", new=AsyncMock(return_value=None)):
        result = await sup._fetch_repo(step, job, tmp_path, job["source_args"], None, None, None)
    return result, repo_mock, sup, src


@pytest.mark.asyncio
async def test_funC_tree_is_handed_to_the_ton_pipeline_with_its_tree(tmp_path: Path) -> None:
    calls: list[dict] = []

    async def fake_ton(sup: Any, step: dict, job: dict) -> None:
        calls.append(job)

    no_sol = MagicMock(return_value=(None, "no_solidity_sources"))
    with patch("soken_review.worker.supervisor.ton_pipeline.run_step", new=fake_ton):
        result, repo_mock, _, src = await _fetch_repo(tmp_path, HIPO_TREE, _job(), no_sol)
    assert result is None
    repo_mock.update_job_fields.assert_any_await("job_HIPO0001", chain="ton")
    repo_mock.transition.assert_not_awaited()
    (handed,) = calls
    assert handed["chain"] == "ton" and handed["resolved_commit"] == SHA
    assert handed["source_args"]["commit"] == SHA and "subdir" not in handed["source_args"]
    assert handed["_repo_src_dir"] == str(src)
    cs = json.loads((tmp_path / "work" / "job_HIPO0001" / "chain_state.json").read_text())
    assert cs == {"mc_seqno": None, "accounts": {}}


@pytest.mark.asyncio
async def test_anchor_tree_is_handed_to_the_solana_runner(tmp_path: Path) -> None:
    runner = AsyncMock()
    with patch("soken_review.worker.supervisor._solana_steps.run_step", new=runner):
        await _fetch_repo(tmp_path, ANCHOR_TREE, _job(), MagicMock(return_value=(None, "no_solidity_sources")))
    handed = runner.await_args.args[2]
    assert handed["chain"] == "solana" and handed["source_args"]["subdir"] == "programs/locker"


@pytest.mark.asyncio
async def test_chain_hint_skips_the_solidity_candidate(tmp_path: Path) -> None:
    candidate = MagicMock(return_value=(None, "no_solidity_sources"))
    runner = AsyncMock()
    with patch("soken_review.worker.supervisor.ton_pipeline.run_step", new=runner):
        await _fetch_repo(tmp_path, HIPO_TREE, _job(chain="ton", subdir="contracts"), candidate)
    candidate.assert_not_called()
    assert runner.await_args.args[2]["source_args"]["subdir"] == "contracts"


@pytest.mark.asyncio
async def test_chain_hint_on_a_tree_without_that_family_names_the_reason(tmp_path: Path) -> None:
    runner = AsyncMock()
    with patch("soken_review.worker.supervisor._solana_steps.run_step", new=runner):
        _, repo_mock, _, _ = await _fetch_repo(tmp_path, HIPO_TREE, _job(chain="solana"),
                                               MagicMock(return_value=(None, "no_solidity_sources")))
    runner.assert_not_awaited()
    args, kwargs = repo_mock.transition.await_args
    assert args[1] == "insufficient_source" and kwargs["error_code"] == "E_SOURCE_NOT_FOUND"
    assert kwargs["error_detail"]["repo_family"] == "no_solana_sources"


@pytest.mark.asyncio
async def test_disabled_ton_family_ends_failed_with_chain_disabled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SOKEN_DISABLED_FAMILIES", "ton")
    runner = AsyncMock()
    with patch("soken_review.worker.supervisor.ton_pipeline.run_step", new=runner):
        _, repo_mock, _, _ = await _fetch_repo(tmp_path, HIPO_TREE, _job(),
                                               MagicMock(return_value=(None, "no_solidity_sources")))
    runner.assert_not_awaited()
    args, kwargs = repo_mock.transition.await_args
    assert args[1] == "failed" and kwargs["error_code"] == "E_CHAIN_DISABLED"


# ── TON provenance ───────────────────────────────────────────────────────────────────────────


def _cand(provider: str = "repo", untrusted: bool = False) -> Candidate:
    return Candidate(provider=provider, files={"contracts/treasury.fc": "() recv_internal() { }"},  # type: ignore[arg-type]
                     sha256="0" * 64, language="func", compiler=None, settings={}, std_json_input=None,
                     entry_contract=None, untrusted_inputs=untrusted)


def _attempt(status: str, hashes: dict[str, str] | None = None, untrusted: bool = False):
    def fn(i: int, c: Candidate) -> Attempt:
        return Attempt(i, c.provider, status, hashes or {}, untrusted_inputs=untrusted)
    return fn


def _dep(status: str = "active", hash_: str | None = DEP_HASH) -> Dep:
    return Dep(address="0:" + "cb" * 32, status=status, hash=hash_)


def test_repo_with_untrusted_inputs_and_a_deployment_is_tier_b_unlinked():
    """The Hipo case: was tier D SOURCE_NOT_OWNER_LINKED / untrusted_inputs, the job stopped."""
    out = resolve_provenance(_dep(), [_cand(untrusted=True)], _attempt("ok", {"treasury": OTHER}))
    assert (out.reason, out.tier, out.src, out.why) == (SOURCE_UNLINKED, "B", 0, "untrusted_inputs")
    assert out.match is None and out.dep_hash == DEP_HASH and out.build_hash == OTHER


def test_trusted_rebuild_that_differs_is_tier_b_never_a():
    out = resolve_provenance(_dep(), [_cand()], _attempt("ok", {"treasury": OTHER}))
    assert (out.reason, out.tier, out.why) == (SOURCE_UNLINKED, "B", "rebuild_differs")


def test_repo_wins_over_an_unmatched_verifier_candidate():
    out = resolve_provenance(_dep(), [_cand(), _cand("ton_verifier")], _attempt("compile_error"))
    assert out.reason == SOURCE_UNLINKED and out.src == 0


def test_exact_match_on_the_repo_is_still_tier_a():
    out = resolve_provenance(_dep(), [_cand()], _attempt("ok", {"treasury": DEP_HASH}))
    assert out.tier == "A"


@pytest.mark.parametrize("dep", [_dep(status="uninit", hash_=None), _dep(hash_=None)])
def test_inactive_or_unhashable_account_still_reviews_the_repo(dep):
    seen: list[int] = []

    def attempt(i: int, c: Candidate) -> Attempt:
        seen.append(i)
        return Attempt(i, c.provider, "ok", {"treasury": OTHER})

    out = resolve_provenance(dep, [_cand()], attempt)
    assert out.reason == SOURCE_UNLINKED and out.tier == "B" and seen == [0]   # built: analyze reads it


def test_verifier_only_unit_keeps_tier_d():
    out = resolve_provenance(_dep(), [_cand("ton_verifier", untrusted=True)], _attempt("ok", {"x": OTHER}))
    assert out.reason == SOURCE_NOT_OWNER_LINKED and out.tier == "D"


def test_no_deployment_stays_tier_b_commit():
    assert resolve_provenance(None, [_cand()], _attempt("ok", {"x": OTHER})).reason == NO_DEPLOYMENT_GIVEN


def test_unlinked_reasons_are_plain_text():
    assert unlinked_reason("untrusted_inputs") == "the repository build inputs cannot be trusted for a rebuild"
    assert unlinked_reason(None).startswith("the deployed code could not be compared")


# ── TON repo candidate from a tree ───────────────────────────────────────────────────────────


def test_blueprint_tree_pins_the_funC_sources_only():
    from soken_review.adapters.ton.fetch import repo_candidate_from_tree

    cand = repo_candidate_from_tree(HIPO_TREE, repo_url="https://github.com/HipoFinance/contract", commit=SHA)
    assert cand is not None and cand.provider == "repo" and cand.language == "func"
    assert sorted(cand.files) == ["contracts/imports/stdlib.fc", "contracts/treasury.fc", "contracts/wallet.fc"]
    assert cand.source_url == f"https://github.com/HipoFinance/contract/tree/{SHA}"


def test_subdir_paths_stay_relative_to_it():
    from soken_review.adapters.ton.fetch import repo_candidate_from_tree

    cand = repo_candidate_from_tree(HIPO_TREE, repo_url="https://github.com/x/y", commit=SHA, subdir="contracts")
    assert "treasury.fc" in cand.files and "imports/stdlib.fc" in cand.files


def test_tree_without_ton_sources_is_no_candidate():
    from soken_review.adapters.ton.fetch import repo_candidate_from_tree

    assert repo_candidate_from_tree(ANCHOR_TREE, repo_url="https://github.com/x/y", commit=SHA) is None


# ── TON fetch step ───────────────────────────────────────────────────────────────────────────


def _ton_sup(tmp_path: Path) -> MagicMock:
    sup = MagicMock()
    sup._job_dir = MagicMock(return_value=tmp_path)
    sup._mark_step = AsyncMock()
    sup._after_fetch = AsyncMock()
    sup._pool.connection = MagicMock(return_value=_conn_ctx())
    return sup


@pytest.mark.asyncio
async def test_inactive_account_with_a_repo_fetches_the_repo(tmp_path: Path) -> None:
    from soken_review.worker import ton_pipeline as T

    (tmp_path / "chain_state.json").write_text(json.dumps(
        {"mc_seqno": 5, "accounts": {"0:" + "cb" * 32: {"status": "uninit", "dep_hash": None}}}))
    fetched: dict[str, Any] = {}

    async def fake_fetch(**kw: Any) -> list[Candidate]:
        fetched.update(kw)
        return [_cand()]

    job = {**_job(), "chain": "ton", "address": "0:" + "cb" * 32, "resolved_commit": SHA}
    sup = _ton_sup(tmp_path)
    with patch.object(T, "fetch_ton_sources", new=fake_fetch):
        await T._fetch(sup, {"id": 3, "job_id": job["job_id"]}, job)
    assert fetched["code_hash"] is None and fetched["repo_commit"] == SHA
    sup._after_fetch.assert_awaited_once()


@pytest.mark.asyncio
async def test_repo_with_no_ton_sources_names_the_reason(tmp_path: Path) -> None:
    from soken_review.worker import ton_pipeline as T

    (tmp_path / "chain_state.json").write_text(json.dumps({"mc_seqno": None, "accounts": {}}))
    terminal = AsyncMock()
    job = {**_job(subdir="wrappers"), "chain": "ton", "resolved_commit": SHA}
    with patch.object(T, "fetch_ton_sources", new=AsyncMock(return_value=[])), patch.object(T, "_terminal", new=terminal):
        await T._fetch(_ton_sup(tmp_path), {"id": 3, "job_id": job["job_id"]}, job)
    detail = terminal.await_args.kwargs["detail"]
    assert detail["repo_family"] == "no_ton_sources" and detail["subdir"] == "wrappers"


@pytest.mark.asyncio
async def test_repo_ref_is_pinned_to_a_commit_before_the_fetch(tmp_path: Path) -> None:
    from soken_review.worker import ton_pipeline as T

    sup = _ton_sup(tmp_path)
    job = {"job_id": "job_HIPO0002", "source_args": {"kind": "repo", "repo_url": "https://github.com/x/y", "ref": "main"}}
    repo_mock = AsyncMock()
    with patch("soken_review.tools.git_probe.resolve_ref", new=AsyncMock(return_value=SHA)), \
         patch.object(T, "JobRepo", return_value=repo_mock):
        pinned = await T._pin_repo_commit(sup, {"id": 1, "job_id": "job_HIPO0002"}, job)
    assert pinned["resolved_commit"] == SHA
    repo_mock.update_job_fields.assert_awaited_once_with("job_HIPO0002", resolved_commit=SHA)


# ── review_status fix texts ──────────────────────────────────────────────────────────────────


def _stopped(source_kind: str, detail: Any) -> dict[str, Any]:
    return {"job_id": "job_" + "2" * 26, "state": "insufficient_source", "tier": "D", "source_kind": source_kind,
            "requester_role": "third_party_public_code", "ownership_proven": False,
            "error_code": "E_SOURCE_NOT_FOUND", "error_detail": detail}


@pytest.mark.parametrize("detail", [
    None,
    {"stage": "repo_candidate", "detail": "no_solidity_sources", "repo_family": "no_manifest"},
    {"reason": "REPO_NO_TON_SOURCES", "repo_family": "no_ton_sources", "chain": "ton", "subdir": "wrappers"},
    {"stage": "repo_candidate", "detail": "chain_hint", "chain": "solana", "repo_family": "no_solana_sources"},
    {"stage": "repo_candidate", "detail": "no_solidity_sources", "repo_family": "ambiguous_package",
     "manifests": ["a/Move.toml", "b/Move.toml"]},
    {"reason": "REPO_EMPTY", "providers": "OtterSec verify registry, program security.txt"},
])
def test_repo_stop_never_says_start_again_with_repo_and_commit(detail):
    from soken_review.contract import load_errors
    from soken_review.tools.start_status import _build_status_response

    err = _build_status_response(_stopped("repo", detail), "concise", steps=[])["error"]
    assert err["fix"] and err["what"]
    assert err["fix"] != load_errors()["E_SOURCE_NOT_FOUND"]["fix"]
    assert "Start again with repo and commit" not in err["fix"]
    assert "—" not in err["fix"] + err["what"]          # no em dashes in client text


def test_ton_repo_fix_points_at_subdir_and_chain():
    from soken_review.tools.start_status import _build_status_response

    err = _build_status_response(_stopped("repo", {"repo_family": "no_ton_sources"}), "concise", steps=[])["error"]
    assert "subdir" in err["fix"] and ".fc" in err["fix"] and "source.chain" in err["fix"]


def test_ambiguous_package_fix_names_the_manifests():
    from soken_review.tools.start_status import _build_status_response

    detail = {"repo_family": "ambiguous_package", "manifests": ["a/Move.toml", "b/Move.toml"]}
    err = _build_status_response(_stopped("repo", detail), "concise", steps=[])["error"]
    assert "a/Move.toml, b/Move.toml" in err["fix"]


def test_deployed_stop_keeps_the_repo_suggestion():
    """For a deployed address a repo start IS a different input."""
    from soken_review.contract import load_errors
    from soken_review.tools.start_status import _build_status_response

    err = _build_status_response(_stopped("deployed", {"reason": "NO_SOURCE_FOUND"}), "concise", steps=[])["error"]
    assert err["fix"] == load_errors()["E_SOURCE_NOT_FOUND"]["fix"]


# ── documents hint ───────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("state", ["awaiting_upload", "queued", "fetching", "building", "analyzing"])
def test_pending_hint_says_set_section_waits_for_ready(state):
    from soken_review.tools.start_status import NO_DOCUMENTS_HINT, no_documents_hint

    hint = no_documents_hint(state)
    assert hint and hint != NO_DOCUMENTS_HINT
    assert "accepted only in the ready state" in hint and "review_add_context" in hint
    assert "to record it, review_set_section" not in hint


@pytest.mark.parametrize("state", ["finalized", "rendered", "insufficient_source", "failed"])
def test_no_hint_where_neither_call_is_accepted(state):
    from soken_review.tools.start_status import no_documents_hint

    assert no_documents_hint(state) is None


def test_ready_hint_is_the_full_one():
    from soken_review.tools.start_status import NO_DOCUMENTS_HINT, no_documents_hint

    assert no_documents_hint("ready") == NO_DOCUMENTS_HINT


# ── review_start source.chain ────────────────────────────────────────────────────────────────

ASYNC = pytest.mark.asyncio(loop_scope="session")


@ASYNC
async def test_review_start_accepts_a_repo_chain_and_reports_it(db_pool) -> None:
    from soken_review.tools.start_status import FakeRepoProbe, GitLsRemoteProbe, set_pool, set_repo_probe
    from tests.tools._client import task_scoped_client

    set_pool(db_pool)
    set_repo_probe(FakeRepoProbe())
    try:
        async with task_scoped_client() as c:
            res = await c.call_tool("review_start", {"source": {
                "kind": "repo", "repo_url": "https://github.com/HipoFinance/contract", "commit": SHA, "chain": "ton"}})
            body = res.structured_content
            assert body["accepted"] is True, body
            assert body["detected"]["chain"] == "ton"
            assert "accepted only in the ready state" in body["next_action"]
            async with db_pool.connection() as conn:
                row = await (await conn.execute("select chain, source_args from jobs where job_id = %s",
                                                (body["job_id"],))).fetchone()
            assert row[0] is None and row[1]["chain"] == "ton"    # the worker runs the family on the tree

            res = await c.call_tool("review_start", {"source": {
                "kind": "repo", "repo_url": "https://github.com/HipoFinance/contract", "commit": SHA, "chain": "solana",
                "deployment": {"chain": "ton", "address": "EQCLyZHP4Xe8fpchQz76O-_RmUhaVc_9BAoGyJrwJrcbz2eZ"}}})
            assert res.is_error
            env = json.loads(res.content[0].text)
            assert env["errors"][0]["code"] == "E_INVALID_ARGUMENT"
    finally:
        set_repo_probe(GitLsRemoteProbe())
        set_pool(None)  # type: ignore[arg-type]


@ASYNC
async def test_review_start_refuses_a_disabled_repo_chain(monkeypatch) -> None:
    from tests.tools._client import task_scoped_client

    monkeypatch.setenv("SOKEN_DISABLED_FAMILIES", "starknet")
    async with task_scoped_client() as c:
        res = await c.call_tool("review_start", {"source": {
            "kind": "repo", "repo_url": "https://github.com/x/y", "commit": SHA, "chain": "starknet"}})
    body = json.loads(res.content[0].text)
    assert body["accepted"] is False and body["errors"][0]["code"] == "E_CHAIN_DISABLED"


def test_unlinked_deployment_doc_and_report_method_row():
    from soken_review.adapters.ton.provenance import deployment_doc
    from soken_review.report.assemble import _deployment_method_detail

    out = resolve_provenance(_dep(), [_cand(untrusted=True)], _attempt("ok", {"treasury": OTHER}))
    prov = {**out.to_json(), "mc_seqno": 51234567, "address": "0:" + "cb" * 32}
    doc = deployment_doc(prov, {"provider": "repo", "sha256": "0" * 64}, "EQCLyZHP")
    assert doc["tier"] == "B" and doc["dep"] is None and doc["code_hash"] == DEP_HASH
    row = _deployment_method_detail({"tier": "B"}, doc)
    assert row == ("The reviewed source could not be matched to the deployed code at seqno 51,234,567: "
                   "the repository build inputs cannot be trusted for a rebuild")


# ── Pump Science (blind run 2026-10-27): Anchor workspace in repo mode, localnet program id ─────

PUMP_ID = "EtZR9gh25YUM6LkL2o2yYV1KzyuDdftHvYk3wsb2Ypkj"
PUMP_TREE = {
    "Anchor.toml": f'[features]\nresolution = true\n\n[programs.localnet]\npump_science = "{PUMP_ID}"\n\n'
                   '[provider]\ncluster = "localnet"\n',
    "Cargo.toml": '[workspace]\nmembers = ["programs/pump-science", "clients/rust"]\nresolver = "2"\n',
    "programs/pump-science/Cargo.toml": '[package]\nname = "pump-science"\n[lib]\ncrate-type = ["cdylib", "lib"]\n'
                                        '[dependencies]\nanchor-lang = { version = "0.29.0" }\n',
    "programs/pump-science/src/lib.rs": f'declare_id!("{PUMP_ID}");\n',
    "clients/rust/Cargo.toml": '[package]\nname = "pump-science-client"\n[dependencies]\nsolana-program = "^1.14"\n',
}


def test_pump_science_workspace_is_solana_with_or_without_subdir():
    assert detect_repo_family(PUMP_TREE) == RepoFamily("solana", "programs/pump-science",
                                                       "programs/pump-science/Cargo.toml")
    assert detect_repo_family(PUMP_TREE, "programs/pump-science").chain == "solana"


@pytest.mark.asyncio
async def test_pump_science_repo_is_handed_to_solana_with_the_program_subdir(tmp_path: Path) -> None:
    runner = AsyncMock()
    with patch("soken_review.worker.supervisor._solana_steps.run_step", new=runner):
        _, repo_mock, _, _ = await _fetch_repo(tmp_path, PUMP_TREE, _job(), MagicMock(return_value=(None, "no_solidity_sources")))
    repo_mock.update_job_fields.assert_any_await("job_HIPO0001", chain="solana")
    assert runner.await_args.args[2]["source_args"]["subdir"] == "programs/pump-science"


def test_anchor_clusters_of_reads_the_program_sections():
    from soken_review.adapters.solana.detect import anchor_clusters_of

    assert anchor_clusters_of(PUMP_TREE, PUMP_ID) == {"localnet"}
    assert anchor_clusters_of(PUMP_TREE, "1" * 44) == set()
    both = {"Anchor.toml": f'[programs.localnet]\na = "{PUMP_ID}"\n[programs.mainnet]\na = "{PUMP_ID}"\n'}
    assert anchor_clusters_of(both, PUMP_ID) == {"localnet", "mainnet"}


@pytest.mark.parametrize(("cs", "want"), [
    # MetaDAO 2026-10-31: the id is live on mainnet; Anchor.toml listing it for localnet changes nothing
    ({"kind": "program", "deployed_program_hash": "ab" * 32, "config_clusters": ["localnet"]}, "Solana mainnet"),
    ({"kind": "program", "deployed_program_hash": None, "why": "no_code", "config_clusters": ["localnet"]},
     "Program id for localnet in Anchor.toml; not on mainnet"),
    ({"kind": "program", "why": "read_failed:timeout", "config_clusters": ["localnet"]},
     "Program id for localnet in Anchor.toml; mainnet not checked"),
    ({"kind": "program", "why": "read_failed:timeout"}, "Solana mainnet; deployment not checked"),
    ({"kind": "program"}, "Solana mainnet; deployment not checked"),
    ({"kind": "mint", "slot": 5, "program": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}, "Solana mainnet"),
    ({"kind": "program", "loader": "BPFLoader1111111111111111111111111111111111", "why": "loader_unsupported"},
     "Solana mainnet"),
    ({"kind": "program", "deployed_program_hash": None, "why": "no_code"}, "Program id not deployed on Solana mainnet"),
    ({"kind": "program", "deployed_program_hash": "ab" * 32, "config_clusters": ["localnet", "mainnet"]}, "Solana mainnet"),
    ({"kind": "program", "deployed_program_hash": "ab" * 32}, "Solana mainnet"),
])
def test_solana_network_label_never_calls_a_localnet_id_mainnet(cs, want):
    from soken_review.report.assemble import _network_label

    job = {"chain": "solana", "address": PUMP_ID}
    label = _network_label(job, cs, {"chain": "solana"})
    assert label == want and len(label) <= 60


def test_unlinked_cover_label_says_the_deployment_is_not_matched():
    from soken_review.report.assemble import provenance

    job = {"tier": "B", "address": "EQCLyZHP4Xe8fpchQz76O-_RmUhaVc_9BAoGyJrwJrcbz2eZ", "chain": "ton",
           "source_kind": "repo", "source_args": {"kind": "repo", "repo_url": "https://github.com/HipoFinance/contract"},
           "resolved_commit": SHA, "source_pin": "sha256:" + "0" * 64}
    dep = {"tier": "B", "chain": "ton", "unlinked_reason": "the rebuilt code differs from the deployed code"}
    prov = provenance(job, [{"provider": "repo"}], None, dep)
    assert prov["label_key"] == "tier_b_unmatched"
    assert prov["label"] == "Deployment given; deployment not matched to this source"
    assert provenance(job, [{"provider": "repo"}], None, {"tier": "B"})["label_key"] == "tier_b_not_checked"
