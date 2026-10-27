"""03 tool tails: server drafts and ETA in review_status, LISTEN/NOTIFY long-poll, ls-remote probe (03 3.1, 4.1, 4.2)."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from jsonschema import Draft202012Validator
from mcp import Client

import soken_review.tools  # noqa: F401
from soken_review.contract import bundle_tools, load_errors
from soken_review.db.job_repo import JobRepo
from soken_review.errors import ReviewError
from soken_review.server import SokenServer
from soken_review.tools import start_status
from soken_review.tools.git_probe import GitLsRemoteProbe, pick_ref, resolve_ref, safe_ref, safe_repo_url
from soken_review.tools.listen import listener_for
from soken_review.tools.start_status import _compute_eta, set_pool, set_repo_probe

from ._client import task_scoped_client

ASYNC = pytest.mark.asyncio(loop_scope="session")   # the db_pool loop (tests/conftest.py)
STATUS_SCHEMA = Draft202012Validator({t["name"]: t for t in bundle_tools()}["review_status"]["outputSchema"])
A = "a" * 40
B = "b" * 40
C = "c" * 40


# ── ref resolution (pure) ────────────────────────────────────────────────────


def test_pick_ref_annotated_tag_uses_peeled_line():
    out = f"{A}\trefs/tags/v1.0.0\n{B}\trefs/tags/v1.0.0^{{}}\n"
    assert pick_ref(out, "v1.0.0") == B      # tag object id never reaches provenance


def test_pick_ref_lightweight_tag_and_branch():
    assert pick_ref(f"{A}\trefs/tags/v2\n", "v2") == A
    assert pick_ref(f"{C}\trefs/heads/main\n", "main") == C


def test_pick_ref_branch_and_tag_is_ambiguous():
    with pytest.raises(ReviewError) as e:
        pick_ref(f"{A}\trefs/heads/release\n{B}\trefs/tags/release\n", "release")
    assert e.value.code == "E_COMMIT_AMBIGUOUS"


@pytest.mark.parametrize("out", ["", f"{A}\trefs/heads/other\n", "ab" * 32 + "\trefs/heads/main\n"])
def test_pick_ref_missing_or_sha256_is_unpinned(out):
    with pytest.raises(ReviewError) as e:
        pick_ref(out, "main")
    assert e.value.code == "E_UNPINNED_REF"


@pytest.mark.parametrize(("url", "ok"), [
    ("https://github.com/OpenZeppelin/openzeppelin-contracts", True),
    ("https://gitlab.com/group/sub/repo.git", True),
    ("https://github.com/a/b/../../c", False),
    ("https://github.com/-upload-pack=x", False),
    ("https://github.com/a/b?x=1", False),
    ("https://user@github.com/a/b", False),
    ("http://github.com/a/b", False),
    ("https://evil.com/a/b", False),
])
def test_safe_repo_url(url, ok):
    assert safe_repo_url(url) is ok


@pytest.mark.parametrize(("ref", "ok"), [("v1.2.3", True), ("feature/x", True), ("-x", False), ("a..b", False),
                                         ("x.lock", False), ("a b", False)])
def test_safe_ref(ref, ok):
    assert safe_ref(ref) is ok


@ASYNC
async def test_unsafe_url_never_runs_git():
    assert await GitLsRemoteProbe().is_reachable("https://github.com/a/b?upload-pack=touch") is False


@pytest.mark.live
@ASYNC
async def test_live_ls_remote_probe_and_peeled_tag():
    url = "https://github.com/OpenZeppelin/openzeppelin-contracts"
    assert await GitLsRemoteProbe().is_reachable(url) is True
    assert await GitLsRemoteProbe().is_reachable("https://github.com/soken-ltd/no-such-repo-0b3c9") is False
    # v5.0.0 is an annotated tag: the peeled commit, not the tag object
    assert await resolve_ref(url, "v5.0.0") == "932fddf69a699a9a80fd2396fd1a2ab91cdda123"


@ASYNC
async def test_review_start_repo_unreachable_is_rejection():
    class Down:
        async def is_reachable(self, repo_url: str) -> bool:
            return False

    set_repo_probe(Down())
    try:
        async with Client(SokenServer()) as c:
            r = await c.call_tool("review_start", {"source": {"kind": "repo", "repo_url": "https://github.com/a/b",
                                                              "commit": "abcdef1"}})
    finally:
        set_repo_probe(GitLsRemoteProbe())
    body = json.loads(r.content[0].text)
    assert not r.is_error and body["accepted"] is False
    assert body["errors"][0]["code"] == "E_REPO_UNREACHABLE"


def test_default_probe_is_ls_remote():
    assert isinstance(start_status._repo_probe, GitLsRemoteProbe)


# ── ETA (pure) ───────────────────────────────────────────────────────────────


def test_eta_defaults_and_medians():
    assert _compute_eta("queued", [], {}) == 5 + 20 + 60 + 180 + 10 + 5
    steps = [{"step": "chain_state", "seq": 0, "status": "done"}, {"step": "fetch", "seq": 0, "status": "done"},
             {"step": "build", "seq": 0, "status": "running",
              "started_at": datetime.now(UTC) - timedelta(seconds=40)}]
    eta = _compute_eta("building", steps, {"build": 100.0, "analyze": 50.0, "map": 2.0, "chain_state": 1.0})
    assert 111 <= eta <= 115                   # (100 - 40) + 50 + 2 + 1
    assert _compute_eta("ready", steps, {}) is None


# ── DB: drafts, ETA, long-poll ───────────────────────────────────────────────


@pytest_asyncio.fixture(loop_scope="session")
async def client(db_pool):
    set_pool(db_pool)
    try:
        async with task_scoped_client() as c:
            yield c
    finally:
        set_pool(None)  # type: ignore[arg-type]


async def _new_job(client) -> str:
    r = await client.call_tool("review_start", {"source": {"kind": "deployed", "chain": "evm", "chain_id": 1,
                                                           "address": "0x" + "e" * 40}})
    return json.loads(r.content[0].text)["job_id"]


async def _status(client, job_id: str, **kw) -> dict:
    r = await client.call_tool("review_status", {"job_id": job_id, **kw})
    body = json.loads(r.content[0].text)
    assert list(STATUS_SCHEMA.iter_errors(body)) == []
    return body


@ASYNC
async def test_server_drafts_in_status(client, db_pool):
    job_id = await _new_job(client)
    flags = [{"file": "src/A.sol", "line": 3, "rule": "J2", "detail": "U+202E"},
             {"file": "src/A.sol", "line": 9, "rule": "J4", "detail": "mixed_script"}]
    async with db_pool.connection() as conn, conn.transaction():
        assert await JobRepo(conn).create_server_drafts(job_id, "evm", flags) == 2
    async with db_pool.connection() as conn, conn.transaction():
        assert await JobRepo(conn).create_server_drafts(job_id, "evm", flags) == 0   # idempotent
    body = await _status(client, job_id)
    assert body["drafts"] == [
        {"draft_key": "srv-j2-0001", "finding_no": "F-01", "status": "needs_text", "severity": "Informational",
         "title": None, "carried_from": None, "flag": "J2", "location": "src/A.sol:3"},
        {"draft_key": "srv-j4-0001", "finding_no": "F-02", "status": "needs_text", "severity": "Informational",
         "title": None, "carried_from": None, "flag": "J4", "location": "src/A.sol:9"},
    ]
    async with db_pool.connection() as conn:
        row = await (await conn.execute("select next_finding_no from jobs where job_id = %s", (job_id,))).fetchone()
        rev = await (await conn.execute(
            "select category, computed_severity, content->'server_flag'->>'rule' from finding_revisions "
            "where job_id = %s and draft_key = 'srv-j2-0001'", (job_id,))).fetchone()
    assert row[0] == 3
    assert rev == ("evm.source_text_integrity", "Informational", "J2")


@ASYNC
async def test_eta_in_status(client):
    job_id = await _new_job(client)
    body = await _status(client, job_id)
    assert isinstance(body["eta_s"], int) and body["eta_s"] > 0


@ASYNC
async def test_long_poll_wakes_on_notify(client, db_pool):
    job_id = await _new_job(client)

    async def advance():
        await asyncio.sleep(1.0)
        async with db_pool.connection() as conn, conn.transaction():
            await JobRepo(conn).transition(job_id, "fetching")

    lst = listener_for(db_pool.conninfo)
    before = lst.notifications
    t0 = time.monotonic()
    task = asyncio.create_task(advance())
    body = await _status(client, job_id, wait_seconds=20)
    elapsed = time.monotonic() - t0
    await task
    assert body["state"] == "fetching"
    assert elapsed < 4.0          # woken by NOTIFY, not by the 20 s wait (re-check is every 5 s)
    assert lst.notifications > before


@ASYNC
async def test_long_poll_times_out_without_change(client):
    job_id = await _new_job(client)
    t0 = time.monotonic()
    body = await _status(client, job_id, wait_seconds=2)
    assert body["state"] == "queued"
    assert 1.8 <= time.monotonic() - t0 < 4.0


@ASYNC
async def test_long_poll_returns_at_once_when_ready(client, db_pool):
    job_id = await _new_job(client)
    async with db_pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        for s in ("fetching", "building", "analyzing", "ready"):
            await repo.transition(job_id, s)
    t0 = time.monotonic()
    body = await _status(client, job_id, wait_seconds=30)
    assert body["state"] == "ready" and time.monotonic() - t0 < 1.0
    assert body["eta_s"] is None


# ── provenance.source (pure): fetch provider -> tools.v1.json enum ────────────


def _tiered_job(source_kind: str, tier: str = "B") -> dict:
    return {"job_id": "job_" + "1" * 26, "state": "ready", "tier": tier, "source_kind": source_kind,
            "requester_role": "third_party_public_code", "ownership_proven": False}


def _fetch_step(provider: str) -> dict:
    return {"step": "fetch", "seq": 0, "status": "done", "provenance": {"provider": provider, "sha256": A}}


@pytest.mark.parametrize(("source_kind", "provider", "want"), [
    ("files", "user", "user_files"),
    ("upload", "user", "upload"),
    ("repo", "repo", "repo_commit"),
    ("deployed", "sourcify", "sourcify"),
    ("deployed", "etherscan", "verified_explorer"),
    ("deployed", "tronscan", "verified_explorer"),
    ("deployed", "eth_bytecode_db", "verifier_api"),
    ("deployed", "ipfs", None),           # no enum value says "metadata hash -> IPFS"; null, never a guess
])
def test_status_provenance_source_from_fetch_provider(source_kind, provider, want):
    body = start_status._build_status_response(_tiered_job(source_kind), "json", steps=[_fetch_step(provider)])
    assert body["provenance"]["source"] == want
    assert list(STATUS_SCHEMA.iter_errors(body)) == []


def test_status_provenance_source_tier_d_without_fetch_is_bytecode_only():
    body = start_status._build_status_response(_tiered_job("deployed", tier="D"), "json", steps=[])
    assert body["provenance"]["source"] == "bytecode_only"
    assert list(STATUS_SCHEMA.iter_errors(body)) == []


@pytest.mark.parametrize("source_kind", ["deployed", "repo", "files", "upload"])
def test_status_provenance_source_never_echoes_input_kind(source_kind):
    body = start_status._build_status_response(_tiered_job(source_kind), "json", steps=[])
    assert body["provenance"]["source"] is None
    assert list(STATUS_SCHEMA.iter_errors(body)) == []


# ── error.detail: omit when null (tools.v1.json error.detail is an optional string) ──


def _errored_job(error_code: str, error_detail):
    job = _tiered_job("repo")
    job.update(state="insufficient_source", error_code=error_code, error_detail=error_detail)
    return job


def test_status_error_omits_detail_when_null():
    # E_SOURCE_NOT_FOUND with no detail text: `detail: null` would fail the schema (type string),
    # so the key must be omitted, not sent as null (a validating MCP client rejects the response).
    body = start_status._build_status_response(_errored_job("E_SOURCE_NOT_FOUND", None), "json", steps=[])
    # `what` names {providers}, which no detail fills: left out; `fix` has no placeholder: sent.
    assert body["error"] == {"code": "E_SOURCE_NOT_FOUND",
                             "fix": load_errors()["E_SOURCE_NOT_FOUND"]["fix"]}
    assert "detail" not in body["error"]
    assert list(STATUS_SCHEMA.iter_errors(body)) == []


def test_status_error_keeps_detail_when_present():
    body = start_status._build_status_response(
        _errored_job("E_BUILD_FAILED", "solc: file not found"), "json", steps=[])
    assert body["error"] == {"code": "E_BUILD_FAILED", "detail": "solc: file not found"}
    assert list(STATUS_SCHEMA.iter_errors(body)) == []


# ── error.detail: structured detail becomes one string (schema: detail is a string) ──


def test_status_error_structured_detail_is_serialized_as_text():
    # The supervisor stores structured details (missing_import packages, missing_dependency_path
    # prefixes); the wire contract types detail as a string, so the object is serialized compactly
    # with sorted keys (stable for the judge), never sent as an object.
    body = start_status._build_status_response(
        _errored_job("E_SOURCE_NOT_FOUND",
                     {"reason": "missing_import", "packages": ["@openzeppelin/contracts", "solmate"]}),
        "json", steps=[])
    assert body["error"]["detail"] == '{"packages":["@openzeppelin/contracts","solmate"],"reason":"missing_import"}'
    assert body["error"]["code"] == "E_SOURCE_NOT_FOUND"
    assert list(STATUS_SCHEMA.iter_errors(body)) == []


def test_status_error_detail_list_and_cap():
    body = start_status._build_status_response(_errored_job("E_BUILD_FAILED", ["a", "b"]), "json", steps=[])
    assert body["error"]["detail"] == '["a","b"]'
    long = start_status._build_status_response(_errored_job("E_BUILD_FAILED", "x" * 5000), "json", steps=[])
    assert len(long["error"]["detail"]) == start_status._ERROR_DETAIL_MAX_CHARS
    assert list(STATUS_SCHEMA.iter_errors(long)) == []


# ── E_DEPENDENCY_UNRESOLVED: what + fix filled from the stored detail (blind run 2026-10-25) ──


def test_status_dependency_unresolved_names_packages_and_fix():
    detail = {"stage": "dependencies", "lockfile": None,
              "missing": [{"name": "@acme/lib", "reason": "not_in_registry"}], "packages": "@acme/lib"}
    body = start_status._build_status_response(_errored_job("E_DEPENDENCY_UNRESOLVED", detail), "json", steps=[])
    err = body["error"]
    assert err["code"] == "E_DEPENDENCY_UNRESOLVED"
    assert "@acme/lib" in err["what"]
    assert "lockfile" in err["fix"] and "lib/" in err["fix"]
    assert "\u2014" not in err["fix"] and "\u2014" not in err["what"]   # no em dash in client text
    assert list(STATUS_SCHEMA.iter_errors(body)) == []


def test_status_build_missing_import_list_fills_packages():
    detail = {"reason": "missing_import", "packages": ["@openzeppelin/contracts", "solmate"], "dropped_invalid": 0}
    body = start_status._build_status_response(_errored_job("E_DEPENDENCY_UNRESOLVED", detail), "json", steps=[])
    assert "@openzeppelin/contracts, solmate" in body["error"]["what"]


def _deps_step(pinned_by: str) -> dict:
    return {"step": "fetch", "status": "done", "provenance": {"provider": "repo", "sha256": "0" * 64,
            "dependencies": {"lockfile": None if pinned_by == "registry_range" else "package-lock.json",
                             "pinned_by": pinned_by,
                             "packages": [{"name": "@openzeppelin/contracts", "version": "5.6.1",
                                           "pinned_by": pinned_by, "integrity": "sha512-x", "files": 227}]}}}


def test_status_dependencies_block_concise_and_detailed():
    job = _tiered_job("repo")
    concise = start_status._build_status_response(job, "json", steps=[_deps_step("lockfile")])
    assert concise["dependencies"]["count"] == 1 and concise["dependencies"]["pinned_by"] == "lockfile"
    assert "packages" not in concise["dependencies"]
    assert list(STATUS_SCHEMA.iter_errors(concise)) == []
    detailed = start_status._build_status_response(job, "detailed", steps=[_deps_step("registry_range")])
    deps = detailed["dependencies"]
    assert deps["packages"] == [{"name": "@openzeppelin/contracts", "version": "5.6.1", "pinned_by": "registry_range"}]
    assert "no lockfile" in deps["note"]
    # Only the new block is checked here: the detailed `build.status` echoes map_status ("none"),
    # which the schema enum does not list (pre-existing, tracked separately).
    deps_schema = {t["name"]: t for t in bundle_tools()}["review_status"]["outputSchema"]["properties"]["dependencies"]
    assert list(Draft202012Validator(deps_schema).iter_errors(deps)) == []


def test_status_no_dependencies_block_without_vendored_packages():
    body = start_status._build_status_response(_tiered_job("repo"), "json", steps=[])
    assert "dependencies" not in body


# ── detailed build.status: schema enum, never a map status ────────────────────


def test_build_status_value_from_build_result_and_map_status(tmp_path):
    pins = tmp_path / "pins"
    work = tmp_path / "work" / "job_X"
    work.mkdir(parents=True)
    assert start_status._build_status_value(pins, "job_X", "none") is None
    assert start_status._build_status_value(pins, "job_X", "failed") == "failed"
    assert start_status._build_status_value(pins, "job_X", "full") == "ok"
    (work / "build_result.json").write_text(json.dumps({"status": "ok"}))
    assert start_status._build_status_value(pins, "job_X", "partial") == "ok"
    (work / "build_result.json").write_text(json.dumps({"status": "weird"}))
    assert start_status._build_status_value(pins, "job_X", "lexical") is None


# ── held-out friction 2026-10-27: files-mode dependency text, bytecode match in status ───────


def test_status_dependency_unresolved_files_mode_talks_about_pasted_files():
    detail = {"reason": "missing_import", "packages": ["@openzeppelin/contracts"], "dropped_invalid": 0, "mode": "files"}
    body = start_status._build_status_response(_errored_job("E_DEPENDENCY_UNRESOLVED", detail), "json", steps=[])
    err = body["error"]
    assert "pasted files import @openzeppelin/contracts" in err["what"]
    assert "repository" not in err["what"] and "lockfile" not in err["fix"]
    assert "review_start.source.remappings" in err["fix"] and "@openzeppelin/contracts/=" in err["fix"]
    assert "—" not in err["fix"]
    assert list(STATUS_SCHEMA.iter_errors(body)) == []


def _build_step(match: str | None, reason: str | None, tier: str, block: int | None = 130092367) -> dict:
    return {"step": "build", "seq": 0, "status": "done",
            "provenance": {"tier": tier, "dep_match": match, "dep_reason": reason, "label_reason": None, "block": block}}


def test_status_detailed_exposes_bytecode_match_from_the_build_step():
    job = _tiered_job("files", tier="A")
    out = start_status._build_status_response(job, "detailed", steps=[_fetch_step("user"), _build_step("exact", None, "A")])
    dep = out["build"]["deployment"]
    assert dep["match"] == "exact" and dep["tier"] == "A"
    assert dep["label"] == "Source matched to deployed code at block 130092367"
    assert out["provenance"]["label"] == dep["label"]
    assert list(STATUS_SCHEMA.iter_errors(out)) == []


def test_status_detailed_bytecode_not_checkable_names_the_reason():
    job = _tiered_job("repo")
    out = start_status._build_status_response(job, "detailed", steps=[_build_step("not_checkable", "build_failed", "B", None)])
    dep = out["build"]["deployment"]
    assert dep["match"] == "not_checkable" and dep["reason"] == "build_failed"
    assert dep["label"] == "Match to the deployed code could not be checked (build_failed)"
    assert list(STATUS_SCHEMA.iter_errors(out)) == []


def test_status_concise_has_no_deployment_block_and_schema_holds():
    job = _tiered_job("repo")
    out = start_status._build_status_response(job, "concise", steps=[_build_step("mismatch", None, "C")])
    assert "build" not in out
    assert list(STATUS_SCHEMA.iter_errors(out)) == []


def test_build_attempts_reader_shape_checks(tmp_path):
    job_id = "job_" + "2" * 26
    work = tmp_path / "work" / job_id
    work.mkdir(parents=True)
    (work / "build_result.json").write_text(json.dumps({"status": "ok", "attempts": [
        {"version": "0.8.0", "version_source": "pragma floor", "status": "failed", "reason": "ParserError"},
        {"version": "0.8.24", "version_source": "newest", "status": "ok", "reason": None},
        {"version": "x", "status": "weird"}]}))
    rows = start_status._build_attempts(tmp_path / "pins", job_id)
    assert [r["version"] for r in rows] == ["0.8.0", "0.8.24"] and rows[0]["reason"] == "ParserError"


def test_build_attempts_carry_the_narrowed_scope(tmp_path):
    job_id = "job_" + "3" * 26
    work = tmp_path / "work" / job_id
    work.mkdir(parents=True)
    (work / "build_result.json").write_text(json.dumps({"status": "ok", "attempts": [
        {"version": "0.8.28", "version_source": "partial", "status": "failed", "reason": "ParserError"},
        {"version": "0.8.28", "status": "failed", "reason": "ParserError", "scope": "closure", "files": 13},
        {"version": "0.8.28", "status": "ok", "reason": None, "scope": "exclude", "files": 12,
         "excluded": ["src/libraries/1inchV6.sol"]}]}))
    rows = start_status._build_attempts(tmp_path / "pins", job_id)
    assert "scope" not in rows[0]
    assert rows[1] == {"version": "0.8.28", "version_source": None, "status": "failed", "reason": "ParserError",
                       "scope": "closure", "files": 13}
    assert rows[2]["excluded"] == ["src/libraries/1inchV6.sol"]
