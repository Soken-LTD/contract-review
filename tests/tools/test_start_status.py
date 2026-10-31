"""Tool-level tests for review_start and review_status (plan-v4 part 03 sections 4.1, 4.2).

Uses the MCP SDK in-process client against a live SokenServer.  DB tests require Docker.
Non-DB tests run everywhere; they cover input validation and rejection paths.
"""

from __future__ import annotations

import json
import re

import pytest
import pytest_asyncio

# Register tool handlers before any test runs
import soken_review.tools  # noqa: F401 – side-effect: @handler decorators fire
from soken_review.tools.start_status import set_pool as tools_set_pool

from ._client import task_scoped_client

ASYNC = pytest.mark.asyncio(loop_scope="session")   # the db_pool loop (tests/conftest.py)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(loop_scope="session")
async def client_no_db():
    """SDK client without a DB pool; only input-validation tests work here."""
    async with task_scoped_client() as c:
        yield c


@pytest_asyncio.fixture(loop_scope="session")
async def client_with_db(db_pool):
    """SDK client with the test pool injected into the tools module."""
    tools_set_pool(db_pool)
    try:
        async with task_scoped_client() as c:
            yield c
    finally:
        tools_set_pool(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# review_start — input validation (no DB needed)
# ---------------------------------------------------------------------------

class TestReviewStartValidation:
    """Schema and synchronous validation checks; no DB pool required."""

    @ASYNC
    async def test_missing_source_is_invalid_argument(self, client_no_db):
        result = await client_no_db.call_tool("review_start", {})
        assert result.is_error
        body = json.loads(result.content[0].text)
        assert body["errors"][0]["code"] == "E_INVALID_ARGUMENT"

    @ASYNC
    async def test_evm_without_chain_id_rejected(self, client_no_db):
        """evm without chain_id -> E_CHAIN_ID_REQUIRED (03 §4.1)."""
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "address": "0x" + "a" * 40}},
        )
        assert result.is_error is False  # schema valid
        body = json.loads(result.content[0].text)
        assert body["accepted"] is False
        assert body["errors"][0]["code"] == "E_CHAIN_ID_REQUIRED"

    @ASYNC
    async def test_evm_bad_address_rejected(self, client_no_db):
        """Bad EVM address format -> E_ADDRESS_INVALID."""
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": "notanaddress"}},
        )
        body = json.loads(result.content[0].text)
        assert body["accepted"] is False
        assert body["errors"][0]["code"] == "E_ADDRESS_INVALID"

    @ASYNC
    async def test_inline_too_many_files(self, client_no_db):
        """20 files × 10001 chars = 200020 total chars -> E_SIZE_LIMIT (handler-level, 03 §4.1).

        Note: 21 files is caught at the schema level (maxItems: 20) as E_INVALID_ARGUMENT
        before the handler runs.  We test total-char overflow here to exercise the handler
        branch for E_SIZE_LIMIT (a rejection-channel code per 03 §7.1).
        """
        content = "x" * 10001  # 10001 chars × 20 files = 200020 > _MAX_INLINE_CHARS_TOTAL
        files = [{"path": f"f{i}.sol", "content": content} for i in range(20)]
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "files", "language": "solidity", "files": files}},
        )
        body = json.loads(result.content[0].text)
        assert body["accepted"] is False
        assert body["errors"][0]["code"] == "E_SIZE_LIMIT"

    @ASYNC
    async def test_inline_total_chars_exceeded(self, client_no_db):
        """200001 total chars -> E_SIZE_LIMIT."""
        # 4 files, 50001 chars each > 200000 total
        content = "x" * 50001
        files = [{"path": f"f{i}.sol", "content": content} for i in range(4)]
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "files", "language": "solidity", "files": files}},
        )
        body = json.loads(result.content[0].text)
        assert body["accepted"] is False
        assert body["errors"][0]["code"] == "E_SIZE_LIMIT"

    @ASYNC
    async def test_repo_bad_url_rejected_by_schema(self, client_no_db):
        """Non-github/gitlab/codeberg URL rejected by schema (E_INVALID_ARGUMENT)."""
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "repo", "repo_url": "https://example.com/foo"}},
        )
        assert result.is_error
        body = json.loads(result.content[0].text)
        assert body["errors"][0]["code"] == "E_INVALID_ARGUMENT"

    @ASYNC
    async def test_upload_kind_accepted_by_schema(self, client_no_db):
        """upload kind is valid in schema; handler will fail without DB."""
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "upload"}},
        )
        # Without DB this raises an exception (no pool), which server catches as E_INTERNAL
        # OR it's accepted; either way it must not be a schema error
        body = json.loads(result.content[0].text)
        # schema should not reject it
        errors = body.get("errors", [])
        schema_errors = [e for e in errors if e["code"] == "E_INVALID_ARGUMENT"]
        assert not schema_errors, "upload kind should pass schema validation"

    @ASYNC
    async def test_chain_without_rpc_rejected(self, client_no_db):
        """A deployed address on a chain the worker cannot read is refused at start with
        E_CHAIN_DISABLED instead of a job that fails minutes later (2026-10-22, Sepolia)."""
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "chain_id": 11155111, "address": "0x" + "a" * 40}},
        )
        body = json.loads(result.content[0].text)
        assert body["accepted"] is False
        err = body["errors"][0]
        assert err["code"] == "E_CHAIN_DISABLED"
        assert "11155111" in err["what"] and "1" in err["fix"]

    @ASYNC
    async def test_repo_deployment_on_chain_without_rpc_rejected(self, client_no_db):
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "repo", "repo_url": "https://github.com/a/b", "commit": "a" * 40,
                        "deployment": {"chain": "evm", "chain_id": 11155111, "address": "0x" + "a" * 40}}},
        )
        body = json.loads(result.content[0].text)
        assert body.get("accepted") is False
        assert body["errors"][0]["code"] == "E_CHAIN_DISABLED"

    @pytest.mark.parametrize("source", [
        {"kind": "deployed", "chain": "starknet", "address": "0x" + "1" * 63},
        {"kind": "repo", "repo_url": "https://github.com/a/b", "commit": "a" * 40,
         "deployment": {"chain": "starknet", "address": "0x" + "1" * 63}},
        {"kind": "files", "language": "cairo", "files": [{"path": "src/lib.cairo", "content": "mod a;"}]},
    ])
    @ASYNC
    async def test_disabled_family_is_refused_at_start(self, client_no_db, monkeypatch, source):
        """Launch without Starknet (decision 2026-10-23): SOKEN_DISABLED_FAMILIES=starknet refuses
        every Starknet entry with E_CHAIN_DISABLED and names the chains that are on."""
        monkeypatch.setenv("SOKEN_DISABLED_FAMILIES", "starknet")
        result = await client_no_db.call_tool("review_start", {"source": source})
        body = json.loads(result.content[0].text)
        assert body["accepted"] is False
        err = body["errors"][0]
        assert err["code"] == "E_CHAIN_DISABLED"
        assert "starknet" not in err["fix"] and "solana" in err["fix"] and "sui" in err["fix"]

    @ASYNC
    async def test_hyperevm_chain_normalised(self, client_no_db):
        """evm with chain_id 999 is normalised to hyperevm (03 §4.1) — no DB needed."""
        # Without DB the job creation will fail, but chain normalization is checked first.
        # We verify it doesn't raise E_CHAIN_ID_REQUIRED or E_ADDRESS_INVALID.
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "chain_id": 999, "address": "0x" + "a" * 40}},
        )
        body = json.loads(result.content[0].text)
        errors = [e["code"] for e in body.get("errors", [])]
        assert "E_CHAIN_ID_REQUIRED" not in errors
        assert "E_ADDRESS_INVALID" not in errors


# ---------------------------------------------------------------------------
# review_start + review_status — DB-backed
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    __import__("subprocess").run(
        ["docker", "info"], capture_output=True
    ).returncode != 0,
    reason="docker unavailable",
)
class TestReviewStartWithDB:

    @ASYNC
    async def test_deployed_creates_job_queued(self, client_with_db):
        result = await client_with_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": "0x" + "a" * 40}},
        )
        body = json.loads(result.content[0].text)
        assert body["accepted"] is True
        assert re.match(r"^job_[0-9A-HJKMNP-TV-Z]{26}$", body["job_id"])
        assert body["state"] == "queued"
        assert body["resume_phrase"].startswith("Resume Soken review job_")
        from soken_review.contract import schema_version
        assert body["schema_version"] == schema_version()

    @ASYNC
    async def test_upload_creates_job_awaiting_upload(self, client_with_db):
        result = await client_with_db.call_tool(
            "review_start",
            {"source": {"kind": "upload"}},
        )
        body = json.loads(result.content[0].text)
        assert body["accepted"] is True
        assert body["state"] == "awaiting_upload"
        assert "upload_url" in body
        assert re.match(
            r"^https://soken\.dev/u/[a-z2-7]{26}\?e=[0-9]{10}&s=[a-z2-7]{26}$",
            body["upload_url"],
        ), body.get("upload_url")
        assert "upload_expires_at" in body

    @ASYNC
    async def test_files_kind_receives_file_list(self, client_with_db):
        files = [{"path": "src/Token.sol", "content": "// SPDX-License-Identifier: MIT\n"}]
        result = await client_with_db.call_tool(
            "review_start",
            {"source": {"kind": "files", "language": "solidity", "files": files}},
        )
        body = json.loads(result.content[0].text)
        assert body["accepted"] is True
        assert len(body["files_received"]) == 1
        f = body["files_received"][0]
        assert f["path"] == "src/Token.sol"
        assert re.match(r"^[0-9a-f]{64}$", f["sha256"])
        assert f["role"] == "source"

    @ASYNC
    async def test_review_status_returns_queued(self, client_with_db):
        # First create a job
        r1 = await client_with_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": "0x" + "b" * 40}},
        )
        job_id = json.loads(r1.content[0].text)["job_id"]

        # Then poll status
        r2 = await client_with_db.call_tool(
            "review_status",
            {"job_id": job_id},
        )
        body = json.loads(r2.content[0].text)
        assert body["accepted"] is True
        assert body["job_id"] == job_id
        assert body["state"] == "queued"
        assert body["step"] == "queued"
        assert body["percent"] == 0

    @ASYNC
    async def test_review_status_unknown_job(self, client_with_db):
        fake_id = "job_" + "A" * 26
        result = await client_with_db.call_tool(
            "review_status",
            {"job_id": fake_id},
        )
        assert result.is_error
        body = json.loads(result.content[0].text)
        assert body["errors"][0]["code"] == "E_JOB_NOT_FOUND"

    @ASYNC
    async def test_output_validates_against_schema(self, client_with_db):
        """Output of review_start must conform to the bundled outputSchema (03 §1)."""
        from jsonschema import Draft202012Validator

        from soken_review.contract import bundle_tools

        contract = {t["name"]: t for t in bundle_tools()}
        schema = contract["review_start"]["outputSchema"]
        validator = Draft202012Validator(schema)

        result = await client_with_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": "0x" + "c" * 40}},
        )
        body = json.loads(result.content[0].text)
        errors = list(validator.iter_errors(body))
        assert errors == [], errors

    @ASYNC
    async def test_status_output_validates_against_schema(self, client_with_db):
        """Output of review_status must conform to the bundled outputSchema (03 §1)."""
        from jsonschema import Draft202012Validator

        from soken_review.contract import bundle_tools

        contract = {t["name"]: t for t in bundle_tools()}
        schema = contract["review_status"]["outputSchema"]
        validator = Draft202012Validator(schema)

        r1 = await client_with_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": "0x" + "d" * 40}},
        )
        job_id = json.loads(r1.content[0].text)["job_id"]

        r2 = await client_with_db.call_tool("review_status", {"job_id": job_id})
        body = json.loads(r2.content[0].text)
        errors = list(validator.iter_errors(body))
        assert errors == [], errors


def test_status_response_names_the_served_schema_version():
    """Every review_status carries the hash of the served tool list, so a client whose cached list
    predates a deploy (D1, blind run 2026-10-26) can tell and reload it."""
    from soken_review.contract import schema_version
    from soken_review.tools.start_status import _build_status_response

    job = {"job_id": "job_SCHEMA00000000000000000000", "state": "ready", "requester_role": "third_party_public_code",
           "ownership_proven": False, "context_items": [], "error_code": None, "error_detail": None,
           "map_status": "partial", "analyzer_degraded": False, "tier": None, "upload_id": None}
    out = _build_status_response(job, "concise")
    assert out["schema_version"] == schema_version()
    out = _build_status_response({**job, "state": "awaiting_upload", "upload_id": "u" * 26}, "detailed")
    assert out["schema_version"] == schema_version()


# ── scope_excluded in review_status (security review of PR #84) ───────────────

def test_scope_excluded_status_from_fetch_provenance():
    from soken_review.tools.start_status import _scope_excluded_status

    steps = [{"step": "fetch", "status": "done", "provenance": {"provider": "repo", "scope_excluded": {
        "count": 3, "files": [{"path": "contracts/mocks/MockUSDC.sol", "reason": "test_or_mock_dir"},
                              {"path": "contracts/Vault.t.sol", "reason": "mock_name"},
                              {"path": "contracts/Odd.sol", "reason": "unknown_code"}]}}}]
    brief = _scope_excluded_status(steps, detailed=False)
    assert brief["count"] == 3 and "files" not in brief and brief["note"]
    detailed = _scope_excluded_status(steps, detailed=True)
    assert [f["reason"] for f in detailed["files"]] == ["test_or_mock_dir", "mock_name", "other"]
    assert _scope_excluded_status([{"step": "fetch", "status": "done", "provenance": {"provider": "repo"}}],
                                  detailed=True) is None


# ---------------------------------------------------------------------------
# Related contracts in one job (matrix run 2026-10-31, Magnum)
# ---------------------------------------------------------------------------

_MAIN = "0x48a2728Db6854f2844c2F77423Ad75876d7c60F7"
_PF = "0x7366388273111e035bbc555cd0f44a5bb3067c32"
_NFT = "0xe063710f0de555894342325d42b921f9fc225590"


class TestRelatedContracts:
    @ASYNC
    async def test_related_field_and_old_scope_include_are_stored(self, client_with_db, db_pool):
        result = await client_with_db.call_tool("review_start", {
            "source": {"kind": "deployed", "chain": "evm", "chain_id": 56, "address": _MAIN,
                       "related": [{"address": _PF, "name": "PriceFeed"}]},
            "scope": {"include": [f"related:NFT={_NFT}"]},
        })
        body = json.loads(result.content[0].text)
        assert body["accepted"] is True, body
        assert body["related"] == [{"address": _PF, "name": "PriceFeed"}, {"address": _NFT, "name": "NFT"}]
        async with db_pool.connection() as conn:
            row = await (await conn.execute("select source_args from jobs where job_id = %s",
                                            (body["job_id"],))).fetchone()
        args = row[0] if isinstance(row[0], dict) else json.loads(row[0])
        assert args["related"] == body["related"]

    @ASYNC
    async def test_old_schema_scope_include_alone_works(self, client_with_db):
        result = await client_with_db.call_tool("review_start", {
            "source": {"kind": "deployed", "chain": "evm", "chain_id": 56, "address": _MAIN},
            "scope": {"include": [f"related:{_PF}"]},
        })
        body = json.loads(result.content[0].text)
        assert body["accepted"] is True and body["related"] == [{"address": _PF, "name": "c_" + _PF[2:12]}]

    @ASYNC
    async def test_bad_related_entry_names_the_field(self, client_with_db):
        result = await client_with_db.call_tool("review_start", {
            "source": {"kind": "deployed", "chain": "evm", "chain_id": 56, "address": _MAIN},
            "scope": {"include": ["related:PriceFeed=0x1234"]},
        })
        env = json.loads(result.content[0].text)["errors"][0]
        assert env["code"] == "E_INVALID_ARGUMENT" and env["field"] == "scope.include[0]"

    @ASYNC
    async def test_related_needs_a_deployed_evm_source(self, client_with_db):
        result = await client_with_db.call_tool("review_start", {
            "source": {"kind": "files", "language": "solidity",
                       "files": [{"path": "A.sol", "content": "contract A {}\n"}]},
            "scope": {"include": [f"related:{_PF}"]},
        })
        env = json.loads(result.content[0].text)["errors"][0]
        assert env["code"] == "E_INVALID_ARGUMENT" and env["field"] == "scope.include"
