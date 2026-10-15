"""Tool-level tests for review_start and review_status (plan-v4 part 03 sections 4.1, 4.2).

Uses the MCP SDK in-process client against a live SokenServer.  DB tests require Docker.
Non-DB tests run everywhere; they cover input validation and rejection paths.
"""

from __future__ import annotations

import json
import re

import pytest
import pytest_asyncio
from mcp import Client

# Register tool handlers before any test runs
import soken_review.tools  # noqa: F401 – side-effect: @handler decorators fire
from soken_review.server import SokenServer
from soken_review.tools.start_status import set_pool as tools_set_pool

pytestmark = pytest.mark.anyio


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture()
async def client_no_db():
    """SDK client without a DB pool; only input-validation tests work here."""
    async with Client(SokenServer()) as c:
        yield c


@pytest_asyncio.fixture()
async def client_with_db(db_pool):
    """SDK client with the test pool injected into the tools module."""
    tools_set_pool(db_pool)
    try:
        async with Client(SokenServer()) as c:
            yield c
    finally:
        tools_set_pool(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# review_start — input validation (no DB needed)
# ---------------------------------------------------------------------------

class TestReviewStartValidation:
    """Schema and synchronous validation checks; no DB pool required."""

    async def test_missing_source_is_invalid_argument(self, client_no_db):
        result = await client_no_db.call_tool("review_start", {})
        assert result.is_error
        body = json.loads(result.content[0].text)
        assert body["errors"][0]["code"] == "E_INVALID_ARGUMENT"

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

    async def test_evm_bad_address_rejected(self, client_no_db):
        """Bad EVM address format -> E_ADDRESS_INVALID."""
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "deployed", "chain": "evm", "chain_id": 1, "address": "notanaddress"}},
        )
        body = json.loads(result.content[0].text)
        assert body["accepted"] is False
        assert body["errors"][0]["code"] == "E_ADDRESS_INVALID"

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

    async def test_repo_bad_url_rejected_by_schema(self, client_no_db):
        """Non-github/gitlab/codeberg URL rejected by schema (E_INVALID_ARGUMENT)."""
        result = await client_no_db.call_tool(
            "review_start",
            {"source": {"kind": "repo", "repo_url": "https://example.com/foo"}},
        )
        assert result.is_error
        body = json.loads(result.content[0].text)
        assert body["errors"][0]["code"] == "E_INVALID_ARGUMENT"

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

    async def test_review_status_unknown_job(self, client_with_db):
        fake_id = "job_" + "A" * 26
        result = await client_with_db.call_tool(
            "review_status",
            {"job_id": fake_id},
        )
        assert result.is_error
        body = json.loads(result.content[0].text)
        assert body["errors"][0]["code"] == "E_JOB_NOT_FOUND"

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
