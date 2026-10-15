# ruff: noqa: F811  (fixtures imported from test_e2e_evm are pytest parameters here)
"""Integration: TON jobs through the supervisor (06 2.4, 4.2, 4.3; 03 4.1, 4.2, 4.7).

MCP client -> Postgres queue -> supervisor -> toncenter v2 + verifier.ton.org + ton-build
sandbox -> ready -> review_leads. Skips unless SOKEN_DATABASE_URL and SOKEN_IMAGE_TON_BUILD
are set (live network, docker).

  USDT jetton master (mainnet): deployed job -> tier A (verifier bundle rebuilds to the
    supervisor-computed code hash) -> leads (lead.v1, categories in checklists/ton.yaml)
  Same bundle with one error code changed, as files with the USDT deployment -> user source
    tried and differs, verifier bundle rebuilds -> tier A from the verifier source
  Control: that changed source against an unverified active account -> tier D
  Files job without a deployment (Tolk) -> tier B, ready
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import httpx
import jsonschema
import pytest
import yaml

from tests.integration.test_e2e_evm import (  # noqa: F401  fixtures
    _mcp_call,
    mcp_client,
    pg_pool,
    pin_root,
    running_supervisor,
)

pytestmark = pytest.mark.skipif(
    not (os.environ.get("SOKEN_DATABASE_URL") and os.environ.get("SOKEN_IMAGE_TON_BUILD")),
    reason="SOKEN_DATABASE_URL and SOKEN_IMAGE_TON_BUILD needed",
)

ROOT = Path(__file__).resolve().parents[2]
USDT_MASTER = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"
# active mainnet account (2026-10-10) whose code hash 9149ae51.. has no verifier bundle
UNVERIFIED_ACCOUNT = "0:0bcc8f7673dc8a2a155cc457eb9efa26ce0f4b17b8eb7370d8dc6b9a237966f0"
USDT_CODE_HASH = "18d5b6e780ff0bb451254c2c760d09d6e485638cd1407abb97078752c3c1c9ee"

TOLK_COUNTER = """\
global counter: int;

fun onInternalMessage(myBalance: int, msgValue: int, msgFull: cell, msgBody: slice) {
    counter += 1;
}

get fun getCounter(): int {
    return counter;
}
"""


async def _poll_status(client, job_id: str, timeout: float) -> dict:
    """review_status until a state that ends the pipeline (ready, insufficient_source, failed)."""
    deadline = asyncio.get_event_loop().time() + timeout
    status: dict = {}
    while asyncio.get_event_loop().time() < deadline:
        status = await _mcp_call(client, "review_status", job_id=job_id)
        if status.get("state") in ("ready", "insufficient_source", "failed"):
            return status
        await asyncio.sleep(2.0)
    raise TimeoutError(f"{job_id}: last status {status}")


def _checklist_categories() -> set[str]:
    data = yaml.safe_load((ROOT / "contract/rubric/checklists/ton.yaml").read_text())
    enums = yaml.safe_load((ROOT / "contract/rubric/enums.yaml").read_text())["categories"]
    generic = {c["id"] for c in enums if c.get("family") == "ton" and c.get("generic")}
    return set(data["categories"]) | generic


def _leads_file(pin_root: Path, job_id: str) -> list[dict]:
    return json.loads((pin_root / job_id / "leads.json").read_text())


@pytest.mark.asyncio
@pytest.mark.timeout(900)
async def test_usdt_master_tier_a_and_leads(running_supervisor, mcp_client, pin_root) -> None:
    start = await _mcp_call(mcp_client, "review_start", source={"kind": "deployed", "chain": "ton", "address": USDT_MASTER})
    assert start.get("accepted"), start
    job_id = start["job_id"]
    status = await _poll_status(mcp_client, job_id, timeout=600.0)
    print(f"\nUSDT status: {json.dumps(status)}")
    assert status["state"] == "ready", status
    assert status["provenance"]["tier"] == "A"
    assert status["provenance"]["code_hash"] == USDT_CODE_HASH

    prov = json.loads((pin_root.parent / "work" / job_id / "provenance.json").read_text())
    print(f"USDT provenance: {json.dumps({k: prov[k] for k in ('reason', 'match', 'dep_hash', 'build_hash', 'matched_target', 'mc_seqno')})}")
    assert prov["match"] == "exact" and prov["build_hash"] == prov["dep_hash"] == USDT_CODE_HASH

    leads = await _mcp_call(mcp_client, "review_leads", job_id=job_id)
    assert not leads.get("is_error"), leads
    print("USDT review_leads:\n" + "\n".join(leads["text"].splitlines()[:6]))
    assert "LEAD-0001" in leads["text"]

    schema = json.loads((ROOT / "contract/rubric/schemas/lead.v1.json").read_text())
    allowed = _checklist_categories()
    docs = _leads_file(pin_root, job_id)
    for lead in docs:
        jsonschema.validate(lead, schema)
        assert lead["category"] in allowed, lead
    first = docs[0]
    read = await _mcp_call(mcp_client, "review_read_code", job_id=job_id, path=first["file"],
                           start_line=first["start"], end_line=first["end"])
    print(f"USDT read {first['file']}:{first['start']}: {str(read)[:200]}")
    assert "accepted" not in read or read.get("accepted") is not False


async def _changed_usdt_files() -> tuple[list[dict], str]:
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get("https://verifier.ton.org/api/v1/verification/source", params={"code_hash": USDT_CODE_HASH})
    bundle = r.json()["bundle"]
    files = []
    for f in bundle["files"]:
        content = f["content"]
        if f["path"] == bundle["entrypoint"]:
            changed = content.replace("throw_unless(error::not_owner,", "throw_unless(999,", 1)
            assert changed != content
            content = changed
        files.append({"path": f["path"], "content": content})
    return files, bundle["compiler"]["version"]


@pytest.mark.asyncio
@pytest.mark.timeout(900)
async def test_changed_user_source_tried_verifier_source_used(running_supervisor, mcp_client, pin_root) -> None:
    """06 2.4: the user's differing source is tried first; the verifier bundle that rebuilds exactly
    is Out.src (tier A) and is what enters the pinned store."""
    files, version = await _changed_usdt_files()
    start = await _mcp_call(
        mcp_client, "review_start",
        source={"kind": "files", "language": "func", "compiler_version": version,
                "files": files, "deployment": {"chain": "ton", "address": USDT_MASTER}},
    )
    assert start.get("accepted"), start
    status = await _poll_status(mcp_client, start["job_id"], timeout=600.0)
    assert status["state"] == "ready" and status["provenance"]["tier"] == "A", status
    prov = json.loads((pin_root.parent / "work" / start["job_id"] / "provenance.json").read_text())
    print(f"\nchanged-source tried: {json.dumps(prov['tried'])}")
    user, verifier = prov["tried"]
    assert user["provider"] == "user" and USDT_CODE_HASH not in user["hashes"].values()
    assert verifier["provider"] == "ton_verifier" and prov["src"] == 1


@pytest.mark.asyncio
@pytest.mark.timeout(900)
async def test_source_against_unverified_account_is_tier_d(running_supervisor, mcp_client, pin_root) -> None:
    """Negative control: the same changed source against an active account whose code hash has
    no verifier bundle -> the only candidate rebuilds to a different hash -> tier D."""
    files, version = await _changed_usdt_files()
    start = await _mcp_call(
        mcp_client, "review_start",
        source={"kind": "files", "language": "func", "compiler_version": version,
                "files": files, "deployment": {"chain": "ton", "address": UNVERIFIED_ACCOUNT}},
    )
    assert start.get("accepted"), start
    status = await _poll_status(mcp_client, start["job_id"], timeout=600.0)
    print(f"\ncontrol status: {json.dumps(status)}")
    assert status["state"] == "insufficient_source", status
    assert status["provenance"]["tier"] == "D"
    prov = json.loads((pin_root.parent / "work" / start["job_id"] / "provenance.json").read_text())
    print(f"control provenance: {json.dumps({k: prov[k] for k in ('reason', 'why', 'dep_hash', 'build_hash')})}")
    assert prov["reason"] == "SOURCE_NOT_OWNER_LINKED" and prov["why"] == "rebuild_differs"


@pytest.mark.asyncio
@pytest.mark.timeout(600)
async def test_tolk_files_without_deployment_is_tier_b(running_supervisor, mcp_client, pin_root) -> None:
    start = await _mcp_call(
        mcp_client, "review_start",
        source={"kind": "files", "language": "tolk", "compiler_version": "0.12.0",
                "files": [{"path": "counter.tolk", "content": TOLK_COUNTER}]},
    )
    assert start.get("accepted"), start
    status = await _poll_status(mcp_client, start["job_id"], timeout=300.0)
    print(f"\nTolk status: {json.dumps(status)}")
    assert status["state"] == "ready", status
    assert status["provenance"]["tier"] == "B"
    leads = await _mcp_call(mcp_client, "review_leads", job_id=start["job_id"])
    assert not leads.get("is_error"), leads
