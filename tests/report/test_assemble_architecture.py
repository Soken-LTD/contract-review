"""Assembly wiring (08 3.1): a job with a semantic map and facts gets the real architecture block and
roles rows in its stored report.json; a job without a map keeps the W0 `no_map` stub."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.mapping.build import build_map, write_map
from soken_review.mapping.facts import fact, write_facts
from soken_review.mapping.step import family_categories
from soken_review.report import render

from .test_render_flow import _claim, _fake, _job

ASYNC = pytest.mark.asyncio(loop_scope="session")
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map"
OWNER = "0x1111111111111111111111111111111111111111"


async def _render(db_pool, tmp_path, monkeypatch, *, with_map: bool) -> dict:
    monkeypatch.setenv("SOKEN_REPORT_STORE", str(tmp_path / "store"))
    monkeypatch.setenv("SOKEN_RENDER_ROOT", str(tmp_path / "render-root"))
    fake, _ = _fake(["ok"])
    monkeypatch.setattr(render, "run_container", fake)
    jid = await _job(db_pool, tmp_path, {"High": "Reentrant withdraw drains the vault", "Low": "Balance written late"})
    pin_root = tmp_path / "pins"
    if with_map:
        # The pinned Vault of test_render_flow is a stub; the map comes from the fixture Vault whose solc
        # output we have, under the same path, so the deployed unit id matches the candidate entry.
        art = build_map({"src/Vault.sol": (FIX / "Vault.sol").read_text()},
                        json.loads((FIX / "vault_solc_output.json").read_text()), list(family_categories("evm")))
        write_map(pin_root, jid, art)
        write_facts(pin_root, jid, [fact("onchain.owner", OWNER, unit_id="src/Vault.sol:Vault",
                                         source="eth_call owner() at block 1")])
    step = await _claim(db_pool)
    out = await render.run_render_step(db_pool, step, pin_root, image="img")
    assert out.code == "ok", out
    async with db_pool.connection() as conn:
        row = await render.report_row(conn, jid)
    return json.loads((tmp_path / "store" / row["object_prefix"] / "report.json").read_text())


@ASYNC
async def test_assembled_report_carries_the_map_diagram_and_roles(db_pool, tmp_path, monkeypatch):
    r = await _render(db_pool, tmp_path, monkeypatch, with_map=True)
    ids = {n["id"] for n in r["architecture"]["nodes"]}
    assert "no_map" not in ids and {"u_vault", "a_onlyowner", "x_any_address"} <= ids
    assert next(n for n in r["architecture"]["nodes"] if n["id"] == "u_vault")["sub"] == "deployed, 4 entries"
    assert r["architecture"]["edges"]
    roles = {x["role"]: x for x in r["roles"]["rows"]}
    assert roles["onlyOwner"]["holder"] == {"addr": OWNER}
    assert roles["onlyOwner"]["gated_functions"] == ["Vault.setFee"]
    assert roles["msg.sender check"]["risk_note"] == "Can move funds held by the contract"


@ASYNC
async def test_assembled_report_without_a_map_keeps_the_stub(db_pool, tmp_path, monkeypatch):
    r = await _render(db_pool, tmp_path, monkeypatch, with_map=False)
    assert [n["id"] for n in r["architecture"]["nodes"]] == ["no_map"]
    assert r["roles"]["rows"] == []


def test_context_quote_reads_from_the_context_store(tmp_path):
    """A finding quote with a `context/` path renders from the context store, not the code pin
    (render crashed with KeyError 'context/docs-1.md' on the first such quote, 2026-10-23)."""
    from soken_review.context.store import ContextStore
    from soken_review.pinning.store import PinnedSource
    from soken_review.report.assemble import AssemblyError, _code_block, _quote_source

    pin = PinnedSource.from_files({"src/V.sol": b"pragma solidity ^0.8.0;\ncontract V {}\n"})
    pin.persist(tmp_path, "job_ctxq")
    store = ContextStore(tmp_path, "job_ctxq")
    store.add([{"kind": "docs", "url": "https://docs.example.org/", "final_url": "https://docs.example.org/",
                "status": "ok", "content_type": "text/html", "bytes": 10, "sha256_raw": "ab" * 32,
                "fetched_at": "2026-10-23T00:00:00+00:00", "title": "Docs", "text": "Governance\nOwner sets fees\n",
                "bundle_hits": {}}])
    path = next(iter(store.entries))
    pin_loaded = PinnedSource.load(tmp_path, "job_ctxq")
    block = _code_block(_quote_source(pin_loaded, store, path), path, 1, 3, 40)
    assert block["code"]["ref"]["path"] == path and len(block["code"]["lines"]) == 3
    assert _quote_source(pin_loaded, store, "src/V.sol") is pin_loaded
    with pytest.raises(AssemblyError):
        _quote_source(pin_loaded, None, path)
