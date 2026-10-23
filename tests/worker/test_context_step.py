"""The supervisor's `context` step and the queue-at-ready hook (context ingestion spec 3)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.context.store import ContextStore
from soken_review.mapping.facts import load_facts, write_facts
from soken_review.worker import supervisor as sup_mod
from soken_review.worker.supervisor import Supervisor

JOB = "job_CTXSTEP0000000000000000000"
ADDR = "0xc2edad668740f1aa35e4d8f227fb8e17dca888cd"


def _sup(pin_root: Path) -> Supervisor:
    sup = Supervisor.__new__(Supervisor)
    sup._pool = MagicMock()
    sup._pin_root = pin_root
    sup._host = "t"
    sup._running = {}
    sup._free_units = sup._total_units = 7
    sup._free_ram_mb = sup._total_ram_mb = 14336
    return sup


def _fake_fetch(kind: str, url: str, job_dir: Path, n: int, **_):
    if "fail" in url:
        return {"kind": kind, "url": url, "final_url": None, "status": "failed", "content_type": None, "bytes": 0,
                "sha256_raw": None, "fetched_at": "2026-10-23T12:00:00+00:00", "title": "", "text": "",
                "bundle_hits": {}, "error": "timeout", "error_detail": "wall"}
    text = f"# Page {n}\n\nThe router is {ADDR} on Ethereum Mainnet. Total supply 500 tokens."
    return {"kind": kind, "url": url, "final_url": url, "status": "ok", "content_type": "text/html", "bytes": 10,
            "sha256_raw": "ab" * 32, "fetched_at": "2026-10-23T12:00:00+00:00", "title": f"Page {n}", "text": text,
            "bundle_hits": {}, "error": None}


@pytest.mark.asyncio
async def test_run_context_fetches_missing_documents_and_writes_facts(tmp_path: Path) -> None:
    pin_root = tmp_path / "pins"
    pin_root.mkdir()
    write_facts(pin_root, JOB, [{"key": "source.files", "value": "1", "unit": None, "unit_id": None,
                                 "source": "pin manifest", "tags": []}])
    items = [{"kind": "website", "url": "https://site.example/", "path": None, "content": None, "sha256": None,
              "requested_at": "2026-10-23T11:00:00+00:00"},
             {"kind": "docs", "url": "https://docs.example/fail", "path": None, "content": None, "sha256": None,
              "requested_at": "2026-10-23T11:00:00+00:00"},
             {"kind": "whitepaper", "url": None, "path": "wp.md", "content": "# WP\n\nMax supply is 1 billion.",
              "sha256": "c" * 64, "requested_at": "2026-10-23T11:00:00+00:00"}]
    job = {"job_id": JOB, "state": "ready", "chain": "evm", "chain_id": 1, "address": ADDR, "context_items": items}
    sup = _sup(pin_root)
    calls: list[tuple[str, str, int]] = []

    def fetch(kind, url, job_dir, n, **kw):
        calls.append((kind, url, n))
        return _fake_fetch(kind, url, job_dir, n)

    with patch.object(sup, "_get_job", new=AsyncMock(return_value=job)), \
         patch.object(sup, "_mark_step", new=AsyncMock()) as mark, \
         patch("soken_review.sandbox.doc_fetch.fetch_document", new=fetch):
        await sup._run_context({"id": 7, "job_id": JOB, "step": "context", "seq": 0})
        store = ContextStore.load(pin_root, JOB)
        assert [(e.path, e.status) for e in store.documents] == [("context/website-1.md", "ok"),
                                                                  ("context/docs-1.md", "failed"),
                                                                  ("context/whitepaper-1.md", "ok")]
        assert calls == [("website", "https://site.example/", 0), ("docs", "https://docs.example/fail", 1)]
        assert store.read_all("context/whitepaper-1.md")[1] == "source: inline wp.md"
        facts = load_facts(pin_root, JOB)
        keys = {f["key"] for f in facts}
        assert {"source.files", "context.website.addresses", "context.website.mentions_reviewed_address",
                "context.website.total_supply", "context.website.chains", "context.whitepaper.max_supply"} <= keys
        assert json.loads((pin_root / JOB / "context_facts.json").read_text())
        prov = mark.await_args.kwargs["provenance"]
        assert mark.await_args.args == (7, "done")
        assert prov["requested"] == 3 and prov["done"] == 2 and prov["failed"] == 1 and prov["fetched_now"] == 2
        assert prov["context_pin"] == store.context_pin

        # a second round: stored documents are skipped, the failed one is retried only when re-requested
        calls.clear()
        await sup._run_context({"id": 8, "job_id": JOB, "step": "context", "seq": 1})
        assert calls == []
        items[1]["requested_at"] = "2026-10-23T13:00:00+00:00"
        items[1]["url"] = "https://docs.example/ok-now"
        with patch.object(sup, "_get_job", new=AsyncMock(return_value=job)):
            await sup._run_context({"id": 9, "job_id": JOB, "step": "context", "seq": 2})
        assert calls == [("docs", "https://docs.example/ok-now", 1)]
        store = ContextStore.load(pin_root, JOB)
        assert [e.path for e in store.documents] == ["context/website-1.md", "context/docs-1.md", "context/whitepaper-1.md",
                                                     "context/docs-2.md"]


def _conn_with_repo(repo):
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    return conn


@pytest.mark.asyncio
@pytest.mark.parametrize("state,items,steps,expect", [
    ("ready", [{"kind": "docs"}], [], True),
    ("ready", [], [], False),
    ("analyzing", [{"kind": "docs"}], [], False),
    ("ready", [{"kind": "docs"}], [{"step": "context", "status": "done"}], False),
])
async def test_maybe_queue_context_only_once_at_ready(tmp_path: Path, state, items, steps, expect) -> None:
    sup = _sup(tmp_path)
    repo = AsyncMock()
    repo.get = AsyncMock(return_value={"job_id": JOB, "state": state, "context_items": items})
    repo.get_steps = AsyncMock(return_value=steps)
    repo.insert_step = AsyncMock()
    sup._pool.connection = MagicMock(return_value=_conn_with_repo(repo))
    with patch.object(sup_mod, "JobRepo", return_value=repo):
        await sup._maybe_queue_context(JOB)
    assert repo.insert_step.await_count == (1 if expect else 0)
    if expect:
        kw = repo.insert_step.await_args.kwargs
        assert kw["step"] == "context" and kw["container"] is True and kw["seq"] == 0


@pytest.mark.asyncio
async def test_run_step_dispatches_context_before_family_runners(tmp_path: Path) -> None:
    sup = _sup(tmp_path)
    step = {"id": 1, "job_id": JOB, "step": "context", "seq": 0, "units": 1, "ram_mb": 1024}
    with patch.object(sup, "_get_job", new=AsyncMock(return_value={"job_id": JOB, "chain": "ton", "state": "ready"})), \
         patch.object(sup, "_run_context", new=AsyncMock()) as run_ctx, \
         patch.object(sup_mod.ton_pipeline, "run_step", new=AsyncMock()) as ton_run, \
         patch.object(sup, "_maybe_queue_context", new=AsyncMock()) as hook:
        await sup._run_step(step)
    run_ctx.assert_awaited_once()
    ton_run.assert_not_awaited()
    hook.assert_not_awaited()            # the context step itself never re-queues a round
