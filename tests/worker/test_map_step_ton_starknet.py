"""The `map` step for the TON and Starknet pipelines (03 3.1; 04 2.1, 12).

Until now only EVM and Move jobs produced `map/`, `flags.json` (J1 to J5) and the static facts.
TON queued a map step after analyze and then dropped it ("no handler"), so the job never reached
`ready`; Starknet went straight to `ready` from analyze with no lexical map and no flags. Both now
run `run_map_step` with their own family and chain, and only the map step moves the job to `ready`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from soken_review.pinning.store import PinnedSource
from soken_review.worker import starknet_steps, ton_pipeline

RLO = chr(0x202E)                       # bidi override: a J2 flag (injection_patterns.yaml)


class _FakeRepo:
    """Records JobRepo calls; one instance is shared through the fake pool."""

    def __init__(self) -> None:
        self.transitions: list[tuple[str, str]] = []
        self.fields: dict[str, Any] = {}
        self.completed: list[dict[str, Any]] = []
        self.inserted: list[dict[str, Any]] = []

    async def transition(self, job_id: str, state: str, error_code=None, error_detail=None) -> None:
        self.transitions.append((job_id, state))

    async def update_job_fields(self, job_id: str, **fields: Any) -> None:
        self.fields.update(fields)

    async def complete_step(self, step_id: int, status: str, error_code=None, provenance=None) -> None:
        self.completed.append({"id": step_id, "status": status, "error_code": error_code, "provenance": provenance})

    async def insert_step(self, **row: Any) -> dict[str, Any]:
        self.inserted.append(row)
        return row


def _fake_sup(tmp_path: Path, repo: _FakeRepo, monkeypatch, module) -> MagicMock:
    conn = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    txn = AsyncMock()
    txn.__aenter__ = AsyncMock(return_value=txn)
    txn.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=txn)
    pool = MagicMock()
    pool.connection = MagicMock(return_value=conn)
    monkeypatch.setattr(module, "JobRepo", lambda _conn: repo)
    sup = MagicMock()
    sup._pool = pool
    sup._pin_root = tmp_path / "pins"
    sup._job_dir = lambda job_id: tmp_path / "work" / job_id
    sup._mark_step = AsyncMock()
    return sup


def _pin(sup, job_id: str, files: dict[str, str], lang: str) -> None:
    pin = PinnedSource.from_files({p: t.encode("utf-8") for p, t in files.items()}, langs={p: lang for p in files})
    pin.persist(sup._pin_root, job_id)


def _write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


# --------------------------------------------------------------------------------------------- TON

FUNC_SRC = "() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {\n" \
           "    ;; owner check " + RLO + "disabled\n    return ();\n}\n"


@pytest.mark.asyncio
async def test_ton_map_step_writes_map_flags_facts_and_moves_to_ready(tmp_path, monkeypatch):
    repo = _FakeRepo()
    sup = _fake_sup(tmp_path, repo, monkeypatch, ton_pipeline)
    job = {"job_id": "job_TON1", "chain": "ton", "address": "0:" + "ab" * 32}
    out = sup._job_dir("job_TON1")
    _pin(sup, "job_TON1", {"contracts/wallet.fc": FUNC_SRC}, "func")
    _write(out / "build_result.json", {"status": "ok", "nsloc": 3, "reason": None, "stderr_head": None,
                                       "work_dir": "/x", "src": 1})
    _write(out / "candidates.json", [{"provider": "ton_verifier", "sha256": "00" * 32},
                                     {"provider": "ton_verifier", "sha256": "11" * 32, "language": "func"}])
    _write(out / "chain_state.json", {"mc_seqno": 42, "accounts": {job["address"]: {"code_hash": "cc" * 32}}})
    step = {"id": 7, "job_id": "job_TON1", "step": "map", "seq": 0}

    await ton_pipeline.run_step(sup, step, job)

    flags = json.loads((sup._pin_root / "job_TON1" / "flags.json").read_text())
    assert [f["rule"] for f in flags] == ["J2"] and flags[0]["file"] == "contracts/wallet.fc"
    status = json.loads((sup._pin_root / "job_TON1" / "map" / "status.json").read_text())
    assert status["map_status"] in ("partial", "full")           # lexical layer present, no solc layer
    assert (sup._pin_root / "job_TON1" / "facts.json").exists()
    assert repo.fields["map_status"] == status["map_status"]
    assert repo.completed[-1]["status"] == "done"
    prov = repo.completed[-1]["provenance"]
    assert prov["files"] == 1 and prov["flags"]["J2"] == 1
    assert repo.transitions == [("job_TON1", "ready")]
    sup._mark_step.assert_not_called()                            # no silent "no handler" path


@pytest.mark.asyncio
async def test_ton_map_step_after_failed_build_still_flags_and_readies(tmp_path, monkeypatch):
    repo = _FakeRepo()
    sup = _fake_sup(tmp_path, repo, monkeypatch, ton_pipeline)
    job = {"job_id": "job_TON2", "chain": "ton"}
    out = sup._job_dir("job_TON2")
    _pin(sup, "job_TON2", {"a.tact": "contract A {\n  // " + RLO + "\n}\n"}, "tact")
    _write(out / "build_result.json", {"status": "failed", "nsloc": 0, "reason": "compile_failed",
                                       "stderr_head": "boom", "work_dir": None, "src": 0})
    _write(out / "candidates.json", [{"provider": "ton_verifier", "sha256": "22" * 32}])

    await ton_pipeline.run_step(sup, {"id": 8, "job_id": "job_TON2", "step": "map", "seq": 0}, job)

    assert json.loads((sup._pin_root / "job_TON2" / "flags.json").read_text())
    assert json.loads((sup._pin_root / "job_TON2" / "map" / "status.json").read_text())["map_status"] == "failed"
    assert json.loads((sup._pin_root / "job_TON2" / "map" / "status.json").read_text())["build_detail"] == "boom"
    assert repo.transitions == [("job_TON2", "ready")]


@pytest.mark.asyncio
async def test_ton_map_is_parsed_when_the_exact_compiler_is_missing(tmp_path, monkeypatch):
    """Matrix run 2026-10-25 (Forton): Tact 1.6.5 not in the image, map lexical with 0 spans,
    source.nsloc 0, no analyzer facts. The parsed map has handlers and a semantic layer."""
    repo = _FakeRepo()
    sup = _fake_sup(tmp_path, repo, monkeypatch, ton_pipeline)
    job = {"job_id": "job_TON4", "chain": "ton"}
    out = sup._job_dir("job_TON4")
    src = ("contract A {\n    owner: Address;\n    receive(msg: Set) {\n        self.owner = msg.owner;\n"
           "    }\n}\n")
    _pin(sup, "job_TON4", {"a.tact": src}, "tact")
    _write(out / "build_result.json", {"status": "failed", "nsloc": 5, "reason": "unsupported_toolchain",
                                       "stderr_head": "tact 1.6.5 is not in the image", "work_dir": None, "src": 0})
    _write(out / "candidates.json", [{"provider": "ton_verifier", "sha256": "44" * 32}])
    _write(out / "static_map.json", {"status": "ok", "analyzer": "misti@0.9.0",
                                      "rule_pack": "soken-ton-rules@0.1.0", "build": "failed"})

    await ton_pipeline.run_step(sup, {"id": 10, "job_id": "job_TON4", "step": "map", "seq": 0}, job)

    status = json.loads((sup._pin_root / "job_TON4" / "map" / "status.json").read_text())
    assert status["map_status"] == "partial"
    doc = json.loads((sup._pin_root / "job_TON4" / "map" / "map.json").read_text())
    assert [s["id"] for s in doc["spans"]] == ["A.receive(Set)"]
    assert doc["semantic"]["functions"][0]["writes"] == [{"var": "owner", "line": "a.tact:4"}]
    facts = {f["key"]: f["value"] for f in json.loads((sup._pin_root / "job_TON4" / "facts.json").read_text())}
    assert facts["source.nsloc"] == "5"
    assert facts["analyzer.soken_ton_rules"] == "0.1.0" and facts["analyzer.misti"] == "0.9.0"
    assert repo.transitions == [("job_TON4", "ready")]


@pytest.mark.asyncio
async def test_ton_unknown_step_is_still_marked_done(tmp_path, monkeypatch):
    repo = _FakeRepo()
    sup = _fake_sup(tmp_path, repo, monkeypatch, ton_pipeline)
    await ton_pipeline.run_step(sup, {"id": 9, "job_id": "job_TON3", "step": "render", "seq": 0}, {"chain": "ton"})
    sup._mark_step.assert_awaited_once_with(9, "done")
    assert repo.transitions == []


# ---------------------------------------------------------------------------------------- Starknet

CAIRO_SRC = "#[starknet::contract]\nmod Vault {\n    // " + RLO + "admin only\n    fn withdraw() {}\n}\n"


def _starknet_job_dir(sup, job_id: str, *, build_status: str = "ok") -> Path:
    out = sup._job_dir(job_id)
    _pin(sup, job_id, {"src/vault.cairo": CAIRO_SRC}, "cairo")
    _write(out / "candidates.json", [{"provider": "repo", "sha256": "33" * 32, "language": "cairo",
                                      "compiler": {"version": "2.8.0", "version_pinned_by": "scarb"}, "settings": {}}])
    _write(out / "build_result.json", {"status": build_status, "nsloc": 4, "reason": None if build_status == "ok" else "x"})
    _write(out / "chain_state.json", {"address": "0x1", "block": 5, "class_hash": "0x2"})
    return out


@pytest.mark.asyncio
async def test_starknet_map_step_writes_flags_and_moves_to_ready_keeping_analyze_map_status(tmp_path, monkeypatch):
    repo = _FakeRepo()
    sup = _fake_sup(tmp_path, repo, monkeypatch, starknet_steps)
    job = {"job_id": "job_SN1", "chain": "starknet", "address": "0x1"}
    _starknet_job_dir(sup, "job_SN1")

    await starknet_steps.run_step(sup, {"id": 11, "job_id": "job_SN1", "step": "map", "seq": 0}, job)

    flags = json.loads((sup._pin_root / "job_SN1" / "flags.json").read_text())
    assert [f["rule"] for f in flags] == ["J2"] and flags[0]["file"] == "src/vault.cairo"
    assert (sup._pin_root / "job_SN1" / "map" / "status.json").exists()
    assert (sup._pin_root / "job_SN1" / "facts.json").exists()
    # The analyze step already set map_status from the Sierra/chain facts (07); the lexical layer
    # must not overwrite it.
    assert "map_status" not in repo.fields
    assert repo.completed[-1]["status"] == "done" and repo.completed[-1]["provenance"]["flags"]["J2"] == 1
    assert repo.transitions == [("job_SN1", "ready")]


@pytest.mark.asyncio
async def test_starknet_analyze_queues_map_instead_of_ready(tmp_path, monkeypatch):
    """analyze -> map -> ready, as for EVM and Move (03 3.1: map runs in `analyzing`)."""
    repo = _FakeRepo()
    sup = _fake_sup(tmp_path, repo, monkeypatch, starknet_steps)
    job = {"job_id": "job_SN2", "chain": "starknet", "address": "0x1"}
    out = _starknet_job_dir(sup, "job_SN2")
    _write(out / "provenance.json", {"tier": "B", "match": None, "reason": "no_class"})
    import soken_review.adapters.starknet.analyze as an
    import soken_review.adapters.starknet.map as mp
    monkeypatch.setattr(an, "analyze",
                        lambda br, facts, cairo, run_stock_lint, with_caracal: ([], {"status": "ok"}, {}))
    monkeypatch.setattr(mp, "chain_extras", lambda cs, facts, sm, prov: {"facts": "complete"})

    await starknet_steps.run_step(sup, {"id": 12, "job_id": "job_SN2", "step": "analyze", "seq": 0}, job)

    assert repo.fields["map_status"] == "full"
    assert repo.transitions == []                                  # not ready yet
    assert [r["step"] for r in repo.inserted] == ["map"]
    assert repo.inserted[0]["container"] is False and repo.inserted[0]["max_attempts"] == 2
    assert (sup._pin_root / "job_SN2" / "leads.json").exists()
    assert not (sup._pin_root / "job_SN2" / "flags.json").exists()  # the map step does that


@pytest.mark.asyncio
async def test_supervisor_routes_starknet_map_to_starknet_steps(monkeypatch):
    from soken_review.worker import supervisor as sup_mod
    seen: list[str] = []

    async def fake_run_step(sup, step, job):
        seen.append(step["step"])
    monkeypatch.setattr(starknet_steps, "run_step", fake_run_step)
    sup = sup_mod.Supervisor.__new__(sup_mod.Supervisor)
    sup._free_units = 7
    sup._free_ram_mb = 1024
    sup._running = {}
    sup._get_job = AsyncMock(return_value={"job_id": "job_SN3", "chain": "starknet"})
    sup._run_map = AsyncMock()
    sup._mark_step = AsyncMock()
    sup._release = MagicMock()
    step = {"id": 13, "job_id": "job_SN3", "step": "map", "seq": 0, "units": 0, "ram_mb": 0, "max_attempts": 2,
            "attempt": 1, "lease_owner": None}
    await sup._run_step(step)
    assert seen == ["map"]
    sup._run_map.assert_not_called()                              # the EVM map (solc output) is not for Cairo
