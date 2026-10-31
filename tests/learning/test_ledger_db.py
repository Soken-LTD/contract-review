"""Learning ledger (learning-loop design 2026-10-27, P0) against Postgres: written at finalize,
survives review_delete_job and the retention purge, replaces instead of double counting, backfill
is idempotent, a rejected submit leaves a friction row, and no identifying value is ever written.
Skipped without Docker (tests/conftest.py)."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest
from psycopg.rows import dict_row

from soken_review.learning import generate, ledger
from soken_review.learning.config import job_tags, tag

ASYNC = pytest.mark.asyncio(loop_scope="session")

_LEDGER_TABLES = ("lead_outcomes", "finding_outcomes", "judge_verdicts", "gate_events")
_TITLE = "Missing reentrancy guard on the withdraw function"
_SECRET_PIN = "pin-7f3a-secret-source"
_REPO = "https://github.com/acme-private/vault"
_ADDRESS = "0x1111111111111111111111111111111111111111"


async def _ready_job(db_pool, *, with_pin: bool = True) -> tuple[str, Path]:
    from soken_review.pinning.store import PinnedSource
    from tests.tools.test_submit_finalize import VAULT_SOL, _create_ready_job

    pin_root = Path(tempfile.mkdtemp()) / "pins"
    pin_root.mkdir(parents=True)
    jid = await _create_ready_job(db_pool)
    async with db_pool.connection() as conn:
        await conn.execute("update jobs set source_pin = %s, address = %s, source_args = %s::jsonb where job_id = %s",
                           (_SECRET_PIN, _ADDRESS, f'{{"repo_url": "{_REPO}"}}', jid))
    if with_pin:
        PinnedSource.from_files({"src/Vault.sol": VAULT_SOL.encode()}).persist(pin_root, jid)
    return jid, pin_root


async def _lead(db_pool, job_id: str, lead_id: str, rule: str, sev: str, state: str = "open",
                reason: str | None = None, lines: tuple[int, int] = (5, 8)) -> None:
    async with db_pool.connection() as conn:
        await conn.execute(
            """insert into leads (job_id, lead_id, rule_id, tools, category, category_family, analyzer_severity_raw,
                                  severity_norm, path, start_line, end_line, state, reason)
               values (%s, %s, %s, array['slither@0.11.6'], 'evm.reentrancy', 'evm', %s, %s,
                       'src/Vault.sol', %s, %s, %s, %s)""",
            (job_id, lead_id, rule, sev, sev, *lines, state, reason))


async def _rows(conn, table: str, tags: list[str]) -> list[dict]:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(f"select * from {table} where job_tag = any(%s) order by id", (tags,))
        return list(await cur.fetchall())


async def _submit_info_finding(db_pool, job_id: str, pin_root: Path, *, lead_ids: list[str]) -> dict:
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    submit_mod.set_pool(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    return await submit_mod.handle_review_submit_finding({
        "job_id": job_id, "draft_key": "draft-info", "category": "evm.reentrancy",
        "quotes": [{"file": "src/Vault.sol", "start": 1, "end": 3, "role": "location",
                    "text": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Vault {"}],
        "matrix": {"impact_class": "best_practice", "magnitude": "unbounded", "trigger": "anyone",
                   "precondition": "none", "reversibility": "irreversible"},
        "lead_ids": lead_ids, "title": _TITLE,
        "body": {"description": [{"p": "The contract does not use a reentrancy guard."}],
                 "impact": [{"p": "An attacker could exploit this to drain funds."}],
                 "recommendation": [{"p": "Add a reentrancy guard to the withdraw function."}]},
    })


def _all_text(row: dict) -> list[str]:
    out = []
    for v in row.values():
        if isinstance(v, list):
            out += [str(x) for x in v]
        elif v is not None:
            out.append(str(v))
    return out


async def _assert_anonymous(conn, job_id: str, principal: str) -> None:
    """No ledger table has a job_id column, and no row anywhere carries an identifying value."""
    async with conn.cursor() as cur:
        await cur.execute("select table_name, column_name from information_schema.columns where table_name = any(%s)",
                          (list(_LEDGER_TABLES),))
        cols = await cur.fetchall()
    assert cols and not [c for c in cols if c[1] in ("job_id", "principal_key", "address", "path", "source_pin")]
    forbidden = [job_id, job_id[4:], principal, _SECRET_PIN, _REPO, "acme-private", _ADDRESS, "src/Vault.sol",
                 "Vault.sol", _TITLE, "reentrancy guard", "draft-info"]
    for table in _LEDGER_TABLES:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(f"select * from {table}")
            for row in await cur.fetchall():
                for text in _all_text(row):
                    for bad in forbidden:
                        assert bad not in text, f"{table} carries {bad!r}"
                for k, v in row.items():
                    if k.endswith("_tag"):
                        assert re.fullmatch(r"[0-9a-f]{16}", v), (table, k, v)


@ASYNC
async def test_finalize_writes_the_ledger_and_it_survives_delete(db_pool):
    from soken_review.tools import delete as delete_mod
    from soken_review.tools import finalize as fin_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _ready_job(db_pool)
    await _lead(db_pool, job_id, "LEAD-0001", "reentrancy-eth", "Low")             # auto-closed at finalize
    await _lead(db_pool, job_id, "LEAD-0002", "incorrect-equality", "Medium", "dismissed", "not_a_vulnerability")
    await _lead(db_pool, job_id, "LEAD-0003", "calls-loop", "Low", lines=(1, 3))   # promoted below
    sub = await _submit_info_finding(db_pool, job_id, pin_root, lead_ids=["LEAD-0003"])
    assert sub["accepted"] is True, sub

    fin_mod.set_pool(db_pool)
    fin_mod.set_context(MemoryJobContext(pin_root))
    fin = await fin_mod.handle_review_finalize({"job_id": job_id})
    assert fin["accepted"] is True, fin
    tags = job_tags(job_id)
    async with db_pool.connection() as conn:
        principal = (await (await conn.execute("select principal_key from jobs where job_id = %s", (job_id,))).fetchone())[0]
        leads = {r["rule_id"]: r for r in await _rows(conn, "lead_outcomes", tags)}
        findings = await _rows(conn, "finding_outcomes", tags)
    assert {k: v["outcome"] for k, v in leads.items()} == {
        "reentrancy-eth": "auto_closed", "incorrect-equality": "dismissed", "calls-loop": "promoted"}
    assert leads["incorrect-equality"]["dismiss_reason"] == "not_a_vulnerability"
    assert leads["calls-loop"]["printed_severity"] == "Informational"
    assert {r["tool"] for r in leads.values()} == {"slither"} and leads["calls-loop"]["tool_version"] == "0.11.6"
    assert all(r["recorded_by"] == "finalize" and r["chain_family"] == "evm" for r in leads.values())
    assert all(r["consent_class"] == "public_code" and r["tier_shown"] == "normal" for r in leads.values())
    assert len(findings) == 1
    f = findings[0]
    assert (f["status"], f["severity_printed"], f["from_lead"], f["lead_rule"], f["lead_tool"]) == \
        ("accepted", "Informational", True, "calls-loop", "slither")
    assert f["severity_computed"] == "Informational" and f["category"] == "evm.reentrancy"

    delete_mod.set_pool(db_pool)
    delete_mod.set_context(MemoryJobContext(pin_root))
    out = await delete_mod.handle_review_delete_job({"job_id": job_id, "confirm": "delete"})
    assert out["state"] == "deleted"
    async with db_pool.connection() as conn:
        assert (await (await conn.execute("select count(*) from leads where job_id = %s", (job_id,))).fetchone())[0] == 0
        after = await _rows(conn, "lead_outcomes", tags)
        after_f = await _rows(conn, "finding_outcomes", tags)
        assert len(after) == 3 and len(after_f) == 1                           # replaced, not doubled
        assert {r["recorded_by"] for r in after} == {"purge"}
        assert {r["outcome"] for r in after} == {"auto_closed", "dismissed", "promoted"}
        await _assert_anonymous(conn, job_id, principal)
        await conn.execute("delete from job_steps where job_id = %s", (job_id,))


@ASYNC
async def test_retention_purge_records_a_job_that_never_finalized(db_pool):
    from soken_review.tools.delete import purge_job

    job_id, _ = await _ready_job(db_pool, with_pin=False)
    await _lead(db_pool, job_id, "LEAD-0001", "timestamp", "Low")
    async with db_pool.connection() as conn, conn.transaction():
        await purge_job(conn, job_id, reason="expiry", to_state="expired")
    async with db_pool.connection() as conn:
        rows = await _rows(conn, "lead_outcomes", job_tags(job_id))
    assert [(r["rule_id"], r["outcome"], r["job_state"], r["recorded_by"]) for r in rows] == \
        [("timestamp", "open", "ready", "purge")]


@ASYNC
async def test_backfill_is_idempotent_and_anonymous(db_pool):
    job_id, _ = await _ready_job(db_pool, with_pin=False)
    await _lead(db_pool, job_id, "LEAD-0001", "assembly", "Info", "not_reviewed")
    async with db_pool.connection() as conn:
        await conn.set_autocommit(True)
        first = await ledger.backfill(conn)
        second = await ledger.backfill(conn)
        rows = await _rows(conn, "lead_outcomes", job_tags(job_id))
        principal = (await (await conn.execute("select principal_key from jobs where job_id = %s", (job_id,))).fetchone())[0]
        await _assert_anonymous(conn, job_id, principal)
        await conn.set_autocommit(False)
    assert first["jobs"] >= 1 and second["jobs"] == 0 and second["skipped"] >= 1
    assert [(r["outcome"], r["recorded_by"]) for r in rows] == [("auto_closed", "backfill")]


@ASYNC
async def test_rejected_submit_writes_a_friction_row_with_code_only(db_pool):
    from soken_review.tools import submit as submit_mod
    from soken_review.tools.context import MemoryJobContext

    job_id, pin_root = await _ready_job(db_pool)
    submit_mod.set_pool(db_pool)
    submit_mod.set_context(MemoryJobContext(pin_root))
    async with db_pool.connection() as conn:
        principal = (await (await conn.execute("select principal_key from jobs where job_id = %s", (job_id,))).fetchone())[0]
    p_tag = tag("principal", principal)
    res = await submit_mod.handle_review_submit_finding({
        "job_id": job_id, "draft_key": "draft-bad", "category": "evm.reentrancy",
        "quotes": [{"file": "src/Vault.sol", "start": 1, "end": 2, "role": "location", "text": "this text is not in the file"}],
        "matrix": {"impact_class": "best_practice", "magnitude": "unbounded", "trigger": "anyone",
                   "precondition": "none", "reversibility": "irreversible"},
        "lead_ids": [], "title": _TITLE,
        "body": {"description": [{"p": "x y z."}], "impact": [{"p": "x y z."}], "recommendation": [{"p": "x y z."}]},
    })
    assert res["accepted"] is False
    async with db_pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from gate_events where principal_tag = %s", (p_tag,))
            rows = await cur.fetchall()
        assert rows and {r["error_code"] for r in rows} <= {e["code"] for e in res["errors"]} | {"UNCATALOGUED"}
        assert all(r["attempt"] == 1 and r["tool"] == "review_submit_finding" for r in rows)
        await _assert_anonymous(conn, job_id, principal)


@ASYNC
async def test_tier_shown_follows_the_job_policy_version_and_rule_stats_view(db_pool, tmp_path, monkeypatch):
    from soken_review.learning import tiers

    d = tmp_path / "rule_tiers"
    d.mkdir()
    (d / "baseline.yaml").write_text("version: baseline\nrules: []\n")
    (d / "t9.yaml").write_text("version: t9\nrules:\n- {tool: slither, rule: incorrect-equality, tier: demoted, severity_shift: -1}\n")
    monkeypatch.setattr(tiers, "TIERS_DIR", d)
    tiers.load_policy.cache_clear()
    monkeypatch.setitem(tiers.config()["exploration"], "rate", 0.0)
    try:
        job_id, _ = await _ready_job(db_pool, with_pin=False)
        await _lead(db_pool, job_id, "LEAD-0001", "incorrect-equality", "Medium", "dismissed", "not_a_vulnerability")
        async with db_pool.connection() as conn:
            await conn.execute("update jobs set learning_policy_version = 't9' where job_id = %s", (job_id,))
            await ledger.record_job(conn, job_id, "finalize")
            (row,) = await _rows(conn, "lead_outcomes", job_tags(job_id))
            assert (row["tier_shown"], row["severity_norm"], row["severity_shown"], row["policy_version"]) == \
                ("demoted", "Medium", "Low", "t9")
            stats = {(s["tool"], s["rule_id"]): s for s in await generate.rule_stats(conn)}
            s = stats[("slither", "incorrect-equality")]
            assert s["triaged"] >= 1 and s["dismissed"] >= 1 and s["targets"] >= 1
    finally:
        tiers.load_policy.cache_clear()


@ASYNC
async def test_recompute_writes_an_immutable_version_and_activate_rollback_set_the_flag(db_pool, tmp_path, monkeypatch):
    from soken_review.learning import tiers

    d = tmp_path / "rule_tiers"
    d.mkdir()
    (d / "baseline.yaml").write_text("version: baseline\nrules: []\n")
    monkeypatch.setattr(tiers, "TIERS_DIR", d)
    tiers.load_policy.cache_clear()
    try:
        async with db_pool.connection() as conn:
            await conn.set_autocommit(True)
            await conn.execute("delete from admin_audit where actor = 'ops-test'")
            out = await generate.recompute(conn, "t-gen-1", "baseline", tiers_dir=d, diff_path=tmp_path / "diff.md")
            assert Path(out["path"]).is_file() and (tmp_path / "diff.md").read_text().startswith("# Rule tiers t-gen-1")
            with pytest.raises(FileExistsError):
                await generate.recompute(conn, "t-gen-1", "baseline", tiers_dir=d)
            await generate.activate(conn, "t-gen-1", "ops-test")
            assert await tiers.active_version(conn) == "t-gen-1"
            await generate.rollback(conn, "ops-test")
            assert await tiers.active_version(conn) == "baseline"
            n = (await (await conn.execute("select count(*) from admin_audit where actor = 'ops-test'")).fetchone())[0]
            assert n == 2
            await conn.execute("delete from flags where key = 'learning.rule_tiers'")
            await conn.set_autocommit(False)
    finally:
        tiers.load_policy.cache_clear()


@ASYNC
async def test_judge_import_tags_the_target_and_feeds_protection(db_pool):
    async with db_pool.connection() as conn:
        await conn.set_autocommit(True)
        n = await generate.import_judge(conn, [{
            "round": "r4-test", "release": "v0", "target": "Apyee v2.0.0 0xabc", "chain_family": "evm", "arm": "mcp",
            "issue_id": "A1", "real": True, "judge_severity": "High", "lead_rules": ["soken-lifecycle:LC-EVM-EMPTY",
                                                                                  "slither:reentrancy-balance"],
            "source": "matrix-run-2026-10-26/JUDGEMENT.md#s5"}])
        assert n == 1
        prot = await generate.protected_from_outcomes(conn)
        assert ("slither", "reentrancy-balance") in prot
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from judge_verdicts where round = 'r4-test'")
            row = await cur.fetchone()
        assert "Apyee" not in " ".join(_all_text(row)) and "0xabc" not in " ".join(_all_text(row))
        await conn.execute("delete from judge_verdicts where round = 'r4-test'")
        await conn.set_autocommit(False)


@ASYNC
async def test_advisory_warnings_are_copied_as_friction_without_text_and_survive_purge(db_pool):
    import json as _json

    from soken_review.tools.delete import purge_job

    job_id, _ = await _ready_job(db_pool, with_pin=False)
    warn = [{"code": "E_TEXT_GATE", "class": "advisory", "rule": "T13", "field": "body.description",
             "what": f"{_TITLE} uses a major claim", "suggest": "reword", "match": "reentrancy guard"}]
    async with db_pool.connection() as conn:
        principal = (await (await conn.execute("select principal_key from jobs where job_id = %s", (job_id,))).fetchone())[0]
        await conn.execute("insert into gate_warnings (job_id, tool, owner_key, revision, warnings)"
                           " values (%s, 'review_submit_finding', 'draft-info', 0, %s::jsonb)", (job_id, _json.dumps(warn)))
        await ledger.record_job(conn, job_id, "finalize")
        await ledger.record_job(conn, job_id, "finalize")                     # replaced, not doubled
    async with db_pool.connection() as conn, conn.transaction():
        await purge_job(conn, job_id, reason="expiry", to_state="expired")
    async with db_pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("select * from gate_events where job_tag = any(%s)", (job_tags(job_id),))
            rows = await cur.fetchall()
        assert [(r["kind"], r["error_code"], r["rule_id"], r["warning_class"], r["field"]) for r in rows] == \
            [("warning", "E_TEXT_GATE", "T13", "advisory", "body.description")]
        assert (await (await conn.execute("select count(*) from gate_warnings where job_id = %s", (job_id,))).fetchone())[0] == 0
        await _assert_anonymous(conn, job_id, principal)
