"""Handlers for review_chain_read, review_chain_roles and review_chain_balances (chain access
design 2026-10-27, P1; CEO 2026-10-28: free sources only).

Additive and advisory: no step depends on these tools, a failure is a rejection or a per-item
error, and nothing here changes the job state, the findings or the report quota (CEO never-worse
rule). Chain and network come from the job; `chain_id` is accepted only for an EVM job without a
deployment. Every successful read becomes a fact (`chain.<alias>.*`, with block and source) in
the job's chain_facts.json, citable as {{fact:...}} in findings.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any

from ..chain import facts as chain_facts
from ..chain import reads
from ..chain.endpoints import capability
from ..chain.proxy import ChainProxy, ChainUnavailable, Meter, RpcFailure
from ..chain.store import Budget, Cache, limits
from ..chain.untrusted import CHAIN_TEXT, GUIDE_NOTE
from ..db.pool import get_pool
from ..errors import ReviewError
from ..server import handler
from .context import JobContext

logger = logging.getLogger(__name__)

_pool: Any | None = None
_ctx: JobContext | None = None
WALL_S = 60.0
_OPEN_STATES = frozenset({"ready"})
# The automatic snapshot of the deployment runs from job start (thin server, 2026-10-31): live state does not
# depend on the source, only on the pin directory that holds the facts.
_AUTO_STATES = frozenset({"queued", "fetching", "building", "analyzing", "ready"})
_FROZEN = frozenset({"finalized", "render_queued", "rendering", "rendered", "render_failed"})
_EVM_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TRON_ADDR = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
_SOL_ADDR = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_NETWORK = {"tron": "TRON Mainnet", "solana": "Solana mainnet", "ton": "TON mainnet"}


def set_pool(pool: Any) -> None:
    global _pool
    _pool = pool


def set_context(ctx: JobContext) -> None:
    global _ctx
    _ctx = ctx


def _get_pool() -> Any | None:
    if _pool is not None:
        return _pool
    try:
        return get_pool()
    except Exception:  # noqa: BLE001  # unit tests run without a pool
        return None


def _pin_root() -> Path:
    if _ctx is None:
        raise ReviewError("E_INTERNAL", incident="chain tools not wired (ctx is None)")
    return _ctx.get_pin_root()


# ── job ────────────────────────────────────────────────────────────────────


async def _job_row(job_id: str, open_states: frozenset[str] = _OPEN_STATES) -> dict[str, Any]:
    pool = _get_pool()
    if pool is None:
        raise ReviewError("E_INTERNAL", incident="chain tools without a database")
    from ..db.job_repo import JobRepo

    async with pool.connection() as conn:
        job = await JobRepo(conn).get(job_id)
    if job is None or job["state"] == "deleted":
        raise ReviewError("E_JOB_NOT_FOUND")
    state = job["state"]
    if state == "expired":
        raise ReviewError("E_JOB_EXPIRED", job=job_id, date=str(job.get("expires_at") or ""))
    if state in _FROZEN:
        raise _Reject(ReviewError("E_JOB_FROZEN"))
    if state not in open_states:
        raise _Reject(ReviewError("E_JOB_NOT_READY", state=state, eta_s=0))
    return job


class _Reject(Exception):
    def __init__(self, err: ReviewError) -> None:
        super().__init__(err.code)
        self.err = err


def _pinned_block(root: Path, job_id: str) -> int | None:
    p = root.parent / "work" / job_id / "chain_state.json"
    try:
        cs = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for k in ("block", "mc_seqno", "slot"):
        v = cs.get(k) if isinstance(cs, dict) else None
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    return None


def _unit_functions(root: Path, job_id: str) -> frozenset[str]:
    try:
        from ..mapping.build import load_map
        from ..mapping.facts import _unit_function_names

        doc, _status = load_map(root, job_id)
        return frozenset(n for n in _unit_function_names(doc, None) if n)
    except Exception:  # noqa: BLE001  # the map only adds role getters; no map is no extra getters
        return frozenset()


def chain_job(job: dict[str, Any], root: Path, chain_id_arg: int | None) -> reads.ChainJob:
    chain = (job.get("chain") or "").lower()
    cid = job.get("chain_id")
    if not chain and chain_id_arg:
        chain, cid = "evm", chain_id_arg
    if chain in ("evm", "hyperevm"):
        cid = int(cid or chain_id_arg or 0)
        from ..adapters.evm.registry import get_chain

        rec = get_chain(cid) if cid else None
        if rec is None:
            raise _Reject(ReviewError("E_CHAIN_UNSUPPORTED", what=f"EVM chain id {cid or 'none'}",
                                      fix_hint="Name a released EVM chain id (for example 1 or 56) in chain_id."))
        family, network = "evm", rec.name
    elif chain in ("tron", "solana", "ton"):
        family, network, cid = chain, _NETWORK[chain], (728126428 if chain == "tron" else cid)
        args = job.get("source_args") or {}
        net = str(((args.get("deployment") or {}) if isinstance(args, dict) else {}).get("network") or "").lower()
        if net and net not in ("mainnet", "mainnet-beta"):
            raise _Reject(ReviewError("E_CHAIN_UNSUPPORTED", what=f"{chain} {net}",
                                      fix_hint="Chain reads run on mainnet only."))
    elif not chain:
        raise _Reject(ReviewError("E_CHAIN_UNSUPPORTED", what="a job without a chain",
                                  fix_hint="Pass chain_id (an EVM chain id) to read a live dependency of this repository."))
    else:
        raise _Reject(ReviewError("E_CHAIN_UNSUPPORTED", what=chain,
                                  fix_hint="Chain reads cover EVM chains, TRON, Solana and TON today."))
    return reads.ChainJob(job_id=job["job_id"], family=family, chain_id=cid, network=network,
                          pinned_block=_pinned_block(root, job["job_id"]), address=job.get("address"),
                          unit_functions=_unit_functions(root, job["job_id"]))


def check_address(family: str, addr: str, field: str) -> str:
    ok = {"evm": _EVM_ADDR, "tron": _TRON_ADDR, "solana": _SOL_ADDR}.get(family)
    if ok is not None and not ok.match(addr):
        raise ReviewError("E_INVALID_ARGUMENT", field=field, rule=f"{family} address", value80=addr[:80],
                          example={"evm": "0x and 40 hex digits", "tron": "T and 33 base58 characters",
                                   "solana": "a base58 public key"}[family])
    if family == "ton":
        from ..chain.ton_codec import parse_address

        try:
            parse_address(addr)
        except ValueError:
            raise ReviewError("E_INVALID_ARGUMENT", field=field, rule="ton address", value80=addr[:80],
                              example="0:<64 hex> or a 48-character user-friendly address") from None
    return addr


def check_alias(alias: str, field: str) -> str:
    if not chain_facts.ALIAS_RE.match(alias) or alias in chain_facts.RESERVED_ALIASES:
        raise ReviewError("E_INVALID_ARGUMENT", field=field, rule="alias [a-z][a-z0-9_]{0,23}, not block, chain_id or target",
                          value80=alias[:80], example="ve")
    return alias


# ── shared call frame ──────────────────────────────────────────────────────


async def _run(args: dict[str, Any], ru: int, body: Any, actual_ru: Any = None,
               open_states: frozenset[str] = _OPEN_STATES) -> dict[str, Any]:
    """Job checks, budget, proxy, block resolution, `body(px, out)`, facts and the result envelope."""
    job_id = args["job_id"]
    try:
        job = await _job_row(job_id, open_states)
        root = _pin_root()
        cj = chain_job(job, root, args.get("chain_id"))
    except _Reject as rj:
        return {"accepted": False, "errors": [rj.err.envelope()]}
    from .. import quota

    pool = _get_pool()
    budget = Budget(pool, job_id, job.get("limit_key") or quota.limit_key(target=quota.job_target(job), job_id=job_id))
    try:
        await budget.reserve(ru)
    except ReviewError as exc:
        return {"accepted": False, "errors": [exc.envelope()]}
    cache = Cache(pool, job_id)
    meter = Meter(max_calls=int(limits().get("upstream_calls_per_call", 400)))
    cap = capability(cj.family, cj.chain_id)
    try:
        async with ChainProxy(meter=meter, cache_get=cache.get, cache_put=cache.put) as px:
            at = await asyncio.wait_for(reads.RESOLVERS[cj.family](px, cj, args.get("block")), timeout=WALL_S / 3)
            out = reads.Out(job=cj, at=at)
            extra = await asyncio.wait_for(body(px, out), timeout=WALL_S)
            out.host = ", ".join(sorted(meter.answered_by))[:120]
    except reads.InputError as exc:
        await budget.refund(ru)
        raise ReviewError("E_INVALID_ARGUMENT", field=exc.field, rule=exc.rule, value80=exc.value, example=exc.example) from None
    except (ChainUnavailable, RpcFailure, TimeoutError) as exc:
        await budget.refund(ru)
        reason = getattr(exc, "reason", "timeout" if isinstance(exc, TimeoutError) else "upstream")
        hosts = ", ".join(getattr(exc, "hosts", []) or cap.sources)[:200]
        return {"accepted": False, "capability": cap.as_dict(),
                "errors": [ReviewError("E_CHAIN_UNAVAILABLE", reason=reason, hosts=hosts,
                                       retry_after_s=30 if reason == "rate_limited" else 10).envelope()]}
    if actual_ru is not None:   # the reserve assumed an archive read; charge what the block really cost
        await budget.refund(max(0, ru - int(actual_ru(out.at, cj))))
    failed = [it for it in out.items if not it.get("ok") and (it.get("error") or {}).get("reason") in reads.REFUNDABLE]
    if failed and budget.reserved:
        await budget.refund(min(budget.reserved, _item_ru(len(failed), out.at, cj)))
    # the facts carry the redacted hosts that answered
    via = out.host
    for f in out.facts:
        if via and " via " not in f["source"]:
            f["source"] = f"{f['source']} via {via}"[:200]
    if out.facts:
        try:
            chain_facts.write_chain_facts(root, job_id, out.facts)
        except OSError as exc:
            logger.warning("chain facts write failed for %s: %s", job_id[-8:], type(exc).__name__)
            return {"accepted": False, "errors": [ReviewError("E_INTERNAL", incident=f"chain-facts-{job_id[-8:]}").envelope()]}
    items = sorted(out.items, key=lambda r: r.pop("_i", 0))
    keys = [f["key"] for f in out.facts]
    res: dict[str, Any] = {
        "accepted": True, "job_id": job_id, "family": cj.family, "network": cj.network,
        "block": {"requested": args.get("block") or "latest", "resolved": out.at.block, "block_time": out.at.block_time,
                  "head": out.at.head, **({"note": out.at.note} if out.at.note else {})},
        "capability": cap.as_dict(), "items": items, "fact_keys": keys[:600],
        "budget": budget.as_dict(), "answered_by": sorted(meter.answered_by)[:6],
        "untrusted_text_note": GUIDE_NOTE,
        "cite": ("Cite a value as {{fact:<key>}}; the report prints it with its block. A fact of class chain_text "
                 "prints as a quoted literal."),
    }
    if extra:
        res.update(extra)
    return res


def _item_ru(n: int, at: reads.At, cj: reads.ChainJob) -> int:
    return n * (2 if (cj.family == "evm" and at.archive) else 1)


# ── handlers ───────────────────────────────────────────────────────────────


@handler("review_chain_read")
async def handle_chain_read(args: dict[str, Any]) -> dict[str, Any]:
    try:
        job = await _job_row(args["job_id"])
        family = chain_job(job, _pin_root(), args.get("chain_id")).family
    except _Reject as rj:
        return {"accepted": False, "errors": [rj.err.envelope()]}
    items = list(args["items"])[: int(limits().get("max_items", 50))]
    seen: set[str] = set()
    for i, it in enumerate(items):
        check_alias(it["alias"], f"items[{i}].alias")
        check_address(family, it["address"], f"items[{i}].address")
        sig = f"{it['alias']}.{it.get('field') or it.get('fn') or it.get('method') or it.get('slot') or it['kind']}"
        if it["kind"] in ("call", "storage", "get_method") and sig in seen:
            raise ReviewError("E_INVALID_ARGUMENT", field=f"items[{i}].field", rule="one fact key per item",
                              value80=sig[:80], example="set field to tell two reads of one getter apart")
        seen.add(sig)
    archive_hint = 2 if family == "evm" and args.get("block") not in (None, "latest") else 1

    async def body(px: ChainProxy, out: reads.Out) -> dict[str, Any] | None:
        await reads.READERS[out.job.family](px, out, items)
        return None

    return await _run(args, len(items) * archive_hint, body,
                      actual_ru=lambda at, cj: _item_ru(len(items), at, cj))


@handler("review_chain_roles")
async def handle_chain_roles(args: dict[str, Any]) -> dict[str, Any]:
    try:
        job = await _job_row(args["job_id"])
        family = chain_job(job, _pin_root(), args.get("chain_id")).family
    except _Reject as rj:
        return {"accepted": False, "errors": [rj.err.envelope()]}
    address = check_address(family, args["address"], "address")
    alias = check_alias(args["alias"], "alias")
    extra = [g for g in (args.get("getters") or []) if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", g)][:10]

    async def body(px: ChainProxy, out: reads.Out) -> dict[str, Any]:
        if family == "evm":
            roles = await reads.evm_roles(px, out, address, alias, extra)
        elif family == "tron":
            roles = await reads.tron_roles(px, out, address, alias, extra)
        elif family == "solana":
            roles = await reads.solana_roles(px, out, address, alias)
        else:
            roles = await reads.ton_roles(px, out, address, alias, extra)
        return {"roles": roles}

    return await _run(args, 30, body)


@handler("review_chain_balances")
async def handle_chain_balances(args: dict[str, Any]) -> dict[str, Any]:
    try:
        job = await _job_row(args["job_id"])
        family = chain_job(job, _pin_root(), args.get("chain_id")).family
    except _Reject as rj:
        return {"accepted": False, "errors": [rj.err.envelope()]}
    token = args["token"]
    if token != "native":
        check_address(family, token, "token")
    talias = check_alias(args.get("token_alias") or ("native" if token == "native" else "token"), "token_alias")
    holders = list(args["holders"])[: int(limits().get("max_holders", 100))]
    for i, h in enumerate(holders):
        check_alias(h["alias"], f"holders[{i}].alias")
        check_address(family, h["address"], f"holders[{i}].address")

    async def body(px: ChainProxy, out: reads.Out) -> dict[str, Any]:
        info = await reads.BALANCES[family](px, out, token, talias, holders)
        return {"token": info}

    return await _run(args, max(1, (len(holders) + 9) // 10), body)


# ── automatic snapshot (stale clients) ─────────────────────────────────────

AUTO_ALIAS = "target"
AUTO_FILE = "chain_auto.json"
AUTO_RETRY_S = 600
AUTO_WAIT_S = 25.0
# review_start launches the snapshot before the source is pinned: the facts file lives in the job's pin
# directory, which the fetch step creates, so the read waits for it (polling) up to AUTO_PIN_WAIT_S.
AUTO_PIN_WAIT_S = 180.0
AUTO_PIN_POLL_S = 2.0
# chain_state on review_status: at most this many chain.target.* values, each value cut to 80 characters.
STATE_MAX_VALUES = 24
_auto_tasks: dict[str, asyncio.Task[Any]] = {}


def _auto_marker(job_id: str) -> Path:
    return _pin_root() / job_id / AUTO_FILE


def _auto_due(job_id: str) -> bool:
    try:
        rec = json.loads(_auto_marker(job_id).read_text())
    except (OSError, ValueError):
        return True
    if rec.get("ok"):
        return False
    import time

    return time.time() - float(rec.get("at") or 0) > AUTO_RETRY_S


def _auto_mark(job_id: str, ok: bool, detail: str = "") -> None:
    import time

    p = _auto_marker(job_id)
    if not p.parent.is_dir():   # never create a job directory: only a pinned job has one
        return
    try:
        p.write_text(json.dumps({"at": time.time(), "ok": ok, "detail": detail[:200]}))
    except OSError:
        pass


async def _await_pin_dir(job_id: str) -> None:
    """Wait for the job's pin directory (created by the fetch step); E_JOB_NOT_READY after the wait,
    which leaves the snapshot unmarked so review_status retries it."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + AUTO_PIN_WAIT_S
    while not (_pin_root() / job_id).is_dir():
        if loop.time() >= deadline:
            raise ReviewError("E_JOB_NOT_READY", state="pin_not_found", eta_s=60)
        await asyncio.sleep(AUTO_PIN_POLL_S)


async def _auto_body(job_id: str) -> None:
    job = await _job_row(job_id, _AUTO_STATES)
    address = str(job.get("address") or "")
    family = chain_job(job, _pin_root(), None).family
    if not address:
        _auto_mark(job_id, True, "no deployment")
        return
    await _await_pin_dir(job_id)
    check_address(family, address, "address")

    async def body(px: ChainProxy, out: reads.Out) -> dict[str, Any]:
        if family == "evm":
            await reads.evm_roles(px, out, address, AUTO_ALIAS, [])
        elif family == "tron":
            await reads.tron_roles(px, out, address, AUTO_ALIAS, [])
        elif family == "solana":
            await reads.solana_roles(px, out, address, AUTO_ALIAS)
        else:
            await reads.ton_roles(px, out, address, AUTO_ALIAS, [])
        if family in ("evm", "tron"):
            await reads.READERS[family](px, out, [{"alias": AUTO_ALIAS, "kind": "call", "address": address,
                                                   "fn": "paused()", "returns": "bool"}])
        await reads.BALANCES[family](px, out, "native", "native", [{"alias": AUTO_ALIAS, "address": address}])
        return {}

    res = await _run({"job_id": job_id}, 32, body, open_states=_AUTO_STATES)
    _auto_mark(job_id, bool(res.get("accepted")),
               "" if res.get("accepted") else str((res.get("errors") or [{}])[0].get("code") or ""))


def chain_state(job: dict[str, Any]) -> dict[str, Any] | None:
    """`chain_state` of review_status: the deployment's chain.target.* facts, compact (thin server,
    2026-10-31). None for a job without a deployment address; never raises."""
    if not job.get("address"):
        return None
    job_id = str(job.get("job_id") or "")
    try:
        root = _pin_root()
        rows = [f for f in chain_facts.load_chain_facts(root, job_id)
                if str(f.get("key", "")).startswith(f"chain.{AUTO_ALIAS}.")]
        rec = json.loads(_auto_marker(job_id).read_text()) if _auto_marker(job_id).exists() else None
    except (ReviewError, OSError, ValueError):
        return {"state": "pending"}
    if rows:
        values: dict[str, Any] = {}
        has_text = False
        for f in rows[:STATE_MAX_VALUES]:
            name = str(f["key"])[len(f"chain.{AUTO_ALIAS}."):]
            raw = f.get("value")
            if f.get("class") == CHAIN_TEXT:
                # chain-derived text (a token name, a revert string) keeps its untrusted marker; it was
                # cleaned by untrusted_text when read and is only re-capped here
                has_text = True
                values[name] = {"untrusted_text": {"value": str(raw)[:80] if raw is not None else "",
                                                   "class": CHAIN_TEXT,
                                                   "origin": str(f.get("method") or f.get("key"))[:160]}}
            else:
                values[name] = str(raw)[:80] if raw is not None else None
        blocks = [b for f in rows if isinstance(b := f.get("block"), int) and not isinstance(b, bool)]
        out: dict[str, Any] = {"state": "done", "block": max(blocks) if blocks else None, "values": values,
                               "note": f"cite as {{{{fact:chain.{AUTO_ALIAS}.<field>}}}}"}
        if len(rows) > STATE_MAX_VALUES:
            out["note"] += f"; {len(rows) - STATE_MAX_VALUES} more in review_facts"
        if has_text:
            out["untrusted_text_note"] = GUIDE_NOTE
        return out
    if rec and not rec.get("ok"):
        return {"state": "failed", "note": f"read failed ({str(rec.get('detail') or 'upstream')[:60]}); retried later"}
    if rec and rec.get("ok"):
        return {"state": "none", "note": str(rec.get("detail") or "no values")[:120]}
    return {"state": "pending"}


async def auto_snapshot(job_id: str, wait: bool) -> None:
    """Read the deployment's owner and admin holders, proxy slots, roles, paused flag and native balance
    once per job, as `chain.target.*` facts, so review_facts carries them for a client whose tool list
    predates review_chain_read and friends (blind round 5: no MCP arm could call them). Advisory like the
    tools: budget-metered, never fails the caller, retried after AUTO_RETRY_S when the chain was down.
    `wait` blocks up to AUTO_WAIT_S (review_facts); otherwise it only starts the read (review_status)."""
    try:
        if not _auto_due(job_id):
            return
    except ReviewError:
        return
    task = _auto_tasks.get(job_id)
    if task is None or task.done():
        async def run() -> None:
            try:
                await _auto_body(job_id)
            except (_Reject, ReviewError) as exc:
                code = exc.err.code if isinstance(exc, _Reject) else exc.code
                if code not in ("E_JOB_NOT_READY",):
                    _auto_mark(job_id, code in ("E_CHAIN_UNSUPPORTED", "E_JOB_FROZEN", "E_INVALID_ARGUMENT"), code)
            except Exception as exc:  # noqa: BLE001 - advisory; logged, never raised to the caller
                logger.warning("chain auto snapshot failed for %s: %s", job_id[-8:], type(exc).__name__)
                _auto_mark(job_id, False, type(exc).__name__)
            finally:
                _auto_tasks.pop(job_id, None)

        task = asyncio.create_task(run())
        _auto_tasks[job_id] = task
    if wait:
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=AUTO_WAIT_S)
        except TimeoutError:
            pass
