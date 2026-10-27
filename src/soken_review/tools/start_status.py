"""Handlers for review_start (03 §4.1) and review_status (03 §4.2).

Registered via ``@handler("review_start")`` / ``@handler("review_status")``.  The pool is
injected either via ``set_pool()`` (tests, lifespan) or read from ``SOKEN_DATABASE_URL``.

The repo reachability check runs `ls-remote` (tools/git_probe.py, 03 4.1); tests inject a fake
through `set_repo_probe`. `review_status` long-polls on LISTEN job_changed (tools/listen.py) and
reports drafts and an ETA from the step history (03 3.1, 4.2). The previous_report_id lookup is
still open (08 owns reports).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import UTC
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)

import psycopg_pool

from .. import quota
from ..context.items import check_cap, status_counts, validate_items
from ..context.store import ContextStore
from ..db.job_repo import JobRepo, new_job_id
from ..db.pool import get_pool
from ..errors import ReviewError
from ..families import require_enabled
from ..mapping.project_url import load_suggested_context
from ..mapping.related import load_related_contracts
from ..networks import publication_outcome
from ..report.render import finalize_reopens, render_failure_client_caused
from ..server import handler
from . import map_view
from .git_probe import GitLsRemoteProbe
from .listen import RECHECK_S, job_hash, listener_for

# ---------------------------------------------------------------------------
# Pool injection (allows tests to inject a test-database pool)
# ---------------------------------------------------------------------------

_pool: psycopg_pool.AsyncConnectionPool | None = None


def set_pool(pool: psycopg_pool.AsyncConnectionPool) -> None:
    """Inject the pool for this module (called by tests or app lifespan)."""
    global _pool
    _pool = pool


def _get_pool() -> psycopg_pool.AsyncConnectionPool:
    if _pool is not None:
        return _pool
    return get_pool()


# ---------------------------------------------------------------------------
# Network-check interface (03 §4.1 synchronous checks)
# ---------------------------------------------------------------------------


class RepoProbe(Protocol):
    """Check whether a public repo URL is reachable without credentials."""

    async def is_reachable(self, repo_url: str) -> bool: ...


class FakeRepoProbe:
    """Fake: always reports reachable (tests only)."""

    async def is_reachable(self, repo_url: str) -> bool:
        return True


_repo_probe: RepoProbe = GitLsRemoteProbe()


def set_repo_probe(probe: RepoProbe) -> None:  # for tests
    global _repo_probe
    _repo_probe = probe


# ---------------------------------------------------------------------------
# Chain normalisation and address validation (03 §4.1)
# ---------------------------------------------------------------------------

# HyperEVM and TRON chain_id aliases per 03 §4.1
_CHAIN_ALIAS: dict[int, str] = {
    999: "hyperevm",
    728126428: "tron",
}

# EVM-family address: hex with optional 0x prefix, 40 hex chars
_EVM_ADDRESS_RE = re.compile(r"^(0x)?[0-9a-fA-F]{40}$")

# TRON base58check: starts with T, 34 chars
_TRON_ADDRESS_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")

# Solana base58: 32-44 chars of base58 alphabet
_SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def _normalise_chain(chain: str, chain_id: int | None) -> tuple[str, int | None, str | None]:
    """Return (normalised_chain, chain_id, detected_chain_or_None).

    Raises ``ReviewError`` for:
    - ``evm`` without ``chain_id`` → ``E_CHAIN_ID_REQUIRED``
    """
    if chain == "evm":
        if chain_id is None:
            raise ReviewError("E_CHAIN_ID_REQUIRED", enabled="(see released chain list)")
        alias = _CHAIN_ALIAS.get(chain_id)
        if alias:
            return alias, chain_id, alias  # detected=alias signals normalisation
    return chain, chain_id, None


def _rpc_backed_chain_ids() -> list[int]:
    """EVM-family chain ids the worker can read: enabled in chains.json with a usable RPC, or an
    ``SOKEN_RPC_<chain_id>`` override."""
    from ..adapters.evm.registry import enabled_chains

    ids = {c.chain_id for c in enabled_chains() if any(not r.disabled for r in c.rpc)}
    for key in os.environ:
        if key.startswith("SOKEN_RPC_") and key[len("SOKEN_RPC_"):].isdigit() and os.environ[key]:
            ids.add(int(key[len("SOKEN_RPC_"):]))
    return sorted(ids)


def _require_rpc_chain(chain: str, chain_id: int | None) -> None:
    """Reject an EVM-family deployment on a chain the worker cannot read (E_CHAIN_DISABLED).

    The worker's chain_state step fails closed without an RPC (supervisor), so admitting such a job
    only produced a `failed` job minutes later (2026-10-22: Sepolia, no RPC row, job stuck).
    """
    if chain not in ("evm", "hyperevm", "tron") or chain_id is None:
        return
    backed = _rpc_backed_chain_ids()
    if int(chain_id) not in backed:
        raise ReviewError("E_CHAIN_DISABLED", value=str(chain_id), enabled=", ".join(str(i) for i in backed))


def _validate_address(address: str, chain: str) -> None:
    """Raise ``ReviewError(E_ADDRESS_INVALID)`` if the address does not match the chain format."""
    if chain in ("evm", "hyperevm"):
        if not _EVM_ADDRESS_RE.match(address):
            raise ReviewError("E_ADDRESS_INVALID", chain=chain, format="0x<40 hex chars>")
    elif chain == "tron":
        if not _TRON_ADDRESS_RE.match(address):
            raise ReviewError("E_ADDRESS_INVALID", chain=chain, format="T<33 base58 chars>")
    elif chain == "solana" and not _SOLANA_ADDRESS_RE.match(address):
        raise ReviewError("E_ADDRESS_INVALID", chain=chain, format="<32-44 base58 chars>")
    elif chain == "ton":
        from ..adapters.ton.detect import parse_ton_address  # 06 4.1

        if parse_ton_address(address)[0] is None:
            raise ReviewError("E_ADDRESS_INVALID", chain=chain, format="<wc>:<64 hex> or 48-char mainnet user-friendly")
    elif chain == "starknet":
        from ..adapters.starknet.felt import normalize_address

        if normalize_address(address) is None:   # 07 9.3: 1 to 64 hex, below the field prime
            raise ReviewError("E_ADDRESS_INVALID", chain=chain, format="0x<1-64 hex chars, below P>")
    # Other chains: accept any non-empty value; chain adapter validates further.


# ---------------------------------------------------------------------------
# Upload URL generation (03 §4.1 — placeholder HMAC; real key from env)
# ---------------------------------------------------------------------------

# One key for every replica in production; unset = per-process random, never a key public in the source.
_UPLOAD_KEY = os.environ.get("SOKEN_UPLOAD_HMAC_KEY", "").encode() or secrets.token_bytes(32)
_UPLOAD_TTL = int(os.environ.get("SOKEN_UPLOAD_TTL_S", "1800"))  # limits.yaml upload.url_ttl_s


def _upload_id_for_job(job_id: str) -> str:
    """Derive upload_id from job_id: base32(HMAC(K_u, job_id))[:26] (03 §4.1)."""
    import base64

    mac = hmac.new(_UPLOAD_KEY, job_id.encode(), hashlib.sha256).digest()
    return base64.b32encode(mac).decode().lower()[:26]


def _upload_url(upload_id: str, expiry_ts: int) -> tuple[str, str]:
    """Return (upload_url, upload_expires_at ISO 8601)."""
    import base64
    from datetime import datetime

    sig_input = f"{upload_id}{expiry_ts}".encode()
    sig = hmac.new(_UPLOAD_KEY, sig_input, hashlib.sha256).digest()
    sig_b32 = base64.b32encode(sig).decode().lower()[:26]
    url = f"https://soken.dev/u/{upload_id}?e={expiry_ts}&s={sig_b32}"
    expires_at = datetime.fromtimestamp(expiry_ts, tz=UTC).isoformat()
    return url, expires_at


# ---------------------------------------------------------------------------
# Surface detection (03 §9)
# ---------------------------------------------------------------------------

def _detect_surface(args: dict[str, Any]) -> str:
    """Derive surface from ``_meta`` if present, default connector (03 §9)."""
    meta = args.get("_meta") or {}
    client_header = meta.get("x_soken_client", "")
    if isinstance(client_header, str) and client_header.startswith("plugin/"):
        return "plugin"
    return "connector"


# ---------------------------------------------------------------------------
# review_start handler (03 §4.1)
# ---------------------------------------------------------------------------

# Limits from limits.yaml (development defaults; real values come from config at runtime)
_MAX_INLINE_FILES = 20
_MAX_INLINE_CHARS_PER_FILE = 60_000
_MAX_INLINE_CHARS_TOTAL = 200_000
_GUIDE_VERSION = "v0"
_RUBRIC_VERSION = "v0"
_LIMITS_CONNECTOR = {"max_nsloc": 3000, "ready_ttl_hours": 24}
_LIMITS_PLUGIN = {"max_nsloc": 10000, "ready_ttl_hours": 24}
_MCP_TERMS_URL = "https://soken.dev/mcp/terms.html"


@handler("review_start")
async def handle_review_start(args: dict[str, Any]) -> dict[str, Any]:
    """Create a job (03 §4.1). Returns accepted output or rejection envelope.

    Per 03 §7.1: rejection-channel errors (E_CHAIN_ID_REQUIRED, E_ADDRESS_INVALID,
    E_SIZE_LIMIT, E_REPO_UNREACHABLE) return {"accepted": false, ...} with is_error=False,
    because the caller can fix the input.  Error-channel ReviewErrors (E_INTERNAL, etc.)
    are raised and handled by server.py → is_error=True.
    """
    source: dict[str, Any] = args["source"]
    kind: str = source["kind"]
    requester_role: str = args.get("requester_role", "third_party_public_code")
    surface = _detect_surface(args)

    # Rejection-channel error codes (03 §7.1): return dict, not raise.
    _REJECTION_CODES = frozenset({
        "E_CHAIN_ID_REQUIRED", "E_ADDRESS_INVALID", "E_SIZE_LIMIT", "E_REPO_UNREACHABLE",
    })

    # -- Chain, chain_id, address validation (deployed and inline deployment) ----
    chain: str | None = None
    chain_id: int | None = None
    address: str | None = None
    detected_chain: str | None = None
    detected_lang: str | None = None
    has_deployment = False

    try:
        if kind == "deployed":
            chain = source["chain"]
            chain_id = source.get("chain_id")
            address = source["address"]

            chain, chain_id, detected_chain = _normalise_chain(chain, chain_id)
            require_enabled(chain=chain)
            _validate_address(address, chain)
            _require_rpc_chain(chain, chain_id)
            has_deployment = True

        elif kind in ("repo", "upload"):
            dep = source.get("deployment")
            if dep:
                dep_chain = dep["chain"]
                dep_chain_id = dep.get("chain_id")
                dep_address = dep["address"]
                dep_chain, dep_chain_id, _ = _normalise_chain(dep_chain, dep_chain_id)
                require_enabled(chain=dep_chain)
                _validate_address(dep_address, dep_chain)
                _require_rpc_chain(dep_chain, dep_chain_id)
                chain = dep_chain
                chain_id = dep_chain_id
                address = dep_address
                has_deployment = True

        elif kind == "files":
            detected_lang = source["language"]
            require_enabled(language=detected_lang)
            # Inline size checks (03 §4.1, limits.yaml inline.*)
            files = source["files"]
            if len(files) > _MAX_INLINE_FILES:
                raise ReviewError(
                    "E_SIZE_LIMIT",
                    measure="file count",
                    value=str(len(files)),
                    cap=str(_MAX_INLINE_FILES),
                    dirs="",
                )
            total_chars = 0
            for f in files:
                c = len(f["content"])
                if c > _MAX_INLINE_CHARS_PER_FILE:
                    raise ReviewError(
                        "E_SIZE_LIMIT",
                        measure=f"file {f['path']} chars",
                        value=str(c),
                        cap=str(_MAX_INLINE_CHARS_PER_FILE),
                        dirs="",
                    )
                total_chars += c
            if total_chars > _MAX_INLINE_CHARS_TOTAL:
                raise ReviewError(
                    "E_SIZE_LIMIT",
                    measure="total inline chars",
                    value=str(total_chars),
                    cap=str(_MAX_INLINE_CHARS_TOTAL),
                    dirs="",
                )
            dep = source.get("deployment")
            if dep:
                dep_chain = dep["chain"]
                dep_chain_id = dep.get("chain_id")
                dep_address = dep["address"]
                dep_chain, dep_chain_id, _ = _normalise_chain(dep_chain, dep_chain_id)
                require_enabled(chain=dep_chain)
                _validate_address(dep_address, dep_chain)
                _require_rpc_chain(dep_chain, dep_chain_id)
                chain = dep_chain
                chain_id = dep_chain_id
                address = dep_address
                has_deployment = True

        # -- Repo reachability probe (03 §4.1 "Synchronous checks") ----------------
        if kind == "repo":
            repo_url = source["repo_url"]
            if not await _repo_probe.is_reachable(repo_url):
                raise ReviewError("E_REPO_UNREACHABLE", url=repo_url)

        # -- Project context items (context ingestion spec 2): checked here, fetched by the worker
        context_items: list[dict[str, Any]] = []
        if args.get("context"):
            context_items = validate_items((args["context"] or {}).get("items") or [])
            check_cap([], context_items)

    except ReviewError as exc:
        if exc.code in _REJECTION_CODES or exc.channel == "rejection":
            # Rejection channel (03 §7.1): caller can fix; is_error stays False
            return {"accepted": False, "errors": [exc.envelope()]}
        raise  # error channel: let server.py convert to is_error=True

    # -- previous_report_id format check (DB check is TODO behind interface) ---
    previous_report_id = args.get("previous_report_id")
    _previous_manage_key = args.get("previous_manage_key")  # TODO(W0): pass to DB check
    if previous_report_id is not None:
        # TODO(W0): verify previous report exists, is live, same target, key matches (03 §4.1)
        pass

    # -- Create job in DB -------------------------------------------------------
    job_id = new_job_id()
    initial_state = "awaiting_upload" if kind == "upload" else "queued"

    upload_id: str | None = None
    upload_url: str | None = None
    upload_expires_at: str | None = None

    if kind == "upload":
        expiry_ts = int(time.time()) + _UPLOAD_TTL
        upload_id = _upload_id_for_job(job_id)
        upload_url, upload_expires_at = _upload_url(upload_id, expiry_ts)

    # principal_key: sha256(job_id)[:12] for logs; the real bearer is job_id itself (03 §3.3)
    principal_key = hashlib.sha256(job_id.encode()).hexdigest()[:12]

    try:
        pool = _get_pool()
    except RuntimeError as exc:
        raise ReviewError("E_INTERNAL", incident="no_db_pool") from exc

    target = quota.target_key(chain=chain, address=address,
                              repo_url=source.get("repo_url") if kind == "repo" else None,
                              subdir=source.get("subdir") if kind == "repo" else None)
    limit_key = quota.limit_key(target=target, job_id=job_id)

    async with pool.connection() as conn:
        repo = JobRepo(conn)
        try:
            # Early refusal: the caller already holds today's reports (quota.py; enforced again,
            # under a lock, at review_finalize where the report is issued).
            await quota.check(conn, limit_key)
        except ReviewError as exc:
            return {"accepted": False, "errors": [exc.envelope()]}
        async with conn.transaction():
            await repo.create(
                job_id=job_id,
                principal_key=principal_key,
                surface=surface,
                state=initial_state,
                requester_role=requester_role,
                source_kind=kind,
                source_args=source,
                has_deployment=has_deployment,
                chain=chain,
                chain_id=chain_id,
                address=address,
                previous_report_id=previous_report_id,
                previous_snapshot=None,  # TODO(W0): copy snapshot from earlier report
                upload_id=upload_id,
                guide_version=_GUIDE_VERSION,
                rubric_version=_RUBRIC_VERSION,
            )
            await conn.execute("update jobs set target_key = %s, limit_key = %s where job_id = %s",
                               (target, limit_key, job_id))
            # Record Terms of Use acceptance at review_start (security review 2026-10-24).
            await conn.execute(
                "update jobs set terms_url = %s, terms_accepted_at = now() where job_id = %s",
                (_MCP_TERMS_URL, job_id),
            )
            if context_items:
                await repo.append_context_items(job_id, context_items)   # fresh row: no cap or duplicate possible
            # Insert the first step for queued jobs (09 section 3.3); upload jobs wait for
            # the archive before being seeded by the supervisor.
            if initial_state == "queued":
                await repo.insert_step(
                    job_id=job_id,
                    step="chain_state",
                    seq=0,
                    container=False,    # supervisor-only row (09 ops.sql comment)
                    units=0,
                    ram_mb=0,
                    max_attempts=3,     # chain_state retries on transient RPC failures
                )

    limits = _LIMITS_PLUGIN if surface == "plugin" else _LIMITS_CONNECTOR

    result: dict[str, Any] = {
        "accepted": True,
        "job_id": job_id,
        "state": initial_state,
        "requester_role": requester_role,
        "terms_url": _MCP_TERMS_URL,
        "detected": {
            "chain": detected_chain or chain,
            "chain_id": chain_id,
            "language": detected_lang,
            "is_proxy": None,  # resolved during fetch
        },
        "poll_after_s": 2,
        "guide_version": _GUIDE_VERSION,
        "resume_phrase": f"Resume Soken review {job_id}",
        "limits": limits,
    }

    if kind == "files":
        # files_received: sha256 and line count per file (03 §4.1)
        result["files_received"] = [
            {
                "path": f["path"],
                "sha256": hashlib.sha256(f["content"].encode()).hexdigest(),
                "lines": f["content"].count("\n") + 1,
                "role": f.get("role", "source"),
            }
            for f in source["files"]
        ]

    if kind == "upload" and upload_url and upload_expires_at:
        result["upload_url"] = upload_url
        result["upload_expires_at"] = upload_expires_at

    if context_items:
        result["context"] = {"requested": len(context_items), "done": 0, "failed": 0}
    else:
        # No documents were supplied: surface a plain-language hint so the model
        # knows to ask the user.  Describe what is possible; never command the model
        # to call a tool (directory prompt-injection rule).
        result["next_action"] = (
            "No project documents were supplied. "
            "Project documents (website, whitepaper, documentation, terms of use, privacy policy) "
            "are needed to detect spec-vs-code mismatches. "
            "Ask the user for the relevant URLs and add them via review_add_context. "
            "When the user has none, a context_notes section saying so (review_set_section) "
            "records that and this hint stops."
        )

    # Optional settle-wait (2026-10-26): the first review_status calls of every blind run only waited for
    # a pipeline of 10 to 70 s; with wait_seconds the status at the end of the wait comes back here.
    wait = min(int(args.get("wait_seconds") or 0), _MAX_WAIT)
    if wait > 0 and initial_state == "queued":
        try:
            result["status"] = await handle_review_status(
                {"job_id": job_id, "wait_seconds": wait, "wait_for": "settled"})
        except ReviewError:
            pass  # the job exists and the id is returned; review_status reports the state on the next call

    return result


def _context_status(job: dict[str, Any]) -> dict[str, int] | None:
    """`{requested, done, failed}` of the job's context requests against the store on disk; None
    when nothing was requested. Without a wired read context (bare server) the counts are the
    requests alone."""
    items = job.get("context_items") or []
    if not items:
        return None
    try:
        from .read import _get_ctx

        store = ContextStore.load(_get_ctx().get_pin_root(), job["job_id"])
    except ReviewError:
        return {"requested": len(items), "done": 0, "failed": 0}
    return status_counts(store, items)


# ---------------------------------------------------------------------------
# review_status handler (03 §4.2)
# ---------------------------------------------------------------------------

# Map job state -> step label (03 §4.2)
_STATE_STEP: dict[str, str] = {
    "awaiting_upload": "upload",
    "queued": "queued",
    "fetching": "fetching",
    "building": "building",
    "analyzing": "analyzing",
    "ready": "interactive",
    "finalized": "interactive",
    "render_queued": "rendering",
    "rendering": "rendering",
    "rendered": "complete",
    "render_failed": "complete",
    "insufficient_source": "stopped",
    "failed": "stopped",
    "expired": "stopped",
    "deleted": "stopped",
}

# Progress weights per state (03 §3.1)
_STATE_PERCENT: dict[str, int] = {
    "awaiting_upload": 0,
    "queued": 0,
    "fetching": 5,
    "building": 20,
    "analyzing": 55,
    "ready": 85,
    "finalized": 85,
    "render_queued": 86,
    "rendering": 90,
    "rendered": 100,
    "render_failed": 100,
    "insufficient_source": 100,
    "failed": 100,
    "expired": 100,
    "deleted": 100,
}

# Long-poll timeout (max 45 s per 03 §4.2; first-byte timer 60 s per plan)
_MAX_WAIT = 45
_POLL_INTERVAL = 0.5  # seconds between DB checks


@handler("review_status")
async def handle_review_status(args: dict[str, Any]) -> dict[str, Any]:
    """Return current job state, optionally long-polling for a change (03 §4.2)."""
    job_id: str = args["job_id"]
    wait_seconds: int = min(int(args.get("wait_seconds", 0)), _MAX_WAIT)

    pool = _get_pool()

    # Initial read
    async with pool.connection() as conn:
        repo = JobRepo(conn)
        job = await repo.get(job_id)
        steps = await repo.get_steps(job_id) if job else []

    if job is None:
        raise ReviewError("E_JOB_NOT_FOUND")

    initial_state: str = job["state"]
    # wait_for settled (2026-10-26): keep waiting through queued -> fetching -> building -> analyzing,
    # which cost 3 to 4 status calls per job in the blind runs although the pipeline took 10 to 70 s.
    settled = args.get("wait_for") == "settled"
    if settled and initial_state == "awaiting_upload":
        wait_seconds = 0  # only the upload moves it on; waiting would just hold the call

    # Long-poll (03 §4.2): return at once on a terminal, ready, rendered or changed state, else wait
    # on LISTEN job_changed (payload sha256(job_id)[:12], migrations/002_ops.sql). The row is re-read
    # on every notification and at least every RECHECK_S, so a dropped listener only adds latency.
    if wait_seconds > 0 and initial_state not in _TERMINAL_OR_READY:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_seconds
        h = job_hash(job_id)
        listener = listener_for(pool.conninfo)
        ev = listener.subscribe(h)
        try:
            await listener.wait_ready(min(2.0, float(wait_seconds)))
            while True:
                async with pool.connection() as conn:
                    job = await JobRepo(conn).get(job_id)
                if job is None:
                    raise ReviewError("E_JOB_NOT_FOUND")
                if job["state"] in _TERMINAL_OR_READY or (not settled and job["state"] != initial_state):
                    break
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                ev.clear()
                try:
                    await asyncio.wait_for(ev.wait(), timeout=min(remaining, RECHECK_S))
                except TimeoutError:
                    pass
        finally:
            listener.unsubscribe(h, ev)
        async with pool.connection() as conn:
            steps = await JobRepo(conn).get_steps(job_id)

    async with pool.connection() as conn:
        repo = JobRepo(conn)
        drafts = await repo.list_drafts(job_id)
        medians = await repo.step_medians(job.get("chain")) if job["state"] in _ETA_STATES else {}
        # Compute finalize_checks for interactive states (03 §4.2, §4.14)
        finalize_checks: list[dict[str, Any]] = []
        if job["state"] in ("ready", "finalized"):
            try:
                from .finalize import compute_finalize_checks
                finalize_checks = await compute_finalize_checks(conn, job_id)
            except Exception:  # noqa: BLE001
                finalize_checks = []  # never fail status due to finalize_checks
        # A context_notes section (also "the user has no documents") ends the documents hint.
        context_notes_recorded = (await (await conn.execute(
            "select 1 from sections where job_id = %s and section = 'context_notes' limit 1",
            (job_id,))).fetchone()) is not None

    # Publish info (CEO 2026-10-24): show the public URL (or "publishing") for rendered jobs.
    from .report import _publish_info
    pub_status, pub_url = await _publish_info(job.get("report_id"))

    return _build_status_response(job, args.get("response_format", "concise"), steps, drafts, medians,
                                  finalize_checks=finalize_checks, pub_status=pub_status, pub_url=pub_url,
                                  context_notes_recorded=context_notes_recorded)


# States where long-poll should return immediately (03 §4.2)
_TERMINAL_OR_READY = {
    "ready",
    "rendered",
    "render_failed",
    "insufficient_source",
    "failed",
    "expired",
    "deleted",
}


def _compute_percent(state: str, steps: list[dict[str, Any]], medians: dict[str, float] | None = None) -> int:
    """Compute progress percent from job state and job_steps rows (03 §3.1 weights).

    Weights: fetching=10, building=25, analyzing=50, rendering=15.
    Within each state, interpolate linearly across done steps; the running step counts for the
    share of its expected time that has elapsed (at most 90 percent of it), so a seven-minute
    Solana build no longer sits at 10 percent from its first second to its last (2026-10-26).
    """
    # For terminal/complete states return fixed values
    _FIXED: dict[str, int] = {
        "awaiting_upload": 0,
        "queued": 0,
        "ready": 85,
        "finalized": 85,
        "render_queued": 86,
        "rendering": 90,
        "rendered": 100,
        "render_failed": 100,
        "insufficient_source": 100,
        "failed": 100,
        "expired": 100,
        "deleted": 100,
    }
    if state in _FIXED:
        return _FIXED[state]

    # State bases and ranges (weights: fetching=10, building=25, analyzing=50)
    _BASE = {"fetching": 0, "building": 10, "analyzing": 35}
    _RANGE = {"fetching": 10, "building": 25, "analyzing": 50}

    base = _BASE.get(state, 0)
    rng = _RANGE.get(state, 0)
    if not steps or rng == 0:
        return base

    # Count steps that belong to this state bucket
    _STEP_STATE: dict[str, str] = {
        "chain_state": "fetching",  # seq=0 is in fetching; seq=1 would be analyzing
        "fetch": "fetching",
        "deps": "fetching",
        "build": "building",
        "analyze": "analyzing",
        "map": "analyzing",
        "verify": "analyzing",
    }
    bucket_steps = [s for s in steps if _STEP_STATE.get(s["step"], "analyzing") == state]
    if not bucket_steps:
        return base
    done = sum(1 for s in bucket_steps if s["status"] in ("done", "failed", "timeout"))
    running = [s for s in bucket_steps if s["status"] == "running" and s.get("started_at") is not None]
    frac = 0.0
    if running:
        from datetime import datetime

        s = running[0]
        expected = max(1.0, (medians or {}).get(s["step"], _STEP_DEFAULT_S.get(s["step"], 30.0)))
        elapsed = max(0.0, (datetime.now(UTC) - s["started_at"]).total_seconds())
        frac = min(0.9, elapsed / expected)
    return base + int(rng * (done + frac) / len(bucket_steps))


# ETA (03 3.1): median of each remaining step over the last 50 jobs of the chain, else these
# development defaults (09 has no default table yet; W0 finding).
_ETA_STATES = frozenset({"queued", "fetching", "building", "analyzing"})
_STEP_DEFAULT_S: dict[str, float] = {"chain_state": 5, "fetch": 20, "deps": 60, "build": 60, "analyze": 180,
                                     "map": 10, "verify": 30}
_PIPELINE = [("chain_state", 0), ("fetch", 0), ("build", 0), ("analyze", 0), ("map", 0), ("chain_state", 1)]
_ETA_FLOOR_S = 30.0        # a running step past its median never reports less than this


def _compute_eta(state: str, steps: list[dict[str, Any]], medians: dict[str, float]) -> int | None:
    """Seconds until `ready`: remaining pipeline steps plus what is left of the running one."""
    if state not in _ETA_STATES:
        return None
    from datetime import datetime

    done = {(s["step"], s.get("seq", 0)) for s in steps if s["status"] == "done"}
    running = [s for s in steps if s["status"] == "running"]
    total = 0.0
    now = datetime.now(UTC)
    for name, seq in _PIPELINE:
        if (name, seq) in done:
            continue
        expected = medians.get(name, _STEP_DEFAULT_S.get(name, 30.0))
        run = next((s for s in running if s["step"] == name and s.get("seq", 0) == seq), None)
        if run is not None and run.get("started_at") is not None:
            elapsed = (now - run["started_at"]).total_seconds()
            # A step past its median is still running: the remaining time is unknown, so the
            # estimate keeps a floor instead of the "3 s" it repeated for four minutes on a Solana
            # build (2026-10-26, median from no-op mint builds).
            expected = expected - elapsed if elapsed < expected else max(_ETA_FLOOR_S, 0.25 * expected)
        total += expected
    return round(total)


def _draft_row(d: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "draft_key": d["draft_key"],
        "finding_no": f"F-{d['finding_no']:02d}",
        "status": d["status"],
        "severity": d["severity"],
        "title": (d["title"][:60] if d.get("title") else None),
        "carried_from": d.get("carried_from"),
    }
    flag = d.get("server_flag")
    if d["status"] == "needs_text" and flag:
        if flag.get("rule") in ("J2", "J4"):
            row["flag"] = flag["rule"]
        if d.get("loc_path"):
            start, end = d["loc_start"], d["loc_end"]
            row["location"] = f"{d['loc_path']}:{start}" if start == end else f"{d['loc_path']}:{start}-{end}"
    return row


# Candidate.provider (adapters/base.py) -> tools.v1.json provenance.source (06 2.2, PLAN-v4 follow-up).
# "user" splits on the input kind; "ipfs" has no enum value and stays null rather than a guess.
_PROVIDER_SOURCE: dict[str, str] = {
    "sourcify": "sourcify",
    "etherscan": "verified_explorer",
    "tronscan": "verified_explorer",
    "eth_bytecode_db": "verifier_api",
    "repo": "repo_commit",
}


def _provenance_source(job: dict[str, Any], steps: list[dict[str, Any]]) -> str | None:
    """The source the reviewed code came from: the done fetch step's provider, never the input kind."""
    fetched = [s for s in steps if s["step"] == "fetch" and s["status"] == "done"]
    provider = ((fetched[-1].get("provenance") or {}).get("provider")) if fetched else None
    if provider == "user":
        return "upload" if job.get("source_kind") == "upload" else "user_files"
    if provider:
        return _PROVIDER_SOURCE.get(provider)
    return "bytecode_only" if job.get("tier") == "D" else None


_ERROR_DETAIL_MAX_CHARS = 2000


def _error_detail_text(detail: Any) -> str:
    """`error.detail` on the wire is a string (tools.v1.json). The supervisor stores structured
    details (e.g. {"reason": "missing_import", "packages": [...]}); they are serialized compactly
    with sorted keys so a client sees one stable string, capped so a stderr dump cannot bloat
    the status response."""
    if isinstance(detail, str):
        text = detail
    elif isinstance(detail, (dict, list)):
        text = json.dumps(detail, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    else:
        text = str(detail)
    return text[:_ERROR_DETAIL_MAX_CHARS]


def _error_texts(code: str, detail: Any) -> dict[str, str]:
    """`what` and `fix` of a status error from contract/errors.yaml (03 section 7), so a stopped
    job always tells the client what to do next. A template is used only when every placeholder
    it names is present in the stored detail; otherwise that text is left out rather than sent
    with a blank hole."""
    import string

    from ..contract import load_errors

    row = load_errors().get(code)
    if not row:
        return {}
    fields: dict[str, str] = {}
    if isinstance(detail, dict):
        for key, value in detail.items():
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(v) for v in value[:10] if isinstance(v, (str, int)))
            if isinstance(value, (str, int)) and str(value):
                fields[str(key)] = str(value)[:300]
    out: dict[str, str] = {}
    for key in ("what", "fix"):
        template = row.get(key) or ""
        names = {n for _, n, _, _ in string.Formatter().parse(template) if n}
        if template and names <= fields.keys():
            out[key] = template.format(**{n: fields[n] for n in names})
    return out


def _build_status_response(
    job: dict[str, Any],
    response_format: str,
    steps: list[dict[str, Any]] | None = None,
    drafts: list[dict[str, Any]] | None = None,
    medians: dict[str, float] | None = None,
    finalize_checks: list[dict[str, Any]] | None = None,
    pub_status: str | None = None,
    pub_url: str | None = None,
    context_notes_recorded: bool = False,
) -> dict[str, Any]:
    """Build the review_status output object from the job row (03 §4.2).

    ``context_notes_recorded``: the job has a context_notes section, so the reviewer has already
    dealt with project documents (including "the user has none") and the next_action hint stops.
    """
    state: str = job["state"]
    _steps = steps or []

    out: dict[str, Any] = {
        "accepted": True,
        "job_id": job["job_id"],
        "state": state,
        "step": _STATE_STEP.get(state, "stopped"),
        "percent": _compute_percent(state, _steps, medians or {}),
    }

    # Upload fields only in awaiting_upload (03 §4.2)
    if state == "awaiting_upload" and job.get("upload_id"):
        expiry_ts = int(time.time()) + _UPLOAD_TTL
        upload_id = job["upload_id"]
        upload_url, upload_expires_at = _upload_url(upload_id, expiry_ts)
        out["upload_url"] = upload_url
        out["upload_expires_at"] = upload_expires_at
    else:
        out["eta_s"] = _compute_eta(state, _steps, medians or {})

    # Provenance (available once tier is set)
    tier = job.get("tier")
    if tier is not None:
        out["provenance"] = {
            "tier": tier,
            "label": None,  # TODO(W0): compute from tier + code_changed banner
            "source": _provenance_source(job, _steps),
            "commit": job.get("resolved_commit"),
            "upload_sha256": job.get("upload_sha256"),
            "code_hash": job.get("code_hash"),
            "source_attribution": None,  # TODO(W0): provider attribution text
            "requester_role": job["requester_role"],
            "ownership_proven": job["ownership_proven"],
            "profile": "owner" if job["ownership_proven"] else "public_review",
        }

    # Build status (03 §4.2)
    out["map_status"] = job.get("map_status", "none")
    out["analyzer_degraded"] = job.get("analyzer_degraded", False)

    # Error info for terminal states. `detail` is an optional schema string (tools.v1.json
    # error object: all props `type: string`, additionalProperties false) — a terminal error
    # with a code but no detail (e.g. E_SOURCE_NOT_FOUND) must OMIT detail, not send null, or
    # a validating MCP client rejects the whole status response.
    if job.get("error_code"):
        err = {"code": job["error_code"]}
        err.update(_error_texts(job["error_code"], job.get("error_detail")))
        if job.get("error_detail") is not None:
            err["detail"] = _error_detail_text(job["error_detail"])
        if job["error_code"] == "E_RENDER_FAILED" and state == "render_failed":
            # The fix must say what review_finalize will actually do on this job (finalize.py
            # recovery path); the catalogue text cannot know the cause or the reset budget.
            err["fix"] = _render_failed_fix(job)
        out["error"] = err

    # Vendored npm dependencies of a repo review (adapters/evm/npm_deps.py, fetch provenance):
    # the weakest pin, the count, and the package list in the detailed format.
    deps = _dependencies_status(_steps, detailed=response_format == "detailed")
    if deps is not None:
        out["dependencies"] = deps
    # Files the scope rules kept out of the review (test and mock contracts): count always,
    # the rows in the detailed format; the report prints them as out of scope.
    excluded = _scope_excluded_status(_steps, detailed=response_format == "detailed")
    if excluded is not None:
        out["scope_excluded"] = excluded

    # Project context (context ingestion spec 3): present once documents were requested
    ctx = _context_status(job)
    if ctx is not None:
        out["context"] = ctx
    elif not context_notes_recorded:
        # No context items: surface a next_action hint so the model asks the user
        # for project documents.  This is server text, not model output; it describes
        # what is available and why, without commanding the model to call anything
        # (directory prompt-injection rule).
        open_states = {"awaiting_upload", "queued", "fetching", "building", "analyzing", "ready", "finalized"}
        if state in open_states:
            out["next_action"] = (
                "No project documents were supplied. "
                "Project documents (website, whitepaper, documentation, terms of use, privacy policy) "
                "are needed to detect spec-vs-code mismatches. "
                "Ask the user for the relevant URLs and add them via review_add_context. "
                "When the user has none, a context_notes section saying so (review_set_section) "
                "records that and this hint stops."
            )

    # Detailed response: related contracts and server-discovered project URLs
    if response_format == "detailed":
        out.update(_detailed_extras(job))

    # Drafts: every draft (03 §4.2); server drafts carry flag and location while needs_text
    out["drafts"] = [_draft_row(d) for d in (drafts or [])][:60]

    # Finalize checks (03 §4.2, F1-F6, F8): shared with review_finalize
    out["finalize_checks"] = finalize_checks or []
    out["next_tools"] = _status_next_tools(state, out["drafts"], out["finalize_checks"],
                                           finalize_reopens=finalize_reopens(job))

    # Publish info (CEO 2026-10-24): present for rendered jobs; null for pre-render.
    out["publish_status"] = pub_status
    out["public_url"] = pub_url

    # Publication outcome: what automatic-publish will do for this job (CEO 2026-10-24).
    _profile = (out.get("provenance") or {}).get("profile") or ("owner" if job.get("ownership_proven") else None)
    out["publication"] = publication_outcome(job, _profile)

    return out


_PIN_NOTES = {
    "lockfile": "Dependency versions and sha512 integrity come from the repository lockfile.",
    "lockfile_version": ("Dependency versions come from the repository lockfile; the lockfile has no sha512 "
                         "integrity, so the registry integrity for those exact versions was checked."),
    "registry_range": ("The repository has no lockfile: dependency versions were chosen from the package.json "
                       "ranges at fetch time and may differ from the versions the project built and deployed."),
}


_SCOPE_REASONS = frozenset({"test_or_mock_dir", "mock_name", "test_harness"})


def _scope_excluded_status(steps: list[dict[str, Any]], *, detailed: bool) -> dict[str, Any] | None:
    fetched = [s for s in steps if s.get("step") == "fetch" and s.get("status") == "done"]
    rec = ((fetched[-1].get("provenance") or {}).get("scope_excluded")) if fetched else None
    if not isinstance(rec, dict) or not rec.get("count"):
        return None
    out: dict[str, Any] = {"count": int(rec["count"]),
                           "note": "Test and mock contracts left out of the review by the scope rules; "
                                   "the report lists them as out of scope."}
    if detailed:
        out["files"] = [{"path": str(f.get("path"))[:300],
                         "reason": f["reason"] if f.get("reason") in _SCOPE_REASONS else "other"}
                        for f in (rec.get("files") or [])[:60] if isinstance(f, dict) and f.get("path")]
    return out


def _dependencies_status(steps: list[dict[str, Any]], *, detailed: bool) -> dict[str, Any] | None:
    fetched = [s for s in steps if s.get("step") == "fetch" and s.get("status") == "done"]
    deps = ((fetched[-1].get("provenance") or {}).get("dependencies")) if fetched else None
    if not isinstance(deps, dict) or not deps.get("packages"):
        return None
    pins = deps.get("pinned_by")
    out: dict[str, Any] = {
        "manager": "npm",
        "lockfile": deps.get("lockfile"),
        "pinned_by": pins,
        "count": len(deps.get("packages") or []),
        "note": _PIN_NOTES.get(str(pins), ""),
    }
    if detailed:
        from ..adapters.evm.npm_deps import safe_version

        rows = []
        for p in (deps.get("packages") or [])[:60]:
            if not isinstance(p, dict):
                continue
            row = {"name": str(p.get("name")), "pinned_by": str(p.get("pinned_by"))}
            if safe_version(p.get("version") if isinstance(p.get("version"), str) else None):
                row["version"] = p["version"]
            rows.append(row)
        out["packages"] = rows
    return out


_BUILD_STATUS = {"ok": "ok", "failed": "failed", "refused": "refused", "not_needed": "not_needed"}


def _build_status_value(pin_root: Any, job_id: str, map_status: str | None) -> str | None:
    """`build.status` in the schema enum (ok, failed, refused, not_needed), never a map status.

    The supervisor's build_result.json (job work dir) is the source; without it, a failed map
    means a failed build and a full semantic map means a successful one; otherwise unknown (None).
    """
    try:
        path = Path(pin_root).parent / "work" / job_id / "build_result.json"
        if path.is_file() and not path.is_symlink() and path.stat().st_size < 4 * 1024 * 1024:
            value = json.loads(path.read_text(encoding="utf-8")).get("status")
            if value in _BUILD_STATUS:
                return _BUILD_STATUS[value]
    except (OSError, ValueError, AttributeError):
        pass
    return {"failed": "failed", "full": "ok"}.get(map_status or "")


_PIPELINE_STATES = frozenset({"awaiting_upload", "queued", "fetching", "building", "analyzing"})
_RENDER_STATES = frozenset({"finalized", "render_queued", "rendering", "rendered", "render_failed"})


def _render_failed_fix(job: dict[str, Any]) -> str:
    """`error.fix` of a render_failed job: the same answer review_finalize gives (finalize.py)."""
    if not finalize_reopens(job):
        return "This job has used its render retries and cannot render again. Start a new review."
    if render_failure_client_caused(job.get("error_detail")):
        return ("Call review_finalize: the job reopens, the flagged reviewer text (see detail) must "
                "be revised, and the job finalizes and renders again in the same call.")
    return ("Call review_finalize once: the failure was in server-built content, so the job reopens "
            "and renders again in that one call. No text change is needed.")


def _status_next_tools(state: str, drafts: list[dict[str, Any]], checks: list[dict[str, Any]], *,
                       finalize_reopens: bool = True) -> list[str]:
    """Tool names (schema `next_tools`, at most 3) that move the job forward from this state; names
    only, no prose. Drafts first (a needs_text or needs_challenge draft blocks finalize), then the
    tools named by open finalize checks, then finalize. A render_failed job names review_finalize
    only when finalize will reopen it (``finalize_reopens``), else a new review."""
    if state in _PIPELINE_STATES:
        return ["review_status"]
    if state == "render_failed":
        return ["review_finalize"] if finalize_reopens else ["review_start"]
    if state in _RENDER_STATES:
        return ["review_report"]
    if state != "ready":
        return []
    statuses = {d.get("status") for d in drafts}
    out: list[str] = []
    if "needs_text" in statuses:
        out.append("review_submit_finding")
    if "needs_challenge" in statuses:
        out.append("review_challenge")
    for check in checks:
        tool = check.get("tool")
        if check.get("open") and tool and tool not in out:
            out.append(tool)
    if not drafts:
        out = ["review_contract_map", "review_leads", "review_read_code"]
    elif not out:
        out = ["review_finalize"]
    return out[:3]


def _detailed_extras(job: dict[str, Any]) -> dict[str, Any]:
    """Additional fields for ``response_format=detailed``: related contracts, suggested URLs, build.

    Bug 8 fix (2026-10-25): the map tool emits "see review_status build" when the build fails,
    but review_status had no build section.  Added: build.status, build.version (compiler), and
    build.error (first 300 chars of the build-detail string from map/status.json).
    """
    extras: dict[str, Any] = {}
    try:
        from ..mapping.build import load_map_status
        from ..mapping.facts import load_facts
        from .read import _get_ctx
        pin_root = _get_ctx().get_pin_root()
        job_id = job["job_id"]
        related = load_related_contracts(pin_root, job_id)
        if related:
            extras["related_contracts"] = related
        suggested = load_suggested_context(pin_root, job_id)
        if suggested:
            extras["suggested_context_items"] = suggested
        # Build section: status from job row + compiler version + build error from status.json
        map_status_doc = load_map_status(pin_root, job_id)
        build_detail = map_status_doc.get("build_detail")
        facts = load_facts(pin_root, job_id) or []
        compiler_version = next((f["value"] for f in facts if f["key"] == "compiler.version"), None)
        # The build outcome the map step recorded (#72: a parsed Solana map is `partial` whether or
        # not the program built), else the supervisor's build_result.json, else failed/full map
        # status; always a schema enum value (ok, failed, refused, not_needed), never a map status.
        build_info: dict[str, Any] = {}
        recorded = map_status_doc.get("build_status")
        status = (_BUILD_STATUS.get(recorded) if isinstance(recorded, str) else None) \
            or _build_status_value(pin_root, job_id, job.get("map_status"))
        if status is not None:
            build_info["status"] = status
        if recorded:
            build_info["map_status"] = job.get("map_status") or map_status_doc.get("map_status")
        if compiler_version:
            build_info["version"] = compiler_version
        if build_detail:
            build_info["error"] = map_view.build_error_summary(build_detail)
        extras["build"] = build_info
    except Exception as exc:  # noqa: BLE001
        logger.debug("_detailed_extras: %s", type(exc).__name__)
    return extras
