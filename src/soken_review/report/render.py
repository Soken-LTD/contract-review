"""Render step (08 3.2, 09 3.1): the supervisor assembles and uploads; soken-render has no network.

`queue_render(conn, job_id)` puts a finalized job in `render_queued` with one render step
(priority 50). `run_render_step(...)` claims nothing itself: the supervisor calls it for a claimed
render row. Attempt budget (03 3.2): 3 attempts, 120 s each, 180 s from the first claim, backoff
5 s then 20 s, retried details `timeout` and `chrome_start`, `page_limit` once with
`compact_evidence`. Each retry is a new render row with `not_before`; the job returns to
`render_queued`. Outputs go to the object store under `reports/<report_id>/<render_no>/`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

from ..db.job_repo import JobRepo
from ..sandbox.profile import StepLimits, docker_argv, locked_image, sandbox_writable_dir
from .assemble import AssemblyError, assemble_report
from .kit.build import BuildError, build

logger = logging.getLogger(__name__)

# Auto-publish consent (CEO 2026-10-24): every successful render enqueues a publish_request.
# The legal basis is acceptance of the Terms of Use at review_start (soken.dev/mcp/terms.html).
# These constants are the server-side consent record; they must not be changed without a ToU
# revision because the text is the legal record stored in publish_consent_log.
AUTO_PUBLISH_PARTY = "requester"
AUTO_PUBLISH_NAME = "MCP Terms of Use acceptance"
AUTO_PUBLISH_STATEMENT = (
    "By submitting source code for this review, the requester accepted the "
    "Contract Review MCP Terms of Use at soken.dev/mcp/terms.html, "
    "which authorises automated publication of this rendered report."
)

RENDER_LIMITS = StepLimits(cpus=1.0, memory="2g", pids=512, max_file=64 * 1024 * 1024)
RENDER_UNITS, RENDER_RAM_MB, RENDER_PRIORITY = 1, 2048, 50
ATTEMPT_CAP_S, TOTAL_S, MAX_ATTEMPTS = 120, 180, 3
BACKOFF_S = {2: 5, 3: 20}
RETRIED = {"timeout", "chrome_start"}
KEY_VERSION = 1   # the launch key; the version a new report row records is current_key_version()


def current_key_version() -> int:
    """K_v for new reports (08 4.1): `SOKEN_REPORT_KEY_CURRENT`, default 1. Rotation = set
    SOKEN_REPORT_KEY_V2 beside V1 and SOKEN_REPORT_KEY_CURRENT=2: new rows record 2, existing
    rows keep their key_version and their links keep verifying with V1."""
    raw = os.environ.get("SOKEN_REPORT_KEY_CURRENT", "").strip()
    if not raw:
        return KEY_VERSION
    if not raw.isdigit() or int(raw) < 1:
        raise RuntimeError(f"SOKEN_REPORT_KEY_CURRENT must be a positive integer, got {raw[:8]!r}")
    return int(raw)
MAX_PDF_BYTES = 20 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024


@dataclass
class RenderOutcome:
    code: str
    detail: str = ""
    pages: int | None = None
    pdf_sha256: str | None = None
    out_dir: Path | None = None
    result: dict[str, Any] | None = None
    files: dict[str, bytes] | None = None


def store_root() -> Path:
    """Object store root (09: Spaces in production; a local dir in development)."""
    return Path(os.environ.get("SOKEN_REPORT_STORE", str(Path(os.environ.get("SOKEN_PIN_ROOT", "/srv/sbx")).parent / "reports")))


async def queue_render(conn: psycopg.AsyncConnection, job_id: str) -> None:
    """finalized -> render_queued with one render step (03 3.1). Call inside a transaction."""
    repo = JobRepo(conn)
    await repo.transition(job_id, "render_queued")
    await repo.insert_step(job_id=job_id, step="render", container=True, units=RENDER_UNITS, ram_mb=RENDER_RAM_MB,
                           priority=RENDER_PRIORITY, max_attempts=1)


DIRECT = "direct"


def render_image() -> str:
    if os.environ.get("SOKEN_RENDER_DIRECT") == "1":
        return DIRECT
    image = locked_image("soken-render")
    if image is None:
        raise RuntimeError("soken-render image not pinned (images.lock.json) and SOKEN_IMAGE_SOKEN_RENDER unset")
    return image


def run_container(render_dir: Path, *, compact: bool, image: str, timeout_s: int = ATTEMPT_CAP_S) -> RenderOutcome:
    """One sandboxed render attempt: in/ read-only, out/ writable, no network (08 3.2, 09 3)."""
    out = render_dir / "out"  # render_dir is fresh (fresh_render_dir): out/ cannot pre-exist
    sandbox_writable_dir(out)
    name = f"soken-render-{render_dir.name[-8:].lower().replace('_', '-')}-{int(time.time() * 1000) % 10**9}"
    if image == DIRECT:
        # Dev only (RULES: explicit env var, off by default, unused in tests): kit on the host
        # with host Chrome and poppler, for a host whose docker VM cannot hold the image.
        argv = [sys.executable, "-m", "soken_review.report.kit.render_job", str(render_dir),
                *(["--compact"] if compact else [])]
    else:
        argv = docker_argv(
            "render", image, render_dir, None, RENDER_LIMITS,
            env={"HOME": "/tmp", "TMPDIR": "/tmp"},
            command=["python", "-m", "soken_review.report.kit.render_job", "/work", *(["--compact"] if compact else [])],
            mounts=[(render_dir / "in", "/work/in", True), (out, "/work/out", False)],
            name=name, shm_size="512m",
        )
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        return RenderOutcome("timeout", f"attempt over {timeout_s} s")
    return collect_outputs(out, proc.returncode, (proc.stderr or proc.stdout or "").strip()[-300:])


def collect_outputs(out: Path, returncode: int, tail: str = "") -> RenderOutcome:
    """Read the sandbox output dir as untrusted data: result.json and report.pdf only."""
    try:
        result = read_result(out)
    except UntrustedOutput as err:
        if err.missing:
            code = "timeout" if returncode == 137 else "chrome_start"
            return RenderOutcome(code, f"no result.json, exit {returncode}: {tail}")
        return RenderOutcome("untrusted_output", str(err))
    if result["code"] != "ok":
        return RenderOutcome(result["code"], result["detail"], result=result)
    try:
        pdf = read_untrusted(out / "report.pdf", MAX_PDF_BYTES)
    except UntrustedOutput as err:
        return RenderOutcome("untrusted_output", str(err))
    sha = hashlib.sha256(pdf).hexdigest()
    if sha != result.get("pdf_sha256"):
        return RenderOutcome("untrusted_output", "pdf sha256 differs from the sandbox result")
    if not pdf.startswith(b"%PDF-"):
        return RenderOutcome("untrusted_output", "report.pdf is not a PDF")
    # Only the PDF leaves the sandbox. screen.html is published on the soken.dev origin, so the
    # supervisor builds it itself from its own report.json (build() is pure, no network).
    return RenderOutcome("ok", pages=result.get("pages"), pdf_sha256=sha, out_dir=out, result=result,
                         files={"report.pdf": pdf})


def build_screen_html(report: dict[str, Any], compact: bool) -> bytes:
    """Hosted page from the supervisor-written report.json, never from sandbox output; built in a
    fresh dir under the supervisor-only root (no sandbox mounts it)."""
    host_dir = Path(tempfile.mkdtemp(prefix="screen-", dir=render_root()))
    try:
        return build(report, host_dir, mode="screen", compact_evidence=compact).html_path.read_bytes()
    finally:
        shutil.rmtree(host_dir, ignore_errors=True)


def render_root() -> Path:
    """Supervisor-only scratch root: never under a job dir, never mounted by build, analyze or any
    other container. `SOKEN_RENDER_ROOT`, default `<store root parent>/render-tmp`."""
    root = Path(os.environ.get("SOKEN_RENDER_ROOT", str(store_root().parent / "render-tmp")))
    root.mkdir(mode=0o711, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"render root {root} is not a plain directory")
    return root


def fresh_render_dir(report_bytes: bytes) -> Path:
    """One fresh dir per attempt (mkdtemp, 0700 then 0711 so uid 10001 can reach in/ and out/);
    the input is written with O_CREAT|O_EXCL|O_NOFOLLOW before the container starts."""
    d = Path(tempfile.mkdtemp(prefix="render-", dir=render_root()))
    d.chmod(0o711)
    (d / "in").mkdir(mode=0o755)
    fd = os.open(d / "in" / "report.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, report_bytes)
    finally:
        os.close(fd)
    return d


class UntrustedOutput(Exception):
    def __init__(self, detail: str, missing: bool = False) -> None:
        super().__init__(detail)
        self.missing = missing


def read_untrusted(path: Path, cap: int) -> bytes:
    """Read one sandbox output file once (09 3.5: the sandbox is untrusted).

    No symlink is followed (O_NOFOLLOW), the opened file must be a regular file under `cap`
    bytes (fstat on the descriptor, so a swap after the check is read as the checked file);
    O_NONBLOCK keeps a planted FIFO from blocking the supervisor.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise UntrustedOutput(f"{path.name} missing", missing=True) from exc
    except OSError as exc:  # ELOOP for a symlink, ENXIO for a FIFO without a writer
        raise UntrustedOutput(f"{path.name} not openable as a regular file: {exc.strerror}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UntrustedOutput(f"{path.name} is not a regular file")
        if st.st_size > cap:
            raise UntrustedOutput(f"{path.name} over {cap} bytes")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                raise UntrustedOutput(f"{path.name} over {cap} bytes")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


RESULT_CODES = {"ok", "schema", "table_attr", "diagram_fit", "late_gate", "timeout", "layout_overflow", "empty_page",
                "chrome_start", "net_request", "page_limit", "fonts", "banner", "size_limit"}


def read_result(out: Path) -> dict[str, Any]:
    """result.json from the sandbox: size-capped, shape-checked, code from the closed 08 set."""
    raw = read_untrusted(out / "result.json", MAX_RESULT_BYTES)
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise UntrustedOutput("result.json is not JSON") from exc
    if not isinstance(result, dict) or result.get("code") not in RESULT_CODES:
        raise UntrustedOutput("result.json code outside the 08 set")
    result["detail"] = str(result.get("detail", ""))[:400]
    pages = result.get("pages")
    if pages is not None and (not isinstance(pages, int) or isinstance(pages, bool) or not 0 <= pages <= 10_000):
        raise UntrustedOutput("result.json pages invalid")
    for k in ("pdf_sha256", "screen_sha256"):
        v = result.get(k)
        if v is not None and not (isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)):
            raise UntrustedOutput(f"result.json {k} invalid")
    fonts = result.get("fonts")
    if fonts is not None and not (isinstance(fonts, list) and all(isinstance(f, str) and len(f) <= 80 for f in fonts)):
        raise UntrustedOutput("result.json fonts invalid")
    return result


def _upload(files: dict[str, bytes], report_json: bytes, report_id: str, render_no: int) -> str:
    """Write exactly the bytes read and hashed from the sandbox output; never copy by path."""
    prefix = f"reports/{report_id}/{render_no}/"
    dest = store_root() / prefix
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("report.pdf", "screen.html"):
        (dest / name).write_bytes(files[name])  # bytes held in memory: PDF hashed, screen built here
    (dest / "report.json").write_bytes(report_json)  # supervisor-written, not sandbox output
    return prefix


def _default_days() -> int:
    from .assemble import _limits

    return int(_limits()["report"]["default_days"])


async def _render_no(conn: psycopg.AsyncConnection, report_id: str) -> int:
    row = await (await conn.execute("select pdf_sha256s from reports where report_id = %s", (report_id,))).fetchone()
    return len(row[0]) + 1 if row else 1


async def _upsert_report(conn: psycopg.AsyncConnection, report: dict[str, Any], extras: dict[str, Any], job_id: str,
                         prefix: str, sha: str, expires_at: datetime) -> None:
    m = report["meta"]
    await conn.execute(
        """
        insert into reports (report_id, report_id_short, job_id, profile, object_prefix, out_name, pdf_sha256s,
                             subject_candidates, key_version, rendered_at, expires_at)
        values (%(rid)s, %(short)s, %(job)s, %(profile)s, %(prefix)s, %(out)s, array[%(sha)s]::char(64)[],
                %(cands)s, %(kv)s, now(), %(exp)s)
        on conflict (report_id) do update set
          profile = excluded.profile, object_prefix = excluded.object_prefix, out_name = excluded.out_name,
          pdf_sha256s = reports.pdf_sha256s || excluded.pdf_sha256s, subject_candidates = excluded.subject_candidates,
          refresh_code = null, rendered_at = now()
        """,
        {"rid": m["report_id"], "short": m["report_id_short"], "job": job_id, "profile": m["profile"], "prefix": prefix,
         "out": m["out_name"], "sha": sha, "cands": psycopg.types.json.Jsonb(extras["subject_candidates"]),
         "kv": current_key_version(), "exp": expires_at},
    )


# Source kinds whose reports are public by nature and published automatically (see below).
AUTO_PUBLISH_SOURCE_KINDS = frozenset({"deployed", "repo"})


async def _auto_enqueue_publish(conn: psycopg.AsyncConnection, report_id: str, job_id: str,
                                render_ts: str, profile: str | None = None) -> None:
    """Enqueue automatic publication inside the rendered-transition transaction (CEO 2026-10-24).

    Inserts one publish_consent_log row (the legal basis) and one publish_requests row
    (idempotent: on conflict do nothing).  Both operations are inside the caller's open
    transaction so they roll back atomically if anything else in that block fails.

    Called only when outcome.code == "ok" and the job is not deleted.  A re-render of the
    same job produces a second consent log entry (correct: a new render = a new consent event)
    but the publish_requests dedup (UNIQUE report_id) prevents a duplicate request.

    Skipped when any of the following conditions hold:
    - ``source_kind`` is not in AUTO_PUBLISH_SOURCE_KINDS (i.e. not deployed or repo).
      ``upload`` (private code through a one-time link) and ``files`` (code pasted into the
      conversation) may be private, and the report quotes that code.
    - The job has any inline context item (``url`` is None), meaning the requester supplied
      private content that may be quoted in the report context section.
    - The report profile is ``owner`` — the requester is the contract owner and has not
      explicitly opted into public disclosure via review_publish.
    In all such cases the report is published only when the owner calls review_publish with
    the manage key.
    """
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "select source_kind, context_items, terms_accepted_at from jobs where job_id = %s",
            (job_id,),
        )
        row = await cur.fetchone()
    if row is None:
        return
    if row["source_kind"] not in AUTO_PUBLISH_SOURCE_KINDS:
        return
    # Skip if any context item was supplied inline (url is None = pasted content, not a URL fetch).
    context_items: list[dict[str, Any]] = row["context_items"] or []
    if any(item.get("url") is None for item in context_items):
        return
    # Skip for owner-profile reports — they contain owner-only context by design.
    if profile == "owner":
        return

    # Build the consent statement, referencing the recorded acceptance timestamp when available.
    terms_accepted_at = row["terms_accepted_at"]
    if terms_accepted_at is not None:
        accepted_str = str(terms_accepted_at)[:19].replace("T", " ")  # "YYYY-MM-DD HH:MM:SS"
        statement = (
            f"By submitting source code for this review, the requester accepted the "
            f"Contract Review MCP Terms of Use at soken.dev/mcp/terms.html "
            f"(recorded {accepted_str} UTC), "
            f"which authorises automated publication of this rendered report."
        )
    else:
        statement = AUTO_PUBLISH_STATEMENT

    await conn.execute(
        """insert into publish_consent_log (report_id, party, name, statement, client_ts)
           values (%s, %s, %s, %s, %s)""",
        (report_id, AUTO_PUBLISH_PARTY, AUTO_PUBLISH_NAME, statement, render_ts),
    )
    await conn.execute(
        """insert into publish_requests (report_id, job_id, status)
           values (%s, %s, 'queued')
           on conflict (report_id) do nothing""",
        (report_id, job_id),
    )


async def _job_deleted(pool: Any, job_id: str) -> bool:
    async with pool.connection() as conn:
        row = await (await conn.execute("select state from jobs where job_id = %s", (job_id,))).fetchone()
    return row is None or row[0] == "deleted"


async def run_render_step(pool: Any, step: dict[str, Any], pin_root: Path, *, image: str | None = None) -> RenderOutcome:
    """Run one claimed render row end to end; returns the outcome (08 3.1, 3.2).

    An unexpected supervisor fault after the job entered `rendering` ends in `render_failed`
    with detail `internal`, so no job is left in `rendering` (03 3.2 exhaustion, alert).
    """
    try:
        return await _run_render_step(pool, step, pin_root, image=image)
    except Exception as exc:
        logger.exception("render step crashed for %s", step["job_id"][-8:])
        async with pool.connection() as conn:
            state = await (await conn.execute("select state from jobs where job_id = %s", (step["job_id"],))).fetchone()
        if state and state[0] == "rendering":
            return await _finish_failed(pool, step["id"], step["job_id"], "internal", str(exc)[:300], 0)
        raise


async def _run_render_step(pool: Any, step: dict[str, Any], pin_root: Path, *, image: str | None) -> RenderOutcome:
    job_id, step_id = step["job_id"], step["id"]
    prov = step.get("provenance") or {}
    budget = prov if prov.get("retry_of") else {}
    attempt = int(budget.get("attempt", 0)) + 1
    first_claim = float(budget.get("first_claim", time.time()))
    compact = bool(budget.get("compact", False))
    async with pool.connection() as conn, conn.transaction():
        await JobRepo(conn).transition(job_id, "rendering")

    try:
        async with pool.connection() as conn:
            report, extras = await assemble_report(conn, job_id, pin_root)
            render_no = await _render_no(conn, report["meta"]["report_id"])
    except (AssemblyError, BuildError) as err:
        logger.error("assembly failed for %s: %s", job_id[-8:], err)
        return await _finish_failed(pool, step_id, job_id, err.code, err.detail, attempt)
    report_bytes = json.dumps(report, ensure_ascii=False, indent=1).encode("utf-8")
    render_dir = fresh_render_dir(report_bytes)
    try:
        t0 = time.monotonic()
        outcome = await asyncio.get_running_loop().run_in_executor(
            None, lambda: run_container(render_dir, compact=compact, image=image or render_image()))
        wall_ms = int((time.monotonic() - t0) * 1000)
        if outcome.code == "ok":
            outcome.files["screen.html"] = build_screen_html(report, bool(outcome.result.get("compact")))
    finally:
        shutil.rmtree(render_dir, ignore_errors=True)  # fresh dir under the supervisor-only root
    logger.info("render %s attempt %d: %s %s (%d ms)", job_id[-8:], attempt, outcome.code, outcome.detail[:120], wall_ms)

    if outcome.code == "ok":
        if await _job_deleted(pool, job_id):
            # review_delete_job ran while the container rendered: nothing of the job may land on
            # disk or in the DB after the delete answered (security review, 2026-10-23).
            logger.info("render %s: job deleted during the render, output discarded", job_id[-8:])
            async with pool.connection() as conn:
                await conn.execute("update job_steps set status = 'cancelled', cancel_reason = 'user_delete' where id = %s",
                                   (step_id,))
            return outcome
        prefix = _upload(outcome.files, report_bytes, report["meta"]["report_id"], render_no)
        exp = datetime.now(UTC) + timedelta(days=_default_days())
        render_ts = datetime.now(UTC).isoformat()
        async with pool.connection() as conn, conn.transaction():
                await _upsert_report(conn, report, extras, job_id, prefix, outcome.pdf_sha256, exp)
                repo = JobRepo(conn)
                await repo.complete_step(step_id, "done", exit_code=0, provenance={
                    "attempt": attempt, "pages": outcome.pages, "pdf_sha256": outcome.pdf_sha256, "image": image or render_image(),
                    "wall_ms": wall_ms, "compact": compact, "fonts": outcome.result.get("fonts")})
                await repo.transition(job_id, "rendered")
                await conn.execute("update jobs set expires_at = %s where job_id = %s", (exp, job_id))
                # Auto-publish: enqueue in the same transaction (CEO 2026-10-24).
                await _auto_enqueue_publish(
                    conn, report["meta"]["report_id"], job_id, render_ts,
                    profile=report.get("meta", {}).get("profile"),
                )
        return outcome

    elapsed = time.time() - first_claim
    retry_compact = outcome.code == "page_limit" and not compact
    retry = (outcome.code in RETRIED or retry_compact) and attempt < MAX_ATTEMPTS
    delay = BACKOFF_S.get(attempt + 1, 20)
    if retry and elapsed + delay < TOTAL_S:
        async with pool.connection() as conn, conn.transaction():
            repo = JobRepo(conn)
            await repo.complete_step(step_id, "failed", error_code="E_RENDER_FAILED", provenance={
                "attempt": attempt, "detail": outcome.code, "first_claim": first_claim, "compact": compact})
            await repo.transition(job_id, "render_queued")
            await repo.insert_step(job_id=job_id, step="render", container=True, units=RENDER_UNITS,
                                   ram_mb=RENDER_RAM_MB, priority=RENDER_PRIORITY, max_attempts=1,
                                   not_before_secs=delay)
            await conn.execute(
                "update job_steps set provenance = %s where id = (select max(id) from job_steps where job_id = %s)",
                (psycopg.types.json.Jsonb({"retry_of": step_id, "attempt": attempt, "first_claim": first_claim,
                                           "compact": compact or retry_compact}), job_id))
        return outcome
    return await _finish_failed(pool, step_id, job_id, outcome.code, outcome.detail, attempt)


async def _finish_failed(pool: Any, step_id: int, job_id: str, code: str, detail: str, attempt: int) -> RenderOutcome:
    async with pool.connection() as conn, conn.transaction():
        repo = JobRepo(conn)
        await repo.complete_step(step_id, "failed", error_code="E_RENDER_FAILED",
                                 provenance={"attempt": attempt, "detail": code})
        await repo.transition(job_id, "render_failed", error_code="E_RENDER_FAILED",
                              error_detail={"detail": code, "note": detail[:300]})
        # Quota refund: a report that never rendered must not count (quota.py counts report_at).
        # Clearing report_at and report_id here means the finalize check at the next attempt
        # will re-issue them under the advisory lock, keeping the count correct.
        await conn.execute(
            "update jobs set report_at = null, report_id = null where job_id = %s",
            (job_id,),
        )
    logger.error("render failed for %s: %s %s", job_id[-8:], code, detail[:200])
    return RenderOutcome(code, detail)


async def report_row(conn: psycopg.AsyncConnection, job_id: str) -> dict[str, Any] | None:
    async with conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("select * from reports where job_id = %s", (job_id,))
        return await cur.fetchone()
