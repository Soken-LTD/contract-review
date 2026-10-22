"""Publish worker: push a rendered PDF to Soken-LTD/smart-contract-audits and trigger
soken.dev refresh.

Design contract (CEO security model):
  - Content is our PDF from our object store — never client-supplied bytes.
  - The git push uses a fixed argument array (no shell interpolation of report metadata).
  - Untrusted data (safe_filename, report_id) is validated by sanitize_filename() before
    it ever appears in any command or path operation.
  - Credentials live entirely in env vars; this module never prints or logs them.
  - GitPublisher and SitePublisher are injectable interfaces so the worker is
    testable without real git or network calls.

Cross-host topology: mcp.soken.dev (this server) is a different box than soken.dev prod.
The SitePublisher interface provides a hook-point for a least-privilege HTTP call to the
prod box trigger endpoint.  The concrete EnvSitePublisher reads the endpoint URL and bearer
token from environment variables (SOKEN_SITE_REFRESH_URL, SOKEN_SITE_REFRESH_TOKEN) which
are set on the mcp.soken.dev box; they are never returned to clients or logged.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path

import psycopg_pool
from psycopg.rows import dict_row

from ..report.render import store_root

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Filename sanitization (security: no shell metacharacters, no path traversal)
# ---------------------------------------------------------------------------

# Allowlist: alphanumeric, dot, hyphen, underscore.  Anything else becomes '-'.
_UNSAFE_CHAR_RE = re.compile(r"[^A-Za-z0-9._-]")
# Collapse consecutive hyphens/dots to a single hyphen.
_MULTI_SEP_RE = re.compile(r"[-_.]{2,}")
# Maximum prefix length before the report_id suffix (avoids excessively long filenames).
_MAX_PREFIX_LEN = 60


def sanitize_filename(title: str, report_id: str) -> str:
    """Return a safe ASCII filename for the published PDF.

    Properties guaranteed:
      - Only chars in [A-Za-z0-9._-] (no shell metacharacters, no path separators).
      - No leading/trailing separators.
      - Always ends with _<report_id[:8]>.pdf for uniqueness.
      - report_id is validated to contain only [a-z2-7] before embedding.
    """
    # Validate report_id before embedding (allowlist: [a-z2-7] only, 8-26 chars).
    # The DB column is exactly 26 chars; we also accept shorter IDs in tests.
    if not re.fullmatch(r"[a-z2-7]{8,26}", report_id):
        raise ValueError(f"report_id {report_id!r:.30} fails allowlist check")

    safe = _UNSAFE_CHAR_RE.sub("-", title)
    safe = _MULTI_SEP_RE.sub("-", safe).strip("-._")
    safe = safe[:_MAX_PREFIX_LEN] or "report"
    return f"{safe}_{report_id[:8]}.pdf"


# Subject is untrusted (derived from the reviewed project's metadata) and is rendered into a
# Markdown TABLE CELL in our public README. Neutralise every character that could break out of
# the cell or inject markup: pipe (column break), CR/LF/TAB (row break), backtick (code span),
# angle brackets (HTML/autolink) and square brackets (link/image), plus other control chars.
# Display-only; the PDF content is unaffected. Closes the README markdown-injection vector.
_CELL_BREAKERS_RE = re.compile(r"[|`<>\[\]\r\n\t]")
_CELL_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_CELL_WS_RE = re.compile(r"\s{2,}")


def sanitize_cell(subject: str) -> str:
    """Return a one-line, Markdown-table-safe rendering of an untrusted subject string."""
    s = _CELL_BREAKERS_RE.sub(" ", subject)
    s = _CELL_CTRL_RE.sub("", s)
    s = _CELL_WS_RE.sub(" ", s).strip()
    return s[:100] or "Security review"


# ---------------------------------------------------------------------------
# Injectable interfaces
# ---------------------------------------------------------------------------

GITHUB_REPO_NAME = "Soken-LTD/smart-contract-audits"
GITHUB_RAW_BASE = "https://github.com/" + GITHUB_REPO_NAME + "/blob/main"


class GitPublisher(ABC):
    """Push one PDF to the public audits repository.

    The concrete implementation (EnvGitPublisher) clones the repo into a temp dir,
    writes the PDF with O_CREAT|O_EXCL (prevents overwrite), commits and pushes.
    All git argv arrays are fixed; report metadata never enters via string interpolation.
    """

    @abstractmethod
    def push_report(self, pdf_bytes: bytes, safe_filename: str, subject: str, report_id: str) -> str:
        """Push PDF; return the public URL of the committed file."""
        ...


class SitePublisher(ABC):
    """Trigger soken.dev to refresh its audits page from the GitHub repo."""

    @abstractmethod
    def trigger_fetch(self) -> None:
        """Fire the refresh; raise on failure."""
        ...


# ---------------------------------------------------------------------------
# Concrete implementations (production)
# ---------------------------------------------------------------------------

class EnvGitPublisher(GitPublisher):
    """Production git publisher.  Reads all config from environment variables.

    Required env vars:
      SOKEN_GIT_PUBLISH_REPO_PATH  — absolute path to a local clone of smart-contract-audits
                                     (pre-configured with origin = GitHub remote).
      SOKEN_GIT_PUBLISH_TOKEN      — GitHub PAT with 'repo' scope (used in remote URL,
                                     never printed).

    Optional:
      SOKEN_GIT_PUBLISH_AUTHOR_NAME   default "SokenDev"
      SOKEN_GIT_PUBLISH_AUTHOR_EMAIL  default "k.manko@soken.dev"

    Security: all git calls use subprocess with a fixed argv list (no shell=True, no
    f-strings that embed report metadata into the command string itself).  The
    safe_filename and PDF bytes are the only data that touch the repo; safe_filename has
    already been through sanitize_filename() by the time it arrives here.
    """

    def push_report(self, pdf_bytes: bytes, safe_filename: str, subject: str, report_id: str) -> str:
        repo_path = os.environ.get("SOKEN_GIT_PUBLISH_REPO_PATH", "")
        if not repo_path:
            raise RuntimeError("SOKEN_GIT_PUBLISH_REPO_PATH is not set")
        token = os.environ.get("SOKEN_GIT_PUBLISH_TOKEN", "")
        author_name = os.environ.get("SOKEN_GIT_PUBLISH_AUTHOR_NAME", "SokenDev")
        author_email = os.environ.get("SOKEN_GIT_PUBLISH_AUTHOR_EMAIL", "k.manko@soken.dev")

        repo = Path(repo_path)
        if not repo.is_dir():
            raise RuntimeError(f"git repo path does not exist: {repo_path}")

        pdf_dest = repo / safe_filename

        # Write PDF — O_CREAT|O_EXCL prevents overwrite (idempotent guard at FS level).
        # If the file already exists this is a duplicate publish; skip write but still push.
        try:
            fd = os.open(str(pdf_dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            try:
                os.write(fd, pdf_bytes)
            finally:
                os.close(fd)
        except FileExistsError:
            logger.info("publish: %s already in repo, skipping write", safe_filename)

        env = {**os.environ}
        if token:
            # Inject token into remote URL via git credential helper env approach.
            # We set GIT_ASKPASS to echo the token; git calls it when prompted.
            # This never touches the command-line arguments.
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False, prefix="gask-") as f:
                f.write(f"#!/bin/sh\necho '{token}'\n")
                askpass = f.name
            os.chmod(askpass, 0o700)
            env["GIT_ASKPASS"] = askpass
        else:
            askpass = None

        try:
            def _run(*argv: str) -> None:
                result = subprocess.run(
                    list(argv),
                    cwd=str(repo),
                    env=env,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                logger.debug("git %s: %s", argv[1] if len(argv) > 1 else "", result.stdout[:200])

            # Pull latest so README edits don't conflict.
            _run("git", "-C", str(repo), "pull", "--ff-only", "origin", "main")

            # Stage the PDF.
            _run("git", "-C", str(repo), "add", safe_filename)

            # Update README: prepend table row and bump report count.
            _update_readme(repo, safe_filename, subject, report_id)
            _run("git", "-C", str(repo), "add", "README.md")

            # Commit with fixed author identity.
            _run(
                "git", "-C", str(repo),
                "-c", f"user.name={author_name}",
                "-c", f"user.email={author_email}",
                "commit", "--no-gpg-sign",
                "-m", f"Add audit report {safe_filename}",
            )

            # Push to origin main.
            _run("git", "-C", str(repo), "push", "origin", "main")

        finally:
            if askpass:
                try:
                    os.unlink(askpass)
                except OSError:
                    pass

        return f"{GITHUB_RAW_BASE}/{safe_filename}"


def _update_readme(repo: Path, safe_filename: str, subject: str, report_id: str) -> None:
    """Prepend a row to the audits table in README.md and bump the reports counter.

    The README is our own file.  We still sanitize subject for display only.
    report_id is already validated (base32 charset) before calling this function.
    """
    readme = repo / "README.md"
    if not readme.exists():
        readme.write_text(
            "# Soken Smart Contract Audits\n\n## Reports (1)\n\n"
            "| Report | PDF |\n| --- | --- |\n"
            f"| {sanitize_cell(subject)} | [{safe_filename}](./{safe_filename}) |\n",
            encoding="utf-8",
        )
        return

    text = readme.read_text(encoding="utf-8")
    # Bump the count in "## Reports (N)"
    import re as _re
    def _bump(m: re.Match) -> str:
        n = int(m.group(1)) + 1
        return f"## Reports ({n})"
    text = _re.sub(r"## Reports \((\d+)\)", _bump, text)

    # Prepend a row right after the table header line.
    new_row = f"| {sanitize_cell(subject)} | [{safe_filename}](./{safe_filename}) |\n"
    header_marker = "| Report | PDF |\n| --- | --- |\n"
    if header_marker in text:
        text = text.replace(header_marker, header_marker + new_row, 1)
    else:
        # No table yet: append section.
        text = text.rstrip() + f"\n\n## Reports (1)\n\n| Report | PDF |\n| --- | --- |\n{new_row}"

    readme.write_text(text, encoding="utf-8")


class EnvSitePublisher(SitePublisher):
    """Production site publisher.

    Fires an HTTP POST to SOKEN_SITE_REFRESH_URL with Bearer SOKEN_SITE_REFRESH_TOKEN.
    Both are injected at deploy time on the mcp.soken.dev box; never echoed to clients.

    When SOKEN_SITE_REFRESH_URL is not set, this is a no-op (useful during initial
    stand-up before the endpoint is wired).
    """

    def trigger_fetch(self) -> None:
        url = os.environ.get("SOKEN_SITE_REFRESH_URL", "")
        token = os.environ.get("SOKEN_SITE_REFRESH_TOKEN", "")
        if not url:
            logger.info("SOKEN_SITE_REFRESH_URL not set; skipping site refresh")
            return
        req = urllib.request.Request(
            url,
            method="POST",
            data=b"",
            headers={
                "Authorization": f"Bearer {token}" if token else "",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 202, 204):
                raise RuntimeError(f"site refresh returned HTTP {resp.status}")
        logger.info("site refresh triggered: %s", url)


# ---------------------------------------------------------------------------
# Publish worker
# ---------------------------------------------------------------------------

class PublishWorker:
    """Process one queued publish_request row end-to-end.

    Injecting git_publisher and site_publisher makes this testable without
    real git or network calls.
    """

    def __init__(
        self,
        pool: psycopg_pool.AsyncConnectionPool,
        git_publisher: GitPublisher | None = None,
        site_publisher: SitePublisher | None = None,
    ) -> None:
        self._pool = pool
        self._git = git_publisher or EnvGitPublisher()
        self._site = site_publisher or EnvSitePublisher()

    async def run_one(self, request_id: int) -> None:
        """Claim and process a single publish_request row.

        Transitions: queued -> publishing -> published | failed.
        All errors are caught and written to error_detail; the row ends in 'failed'
        rather than leaving the worker in an undefined state.
        """
        try:
            await self._do_publish(request_id)
        except Exception as exc:
            logger.exception("publish_worker: request %d failed", request_id)
            await self._mark(request_id, "failed", error_detail=str(exc)[:400])

    async def run_queued(self) -> int:
        """Claim and run all queued requests.  Returns count processed."""
        async with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select id from publish_requests where status = 'queued' order by queued_at limit 20"
            )
            rows = await cur.fetchall()
        count = 0
        for row in rows:
            await self.run_one(row["id"])
            count += 1
        return count

    async def _do_publish(self, request_id: int) -> None:
        # Load the request row.
        async with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "select pr.*, r.object_prefix, r.out_name, j.job_id as _jid "
                "from publish_requests pr "
                "join reports r on r.report_id = pr.report_id "
                "join jobs j on j.job_id = pr.job_id "
                "where pr.id = %s",
                (request_id,),
            )
            req = await cur.fetchone()
        if req is None:
            raise RuntimeError(f"publish_request {request_id} not found")
        if req["status"] not in ("queued", "failed"):
            logger.info("publish_request %d already in status %s; skipping", request_id, req["status"])
            return

        # Transition to publishing.
        await self._mark(request_id, "publishing")

        report_id: str = req["report_id"]
        object_prefix: str = req["object_prefix"]
        out_name: str = req["out_name"]

        # Read PDF from our object store (not from client input).
        pdf_path = store_root() / object_prefix / "report.pdf"
        if not pdf_path.exists():
            raise RuntimeError(f"PDF not found at object store path: {object_prefix}report.pdf")
        pdf_bytes = pdf_path.read_bytes()

        # Sanitize the filename used in git (re-derive from out_name for determinism).
        # out_name is already a validated '^[A-Za-z0-9_-]{1,76}\.pdf$' column per migration 003.
        # We additionally run it through sanitize_filename for belt-and-braces.
        base_title = out_name.removesuffix(".pdf")
        safe_filename = sanitize_filename(base_title, report_id)

        # Read subject from the report.json for the README row.
        import json as _json
        report_json_path = store_root() / object_prefix / "report.json"
        subject = report_id  # fallback
        if report_json_path.exists():
            try:
                rj = _json.loads(report_json_path.read_text(encoding="utf-8"))
                subject = rj.get("meta", {}).get("subject", subject)
            except (OSError, ValueError, KeyError) as exc:
                logger.warning("publish_worker: could not read subject from report.json: %s", exc)

        # Push to git repo.
        public_url = self._git.push_report(pdf_bytes, safe_filename, subject, report_id)

        # Update safe_filename and public_url on the request row before triggering the site.
        async with self._pool.connection() as conn:
            await conn.execute(
                "update publish_requests set safe_filename = %s, updated_at = now() where id = %s",
                (safe_filename, request_id),
            )

        # Trigger site refresh.
        self._site.trigger_fetch()

        # Mark published.
        await self._mark(request_id, "published", public_url=public_url)
        logger.info("published report %s -> %s", report_id, public_url)

    async def _mark(
        self,
        request_id: int,
        status: str,
        *,
        public_url: str | None = None,
        error_detail: str | None = None,
    ) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                """update publish_requests
                   set status = %s,
                       public_url = coalesce(%s, public_url),
                       error_detail = coalesce(%s, error_detail),
                       updated_at = now()
                   where id = %s""",
                (status, public_url, error_detail, request_id),
            )
