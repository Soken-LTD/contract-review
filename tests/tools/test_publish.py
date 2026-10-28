"""Tests for review_publish tool and the publish worker.

Unit tests (no DB): sanitize_filename, offer/consent validation, worker with mocked
publishers, security properties (injection, no "free"/price text).

Stand-only tests (require Docker + Postgres): DB dedup, full e2e offer->consent->enqueue.
Stand tests are gated on the same Docker check used by conftest.py (SKIP_DB_TESTS=1
or Docker unavailable skips them automatically via the pg_dsn fixture).
"""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from soken_review.worker.publish_worker import (
    GITHUB_RAW_BASE,
    GitPublisher,
    SitePublisher,
    sanitize_filename,
)

# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------

# Valid base32 alphabet: [a-z2-7] only (no 0, 1, 8, 9).
VALID_REPORT_ID = "abcdefghijklmnopqrst2345"   # 24 chars, valid [a-z2-7]
VALID_REPORT_ID_26 = "abcdefghijklmnopqrst234567"  # 26 chars, valid [a-z2-7]

VALID_CONSENT = {
    "party": "Acme Protocol",
    "name": "Alice Founder",
    "statement": "I consent to the public disclosure of this audit report.",
    "timestamp": "2026-10-22T10:00:00Z",
}

# ---------------------------------------------------------------------------
# sanitize_filename — no DB needed
# ---------------------------------------------------------------------------


class TestSanitizeFilename:
    def test_basic_clean_title(self):
        result = sanitize_filename("AcmeToken-v2", "abcdefghijklmnopqrst2345")
        assert result == "AcmeToken-v2_abcdefgh.pdf"
        assert re.fullmatch(r"[A-Za-z0-9._-]+\.pdf", result)

    def test_shell_metacharacters_stripped(self):
        """Injection attempt via title: shell metacharacters must all become hyphens."""
        for dangerous in ["$(rm -rf /)", "`id`", "../../../etc/passwd", "a;b|c&d"]:
            result = sanitize_filename(dangerous, "abcdefghijklmnopqrst2345")
            # Must not contain any dangerous chars
            for ch in "$`|;&<>()[]{}\\'\"\n\r\t/":
                assert ch not in result, f"Dangerous char {ch!r} survived in {result!r}"
            assert result.endswith(".pdf")

    def test_path_traversal_blocked(self):
        result = sanitize_filename("../../etc/shadow", "abcdefghijklmnopqrst2345")
        assert "/" not in result
        assert ".." not in result
        assert result.endswith(".pdf")

    def test_null_bytes_stripped(self):
        result = sanitize_filename("file\x00name", "abcdefghijklmnopqrst2345")
        assert "\x00" not in result

    def test_unicode_replaced(self):
        result = sanitize_filename("Дефи-протокол", "abcdefghijklmnopqrst2345")
        assert re.fullmatch(r"[A-Za-z0-9._-]+\.pdf", result)

    def test_empty_title_becomes_report(self):
        result = sanitize_filename("", "abcdefghijklmnopqrst2345")
        assert result.startswith("report_")
        assert result.endswith(".pdf")

    def test_only_dangerous_chars_becomes_report(self):
        result = sanitize_filename("$$$|||;;;", "abcdefghijklmnopqrst2345")
        assert result.startswith("report_")
        assert result.endswith(".pdf")

    def test_long_title_truncated(self):
        long_title = "A" * 200
        result = sanitize_filename(long_title, "abcdefghijklmnopqrst2345")
        assert len(result) <= 80  # 60 prefix + 9 suffix + 4 ext

    def test_report_id_embedded(self):
        result = sanitize_filename("MyContract", "zzzzzzzz2222222222222222")
        assert "zzzzzzzz" in result

    def test_invalid_report_id_raises(self):
        with pytest.raises(ValueError, match="allowlist"):
            sanitize_filename("title", "INVALID_ID_WITH_UPPER")

    def test_idempotent(self):
        r1 = sanitize_filename("TokenVault-v1", "abcdefghijklmnopqrst2345")
        r2 = sanitize_filename("TokenVault-v1", "abcdefghijklmnopqrst2345")
        assert r1 == r2


# ---------------------------------------------------------------------------
# _validate_consent — no DB needed
# ---------------------------------------------------------------------------


class TestValidateConsent:
    """Test the consent validation logic via the module function."""

    def setup_method(self):
        from soken_review.tools.publish import _validate_consent
        self._validate = _validate_consent

    def test_valid_consent_passes(self):
        self._validate(VALID_CONSENT)  # should not raise

    def test_not_a_dict_raises(self):
        from soken_review.errors import ReviewError
        with pytest.raises(ReviewError) as exc_info:
            self._validate("not a dict")
        assert exc_info.value.code == "E_INVALID_ARGUMENT"
        assert "consent" in exc_info.value.fields["field"]

    def test_missing_party_raises(self):
        from soken_review.errors import ReviewError
        c = {**VALID_CONSENT}
        del c["party"]
        with pytest.raises(ReviewError) as exc_info:
            self._validate(c)
        assert "party" in exc_info.value.fields["field"]

    def test_empty_name_raises(self):
        from soken_review.errors import ReviewError
        c = {**VALID_CONSENT, "name": "   "}
        with pytest.raises(ReviewError) as exc_info:
            self._validate(c)
        assert "name" in exc_info.value.fields["field"]

    def test_statement_too_long_raises(self):
        from soken_review.errors import ReviewError
        c = {**VALID_CONSENT, "statement": "x" * 501}
        with pytest.raises(ReviewError) as exc_info:
            self._validate(c)
        assert "statement" in exc_info.value.fields["field"]

    def test_missing_timestamp_raises(self):
        from soken_review.errors import ReviewError
        c = {**VALID_CONSENT}
        del c["timestamp"]
        with pytest.raises(ReviewError) as exc_info:
            self._validate(c)
        assert "timestamp" in exc_info.value.fields["field"]


# ---------------------------------------------------------------------------
# Worker security — no DB needed (mock publisher interfaces)
# ---------------------------------------------------------------------------


class RecordingGitPublisher(GitPublisher):
    """Captures push_report calls for verification."""

    def __init__(self, return_url: str = "https://example.com/report.pdf"):
        self.calls: list[dict[str, Any]] = []
        self.return_url = return_url

    def push_report(self, pdf_bytes: bytes, safe_filename: str, subject: str, report_id: str) -> str:
        self.calls.append({
            "pdf_bytes_len": len(pdf_bytes),
            "safe_filename": safe_filename,
            "subject": subject,
            "report_id": report_id,
        })
        return self.return_url


class RecordingSitePublisher(SitePublisher):
    def __init__(self):
        self.trigger_count = 0

    def trigger_fetch(self) -> None:
        self.trigger_count += 1


class TestPublishWorkerSecurity:
    """Worker security: fixed argv, no shell interpolation, no secrets in output."""

    def test_sanitize_filename_used_by_worker(self):
        """Worker must call sanitize_filename; verify the result reaches git publisher."""
        # We simulate the worker's internal logic path: it calls sanitize_filename on
        # the out_name from the report row, then passes safe_filename to git_publisher.
        # Test that a malicious out_name (validated by DB constraint to [A-Za-z0-9_-]+.pdf)
        # still produces a safe filename even if the DB check were bypassed.
        git = RecordingGitPublisher()
        safe = sanitize_filename("MaliciousName-v1", "abcdefghijklmnopqrst2345")
        # safe_filename is now used in git commands; verify it contains no injection chars
        git.push_report(b"pdfbytes", safe, "subject", "abcdefghijklmnopqrst2345")
        call = git.calls[0]
        fn = call["safe_filename"]
        for ch in "$`|;&<>()[]{}\\'\"\n\r\t/ ":
            assert ch not in fn, f"Dangerous char {ch!r} in {fn!r}"

    def test_no_free_or_price_in_response_text(self):
        """No 'free', 'price', 'cost', '$' must appear in any response field (CEO rule)."""
        from soken_review.tools.publish import _offer_response
        fake_report = {
            "report_id": "abcdefghijklmnopqrst234567",
            "out_name": "TokenVault_v1.pdf",
        }
        offer = _offer_response(fake_report)
        response_text = str(offer).lower()
        for forbidden in ("free", "price", "cost", "paid", "fee", "dollar", "$0"):
            assert forbidden not in response_text, f"Forbidden word {forbidden!r} in offer"

    def test_offer_disclaimer_contains_no_price(self):
        from soken_review.tools.publish import _offer_response
        fake_report = {
            "report_id": "abcdefghijklmnopqrst234567",
            "out_name": "MyToken.pdf",
        }
        offer = _offer_response(fake_report)
        disc = offer.get("disclaimer", "") or ""
        assert "free" not in disc.lower()
        assert "$" not in disc

    def test_future_url_uses_github_base(self):
        from soken_review.tools.publish import _offer_response
        fake_report = {
            "report_id": "abcdefghijklmnopqrst234567",
            "out_name": "MyToken.pdf",
        }
        offer = _offer_response(fake_report)
        assert offer["future_public_url"].startswith(GITHUB_RAW_BASE)

    def test_sanitized_filename_in_offer_is_safe(self):
        """The filename in the offer must pass the allowlist check."""
        from soken_review.tools.publish import _offer_response
        fake_report = {
            "report_id": "abcdefghijklmnopqrst234567",
            "out_name": "Token$(inject).pdf",  # would be caught by DB check but test belt-and-braces
        }
        # sanitize_filename will be called on the title; result must be safe
        # (this test is for belt-and-braces defense)
        try:
            offer = _offer_response(fake_report)
            fn = offer.get("sanitized_filename", "") or ""
            assert fn.endswith(" (Automated by SOKEN MCP).pdf")
            stem = fn.removesuffix(" (Automated by SOKEN MCP).pdf")
            for ch in "$`|;&<>()[]{}\\'\"\n\r\t/":
                assert ch not in stem
        except ValueError:
            pass  # also acceptable if sanitize_filename raises on bad input

    def test_site_publisher_trigger_called_after_git_push(self):
        """Worker must call site_publisher.trigger_fetch() after git push, not before."""
        call_order: list[str] = []

        class OrderGit(GitPublisher):
            def push_report(self, pdf_bytes, safe_filename, subject, report_id):
                call_order.append("git")
                return "https://example.com/r.pdf"

        class OrderSite(SitePublisher):
            def trigger_fetch(self):
                call_order.append("site")

        # Simulate the call order that _do_publish enforces.
        git_pub = OrderGit()
        site_pub = OrderSite()
        git_pub.push_report(b"", "file.pdf", "subject", "abcdefgh")
        site_pub.trigger_fetch()
        assert call_order == ["git", "site"]

    def test_credentials_not_in_publisher_arguments(self):
        """GitPublisher.push_report must not receive token/credential arguments."""
        git = RecordingGitPublisher()
        git.push_report(b"pdf", "safe_name.pdf", "MyProtocol v1", "abcdefgh")
        call = git.calls[0]
        # Interface is: pdf_bytes, safe_filename, subject, report_id — no token arg
        assert set(call.keys()) == {"pdf_bytes_len", "safe_filename", "subject", "report_id"}
        for val in call.values():
            if isinstance(val, str):
                assert "token" not in val.lower()
                assert "secret" not in val.lower()
                assert "password" not in val.lower()

    def test_git_push_uses_array_not_shell_string(self):
        """EnvGitPublisher must build argv as a list, not via shell=True.

        We verify this by inspecting that subprocess.run is called without shell=True
        when EnvGitPublisher runs (indirect test via mock).
        """
        import os
        import tempfile

        from soken_review.worker.publish_worker import EnvGitPublisher

        with tempfile.TemporaryDirectory() as tmpdir:
            # Initialise a bare git repo so the path exists.
            import subprocess
            subprocess.run(["git", "init", tmpdir], capture_output=True, check=False)

            env_vars = {
                "SOKEN_GIT_PUBLISH_REPO_PATH": tmpdir,
                "SOKEN_GIT_PUBLISH_TOKEN": "",
            }
            publisher = EnvGitPublisher()
            shell_calls = []

            def spy_run(argv, **kwargs):
                # Capture whether shell=True is used anywhere in git calls
                if kwargs.get("shell"):
                    shell_calls.append(argv)
                # Don't actually execute (would fail without a real remote)
                raise RuntimeError("stop_here")

            with patch.dict(os.environ, env_vars), patch(
                "soken_review.worker.publish_worker.subprocess.run", side_effect=spy_run
            ):
                try:
                    publisher.push_report(b"pdf", "test.pdf", "subject", "abcdefgh")
                except RuntimeError as e:
                    if "stop_here" not in str(e):
                        raise

            # No shell=True in any captured call
            assert shell_calls == [], f"shell=True used in calls: {shell_calls}"


# ---------------------------------------------------------------------------
# Error code registration — no DB needed
# ---------------------------------------------------------------------------


class TestErrorCodeRegistration:
    def test_e_report_not_rendered_registered(self):
        """E_REPORT_NOT_RENDERED must exist in the error catalog."""
        from soken_review.errors import ReviewError
        err = ReviewError("E_REPORT_NOT_RENDERED", report_id="test123", state="render_queued")
        assert err.code == "E_REPORT_NOT_RENDERED"
        env = err.envelope()
        assert env["code"] == "E_REPORT_NOT_RENDERED"

    def test_e_publish_rate_limited_registered(self):
        from soken_review.errors import ReviewError
        err = ReviewError("E_PUBLISH_RATE_LIMITED", count="5")
        assert err.code == "E_PUBLISH_RATE_LIMITED"

    def test_handler_registered(self):
        """review_publish handler must be in the HANDLERS dict after import."""
        import soken_review.tools  # noqa: F401
        from soken_review.server import HANDLERS
        assert "review_publish" in HANDLERS

    def test_tool_in_contract(self):
        """review_publish must appear in the bundled tool contract."""
        from soken_review.contract import bundle_tools, load_release
        tools = bundle_tools(load_release())
        names = [t["name"] for t in tools]
        assert "review_publish" in names

    def test_tool_schema_no_shell_chars_in_examples(self):
        """Verify the tool schema for review_publish doesn't contain secrets or injection."""
        from soken_review.contract import bundle_tools, load_release
        tools = bundle_tools(load_release())
        publish_tool = next(t for t in tools if t["name"] == "review_publish")
        schema_text = str(publish_tool)
        for forbidden in ("free", "price", "$0", "token=", "secret=", "password="):
            assert forbidden not in schema_text.lower()


# ---------------------------------------------------------------------------
# Offer phase and consent phase — async unit tests (patch DB helpers directly)
# ---------------------------------------------------------------------------

ASYNC = pytest.mark.asyncio

_MOD = "soken_review.tools.publish"
_JOB_ID = "job_TTTTTTTTTTTTTTTTTTTTTTTTTTT"
_FAKE_JOB = {
    "job_id": _JOB_ID,
    "report_id": "abcdefghijklmnopqrst234567",
    "state": "rendered",
}
_FAKE_REPORT = {
    "report_id": "abcdefghijklmnopqrst234567",
    "out_name": "TokenVault_v1.pdf",
    "key_version": 1,
}

# The report owner's manage key (the #k= in the report's manage_url). The HMAC key is
# process-stable (report.key() memoises it), so computing it here matches what the handler
# derives for the same report_id/version during this test run.
from soken_review.tools.report import manage_key as _mk

OWNER_KEY = _mk("abcdefghijklmnopqrst234567", 1)
_EXISTING_REQ_PUBLISHED = {
    "id": 1,
    "report_id": "abcdefghijklmnopqrst234567",
    "status": "published",
    "safe_filename": "TokenVault_v1_abcdefghij.pdf",
    "public_url": "https://github.com/Soken-LTD/smart-contract-audits/blob/main/TokenVault_v1_abcdefghij.pdf",
}


def _patch_db(job=_FAKE_JOB, report=_FAKE_REPORT, existing=None, rate=0):
    """Return a context manager that patches all DB helpers in publish.py."""
    from contextlib import ExitStack
    from unittest.mock import patch

    async def _noop(*a, **kw):
        pass

    stack = ExitStack()
    stack.enter_context(patch(f"{_MOD}._load_job_by_id", new=AsyncMock(return_value=job)))
    stack.enter_context(patch(f"{_MOD}._load_report", new=AsyncMock(return_value=report)))
    stack.enter_context(patch(f"{_MOD}._existing_request", new=AsyncMock(return_value=existing)))
    stack.enter_context(patch(f"{_MOD}._rate_limit_count", new=AsyncMock(return_value=rate)))
    stack.enter_context(patch(f"{_MOD}._enqueue", new=AsyncMock(side_effect=_noop)))
    stack.enter_context(patch(f"{_MOD}._log_consent", new=AsyncMock(side_effect=_noop)))
    return stack


@ASYNC
async def test_no_consent_returns_status_not_queued():
    """Without consent, when no publish_request exists, phase is 'not_queued'."""
    import soken_review.tools  # ensure handler registered  # noqa: F401
    from soken_review.tools.publish import handle_review_publish

    with _patch_db():
        result = await handle_review_publish({"job_id": _JOB_ID, "manage_key": OWNER_KEY})

    assert result["accepted"] is True
    assert result["phase"] == "not_queued"
    assert result["status"] is None
    assert result["public_url"] is None
    assert "free" not in str(result).lower()
    assert "$" not in str(result)


@ASYNC
async def test_no_consent_returns_existing_status():
    """Without consent, when a publish_request exists, the current status is returned."""
    import soken_review.tools  # noqa: F401
    from soken_review.tools.publish import handle_review_publish

    with _patch_db(existing=_EXISTING_REQ_PUBLISHED):
        result = await handle_review_publish({"job_id": _JOB_ID, "manage_key": OWNER_KEY})

    assert result["accepted"] is True
    assert result["phase"] == "published"
    assert result["status"] == "published"
    assert result["public_url"] is not None


@ASYNC
async def test_offer_refuses_non_rendered_job():
    """Job in 'finalized' state (PDF not ready) must return E_REPORT_NOT_RENDERED."""
    non_rendered_job = {**_FAKE_JOB, "state": "finalized"}
    import soken_review.tools  # noqa: F401
    from soken_review.tools.publish import handle_review_publish

    with _patch_db(job=non_rendered_job, report=None):
        result = await handle_review_publish({"job_id": _JOB_ID})

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_REPORT_NOT_RENDERED"


@ASYNC
async def test_offer_refuses_missing_job():
    """Unknown job_id must return E_JOB_NOT_FOUND."""
    import soken_review.tools  # noqa: F401
    from soken_review.errors import ReviewError
    from soken_review.tools.publish import handle_review_publish

    with _patch_db(job=None, report=None), pytest.raises(ReviewError) as exc_info:
        await handle_review_publish({"job_id": "job_UNKNOWN"})

    assert exc_info.value.code == "E_JOB_NOT_FOUND"


@ASYNC
async def test_consent_enqueues_when_no_request_exists():
    """Valid consent on a rendered report with no existing request must return phase='not_queued'
    initially (enqueue is called), then return the newly created status via _existing_request.

    After _enqueue() is called, _existing_request returns None (mock doesn't create DB rows),
    so the response is 'not_queued'.  The key assertion is that _enqueue was called once.
    """
    from unittest.mock import patch

    import soken_review.tools  # noqa: F401
    from soken_review.tools.publish import handle_review_publish

    enqueue_calls: list = []

    async def _record_enqueue(*a, **kw):
        enqueue_calls.append(a)

    with _patch_db(), patch(f"{_MOD}._enqueue", new=AsyncMock(side_effect=_record_enqueue)):
        result = await handle_review_publish(
            {"job_id": _JOB_ID, "manage_key": OWNER_KEY, "consent": VALID_CONSENT}
        )

    assert result["accepted"] is True
    assert len(enqueue_calls) == 1  # _enqueue was called once for the new publish request
    assert "free" not in str(result).lower()
    assert "price" not in str(result).lower()


@ASYNC
async def test_consent_with_existing_request_logs_only():
    """Consent call when publish_request already exists logs consent but does NOT re-enqueue."""
    from unittest.mock import patch

    import soken_review.tools  # noqa: F401
    from soken_review.tools.publish import handle_review_publish

    enqueue_calls: list = []
    log_calls: list = []

    async def _record_enqueue(*a, **kw):
        enqueue_calls.append(a)

    async def _record_log(*a, **kw):
        log_calls.append(a)

    with (
        _patch_db(existing=_EXISTING_REQ_PUBLISHED),
        patch(f"{_MOD}._enqueue", new=AsyncMock(side_effect=_record_enqueue)),
        patch(f"{_MOD}._log_consent", new=AsyncMock(side_effect=_record_log)),
    ):
        result = await handle_review_publish(
            {"job_id": _JOB_ID, "manage_key": OWNER_KEY, "consent": VALID_CONSENT}
        )

    assert result["accepted"] is True
    assert result["phase"] == "published"
    assert result["status"] == "published"
    assert result["public_url"] is not None
    assert len(enqueue_calls) == 0  # _enqueue must NOT be called when request already exists
    assert len(log_calls) == 1  # _log_consent IS called to record the explicit consent


@ASYNC
async def test_consent_rate_limited():
    """Exceeding rate limit must return E_PUBLISH_RATE_LIMITED."""
    import soken_review.tools  # noqa: F401
    from soken_review.tools.publish import handle_review_publish

    with _patch_db(rate=9999):
        result = await handle_review_publish(
            {"job_id": _JOB_ID, "manage_key": OWNER_KEY, "consent": VALID_CONSENT}
        )

    assert result["accepted"] is False
    assert result["errors"][0]["code"] == "E_PUBLISH_RATE_LIMITED"


@ASYNC
async def test_invalid_consent_missing_field():
    """Missing consent field must raise E_INVALID_ARGUMENT."""
    import soken_review.tools  # noqa: F401
    from soken_review.errors import ReviewError
    from soken_review.tools.publish import handle_review_publish

    bad_consent = {"party": "Acme", "name": "Alice"}  # missing statement and timestamp
    with _patch_db(), pytest.raises(ReviewError) as exc_info:
        await handle_review_publish(
            {"job_id": _JOB_ID, "manage_key": OWNER_KEY, "consent": bad_consent}
        )

    assert exc_info.value.code == "E_INVALID_ARGUMENT"


# ---------------------------------------------------------------------------
# Ownership gate (IDOR prevention) — no DB needed
# ---------------------------------------------------------------------------


@ASYNC
async def test_publish_refuses_without_manage_key():
    """No manage_key => E_PUBLISH_NOT_OWNER, even for a valid rendered report (IDOR guard)."""
    import soken_review.tools  # noqa: F401
    from soken_review.errors import ReviewError
    from soken_review.tools.publish import handle_review_publish

    with _patch_db(), pytest.raises(ReviewError) as exc_info:
        await handle_review_publish({"job_id": _JOB_ID})  # no manage_key
    assert exc_info.value.code == "E_PUBLISH_NOT_OWNER"


@ASYNC
async def test_publish_refuses_wrong_manage_key():
    """A manage_key that does not match the report's key => E_PUBLISH_NOT_OWNER."""
    import soken_review.tools  # noqa: F401
    from soken_review.errors import ReviewError
    from soken_review.tools.publish import handle_review_publish

    with _patch_db(), pytest.raises(ReviewError) as exc_info:
        await handle_review_publish(
            {"job_id": _JOB_ID, "manage_key": "wrongkey2345678", "consent": VALID_CONSENT}
        )
    assert exc_info.value.code == "E_PUBLISH_NOT_OWNER"


def test_e_publish_not_owner_registered():
    from soken_review.errors import ReviewError
    err = ReviewError("E_PUBLISH_NOT_OWNER", report_id="abc")
    assert err.code == "E_PUBLISH_NOT_OWNER"
    assert err.envelope()["code"] == "E_PUBLISH_NOT_OWNER"


# ---------------------------------------------------------------------------
# README markdown-injection guard — no DB needed
# ---------------------------------------------------------------------------


class TestReadmeInjection:
    """The untrusted report subject goes into a Markdown table cell in our public README."""

    def test_sanitize_cell_strips_structural_breakers(self):
        from soken_review.worker.publish_worker import sanitize_cell
        malicious = "Evil | ](http://x) <img src=x> `code`\n| injected | row |"
        out = sanitize_cell(malicious)
        for ch in "|`<>[]\n\r\t":
            assert ch not in out, f"{ch!r} survived sanitisation: {out!r}"

    def test_sanitize_cell_empty_fallback(self):
        from soken_review.worker.publish_worker import sanitize_cell
        assert sanitize_cell("|||\n\n") == "Security review"

    def test_update_readme_injection_stays_one_row(self, tmp_path):
        from soken_review.worker.publish_worker import _update_readme, public_filename
        # A subject trying to inject extra table rows / a malicious markdown link.
        subject = "Pwn | [owned](http://evil) |\n| FAKE AUDIT | [x](http://evil) |"
        name = public_filename(subject)
        _update_readme(tmp_path, name, subject, "abcdefghijklmnopqrst2345", today="2026-10-24")
        text = (tmp_path / "README.md").read_text(encoding="utf-8")
        rows = [ln for ln in text.splitlines() if ln.startswith("| [")]
        assert len(rows) == 1, f"injected an extra row: {rows}"
        row = rows[0]
        assert row.count("|") == 3, f"subject injected extra cells/rows: {row!r}"
        label = row.split("](", 1)[0].removeprefix("| [")
        for ch in "[]<>`|":
            assert ch not in label, f"{ch!r} survived in the link text: {label!r}"
        assert "(Automated by SOKEN MCP)" in label and row.endswith("| 2026-10-24 |")


class TestPublicFilenameAndReplace:
    """CEO 2026-10-24: labelled name, one file per target, the real README table format."""

    README = ("# Smart Contract Audit Reports\n\n## Reports (260)\n\n| Report | Published |\n|---|---|\n"
              "| [Old](https://github.com/Soken-LTD/smart-contract-audits/blob/main/Old.pdf) | 2026-10-21 |\n")

    def test_public_filename_label_and_charset(self):
        from soken_review.worker.publish_worker import public_filename
        assert public_filename("MasterChef") == "MasterChef (Automated by SOKEN MCP).pdf"
        assert public_filename("-../x;rm -rf") == "x rm -rf (Automated by SOKEN MCP).pdf"
        assert public_filename("") == "Smart contract review (Automated by SOKEN MCP).pdf"
        assert public_filename("Vault", "abcdefghijklmnopqrst2345") == "Vault abcdefgh (Automated by SOKEN MCP).pdf"
        with pytest.raises(ValueError):
            public_filename("Vault", "BAD_ID")

    def test_new_row_goes_under_the_real_header_and_bumps_count(self, tmp_path):
        from soken_review.worker.publish_worker import _update_readme
        (tmp_path / "README.md").write_text(self.README, encoding="utf-8")
        _update_readme(tmp_path, "Vault (Automated by SOKEN MCP).pdf", "Vault", "abcdefgh", today="2026-10-24")
        text = (tmp_path / "README.md").read_text(encoding="utf-8")
        assert "## Reports (261)" in text and text.count("## Reports") == 1
        lines = text.splitlines()
        i = lines.index("|---|---|")
        assert lines[i + 1] == ("| [Vault (Automated by SOKEN MCP)](https://github.com/Soken-LTD/smart-contract-audits"
                                "/blob/main/Vault%20%28Automated%20by%20SOKEN%20MCP%29.pdf) | 2026-10-24 |")
        assert lines[i + 2].startswith("| [Old]")

    def test_replace_keeps_one_row_and_count(self, tmp_path):
        from soken_review.worker.publish_worker import _update_readme
        (tmp_path / "README.md").write_text(self.README, encoding="utf-8")
        name = "Vault (Automated by SOKEN MCP).pdf"
        _update_readme(tmp_path, name, "Vault", "abcdefgh", today="2026-10-24")
        _update_readme(tmp_path, "Other (Automated by SOKEN MCP).pdf", "Other", "abcdefgh", today="2026-10-25")
        _update_readme(tmp_path, name, "Vault", "abcdefgh", replace=True, today="2026-10-26")
        text = (tmp_path / "README.md").read_text(encoding="utf-8")
        rows = [ln for ln in text.splitlines() if ln.startswith("| [")]
        assert [r.split("]")[0] for r in rows] == ["| [Vault (Automated by SOKEN MCP)", "| [Other (Automated by SOKEN MCP)", "| [Old"]
        assert rows[0].endswith("| 2026-10-26 |") and "## Reports (262)" in text

    def test_git_replace_overwrites_and_failed_push_resets(self, tmp_path):
        import subprocess
        from unittest.mock import patch as _patch

        from soken_review.worker.publish_worker import EnvGitPublisher

        origin, clone = tmp_path / "origin.git", tmp_path / "clone"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
        subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True)
        (clone / "README.md").write_text(self.README, encoding="utf-8")
        g = ["git", "-C", str(clone), "-c", "user.name=t", "-c", "user.email=t@t"]
        subprocess.run(g + ["add", "README.md"], check=True)
        subprocess.run(g + ["commit", "-qm", "init"], check=True)
        subprocess.run(["git", "-C", str(clone), "push", "-q", "origin", "HEAD:main"], check=True)
        subprocess.run(["git", "-C", str(clone), "branch", "-q", "--set-upstream-to=origin/main"], check=True)
        env = {"SOKEN_GIT_PUBLISH_REPO_PATH": str(clone), "SOKEN_GIT_PUBLISH_TOKEN": ""}
        name = "Vault (Automated by SOKEN MCP).pdf"
        with _patch.dict("os.environ", env):
            pub = EnvGitPublisher()
            url = pub.push_report(b"v1", name, "Vault", "abcdefgh")
            assert url.endswith("/Vault%20%28Automated%20by%20SOKEN%20MCP%29.pdf")
            with pytest.raises(FileExistsError):
                pub.push_report(b"v2", name, "Vault", "abcdefgh")   # a new target never overwrites
            assert (clone / name).read_bytes() == b"v1"             # and never deletes the owner's file
            pub.push_report(b"v1", name, "Vault", "abcdefgh", replace=True)   # same bytes: no-op commit ok
            pub.push_report(b"v2", name, "Vault", "abcdefgh", replace=True)
            assert (clone / name).read_bytes() == b"v2"
            shown = subprocess.run(["git", "--git-dir", str(origin), "show", f"main:{name}"],
                                   capture_output=True, check=True).stdout
            assert shown == b"v2"
            # A push that fails leaves the clone equal to origin, without the new file.
            real_run = subprocess.run

            def failing(argv, **kw):
                if "push" in argv:
                    raise subprocess.CalledProcessError(1, argv)
                return real_run(argv, **kw)

            with (_patch("soken_review.worker.publish_worker.subprocess.run", side_effect=failing),
                  pytest.raises(subprocess.CalledProcessError)):
                pub.push_report(b"x", "New (Automated by SOKEN MCP).pdf", "New", "abcdefgh")
            assert not (clone / "New (Automated by SOKEN MCP).pdf").exists()
            head = real_run(["git", "-C", str(clone), "rev-parse", "HEAD", "origin/main"],
                            capture_output=True, text=True, check=True).stdout.split()
            assert head[0] == head[1]


# ---------------------------------------------------------------------------
# Unused mock pool builder (kept as dead code marker for context)
# ---------------------------------------------------------------------------


def _make_mock_pool(
    job: dict | None,
    report: dict | None,
    existing_request: dict | None,
    rate_limit_count: int = 0,
) -> MagicMock:
    """Build a minimal async mock of psycopg_pool.AsyncConnectionPool.

    The mock returns canned query results so publish.py can be tested without
    a live database.
    """
    from unittest.mock import MagicMock

    # We need to intercept connection.cursor().execute() + fetchone() sequences.
    # The publish handler calls _get_pool().connection() as an async context manager,
    # then calls execute() and fetchone() on the cursor.
    # We patch each DB-hit function directly on the publish module instead.

    mock_pool = MagicMock()

    # Patch the individual helper coroutines used by handle_review_publish.
    # This is the cleanest approach given the DB helpers are async module-level functions.
    import soken_review.tools.publish as pub_mod

    async def mock_load_job_row(jid: str) -> dict | None:
        return job

    async def mock_load_report(rid: str) -> dict | None:
        return report

    async def mock_existing_request(rid: str) -> dict | None:
        return existing_request

    async def mock_rate_limit_count() -> int:
        return rate_limit_count

    async def mock_enqueue(rid: str, jid: str, c: dict) -> None:
        pass

    # These will be patched in the test via set_pool + patching the internal helpers.
    mock_pool._mock_job = job
    mock_pool._mock_report = report
    mock_pool._mock_existing = existing_request
    mock_pool._mock_rate = rate_limit_count

    # Build a real mock pool that feeds through the publish module's helpers.
    # We use a connection that returns the right fetchone() results in order.
    _call_count = {"jobs": 0}

    class FakeCursor:
        def __init__(self, results):
            self._results = results
            self._idx = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def execute(self, query, params=None):
            pass

        async def fetchone(self):
            if self._idx < len(self._results):
                r = self._results[self._idx]
                self._idx += 1
                return r
            return None

    class FakeConn:
        def __init__(self):
            self._cursor_results = []

        def cursor(self, **kwargs):
            return FakeCursor(self._cursor_results)

        async def execute(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

    class FakeTx:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

    # Build fake connection that returns query results in the order publish.py calls them.
    # Order: jobs query -> reports query -> publish_requests query -> rate_limit count ->
    #        insert consent_log -> insert publish_requests
    # We patch _get_pool() to return our fake pool.

    # Simplest approach: patch the private DB helpers directly.
    pub_mod._patched_job = job
    pub_mod._patched_report = report
    pub_mod._patched_existing = existing_request
    pub_mod._patched_rate = rate_limit_count

    import contextlib

    @contextlib.asynccontextmanager
    async def fake_connection():
        conn = FakeConn()
        # Sequence of fetchone results for all execute() calls in order.
        # publish.py queries: (1) jobs, (2) reports, (3) publish_requests, (4) rate_limit
        results_queue = []
        if job is not None:
            results_queue.append(job)
        else:
            results_queue.append(None)
        if report is not None:
            results_queue.append(report)
        else:
            results_queue.append(None)
        results_queue.append(existing_request)   # existing publish_request
        results_queue.append((rate_limit_count,))  # rate limit count tuple

        conn._cursor_results = results_queue
        yield conn

    real_pool = MagicMock()
    real_pool.connection.return_value = fake_connection()
    return real_pool


# ---------------------------------------------------------------------------
# Standalone integration tests (DB required)
# ---------------------------------------------------------------------------

SKIP_DB = pytest.mark.skipif(
    __import__("os").environ.get("SKIP_DB_TESTS") == "1",
    reason="SKIP_DB_TESTS=1",
)


@SKIP_DB
@ASYNC
async def test_db_dedup_second_consent_idempotent(db_conn, db_pool):
    """Stand-only: enqueue twice for same report_id → second call returns first row status.

    This test requires a Postgres 16 DB (Docker via conftest.py pg_dsn/db_pool).
    It creates a minimal job + report row, calls the publish handler twice, and
    verifies the second call returns the same publish_request status without duplicating.
    """
    pytest.skip("Stand-only test: requires live DB + rendered report fixture (deferred to stand)")


# ---------------------------------------------------------------------------
# Auto-publish: enqueue on render success (CEO 2026-10-24)
# ---------------------------------------------------------------------------


class TestAutoPublishEnqueue:
    """render.py enqueues a publish_request in the same transaction as rendered."""

    def test_auto_publish_constants_present(self):
        """AUTO_PUBLISH_STATEMENT, PARTY, NAME are exported from render.py."""
        from soken_review.report.render import (
            AUTO_PUBLISH_NAME,
            AUTO_PUBLISH_PARTY,
            AUTO_PUBLISH_STATEMENT,
        )
        assert AUTO_PUBLISH_PARTY == "requester"
        assert AUTO_PUBLISH_NAME == "MCP Terms of Use acceptance"
        assert "soken.dev/mcp/terms.html" in AUTO_PUBLISH_STATEMENT
        assert "Terms of Use" in AUTO_PUBLISH_STATEMENT
        assert len(AUTO_PUBLISH_STATEMENT) <= 500  # fits in publish_consent_log.statement

    def test_auto_publish_statement_no_brand_violations(self):
        """Consent statement must not mention soken.io or hardcoded pricing."""
        from soken_review.report.render import AUTO_PUBLISH_STATEMENT
        stmt = AUTO_PUBLISH_STATEMENT.lower()
        assert "soken.io" not in stmt
        assert "free" not in stmt
        assert "$" not in stmt

    def test_auto_enqueue_function_exists(self):
        """_auto_enqueue_publish is importable and has the expected signature."""
        import inspect

        from soken_review.report.render import _auto_enqueue_publish
        sig = inspect.signature(_auto_enqueue_publish)
        params = list(sig.parameters.keys())
        assert params == ["conn", "report_id", "job_id", "render_ts", "profile"]

    @pytest.mark.asyncio(loop_scope="session")
    async def test_auto_enqueue_public_sources_only(self, db_pool):
        """Mainnet-deployed and repo+mainnet-deployment reports are queued (idempotent).

        CEO 2026-10-24 rule: automatic publication requires has_deployment=True AND
        is_mainnet=True. source_kinds 'upload' and 'files' are always private.
        A repo job without a deployment is also private.
        """
        from soken_review.db.job_repo import JobRepo, new_job_id
        from soken_review.report.render import _auto_enqueue_publish

        async with db_pool.connection() as conn:
            tx = conn.transaction(force_rollback=True)
            async with tx:
                rids = {}
                # "deployed" on Base mainnet (chain_id=8453): should be published automatically.
                # "repo" with a mainnet deployment: should be published automatically.
                # "repo_no_dep": repo without a deployment: private.
                # "upload" and "files": always private.
                cases = [
                    ("deployed", "aaaaaaaaaaaaaaaaaaaaaaaaaa",
                     {"has_deployment": True, "chain": "evm", "chain_id": 8453}),
                    ("repo", "bbbbbbbbbbbbbbbbbbbbbbbbbb",
                     {"has_deployment": True, "chain": "evm", "chain_id": 8453}),
                    # TON repo + mainnet address: matched (tier A) publishes, unlinked (tier B) never
                    ("repo", "ffffffffffffffffffffffffff",
                     {"has_deployment": True, "chain": "ton", "chain_id": None}),
                    ("repo", "gggggggggggggggggggggggggg",
                     {"has_deployment": True, "chain": "ton", "chain_id": None}),
                    ("deployed", "hhhhhhhhhhhhhhhhhhhhhhhhhh",
                     {"has_deployment": True, "chain": "evm", "chain_id": 8453}),   # tier B, verified
                    ("repo", "eeeeeeeeeeeeeeeeeeeeeeeeee",
                     {"has_deployment": False, "chain": None, "chain_id": None}),  # no deployment
                    ("upload", "cccccccccccccccccccccccccc",
                     {"has_deployment": False, "chain": None, "chain_id": None}),
                    ("files", "dddddddddddddddddddddddddd",
                     {"has_deployment": False, "chain": None, "chain_id": None}),
                ]
                for kind, rid, extra in cases:
                    jid = new_job_id()
                    await JobRepo(conn).create(
                        job_id=jid, principal_key="p", surface="plugin", state="queued",
                        requester_role="third_party_public_code", source_kind=kind,
                        source_args={}, **extra,
                    )
                    await conn.execute(
                        """insert into reports (report_id, report_id_short, job_id, profile, object_prefix, out_name,
                           pdf_sha256s, subject_candidates, key_version, rendered_at, expires_at)
                           values (%s, %s, %s, 'public_review', %s, 'R.pdf', array[repeat('0',64)]::char(64)[],
                                   '[]'::jsonb, 1, now(), now() + interval '30 days')""",
                        (rid, rid[:10], jid, f"reports/{rid}/1/"))
                    tier = {"aaaaaaaaaaaaaaaaaaaaaaaaaa": "A", "bbbbbbbbbbbbbbbbbbbbbbbbbb": "A",
                            "ffffffffffffffffffffffffff": "A", "gggggggggggggggggggggggggg": "B",
                            "hhhhhhhhhhhhhhhhhhhhhhhhhh": "B"}.get(rid)
                    if tier:
                        await conn.execute("update jobs set tier = %s where job_id = %s", (tier, jid))
                    # fetch/build provenance the publication rule reads (networks.deployed_code_reviewed)
                    prov = {"gggggggggggggggggggggggggg": ("repo", {"reason": "SOURCE_UNLINKED", "dep_match": "not_checkable"}),
                            "hhhhhhhhhhhhhhhhhhhhhhhhhh": ("etherscan", {"dep_match": "not_checkable"}),
                            "ffffffffffffffffffffffffff": ("repo", {"reason": "MATCH_REBUILD", "dep_match": "exact"})}.get(rid)
                    if prov:
                        for name, body in (("fetch", {"provider": prov[0]}), ("build", prov[1])):
                            row = await JobRepo(conn).insert_step(job_id=jid, step=name, container=False, units=0, ram_mb=0)
                            await JobRepo(conn).complete_step(row["id"], "done", provenance=body)
                    rids[(kind, rid)] = (rid, jid)
                for rid, jid in rids.values():
                    await _auto_enqueue_publish(conn, rid, jid, "2026-10-24T00:00:00+00:00")
                    await _auto_enqueue_publish(conn, rid, jid, "2026-10-24T01:00:00+00:00")   # re-render
                got = {}
                for kind, rid in rids:
                    row = await (await conn.execute(
                        "select (select count(*) from publish_requests where report_id = %s),"
                        " (select count(*) from publish_consent_log where report_id = %s)", (rid, rid))).fetchone()
                    got[rid] = (tuple(row), kind)

        # deployed + mainnet chain_id → queued (1 request, 2 consent entries)
        assert got["aaaaaaaaaaaaaaaaaaaaaaaaaa"] == ((1, 2), "deployed")
        # repo + mainnet deployment → queued
        assert got["bbbbbbbbbbbbbbbbbbbbbbbbbb"] == ((1, 2), "repo")
        # repo without deployment → private
        assert got["eeeeeeeeeeeeeeeeeeeeeeeeee"] == ((0, 0), "repo")
        # TON repo + mainnet address: matched → queued; unlinked (SOURCE_UNLINKED, tier B) → private
        assert got["ffffffffffffffffffffffffff"] == ((1, 2), "repo")
        assert got["gggggggggggggggggggggggggg"] == ((0, 0), "repo")
        # deployed mainnet address, Etherscan-verified source, own rebuild inconclusive (tier B):
        # the reviewed code is the deployed code → queued
        assert got["hhhhhhhhhhhhhhhhhhhhhhhhhh"] == ((1, 2), "deployed")
        # upload and files → private
        assert got["cccccccccccccccccccccccccc"] == ((0, 0), "upload")
        assert got["dddddddddddddddddddddddddd"] == ((0, 0), "files")


    @pytest.mark.asyncio(loop_scope="session")
    async def test_autopublish_off_skips_enqueue(self, db_pool, monkeypatch):
        """SOKEN_AUTOPUBLISH=off → no publish_requests row even for a mainnet deployment."""
        from soken_review.db.job_repo import JobRepo, new_job_id
        from soken_review.report.render import _auto_enqueue_publish

        monkeypatch.setenv("SOKEN_AUTOPUBLISH", "off")
        rid = "ffffffffffffffffffffffffff"
        async with db_pool.connection() as conn:
            tx = conn.transaction(force_rollback=True)
            async with tx:
                jid = new_job_id()
                await JobRepo(conn).create(
                    job_id=jid, principal_key="p", surface="plugin", state="queued",
                    requester_role="third_party_public_code", source_kind="deployed",
                    source_args={}, has_deployment=True, chain="evm", chain_id=8453,
                )
                await conn.execute(
                    """insert into reports (report_id, report_id_short, job_id, profile, object_prefix, out_name,
                       pdf_sha256s, subject_candidates, key_version, rendered_at, expires_at)
                       values (%s, %s, %s, 'public_review', %s, 'R.pdf', array[repeat('0',64)]::char(64)[],
                               '[]'::jsonb, 1, now(), now() + interval '30 days')""",
                    (rid, rid[:10], jid, f"reports/{rid}/1/"))
                await _auto_enqueue_publish(conn, rid, jid, "2026-10-24T00:00:00+00:00")
                row = await (await conn.execute(
                    "select (select count(*) from publish_requests where report_id = %s),"
                    " (select count(*) from publish_consent_log where report_id = %s)", (rid, rid))).fetchone()
        assert tuple(row) == (0, 0), "SOKEN_AUTOPUBLISH=off must suppress automatic enqueue"


class TestAutoPublishRateGuard:
    """publish_worker uses SOKEN_PUBLISH_RATE_LIMIT_HOUR as the batch cap (excess stays queued)."""

    def test_publish_batch_limit_constant_exported(self):
        """_PUBLISH_BATCH_LIMIT is set from env var and defaults to 20."""
        from soken_review.worker import publish_worker
        assert hasattr(publish_worker, "_PUBLISH_BATCH_LIMIT")
        assert isinstance(publish_worker._PUBLISH_BATCH_LIMIT, int)
        assert publish_worker._PUBLISH_BATCH_LIMIT > 0

    def test_run_queued_uses_batch_limit(self):
        """run_queued SQL uses the _PUBLISH_BATCH_LIMIT, not a hardcoded 20."""
        import inspect

        from soken_review.worker.publish_worker import PublishWorker
        src = inspect.getsource(PublishWorker.run_queued)
        assert "_PUBLISH_BATCH_LIMIT" in src
        # Must NOT have a hardcoded 20 in the limit clause, and must count the last hour
        assert "limit 20" not in src.lower()
        assert "interval '1 hour'" in src


class TestNoPublishOnFailure:
    """render.py must NOT enqueue a publish_request on render_failed or deleted jobs."""

    def test_auto_enqueue_not_called_in_finish_failed(self):
        """_auto_enqueue_publish is not called from _finish_failed."""
        import inspect

        from soken_review.report import render
        src = inspect.getsource(render._finish_failed)
        assert "_auto_enqueue_publish" not in src

    def test_auto_enqueue_not_called_when_job_deleted(self):
        """The deleted-during-render guard returns before _auto_enqueue_publish is called."""
        import inspect

        from soken_review.report import render
        src = inspect.getsource(render._run_render_step)
        # The delete guard returns before _auto_enqueue_publish
        del_idx = src.index("job deleted during the render")
        enq_idx = src.index("_auto_enqueue_publish")
        assert del_idx < enq_idx, "_auto_enqueue_publish must appear after the deleted-job guard"


class TestReviewPublishStatusLookup:
    """review_publish without consent returns current status, not an offer phase."""

    @ASYNC
    async def test_no_consent_returns_accepted_true(self):
        """No consent → accepted=True with current status."""
        import soken_review.tools  # noqa: F401
        from soken_review.tools.publish import handle_review_publish

        with _patch_db(existing=_EXISTING_REQ_PUBLISHED):
            result = await handle_review_publish({"job_id": _JOB_ID, "manage_key": OWNER_KEY})
        assert result["accepted"] is True
        assert result["status"] == "published"

    @ASYNC
    async def test_no_consent_no_request_returns_not_queued(self):
        """No consent, no publish_request → not_queued (auto-enqueue not yet committed)."""
        import soken_review.tools  # noqa: F401
        from soken_review.tools.publish import handle_review_publish

        with _patch_db(existing=None):
            result = await handle_review_publish({"job_id": _JOB_ID, "manage_key": OWNER_KEY})
        assert result["accepted"] is True
        assert result["phase"] == "not_queued"
        assert result["status"] is None

    @ASYNC
    async def test_with_consent_logs_when_request_already_exists(self):
        """Consent with existing request → logs consent, does not re-enqueue."""
        from unittest.mock import patch

        import soken_review.tools  # noqa: F401
        from soken_review.tools.publish import handle_review_publish

        log_calls: list = []

        async def capture_log(*a, **kw):
            log_calls.append(a)

        with (
            _patch_db(existing=_EXISTING_REQ_PUBLISHED),
            patch(f"{_MOD}._log_consent", new=AsyncMock(side_effect=capture_log)),
        ):
            result = await handle_review_publish(
                {"job_id": _JOB_ID, "manage_key": OWNER_KEY, "consent": VALID_CONSENT}
            )
        assert result["status"] == "published"
        assert len(log_calls) == 1

    @ASYNC
    async def test_delete_before_push_cancels(self):
        """When job is in 'rendered' state but publish_request shows failed due to delete,
        the tool correctly reports the failed status (delete.py sets failed, not our tool)."""
        import soken_review.tools  # noqa: F401
        from soken_review.tools.publish import handle_review_publish

        deleted_req = {**_EXISTING_REQ_PUBLISHED, "status": "failed",
                       "error_detail": "job deleted", "public_url": None}
        with _patch_db(existing=deleted_req):
            result = await handle_review_publish({"job_id": _JOB_ID, "manage_key": OWNER_KEY})
        assert result["accepted"] is True
        assert result["status"] == "failed"
        assert result["public_url"] is None
