"""Server-side discovery of project URLs from pinned source files (feat/context-related-state).

Scans the text of every pinned Solidity/Vyper/Cairo/etc. file for NatSpec
``@custom:website`` / ``@custom:security-contact`` directives and for public GitHub
repository URLs mentioned in comments.  Returns a de-duplicated list of
suggested context items; each is ``{url, kind, source_hint, origin, status}``.

Security
--------
URLs come from untrusted contract source text.  Each candidate URL is run through
two gates before it can appear in the output (which reaches the model):

1. **Strict charset**: ``^https://[A-Za-z0-9.-]{1,253}(/[A-Za-z0-9._~/%-]{0,120})?$``
   — no query string, no fragment, path capped at 120 chars, host 1-253 chars.
   This blocks ``javascript:``, data-URI, query-injection, and overly long inputs.

2. **J1 injection scan**: the URL string is checked against the prompt-injection
   phrase list (``injection_patterns.yaml J1``).  A URL whose path contains
   "ignore previous instructions" or similar is silently dropped.

Items carry ``"origin": "source_code_untrusted"`` so downstream handlers know the
provenance and ``"status": "suggested"`` to signal that the URL was never fetched.

Findings are *suggestions only*: they are written to
``<pin_root>/<job_id>/suggested_context.json`` so ``review_status`` can surface
them to the model, which can then ask the user whether to add them via
``review_add_context``.  No network fetch is triggered automatically.

Runs on the host in the map step; pure (no I/O beyond persistence); degrades
gracefully (any parse error is logged, never raised).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SUGGESTED_CONTEXT_FILE = "suggested_context.json"
MAX_SUGGESTIONS = 6

# Strict URL pattern for source-code-discovered URLs.
# No query string (no ?), no fragment (no #), path ≤ 120 chars.
# This is tighter than check_url which allows longer inputs.
_STRICT_URL_RE = re.compile(
    r"^https://[A-Za-z0-9][A-Za-z0-9.-]{0,252}"   # host
    r"(/[A-Za-z0-9._~/-]{0,120})?$"                # optional path (no query, fragment or %-escapes)
)
_MAX_STRICT_URL_LEN = 300  # host(253) + "/" + path(120) + "https://" = well under 300

# NatSpec directives that carry project URLs.
_NATSPEC_WEBSITE_RE = re.compile(
    r"@custom:website\s+(https://\S+)",
    re.IGNORECASE,
)
_NATSPEC_SECURITY_RE = re.compile(
    r"@custom:security-contact\s+(https://\S+)",
    re.IGNORECASE,
)

# GitHub repository URL: https://github.com/{owner}/{repo}[/...] in any text.
_GITHUB_REPO_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_./-]*)?(?=[^\w/.-]|$)",
)

# Strip trailing comment/punctuation noise before a line end.
# NOTE: '/' is intentionally excluded so that a trailing path separator
# (e.g. https://example.com/) is preserved.  A block-comment close "*/"
# where the "/" is the last character is an edge case that the strict-
# charset gate will reject anyway (the '*' would survive and fail the
# regex), so excluding '/' here has no security downside.
_TRAIL_RE = re.compile(r"[*>)\]\s]+$")

# Valid pinned file path: relative path with safe characters only.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./\-]{1,200}$")


def _validate_url_strict(raw: str) -> str | None:
    """Validate a source-code URL against the strict charset and injection patterns.

    Returns the cleaned URL or None when the URL fails any gate.
    """
    # Strip trailing comment noise
    url = _TRAIL_RE.sub("", raw).rstrip(".")

    if not url or len(url) > _MAX_STRICT_URL_LEN:
        return None

    # Must start with https://
    if not url.startswith("https://"):
        return None

    # Strict charset check
    if not _STRICT_URL_RE.match(url):
        return None

    # J1 injection scan: check the full URL string for injection phrases
    # Separators turned into spaces so a phrase written as ignore-previous_instructions is seen.
    if _has_injection(url) or _has_injection(re.sub(r"[-_./~]+", " ", url)):
        logger.debug("project_url: J1 injection pattern in URL %r; dropped", url[:80])
        return None

    return url


def _has_injection(text: str) -> bool:
    """Return True when text matches any J1 prompt-injection phrase pattern."""
    try:
        from ..engine.injection import _j1_regexes
        return any(pat.search(text) for _, pat in _j1_regexes())
    except Exception:  # noqa: BLE001  # never crash the map step; fail closed (drop the URL)
        return True


def _kind_for_url(url: str) -> str:
    """Guess context kind from URL path; defaults to 'website'."""
    low = url.lower()
    if any(w in low for w in ("/whitepaper", "/litepaper", "/paper", ".pdf")):
        return "whitepaper"
    if any(w in low for w in ("/docs", "/documentation", "docs.", "docs/")):
        return "docs"
    if "terms" in low or "tos" in low:
        return "terms"
    if "privacy" in low:
        return "privacy"
    return "website"


def discover_project_urls(files: dict[str, str]) -> list[dict[str, Any]]:
    """Return deduplicated suggested context items from source file text.

    Args:
        files: ``{path: text}`` of the pinned source files.

    Returns:
        List of ``{url, kind, source_hint, origin, status}`` with at most
        ``MAX_SUGGESTIONS`` entries; empty when nothing useful is found.
        Every item carries ``origin="source_code_untrusted"`` and
        ``status="suggested"``.
    """
    seen: dict[str, None] = {}
    results: list[dict[str, Any]] = []

    for path, text in sorted(files.items()):
        if len(results) >= MAX_SUGGESTIONS:
            break
        try:
            _scan_file(path, text, seen, results)
        except Exception:  # a buggy source file must never fail the map step
            logger.debug("project_url: scan error in %s", path, exc_info=True)

    return results[:MAX_SUGGESTIONS]


def _source_hint(path: str) -> str | None:
    """Return the file path as a source hint only if it looks like a valid pinned path."""
    if _SAFE_PATH_RE.match(path):
        return path
    return None


def _scan_file(
    path: str,
    text: str,
    seen: dict[str, None],
    results: list[dict[str, Any]],
) -> None:
    hint = _source_hint(path)

    def add(url_raw: str, kind_override: str | None = None) -> None:
        if len(results) >= MAX_SUGGESTIONS:
            return
        url = _validate_url_strict(url_raw)
        if url is None or url in seen:
            return
        kind = kind_override if kind_override is not None else _kind_for_url(url)
        seen[url] = None
        item: dict[str, Any] = {
            "url": url,
            "kind": kind,
            "origin": "source_code_untrusted",
            "status": "suggested",
        }
        if hint is not None:
            item["source_hint"] = hint
        results.append(item)

    # NatSpec @custom:website — kind from URL path takes priority
    for m in _NATSPEC_WEBSITE_RE.finditer(text):
        add(m.group(1))

    # NatSpec @custom:security-contact (URL form only)
    for m in _NATSPEC_SECURITY_RE.finditer(text):
        add(m.group(1), "other")

    # GitHub repo URLs in any position (comments, strings, NatSpec)
    for m in _GITHUB_REPO_RE.finditer(text):
        raw = m.group(0)
        # Normalise to the repo root (strip deep paths, branches, etc.)
        parts = raw.split("/")
        repo_url = "/".join(parts[:5]) if len(parts) >= 5 else raw
        add(repo_url, "other")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def write_suggested_context(root: Path, job_id: str, items: list[dict[str, Any]]) -> None:
    """Write suggestions to ``<pin_root>/<job_id>/suggested_context.json``."""
    d = root / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / SUGGESTED_CONTEXT_FILE).write_text(
        json.dumps(items, indent=1),
        encoding="utf-8",
    )


def load_suggested_context(root: Path, job_id: str) -> list[dict[str, Any]]:
    """Return suggestions written by the map step; empty list when not present."""
    p = root / job_id / SUGGESTED_CONTEXT_FILE
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []
