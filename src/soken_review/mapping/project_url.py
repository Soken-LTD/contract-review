"""Server-side discovery of project URLs from pinned source files (feat/context-related-state).

Scans the text of every pinned Solidity/Vyper/Cairo/etc. file for NatSpec
`@custom:website` / `@custom:security-contact` directives and for public GitHub
repository URLs mentioned in comments.  Returns a de-duplicated list of
suggested context items; each is `{url, kind, source_hint}`.

Findings are *suggestions only*: they are written to
``<pin_root>/<job_id>/suggested_context.json`` so ``review_status`` can surface
them to the model, which can then ask the user whether to add them via
``review_add_context``.  No network fetch is triggered automatically.

Design choice — suggested, not auto-fetched: a URL discovered in source code
may be internal (a repo README, a coverage badge), rate-limited, or irrelevant
to the specific contract.  Auto-fetching would burn context budget and violate
the "user confirms" principle; the model can call ``review_add_context`` once
the user confirms.

Runs on the host in the map step; pure (no I/O beyond persistence); degrades
gracefully (any parse error is logged, never raised).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from ..context.fetcher import check_url

logger = logging.getLogger(__name__)

SUGGESTED_CONTEXT_FILE = "suggested_context.json"
MAX_SUGGESTIONS = 6

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
# We match through common comment terminators (* / \n) to avoid capturing noise.
_GITHUB_REPO_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_./-]*)?(?=[^\w/.-]|$)",
)

# Strip trailing punctuation that often appears before a line end in comments.
_TRAIL_RE = re.compile(r"[*/>)\]\s]+$")


def _clean_url(raw: str) -> str | None:
    """Strip trailing comment/punctuation noise and validate the URL; None if invalid."""
    url = _TRAIL_RE.sub("", raw).rstrip(".")
    try:
        return check_url(url)
    except (ValueError, Exception):  # noqa: BLE001  # check_url raises ValueError for bad URLs
        return None


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
        List of ``{url, kind, source_hint}`` with at most ``MAX_SUGGESTIONS``
        entries; empty when nothing useful is found.
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


def _scan_file(
    path: str,
    text: str,
    seen: dict[str, None],
    results: list[dict[str, Any]],
) -> None:
    def add(url_raw: str, kind: str) -> None:
        if len(results) >= MAX_SUGGESTIONS:
            return
        url = _clean_url(url_raw)
        if url is None or url in seen:
            return
        seen[url] = None
        results.append({"url": url, "kind": kind, "source_hint": path})

    # NatSpec @custom:website — use _kind_for_url so .pdf / /docs paths take priority
    for m in _NATSPEC_WEBSITE_RE.finditer(text):
        raw_url = m.group(1)
        cleaned = _clean_url(raw_url)
        kind = _kind_for_url(cleaned) if cleaned else "website"
        add(raw_url, kind)

    # NatSpec @custom:security-contact (URL form only)
    for m in _NATSPEC_SECURITY_RE.finditer(text):
        add(m.group(1), "other")

    # GitHub repo URLs in any position (comments, strings, NatSpec)
    for m in _GITHUB_REPO_RE.finditer(text):
        raw = m.group(0)
        # Normalise to the repo root (strip deep paths, branches, etc.)
        parts = raw.split("/")
        if len(parts) >= 5:
            repo_url = "/".join(parts[:5])
        else:
            repo_url = raw
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
