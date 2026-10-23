"""Context item requests (spec section 2): what `review_start.context` and `review_add_context`
accept, how a request is keyed, how an inline document becomes a store record, and the
`{requested, done, failed}` counts `review_status` reports.

A request record (`jobs.context_items`) is `{kind, url|None, path|None, content|None, sha256|None,
requested_at}`. URL items are keyed by URL, inline items by the sha256 of their content.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from ..errors import ReviewError
from .fetcher import check_url
from .store import KINDS, MAX_DOCS_PER_JOB, ContextStore

MAX_ITEMS_PER_CALL = 8
MAX_INLINE_CHARS = 60_000
_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.{1,200}?)\s*#*\s*$")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def validate_items(raw: list[dict[str, Any]], *, requested_at: str | None = None) -> list[dict[str, Any]]:
    """Normalise request items. Raises ReviewError: `E_CONTEXT_URL` (rejection channel) for a bad
    URL, `E_INVALID_ARGUMENT` for a malformed item. Duplicates inside one call collapse."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str | None]] = set()
    stamp = requested_at or now_iso()
    for i, item in enumerate(raw or []):
        if not isinstance(item, dict):
            raise ReviewError("E_INVALID_ARGUMENT", field=f"items[{i}]", rule="object", value80=str(item)[:80],
                              example='{"kind": "docs", "url": "https://docs.example.org/"}')
        kind = item.get("kind")
        if kind not in KINDS:
            raise ReviewError("E_INVALID_ARGUMENT", field=f"items[{i}].kind", rule="enum", value80=str(kind)[:80],
                              example=f"one of {list(KINDS)}")
        url = item.get("url")
        content = item.get("content")
        path = item.get("path")
        if (url is None) == (content is None):
            raise ReviewError("E_INVALID_ARGUMENT", field=f"items[{i}]", rule="exactly one of url or path+content",
                              value80=str(url or path or "")[:80], example='{"kind": "whitepaper", "url": "https://..."}')
        if url is not None:
            if not isinstance(url, str):
                raise ReviewError("E_CONTEXT_URL", url80=str(url)[:80], reason="not a string")
            try:
                url = check_url(url)
            except ValueError as exc:
                raise ReviewError("E_CONTEXT_URL", url80=url[:80], reason=str(exc)) from None
            key: tuple[str | None, str | None] = (url, None)
            record = {"kind": kind, "url": url, "path": None, "content": None, "sha256": None, "requested_at": stamp}
        else:
            if not isinstance(path, str) or not _PATH_RE.match(path) or path.startswith("/") or ".." in path.split("/"):
                raise ReviewError("E_INVALID_ARGUMENT", field=f"items[{i}].path", rule="pattern",
                                  value80=str(path)[:80], example="whitepaper.md")
            if not isinstance(content, str) or not content.strip():
                raise ReviewError("E_INVALID_ARGUMENT", field=f"items[{i}].content", rule="non-empty text",
                                  value80="", example="the document text")
            if len(content) > MAX_INLINE_CHARS:
                raise ReviewError("E_INVALID_ARGUMENT", field=f"items[{i}].content", rule=f"maxLength {MAX_INLINE_CHARS}",
                                  value80=content[:80], example=f"at most {MAX_INLINE_CHARS} characters")
            sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            key = (None, sha)
            record = {"kind": kind, "url": None, "path": path, "content": content, "sha256": sha, "requested_at": stamp}
        if key in seen:
            continue
        seen.add(key)
        out.append(record)
    return out


def item_key(item: dict[str, Any]) -> tuple[str | None, str | None]:
    return (item.get("url") or None, item.get("sha256") or None)


def check_cap(existing: list[dict[str, Any]], new: list[dict[str, Any]]) -> None:
    """E_CONTEXT_LIMIT (rejection) when the union of requests would pass the per-job cap."""
    keys = {item_key(r) for r in existing}
    added = [n for n in new if item_key(n) not in keys]
    if len(keys) + len(added) > MAX_DOCS_PER_JOB:
        raise ReviewError("E_CONTEXT_LIMIT", cap=MAX_DOCS_PER_JOB, have=len(keys), add=len(added))


def find_entry(store: ContextStore, item: dict[str, Any]):
    url, sha = item_key(item)
    if url:
        return store.find(url=url)
    return store.find(sha256_raw=sha) if sha else None


def inline_document(item: dict[str, Any]) -> dict[str, Any]:
    """A store record for an inline item: text as given, title from the first heading or the path."""
    content = str(item.get("content") or "")
    raw = content.encode("utf-8")
    title = ""
    for line in content.splitlines()[:20]:
        m = _HEADING_RE.match(line)
        if m:
            title = m.group(1).strip()
            break
    return {"kind": item["kind"], "url": None, "final_url": None, "status": "ok", "content_type": "text/markdown",
            "bytes": len(raw), "sha256_raw": item.get("sha256") or hashlib.sha256(raw).hexdigest(),
            "fetched_at": item.get("requested_at") or now_iso(), "title": title or str(item.get("path") or ""),
            "text": content, "bundle_hits": {}, "error": None, "inline_path": item.get("path")}


def status_counts(store: ContextStore, items: list[dict[str, Any]]) -> dict[str, int]:
    """`{requested, done, failed}` of the job's requests against the store (spec section 3)."""
    done = failed = 0
    for item in items or []:
        entry = find_entry(store, item)
        if entry is None:
            continue
        if entry.ok:
            done += 1
        else:
            failed += 1
    return {"requested": len(items or []), "done": done, "failed": failed}


def item_result(store: ContextStore, item: dict[str, Any], *, already_requested: bool) -> dict[str, Any]:
    """The per-item row of review_add_context: queued, exists (ok) or failed (E_CONTEXT_FETCH)."""
    entry = find_entry(store, item)
    row: dict[str, Any] = {"kind": item["kind"], "url": item.get("url"), "path": None, "status": "queued"}
    if entry is None:
        return row
    row["path"] = entry.path
    if entry.ok:
        row["status"] = "exists"
        return row
    row["status"] = "queued"      # a failed document is fetched again on the next round
    row["error"] = ReviewError("E_CONTEXT_FETCH", kind=item["kind"], url80=(item.get("url") or item.get("path") or "")[:80],
                               error=entry.error or "unreachable").envelope()
    del already_requested
    return row
