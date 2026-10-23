"""ContextStore: the project documents of one job (context ingestion spec 2026-10-23, section 4).

Separate from the code pin: the code `source_pin` never changes when documents are added.

    <pin_root>/<job_id>/context/manifest.json
    <pin_root>/<job_id>/context/files/<sha256_lf>     # extracted text, LF, write-once

`manifest.json` is `{"context_pin": "<sha256 of the sorted entries>", "entries": [...]}`; paths are
`context/<kind>-<n>.md` with `n` per kind, 1-based, assigned by the store (never by the document).
Each stored text starts with a six-line header (`# <title>`, `source: <url>`, `retrieved: <date>`,
`sha256: <raw>`, `kind: <kind>`, blank) so a quote of the header is a provenance quote. The API
mirrors `PinnedSource` (`get_entry`, `line_count`, `read_lines`, `read_all`) so the read, search
and quote tools route `context/` paths here unchanged.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

CONTEXT_PREFIX = "context/"
KINDS = ("whitepaper", "website", "app", "docs", "terms", "privacy", "other")
MAX_DOCS_PER_JOB = 12
HEADER_LINES = 6
_PATH_RE = re.compile(r"^context/(whitepaper|website|app|docs|terms|privacy|other)-([1-9][0-9]*)\.md$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def is_context_path(path: str) -> bool:
    return isinstance(path, str) and path.startswith(CONTEXT_PREFIX)


@dataclass(frozen=True)
class ContextEntry:
    """One row of the context manifest (spec section 4). Field names are the wire names."""

    path: str
    kind: str
    url: str | None
    final_url: str | None
    title: str
    content_type: str | None
    bytes_raw: int
    sha256_raw: str | None
    sha256_lf: str | None          # None when status is failed (no text stored)
    lines: int
    fetched_at: str
    status: str                    # ok | failed
    error: str | None
    bundle_hits: dict[str, Any] = field(default_factory=dict)
    inline_path: str | None = None  # the client's label of an inline document; None for a URL

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class ContextStore:
    """Documents of one job: manifest plus write-once text blobs under <pin_root>/<job_id>/context/."""

    def __init__(self, root: Path, job_id: str, entries: list[ContextEntry] | None = None) -> None:
        self._root = root
        self._job_id = job_id
        self._entries: list[ContextEntry] = list(entries or [])
        self._cache: dict[str, tuple[str, ...]] = {}

    # ── loading ───────────────────────────────────────────────────────────

    @classmethod
    def load(cls, pin_root: Path, job_id: str) -> ContextStore:
        """The store of a job; empty (no entries) when nothing was ingested yet."""
        path = _dir(pin_root, job_id) / "manifest.json"
        if not path.is_file():
            return cls(pin_root, job_id, [])
        raw = json.loads(path.read_text(encoding="utf-8"))
        entries = [_entry_from_dict(row) for row in raw.get("entries") or []]
        return cls(pin_root, job_id, entries)

    @classmethod
    def exists(cls, pin_root: Path, job_id: str) -> bool:
        return (_dir(pin_root, job_id) / "manifest.json").is_file()

    # ── PinnedSource-shaped reads ─────────────────────────────────────────

    @property
    def job_id(self) -> str:
        return self._job_id

    @property
    def entries(self) -> dict[str, ContextEntry]:
        """path -> entry, in manifest order (ok and failed alike)."""
        return {e.path: e for e in self._entries}

    @property
    def documents(self) -> list[ContextEntry]:
        return list(self._entries)

    @property
    def context_pin(self) -> str:
        return _compute_pin(self._entries)

    def has_path(self, path: str) -> bool:
        e = self.entries.get(path)
        return e is not None and e.ok

    def get_entry(self, path: str) -> ContextEntry | None:
        """Only readable (ok) documents answer, so a failed one reads as unknown."""
        e = self.entries.get(path)
        return e if e is not None and e.ok else None

    def find(self, *, url: str | None = None, sha256_raw: str | None = None) -> ContextEntry | None:
        for e in self._entries:
            if url is not None and e.url == url:
                return e
            if sha256_raw is not None and url is None and e.url is None and e.sha256_raw == sha256_raw:
                return e
        return None

    def line_count(self, path: str) -> int:
        return self._require(path).lines

    def read_all(self, path: str) -> list[str]:
        return list(self._lines(self._require(path)))

    def read_lines(self, path: str, start: int, end: int) -> list[str]:
        lines = self._lines(self._require(path))
        if start < 1 or end > len(lines) or start > end:
            raise IndexError(f"Range {start}-{end} outside {path} ({len(lines)} lines)")
        return list(lines[start - 1 : end])

    def read_text(self, path: str) -> str:
        return "\n".join(self._lines(self._require(path))) + "\n"

    # ── writes ────────────────────────────────────────────────────────────

    def add(self, docs: list[dict[str, Any]]) -> list[ContextEntry]:
        """Append fetched or inline documents (the fetcher's JSON shape, `text` as LF text).

        Each doc: `{kind, url|None, final_url, status, content_type, bytes, sha256_raw, fetched_at,
        title, text, bundle_hits, error, inline_path?}`. A URL already stored as `ok` is returned as
        it is (idempotent per URL); a URL stored as `failed` is replaced in place (same path) so a
        retry can succeed. Blobs are write-once. The manifest is rewritten and the pin recomputed.
        Raises ValueError over MAX_DOCS_PER_JOB.
        """
        out: list[ContextEntry] = []
        for doc in docs:
            kind = str(doc.get("kind") or "other")
            if kind not in KINDS:
                raise ValueError(f"unknown context kind {kind!r}")
            url = doc.get("url")
            existing = self.find(url=url) if url else self.find(sha256_raw=doc.get("sha256_raw"))
            if existing is not None and existing.ok:
                out.append(existing)
                continue
            path = existing.path if existing is not None else self._next_path(kind)
            entry = self._store(doc, kind, path)
            if existing is not None:
                self._entries = [entry if e.path == existing.path else e for e in self._entries]
            else:
                if len(self._entries) >= MAX_DOCS_PER_JOB:
                    raise ValueError(f"context documents per job capped at {MAX_DOCS_PER_JOB}")
                self._entries.append(entry)
            self._cache.pop(path, None)
            out.append(entry)
        self.persist()
        return out

    def persist(self) -> None:
        d = _dir(self._root, self._job_id)
        (d / "files").mkdir(parents=True, exist_ok=True)
        (d / "manifest.json").write_text(json.dumps(self.manifest(), sort_keys=True, separators=(",", ":")),
                                         encoding="utf-8")

    def manifest(self) -> dict[str, Any]:
        return {"context_pin": self.context_pin, "entries": [e.to_dict() for e in self._entries]}

    # ── private ───────────────────────────────────────────────────────────

    def _require(self, path: str) -> ContextEntry:
        e = self.get_entry(path)
        if e is None:
            raise KeyError(path)
        return e

    def _lines(self, entry: ContextEntry) -> tuple[str, ...]:
        cached = self._cache.get(entry.path)
        if cached is None:
            blob = (_dir(self._root, self._job_id) / "files" / str(entry.sha256_lf)).read_bytes()
            parts = blob.decode("utf-8").split("\n")
            if parts and parts[-1] == "":
                parts = parts[:-1]
            cached = tuple(parts)
            self._cache[entry.path] = cached
        return cached

    def _next_path(self, kind: str) -> str:
        n = 1 + sum(1 for e in self._entries if e.kind == kind)
        return f"{CONTEXT_PREFIX}{kind}-{n}.md"

    def _store(self, doc: dict[str, Any], kind: str, path: str) -> ContextEntry:
        status = "ok" if doc.get("status") == "ok" else "failed"
        url = doc.get("url") or None
        title = _clean_line(str(doc.get("title") or "")) or _default_title(kind, url, doc.get("inline_path"))
        fetched_at = str(doc.get("fetched_at") or "")
        sha_raw = doc.get("sha256_raw")
        entry = ContextEntry(
            path=path, kind=kind, url=url, final_url=doc.get("final_url") or None, title=title,
            content_type=doc.get("content_type") or None, bytes_raw=int(doc.get("bytes") or 0),
            sha256_raw=sha_raw, sha256_lf=None, lines=0, fetched_at=fetched_at, status=status,
            error=(doc.get("error") or None) if status == "failed" else None,
            bundle_hits=dict(doc.get("bundle_hits") or {}), inline_path=doc.get("inline_path") or None,
        )
        if status != "ok":
            return entry
        text = _lf(str(doc.get("text") or ""))
        header = render_header(entry)
        blob = (header + text).encode("utf-8")
        if not blob.endswith(b"\n"):
            blob += b"\n"
        sha_lf = hashlib.sha256(blob).hexdigest()
        files = _dir(self._root, self._job_id) / "files"
        files.mkdir(parents=True, exist_ok=True)
        target = files / sha_lf
        if not target.exists():
            target.write_bytes(blob)
        return replace(entry, sha256_lf=sha_lf, lines=blob.count(b"\n"))


def render_header(entry: ContextEntry) -> str:
    """The six-line provenance header every stored text starts with (spec section 4)."""
    source = entry.url or (f"inline {entry.inline_path}" if entry.inline_path else "inline")
    retrieved = (entry.fetched_at or "")[:10]
    return (f"# {entry.title}\n"
            f"source: {source}\n"
            f"retrieved: {retrieved}\n"
            f"sha256: {entry.sha256_raw or ''}\n"
            f"kind: {entry.kind}\n"
            "\n")


def parse_path(path: str) -> tuple[str, int] | None:
    """(kind, n) of a well-formed context path, None otherwise."""
    m = _PATH_RE.match(path or "")
    return (m.group(1), int(m.group(2))) if m else None


def _default_title(kind: str, url: str | None, inline_path: str | None) -> str:
    if inline_path:
        return _clean_line(inline_path)[:200]
    if url:
        return url[:200]
    return kind


def _clean_line(text: str) -> str:
    text = _CONTROL_RE.sub("", text.replace("\r", " ").replace("\n", " ").replace("\t", " "))
    return re.sub(r"\s+", " ", text).strip()[:200]


def _lf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _dir(root: Path, job_id: str) -> Path:
    return root / job_id / "context"


def _entry_from_dict(row: dict[str, Any]) -> ContextEntry:
    return ContextEntry(
        path=row["path"], kind=row["kind"], url=row.get("url"), final_url=row.get("final_url"),
        title=row.get("title") or "", content_type=row.get("content_type"), bytes_raw=int(row.get("bytes_raw") or 0),
        sha256_raw=row.get("sha256_raw"), sha256_lf=row.get("sha256_lf"), lines=int(row.get("lines") or 0),
        fetched_at=row.get("fetched_at") or "", status=row.get("status") or "failed", error=row.get("error"),
        bundle_hits=dict(row.get("bundle_hits") or {}), inline_path=row.get("inline_path"),
    )


def _compute_pin(entries: list[ContextEntry]) -> str:
    rows = [e.to_dict() for e in sorted(entries, key=lambda e: e.path)]
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
