"""PinnedSource: immutable file store for one job (04 section 5.1).

Disk layout:
  <root>/<job_id>/pin/manifest.json
  <root>/<job_id>/pin/files/<sha256_lf>   (LF-normalised bytes, write-once)

`source_pin` is sha256 of the canonical JSON of the manifest (sorted keys, no whitespace).
Lines are 1-based. Files decode as strict UTF-8; invalid files raise UnicodeDecodeError.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Role = Literal["source", "dependency", "test", "doc"]


@dataclass(frozen=True)
class FileEntry:
    """One row of the pin manifest (04 5.1)."""

    path: str
    sha256_raw: str   # sha256 of raw bytes as delivered
    sha256_lf: str    # sha256 of LF-normalised content
    lines: int        # count of logical lines (1-based: 1..lines)
    lang: str | None
    in_scope: bool
    role: Role
    user_supplied: bool


class PinnedSource:
    """Immutable set of files pinned for one job.

    All access uses LF-normalised content; sha256_raw is kept for provenance only.
    """

    def __init__(
        self,
        entries: dict[str, FileEntry],
        content: dict[str, bytes],  # path -> raw bytes
    ) -> None:
        self._entries: dict[str, FileEntry] = dict(entries)
        # Store by sha256_lf to avoid duplication across paths with identical content.
        self._blobs: dict[str, bytes] = {}  # sha256_lf -> lf-normalised bytes
        for entry in entries.values():
            sha = entry.sha256_lf
            if sha not in self._blobs:
                self._blobs[sha] = _lf_normalize(content[entry.path])
        self._source_pin = _compute_source_pin(entries)

    # ── public API ──────────────────────────────────────────────────────────

    @property
    def source_pin(self) -> str:
        """sha256 of the canonical JSON manifest (04 5.1)."""
        return self._source_pin

    @property
    def entries(self) -> dict[str, FileEntry]:
        return dict(self._entries)

    def has_path(self, path: str) -> bool:
        return path in self._entries

    def get_entry(self, path: str) -> FileEntry | None:
        return self._entries.get(path)

    def line_count(self, path: str) -> int:
        """Number of lines in the pinned file."""
        return self._entries[path].lines

    def read_lines(self, path: str, start: int, end: int) -> list[str]:
        """Return 1-based lines [start, end] inclusive as strings (no newline suffix).

        Raises IndexError on out-of-range.
        """
        entry = self._entries[path]
        all_lines = self._split_lines(entry.sha256_lf)
        if start < 1 or end > len(all_lines) or start > end:
            raise IndexError(f"Range {start}-{end} outside {path} ({len(all_lines)} lines)")
        return list(all_lines[start - 1 : end])

    def read_all(self, path: str) -> list[str]:
        """Return every line of the file."""
        entry = self._entries[path]
        return list(self._split_lines(entry.sha256_lf))

    def read_text(self, path: str) -> str:
        """The whole LF-normalised file as text, final newline kept (build inputs need exact bytes)."""
        return self._blobs[self._entries[path].sha256_lf].decode("utf-8")

    # ── persistence ─────────────────────────────────────────────────────────

    def persist(self, root: Path, job_id: str) -> None:
        """Write pin dir to <root>/<job_id>/pin/. Blobs are write-once."""
        pin_dir = _pin_dir(root, job_id)
        blobs_dir = pin_dir / "files"
        blobs_dir.mkdir(parents=True, exist_ok=True)
        for sha, data in self._blobs.items():
            blob_path = blobs_dir / sha
            if not blob_path.exists():
                blob_path.write_bytes(data)
        manifest = _build_manifest(self._source_pin, self._entries)
        (pin_dir / "manifest.json").write_text(manifest, encoding="utf-8")

    @classmethod
    def load(cls, root: Path, job_id: str) -> PinnedSource:
        """Load a persisted PinnedSource from disk."""
        pin_dir = _pin_dir(root, job_id)
        raw_manifest = json.loads((pin_dir / "manifest.json").read_text())
        entries: dict[str, FileEntry] = {}
        path_to_raw: dict[str, bytes] = {}
        for row in raw_manifest["files"]:
            entry = FileEntry(
                path=row["path"],
                sha256_raw=row["sha256_raw"],
                sha256_lf=row["sha256_lf"],
                lines=row["lines"],
                lang=row.get("lang"),
                in_scope=row["in_scope"],
                role=row["role"],
                user_supplied=row["user_supplied"],
            )
            entries[entry.path] = entry
            blob_path = pin_dir / "files" / entry.sha256_lf
            # Provide raw bytes = LF-normalised bytes (already normalised at persist time)
            path_to_raw[entry.path] = blob_path.read_bytes()
        # Re-construct without double-normalising (content is already LF)
        obj = cls.__new__(cls)
        obj._entries = entries
        obj._blobs = {}
        for entry in entries.values():
            sha = entry.sha256_lf
            if sha not in obj._blobs:
                obj._blobs[sha] = path_to_raw[entry.path]
        obj._source_pin = raw_manifest["source_pin"]
        return obj

    # ── factory ─────────────────────────────────────────────────────────────

    @classmethod
    def from_files(
        cls,
        files: dict[str, bytes],
        *,
        roles: dict[str, Role] | None = None,
        langs: dict[str, str | None] | None = None,
        in_scope: dict[str, bool] | None = None,
        user_supplied: dict[str, bool] | None = None,
    ) -> PinnedSource:
        """Build a PinnedSource from raw bytes.

        Raises UnicodeDecodeError on invalid UTF-8 (04 5.1: invalid files go out of scope;
        callers should catch and exclude the path).
        """
        entries: dict[str, FileEntry] = {}
        for path, raw in files.items():
            raw.decode("utf-8")  # strict validation
            lf = _lf_normalize(raw)
            n_lines = _count_lines(lf)
            entries[path] = FileEntry(
                path=path,
                sha256_raw=_sha256(raw),
                sha256_lf=_sha256(lf),
                lines=n_lines,
                lang=(langs or {}).get(path),
                in_scope=(in_scope or {}).get(path, True),
                role=(roles or {}).get(path, "source"),
                user_supplied=(user_supplied or {}).get(path, False),
            )
        return cls(entries, files)

    # ── private ─────────────────────────────────────────────────────────────

    def _split_lines(self, sha: str) -> tuple[str, ...]:
        """Return lines of a blob by sha256_lf (cached as a tuple for reads)."""
        data = self._blobs[sha].decode("utf-8")
        parts = data.split("\n")
        # 'a\nb\n' -> ['a', 'b', ''] -> strip trailing empty
        if parts and parts[-1] == "":
            parts = parts[:-1]
        return tuple(parts)


# ── module helpers ───────────────────────────────────────────────────────────


def _pin_dir(root: Path, job_id: str) -> Path:
    return root / job_id / "pin"


def _lf_normalize(data: bytes) -> bytes:
    """CRLF and lone CR -> LF (04 5.1 normalization rule)."""
    text = data.decode("utf-8")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.encode("utf-8")


def _count_lines(lf_data: bytes) -> int:
    """Count logical lines. 'a\\nb' -> 2, 'a\\n' -> 1, '' -> 0."""
    text = lf_data.decode("utf-8")
    if not text:
        return 0
    parts = text.split("\n")
    return len(parts) - 1 if parts[-1] == "" else len(parts)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry_to_dict(e: FileEntry) -> dict:
    return {
        "path": e.path,
        "sha256_raw": e.sha256_raw,
        "sha256_lf": e.sha256_lf,
        "lines": e.lines,
        "lang": e.lang,
        "in_scope": e.in_scope,
        "role": e.role,
        "user_supplied": e.user_supplied,
    }


def _compute_source_pin(entries: dict[str, FileEntry]) -> str:
    """sha256 of canonical JSON of manifest rows sorted by path (04 5.1)."""
    rows = [_entry_to_dict(e) for _, e in sorted(entries.items())]
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return _sha256(canonical.encode("utf-8"))


def _build_manifest(source_pin: str, entries: dict[str, FileEntry]) -> str:
    doc = {
        "source_pin": source_pin,
        "files": [_entry_to_dict(e) for _, e in sorted(entries.items())],
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))
