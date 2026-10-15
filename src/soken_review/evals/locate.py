"""Ground-truth line location for imported judged findings (10 2.4 `root_cause_lines`).

Three evidence kinds, each verified against the checked-out tree at the case commit before a
range is accepted (a range nobody can re-find in the tree is dropped, never guessed):

1. GitHub permalinks in the finding text (`blob/<sha>/<path>#L<a>-L<b>`): the linked lines are
   read from that sha and searched as a block in the tree file with the longest path suffix.
2. `@>` marker lines in the finding's code blocks: the stripped line must occur exactly once
   in the tree's in-scope sources.
3. The official patch diff: removed lines at their old line numbers, verified by text; a pure
   insertion contributes the context line it follows.
"""

from __future__ import annotations

import os
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

LINK = re.compile(
    r"github\.com/(?P<repo>[\w.-]+/[\w.-]+)/blob/(?P<sha>[0-9a-f]{7,40}|main|master)/(?P<path>[^\s#)\]?]+)"
    r"#L(?P<a>\d+)(?:-L(?P<b>\d+))?"
)
MARKER = re.compile(r"^\s*@>\s?(?P<code>.*)$")
HUNK = re.compile(r"^@@ -(?P<old>\d+)(?:,(?P<n>\d+))? \+\d+(?:,\d+)? @@")
SKIP_PARTS = {"lib", "node_modules", "test", "tests", "testFoundry", "script", "scripts", "mocks", "mock"}
MAX_LINK_SPAN = 60   # a permalink over a whole contract is a pointer, not a root cause


@dataclass(frozen=True)
class Span:
    file: str
    start: int
    end: int
    via: str  # link | marker | patch


def safe_read(root: Path, rel: str) -> str | None:
    """Read `root/rel` without following any symlink: every component is lstat-checked, the file
    is opened with O_NOFOLLOW, and the path must stay inside `root`. A checked-out corpus repo is
    untrusted and may carry links out of the tree; such a file reads as None."""
    parts = tuple(rel.split("/")) if isinstance(rel, str) else ()
    if not parts or Path(rel).is_absolute() or any(p in ("..", ".", "") for p in parts):
        return None
    probe = root
    for part in parts:
        probe = probe / part
        try:
            if stat.S_ISLNK(os.lstat(probe).st_mode):
                return None
        except OSError:
            return None
    try:
        fd = os.open(probe, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return None
        return fh.read().decode(errors="replace")


def in_scope(rel: str) -> bool:
    parts = tuple(rel.split("/")) if isinstance(rel, str) else ()
    return rel.endswith((".sol", ".vy")) and not rel.endswith(".t.sol") and not (set(parts[:-1]) & SKIP_PARTS)


def source_files(tree: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(tree, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git" and not os.path.islink(os.path.join(dirpath, d))]
        for name in filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(tree).as_posix()
            if not full.is_symlink() and in_scope(rel):
                out.append(rel)
    return sorted(out)


def _norm(line: str) -> str:
    return " ".join(line.split())


def find_block(lines: list[str], block: list[str]) -> list[int]:
    """1-based start lines where the normalized `block` occurs (blank lines inside are kept)."""
    want = [_norm(b) for b in block]
    while want and not want[0]:
        want.pop(0)
    while want and not want[-1]:
        want.pop()
    if not want or all(len(w) < 4 for w in want):
        return []
    have = [_norm(x) for x in lines]
    n = len(want)
    return [i + 1 for i in range(len(have) - n + 1) if have[i:i + n] == want]


RAW_HOST = "raw.githubusercontent.com"   # the only host a permalink read goes to
MAX_RAW_BYTES = 2_000_000


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


_NO_REDIRECT = urllib.request.build_opener(_RefuseRedirect)

PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
REF = re.compile(r"[0-9a-f]{40}|main|master")   # branch literals only: c4 permalinks use blob/main


def safe_parts(repo: str, sha: str, path: str) -> list[str] | None:
    """Cache-key parts from a permalink, or None: owner/name/ref/path segments are plain names
    (no `.`, `..`, empty or absolute parts, no leading `-`), the ref a 40-hex sha or a branch literal."""
    repo_parts = repo.split("/")
    path_parts = path.split("/")
    if len(repo_parts) != 2 or not REF.fullmatch(sha) or not path_parts:
        return None
    parts = [*repo_parts, sha, *path_parts]
    if any(not PART.fullmatch(x) or set(x) <= {"."} for x in parts):
        return None
    return parts


class RawCache:
    """raw.githubusercontent.com reads for permalinked files, cached on disk (public, read-only).

    Cache paths come from finding text, so every part is validated (safe_parts), the result must
    resolve inside the cache root, and no existing component on the way may be a symlink."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _confined(self, parts: list[str]) -> Path | None:
        root = self.root.resolve()
        probe = root
        for part in parts:
            probe = probe / part
            if probe.is_symlink():
                return None
        dest = root.joinpath(*parts)
        return dest if dest.resolve().is_relative_to(root) else None

    def get(self, repo: str, sha: str, path: str) -> str | None:
        parts = safe_parts(repo, sha, path)
        if parts is None:
            return None
        self.root.mkdir(parents=True, exist_ok=True)
        miss_parts = [*parts[:-1], parts[-1] + ".missing"]
        dest, miss = self._confined(parts), self._confined(miss_parts)
        if dest is None or miss is None:
            return None
        if dest.is_file():
            return safe_read(self.root.resolve(), "/".join(parts))
        if miss.exists():
            return None
        url = f"https://{RAW_HOST}/" + "/".join(parts)
        try:
            with _NO_REDIRECT.open(url, timeout=30) as resp:
                if urllib.parse.urlsplit(resp.geturl()).hostname != RAW_HOST:
                    raise ValueError("left the raw host")
                text = resp.read(MAX_RAW_BYTES + 1).decode(errors="replace")
            if len(text) > MAX_RAW_BYTES:
                raise ValueError("file too large")
        except (OSError, ValueError):
            miss.parent.mkdir(parents=True, exist_ok=True)
            if self._confined(miss_parts) is not None:
                miss.write_text(url)
            return None
        dest.parent.mkdir(parents=True, exist_ok=True)
        if self._confined(parts) is None:
            return None
        dest.write_text(text)
        return text


def _best_suffix(path: str, files: list[str]) -> list[str]:
    parts = Path(path).parts
    for k in range(len(parts), 0, -1):
        tail = "/".join(parts[-k:])
        hits = [f for f in files if f == tail or f.endswith("/" + tail)]
        if hits:
            return hits
    return []


def from_links(text: str, tree: Path, files: list[str], raw: RawCache) -> list[Span]:
    spans: list[Span] = []
    for m in LINK.finditer(text):
        a = int(m["a"])
        b = int(m["b"] or a)
        if b < a or b - a > MAX_LINK_SPAN:
            continue
        targets = _best_suffix(m["path"], files)
        if not targets:
            continue
        linked = raw.get(m["repo"], m["sha"], m["path"])
        if linked is None:
            continue
        block = linked.splitlines()[a - 1:b]
        found = [(f, s) for f in targets for s in find_block((safe_read(tree, f) or "").splitlines(), block)]
        if len(found) == 1:
            f, s = found[0]
            spans.append(Span(f, s, s + (b - a), "link"))
    return spans


def from_markers(text: str, tree: Path, files: list[str]) -> list[Span]:
    spans: list[Span] = []
    in_code = False
    contents = {f: (safe_read(tree, f) or "").splitlines() for f in files}
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        m = MARKER.match(line) if in_code else None
        if not m or len(_norm(m["code"])) < 8:
            continue
        found = [(f, s) for f, ls in contents.items() for s in find_block(ls, [m["code"]])]
        if len(found) == 1:
            f, s = found[0]
            spans.append(Span(f, s, s, "marker"))
    return spans


def from_patch(diff: str, tree: Path) -> list[Span]:
    spans: list[Span] = []
    current: str | None = None
    old = 0
    lines: list[str] = []
    for row in diff.splitlines():
        if row.startswith("--- "):
            name = row[4:].strip()
            current = name[2:] if name.startswith("a/") else None
            text = safe_read(tree, current) if current else None
            lines = text.splitlines() if text else []
            if not lines or not in_scope(current or ""):
                current = None
            continue
        if row.startswith("+++ "):
            continue
        h = HUNK.match(row)
        if h:
            old = int(h["old"])
            prev = old - 1
            replacing = False
            continue
        if current is None or not old:
            continue
        if row.startswith("-"):
            if old <= len(lines) and _norm(lines[old - 1]) == _norm(row[1:]):
                spans.append(Span(current, old, old, "patch"))
            old += 1
            replacing = True
        elif row.startswith("+"):
            # A pure insertion marks the context line it follows; a replacement is already
            # covered by its removed lines.
            if (not replacing and 1 <= prev <= len(lines) and _norm(lines[prev - 1])
                    and not any(s.file == current and s.start == prev for s in spans)):
                spans.append(Span(current, prev, prev, "patch"))
        else:
            prev = old
            old += 1
            replacing = False
    return spans


def merge(spans: list[Span], gap: int = 1) -> list[dict[str, object]]:
    """Merge spans per file when they touch or are `gap` lines apart; ordered output."""
    out: list[dict[str, object]] = []
    for s in sorted(spans, key=lambda x: (x.file, x.start, x.end)):
        last = out[-1] if out else None
        if last and last["file"] == s.file and s.start <= int(last["end"]) + gap + 1:  # type: ignore[arg-type]
            last["end"] = max(int(last["end"]), s.end)  # type: ignore[arg-type]
        else:
            out.append({"file": s.file, "start": s.start, "end": s.end})
    return out
