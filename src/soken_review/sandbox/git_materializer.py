"""soken-fetch: git materializer of 09 section 5.2 (P0-GIT, UV9-5). Standard library only.

Runs inside the `git-fetch` image (Debian trixie, git 2.47) on the family egress network, as
uid 10001 with a read-only root. It never checks out: the commit is fetched with depth 1 and a
5 MiB blob filter into an empty repository, files come from `ls-tree -r -z` and
`cat-file --batch`, and every path passes our checks before one `O_EXCL` write under the
output dir. No hook, filter, fsmonitor, submodule or lazy fetch runs: git gets a fixed
environment and fixed `-c` config on every call, and the promisor remote is removed before any
object is read.

    soken-fetch --url URL (--commit HEX | --ref NAME) [--out /work/src] [--manifest
                /work/out/manifest.json] [--scratch /work/tmp] [--allow-host H ...]

Exit codes (09 3.6): 0 ok; 20 transient (network, 5xx, timeout); 21 commit not found or refused
by the host; 22 size limit (20,000 files or 200 MiB); 23 ambiguous (several commits for a
short sha, or a branch and a tag of one name); 24 no ref line; 25 invalid argument; 26 internal.
The manifest is data for the supervisor, which re-checks every path it reads.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import urlsplit

EXIT_OK, EXIT_TRANSIENT, EXIT_NOT_FOUND, EXIT_SIZE, EXIT_AMBIGUOUS, EXIT_NO_REF = 0, 20, 21, 22, 23, 24
EXIT_INVALID, EXIT_INTERNAL = 25, 26

DEFAULT_HOSTS = ("github.com", "gitlab.com", "codeberg.org")
# Caps (09 5.2, 3.2). Every one is enforced while the work runs, before the bytes land:
MAX_FILES = 20_000                     # files written (all submodules together)
MAX_DIRS = 20_000                      # directories created
MAX_DEPTH = 32                         # path components
MAX_BYTES = 200 * 1024 * 1024          # source bytes written; checked on blob sizes before any write
BLOB_LIMIT = "5m"                      # server-side filter
MAX_BLOB_BYTES = 5 * 1024 * 1024       # checked again locally: a host may ignore the filter
MAX_FETCH_BYTES = 768 * 1024 * 1024    # object store on disk (st_blocks) while git fetch runs
MAX_SYMLINK_TARGET = 4096
MAX_GITMODULES_BYTES = 64 * 1024
MAX_SUBMODULES = 20
MAX_SUBMODULE_DEPTH = 2
MAX_AMBIGUOUS = 5
WALL_S = 80               # whole run; the fetch step wall is 90 s (09 3.2) and the supervisor kills at it
GIT_TIMEOUT_S = WALL_S
_DEADLINE: float | None = None         # monotonic end of the run, set by run()

# Exported for every git process (09 5.2, S7). PATH and HOME are the only inherited values.
GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_ASKPASS": "/bin/false",
    "SSH_ASKPASS": "/bin/false", "GIT_PROTOCOL_FROM_USER": "0", "LC_ALL": "C",
}
# Passed as -c on every call and written to the repo config after init (09 5.2).
GIT_CONFIG = [
    ("core.symlinks", "false"), ("core.hooksPath", "/dev/null"), ("core.fsmonitor", "false"),
    ("protocol.allow", "never"), ("protocol.https.allow", "always"), ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"), ("transfer.fsckObjects", "true"),
    ("credential.helper", ""), ("http.followRedirects", "false"), ("core.askPass", "/bin/false"),
    ("http.lowSpeedLimit", "1024"), ("http.lowSpeedTime", "20"),      # slow-drip transfers abort
]

_HEX_RE = re.compile(r"^[0-9a-f]{7,40}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/+@-]{1,200}$")
_SEG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_TRANSIENT = re.compile(
    r"could not resolve|failed to connect|timed out|connection reset|early eof|rpc failed|"
    r"http[ /]5\d\d|returned error: 5\d\d|the remote end hung up|proxy connect|tls|ssl|"
    r"received http code 5\d\d|operation too slow|temporary failure", re.IGNORECASE)


class Refusal(Exception):
    def __init__(self, code: int, detail: str):
        super().__init__(detail)
        self.code, self.detail = code, detail


# ---------------------------------------------------------------------------------------------
# Input checks (09 5.1 rules repeated here: the container trusts nothing it is given)
# ---------------------------------------------------------------------------------------------

def check_url(url: str, hosts: tuple[str, ...]) -> str:
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise Refusal(EXIT_INVALID, "url") from exc
    host = parts.hostname or ""
    if (parts.scheme != "https" or parts.username or parts.password or parts.port
            or parts.query or parts.fragment or "%" in url or host not in hosts
            or parts.netloc != host or not host.isascii()):
        raise Refusal(EXIT_INVALID, "url")
    segs = [s for s in parts.path.split("/") if s]
    if not 2 <= len(segs) <= 6 or any(not _SEG_RE.match(s) or s in {".", ".."} for s in segs):
        raise Refusal(EXIT_INVALID, "url")
    # Canonical form ends in .git: GitLab answers the bare path with a redirect, and redirects
    # are refused (http.followRedirects=false).
    segs[-1] = segs[-1].removesuffix(".git") + ".git"
    return f"https://{host}/{'/'.join(segs)}"


def check_ref(ref: str) -> str:
    if ref == "HEAD":
        return ref
    if (not _REF_RE.match(ref) or ref.startswith(("-", "/", "refs/")) or ref.endswith(("/", ".lock", "."))
            or ".." in ref or "//" in ref or "@{" in ref):
        raise Refusal(EXIT_INVALID, "ref")
    return ref


def check_path(raw: bytes) -> str:
    """One tree path to a safe relative path, or Refusal(EXIT_INVALID, reason) (09 5.2)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refusal(EXIT_INVALID, "not_utf8") from exc
    text = unicodedata.normalize("NFC", text)
    if not text or len(text) > 1024 or text.startswith("/") or "\\" in text:
        raise Refusal(EXIT_INVALID, "absolute_or_backslash")
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c in "  " for c in text):
        raise Refusal(EXIT_INVALID, "control_char")
    parts = text.split("/")
    if len(parts) > MAX_DEPTH:
        raise Refusal(EXIT_INVALID, "too_deep")
    for part in parts:
        if part in {"", ".", ".."} or len(part.encode()) > 255:
            raise Refusal(EXIT_INVALID, "dot_segment")
        bare = part.rstrip(". ").casefold()
        if bare == ".git" or bare.startswith("git~"):
            raise Refusal(EXIT_INVALID, "git_component")
    return text


# ---------------------------------------------------------------------------------------------
# git runner
# ---------------------------------------------------------------------------------------------

def _env() -> dict[str, str]:
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"), **GIT_ENV}
    return env


def _proxy() -> str:
    return os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""


def _raise(exc: OSError) -> None:
    raise exc


def _raise_unless_vanished(exc: OSError) -> None:
    """os.walk error hook: a directory that disappeared between listing and scandir counts as
    nothing (git renames and deletes pack temp files while the watcher polls); anything else
    (permissions, I/O) is a real error."""
    if not isinstance(exc, FileNotFoundError):
        raise exc


def dir_usage(path: str) -> tuple[int, int] | None:
    """(allocated bytes by st_blocks, inode count) under path; None if any entry that exists is
    unreadable (the caller treats None as over budget). An entry that vanishes between the
    listing and its lstat counts nothing: git fetch renames tmp_pack_* and index-pack deletes
    files while the watcher polls, so a vanished entry is the normal case, not an over-budget
    signal. Tiny files count their blocks, hardlinks count twice."""
    total = inodes = 0
    try:
        for root, dirs, files in os.walk(path, onerror=_raise_unless_vanished, followlinks=False):
            for name in (*dirs, *files):
                try:
                    st = os.lstat(os.path.join(root, name))
                except FileNotFoundError:
                    continue
                total += st.st_blocks * 512
                inodes += 1
    except OSError:
        return None
    return total, inodes


def _remaining(timeout: float) -> float:
    if _DEADLINE is not None:
        timeout = min(timeout, _DEADLINE - time.monotonic())
    if timeout <= 0:
        raise Refusal(EXIT_TRANSIENT, "wall")
    return timeout


def _killpg(proc: subprocess.Popen) -> None:
    """Kill the whole process group (git-remote-https, index-pack, helpers), then reap."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def run_watched(argv: list[str], cwd: str | None = None, stdin: bytes | None = None,
                timeout: float = GIT_TIMEOUT_S, watch: str | None = None,
                watch_cap: int | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run argv in its own process group. While it runs: the wall (and the run deadline) and, with
    `watch`, the allocated size of that dir are checked every 0.25 s; on a breach the whole group
    is killed (20 on time, 22 on size). Output goes to unlinked temp files, not pipes."""
    end = time.monotonic() + _remaining(timeout)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(argv, cwd=cwd, env=env or _env(), stdout=out, stderr=err,
                                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                start_new_session=True)
        if stdin is not None:
            def feed() -> None:
                try:
                    assert proc.stdin
                    proc.stdin.write(stdin)
                    proc.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
            threading.Thread(target=feed, daemon=True).start()
        try:
            while True:
                try:
                    proc.wait(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() > end:
                    raise Refusal(EXIT_TRANSIENT, "git_timeout")
                if watch and watch_cap is not None:
                    usage = dir_usage(watch)
                    if usage is None or usage[0] > watch_cap:
                        raise Refusal(EXIT_SIZE, "fetch_bytes")
        finally:
            _killpg(proc)                  # also reaps helpers left behind by a finished git
        if watch and watch_cap is not None:    # a fetch faster than one poll is checked here
            usage = dir_usage(watch)
            if usage is None or usage[0] > watch_cap:
                raise Refusal(EXIT_SIZE, "fetch_bytes")
        out.seek(0)
        err.seek(0)
        return subprocess.CompletedProcess(argv, proc.returncode, out.read(), err.read())


def git(args: list[str], cwd: str | None = None, stdin: bytes | None = None,
        timeout: float = GIT_TIMEOUT_S, watch: str | None = None) -> subprocess.CompletedProcess:
    cfg: list[str] = []
    for key, value in GIT_CONFIG:
        cfg += ["-c", f"{key}={value}"]
    if _proxy():
        cfg += ["-c", f"http.proxy={_proxy()}"]
    return run_watched(["git", *cfg, *args], cwd=cwd, stdin=stdin, timeout=timeout, watch=watch,
                       watch_cap=MAX_FETCH_BYTES if watch else None)


def _fail(proc: subprocess.CompletedProcess, default: int) -> Refusal:
    err = proc.stderr.decode(errors="replace")
    if "fsck error" in err or "hasDotgit" in err:
        # transfer.fsckObjects refused hostile objects (`.git` trees, bad modes): the repo is refused
        return Refusal(EXIT_INVALID, "fsck: " + " | ".join(err.splitlines()[:2])[:300])
    code = EXIT_TRANSIENT if _TRANSIENT.search(err) else default
    lines = [ln for ln in err.splitlines() if ln.strip()][-3:]
    return Refusal(code, " | ".join(lines)[:400])


def init_repo(path: str, url: str) -> None:
    os.makedirs(path, exist_ok=False)
    proc = git(["init", "-q", "--bare", path])
    if proc.returncode != 0:
        raise _fail(proc, EXIT_INTERNAL)
    for key, value in GIT_CONFIG:
        git(["config", key, value], cwd=path)
    if _proxy():
        git(["config", "http.proxy", _proxy()], cwd=path)
    git(["remote", "add", "origin", url], cwd=path)


# ---------------------------------------------------------------------------------------------
# Resolution (03 4.1 table)
# ---------------------------------------------------------------------------------------------

def resolve_ref(url: str, ref: str) -> tuple[str, str]:
    """`ls-remote` heads and tags of one name -> (commit-ish sha, kind). 23 if both, 24 if none."""
    if ref == "HEAD":
        proc = git(["ls-remote", "--", url, "HEAD"])
        if proc.returncode != 0:
            raise _fail(proc, EXIT_NOT_FOUND)
        rows = _ls_rows(proc.stdout)
        if "HEAD" not in rows:
            raise Refusal(EXIT_NO_REF, "no HEAD line")
        return rows["HEAD"], "head"
    names = [f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"]
    proc = git(["ls-remote", "--", url, *names])
    if proc.returncode != 0:
        raise _fail(proc, EXIT_NOT_FOUND)
    rows = _ls_rows(proc.stdout)
    head, tag, peeled = rows.get(names[0]), rows.get(names[1]), rows.get(names[2])
    if head and tag:
        raise Refusal(EXIT_AMBIGUOUS, "branch and tag of one name")
    if head:
        return head, "branch"
    if tag:
        return (peeled or tag), "tag"
    raise Refusal(EXIT_NO_REF, "no ref line")


def _ls_rows(out: bytes) -> dict[str, str]:
    rows = {}
    for line in out.decode(errors="replace").splitlines():
        sha, _, name = line.partition("\t")
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            rows[name] = sha
    return rows


def resolve_short(url: str, prefix: str, scratch: str) -> str:
    """Blobless clone, resolve only: the unique commit with this prefix (21, or 23 with <= 5)."""
    repo = os.path.join(scratch, "resolve")
    init_repo(repo, url)
    proc = git(["fetch", "-q", "--filter=blob:none", "--no-tags", "origin",
                "+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*"], cwd=repo, watch=repo)
    if proc.returncode != 0:
        raise _fail(proc, EXIT_NOT_FOUND)
    git(["config", "--unset", "remote.origin.promisor"], cwd=repo)
    proc = git(["rev-parse", f"--disambiguate={prefix}"], cwd=repo)
    shas = [s for s in proc.stdout.decode().split() if re.fullmatch(r"[0-9a-f]{40}", s)]
    commits = []
    for sha in shas:
        kind = git(["cat-file", "-t", sha], cwd=repo).stdout.decode().strip()
        if kind == "commit":
            commits.append(sha)
    if not commits:
        raise Refusal(EXIT_NOT_FOUND, "no commit with this prefix")
    if len(commits) > 1:
        raise Refusal(EXIT_AMBIGUOUS, " ".join(sorted(commits)[:MAX_AMBIGUOUS]))
    return commits[0]


def fetch_commit(url: str, sha: str, repo: str) -> str:
    """Depth-1 filtered fetch of one sha into an empty repo; the verified commit id."""
    init_repo(repo, url)
    proc = git(["fetch", "-q", "--depth", "1", f"--filter=blob:limit={BLOB_LIMIT}", "--no-tags",
                "--no-write-fetch-head", "origin", sha], cwd=repo, watch=repo)
    if proc.returncode != 0:
        raise _fail(proc, EXIT_NOT_FOUND)
    # No promisor and no remote from here on: a missing blob can never be fetched lazily.
    git(["config", "--unset", "remote.origin.promisor"], cwd=repo)
    git(["remote", "remove", "origin"], cwd=repo)
    proc = git(["rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"], cwd=repo)
    resolved = proc.stdout.decode().strip()
    if proc.returncode != 0 or resolved != sha:
        raise Refusal(EXIT_NOT_FOUND, "commit not in fetched objects")
    return resolved


# ---------------------------------------------------------------------------------------------
# Materialize (no checkout)
# ---------------------------------------------------------------------------------------------

@dataclass
class Result:
    files: list[dict] = field(default_factory=list)
    too_large: list[str] = field(default_factory=list)
    symlinks: list[dict] = field(default_factory=list)
    submodules: list[dict] = field(default_factory=list)
    refused: list[dict] = field(default_factory=list)
    total_bytes: int = 0
    seen_files: set = field(default_factory=set)       # casefolded file paths
    seen_dirs: set = field(default_factory=set)        # casefolded dir paths


def _tree(repo: str, sha: str) -> list[tuple[str, str, str, bytes]]:
    proc = git(["ls-tree", "-r", "-z", "--full-tree", sha], cwd=repo)
    if proc.returncode != 0:
        raise _fail(proc, EXIT_INTERNAL)
    rows = []
    for rec in proc.stdout.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        mode, kind, obj = meta.decode().split(" ")
        rows.append((mode, kind, obj, path))
    return rows


def _sizes(repo: str, shas: list[str]) -> dict[str, int]:
    """Size of each blob present locally (absent = filtered out by the host)."""
    if not shas:
        return {}
    proc = git(["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], cwd=repo,
               stdin=("\n".join(shas) + "\n").encode())
    sizes = {}
    for line in proc.stdout.decode().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
            sizes[parts[0]] = int(parts[2])
    return sizes


def _stream_blobs(repo: str, shas: list[str]):
    """Yield (sha, bytes) through one `cat-file --batch` in its own process group. Each blob was
    size-checked before; a header over MAX_BLOB_BYTES or the run deadline kills the group."""
    if not shas:
        return
    proc = subprocess.Popen(["git", "cat-file", "--batch"], cwd=repo, env=_env(), start_new_session=True,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert proc.stdin and proc.stdout

    def feed() -> None:
        try:
            proc.stdin.write(("\n".join(shas) + "\n").encode())
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    threading.Thread(target=feed, daemon=True).start()
    try:
        for _ in shas:
            _remaining(GIT_TIMEOUT_S)
            header = proc.stdout.readline(200).decode(errors="replace").split()
            if len(header) != 3 or not header[2].isdigit():
                raise Refusal(EXIT_INTERNAL, "cat-file header")
            sha, _kind, size = header[0], header[1], int(header[2])
            if size > MAX_BLOB_BYTES:
                raise Refusal(EXIT_INTERNAL, "blob over the checked size")
            data = proc.stdout.read(size)
            proc.stdout.read(1)
            yield sha, data
    finally:
        _killpg(proc)


def _claim(res: Result, rel: str) -> str | None:
    """Case-fold collision check across files and directories; None if free. The file and
    directory caps are counted here, before anything is written."""
    key = rel.casefold()
    parents = [str(p).casefold() for p in PurePosixPath(rel).parents if str(p) != "."]
    if key in res.seen_files or key in res.seen_dirs or any(p in res.seen_files for p in parents):
        return "case_collision"
    res.seen_files.add(key)
    res.seen_dirs.update(parents)
    if len(res.seen_files) > MAX_FILES:
        raise Refusal(EXIT_SIZE, "files")
    if len(res.seen_dirs) > MAX_DIRS:
        raise Refusal(EXIT_SIZE, "dirs")
    return None


def _write(out: str, rel: str, data: bytes) -> None:
    target = os.path.realpath(os.path.join(out, rel))
    root = os.path.realpath(out)
    if os.path.commonpath([root, target]) != root or target == root:
        raise Refusal(EXIT_INVALID, "outside_out")
    os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as fh:          # open "xb": never overwrites, never follows
        fh.write(data)


def parse_gitmodules(data: bytes) -> dict[str, dict[str, str]]:
    """Our own reader of `.gitmodules` (09 5.2): sections `submodule "name"`, keys path and url."""
    mods: dict[str, dict[str, str]] = {}
    current = None
    for raw in data.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        m = re.fullmatch(r'\[\s*submodule\s+"([^"\n]{1,200})"\s*\]', line)
        if m:
            current = mods.setdefault(m.group(1), {})
            continue
        if line.startswith("["):
            current = None
            continue
        if current is not None and "=" in line:
            key, _, value = line.partition("=")
            key = key.strip().lower()
            if key in {"path", "url"}:
                current[key] = value.strip().strip('"')
    return mods


def _sub_url(parent: str, url: str) -> str:
    if url.startswith(("../", "./")):
        base = parent.rstrip("/").split("/")
        for seg in url.split("/"):
            if seg == "..":
                base.pop()
            elif seg not in {".", ""}:
                base.append(seg)
        return "/".join(base)
    return url


def materialize(url: str, sha: str, out_root: str, prefix: str, scratch: str, hosts: tuple[str, ...],
                res: Result, depth: int) -> None:
    repo = os.path.join(scratch, f"content-{depth}-{len(res.submodules)}")
    fetch_commit(url, sha, repo)
    rows = _tree(repo, sha)
    sizes = _sizes(repo, [obj for _mode, kind, obj, _ in rows if kind == "blob"])

    plan: list[tuple[str, str, str]] = []     # (rel, obj, mode)
    gitlinks: dict[str, str] = {}
    gitmodules_obj = None
    for mode, kind, obj, raw in rows:
        try:
            rel = check_path(raw)
        except Refusal as r:
            res.refused.append({"path": raw.decode("utf-8", "replace")[:300], "reason": r.detail})
            continue
        full = f"{prefix}{rel}"
        if kind == "commit":                   # gitlink (160000)
            gitlinks[rel] = obj
            continue
        if kind != "blob":
            res.refused.append({"path": full, "reason": f"type_{kind}"})
            continue
        if mode == "120000":                   # symlink: recorded, never written
            if sizes.get(obj, MAX_SYMLINK_TARGET + 1) <= MAX_SYMLINK_TARGET:
                plan.append((full, obj, mode))
            else:
                res.refused.append({"path": full, "reason": "symlink_target"})
            continue
        if obj not in sizes or sizes[obj] > MAX_BLOB_BYTES:
            res.too_large.append(full)         # filtered by the host, or the host ignored the filter
            continue
        if rel == ".gitmodules" and sizes[obj] <= MAX_GITMODULES_BYTES:
            gitmodules_obj = obj
        reason = _claim(res, full)
        if reason:
            res.refused.append({"path": full, "reason": reason})
            continue
        plan.append((full, obj, mode))

    # Byte cap on the checked blob sizes, before the first write.
    planned = sum(sizes[obj] for _, obj, mode in plan if mode != "120000")
    if res.total_bytes + planned > MAX_BYTES:
        raise Refusal(EXIT_SIZE, "bytes")
    targets: dict[str, list[tuple[str, str]]] = {}
    for full, obj, mode in plan:
        targets.setdefault(obj, []).append((full, mode))
    gitmodules = b""
    for obj, data in _stream_blobs(repo, sorted(targets)):
        if len(data) != sizes.get(obj):
            raise Refusal(EXIT_INTERNAL, "blob size changed")
        digest = hashlib.sha256(data).hexdigest()
        for full, mode in targets.pop(obj, []):
            if mode == "120000":
                res.symlinks.append({"path": full, "target": data.decode("utf-8", "replace")})
                continue
            res.total_bytes += len(data)
            if res.total_bytes > MAX_BYTES:
                raise Refusal(EXIT_SIZE, "bytes")
            _write(out_root, full, data)
            res.files.append({"path": full, "size": len(data), "sha256": digest,
                              "executable": mode == "100755"})
        if obj == gitmodules_obj:
            gitmodules = data
    for obj, entries in targets.items():         # not delivered by cat-file
        res.too_large.extend(full for full, _ in entries)

    mods = parse_gitmodules(gitmodules) if gitmodules_obj else {}
    by_path = {m.get("path"): m for m in mods.values() if m.get("path")}
    for rel, commit in sorted(gitlinks.items()):
        entry = {"path": f"{prefix}{rel}", "commit": commit, "url": None, "status": None}
        res.submodules.append(entry)
        mod = by_path.get(rel)
        if mod is None or not mod.get("url"):
            entry["status"] = "no_gitmodules_entry"
            continue
        try:
            sub = check_url(_sub_url(url, mod["url"]), hosts)
        except Refusal:
            entry.update(url=mod["url"][:300], status="refused_host")
            continue
        entry["url"] = sub
        if depth >= MAX_SUBMODULE_DEPTH:
            entry["status"] = "depth_limit"
        elif sum(1 for s in res.submodules if s["status"] == "fetched") >= MAX_SUBMODULES:
            entry["status"] = "count_limit"
        else:
            materialize(sub, commit, out_root, f"{prefix}{rel}/", scratch, hosts, res, depth + 1)
            entry["status"] = "fetched"


def run(args: argparse.Namespace) -> tuple[int, dict]:
    global _DEADLINE
    _DEADLINE = time.monotonic() + min(float(args.wall), WALL_S)
    hosts = tuple(args.allow_host) if args.allow_host else DEFAULT_HOSTS
    manifest: dict = {"schema": "soken-fetch.v1", "url": None, "requested": None, "resolved_commit": None}
    try:
        url = check_url(args.url, hosts)
        manifest["url"] = url
        if bool(args.commit) == bool(args.ref):
            raise Refusal(EXIT_INVALID, "exactly one of commit or ref")
        os.makedirs(args.scratch, exist_ok=True)
        if args.commit:
            commit = args.commit.lower()
            if not _HEX_RE.match(commit):
                raise Refusal(EXIT_INVALID, "commit")
            manifest["requested"] = {"commit": commit}
            sha = commit if len(commit) == 40 else resolve_short(url, commit, args.scratch)
        else:
            ref = check_ref(args.ref)
            sha, kind = resolve_ref(url, ref)
            manifest["requested"] = {"ref": ref, "kind": kind}
        if os.listdir(args.out):
            raise Refusal(EXIT_INVALID, "out dir not empty")
        res = Result()
        materialize(url, sha, args.out, "", args.scratch, hosts, res, depth=0)
        manifest.update(resolved_commit=sha, files=res.files, too_large=sorted(res.too_large),
                        symlinks=res.symlinks, submodules=res.submodules, refused=res.refused,
                        total_bytes=res.total_bytes)
        return EXIT_OK, manifest
    except Refusal as r:
        manifest["error"] = {"exit": r.code, "detail": r.detail}
        return r.code, manifest
    except Exception as exc:  # noqa: BLE001
        manifest["error"] = {"exit": EXIT_INTERNAL, "detail": type(exc).__name__}
        return EXIT_INTERNAL, manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="soken-fetch")
    p.add_argument("--url", required=True)
    p.add_argument("--commit")
    p.add_argument("--ref")
    p.add_argument("--out", default="/work/src")
    p.add_argument("--manifest", default="/work/out/manifest.json")
    p.add_argument("--scratch", default="/work/tmp")
    p.add_argument("--allow-host", action="append")
    p.add_argument("--wall", type=float, default=WALL_S)
    args = p.parse_args(argv)
    code, manifest = run(args)
    manifest["exit"] = code
    with open(args.manifest, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    err = manifest.get("error")
    print(json.dumps({"exit": code, "resolved_commit": manifest.get("resolved_commit"),
                      "files": len(manifest.get("files") or []), "error": err}), file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
