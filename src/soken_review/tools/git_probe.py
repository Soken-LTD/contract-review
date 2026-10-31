"""`git ls-remote` reachability probe and ref resolution (03 section 4.1).

Synchronous check in `review_start`: `git ls-remote <url>` with a 10 s wall; failure is
E_REPO_UNREACHABLE (private code goes through `kind: upload`). Ref resolution for the worker fetch:
`git ls-remote origin refs/heads/<ref> refs/tags/<ref> 'refs/tags/<ref>^{}'`; a branch and a tag of
that name is E_COMMIT_AMBIGUOUS; a tag uses its peeled `^{}` line when present (annotated tag),
else its own line; no line is E_UNPINNED_REF. A tag object id never reaches provenance; 40-hex
only (SHA-256 object-format repositories are refused).

git runs with no user or system config (no credential helper, no `insteadOf` rewrite, no prompt),
https only, so a repository is reachable only when it is public.
"""

from __future__ import annotations

import asyncio
import os
import re
import tempfile

from ..errors import ReviewError

PROBE_TIMEOUT_S = 10.0
# `git ls-remote` runs in the API process on every review_start with a repo source; at most this
# many at once, the rest wait (bounded by the probe timeout), so a burst of starts cannot fork
# an unbounded number of git processes on the API host.
MAX_CONCURRENT_PROBES = 4
_probe_slots: asyncio.Semaphore | None = None


def _slots() -> asyncio.Semaphore:
    global _probe_slots
    if _probe_slots is None:
        _probe_slots = asyncio.Semaphore(MAX_CONCURRENT_PROBES)
    return _probe_slots
_URL_RE = re.compile(r"^https://(github\.com|gitlab\.com|codeberg\.org)/[A-Za-z0-9][A-Za-z0-9._~/-]{0,300}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


def safe_repo_url(url: str) -> bool:
    return bool(_URL_RE.match(url)) and ".." not in url and "//" not in url[len("https://"):]


def safe_ref(ref: str) -> bool:
    return bool(_REF_RE.match(ref)) and ".." not in ref and not ref.endswith((".lock", "/", "."))


def _git_env(home: str) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/echo",
        "SSH_ASKPASS": "/bin/echo",
        "GIT_PROTOCOL_FROM_USER": "0",
        "LC_ALL": "C",
    }


_LS_OPTIONS = frozenset({"--symref"})


async def ls_remote(url: str, patterns: list[str], timeout: float = PROBE_TIMEOUT_S,
                    options: tuple[str, ...] = ()) -> tuple[int, str]:
    """Run `git ls-remote` on a validated public https URL. Returns (exit code, stdout); 124 on timeout.
    `options`: ls-remote flags from a fixed allowlist (`--symref`), placed before `--`."""
    if not safe_repo_url(url) or not set(options) <= _LS_OPTIONS:
        return 2, ""
    argv = ["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", "credential.helper=", "-c", "core.askPass=/bin/echo",
            "ls-remote", *options, "--", url, *patterns]
    async with _slots():
        return await _ls_remote(argv, timeout)


async def _ls_remote(argv: list[str], timeout: float) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as home:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=_git_env(home), cwd=home,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return 124, ""
    return proc.returncode or 0, out.decode("utf-8", errors="replace")


class GitLsRemoteProbe:
    """`RepoProbe` for `review_start`: reachable when `git ls-remote <url>` exits 0 within 10 s."""

    async def is_reachable(self, repo_url: str) -> bool:
        code, _ = await ls_remote(repo_url, ["HEAD"])
        return code == 0


def pick_ref(ls_output: str, ref: str) -> str:
    """Commit id for `ref` from `ls-remote` output (03 4.1 table, row `ref`). Pure."""
    rows: dict[str, str] = {}
    for line in ls_output.splitlines():
        sha, _, name = line.partition("\t")
        if name:
            rows[name.strip()] = sha.strip()
    head = rows.get(f"refs/heads/{ref}")
    tag = rows.get(f"refs/tags/{ref}")
    peeled = rows.get(f"refs/tags/{ref}^{{}}")
    if head and (tag or peeled):
        raise ReviewError("E_COMMIT_AMBIGUOUS", value=ref, matches=f"refs/heads/{ref}, refs/tags/{ref}")
    sha = peeled or tag or head
    if sha is None or not _SHA1_RE.match(sha):
        raise ReviewError("E_UNPINNED_REF", ref=ref)
    return sha


def pick_default_branch(ls_output: str) -> str | None:
    """Branch name from `git ls-remote --symref <url> HEAD` (`ref: refs/heads/<name>\tHEAD`). Pure."""
    for line in ls_output.splitlines():
        head, _, name = line.partition("\t")
        if name.strip() == "HEAD" and head.startswith("ref: refs/heads/"):
            branch = head[len("ref: refs/heads/"):].strip()
            return branch if safe_ref(branch) else None
    return None


async def default_branch(url: str) -> str | None:
    """The repository's default branch (its HEAD symref), or None when it cannot be read."""
    code, out = await ls_remote(url, ["HEAD"], options=("--symref",))
    return pick_default_branch(out) if code == 0 else None


async def resolve_ref(url: str, ref: str) -> str:
    """Resolve a branch or tag to a 40-hex commit with one `ls-remote` call.

    A ref that names no branch or tag is E_UNPINNED_REF with `default_branch` set when the
    repository's HEAD can be read, so the client is told the branch to use (matrix r5
    2026-10-31: `ref: main` on a repository whose default branch is `master`)."""
    if not safe_ref(ref):
        raise ReviewError("E_UNPINNED_REF", ref=ref[:80])
    code, out = await ls_remote(url, [f"refs/heads/{ref}", f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}"])
    if code != 0:
        raise ReviewError("E_REPO_UNREACHABLE", url=url)
    try:
        return pick_ref(out, ref)
    except ReviewError as err:
        if err.code != "E_UNPINNED_REF":
            raise
        branch = await default_branch(url)
        if branch and branch != ref:
            raise ReviewError("E_UNPINNED_REF", ref=ref, default_branch=branch) from None
        raise


def unpinned_ref_detail(err: ReviewError, ref: str) -> dict[str, str]:
    """`error_detail` of a job stopped on a ref: the ref, and the default branch when known (the
    status `what_default_branch` / `fix_default_branch` texts read it)."""
    detail = {"stage": "repo_ref", "ref": ref[:80]}
    branch = err.fields.get("default_branch") if err.code == "E_UNPINNED_REF" else None
    if isinstance(branch, str) and branch:
        detail.update(default_branch=branch[:100], mode="default_branch")
    return detail
