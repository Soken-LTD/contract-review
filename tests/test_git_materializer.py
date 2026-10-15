"""soken-fetch (09 5.2, X6 to X8) against local repositories.

The production config allows https only; these tests swap in `protocol.file.allow=always` on the
module constant (never through the environment) and call the resolution and materialize steps
directly. The live https proof per host runs on the x86 runner (scripts/p0_git.py).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from soken_review.sandbox import git_materializer as gm

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
       "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}


def sh(*args: str, cwd: Path, stdin: bytes | None = None) -> str:
    out = subprocess.run(["git", *args], cwd=cwd, input=stdin, capture_output=True, check=True,
                         env={**os.environ, **ENV})
    return out.stdout.decode().strip()


@pytest.fixture(autouse=True)
def allow_file(monkeypatch):
    cfg = [(k, v) for k, v in gm.GIT_CONFIG if k != "protocol.allow"] + [("protocol.allow", "always")]
    monkeypatch.setattr(gm, "GIT_CONFIG", cfg)


def make_origin(tmp: Path, files: dict[str, bytes], name: str = "origin") -> tuple[Path, Path, str]:
    work = tmp / f"{name}-work"
    work.mkdir()
    sh("init", "-q", "-b", "main", cwd=work)
    for path, data in files.items():
        p = work / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    sh("add", "-A", cwd=work)
    sh("commit", "-q", "-m", "c1", cwd=work)
    bare = tmp / f"{name}.git"
    sh("clone", "-q", "--bare", str(work), str(bare), cwd=tmp)
    for key in ("uploadpack.allowFilter", "uploadpack.allowAnySHA1InWant"):
        sh("config", key, "true", cwd=bare)
    return work, bare, sh("rev-parse", "HEAD", cwd=work)


def push(work: Path, bare: Path) -> None:
    sh("push", "-q", "--mirror", str(bare), cwd=work)


def materialize(bare: Path, sha: str, tmp: Path) -> tuple[gm.Result, Path]:
    out = tmp / "src"
    out.mkdir()
    res = gm.Result()
    gm.materialize(f"file://{bare}", sha, str(out), "", str(tmp / "scratch"), ("localhost",), res, 0)
    return res, out


def test_full_sha_materializes_without_checkout(tmp_path):
    _, bare, sha = make_origin(tmp_path, {"src/a.rs": b"fn a() {}\n", "Cargo.toml": b"[package]\n"})
    (tmp_path / "scratch").mkdir()
    res, out = materialize(bare, sha, tmp_path)
    assert sorted(f["path"] for f in res.files) == ["Cargo.toml", "src/a.rs"]
    assert (out / "src/a.rs").read_bytes() == b"fn a() {}\n"
    assert not (out / ".git").exists()


def test_large_blob_is_listed_not_fetched(tmp_path):
    # X8: a 6 MiB blob stays on the server; listed too_large.
    big = os.urandom(6 * 1024 * 1024)
    _, bare, sha = make_origin(tmp_path, {"big.bin": big, "a.sol": b"contract A {}\n"})
    (tmp_path / "scratch").mkdir()
    res, out = materialize(bare, sha, tmp_path)
    assert res.too_large == ["big.bin"]
    assert not (out / "big.bin").exists() and (out / "a.sol").exists()


def test_symlink_recorded_not_written_and_hooks_never_run(tmp_path):
    # X6: symlink recorded only; a hooks dir in the tree is refused as a .git component.
    work, bare, _ = make_origin(tmp_path, {"a.txt": b"x"})
    (work / "link").symlink_to("/etc/passwd")
    sh("add", "-A", cwd=work)
    sh("commit", "-q", "-m", "c2", cwd=work)
    push(work, bare)
    sha = sh("rev-parse", "HEAD", cwd=work)
    (tmp_path / "scratch").mkdir()
    res, out = materialize(bare, sha, tmp_path)
    assert res.symlinks == [{"path": "link", "target": "/etc/passwd"}]
    assert not (out / "link").exists() and not (out / "link").is_symlink()


def _evil_commit(work: Path, bare: Path, entries: str) -> str:
    tree = sh("mktree", cwd=work, stdin=entries.encode())
    commit = sh("commit-tree", tree, "-m", "evil", cwd=work)
    sh("update-ref", "refs/heads/evil", commit, cwd=work)
    push(work, bare)
    return commit


def test_dotgit_tree_refused_by_fsck_at_fetch(tmp_path):
    # X6, CVE-2024-32002 class: a `.GIT/hooks` tree never reaches the object store.
    work, bare, _ = make_origin(tmp_path, {"a.txt": b"x"})
    blob = sh("hash-object", "-w", "--stdin", cwd=work, stdin=b"#!/bin/sh\ntouch /tmp/pwned\n")
    hooks = sh("mktree", cwd=work, stdin=f"100755 blob {blob}\tpost-checkout\n".encode())
    dotgit = sh("mktree", cwd=work, stdin=f"040000 tree {hooks}\thooks\n".encode())
    commit = _evil_commit(work, bare, f"040000 tree {dotgit}\t.GIT\n")
    (tmp_path / "scratch").mkdir()
    with pytest.raises(gm.Refusal) as e:
        materialize(bare, commit, tmp_path)
    assert e.value.code == gm.EXIT_INVALID and e.value.detail.startswith("fsck")
    assert not Path("/tmp/pwned").exists()


def test_case_pair_refused(tmp_path):
    work, bare, _ = make_origin(tmp_path, {"a.txt": b"x"})
    blob = sh("hash-object", "-w", "--stdin", cwd=work, stdin=b"same\n")
    commit = _evil_commit(work, bare, f"100644 blob {blob}\tReadme\n100644 blob {blob}\treadme\n"
                                      f"100644 blob {blob}\tdir\n")
    (tmp_path / "scratch").mkdir()
    res, out = materialize(bare, commit, tmp_path)
    assert [f["path"] for f in res.files] == ["Readme", "dir"]
    assert res.refused == [{"path": "readme", "reason": "case_collision"}]
    assert sorted(p.name for p in out.iterdir()) == ["Readme", "dir"]


@pytest.mark.parametrize("raw,reason", [
    (b"../x", "dot_segment"), (b"a/../../x", "dot_segment"), (b"/etc/x", "absolute_or_backslash"),
    (b"a\x01b", "control_char"), (b"a\\b", "absolute_or_backslash"), (b".git/config", "git_component"),
    (b"x/.Git./hooks", "git_component"), (b"\xff", "not_utf8"),
])
def test_check_path_refusals(raw, reason):
    with pytest.raises(gm.Refusal) as e:
        gm.check_path(raw)
    assert e.value.detail == reason


def test_check_path_nfc():
    assert gm.check_path("café.sol".encode()) == "café.sol"


def test_ref_resolution_branch_tag_and_codes(tmp_path):
    work, bare, sha = make_origin(tmp_path, {"a.txt": b"x"})
    sh("tag", "-a", "v1", "-m", "v1", cwd=work)
    sh("tag", "main", cwd=work)          # a branch and a tag of one name
    push(work, bare)
    url = f"file://{bare}"
    assert gm.resolve_ref(url, "v1") == (sha, "tag")          # annotated: the ^{} line, not the tag object
    with pytest.raises(gm.Refusal) as e:
        gm.resolve_ref(url, "main")
    assert e.value.code == gm.EXIT_AMBIGUOUS
    with pytest.raises(gm.Refusal) as e:
        gm.resolve_ref(url, "nope")
    assert e.value.code == gm.EXIT_NO_REF


def test_unknown_full_sha_is_not_found(tmp_path):
    _, bare, _ = make_origin(tmp_path, {"a.txt": b"x"})
    (tmp_path / "scratch").mkdir()
    with pytest.raises(gm.Refusal) as e:
        gm.fetch_commit(f"file://{bare}", "0" * 40, str(tmp_path / "scratch" / "c"))
    assert e.value.code == gm.EXIT_NOT_FOUND


def test_short_sha_resolves_and_ambiguity_lists_commits(tmp_path):
    work, bare, sha = make_origin(tmp_path, {"a.txt": b"x"})
    (tmp_path / "s1").mkdir()
    assert gm.resolve_short(f"file://{bare}", sha[:8], str(tmp_path / "s1")) == sha
    # find two commits sharing a 4-hex prefix (rev-parse needs >= 4); 7+ is enforced by the CLI
    seen: dict[str, str] = {}
    for i in range(400):
        (work / "a.txt").write_text(str(i))
        sh("commit", "-q", "-am", f"c{i}", cwd=work)
        h = sh("rev-parse", "HEAD", cwd=work)
        if h[:4] in seen:
            break
        seen[h[:4]] = h
    else:
        pytest.skip("no prefix collision in 400 commits")
    push(work, bare)
    (tmp_path / "s2").mkdir()
    with pytest.raises(gm.Refusal) as e:
        gm.resolve_short(f"file://{bare}", h[:4], str(tmp_path / "s2"))
    assert e.value.code == gm.EXIT_AMBIGUOUS and h in e.value.detail


def test_size_cap_exit_22(tmp_path, monkeypatch):
    monkeypatch.setattr(gm, "MAX_BYTES", 10)
    _, bare, sha = make_origin(tmp_path, {"a.txt": b"x" * 64})
    (tmp_path / "scratch").mkdir()
    with pytest.raises(gm.Refusal) as e:
        materialize(bare, sha, tmp_path)
    assert e.value.code == gm.EXIT_SIZE


def test_submodule_foreign_host_refused_and_allowed_one_fetched(tmp_path):
    _, sub_bare, sub_sha = make_origin(tmp_path, {"lib.sol": b"library L {}\n"}, name="sub")
    work, bare, _ = make_origin(tmp_path, {"a.sol": b"contract A {}\n"})
    sh("update-index", "--add", "--cacheinfo", f"160000,{sub_sha},lib/sub", cwd=work)
    sh("update-index", "--add", "--cacheinfo", f"160000,{sub_sha},lib/evil", cwd=work)
    (work / ".gitmodules").write_text(
        f'[submodule "sub"]\n\tpath = lib/sub\n\turl = file://{sub_bare}\n'
        '[submodule "evil"]\n\tpath = lib/evil\n\turl = https://evil.example/x/y\n')
    sh("add", ".gitmodules", cwd=work)
    sh("commit", "-q", "-m", "subs", cwd=work)
    push(work, bare)
    sha = sh("rev-parse", "HEAD", cwd=work)
    (tmp_path / "scratch").mkdir()
    out = tmp_path / "src"
    out.mkdir()
    res = gm.Result()
    real_check = gm.check_url

    def check_url(url, hosts):          # allow the local file:// submodule only
        if url.startswith("file://"):
            return url
        return real_check(url, hosts)

    import unittest.mock as um
    with um.patch.object(gm, "check_url", check_url):
        gm.materialize(f"file://{bare}", sha, str(out), "", str(tmp_path / "scratch"),
                       ("github.com",), res, 0)
    status = {s["path"]: s["status"] for s in res.submodules}
    assert status == {"lib/evil": "refused_host", "lib/sub": "fetched"}
    assert (out / "lib/sub/lib.sol").read_text() == "library L {}\n"


@pytest.mark.parametrize("url", [
    "http://github.com/a/b", "https://user@github.com/a/b", "https://github.com:443/a/b",
    "https://evil.com/a/b", "https://github.com/a", "https://github.com/a/../b",
    "https://github.com/a/b?x=1", "https://github.com/a/b%2f", "file:///etc",
])
def test_check_url_refusals(url):
    with pytest.raises(gm.Refusal):
        gm.check_url(url, gm.DEFAULT_HOSTS)


@pytest.mark.parametrize("ref", ["-x", "a..b", "a//b", "a@{1}", "x.lock", "refs/heads/x", "a b"])
def test_check_ref_refusals(ref):
    with pytest.raises(gm.Refusal):
        gm.check_ref(ref)


def test_cli_writes_manifest_on_refusal(tmp_path):
    out = tmp_path / "src"
    out.mkdir()
    code = gm.main(["--url", "https://evil.com/a/b", "--commit", "a" * 40, "--out", str(out),
                    "--manifest", str(tmp_path / "m.json"), "--scratch", str(tmp_path / "s")])
    assert code == gm.EXIT_INVALID
    assert '"exit": 25' in (tmp_path / "m.json").read_text()


# --- caps enforced while the work runs (review: resource-cap-defeat) ---------------------------

def test_blob_over_local_cap_not_written_when_host_ignores_filter(tmp_path, monkeypatch):
    monkeypatch.setattr(gm, "MAX_BLOB_BYTES", 1000)      # the 5m filter lets this 4 KiB blob through
    _, bare, sha = make_origin(tmp_path, {"big.txt": b"x" * 4096, "a.sol": b"contract A {}\n"})
    (tmp_path / "scratch").mkdir()
    res, out = materialize(bare, sha, tmp_path)
    assert res.too_large == ["big.txt"] and not (out / "big.txt").exists()


def _materialize_raises(bare, sha, tmp_path):
    (tmp_path / "scratch").mkdir()
    out = tmp_path / "src"
    out.mkdir()
    with pytest.raises(gm.Refusal) as e:
        gm.materialize(f"file://{bare}", sha, str(out), "", str(tmp_path / "scratch"), (), gm.Result(), 0)
    return e.value, out


def test_byte_cap_refuses_before_any_write(tmp_path, monkeypatch):
    monkeypatch.setattr(gm, "MAX_BYTES", 100)
    _, bare, sha = make_origin(tmp_path, {f"f{i}.txt": b"y" * 40 for i in range(5)})
    err, out = _materialize_raises(bare, sha, tmp_path)
    assert err.code == gm.EXIT_SIZE and list(out.iterdir()) == []


def test_many_empty_files_hit_file_cap_before_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(gm, "MAX_FILES", 5)
    _, bare, sha = make_origin(tmp_path, {f"e{i}": b"" for i in range(10)})
    err, out = _materialize_raises(bare, sha, tmp_path)
    assert err.code == gm.EXIT_SIZE and list(out.iterdir()) == []


def test_directory_cap_and_depth(tmp_path, monkeypatch):
    monkeypatch.setattr(gm, "MAX_DIRS", 3)
    _, bare, sha = make_origin(tmp_path, {f"d{i}/x": b"1" for i in range(6)})
    err, out = _materialize_raises(bare, sha, tmp_path)
    assert err.code == gm.EXIT_SIZE and err.detail == "dirs" and list(out.iterdir()) == []
    with pytest.raises(gm.Refusal) as e:
        gm.check_path("/".join(["d"] * 40).encode())
    assert e.value.detail == "too_deep"


def test_fetch_killed_when_object_store_grows_past_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(gm, "MAX_FETCH_BYTES", 64 * 1024)
    _, bare, sha = make_origin(tmp_path, {"rand.bin": os.urandom(3 * 1024 * 1024)})
    (tmp_path / "scratch").mkdir()
    with pytest.raises(gm.Refusal) as e:
        gm.fetch_commit(f"file://{bare}", sha, str(tmp_path / "scratch" / "c"))
    assert e.value.code == gm.EXIT_SIZE and e.value.detail == "fetch_bytes"


def test_wall_kills_whole_process_group(tmp_path):
    # slow drip: a child that never finishes, with a grandchild in the background
    import time

    pidfile = tmp_path / "pid"
    t0 = time.monotonic()
    with pytest.raises(gm.Refusal) as e:
        gm.run_watched(["sh", "-c", f"sleep 60 & echo $! > {pidfile}; sleep 60"], timeout=1,
                       env={"PATH": "/usr/bin:/bin"})
    assert e.value.code == gm.EXIT_TRANSIENT and time.monotonic() - t0 < 10
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(int(pidfile.read_text()), 0)


def test_run_deadline_stops_further_git_calls(monkeypatch):
    import time

    monkeypatch.setattr(gm, "_DEADLINE", time.monotonic() - 1)
    with pytest.raises(gm.Refusal) as e:
        gm.git(["--version"])
    assert e.value.code == gm.EXIT_TRANSIENT


def test_dir_usage_counts_blocks_and_fails_closed(tmp_path):
    for i in range(50):
        (tmp_path / f"t{i}").write_bytes(b"x")       # 50 bytes of content, >= 50 blocks allocated
    used, inodes = gm.dir_usage(str(tmp_path))
    assert inodes == 50 and used >= 50 * 512
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "f").write_bytes(b"y")
    locked.chmod(0)
    try:
        if os.geteuid() != 0:
            assert gm.dir_usage(str(tmp_path)) is None
    finally:
        locked.chmod(0o755)
