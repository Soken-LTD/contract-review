import subprocess

import pytest

from soken_review.evals import locate, sources
from soken_review.evals.sources import case_dir, case_tree, check_commit, check_repo, checkout

SHA = "24555d044802db4022112a94d6d70e74291a4b6d"


# --- path confinement (case dirs, permalink cache) ---------------------------------------


@pytest.mark.parametrize("case_id", ["../evil", "/etc", "evm-contest-0001/../../x", "", None, "a/b", "Evm-x-0001"])
def test_case_dir_refuses_traversal(tmp_path, case_id):
    with pytest.raises(ValueError):
        case_dir(tmp_path, case_id)


def test_case_dir_refuses_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "evm-contest-0001").symlink_to(outside)
    with pytest.raises(ValueError):
        case_dir(root, "evm-contest-0001")


def test_case_tree_refuses_bad_subdir(tmp_path):
    case = {"case_id": "sol-pattern-0001", "source": {"subdir": "../../etc"}}
    with pytest.raises(ValueError):
        case_tree(case, root=tmp_path)


@pytest.mark.parametrize(
    ("repo", "sha", "path"),
    [
        ("code-423n4/x", SHA, "../../../etc/passwd"),
        ("code-423n4/x", SHA, "/etc/passwd"),
        ("code-423n4/x", SHA, "src//A.sol"),
        ("code-423n4/x", SHA, "src/./A.sol"),
        ("../x", SHA, "A.sol"),
        ("code-423n4/x", "..", "A.sol"),
        ("code-423n4/x", "deadbeef", "A.sol"),
        ("code-423n4/x", SHA, "-rf/A.sol"),
    ],
)
def test_raw_cache_refuses_unsafe_parts(tmp_path, monkeypatch, repo, sha, path):
    monkeypatch.setattr(locate.urllib.request, "urlopen", lambda *a, **k: pytest.fail("network called"))
    assert locate.RawCache(tmp_path / "cache").get(repo, sha, path) is None
    assert not any(p for p in tmp_path.rglob("*") if p.is_file())


def test_raw_cache_refuses_symlinked_parent(tmp_path, monkeypatch):
    monkeypatch.setattr(locate.urllib.request, "urlopen", lambda *a, **k: pytest.fail("network called"))
    outside = tmp_path / "outside"
    outside.mkdir()
    cache = tmp_path / "cache"
    (cache / "code-423n4").mkdir(parents=True)
    (cache / "code-423n4" / "x").symlink_to(outside)
    assert locate.RawCache(cache).get("code-423n4/x", SHA, "src/A.sol") is None
    assert list(outside.iterdir()) == []


def test_raw_cache_reads_confined_hit(tmp_path):
    cache = tmp_path / "cache"
    hit = cache / "code-423n4" / "x" / SHA / "src" / "A.sol"
    hit.parent.mkdir(parents=True)
    hit.write_text("contract A {}\n")
    assert locate.RawCache(cache).get("code-423n4/x", SHA, "src/A.sol") == "contract A {}\n"


# --- git option smuggling ----------------------------------------------------------------


@pytest.mark.parametrize(
    "repo",
    [
        "-uhttps://github.com/a/b",
        "--upload-pack=touch /tmp/x",
        "ext::sh -c touch% /tmp/pwned",
        "file:///etc",
        "/srv/repo",
        "ssh://git@github.com/a/b",
        "http://github.com/a/b",
        "https://github.com/a/../b",
        "https://github.com/a/b --upload-pack=x",
        "https://github.com/a/-b",
    ],
)
def test_repo_refused(repo):
    with pytest.raises(ValueError):
        check_repo(repo)


@pytest.mark.parametrize("commit", ["main", "HEAD", "--all", "24555d0", SHA.upper(), SHA + "0", "-" + SHA[1:], None])
def test_commit_refused(commit):
    with pytest.raises(ValueError):
        check_commit(commit)


def test_checkout_validates_before_running_git(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(sources, "git_run", lambda *a, **k: calls.append(a) or "")
    for repo, commit in [("-oops", SHA), ("ext::sh -c id", SHA), ("file:///tmp", SHA),
                         ("https://github.com/a/b", "--upload-pack=x")]:
        with pytest.raises(ValueError):
            checkout(repo, commit, tmp_path / "t")
    with pytest.raises(ValueError):
        checkout("https://github.com/a/b", SHA, tmp_path / "t", sparse=["--no-cone"])
    assert calls == []


def test_git_run_pins_protocol_and_hooks(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(sources.subprocess, "run", fake_run)
    sources.git_run("fetch", "--", "origin", SHA)
    argv = seen["argv"]
    assert argv[:1] == ["git"]
    for opt in ("protocol.allow=never", "protocol.https.allow=always", "core.hooksPath=/dev/null"):
        assert opt in argv
    assert argv.index("--") < argv.index("origin")


def test_checkout_puts_double_dash_before_positionals(tmp_path, monkeypatch):
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return SHA if args[:1] == ("rev-parse",) else ""

    monkeypatch.setattr(sources, "git_run", fake)
    checkout("https://github.com/coral-xyz/sealevel-attacks", SHA, tmp_path / "t")
    remote = next(c for c in calls if c[:2] == ("remote", "add"))
    fetch = next(c for c in calls if c[0] == "fetch")
    assert remote[2] == "--" and fetch.index("--") < fetch.index(SHA)
