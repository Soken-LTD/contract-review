"""Corpus trees and permalinks are untrusted: symlinks never followed, URLs only to allowlisted hosts."""

import io
import urllib.error

import pytest

from soken_review.evals import locate, sources
from soken_review.evals.corpus import check_case

SHA = "24555d044802db4022112a94d6d70e74291a4b6d"


@pytest.fixture
def tree(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "Secret.sol").write_text("contract Secret {}\n" * 5)
    t = tmp_path / "tree"
    (t / "src").mkdir(parents=True)
    (t / "src" / "A.sol").write_text("contract A {}\n")
    (t / "src" / "Link.sol").symlink_to(outside / "Secret.sol")
    (t / "linkdir").symlink_to(outside)
    return t


def test_safe_read_refuses_symlinks_and_escapes(tree):
    assert locate.safe_read(tree, "src/A.sol") == "contract A {}\n"
    for rel in ("src/Link.sol", "linkdir/Secret.sol", "../outside/Secret.sol", "/etc/passwd", "src/./A.sol", ""):
        assert locate.safe_read(tree, rel) is None


def test_source_files_skip_symlinks(tree):
    assert locate.source_files(tree) == ["src/A.sol"]


def test_patch_through_symlink_ignored(tree):
    diff = "--- a/src/Link.sol\n+++ b/src/Link.sol\n@@ -1,1 +1,1 @@\n-contract Secret {}\n+contract S {}\n"
    assert locate.from_patch(diff, tree) == []


def test_corpus_check_refuses_symlinked_gt_file(tree, tmp_path):
    case = tmp_path / "case.yaml"
    case.write_text(
        "case_id: evm-contest-0001\nchain: evm\nchain_id: 1\nsplit: dev\norigin: contest\n"
        "source: {provider: repo, repo: 'https://github.com/a/b', commit: " + SHA + ", license: MIT}\n"
        "input_mode: repo\nprovenance_tier_expected: B\nexpected_outcome: report\nconsent: not_needed\n"
        "ground_truth:\n- {gt_id: GT-1, severity: High, category: evm.reentrancy, min_match: location_only,\n"
        "   root_cause_lines: [{file: src/Link.sol, start: 1, end: 1}]}\n"
    )
    report = check_case(case, tree=tree)
    assert any("not a regular file" in e for e in report.errors)


@pytest.mark.parametrize(
    "repo",
    [
        "https://gitlab.com/a/b",
        "https://127.0.0.1/a/b",
        "https://169.254.169.254/latest/meta",
        "https://github.com.evil.example/a/b",
        "https://github.com@evil.example/a/b",
        "https://github.com:8443/a/b",
        "https://raw.githubusercontent.com/a/b",
    ],
)
def test_repo_host_allowlist(repo):
    with pytest.raises(ValueError):
        sources.check_repo(repo)


def test_git_does_not_follow_redirects(monkeypatch):
    seen = {}
    monkeypatch.setattr(sources.subprocess, "run",
                        lambda argv, **k: seen.setdefault("argv", argv) and sources.subprocess.CompletedProcess(argv, 0, "", ""))
    sources.git_run("ls-remote", "--", "https://github.com/a/b", "HEAD")
    assert "http.followRedirects=false" in seen["argv"]


def test_raw_cache_refuses_redirect(tmp_path, monkeypatch):
    def redirected(url, timeout):
        raise urllib.error.HTTPError(url, 302, "redirect refused", {}, io.BytesIO())

    monkeypatch.setattr(locate._NO_REDIRECT, "open", redirected)
    assert locate.RawCache(tmp_path / "c").get("code-423n4/x", SHA, "src/A.sol") is None


def test_raw_cache_only_fetches_raw_host(tmp_path, monkeypatch):
    urls = []

    class Resp(io.BytesIO):
        def geturl(self):
            return urls[-1]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_open(url, timeout):
        urls.append(url)
        return Resp(b"contract A {}\n")

    monkeypatch.setattr(locate._NO_REDIRECT, "open", fake_open)
    assert locate.RawCache(tmp_path / "c").get("code-423n4/x", SHA, "src/A.sol") == "contract A {}\n"
    assert urls == [f"https://raw.githubusercontent.com/code-423n4/x/{SHA}/src/A.sol"]
