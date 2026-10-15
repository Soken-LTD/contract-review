"""Security tests for fetch.py sandboxed git clone.

Coordinator requirement: sandbox failure must be fail-closed.
When _clone_in_sandbox returns None, _clone_direct must NOT be called
unless SOKEN_SOLANA_DIRECT=1.

Also tests: no unsafe protocol flags, no host bypass.
"""

from __future__ import annotations


class TestSandboxFailClosed:
    """Sandbox failure = fetch failed (None returned); _clone_direct never called implicitly."""

    def test_sandbox_failure_returns_none_not_direct(self, tmp_path, monkeypatch):
        """When _clone_in_sandbox returns None in production mode, fetch returns None.

        _clone_direct must NOT be called.
        """
        # Ensure we are NOT in direct mode
        monkeypatch.delenv("SOKEN_SOLANA_DIRECT", raising=False)

        from soken_review.adapters.solana import fetch

        direct_calls: list[str] = []

        def _fake_sandbox(src_url, commit, work_dir):
            return None  # simulate sandbox failure

        def _fake_direct(src_url, commit, clone_dir):
            direct_calls.append(src_url)
            return {}  # would succeed if called

        monkeypatch.setattr(fetch, "_clone_in_sandbox", _fake_sandbox)
        monkeypatch.setattr(fetch, "_clone_direct", _fake_direct)

        result = fetch._clone_repo(
            "https://github.com/coral-xyz/anchor",
            "a" * 40,
            tmp_path,
        )

        assert result is None, "Sandbox failure must return None (fail closed)"
        assert not direct_calls, "_clone_direct must NOT be called on sandbox failure"

    def test_direct_mode_uses_clone_direct(self, tmp_path, monkeypatch):
        """With SOKEN_SOLANA_DIRECT=1, _clone_direct IS used (dev mode)."""
        monkeypatch.setenv("SOKEN_SOLANA_DIRECT", "1")

        from soken_review.adapters.solana import fetch

        direct_calls: list[str] = []
        sandbox_calls: list[str] = []

        def _fake_sandbox(src_url, commit, work_dir):
            sandbox_calls.append(src_url)

        def _fake_direct(src_url, commit, clone_dir):
            direct_calls.append(src_url)
            return {"Cargo.toml": "[package]\nname=\"x\"\nversion=\"0.1.0\""}

        monkeypatch.setattr(fetch, "_clone_in_sandbox", _fake_sandbox)
        monkeypatch.setattr(fetch, "_clone_direct", _fake_direct)

        result = fetch._clone_repo(
            "https://github.com/coral-xyz/anchor",
            None,
            tmp_path,
        )

        assert result is not None, "Direct mode should use _clone_direct"
        assert not sandbox_calls, "DIRECT mode must not call _clone_in_sandbox"
        assert direct_calls, "_clone_direct must be called in DIRECT mode"


class TestSandboxUsesMaterializer:
    """The sandboxed path is soken-fetch (09 5.2) on the solana egress family; flags and hardening
    are tested in tests/test_git_materializer.py."""

    def test_pinned_commit_goes_to_materializer(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SOKEN_SOLANA_DIRECT", raising=False)
        from soken_review.adapters.solana import fetch
        from soken_review.sandbox import repo_fetch

        calls = []

        def _fake(url, job_dir, family, commit=None, ref=None, image=None, **_kw):
            calls.append((url, family, commit, ref))
            src = job_dir / "src"
            src.mkdir(parents=True, exist_ok=True)
            (src / "lib.rs").write_text("fn main() {}\n")
            return repo_fetch.FetchResult(0, "", False, src, {"resolved_commit": "a" * 40})

        monkeypatch.setattr(repo_fetch, "materialize_repo", _fake)
        files = fetch._clone_repo("https://github.com/coral-xyz/anchor", "a" * 40, tmp_path)
        assert calls == [("https://github.com/coral-xyz/anchor", "solana", "a" * 40, None)]
        assert files == {"lib.rs": "fn main() {}\n"}

    def test_unpinned_uses_remote_head_and_refusal_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SOKEN_SOLANA_DIRECT", raising=False)
        from soken_review.adapters.solana import fetch
        from soken_review.sandbox import repo_fetch

        calls = []

        def _refuse(url, job_dir, family, commit=None, ref=None, image=None, **_kw):
            calls.append(ref)
            return repo_fetch.FetchResult(21, "E_COMMIT_NOT_FOUND", False, tmp_path, {"error": {"exit": 21}})

        monkeypatch.setattr(repo_fetch, "materialize_repo", _refuse)
        assert fetch._clone_repo("https://github.com/coral-xyz/anchor", None, tmp_path) is None
        assert calls == ["HEAD"]
