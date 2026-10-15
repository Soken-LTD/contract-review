"""Tests for the --locked contract in the Solana build step (security invariant).

Security rule: every cargo fetch and cargo build-sbf call in the sandbox must pass --locked.
A Cargo.lock format mismatch ("needs to be updated but --locked was passed") is deps_failed,
never a path that drops --locked or rewrites the lockfile.

Rationale: the lock file is part of the reviewed source.  Allowing cargo to re-resolve
dependencies (even only for format normalisation) changes the dependency set that actually
gets built, breaking provenance.  A hostile repo can trigger this error on purpose.

Two test categories:
  1. Source-level: grep build.py to verify no fetch or build invocation can omit --locked.
  2. Functional: mock _fetch_deps to return the stale-error string and verify deps_failed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

_WORKTREE_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_WORKTREE_SRC) not in sys.path:
    sys.path.insert(0, str(_WORKTREE_SRC))

_ADAPTER_ROOT = Path(__file__).resolve().parents[3] / "src" / "soken_review" / "adapters" / "solana"
_BUILD_PY = _ADAPTER_ROOT / "build.py"

_LOCK_STALE = "needs to be updated but --locked was passed"


# ---------------------------------------------------------------------------
# Source-level checks
# ---------------------------------------------------------------------------

class TestLockedInSource:
    """Static checks: build.py must not contain any unlocked fetch path."""

    def test_no_fetch_without_locked_in_source(self) -> None:
        """Every fetch_args list in the docker build path includes --locked."""
        src = _BUILD_PY.read_text()
        # fetch_args must always start with ["fetch", "--locked", ...]
        assert '"--locked"' in src, 'build.py must contain "--locked" in fetch args'

    def test_no_host_stale_variable(self) -> None:
        """The host_stale variable (deleted fallback) must not exist in build.py."""
        src = _BUILD_PY.read_text()
        assert "host_stale" not in src, (
            "host_stale variable was deleted as a security fix and must not be re-introduced; "
            "it allowed repos to bypass --locked by crafting a Cargo.lock v3"
        )

    def test_no_lock_stale_err_variable(self) -> None:
        """_LOCK_STALE_ERR (deleted fallback trigger) must not exist in build.py."""
        src = _BUILD_PY.read_text()
        assert "_LOCK_STALE_ERR" not in src, (
            "_LOCK_STALE_ERR was part of the deleted host_stale fallback and must not be re-introduced"
        )

    def test_no_fetch_nolocked_invocation(self) -> None:
        """fetch_nolocked (the unlocked re-fetch) must not exist in build.py."""
        src = _BUILD_PY.read_text()
        assert "fetch_nolocked" not in src, (
            "fetch_nolocked was the unlocked cargo fetch call deleted as a security fix"
        )

    def test_build_lock_args_always_includes_locked(self) -> None:
        """build_lock_args variable must not appear (it was the conditional that could omit --locked)."""
        src = _BUILD_PY.read_text()
        assert "build_lock_args" not in src, (
            "build_lock_args was conditional on host_stale; after the fix the build always uses "
            "lock_args which always contains --locked.  This variable must not be re-introduced."
        )

    def test_build_command_uses_lock_args(self) -> None:
        """Build command must use *lock_args expansion, which always includes --locked."""
        src = _BUILD_PY.read_text()
        # After the fix the build command line is: cmd += ["--", *lock_args, "--offline", ...]
        assert "*lock_args" in src, (
            "build command must expand *lock_args (which includes --locked), not a conditional"
        )


# ---------------------------------------------------------------------------
# Functional: stale-error → deps_failed, never a crash or unlocked retry
# ---------------------------------------------------------------------------

def _fake_build_image(version: str):
    """Return a minimal BuildImage for any version, without requiring images.lock.json entry."""
    from soken_review.adapters.solana.images import BuildImage
    line = ".".join(version.split(".")[:2])
    return BuildImage(
        version=version, line=line,
        ref=f"solanafoundation/solana-verifiable-build:{version}",
        upstream=f"solanafoundation/solana-verifiable-build@sha256:{'0'*64}",
        working_dir="/build", cargo_home="/root/.cargo",
        home="/root", active_toolchain="stable",
        arch_values=("sbfv1", "sbfv2", "sbfv3"),
        u_s1="not_run",
    )


def _minimal_candidate(tmp_path: Path):
    """A minimal Solana candidate with Cargo.lock and verify_args."""
    from soken_review.adapters.solana.fetch import SourceFiles, _make_candidate

    files = SourceFiles({
        "Cargo.toml": '[package]\nname = "my_program"\nversion = "0.1.0"\nedition = "2021"\n',
        "Cargo.lock": (
            'version = 3\n\n'
            '[[package]]\n'
            'name = "my_program"\n'
            'version = "0.1.0"\n'
        ),
        "src/lib.rs": "// stub\n",
    })
    cand = _make_candidate(files, provider="repo", repo_url="https://example.com/repo",
                           commit="aaa" * 14)
    # verify_args: use --base-image to pin version without requiring a real images.lock entry
    cand.settings["verify_args"] = [
        "--base-image", "solanafoundation/solana-verifiable-build:1.18.26"
    ]
    cand.settings["commit"] = "aaa" * 14
    cand.program_id = "11111111111111111111111111111112"  # type: ignore[attr-defined]
    return cand


class TestStaleLockFileDepsFailedNotCrash:
    """When cargo fetch --locked returns the stale-error, the outcome is deps_failed."""

    def test_sbf_cargo_stale_gives_deps_failed(self, tmp_path: Path) -> None:
        """sbf-cargo returning the stale-error string → deps_failed, no FileNotFoundError."""
        from soken_review.adapters.solana.build import _do_build

        cand = _minimal_candidate(tmp_path)

        # Patch _fetch_deps to return the stale-error on the first call (sbf-cargo).
        call_count = 0
        def _mock_fetch_deps(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return _LOCK_STALE

        with (
            patch("soken_review.adapters.solana.build._fetch_deps", side_effect=_mock_fetch_deps),
            patch("soken_review.adapters.solana.build.solana_images.build_image",
                  side_effect=_fake_build_image),
            patch("shutil.which", return_value="/usr/bin/docker"),
        ):
            result = _do_build(cand, tmp_path / "work")

        assert result.status == "failed"
        assert result.reason == "deps_failed", (
            f"Expected deps_failed, got {result.reason!r}.  "
            "A Cargo.lock stale error must never be silently retried without --locked."
        )
        # Must have tried sbf-cargo exactly once and stopped — not fallen through to an unlocked path.
        assert call_count == 1, (
            f"Expected exactly 1 _fetch_deps call before deps_failed, got {call_count}.  "
            "The stale-error must not trigger a second unlocked fetch."
        )

    def test_host_cargo_stale_gives_deps_failed(self, tmp_path: Path) -> None:
        """Host cargo returning the stale-error string → deps_failed."""
        from soken_review.adapters.solana.build import _do_build

        cand = _minimal_candidate(tmp_path)

        call_count = 0
        def _mock_fetch_deps(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            cmd = args[5] if len(args) > 5 else kwargs.get("command", [])
            if cmd and cmd[0] == "sbf-cargo":
                return None  # sbf-cargo succeeds
            return _LOCK_STALE   # host cargo returns the stale error

        with (
            patch("soken_review.adapters.solana.build._fetch_deps", side_effect=_mock_fetch_deps),
            patch("soken_review.adapters.solana.build.solana_images.build_image",
                  side_effect=_fake_build_image),
            patch("shutil.which", return_value="/usr/bin/docker"),
        ):
            result = _do_build(cand, tmp_path / "work2")

        assert result.status == "failed"
        assert result.reason == "deps_failed", (
            f"Expected deps_failed, got {result.reason!r}."
        )
        assert call_count == 2, (
            f"Expected 2 _fetch_deps calls (sbf-cargo ok, host cargo stale), got {call_count}."
        )

    def test_locked_in_every_fetch_argv(self, tmp_path: Path) -> None:
        """Every _fetch_deps call must pass a command list containing '--locked'."""
        from unittest.mock import MagicMock

        from soken_review.adapters.solana.build import _do_build

        cand = _minimal_candidate(tmp_path)
        captured: list[list[str]] = []

        def _capturing_fetch_deps(image, cargo_home, mounts, workdir, env, command, image_paths):
            captured.append(list(command))

        # Mock docker_argv so we don't need real sandbox profile, and patch subprocess.run
        # so the build container exits with non-zero (artifact_missing / failed after deps).
        fake_proc = MagicMock()
        fake_proc.returncode = 1
        fake_proc.stdout = b""
        fake_proc.stderr = b"mock build failed"

        with (
            patch("soken_review.adapters.solana.build._fetch_deps",
                  side_effect=_capturing_fetch_deps),
            patch("soken_review.adapters.solana.build.solana_images.build_image",
                  side_effect=_fake_build_image),
            patch("shutil.which", return_value="/usr/bin/docker"),
            patch("subprocess.run", return_value=fake_proc),
        ):
            _do_build(cand, tmp_path / "work3")

        assert captured, "Expected at least one _fetch_deps call"
        for argv in captured:
            assert "--locked" in argv, (
                f"fetch command {argv!r} does not contain --locked"
            )
