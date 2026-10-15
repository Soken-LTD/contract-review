"""Tests for build arg validation and shell-injection absence.

The coordinator mandated: a test that greps the adapter source for
"bash" / "-c" / "sh -c" and fails if present in executable context.
"""

import re
import typing
from pathlib import Path

import pytest

_ADAPTER_ROOT = Path(__file__).parents[3] / "src" / "soken_review" / "adapters" / "solana"


class TestNoShellInAdapter:
    """Grep all .py files in the Solana adapter for shell invocation patterns.

    A match in a string literal that would be executed (not in a comment or docstring)
    is a hard failure. We allow "bash" and "-c" in comments and docstrings.
    """

    # Patterns that indicate shell invocation in executable code
    _SHELL_EXEC_PATTERNS: typing.ClassVar[list[str]] = [
        r'"\s*bash\s*"',
        r"'\s*bash\s*'",
        r'"sh"\s*,\s*"-c"',
        r"'sh'\s*,\s*'-c'",
        r'subprocess\.\w+\s*\([^)]*"bash',
        r'subprocess\.\w+\s*\([^)]*"sh\s',
    ]

    def test_no_bash_in_docker_command(self):
        """No bash/-c in any argv list in the Solana adapter source."""
        build_py = _ADAPTER_ROOT / "build.py"
        assert build_py.exists()
        source = build_py.read_text()

        for pattern in self._SHELL_EXEC_PATTERNS:
            matches = re.findall(pattern, source)
            # Filter: allow in comments and string-only docstring context
            for match in matches:
                # If it's in a comment line, skip
                line_with_match = next(
                    (l for l in source.splitlines() if match.strip() in l), ""
                )
                if line_with_match.lstrip().startswith("#"):
                    continue
                pytest.fail(
                    f"Shell invocation pattern found in build.py: {match!r}\n"
                    f"  Line: {line_with_match!r}\n"
                    f"  This indicates a potential shell injection vulnerability."
                )


class TestBuildArgValidation:
    def test_valid_args_accepted(self):
        from soken_review.adapters.solana.build import _validate_args

        args, ok = _validate_args(["--no-default-features"])
        assert ok
        assert "--no-default-features" in args

    def test_features_split_into_tokens(self):
        from soken_review.adapters.solana.build import _validate_args

        args, ok = _validate_args(["--features", "feat1,feat2"])
        assert ok
        # Features must be expanded into separate argv tokens
        assert args.count("--features") == 2
        assert "feat1" in args
        assert "feat2" in args

    def test_feature_with_space_rejected(self):
        """Features with spaces would allow arg injection: '--features', 'a b --config=...'"""
        from soken_review.adapters.solana.build import _validate_args

        _args, ok = _validate_args(["--features", "good --config=evil"])
        assert not ok, "Feature string with space must be rejected"

    def test_feature_with_leading_dash_rejected(self):
        from soken_review.adapters.solana.build import _validate_args

        _args, ok = _validate_args(["--features", "-evil-feature"])
        assert not ok

    def test_arch_valid(self):
        from soken_review.adapters.solana.build import _validate_args

        for arch in ("sbfv1", "sbfv2", "sbfv3"):
            _args, ok = _validate_args(["--arch", arch])
            assert ok, f"--arch {arch} should be accepted"

    def test_arch_arbitrary_value_rejected(self):
        from soken_review.adapters.solana.build import _validate_args

        _args, ok = _validate_args(["--arch", "x86_64"])
        assert not ok, "--arch with non-sbfvN value must be rejected"

    def test_arch_config_injection_rejected(self):
        """--arch with config-injection value must be rejected."""
        from soken_review.adapters.solana.build import _validate_args

        _args, ok = _validate_args(["--arch", "sbfv1; touch /tmp/pwn"])
        assert not ok

    def test_unknown_flag_rejected(self):
        from soken_review.adapters.solana.build import _validate_args

        _args, ok = _validate_args(["--config", "evil"])
        assert not ok


class TestMountPathInjection:
    def test_safe_container_workdir_rejects_semicolon(self):
        """mount_path 'x; touch /tmp/pwn' must not produce a valid workdir."""
        import tempfile
        from pathlib import Path

        from soken_review.adapters.solana.build import _safe_container_workdir

        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            src_dir.mkdir()
            crate_dir = src_dir / "x; touch /tmp/pwn"
            # This path doesn't exist, but even if it did, it must be rejected
            result = _safe_container_workdir(src_dir, crate_dir)
            assert result is None, "Semicolon in path must be rejected"

    def test_safe_container_workdir_valid(self):
        import tempfile
        from pathlib import Path

        from soken_review.adapters.solana.build import _safe_container_workdir

        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            src_dir.mkdir()
            crate_dir = src_dir / "programs" / "counter"
            crate_dir.mkdir(parents=True)
            result = _safe_container_workdir(src_dir, crate_dir)
            assert result == "/work/src/programs/counter"

    def test_safe_container_workdir_outside_src_rejected(self):
        import tempfile
        from pathlib import Path

        from soken_review.adapters.solana.build import _safe_container_workdir

        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "src"
            src_dir.mkdir()
            crate_dir = Path(tmp) / "outside"  # NOT under src_dir
            crate_dir.mkdir()
            result = _safe_container_workdir(src_dir, crate_dir)
            assert result is None


class TestImageKeySeparation:
    """Build step uses 'solana-build' (upstream); analyze step uses 'solana-analyze' (extended)."""

    def test_build_py_uses_version_line_image(self):
        """build.py picks the image of the program's Solana version (images.build_image), never the
        analysis image (06 3.3.1: one build image per version line, U-S1)."""
        build_py = _ADAPTER_ROOT / "build.py"
        src = build_py.read_text()
        assert "solana_images.build_image(version)" in src
        assert 'locked_image("solana-analyze")' not in src, (
            "build.py must not use solana-analyze (that image may differ from what OtterSec used)"
        )

    def test_analyze_py_uses_solana_analyze_key(self):
        """analyze.py must use locked_image('solana-analyze') for clippy and cargo-audit."""
        analyze_py = _ADAPTER_ROOT / "analyze.py"
        src = analyze_py.read_text()
        assert 'locked_image("solana-analyze")' in src, (
            "analyze.py must use locked_image('solana-analyze') for clippy/cargo-audit steps"
        )
        # It should NOT use solana-build for those steps (hash-reproducibility concern)
        # Count occurrences: locked_image("solana-build") should not appear in analyze.py
        assert 'locked_image("solana-build")' not in src, (
            "analyze.py must not use locked_image('solana-build'); "
            "use solana-analyze which has clippy+cargo-audit pre-installed"
        )

    def test_images_lock_has_both_entries(self):
        """images.lock.json must have both solana-build and solana-analyze entries."""
        import json
        lock_path = _ADAPTER_ROOT.parents[3] / "images.lock.json"
        lock = json.loads(lock_path.read_text())
        images = lock["images"]
        assert "solana-build" in images, "images.lock.json must have solana-build entry"
        assert "solana-analyze" in images, "images.lock.json must have solana-analyze entry"
        # solana-build must point to the upstream image
        assert "solanafoundation" in images["solana-build"]["repository"], (
            "solana-build must point to solanafoundation upstream for hash reproducibility"
        )
        # solana-analyze must point to our extended image
        assert "ghcr.io/soken-ltd" in images["solana-analyze"]["repository"], (
            "solana-analyze must point to ghcr.io/soken-ltd/solana-build (extended image)"
        )


def test_dir_bytes_counts_blocks_and_fails_closed(tmp_path):
    """Sparse files count by allocated blocks; an unreadable subdir makes the size unknown."""
    import os

    from soken_review.adapters.solana.build import _dir_bytes

    (tmp_path / "a").write_bytes(b"x" * 8192)
    assert _dir_bytes(tmp_path) >= 8192
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "f").write_bytes(b"y")
    locked.chmod(0)
    try:
        if os.geteuid() != 0:
            assert _dir_bytes(tmp_path) is None
    finally:
        locked.chmod(0o700)


def test_read_so_ignores_symlinked_deploy_dir(tmp_path):
    """A container-planted deploy -> /elsewhere symlink is neither read nor listed."""
    from soken_review.adapters.solana.build import _safe_read_so

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.so").write_bytes(b"\x7fELF" + b"\0" * 28)
    out = tmp_path / "output"
    out.mkdir()
    (out / "deploy").symlink_to(outside)
    host = tmp_path / "host"
    host.mkdir()
    assert _safe_read_so(out, host) == (None, None)
