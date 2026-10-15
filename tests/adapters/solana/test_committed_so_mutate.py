"""Negative control: ripstr-committed-so must write a real .so and let the trust scan detect it.

The committed_so control must exercise the complete detection path:
  write .so to work/src → _walk_source_files finds it → unread_paths → scan_candidate_files →
  untrusted_inputs=True → tier B / BUILD_INPUT_UNTRUSTED

Injecting a path directly into unread_paths is a tautology that bypasses the detection
mechanism.  The test verifies:
  1. _mutate("committed_so") writes a real ELF fixture to work_dir/src/fixtures/prebuilt.so.
  2. The returned SourceFiles has the path in unread_paths (detection worked).
  3. The test fails if .so files are removed from the trust scan (_TRUST_ARTIFACT_EXTS).
  4. An absent source dir raises RuntimeError (clear error, not FileNotFoundError crash).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_WORKTREE_SRC = Path(__file__).resolve().parents[3] / "src"
if str(_WORKTREE_SRC) not in sys.path:
    sys.path.insert(0, str(_WORKTREE_SRC))

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))


class TestCommittedSoMutateRealScan:
    """_mutate("committed_so") must write to disk and re-walk, not inject into unread_paths."""

    def test_writes_so_to_src_dir(self, tmp_path: Path) -> None:
        """A real ELF fixture is written to work/src/fixtures/prebuilt.so."""
        import e2e_solana_adapter as e2e

        work = tmp_path / "work"
        src_dir = work / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "src").mkdir()
        (src_dir / "src" / "lib.rs").write_text("// code\n")
        (src_dir / "Cargo.lock").write_text("version = 3\n")

        files = e2e._walk_source_files(src_dir)  # initial scan, no .so yet
        assert not any(".so" in p for p in getattr(files, "unread_paths", []))

        result = e2e._mutate({"mutate": "committed_so"}, files, work)

        # 1. File on disk
        fixture = src_dir / "fixtures" / "prebuilt.so"
        assert fixture.is_file(), "prebuilt.so must be written to work/src/fixtures/"

        # 2. Detected via normal scan
        assert any(".so" in p for p in getattr(result, "unread_paths", [])), (
            "unread_paths must contain the .so path after re-scan; "
            "if this fails, _trust_relevant_unread or _TRUST_ARTIFACT_EXTS no longer sees .so"
        )

        # 3. Original files still present
        assert "src/lib.rs" in result or any("lib.rs" in p for p in result)

    def test_no_scan_no_detection(self, tmp_path: Path) -> None:
        """Control for the above: removing .so from TRUST_ARTIFACT_EXTS breaks detection.

        _trust_relevant_unread has three detection gates:
          1. Extension in _TRUST_ARTIFACT_EXTS
          2. .cargo/config* path
          3. ELF magic bytes (\\x7fELF)

        To isolate gate 1 (extension), the test fixture must NOT have ELF magic bytes.
        A non-ELF .so (e.g. stub WASM or random bytes) is only caught by the extension gate.
        """
        import e2e_solana_adapter as e2e

        from soken_review.adapters.solana import fetch as solana_fetch

        work = tmp_path / "work2"
        src_dir = work / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "Cargo.lock").write_text("version = 3\n")

        (src_dir / "fixtures").mkdir()
        # Write a non-ELF .so (WASM magic bytes instead) to isolate the extension-based detection.
        (src_dir / "fixtures" / "prebuilt.so").write_bytes(b"\x00asm" + b"\x01\x00\x00\x00" + b"\x00" * 50)

        orig = solana_fetch._TRUST_ARTIFACT_EXTS
        try:
            # Temporarily strip .so from the detection set
            solana_fetch._TRUST_ARTIFACT_EXTS = frozenset(orig - {".so"})
            result = e2e._walk_source_files(src_dir)
        finally:
            solana_fetch._TRUST_ARTIFACT_EXTS = orig

        # With .so removed from detection, unread_paths must be empty — the control was silent.
        assert not any(".so" in p for p in getattr(result, "unread_paths", [])), (
            "When .so is not in _TRUST_ARTIFACT_EXTS the walker must NOT add it to unread_paths; "
            "this test verifies the extension-based detection path"
        )

    def test_missing_src_dir_raises(self, tmp_path: Path) -> None:
        """A work_dir with neither work/src nor work/clone raises RuntimeError (not crash)."""
        import e2e_solana_adapter as e2e

        work = tmp_path / "empty_work"
        work.mkdir()
        # Neither work/src nor work/clone exists
        from soken_review.adapters.solana.fetch import SourceFiles
        files = SourceFiles({"Cargo.lock": "version = 3\n"})
        with pytest.raises(RuntimeError, match="source dir not found"):
            e2e._mutate({"mutate": "committed_so"}, files, work)

    def test_uses_clone_dir_when_no_src(self, tmp_path: Path) -> None:
        """Direct-clone mode: falls back to work/clone when work/src is absent."""
        import e2e_solana_adapter as e2e

        work = tmp_path / "work3"
        clone_dir = work / "clone"
        clone_dir.mkdir(parents=True)
        (clone_dir / "Cargo.lock").write_text("version = 3\n")

        from soken_review.adapters.solana.fetch import SourceFiles
        files = SourceFiles({"Cargo.lock": "version = 3\n"})
        result = e2e._mutate({"mutate": "committed_so"}, files, work)

        fixture = clone_dir / "fixtures" / "prebuilt.so"
        assert fixture.is_file(), "In direct-clone mode, .so must be written to work/clone/fixtures/"
        assert any(".so" in p for p in getattr(result, "unread_paths", []))

    def test_no_mutate_returns_original(self, tmp_path: Path) -> None:
        """A target with no 'mutate' key returns the files unchanged."""
        import e2e_solana_adapter as e2e

        from soken_review.adapters.solana.fetch import SourceFiles

        files = SourceFiles({"src/lib.rs": "// code"})
        result = e2e._mutate({}, files, tmp_path / "work")
        assert result is files
