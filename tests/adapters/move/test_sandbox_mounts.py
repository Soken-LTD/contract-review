"""Move sandbox bind mounts per step: source read-only after the pin, artifacts written by
build/analyze only, MOVE_HOME writable in every step (the new Sui package system takes a lock
file under $MOVE_HOME/git/ even for cached deps; read-only panicked the offline build, 2026-10-23).
Offline-ness is the step's --network=none, not the cache mount."""

from __future__ import annotations

from pathlib import Path

import pytest

from soken_review.adapters.move import sandbox as S


def _dirs(tmp_path: Path) -> dict[str, Path]:
    return {k: tmp_path / k for k in ("src", "out", "move")}


@pytest.mark.parametrize("step, out_ro", [("deps", True), ("build", False), ("analyze", False), ("prove", False)])
def test_mount_flags_per_step(tmp_path: Path, step: str, out_ro: bool) -> None:
    mounts = {c: ro for _h, c, ro in S.mounts_for(_dirs(tmp_path), step)}
    assert mounts == {"/work/src": True, "/work/out": out_ro, "/work/move": False}


def test_mounts_resolve_host_paths(tmp_path: Path) -> None:
    hosts = [h for h, _c, _ro in S.mounts_for(_dirs(tmp_path), "build")]
    assert all(h.is_absolute() for h in hosts)
