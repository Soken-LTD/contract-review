"""Move sandbox bind mounts per step: source read-only after the pin, artifacts written by
build/analyze only, MOVE_HOME writable (the new Sui package system takes a lock file under
$MOVE_HOME/git/ even for cached deps; read-only panicked the offline build, 2026-10-23) but only
the deps step writes the job's canonical cache: every other step mounts a fresh copy, so a build
cannot poison what analyze or prove compile against. Offline-ness is the step's --network=none."""

from __future__ import annotations

from pathlib import Path

import pytest

from soken_review.adapters.move import sandbox as S


def _dirs(tmp_path: Path) -> dict[str, Path]:
    d = {k: tmp_path / k for k in ("src", "out", "move")}
    for p in d.values():
        p.mkdir()
    return d


@pytest.mark.parametrize("step, out_ro", [("build", False), ("analyze", False), ("prove", False)])
def test_non_deps_steps_mount_a_writable_copy_of_the_cache(tmp_path: Path, step: str, out_ro: bool) -> None:
    dirs = _dirs(tmp_path)
    (dirs["move"] / "git").mkdir()
    (dirs["move"] / "git" / "dep.move").write_text("module a::a {}")
    copy = S.cache_copy(dirs, step)
    mounts = {c: (h, ro) for h, c, ro in S.mounts_for(dirs | {"move_copy": copy}, step)}
    assert mounts["/work/src"][1] is True and mounts["/work/out"][1] is out_ro
    host, ro = mounts["/work/move"]
    assert ro is False and host == copy.resolve() and host != dirs["move"].resolve()
    assert (copy / "git" / "dep.move").read_text() == "module a::a {}"


def test_deps_step_writes_the_canonical_cache_and_keeps_artifacts_read_only(tmp_path: Path) -> None:
    dirs = _dirs(tmp_path)
    mounts = {c: (h, ro) for h, c, ro in S.mounts_for(dirs, "deps")}
    assert mounts["/work/move"] == (dirs["move"].resolve(), False)
    assert mounts["/work/out"][1] is True and mounts["/work/src"][1] is True


def test_cache_copy_does_not_follow_symlinks(tmp_path: Path) -> None:
    dirs = _dirs(tmp_path)
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "k").write_text("x")
    (dirs["move"] / "link").symlink_to(secret, target_is_directory=True)
    (dirs["move"] / "flink").symlink_to(secret / "k")
    copy = S.cache_copy(dirs, "build")
    assert (copy / "link").is_symlink() and (copy / "flink").is_symlink()      # links copied as links
    assert not any(p.is_file() and not p.is_symlink() and p.read_text() == "x" for p in copy.rglob("*"))


def test_run_removes_the_copy_after_the_container(tmp_path: Path, monkeypatch) -> None:
    dirs = _dirs(tmp_path)
    seen: dict[str, Path] = {}

    def fake_run(argv, capture_output, timeout, check):
        copies = [p for p in dirs["move"].parent.iterdir() if p.name.startswith("move-build-")]
        seen["copy"] = copies[0]

        class P:
            returncode, stdout, stderr = 0, b"", b""
        return P()

    monkeypatch.setattr(S, "image_for", lambda chain: "img@sha256:" + "a" * 64)
    monkeypatch.setattr(S, "docker_argv", lambda **kw: ["docker", "run"])
    monkeypatch.setattr(S.subprocess, "run", fake_run)
    S.run("sui", "build", dirs, ["sui", "move", "build"], timeout=5)
    assert not seen["copy"].exists()
