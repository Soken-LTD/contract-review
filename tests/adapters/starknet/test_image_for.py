"""`image_for(cairo_version)`: per-version env override, then the per-version image map, then the
images.lock.json `starknet-build` entry when its recorded Scarb equals the requested version.

The lock is what CI writes on every images run; the map is the per-version table that only a
human updates. Without the fallback a fresh lock digest leaves the map stale and the build step
fails closed (None) although a correct, pinned image exists (stand drop-in override, 2026-10-23)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.adapters.starknet import build as B

_ZERO = "sha256:" + "0" * 64
_MAP_DIGEST = "sha256:" + "ab" * 32
_LOCK_DIGEST = "sha256:" + "cd" * 32
_REPO = "ghcr.io/soken-ltd/starknet-build"


def _map(tmp_path: Path, monkeypatch, digest: str, version: str = "2.13.1") -> None:
    path = tmp_path / "image_map.json"
    path.write_text(json.dumps({"images": {version: {"repository": _REPO, "tag": version, "digest": digest}}}))
    monkeypatch.setattr(B, "_IMAGE_MAP", path)


def _lock(monkeypatch, scarb: str | None, image: str | None = f"{_REPO}@{_LOCK_DIGEST}") -> None:
    monkeypatch.setattr(B, "locked_image", lambda name: image if name == "starknet-build" else None)
    monkeypatch.setattr(B, "locked_tools", lambda name: {"scarb": scarb} if scarb and name == "starknet-build" else {})


def test_env_override_wins(tmp_path: Path, monkeypatch) -> None:
    _map(tmp_path, monkeypatch, _MAP_DIGEST)
    _lock(monkeypatch, "2.13.1")
    monkeypatch.setenv("SOKEN_IMAGE_STARKNET_BUILD_2_13_1", "local/starknet-build:dev")
    assert B.image_for("2.13.1") == "local/starknet-build:dev"


def test_map_digest_used_when_pinned(tmp_path: Path, monkeypatch) -> None:
    _map(tmp_path, monkeypatch, _MAP_DIGEST)
    _lock(monkeypatch, "2.13.1")
    monkeypatch.delenv("SOKEN_IMAGE_STARKNET_BUILD_2_13_1", raising=False)
    assert B.image_for("2.13.1") == f"{_REPO}@{_MAP_DIGEST}"


def test_placeholder_map_falls_back_to_lock_of_the_same_scarb(tmp_path: Path, monkeypatch) -> None:
    _map(tmp_path, monkeypatch, _ZERO)
    _lock(monkeypatch, "2.13.1")
    monkeypatch.delenv("SOKEN_IMAGE_STARKNET_BUILD_2_13_1", raising=False)
    assert B.image_for("2.13.1") == f"{_REPO}@{_LOCK_DIGEST}"


def test_version_absent_from_map_falls_back_to_lock_of_the_same_scarb(tmp_path: Path, monkeypatch) -> None:
    _map(tmp_path, monkeypatch, _MAP_DIGEST, version="2.11.4")
    _lock(monkeypatch, "2.13.1")
    monkeypatch.delenv("SOKEN_IMAGE_STARKNET_BUILD_2_13_1", raising=False)
    assert B.image_for("2.13.1") == f"{_REPO}@{_LOCK_DIGEST}"


@pytest.mark.parametrize("scarb", ["2.11.4", None])
def test_lock_of_another_scarb_is_not_used(tmp_path: Path, monkeypatch, scarb: str | None) -> None:
    _map(tmp_path, monkeypatch, _ZERO)
    _lock(monkeypatch, scarb)
    monkeypatch.delenv("SOKEN_IMAGE_STARKNET_BUILD_2_13_1", raising=False)
    assert B.image_for("2.13.1") is None


def test_unpinned_lock_fails_closed(tmp_path: Path, monkeypatch) -> None:
    _map(tmp_path, monkeypatch, _ZERO)
    _lock(monkeypatch, "2.13.1", image=None)
    monkeypatch.delenv("SOKEN_IMAGE_STARKNET_BUILD_2_13_1", raising=False)
    assert B.image_for("2.13.1") is None


def test_bad_version_is_none(tmp_path: Path, monkeypatch) -> None:
    _map(tmp_path, monkeypatch, _MAP_DIGEST)
    _lock(monkeypatch, "2.13.1")
    assert B.image_for("2.13") is None
    assert B.image_for("") is None


def test_shipped_map_and_lock_agree_on_2_13_1() -> None:
    """The committed data: the 2.13.1 row carries the lock's starknet-build digest and the lock
    records the Scarb the image was probed with (`scarb --version`, stand 2026-10-23)."""
    row = json.loads(B._IMAGE_MAP.read_text())["images"]["2.13.1"]
    lock = json.loads((Path(B.__file__).resolve().parents[4] / "images.lock.json").read_text())
    entry = lock["images"]["starknet-build"]
    assert row["repository"] == entry["repository"] == _REPO
    assert row["digest"] == entry["digest"] and not set(row["digest"].removeprefix("sha256:")) <= {"0"}
    assert entry["tools"]["scarb"] == "2.13.1"
