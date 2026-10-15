"""Per-version Solana build image publish flow (06 3.3.1; .github/workflows/solana-images.yml).

`images.plan_images(versions)` turns image_map.json rows into build-plan entries in the shape
scripts/images.py and the image-build / image-push composite actions consume;
`images.record_digests(results_dir)` writes the pushed digests back into `soken_image`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.adapters.solana import images

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ["1.18.26", "3.1.8", "3.1.10", "4.3.0"]
ZERO = "sha256:" + "0" * 64


def _result(version: str, digest: str, *, name: str | None = None, repository: str | None = None,
            tag: str | None = None, **extra) -> dict:
    return {"name": name or f"solana-build-{version}",
            "repository": repository or "ghcr.io/soken-ltd/solana-build",
            "tag": tag or version, "digest": digest,
            "commit": "c" * 40, "run_id": "123", "trivy_critical": 3, **extra}


@pytest.fixture
def map_copy(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "image_map.json"
    path.write_text(images.IMAGE_MAP_PATH.read_text())
    monkeypatch.setattr(images, "IMAGE_MAP_PATH", path)
    return path


class TestPlan:
    def test_every_published_line_has_a_build_target_entry(self):
        plan = images.plan_images(VERSIONS)
        assert [p["name"] for p in plan] == [f"solana-build-{v}" for v in VERSIONS]
        for p, v in zip(plan, VERSIONS):
            assert p["repository"] == "ghcr.io/soken-ltd/solana-build" and p["tag"] == v
            assert p["target"] == "build"                       # never the analyze stage
            assert p["dockerfile"] == "docker/solana-build/Dockerfile"
            assert p["dir"] == "docker/solana-build"
            assert p["deps"] == [] and p["dep_refs"] == []     # FROM is the upstream digest, not ghcr

    def test_build_args_pin_upstream_digest_and_toolchain(self):
        (p,) = images.plan_images(["3.1.10"])
        row = images.load_map()["images"]["3.1.10"]
        assert p["build_args"] == {
            "BASE_IMAGE": f"{row['repository']}@{row['digest']}",
            "ACTIVE_TOOLCHAIN": row["active_toolchain"],
        }
        assert "@sha256:" in p["build_args"]["BASE_IMAGE"]      # a digest, never a floating tag

    def test_plan_entries_pass_the_shared_build_argv(self):
        """The entry is accepted by scripts/images.py build_argv and selects the build stage."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("images_script", ROOT / "scripts" / "images.py")
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        (p,) = images.plan_images(["4.3.0"])
        argv = script.build_argv(p, None)
        assert argv[argv.index("--target") + 1] == "build"
        assert "--build-arg" in argv and any(a.startswith("ACTIVE_TOOLCHAIN=1.97.1") for a in argv)

    @pytest.mark.parametrize("bad", ["2.1.21", "9.9.9", "bpf", "4.3", "4.3.0; rm -rf /"])
    def test_rejects_versions_without_a_derived_image(self, bad):
        with pytest.raises(ValueError):
            images.plan_images([bad])

    def test_cli_plan_prints_json_list(self, capsys):
        assert images._main(["plan", "1.18.26", "4.3.0"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert [o["tag"] for o in out] == ["1.18.26", "4.3.0"]


class TestRecordDigests:
    def test_writes_digest_and_provenance_only_into_soken_image(self, map_copy, tmp_path):
        before = json.loads(map_copy.read_text())
        results = tmp_path / "results"
        results.mkdir()
        d1, d4 = "sha256:" + "ab" * 32, "sha256:" + "cd" * 32
        (results / "solana-build-1.18.26.json").write_text(json.dumps(_result("1.18.26", d1)))
        (results / "solana-build-4.3.0.json").write_text(json.dumps(_result("4.3.0", d4)))

        changed = images.record_digests(results)

        after = json.loads(map_copy.read_text())
        assert sorted(changed) == [f"1.18.26 ghcr.io/soken-ltd/solana-build@{d1}",
                                   f"4.3.0 ghcr.io/soken-ltd/solana-build@{d4}"]
        for v, d in (("1.18.26", d1), ("4.3.0", d4)):
            soken = after["images"][v]["soken_image"]
            assert soken["digest"] == d and soken["tag"] == v
            assert soken["repository"] == "ghcr.io/soken-ltd/solana-build"
            assert soken["built"] == {"commit": "c" * 40, "run_id": "123", "trivy_critical": 3}
            # Everything outside soken_image is byte-for-byte the same row.
            assert {k: x for k, x in after["images"][v].items() if k != "soken_image"} == \
                   {k: x for k, x in before["images"][v].items() if k != "soken_image"}
        # Untouched versions, the upstream-only rows, version_lines and the comment stay.
        for v in ("3.1.8", "3.1.10", "2.1.21", "bpf"):
            assert after["images"][v] == before["images"][v]
        assert after["version_lines"] == before["version_lines"]
        assert after["$comment"] == before["$comment"]
        assert list(after["images"]) == list(before["images"])     # order preserved

    def test_runtime_sees_the_recorded_image(self, map_copy, tmp_path, monkeypatch):
        monkeypatch.delenv(images.env_override_name("3.1.8"), raising=False)
        data = json.loads(map_copy.read_text())
        data["images"]["3.1.8"]["soken_image"]["digest"] = ZERO
        map_copy.write_text(json.dumps(data))
        assert images.build_image("3.1.8") is None                  # placeholder: fail closed
        results = tmp_path / "r"
        results.mkdir()
        d = "sha256:" + "ef" * 32
        (results / "x.json").write_text(json.dumps(_result("3.1.8", d)))
        images.record_digests(results)
        img = images.build_image("3.1.8")
        assert img is not None and img.ref == f"ghcr.io/soken-ltd/solana-build@{d}"

    @pytest.mark.parametrize("field,value", [
        ("digest", ZERO), ("digest", "sha256:abc"), ("digest", "latest"),
        ("repository", "ghcr.io/evil/solana-build"), ("repository", "ghcr.io/soken-ltd/solana-build:4.3.0"),
        ("tag", "2.1.21"), ("tag", "4.3.0-analyze"), ("tag", "bpf"),
    ])
    def test_rejects_bad_results_and_writes_nothing(self, map_copy, tmp_path, field, value):
        before = map_copy.read_text()
        results = tmp_path / "r"
        results.mkdir()
        good = _result("4.3.0", "sha256:" + "11" * 32)
        bad = _result("3.1.8", "sha256:" + "22" * 32)
        bad[field] = value
        (results / "a.json").write_text(json.dumps(good))
        (results / "b.json").write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            images.record_digests(results)
        assert map_copy.read_text() == before                       # all or nothing

    def test_empty_results_is_an_error(self, map_copy, tmp_path):
        results = tmp_path / "r"
        results.mkdir()
        with pytest.raises(ValueError):
            images.record_digests(results)

    def test_cli_record_digests(self, map_copy, tmp_path, capsys):
        results = tmp_path / "r"
        results.mkdir()
        (results / "a.json").write_text(json.dumps(_result("3.1.10", "sha256:" + "33" * 32)))
        assert images._main(["record-digests", str(results)]) == 0
        assert "3.1.10 ghcr.io/soken-ltd/solana-build@sha256:" + "33" * 32 in capsys.readouterr().out
        assert json.loads(map_copy.read_text())["images"]["3.1.10"]["soken_image"]["digest"].endswith("33" * 32)


def test_analyze_image_tag_does_not_collide_with_a_version_tag():
    """images.yml publishes the analyze stage under the same repository; its tag must not be a
    bare version, or a per-version build push would move it."""
    lock = json.loads((ROOT / "images.lock.json").read_text())["images"]["solana-analyze"]
    versions = {v for v, row in images.load_map()["images"].items() if "soken_image" in row}
    assert lock["repository"] == "ghcr.io/soken-ltd/solana-build"
    assert lock["tag"] not in versions
    assert {row["soken_image"]["tag"] for v, row in images.load_map()["images"].items()
            if "soken_image" in row} == versions
