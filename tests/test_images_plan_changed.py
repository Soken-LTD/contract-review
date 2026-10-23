"""`scripts/images.py`: an image's build inputs are derived from its Dockerfile (the `docker/<dir>`
tree, `.dockerignore` and every repo path a `COPY`/`ADD` reads from the build context), and
`plan --changed` builds only the images whose inputs changed plus their dependants and
dependencies. Before this, images.yml listed the inputs by hand in `paths:` and missed the render
image's `src/soken_review` + `contract` (a stale soken-render digest on 2026-10-23)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_images():
    spec = importlib.util.spec_from_file_location("images", ROOT / "scripts" / "images.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ─── inputs derived from a Dockerfile ────────────────────────────────────────────────────────

def test_copy_sources_become_inputs_and_from_stages_are_skipped():
    m = load_images()
    text = (
        "FROM python:3.12\n"
        "COPY --from=node /usr/local/bin/node /usr/local/bin/node\n"
        "COPY --chown=10001:10001 contract /opt/app/contract\n"
        "COPY ./src/soken_review/ /opt/app/src/soken_review\n"
        "ADD docker/x/package.json docker/x/package-lock.json ./\n"
        "  copy slither_plugins /tmp/slither_plugins/\n"
    )
    assert m.inputs_for("docker/x", text) == [
        ".dockerignore", "contract", "docker/x", "docker/x/package-lock.json", "docker/x/package.json",
        "slither_plugins", "src/soken_review",
    ]


def test_discover_records_inputs_for_every_image():
    m = load_images()
    by_name = {i["name"]: i for i in m.discover(m._load_lock())}
    assert "src/soken_review" in by_name["soken-render"]["inputs"]
    assert "contract" in by_name["soken-render"]["inputs"]
    assert "slither_plugins" in by_name["hyperevm-analyze"]["inputs"]
    assert "src/soken_review/sandbox/git_materializer.py" in by_name["git-fetch"]["inputs"]
    assert "src/soken_review/adapters/ton/node_scripts" in by_name["ton-build"]["inputs"]
    assert by_name["evm-analyze"]["inputs"] == [".dockerignore", "docker/evm-analyze"]


# ─── plan --changed ───────────────────────────────────────────────────────────────────────────

def _names(plan: dict) -> set[str]:
    return {i["name"] for i in plan["level0"] + plan["level1"]}


def test_render_inputs_select_only_the_render_image():
    m = load_images()
    assert _names(m.plan(None, changed=["src/soken_review/report/kit/build.py"])) == {"soken-render"}
    assert _names(m.plan(None, changed=["contract/review.schema.json"])) == {"soken-render"}


def test_unrelated_paths_select_nothing():
    m = load_images()
    plan = m.plan(None, changed=["scripts/images.py", ".github/workflows/images.yml", "tests/x.py", "README.md"])
    assert plan["level0"] == [] and plan["level1"] == []


def test_a_changed_base_rebuilds_its_dependants():
    m = load_images()
    names = _names(m.plan(None, changed=["docker/evm-analyze/Dockerfile"]))
    assert {"evm-analyze", "hyperevm-analyze", "tron-analyze"} <= names
    assert "soken-render" not in names


def test_a_changed_dependant_pulls_its_base_in():
    m = load_images()
    names = _names(m.plan(None, changed=["docker/starknet-caracal/Dockerfile"]))
    assert names == {"starknet-build", "starknet-caracal"}


def test_shared_plugin_source_selects_both_consumers():
    m = load_images()
    names = _names(m.plan(None, changed=["slither_plugins/soken/hl_detectors.py"]))
    assert {"hyperevm-analyze", "tron-analyze"} <= names
    assert "soken-render" not in names


def test_dockerignore_selects_every_image():
    m = load_images()
    assert _names(m.plan(None, changed=[".dockerignore"])) == {i["name"] for i in m.discover(m._load_lock())}


def test_prefix_match_is_by_path_component():
    """`contract` must not match `contracts-foo/x` and a file input must match exactly."""
    m = load_images()
    assert m.plan(None, changed=["contracts-foo/x.json", "src/soken_review_other/y.py"])["level0"] == []
    names = _names(m.plan(None, changed=["src/soken_review/sandbox/git_materializer.py"]))
    assert "git-fetch" in names
    assert _names(m.plan(None, changed=["src/soken_review/sandbox/git_materializer.pyc"])) == {"soken-render"}


def test_only_and_changed_intersect():
    m = load_images()
    names = _names(m.plan({"soken-render"}, changed=["docker/evm-analyze/Dockerfile"]))
    assert names == set()
    names = _names(m.plan({"soken-render", "evm-analyze"}, changed=["docker/evm-analyze/Dockerfile"]))
    assert names == {"evm-analyze"}


def test_changed_none_keeps_the_full_plan():
    m = load_images()
    assert _names(m.plan(None)) == _names(m.plan(None, changed=None))


def test_cli_reads_changed_paths_from_a_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    import json

    m = load_images()
    listing = tmp_path / "changed.txt"
    listing.write_text("contract/x.json\n\n  \nREADME.md\n")
    assert m.main(["plan", "--changed", str(listing)]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert _names(plan) == {"soken-render"}
