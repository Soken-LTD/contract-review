"""Egress ACL rendering (09 4.3) and the image plan and lock (09 4.4)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from soken_review.sandbox import egress

ROOT = Path(__file__).resolve().parents[1]


def load_images():
    spec = importlib.util.spec_from_file_location("images", ROOT / "scripts" / "images.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_acl_default_rule_only_with_family_hosts():
    acl = yaml.safe_load(egress.render_acl("solana"))
    assert acl["services"] == []
    assert acl["default"]["action"] == "enforce"
    hosts = acl["default"]["allowed_domains"]
    assert {"github.com", "gitlab.com", "codeberg.org", "index.crates.io", "static.crates.io"} == set(hosts)
    assert "registry.npmjs.org" not in hosts          # another family's host


def test_config_allows_missing_role_and_denies_metadata():
    cfg = yaml.safe_load(egress.render_config())
    assert cfg["allow_missing_role"] is True and cfg["acl_file"] == "/etc/smokescreen/acl.yaml"
    assert "169.254.169.254" in cfg["deny_addresses"]


def test_no_provider_host_in_any_acl():
    # 09 4.3: no explorer, verifier or RPC host in an ACL; providers are supervisor calls.
    providers = yaml.safe_load((ROOT / "compliance" / "providers.yaml").read_text())
    provider_hosts = {h for row in providers for h in (row.get("hosts") or [])}
    for family in egress.FAMILIES:
        assert not provider_hosts & set(egress.allowlist(family)), family


def test_allowlist_refuses_wildcards_and_ips(tmp_path):
    limits = tmp_path / "limits.yaml"
    for bad in ("*.github.com", "10.0.0.1", "github.com:443", "HTTPS://x.com"):
        limits.write_text(yaml.safe_dump({"egress": {"all": [bad], "evm": []}}))
        with pytest.raises(ValueError):
            egress.allowlist("evm", limits)
    with pytest.raises(ValueError):
        egress.allowlist("nope")


def test_image_plan_covers_every_dockerfile_and_orders_deps():
    images = load_images()
    plan = images.plan(None)
    names0 = {i["name"] for i in plan["level0"]}
    names1 = {i["name"] for i in plan["level1"]}
    dirs = {p.parent.name for p in (ROOT / "docker").glob("*/Dockerfile")}
    assert dirs <= names0 | names1
    assert "evm-analyze" in names0 and {"hyperevm-analyze", "tron-analyze"} <= names1
    for i in plan["level1"]:
        argv = None
        with pytest.raises(SystemExit):
            argv = images.build_argv(i, None)       # a dependant never builds on a floating tag
        assert argv is None


def test_build_argv_pins_dependency_by_digest(tmp_path):
    images = load_images()
    hl = next(i for i in images.plan({"hyperevm-analyze"})["level1"] if i["name"] == "hyperevm-analyze")
    digest = "sha256:" + "ab" * 32
    (tmp_path / "evm-analyze.json").write_text(json.dumps(
        {"repository": "ghcr.io/soken-ltd/evm-analyze", "digest": digest}))
    argv = images.build_argv(hl, tmp_path)
    assert f"ghcr.io/soken-ltd/evm-analyze:0.1.0-dev=docker-image://ghcr.io/soken-ltd/evm-analyze@{digest}" in argv
    assert ["--platform", "linux/amd64"] == argv[:2]


def test_build_argv_selects_a_stage_only_when_the_entry_names_one():
    images = load_images()
    entry = next(i for i in images.plan({"git-fetch"})["level0"] if i["name"] == "git-fetch")
    assert "--target" not in images.build_argv(entry, None)
    argv = images.build_argv({**entry, "target": "build"}, None)
    assert argv[argv.index("--target") + 1] == "build"
    for bad in ("Build", "build stage", "../x", ""):
        with pytest.raises(SystemExit):
            images.build_argv({**entry, "target": bad}, None)


def test_actions_pin_check(tmp_path):
    spec = importlib.util.spec_from_file_location("pins", ROOT / "scripts" / "check_actions_pinned.py")
    pins = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pins)
    assert pins.check(ROOT) == []                     # this repo
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "x.yml").write_text(
        "on: push\njobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
        "      - uses: ./.github/actions/local\n")
    bad = pins.check(tmp_path)
    assert any("not pinned" in b for b in bad) and any("comment" in b for b in bad)
    assert any("permissions" in b for b in bad) and len(bad) == 3


def test_lock_updates_aliases_and_keeps_other_entries(tmp_path, monkeypatch):
    images = load_images()
    lock = tmp_path / "images.lock.json"
    lock.write_text((ROOT / "images.lock.json").read_text())
    monkeypatch.setattr(images, "LOCK", lock)
    before = json.loads(lock.read_text())["images"]
    results = tmp_path / "results"
    results.mkdir()
    digest = "sha256:" + "cd" * 32
    (results / "solana-build.json").write_text(json.dumps({
        "name": "solana-build", "repository": "ghcr.io/soken-ltd/solana-build", "tag": "4.3.0",
        "digest": digest, "commit": "x", "run_id": "1"}))
    assert images.lock(results) == 0
    after = json.loads(lock.read_text())["images"]
    assert after["solana-analyze"]["digest"] == digest
    assert after["solana-build"] == before["solana-build"]          # upstream pin untouched
    assert set(after) == set(before)
    assert after["evm-analyze"] == before["evm-analyze"]


def test_docs_family_renders_an_open_acl_without_hosts():
    # Context ingestion spec 3: `docs: {allow_public: true}` -> smokescreen `open` default, no host
    # list; the proxy's own private-range denial is what keeps metadata and LAN out of reach.
    acl = yaml.safe_load(egress.render_acl("docs"))
    assert acl["default"] == {"project": "soken-docs", "action": "open"}
    assert egress.allowlist("docs") == [] and egress.allow_public("docs") is True
    assert egress.network_name("docs") == "soken-egress-docs"
    assert egress.allow_public("evm") is False
    evm = yaml.safe_load(egress.render_acl("evm"))
    assert evm["default"]["action"] == "enforce" and "github.com" in evm["default"]["allowed_domains"]


def test_allow_public_row_must_be_exact(tmp_path):
    limits = tmp_path / "limits.yaml"
    for bad in ({"allow_public": False}, {"allow_public": True, "hosts": []}, {"open": True}):
        limits.write_text(yaml.safe_dump({"egress": {"all": [], "docs": bad}}))
        with pytest.raises(ValueError):
            egress.allowlist("docs", limits)
