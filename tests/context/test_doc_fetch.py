"""Host side of the `context` step (spec section 3): docker argv, stderr hardening, output reading,
per-document failures, re-checked fields."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from soken_review.sandbox import doc_fetch as df

IMAGE = "ghcr.io/soken-ltd/doc-fetch@sha256:" + "a" * 64
URL = "https://docs.example.org/guide"


@pytest.fixture
def harness(monkeypatch):
    """Patch the docker boundary: the fake run_watched writes what a container would."""
    seen: dict = {}

    def install(writer=None, code: int = 0, killed_by: str | None = None, stderr: bytes = b""):
        def fake_run_watched(argv, job_dir, wall_s, kill, stderr=None, **kw):
            seen["argv"], seen["job_dir"], seen["wall_s"], seen["kw"] = argv, Path(job_dir), wall_s, kw
            seen["stderr"] = Path(stderr.name)
            stderr.write(b"stderr line\n")
            out = job_dir / "out" / "context"
            if writer is not None:
                writer(out)
            return code, killed_by

        monkeypatch.setattr(df, "run_watched", fake_run_watched)
        monkeypatch.setattr(df, "locked_image", lambda name: IMAGE if name == "doc-fetch" else None)
        monkeypatch.setattr(df, "network_name", lambda fam: f"soken-egress-{fam}")
        monkeypatch.setenv("SOKEN_SANDBOX_RUNTIME", "runc")
        return seen

    return install


def _write_ok(out: Path, n: int = 0, **extra) -> None:
    doc = {"kind": "evil", "url": "https://evil.example/", "final_url": URL, "status": "ok",
           "content_type": "text/html; charset=utf-8", "bytes": 123, "sha256_raw": "b" * 64,
           "fetched_at": "2026-10-23T10:00:00+00:00", "title": "Guide\n\x00 title", "text": "Hello\r\nworld",
           "bundle_hits": {"addresses": {"evm": ["0x" + "c" * 40, "not-an-address"], "solana": ["x"]},
                           "chain_ids": [1, "7", -3], "bundles": [{"url": "https://docs.example.org/a.js", "bytes": 5,
                                                                   "status": "ok"}, {"url": "http://bad/", "status": "ok"}]},
           "error": None, **extra}
    (out / f"{n}.json").write_text(json.dumps(doc))


def test_argv_mounts_only_out_on_the_docs_network(tmp_path: Path, harness) -> None:
    seen = harness(writer=_write_ok)
    doc = df.fetch_document("docs", URL, tmp_path, 0)
    argv = seen["argv"]
    assert argv[:2] == ["docker", "run"] and "--network=soken-egress-docs" in argv
    assert "--read-only" in argv and "--user" in argv and argv[argv.index("--user") + 1] == "10001:10001"
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    assert len(mounts) == 1 and mounts[0].endswith("dst=/work/out") and "readonly" not in mounts[0]
    cmd = argv[argv.index("soken-doc-fetch"):]
    assert cmd[:7] == ["soken-doc-fetch", "--kind", "docs", "--url", URL, "--out", "/work/out/context/0.json"]
    assert argv[argv.index("--wall") + 1] == str(df.DOC_WALL_S - 10)
    assert IMAGE in argv
    assert seen["wall_s"] == df.DOC_WALL_S
    assert seen["kw"]["max_bytes"] == df.DOC_MAX_BYTES and seen["kw"]["max_inodes"] == df.DOC_MAX_INODES
    assert "HTTPS_PROXY=http://smokescreen:4750" in argv
    assert doc["status"] == "ok"


def test_stderr_file_lives_in_the_work_root_not_under_the_mount(tmp_path: Path, harness) -> None:
    seen = harness(writer=_write_ok)
    df.fetch_document("docs", URL, tmp_path, 0)
    assert seen["stderr"] == seen["job_dir"] / "fetch.stderr"
    assert seen["stderr"].parent != seen["job_dir"] / "out"
    assert not (tmp_path / "doc-0").exists()         # the per-document work dir is removed afterwards


def test_output_is_rechecked_and_request_fields_win(tmp_path: Path, harness) -> None:
    harness(writer=_write_ok)
    doc = df.fetch_document("docs", URL, tmp_path, 0)
    assert doc["kind"] == "docs" and doc["url"] == URL                       # never the container's values
    assert doc["final_url"] == URL and doc["title"] == "Guide title" and doc["text"] == "Hello\r\nworld"
    assert doc["sha256_raw"] == "b" * 64 and doc["bytes"] == 123 and doc["error"] is None
    hits = doc["bundle_hits"]
    assert hits["addresses"] == {"evm": ["0x" + "c" * 40]}
    assert hits["chain_ids"] == [1]
    assert hits["bundles"] == [{"url": "https://docs.example.org/a.js", "bytes": 5, "status": "ok"}]


def test_container_failure_record_is_kept(tmp_path: Path, harness) -> None:
    def writer(out: Path) -> None:
        (out / "0.json").write_text(json.dumps({"status": "failed", "error": "too_large", "error_detail": "x" * 500,
                                                "sha256_raw": "zz", "bytes": -1, "final_url": "ftp://x/"}))
    harness(writer=writer)
    doc = df.fetch_document("website", URL, tmp_path, 0)
    assert doc["status"] == "failed" and doc["error"] == "too_large" and len(doc["error_detail"]) == 200
    assert doc["sha256_raw"] is None and doc["bytes"] == 0 and doc["final_url"] is None and doc["text"] == ""
    def bad(out: Path) -> None:
        (out / "0.json").write_text(json.dumps({"status": "failed", "error": "made_up"}))
    harness(writer=bad)
    assert df.fetch_document("website", URL, tmp_path, 0)["error"] == "unreachable"


@pytest.mark.parametrize("killed_by,error", [("wall", "timeout"), ("disk", "too_large")])
def test_supervisor_kill_maps_to_a_document_error(tmp_path: Path, harness, killed_by: str, error: str) -> None:
    harness(writer=_write_ok, killed_by=killed_by)
    doc = df.fetch_document("docs", URL, tmp_path, 0)
    assert doc["status"] == "failed" and doc["error"] == error


def test_missing_or_bad_output_is_unreachable_with_the_stderr_tail(tmp_path: Path, harness) -> None:
    harness(writer=None, code=26)
    doc = df.fetch_document("docs", URL, tmp_path, 0)
    assert doc["status"] == "failed" and doc["error"] == "unreachable" and "stderr line" in doc["error_detail"]
    harness(writer=lambda out: (out / "0.json").write_text("{not json"))
    assert df.fetch_document("docs", URL, tmp_path, 0)["error_detail"] == "output not json"
    harness(writer=lambda out: (out / "0.json").write_text("[1,2]"))
    assert df.fetch_document("docs", URL, tmp_path, 0)["error_detail"] == "output not an object"


def test_symlink_in_output_is_refused(tmp_path: Path, harness) -> None:
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"status": "ok", "text": "leak"}))

    def writer(out: Path) -> None:
        os.symlink(secret, out / "0.json")
    harness(writer=writer)
    doc = df.fetch_document("docs", URL, tmp_path, 0)
    assert doc["status"] == "failed" and "unsafe output" in doc["error_detail"]


def test_bad_url_and_unpinned_image_fail_per_document(tmp_path: Path, monkeypatch) -> None:
    doc = df.fetch_document("docs", "http://plain.example/", tmp_path, 0)
    assert doc["status"] == "failed" and doc["error"] == "blocked"
    monkeypatch.setattr(df, "locked_image", lambda name: None)
    monkeypatch.delenv("SOKEN_IMAGE_DOC_FETCH", raising=False)
    doc = df.fetch_document("docs", URL, tmp_path, 0)
    assert doc["status"] == "failed" and doc["error"] == "unreachable" and "not pinned" in doc["error_detail"]


def test_text_is_capped_and_title_cleaned() -> None:
    doc = df.sanitize_doc({"status": "ok", "text": "x" * (df.MAX_TEXT_CHARS + 5), "title": " a \t b "}, "docs", URL)
    assert len(doc["text"]) == df.MAX_TEXT_CHARS and doc["title"] == "a b"
    assert doc["bundle_hits"] == {}
