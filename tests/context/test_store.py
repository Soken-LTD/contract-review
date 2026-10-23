"""ContextStore (spec section 4): write-once blobs, append, pin, header, idempotency, failed rows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.context.store import (
    HEADER_LINES,
    MAX_DOCS_PER_JOB,
    ContextStore,
    is_context_path,
    parse_path,
    render_header,
)

from .conftest import JOB_ID, doc


def test_empty_store_loads_without_manifest(tmp_path: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    assert store.entries == {} and store.documents == []
    assert not ContextStore.exists(tmp_path, JOB_ID)
    assert store.get_entry("context/whitepaper-1.md") is None


def test_add_assigns_paths_per_kind_and_writes_header(tmp_path: Path, fixtures: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    text = (fixtures / "whitepaper.md").read_text()
    entries = store.add([
        doc("whitepaper", "https://example.org/wp.md", text, title="Sample Token Whitepaper"),
        doc("website", "https://example.org/", "Hello site", title="Home"),
        doc("website", "https://example.org/about", "About us", title="About"),
    ])
    assert [e.path for e in entries] == ["context/whitepaper-1.md", "context/website-1.md", "context/website-2.md"]
    wp = store.get_entry("context/whitepaper-1.md")
    assert wp is not None and wp.ok and wp.status == "ok" and wp.error is None
    lines = store.read_all("context/whitepaper-1.md")
    assert lines[0] == "# Sample Token Whitepaper"
    assert lines[1] == "source: https://example.org/wp.md"
    assert lines[2] == "retrieved: 2026-10-23"
    assert lines[3] == f"sha256: {wp.sha256_raw}"
    assert lines[4] == "kind: whitepaper"
    assert lines[5] == ""
    assert lines[HEADER_LINES] == "# Sample Token Whitepaper"       # the document text starts after the header
    assert store.line_count("context/whitepaper-1.md") == len(lines) == wp.lines
    assert store.read_lines("context/whitepaper-1.md", 1, 2) == lines[:2]
    with pytest.raises(IndexError):
        store.read_lines("context/whitepaper-1.md", 0, 1)
    assert render_header(wp).count("\n") == HEADER_LINES
    assert ContextStore.exists(tmp_path, JOB_ID)
    manifest = json.loads((tmp_path / JOB_ID / "context" / "manifest.json").read_text())
    assert set(manifest) == {"context_pin", "entries"}
    row = manifest["entries"][0]
    for key in ("path", "kind", "url", "final_url", "title", "content_type", "bytes_raw", "sha256_raw", "sha256_lf",
                "lines", "fetched_at", "status", "error", "bundle_hits"):
        assert key in row, key
    assert manifest["context_pin"] == store.context_pin


def test_blobs_are_write_once(tmp_path: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    a, b = store.add([doc("docs", "https://d.example/a", "same text", title="T"),
                      doc("docs", "https://d.example/b", "same text", title="T")])
    assert a.sha256_lf != b.sha256_lf          # the header names the source, so the stored texts differ
    files = tmp_path / JOB_ID / "context" / "files"
    assert {a.sha256_lf, b.sha256_lf} == {p.name for p in files.iterdir()}
    before = (files / a.sha256_lf).stat().st_mtime_ns
    (tmp_path / JOB_ID / "context" / "manifest.json").unlink()      # forget the manifest, keep the blobs
    fresh = ContextStore.load(tmp_path, JOB_ID)
    again = fresh.add([doc("docs", "https://d.example/a", "same text", title="T")])[0]
    assert again.sha256_lf == a.sha256_lf
    assert (files / a.sha256_lf).stat().st_mtime_ns == before      # an existing blob is never rewritten


def test_add_is_idempotent_per_url_and_pin_changes_on_append(tmp_path: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    first = store.add([doc("docs", "https://d.example/one", "one")])[0]
    pin1 = store.context_pin
    again = store.add([doc("docs", "https://d.example/one", "changed text")])[0]
    assert again == first                                   # same URL -> the existing document
    assert store.context_pin == pin1
    store.add([doc("docs", "https://d.example/two", "two")])
    assert store.context_pin != pin1
    reloaded = ContextStore.load(tmp_path, JOB_ID)
    assert reloaded.context_pin == store.context_pin
    assert list(reloaded.entries) == ["context/docs-1.md", "context/docs-2.md"]
    assert reloaded.read_all("context/docs-2.md")[-1] == "two"


def test_failed_document_keeps_a_row_but_no_text_and_can_be_retried(tmp_path: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    failed = store.add([doc("terms", "https://t.example/terms", "", status="failed", error="timeout")])[0]
    assert failed.status == "failed" and failed.error == "timeout" and failed.sha256_lf is None and failed.lines == 0
    assert failed.path == "context/terms-1.md"
    assert store.get_entry(failed.path) is None             # a failed row is not readable
    assert not store.has_path(failed.path)
    with pytest.raises(KeyError):
        store.read_all(failed.path)
    retried = store.add([doc("terms", "https://t.example/terms", "Terms text")])[0]
    assert retried.path == "context/terms-1.md" and retried.ok    # same path, replaced in place
    assert [e.path for e in store.documents] == ["context/terms-1.md"]
    assert store.read_all(retried.path)[-1] == "Terms text"


def test_inline_document_is_keyed_by_content_hash(tmp_path: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    a = store.add([doc("whitepaper", None, "inline body", inline_path="wp.md")])[0]
    assert a.url is None and a.inline_path == "wp.md" and a.title == "wp.md"
    assert store.read_all(a.path)[1] == "source: inline wp.md"
    b = store.add([doc("whitepaper", None, "inline body", inline_path="wp.md")])[0]
    assert b == a
    c = store.add([doc("whitepaper", None, "other body", inline_path="wp.md")])[0]
    assert c.path == "context/whitepaper-2.md"


def test_cap_per_job_and_unknown_kind(tmp_path: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    store.add([doc("other", f"https://o.example/{i}", f"doc {i}") for i in range(MAX_DOCS_PER_JOB)])
    with pytest.raises(ValueError):
        store.add([doc("other", "https://o.example/extra", "x")])
    with pytest.raises(ValueError):
        store.add([doc("novel", "https://o.example/k", "x")])


def test_title_is_one_clean_line_and_text_is_lf(tmp_path: Path) -> None:
    store = ContextStore.load(tmp_path, JOB_ID)
    e = store.add([doc("docs", "https://d.example/x", "a\r\nb\rc", title="Multi\nline\x00 title\t here")])[0]
    assert e.title == "Multi line title here"
    assert store.read_all(e.path)[HEADER_LINES:] == ["a", "b", "c"]


def test_path_helpers() -> None:
    assert is_context_path("context/docs-1.md") and not is_context_path("src/Vault.sol")
    assert parse_path("context/privacy-3.md") == ("privacy", 3)
    assert parse_path("context/privacy-0.md") is None and parse_path("context/../x") is None
