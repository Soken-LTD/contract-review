"""Every degraded analyzer state names its cause in plain words (MetaDAO blind run 2026-10-31:
analyzer_degraded true with no reason; cargo-audit had no RustSec snapshot)."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from soken_review.contract import bundle_tools
from soken_review.mapping.analyzer_note import job_analyzer_note, note_from, reasons_of
from soken_review.tools.start_status import _build_status_response

METADAO = {"status": "degraded", "not_run": ["cargo_audit"],
           "degraded_reasons": ["cargo_audit:rustsec_db_not_found:/root/.cache/soken/rustsec-db/7eebec69"],
           "tools": {"clippy": {"status": "ok", "items": []},
                     "cargo_audit": {"status": "not_run", "reason": "rustsec_db_not_found:/root/.cache/x"}}}


def test_metadao_static_map_names_cargo_audit_and_never_a_host_path():
    assert reasons_of(METADAO) == [("cargo_audit", "rustsec_db_not_found")]
    note = note_from(METADAO)
    assert note.startswith("cargo-audit did not run fully: the RustSec advisory snapshot was not available")
    assert "/root" not in note and "\u2014" not in note


def test_each_family_shape_yields_a_reason():
    assert reasons_of({"status": "not_run", "reason": "analyzer_failed"}) == [("slither", "analyzer_failed")]
    assert reasons_of({"status": "ok", "tool": "slither@0.11", "aderyn": "not_run"}) == [("aderyn", "not_available")]
    assert reasons_of({"status": "degraded", "analyzer": "not_run", "not_run": ["misti@0.8"]}) == [("misti", "not_run")]
    src_only = {"degraded_reasons": ["cargo_audit:build_failed", "clippy:build_compile_error"]}
    note = note_from(src_only)
    assert "clippy did not run fully: the build did not finish (compile error)" in note
    assert "cargo-audit did not run fully: the build failed" in note


def test_no_record_says_the_cause_was_not_recorded():
    assert note_from(None) == "An analyzer did not run fully, and the run did not record why."
    assert "build failed" in note_from({}, {"status": "failed"})


def test_job_note_reads_the_work_dir(tmp_path: Path):
    pins, work = tmp_path / "pins", tmp_path / "work" / "job_X"
    pins.mkdir()
    work.mkdir(parents=True)
    (work / "static_map.json").write_text(json.dumps(METADAO))
    assert "RustSec" in job_analyzer_note(pins, "job_X")
    (work / "static_map.json").unlink()
    (work / "map.json").write_text(json.dumps({"static": {"status": "not_run", "reason": "step_deadline", "tool": "caracal"}}))
    assert job_analyzer_note(pins, "job_X") == "caracal did not run fully: the analysis step ran out of time."


def test_status_carries_analyzer_note_when_degraded():
    job = {"job_id": "job_01J9ZZZZZZZZZZZZZZZZZZZZZZ", "state": "ready", "analyzer_degraded": True,
           "map_status": "full", "requester_role": "third_party_public_code", "ownership_proven": False}
    out = _build_status_response(job, "concise")
    assert out["analyzer_note"]          # no pin root wired here: the "not recorded" sentence
    schema = {t["name"]: t for t in bundle_tools()}["review_status"]["outputSchema"]
    Draft202012Validator(schema).validate(out)
    assert "analyzer_note" not in _build_status_response({**job, "analyzer_degraded": False}, "concise")
