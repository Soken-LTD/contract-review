"""analyze() turns the new soken-ton-rules depth findings into schema-valid lead.v1.

Covers the end-to-end path for the added rules: the new ton.storage_persistence
category must map through rule_map.json + enums.yaml (not fall back to ton.best_practice),
and every produced lead must validate against contract/rubric/schemas/lead.v1.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.ton.analyze import analyze

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCHEMA = json.loads((_REPO_ROOT / "contract" / "rubric" / "schemas" / "lead.v1.json").read_text())

# recv_internal reads c4 and mutates it but never set_data(): TON-STO-01 + TON-AUTH-03.
VULN_FUNC = """() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    (int counter) = load_data();
    counter += 1;
    send_raw_message(begin_cell().store_coins(msg_value).end_cell(), 64);
}
"""


def _run(tmp_path: Path, files: dict[str, str], language: str = "func"):
    attempt = tmp_path / "attempts" / "0"
    attempt.mkdir(parents=True)
    cand = Candidate(provider="user", files=files, sha256="0" * 64, language=language,
                     compiler=None, settings={}, std_json_input=None, entry_contract=None)
    return analyze(BuildResult(candidate=cand, status="ok", work_dir=str(attempt)))


def test_depth_leads_are_valid_lead_v1(tmp_path: Path) -> None:
    leads, static_map, _ = _run(tmp_path, {"counter.fc": VULN_FUNC})
    assert static_map["status"] == "ok"
    assert leads, "expected at least one depth lead"
    for lead in leads:
        jsonschema.validate(lead, _SCHEMA)


def test_storage_persistence_category_is_mapped(tmp_path: Path) -> None:
    """TON-STO-01 resolves to its dedicated category, not the ton.best_practice fallback."""
    leads, _, _ = _run(tmp_path, {"counter.fc": VULN_FUNC})
    cats = {lead["category"] for lead in leads}
    assert "ton.storage_persistence" in cats, cats
