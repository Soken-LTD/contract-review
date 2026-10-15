"""Supervisor never writes into a dir a container has written (commit review, 09 3.5)."""

from __future__ import annotations

from pathlib import Path

from soken_review.adapters.base import BuildResult, Candidate
from soken_review.adapters.ton.analyze import analyze

FUNC = """() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
  send_raw_message(begin_cell().end_cell(), 128);
}
"""


def test_analyze_records_not_written_through_planted_symlink(tmp_path: Path) -> None:
    attempt = tmp_path / "attempts" / "0"
    attempt.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.mkdir()
    (attempt / "analyze").symlink_to(victim)          # planted by the build container
    cand = Candidate(provider="user", files={"a.fc": FUNC}, sha256="0" * 64, language="func",
                     compiler=None, settings={}, std_json_input=None, entry_contract=None)
    _leads, static_map, _ = analyze(BuildResult(candidate=cand, status="ok", work_dir=str(attempt)))
    assert static_map["status"] == "ok"
    assert list(victim.iterdir()) == []
    assert (tmp_path / "attempts" / "0.host" / "analyze" / "leads.json").is_file()
