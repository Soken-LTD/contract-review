"""Parsers of the client-path driver (scripts/client_path_driver.py) against the server's line formats:
review_leads (tools/read._format_lead), review_get_guide topic invariants (mapping/lifecycle.render_guide),
review_read_code (tools/read._read_range) and review_contract_map (tools/map_view.render_unit)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import client_path_driver as d

LEADS = """leads all 3 of 3 (High and Medium open 1, carried open 0), page 1
LEAD-0001 open reentrancy high src/Vault.sol:5-8 reentrancy-eth [slither] "Reentrancy in withdraw"
LEAD-0002 dismissed other low src/Vault.sol:1-1 unknown [aderyn+slither] "aderyn rule unknown; the detector gave no message"
LEAD-0003 open centralization medium contracts/Vault.sol:40-52 prev H-001 owner-power [soken-lifecycle] "x"
end"""

GUIDE = """guide_version v0 topic invariants chain evm
Every walk is traced through the code.
Lifecycle leads: LEAD-0003 stale_share_price src/Vault.sol:22
Invariant walks (2):
IW-VS-1 Shares back assets: the share price moves only with a deposit.
  focus: withdraw src/Vault.sol:5-8, deposit src/Vault.sol:20-30
  anchors: LEAD-0003 src/Vault.sol:22
IW-VS-4 Rounding at the boundaries: rounding favours the vault.
"""

READ = """Untrusted source data, file src/Vault.sol, lines 5-8
src/Vault.sol sha256:0123abcd lines 5-8 of 9
```
5|     function withdraw(uint256 a) external {
6|         (bool ok, ) = msg.sender.call{value: a}("");
7|         balances[msg.sender] -= a;
8|     }
```
flags none

Untrusted source data, file src/Other.sol, lines 1-2
src/Other.sol sha256:ffff0000 lines 1-2 of 500
```
1| pragma solidity ^0.8.0;
2| contract Other {}
```
flags none
next_start_line 3"""

MAP = """contract map full, units 2, page 1
unit Vault contract src/Vault.sol:3-9
  entries 1: withdraw
  roles: none found in code
  entry Vault.withdraw(uint256) external src/Vault.sol:5-8
    guards: none
unit Owned contract src/Owned.sol:1-40
  entries 2: setFeeRate, transferOwnership
  entry Owned.setFeeRate(uint256) external src/Owned.sol:10-14
    guards: caller_check 11
end"""


def test_parse_leads_reads_state_severity_location_and_tools():
    rows = d.parse_leads(LEADS)
    assert [r["id"] for r in rows] == ["LEAD-0001", "LEAD-0002", "LEAD-0003"]
    assert rows[0]["state"] == "open" and rows[0]["severity"] == "high"
    assert rows[0]["path"] == "src/Vault.sol" and (rows[0]["start"], rows[0]["end"]) == (5, 8)
    assert rows[1]["tools"] == ["aderyn", "slither"]
    assert rows[2]["severity"] == "medium" and rows[2]["tools"] == ["soken-lifecycle"]


def test_parse_walks_collects_focus_ranges_and_anchor_refs():
    walks = d.parse_walks(GUIDE)
    assert [w["id"] for w in walks] == ["IW-VS-1", "IW-VS-4"]
    assert walks[0]["focus"] == ["src/Vault.sol:5-8", "src/Vault.sol:20-30"]
    assert walks[0]["anchors"] == ["src/Vault.sol:22-22"]
    assert walks[1]["focus"] == [] and walks[1]["anchors"] == []


def test_parse_read_keeps_numbered_lines_and_file_totals():
    totals: dict[str, int] = {}
    out = d.parse_read(READ, totals)
    assert out["src/Vault.sol"][6] == '        (bool ok, ) = msg.sender.call{value: a}("");'
    assert sorted(out["src/Vault.sol"]) == [5, 6, 7, 8]
    assert out["src/Other.sol"][1] == "pragma solidity ^0.8.0;"
    assert totals == {"src/Vault.sol": 9, "src/Other.sol": 500}


def test_locate_block_finds_the_function_body():
    lines = d.parse_read(READ)["src/Vault.sol"]
    assert d.locate_block(lines, "function withdraw(") == (5, 8)


def test_parse_units_and_split_range():
    units = d.parse_units(MAP)
    assert [(u["id"], u["file"], u["start"], u["end"]) for u in units] == [
        ("Vault", "src/Vault.sol", 3, 9), ("Owned", "src/Owned.sol", 1, 40)]
    assert d.split_range("src/A.sol:1-900") == [("src/A.sol", 1, 400), ("src/A.sol", 401, 800), ("src/A.sol", 801, 900)]


def test_target_fixtures_are_well_formed():
    for name, spec in d.TARGETS.items():
        assert spec.name == name
        assert spec.start["source"]["kind"] in ("deployed", "repo")
        assert spec.probe_url.startswith("https://")
        if spec.finding:
            assert 10 <= len(spec.finding.title) <= 110 and not spec.finding.title.endswith(".")
            assert "{fact}" in spec.finding.description
