"""Guard rules table (04 2.1): one row per rule and per spoof. Verified classes only; spoofs give no
guard or a `name_only` hint, which fp_guarded and `fixed` never accept."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "map"


@pytest.fixture(scope="module")
def guards() -> dict[str, set[str]]:
    out = json.loads((FIX / "guardrules_solc_output.json").read_text())
    m = build_map({"src/GuardRules.sol": (FIX / "GuardRules.sol").read_text()}, out, list(family_categories("evm")))
    return {f["span"]: {g["class"] if g["class"] != "name_only" else f"name_only:{g['hint']}" for g in f["guards"]}
            for f in m.doc["semantic"]["functions"]}


TABLE = [
    # caller_check
    ("CallerRules.okEq()", {"caller_check"}),                  # require(msg.sender == owner)
    ("CallerRules.okNe()", {"caller_check"}),                  # if (msg.sender != owner) revert
    ("CallerRules.okAnd()", {"caller_check"}),                 # && combines
    ("CallerRules.okOrNegated()", {"caller_check"}),           # if (a != o || p) revert == require(a == o && !p)
    ("CallerRules.okAllowList()", {"caller_check"}),           # require(allowed[msg.sender])
    ("CallerRules.spoofSelf()", set()),                        # msg.sender == msg.sender
    ("CallerRules.spoofZero()", set()),                        # msg.sender != address(0)
    ("CallerRules.spoofZeroConst()", set()),                   # constant initialised to address(0)
    ("CallerRules.spoofParam(address)", set()),                # caller-chosen parameter
    ("CallerRules.spoofReversed()", set()),                    # polarity: reverts for the owner only
    ("CallerRules.spoofOr()", set()),                          # an OR branch without a check
    ("CallerRules.spoofNegatedAnd()", set()),                  # if (a != o && x > 0) revert is an OR
    ("CallerRules.spoofBlacklist()", set()),                   # negated lookup admits everyone else
    ("CallerRules.spoofTxOrigin()", set()),                    # tx.origin is no authority
    # pause_check
    ("PauseRules.okPause()", {"pause_check"}),                 # require(!paused)
    ("PauseRules.spoofPauseCounter()", set()),                 # not a bool sole operand
    ("PauseRules.spoofPauseLocal()", set()),                   # local, not state
    # reentrancy_lock
    ("LockRules.okLock()", {"reentrancy_lock"}),               # reads _a, writes _a before and after `_`
    ("LockRules.spoofOtherVar()", {"name_only:reentrancy_lock"}),  # checks _b, writes _c
    ("LockRules.spoofNoWriteBack()", set()),                   # never released, name gives no hint either
    # initializer_guard
    ("InitRules.okInit()", {"initializer_guard"}),             # require(!_inited); _inited = true; _
    ("InitRules.spoofInit()", {"name_only:initializer_guard"}),  # empty body
]


@pytest.mark.parametrize(("span", "expected"), TABLE, ids=[t[0] for t in TABLE])
def test_guard_rule(guards, span, expected):
    assert guards[span] == expected


def test_oz_reentrancy_guard_still_verified():
    out = json.loads((FIX / "guards_solc_output.json").read_text())
    m = build_map({"src/Guards.sol": (FIX / "Guards.sol").read_text()}, out, list(family_categories("evm")))
    f = next(f for f in m.doc["semantic"]["functions"] if f["span"] == "Guards.realLock()")
    assert f["guards"] == [{"class": "reentrancy_lock", "line": "src/Guards.sol:19"}]
