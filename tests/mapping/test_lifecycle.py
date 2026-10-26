"""Lifecycle and invariant pass, server side (mapping/lifecycle*.py, rubric invariants.yaml).

The fixture `tests/fixtures/lifecycle/Lifecycle.sol` holds one positive and one negative case per
EVM signal: a snapshot never reset (StaleVault) next to the same snapshot reset on the last burn
(ResetVault), a Synthetix clock next to an admin-only setter, and an unguarded division. The
Solana cases are inline Anchor structs. None of them is taken from a review target."""

from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest
import yaml

from soken_review.mapping.build import build_map
from soken_review.mapping.lifecycle import (
    apply_lifecycle,
    build_lifecycle,
    build_walks,
    detect_protocol_types,
    leads_from_signals,
    load_lifecycle,
    map_pointer,
    rank_signals,
    render_guide,
    rubric,
)
from soken_review.mapping.lifecycle_evm import evm_signals
from soken_review.mapping.lifecycle_solana import solana_signals
from soken_review.mapping.step import family_categories

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "lifecycle"
RUBRIC = Path(__file__).resolve().parents[2] / "contract" / "rubric"
SOL = "src/Lifecycle.sol"


@pytest.fixture(scope="module")
def evm_case():
    out = json.loads((FIX / "lifecycle_solc_output.json").read_text())
    files = {SOL: (FIX / "Lifecycle.sol").read_text()}
    art = build_map(files, out, list(family_categories("evm")))
    return files, out, art


def _line_of(text: str, needle: str, nth: int = 1) -> int:
    hits = [i + 1 for i, line in enumerate(text.splitlines()) if needle in line]
    return hits[nth - 1]


def test_evm_signals_positive_and_negative(evm_case):
    files, out, art = evm_case
    text = files[SOL]
    sigs = evm_signals(out, files, None, art.doc["semantic"], rubric()["evm"])
    got = {(s["signal"], s["start"]) for s in sigs}
    stale_vars = {s["params"]["var"]: s for s in sigs if s["signal"] == "LC-EVM-STALE"}
    # StaleVault.lastSharePrice: snapshot written on deposit, never reset
    assert ("LC-EVM-STALE", _line_of(text, "lastSharePrice = totalAssets", 1)) in got
    assert stale_vars["lastSharePrice"]["strong"] is True
    # ResetVault.lastSharePrice is reset on the last burn: its write line carries no signal
    assert ("LC-EVM-STALE", _line_of(text, "lastSharePrice = totalAssets", 2)) not in got
    # admin-only configuration and the accumulator are no stale snapshots
    assert "feeBps" not in stale_vars and "rewardPerTokenStored" not in stale_vars
    assert "lastUpdateTime" not in stale_vars
    # Synthetix clock: rewardPerToken returns early while nothing is staked, the clock still moves
    accrue = [s for s in sigs if s["signal"] == "LC-EVM-ACCRUE"]
    assert [s["start"] for s in accrue] == [_line_of(text, "lastUpdateTime = block.timestamp")]
    assert accrue[0]["params"]["clocks"] == "lastUpdateTime"
    # zero branches: the if in StaleVault.deposit and the ternary in ResetVault.deposit
    assert ("LC-EVM-EMPTY", _line_of(text, "if (supply == 0)")) in got
    assert ("LC-EVM-EMPTY", _line_of(text, "totalSupply() == 0 ?")) in got
    # an unguarded division by the population
    assert ("LC-EVM-DIV", _line_of(text, "amount * 1e18 / totalStaked")) in got
    # the guarded division inside rewardPerToken is no signal
    assert ("LC-EVM-DIV", _line_of(text, "rewardRate * 1e18 / totalStaked")) not in got


def test_rank_caps_and_grades():
    lim = rubric()["limits"]
    sigs = [{"signal": "LC-EVM-EMPTY", "file": "a.sol", "start": i, "end": i, "strong": True, "score": 70,
             "params": {"fn": f"f{i}", "subject": "totalSupply()", "vars": "x"}} for i in range(1, 20)]
    sigs.append({"signal": "LC-EVM-DIV", "file": "a.sol", "start": 99, "end": 99, "strong": False, "score": 20,
                 "params": {"fn": "g", "subject": "totalSupply()"}})
    ranked = rank_signals(sigs)
    assert len(ranked) == lim["max_leads"]
    assert sum(1 for s in ranked if s["severity_raw"] == "warning") == lim["max_medium"]
    weak = rank_signals([{**sigs[0], "strong": False}])
    assert weak[0]["severity_raw"] == "note"


def test_leads_are_lead_v1_and_text_from_rubric(evm_case):
    files, out, art = evm_case
    lc = build_lifecycle("evm", files, art.doc, out, None)
    leads = leads_from_signals(lc["signals"], 7)
    schema = json.loads((RUBRIC / "schemas" / "lead.v1.json").read_text())
    for lead in leads:
        jsonschema.validate(lead, schema)
        assert lead["tools"] == [f"soken-lifecycle@{rubric()['version']}"]
        assert "{" not in lead["message"] and "—" not in lead["message"]
    assert leads[0]["id"] == "LEAD-0007"
    sev = yaml.safe_load((RUBRIC / "analyzer_severity.yaml").read_text())
    assert sev["analyzers"]["soken-lifecycle"]["warning"] == "Medium"


SETTLE_RS = """
use anchor_lang::prelude::*;

#[program]
pub mod locker {
    pub fn settle(ctx: Context<Settle>) -> Result<()> { Ok(()) }
    pub fn claim(mut ctx: Context<Claim>) -> Result<()> { Ok(()) }
}

#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(mut)]
    pub borrower: Signer<'info>,
    /// CHECK: stored on the position; associated_token::authority = borrower in a comment is ignored
    pub lender: UncheckedAccount<'info>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = lender,
        associated_token::token_program = token_program,
    )]
    pub lender_ata: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, address = position.payout_account)]
    pub payout: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    #[account(mut, token::authority = vault_authority)]
    pub vault_ata: InterfaceAccount<'info, TokenAccount>,
    #[account(seeds = [b"auth"], bump)]
    pub vault_authority: UncheckedAccount<'info>,
    pub position: Account<'info, Position>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    pub lender: Signer<'info>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = lender)]
    pub lender_ata: Account<'info, TokenAccount>,
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Release<'info> {
    pub caller: Signer<'info>,
    pub recipient: SystemAccount<'info>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = recipient,
              associated_token::token_program = token_program)]
    pub recipient_ata: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct Payout<'info> {
    pub keeper: Signer<'info>,
    #[account(mut, has_one = mint)]
    pub escrow: AccountLoader<'info, Escrow>,
    #[account(mut, associated_token::mint = mint, associated_token::authority = escrow)]
    pub escrow_token: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = escrow.load()?.beneficiary @ LockerError::WrongOwner,
    )]
    pub beneficiary_token: Box<Account<'info, TokenAccount>>,
    pub mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}
"""


def test_solana_signals():
    files = {"programs/locker/src/lib.rs": SETTLE_RS, "programs/locker/tests/fake.rs": SETTLE_RS}
    sigs = solana_signals(files, rubric()["solana"])
    by = {(s["signal"], s["params"]["account"]): s for s in sigs}
    # counterparty-controlled ATA: lender does not sign settle
    auth = by[("LC-SOL-AUTH", "lender_ata")]
    assert auth["params"]["ix"] == "settle" and auth["params"]["authority"] == "lender"
    assert auth["file"] == "programs/locker/src/lib.rs"
    assert auth["start"] == _line_of(SETTLE_RS, "#[account(", 2) and auth["end"] == _line_of(SETTLE_RS, "pub lender_ata")
    # pinned to a stored key while the instruction has a signer
    assert ("LC-SOL-PIN", "payout") in by
    # the claimant signs Claim; a PDA authority; a Token-2022-only program; test files: no signal
    assert not any(s["params"]["ix"] in ("claim",) for s in sigs)
    assert ("LC-SOL-AUTH", "vault_ata") not in by and ("LC-SOL-AUTH", "vault") not in by
    assert ("LC-SOL-AUTH", "recipient_ata") not in by
    assert all("tests/" not in s["file"] for s in sigs)
    # a program data account as authority is a PDA the program signs for: no signal; a party key
    # stored in program state is the strongest form
    assert ("LC-SOL-AUTH", "escrow_token") not in by
    stored = by[("LC-SOL-AUTH", "beneficiary_token")]
    assert stored["score"] > auth["score"] and stored["params"]["authority"] == "escrow.load()?.beneficiary"
    assert len(sigs) == 3


def test_protocol_types_and_walks(evm_case):
    files, out, art = evm_case
    lc = build_lifecycle("evm", files, art.doc, out, None)
    types = [t["id"] for t in lc["protocol_types"]]
    assert types[0] == "vault_shares"
    leads_from_signals(lc["signals"], 1)
    from soken_review.mapping.lifecycle import _in_scope_functions

    walks = build_walks(lc["protocol_types"], _in_scope_functions(art.doc, "evm"), lc["signals"])
    w1 = next(w for w in walks if w["id"] == "IW-VS-1")
    assert any(f["name"] == "deposit" for f in w1["focus"])
    assert all(re.match(r"^src/Lifecycle\.sol:\d+-\d+$", f["range"]) for f in w1["focus"])
    assert 1 <= len(w1["anchors"]) <= rubric()["limits"]["max_walk_anchors"]
    assert len(walks) <= rubric()["limits"]["max_walks"]
    # signal-driven type when no catalogue name matches
    assert [t["id"] for t in detect_protocol_types({"lz_receive", "send"}, {"LC-SOL-AUTH"})] == ["external_accounts"]
    assert detect_protocol_types({"lz_receive"}, set()) == []


def test_apply_lifecycle_merges_and_is_idempotent(tmp_path, evm_case):
    files, out, art = evm_case
    job = "job-lc"
    (tmp_path / job).mkdir()
    prior = [{"id": "LEAD-0001", "rule_id": "slither:reentrancy-eth", "tools": ["slither@0.11.3"],
              "category": "evm.reentrancy", "analyzer_severity_raw": "High", "severity_norm": "High",
              "file": SOL, "start": 3, "end": 4, "state": "open"},
             {"id": "LEAD-0002", "rule_id": "slither:timestamp", "tools": ["slither@0.11.3"],
              "category": "evm.timestamp", "analyzer_severity_raw": "Low", "severity_norm": "Low",
              "file": SOL, "start": 5, "end": 5, "state": "open"}]
    (tmp_path / job / "leads.json").write_text(json.dumps(prior))
    s1 = apply_lifecycle(tmp_path, job, "evm", files, art.doc, out, None)
    leads1 = json.loads((tmp_path / job / "leads.json").read_text())
    s2 = apply_lifecycle(tmp_path, job, "evm", files, art.doc, out, None)
    leads2 = json.loads((tmp_path / job / "leads.json").read_text())
    assert s1 == s2 and leads1 == leads2
    assert len(leads1) == 2 + s1["leads"] and s1["leads"] > 0
    ids = [x["id"] for x in leads1]
    assert len(set(ids)) == len(ids) and "LEAD-0003" in ids
    assert leads1[0]["severity_norm"] == "High"           # keyset order: severity first
    lc = load_lifecycle(tmp_path, job)
    assert lc and lc["walks"] and all(a["lead_id"] in ids for w in lc["walks"] for a in w["anchors"])
    assert "invariant walks" in (map_pointer(lc) or "")


def test_guide_rendering(tmp_path, evm_case):
    files, out, art = evm_case
    (tmp_path / "j").mkdir()
    apply_lifecycle(tmp_path, "j", "evm", files, art.doc, out, None)
    text = "\n".join(render_guide(load_lifecycle(tmp_path, "j"), "evm"))
    assert "IW-VS-1" in text and "focus:" in text and "anchors:" in text and "invariant_walks" in text
    generic = "\n".join(render_guide(None, "evm"))
    assert "IW-LE-1" in generic and "IW-VS-1" in generic


def test_rubric_text_is_plain():
    """Client-facing rubric text: no em dashes, no second person, every placeholder known."""
    r = rubric()
    texts = [d["message"] for d in r["lifecycle_signals"].values()]
    texts += [w["text"] for t in r["protocol_types"].values() for w in t["walks"]]
    texts += [r["guide"]["intro"], *r["guide"]["steps"], r["map_pointer"]]
    for t in texts:
        assert "—" not in t and "–" not in t
        assert not re.search(r"\byou(r)?\b", t, re.IGNORECASE), t[:80]
    ids = [w["id"] for t in r["protocol_types"].values() for w in t["walks"]]
    assert len(ids) == len(set(ids))
    for sig in {s for t in r["protocol_types"].values() for w in t["walks"] for s in w.get("signals") or []}:
        assert sig in r["lifecycle_signals"]
