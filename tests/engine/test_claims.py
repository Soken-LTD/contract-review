"""Owner/deployer identity claims against the recorded facts (engine.claims; JUDGEMENT 2026-10-27 E5/E7).

The APAD texts and facts are the stored ones of job_BZJD7F3E01142Q3YK00P0EP0NT: owner
0xa9e3...e17582 on chain, no deployer fact recorded, and two sentences that call the owner the deployer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soken_review.engine.claims import check_owner_deployer, identity_claims, recorded_accounts
from soken_review.tools.number_errors import claim_error

FACTS = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "matrix_2026_10_27" / "apad.facts.json")
                   .read_text(encoding="utf-8"))
OWNER = "0xa9e3e9afa056d200241b85aec824b039ffe17582"
APAD_FINDING = ("The current owner is the deployer account {{fact:onchain.owner}}, an externally owned account, "
                "which also received the whole initial supply. Holders are not exposed to owner action through "
                "the contract code; their exposure is limited to the deployer's token balance, which is a market "
                "consideration rather than a code one.")
APAD_ROLE = ("onlyOwner: Held by the deployer account. Gates only renounceOwnership and transferOwnership; it "
             "cannot mint, burn, pause or move balances.")


def test_recorded_accounts_read_the_owner_and_no_deployer_from_the_apad_facts():
    assert recorded_accounts(FACTS) == (OWNER, None)


@pytest.mark.parametrize("text", [APAD_FINDING, APAD_ROLE])
def test_apad_sentences_are_rejected_when_no_deployer_fact_is_recorded(text):
    vs = check_owner_deployer(text, FACTS)
    assert [v.code for v in vs] == ["E_CLAIM_UNSUPPORTED"] and vs[0].rule_id == "C1"
    assert "deployer" in vs[0].match and len(identity_claims(text)) == 1
    env = claim_error(vs[0], "description", FACTS)
    assert env["code"] == "E_CLAIM_UNSUPPORTED" and env["field"] == "description"
    assert OWNER in env["what"] and "no deployer fact" in env["what"]
    assert "{{fact:onchain.owner}}" in env["fix"]


def test_claim_is_rejected_when_the_recorded_deployer_differs_and_accepted_when_it_matches():
    deployer = "0xb4a6b7df1b3c1d2e3f4a5b6c7d8e9f0a1b9db2f7"
    differ = FACTS + [{"key": "deploy.deployer", "value": deployer, "tags": []}]
    vs = check_owner_deployer(APAD_FINDING, differ)
    assert len(vs) == 1
    env = claim_error(vs[0], "description", differ)
    assert OWNER in env["what"] and deployer in env["what"] and "differ" in env["fix"]
    same = FACTS + [{"key": "deploy.deployer", "value": OWNER.upper().replace("0X", "0x"), "tags": []}]
    assert check_owner_deployer(APAD_FINDING, same) == []


def test_no_owner_fact_means_nothing_to_compare():
    repo_facts = [{"key": "compiler.version", "value": "0.8.0"}, {"key": "source.nsloc", "value": "624"}]
    assert check_owner_deployer(APAD_FINDING, repo_facts) == []
    assert check_owner_deployer(APAD_FINDING, None) == []
    assert check_owner_deployer("", FACTS) == []


@pytest.mark.parametrize("text", [
    "The owner can transfer ownership to an account other than the deployer.",
    "The constructor sets the owner to the deploying account.",
    "Ownable assigns msg.sender as the initial owner; the deployer may hand it on.",
    "The owner role is held by a multisig; the deployer has no role.",
    "Only the owner may call pause; the deployer address holds no tokens today.",
])
def test_construction_statements_and_unrelated_mentions_pass(text):
    assert identity_claims(text) == []
    assert check_owner_deployer(text, FACTS) == []


@pytest.mark.parametrize("text", [
    "Ownership remains with the deployer.",
    "The deployer still holds the owner role.",
    "The current owner is the deployer account.",
    "The onlyOwner role is held by the deployer.",
    "The deployer is the owner today and can renounce.",
])
def test_identity_claims_in_other_wordings_are_found(text):
    assert len(identity_claims(text)) == 1
