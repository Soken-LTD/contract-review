"""Fact-consistency check for owner and deployer identity claims (04 section 6 meaning rule).

Matrix run 2026-10-27 (APAD, job_BZJD7F3E01142Q3YK00P0EP0NT): the finding text read "The current
owner is the deployer account {{fact:onchain.owner}}" and the roles note "Held by the deployer
account", while the chain shows owner 0xa9e3...e17582 and deployer 0xB4A6...9DB2f7. The connector
records the owner (`onchain.owner`) and, when a pipeline supplies it, the deployer; a sentence that
equates the two is accepted only when both facts exist and agree. Construction-time statements
("the constructor sets the owner to the deploying account") describe code, not the chain, and pass.
Pure: text and fact records in, violations out.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from .text_gate import Violation

OWNER_KEY_RE = re.compile(r"^(?:onchain|state)\.(?:get_)?owner$")
DEPLOYER_KEY_RE = re.compile(r"^(?:onchain|deploy|deployment|state)\.(?:deployer|creator|created_by)$")

_OWNER = r"(?:owner|ownership|onlyowner|owned|owns)"
_DEPLOYER = r"(?:deployer|deploying account|deployment account|contract creator|account that deployed)"
_OWNER_FIRST = re.compile(
    rf"\b{_OWNER}\b[^.;:]{{0,60}}?\b(?:is|was|remains|stays|belongs to|sits with|rests with|held by|lies with)\b"
    rf"[^.;]{{0,30}}?\b{_DEPLOYER}\b", re.IGNORECASE)
_DEPLOYER_FIRST = re.compile(
    rf"\b{_DEPLOYER}\b[^.;]{{0,60}}?\b(?:is|was|remains|stays|holds|retains|keeps|acts as|also|still)\b"
    rf"[^.;]{{0,40}}?\b{_OWNER}\b", re.IGNORECASE)
_HELD_BY = re.compile(rf"\bheld by (?:the |a |an )?{_DEPLOYER}\b", re.IGNORECASE)
_OWNER_WORD = re.compile(rf"\b{_OWNER}\b", re.IGNORECASE)
# A statement about what the code does at construction is not a claim about the chain today.
_CONSTRUCTION_RE = re.compile(
    r"\b(?:constructor|at construction|on construction|at deployment|on deployment|when deployed|"
    r"initially|initial owner|msg\.sender|_msgSender)\b", re.IGNORECASE)
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def identity_claims(text: str) -> list[tuple[int, int, str]]:
    """Spans of sentences that state the owner and the deployer are the same account."""
    nfkc = unicodedata.normalize("NFKC", text)
    out: list[tuple[int, int, str]] = []
    pos = 0
    for sentence in _SENTENCE_SPLIT_RE.split(nfkc):
        start = nfkc.find(sentence, pos)
        if start < 0:
            start = pos
        pos = start + len(sentence)
        if not sentence.strip() or _CONSTRUCTION_RE.search(sentence):
            continue
        claim = bool(_OWNER_FIRST.search(sentence) or _DEPLOYER_FIRST.search(sentence)
                     or (_HELD_BY.search(sentence) and _OWNER_WORD.search(sentence)))
        if claim:
            out.append((start, start + len(sentence), sentence.strip()))
    return out


def recorded_accounts(facts: list[dict[str, Any]] | None) -> tuple[str | None, str | None]:
    """(owner, deployer) as the job's fact records give them; None when not recorded."""
    owner = deployer = None
    for f in facts or []:
        key = str(f.get("key") or "")
        value = f.get("value")
        if value in (None, ""):
            continue
        if owner is None and OWNER_KEY_RE.match(key):
            owner = str(value)
        elif deployer is None and DEPLOYER_KEY_RE.match(key):
            deployer = str(value)
    return owner, deployer


def check_owner_deployer(text: str, facts: list[dict[str, Any]] | None) -> list[Violation]:
    """Violations (`E_CLAIM_UNSUPPORTED`, rule C1) for every sentence of *text* that equates the
    owner with the deployer while the facts record no deployer or a different one. Without an
    owner fact (no deployment, no owner getter) there is nothing to compare and nothing fires."""
    if not text:
        return []
    owner, deployer = recorded_accounts(facts)
    if owner is None:
        return []
    if deployer is not None and deployer.lower() == owner.lower():
        return []
    return [Violation("E_CLAIM_UNSUPPORTED", "C1", (s, e), sentence) for s, e, sentence in identity_claims(text)]


def claim_facts_text(facts: list[dict[str, Any]] | None) -> tuple[str, str]:
    """(`facts`, `hint`) for the E_CLAIM_UNSUPPORTED envelope: what is recorded and what to write."""
    owner, deployer = recorded_accounts(facts)
    if deployer is None:
        hint = ("Name the owner as {{fact:onchain.owner}} without calling it the deployer, or describe the "
                "constructor assignment as a construction-time fact with the constructor line quoted.")
        return f"owner {owner}; no deployer fact is recorded for this job", hint
    hint = ("The recorded deployer and owner differ: drop the identity claim and cite each account with its "
            "own fact placeholder.")
    return f"owner {owner}, deployer {deployer}", hint
