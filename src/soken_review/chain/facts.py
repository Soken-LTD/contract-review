"""Chain facts: every successful chain read is a fact (chain access design 1.1).

A chain fact is the usual record of `mapping.facts.fact` plus `chain_id`, `block` (int: block
number, Solana slot or TON masterchain seqno), `block_time` (ISO-8601 when known), `method`
(the read, for the report's Figures used row), `network` (the printed chain name) and, for text
read from the chain, `class: chain_text`. Keys are `chain.<alias>.<field>`, the alias being the
reviewer's name for an address (`[a-z][a-z0-9_]{0,23}`, never taken from chain data).

They live in `chain_facts.json` beside `facts.json` (the map step rewrites facts.json; this
file is written only by the chain tools) and `mapping.facts.load_facts` merges them, so the
submit gate, review_facts and the report see them like any other fact. The file goes with the
job's pin directory on review_delete_job and retention.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
from pathlib import Path
from typing import Any

from ..mapping.facts import fact

CHAIN_FACTS_FILE = "chain_facts.json"
ALIAS_RE = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
RESERVED_ALIASES = frozenset({"block", "chain_id"})   # chain.block and chain.chain_id are pipeline facts
MAX_CHAIN_FACTS = 2000
ORIGIN = "chain_tool"   # marks the record so mapping.facts.write_facts never copies it into facts.json


def field_key(name: str) -> str:
    """A getter name as a key segment: `getPastTotalSupply` -> `get_past_total_supply`."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    s = re.sub(r"[^a-z0-9_]", "_", s.lower()).strip("_")
    s = re.sub(r"_+", "_", s)
    if not s or not s[0].isalpha():
        s = "f_" + s
    return s[:40]


def chain_fact(key: str, value: Any, *, source: str, chain_id: int | str | None, block: int | None,
               method: str, network: str, block_time: str | None = None, unit: str | None = None,
               text_class: str | None = None, family: str = "evm") -> dict[str, Any]:
    rec = fact(key, value, unit=unit, source=source[:200])
    rec.update({"chain_id": chain_id, "block": block, "block_time": block_time, "method": method[:60],
                "network": network[:60], "family": family, "origin": ORIGIN})
    if text_class:
        rec["class"] = text_class
    return rec


def _path(root: Path, job_id: str) -> Path:
    return root / job_id / CHAIN_FACTS_FILE


def load_chain_facts(root: Path, job_id: str) -> list[dict[str, Any]]:
    p = _path(root, job_id)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def write_chain_facts(root: Path, job_id: str, new: list[dict[str, Any]]) -> int:
    """Merge `new` into the job's chain facts (a later read of a key replaces the earlier one);
    returns the stored count. A file lock serialises concurrent tool calls of one job."""
    d = root / job_id
    if not d.is_dir():
        raise FileNotFoundError(f"no pin directory for {job_id}")
    lock = d / ".chain_facts.lock"
    with open(lock, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            by_key = {f["key"]: f for f in load_chain_facts(root, job_id)}
            for f in new:
                by_key[f["key"]] = f
            rows = sorted(by_key.values(), key=lambda f: f["key"])[:MAX_CHAIN_FACTS]
            tmp = d / (CHAIN_FACTS_FILE + ".tmp")
            tmp.write_text(json.dumps(rows, indent=1), encoding="utf-8")
            os.replace(tmp, _path(root, job_id))
            return len(rows)
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def at_text(rec: dict[str, Any]) -> str | None:
    """`BNB Smart Chain Mainnet, block 45,123,456` for a chain fact, else None."""
    block = rec.get("block")
    if not isinstance(block, int) or isinstance(block, bool):
        return None
    word = {"solana": "slot", "ton": "masterchain block"}.get(str(rec.get("family") or ""), "block")
    net = str(rec.get("network") or "").strip()
    return f"{net}, {word} {block:,}" if net else f"{word} {block:,}"
