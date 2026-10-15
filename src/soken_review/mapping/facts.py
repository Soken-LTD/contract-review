"""Server facts (04 section 6.3 A4; 03 sections 4.8 and 17.4: fact records carry `unit_id`).

A fact record is `{key, value, unit, unit_id, source, tags}`: `unit` is the measurement unit,
`unit_id` the 2.1 unit id the value was read from (null for job-wide facts), `source` the read
that produced it (RPC method and block for on-chain facts), `tags` from `units.yaml`.

`static_facts` is pure (job inputs, pin, build and map). `onchain_facts` reads at the pinned block
(03 3.1 `chain_state 1`, after the map step) and returns only reads that succeeded; a missing read
is no fact (04 1.3: placeholders to it fail).
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .keccak import keccak256

logger = logging.getLogger(__name__)
_UNITS_YAML = Path(__file__).resolve().parents[3] / "contract" / "rubric" / "units.yaml"
_KEY_RE = re.compile(r"^[a-z][a-z0-9_.]*$")

_EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
_SEL = {"owner": "0x8da5cb5b", "totalSupply": "0x18160ddd", "decimals": "0x313ce567"}


@lru_cache(maxsize=1)
def _tag_rules() -> list[tuple[str, re.Pattern[str]]]:
    data = yaml.safe_load(_UNITS_YAML.read_text(encoding="utf-8"))
    return [(tag, re.compile(p)) for tag, pats in (data.get("tags") or {}).items() for p in pats]


def fact(key: str, value: Any, *, unit: str | None = None, unit_id: str | None = None, source: str) -> dict[str, Any]:
    if not _KEY_RE.match(key):
        raise ValueError(f"fact key {key!r} outside the 04 6.4 key grammar")
    tags = sorted({tag for tag, rx in _tag_rules() if rx.search(key)})
    return {"key": key, "value": str(value), "unit": unit, "unit_id": unit_id, "source": source, "tags": tags}


def entry_unit_id(entry_contract: str | None, units: list[dict[str, Any]]) -> str | None:
    """`path:Name` of the deployed unit (candidate `entry_contract`), when the map lists it."""
    if not entry_contract:
        return None
    ids = {u["id"] for u in units}
    return entry_contract if entry_contract in ids else None


def static_facts(
    *,
    chain_id: int | None,
    address: str | None,
    chain_state: dict[str, Any] | None,
    candidate: dict[str, Any] | None,
    nsloc: int | None,
    pin_files: int,
    source_pin: str | None,
    analyzers: dict[str, str],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    block = (chain_state or {}).get("block")
    if chain_id is not None:
        out.append(fact("chain.chain_id", chain_id, source="job input"))
    if block is not None:
        out.append(fact("chain.block", block, unit="block", source="eth_blockNumber at pin, minus one"))
    if address:
        out.append(fact("deploy.address", address, source="job input"))
    code = (chain_state or {}).get("bytecode")
    if code and code not in ("0x", "0x0") and block is not None:
        raw = bytes.fromhex(code.removeprefix("0x"))
        out.append(fact("deploy.code_hash", "0x" + keccak256(raw).hex(), source=f"keccak256 of eth_getCode at block {block}"))
        out.append(fact("deploy.code_bytes", len(raw), unit="bytes", source=f"eth_getCode at block {block}"))
    if candidate:
        version = ((candidate.get("compiler") or {}).get("version") or "").split("+")[0]
        if re.fullmatch(r"\d+\.\d+\.\d+", version):
            out.append(fact("compiler.version", version, source=f"source candidate ({candidate.get('provider')})"))
    if nsloc is not None:
        out.append(fact("source.nsloc", nsloc, unit="lines", source="pinned source"))
    out.append(fact("source.files", pin_files, source="pin manifest"))
    if source_pin:
        out.append(fact("source.pin", source_pin, source="pin manifest sha256"))
    for name, version in sorted(analyzers.items()):
        out.append(fact(f"analyzer.{name}", version, source="analyzer image"))
    return out


async def onchain_facts(rpc: Any, address: str, block: int, map_doc: dict[str, Any] | None,
                        unit_id: str | None) -> list[dict[str, Any]]:
    """Reads at the pinned block for the deployed unit (03 3.1 `chain_state 1`)."""
    out: list[dict[str, Any]] = []
    names = _unit_function_names(map_doc, unit_id)
    try:
        bal = await rpc.get_balance(address, block)
        out.append(fact("onchain.balance", int(bal, 16), unit="wei", unit_id=unit_id,
                        source=f"eth_getBalance at block {block}"))
    except Exception as exc:  # noqa: BLE001  # a failed read is no fact (04 1.3)
        logger.info("eth_getBalance failed: %s", exc)
    for key, fn, kind, unit in (("onchain.owner", "owner", "address", None),
                                ("onchain.total_supply", "totalSupply", "uint", "token_units"),
                                ("onchain.decimals", "decimals", "uint", None)):
        if fn not in names:
            continue
        try:
            raw = await rpc.eth_call(address, _SEL[fn], block=block)
        except Exception as exc:  # noqa: BLE001  # a failed read is no fact (04 1.3)
            logger.info("eth_call %s failed: %s", fn, exc)
            continue
        value = _decode_word(raw, kind)
        if value is not None:
            out.append(fact(key, value, unit=unit, unit_id=unit_id, source=f"eth_call {fn}() at block {block}"))
    for key, slot in (("onchain.eip1967.implementation", _EIP1967_IMPL), ("onchain.eip1967.admin", _EIP1967_ADMIN)):
        try:
            raw = await rpc.get_storage_at(address, slot, block=block)
        except Exception as exc:  # noqa: BLE001  # a failed read is no fact (04 1.3)
            logger.info("eth_getStorageAt failed: %s", exc)
            continue
        value = _decode_word(raw, "address")
        if value is not None and int(value, 16) != 0:
            out.append(fact(key, value, unit_id=unit_id, source=f"eth_getStorageAt EIP-1967 slot at block {block}"))
    return out


def _unit_function_names(map_doc: dict[str, Any] | None, unit_id: str | None) -> set[str]:
    sem = (map_doc or {}).get("semantic") or {}
    spans = {s["id"]: s for s in (map_doc or {}).get("spans") or []}
    out: set[str] = set()
    for f in sem.get("functions") or []:
        if not f.get("is_entry"):
            continue
        sp = spans.get(f["span"]) or {}
        out.add(sp.get("name", ""))
    # also public state variable getters (`owner` is often a public variable)
    for v in sem.get("state_vars") or []:
        out.add(v.get("name", ""))
    del unit_id  # entry functions of every unit; the deployed unit is the only address read
    return out


def _decode_word(raw: str | None, kind: str) -> str | None:
    if not raw or not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return None
    word = raw[2:66]
    try:
        n = int(word, 16)
    except ValueError:
        return None
    if kind == "address":
        if n >> 160:
            return None
        return "0x" + word[24:]
    return str(n)


def write_facts(root: Path, job_id: str, facts: list[dict[str, Any]]) -> None:
    d = root / job_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "facts.json").write_text(json.dumps(sorted(facts, key=lambda f: f["key"]), indent=1), encoding="utf-8")


def load_facts(root: Path, job_id: str) -> list[dict[str, Any]] | None:
    p = root / job_id / "facts.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))
