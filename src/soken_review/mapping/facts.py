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
from functools import cache, lru_cache
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

# Zero-argument getters that name a privileged holder (08 2.2 roles table). Read only when the
# deployed unit exposes a function of that name; a word that is not an address is no fact. The
# fact key is `onchain.<snake_name>`; `owner` keeps its historical key through _SEL above.
HOLDER_GETTERS = ("admin", "governance", "governor", "guardian", "pendingOwner", "pauser", "minter", "operator",
                  "manager", "controller", "authority", "timelock", "strategist", "keeper", "treasury", "feeRecipient")


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


@cache
def getter_selector(name: str) -> str:
    from soken_review.mapping.keccak import keccak256

    return "0x" + keccak256(f"{name}()".encode()).hex()[:8]


def holder_fact_key(getter: str) -> str:
    return "onchain.owner" if getter == "owner" else f"onchain.{_snake(getter)}"


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
    for getter in HOLDER_GETTERS:
        if getter not in names:
            continue
        try:
            raw = await rpc.eth_call(address, getter_selector(getter), block=block)
        except Exception as exc:  # noqa: BLE001  # a failed read is no fact (04 1.3)
            logger.info("eth_call %s failed: %s", getter, exc)
            continue
        value = _decode_word(raw, "address")
        if value is not None:
            out.append(fact(holder_fact_key(getter), value, unit_id=unit_id,
                            source=f"eth_call {getter}() at block {block}"))
    holders = {"owner": "onchain.owner", "admin": "onchain.eip1967.admin"}
    holders.update({_snake(g): holder_fact_key(g) for g in HOLDER_GETTERS})
    by_key = {f["key"]: f["value"] for f in out}
    if "onchain.admin" not in by_key and "onchain.eip1967.admin" in by_key:
        holders["admin"] = "onchain.eip1967.admin"
    for role, key in holders.items():
        holder = by_key.get(key)
        if holder and int(holder, 16) != 0:
            out.extend(await holder_facts(rpc, role, holder, block, unit_id))
    return out


# Kind of a holder contract (08 2.2 roles table `type`). Getter probes (`getThreshold()`,
# `getMinDelay()`) are not evidence: any contract can answer them, and the report would print
# "Multisig" for an attacker-chosen holder (security review, 2026-10-23). A Safe is recognised
# structurally instead: a Safe proxy keeps its singleton in storage slot 0, and the singleton
# addresses are the published deployments (adapters/evm/data/safe_singletons.json). A timelock
# has no canonical bytecode, so it stays the generic `contract`.
_SAFE_SINGLETONS_PATH = Path(__file__).resolve().parents[1] / "adapters" / "evm" / "data" / "safe_singletons.json"


@lru_cache(maxsize=1)
def _safe_singletons() -> frozenset[str]:
    data = json.loads(_SAFE_SINGLETONS_PATH.read_text(encoding="utf-8"))
    return frozenset(str(a).lower() for a in data.get("singletons") or [])


@lru_cache(maxsize=1)
def _safe_proxy_prefix() -> tuple[bytes, int]:
    data = json.loads(_SAFE_SINGLETONS_PATH.read_text(encoding="utf-8"))
    return bytes.fromhex(str(data["proxy_runtime_prefix"]).removeprefix("0x")), int(data.get("proxy_runtime_max_bytes", 256))


def is_safe_proxy_code(code: bytes) -> bool:
    """True when `code` is the Safe proxy runtime: the functional prefix shared by v1.1.1, v1.3.0
    and v1.4.1 (verified against live proxies), followed by the 0xfe INVALID byte and the solc
    metadata. A contract that merely stores a singleton address in slot 0 does not pass (security
    review 2026-10-23: slot 0 alone was spoofable)."""
    prefix, max_bytes = _safe_proxy_prefix()
    return len(code) <= max_bytes and code.startswith(prefix) and len(code) > len(prefix) and code[len(prefix)] == 0xFE


async def holder_facts(rpc: Any, role: str, holder: str, block: int, unit_id: str | None) -> list[dict[str, Any]]:
    """`onchain.<role>.holder_code_size`, `.holder_is_contract` and `.holder_kind` for one holder address.

    Fail-closed: a failed `eth_getCode` yields no fact at all (never a false). `holder_kind` is
    `eoa` for empty code, `multisig` when the code is the Safe proxy runtime AND storage slot 0
    holds a published Safe singleton address (`onchain.<role>.holder_singleton` records it), else
    `contract`; a failed storage read only means the generic `contract`."""
    try:
        code = await rpc.get_code(holder, block=block)
    except Exception as exc:  # noqa: BLE001  # a failed read is no fact (04 1.3)
        logger.info("eth_getCode %s failed: %s", holder, exc)
        return []
    if not isinstance(code, str) or not code.startswith("0x"):
        return []
    try:
        size = len(bytes.fromhex(code[2:]))
    except ValueError:
        return []
    source = f"eth_getCode at block {block}"
    out = [fact(f"onchain.{role}.holder_code_size", size, unit="bytes", unit_id=unit_id, source=source),
           fact(f"onchain.{role}.holder_is_contract", "true" if size else "false", unit_id=unit_id, source=source)]
    kind = "contract" if size else "eoa"
    if size and is_safe_proxy_code(bytes.fromhex(code[2:])):
        try:
            raw = await rpc.get_storage_at(holder, "0x" + "0" * 64, block=block)
        except Exception as exc:  # noqa: BLE001  # a failed read is the generic kind, not an error
            logger.info("eth_getStorageAt slot 0 on %s failed: %s", holder, exc)
            raw = None
        singleton = _decode_word(raw, "address") if isinstance(raw, str) else None
        if singleton and singleton.lower() in _safe_singletons():
            kind = "multisig"
            out.append(fact(f"onchain.{role}.holder_singleton", singleton.lower(), unit_id=unit_id,
                            source=f"eth_getStorageAt slot 0 at block {block}"))
    out.append(fact(f"onchain.{role}.holder_kind", kind, unit_id=unit_id, source=source))
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


_CONTEXT_FACTS_FILE = "context_facts.json"   # written by the `context` step (context/facts.py)


def _is_context_fact(f: dict[str, Any]) -> bool:
    return str(f.get("key", "")).startswith("context.")


def write_facts(root: Path, job_id: str, facts: list[dict[str, Any]]) -> None:
    """facts.json holds the code and chain facts only. Context facts (`context.*`) live in
    `context_facts.json`, written by the `context` step, which may run before or after the map step
    rewrites this file; dropping them here keeps the two files disjoint and `load_facts` the merge."""
    d = root / job_id
    d.mkdir(parents=True, exist_ok=True)
    rows = [f for f in facts if not _is_context_fact(f)]
    (d / "facts.json").write_text(json.dumps(sorted(rows, key=lambda f: f["key"]), indent=1), encoding="utf-8")


def load_facts(root: Path, job_id: str) -> list[dict[str, Any]] | None:
    """The job's facts: facts.json plus the context facts file when present. None without facts.json."""
    p = root / job_id / "facts.json"
    if not p.exists():
        return None
    facts = json.loads(p.read_text(encoding="utf-8"))
    ctx = root / job_id / _CONTEXT_FACTS_FILE
    if ctx.exists():
        extra = json.loads(ctx.read_text(encoding="utf-8"))
        if isinstance(extra, list):
            facts = [f for f in facts if not _is_context_fact(f)] + extra
    return facts
