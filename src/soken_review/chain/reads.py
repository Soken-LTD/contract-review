"""Chain reads behind review_chain_read, review_chain_roles and review_chain_balances (design 1.2,
1.4, 1.5). Every read goes through `ChainProxy` (policy, cache, failover) and every successful
read becomes a fact with its block (slot, masterchain seqno) and source.

Families: `evm` (EVM and HyperEVM chains, Multicall3 batching when deployed at the block), `tron`
(TronGrid, latest state only), `solana` (latest slot only), `ton` (toncenter v2 at a masterchain
seqno). Per-item failures are results (`ok: false` with `error`), never exceptions: one bad item
never loses the others, and no failure here ever changes the job.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..mapping.facts import HOLDER_GETTERS, _safe_singletons, is_safe_proxy_code
from . import abi
from .facts import chain_fact, field_key
from .proxy import ChainProxy, ChainUnavailable, RpcFailure
from .store import limits
from .untrusted import CHAIN_TEXT, REVERT_CAP, untrusted_text

MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
_AGG3 = "aggregate3((address,bool,bytes)[])"
EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EVM_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
SLOT_RE = re.compile(r"^0x[0-9a-fA-F]{1,64}$")
_VALUE_CAP = 200
REFUNDABLE = frozenset({"archive", "rate_limited", "upstream", "budget", "input"})


class InputError(ValueError):
    """A caller value the tool cannot use (E_INVALID_ARGUMENT)."""

    def __init__(self, field: str, rule: str, value: Any = "", example: str = "") -> None:
        super().__init__(f"{field}: {rule}")
        self.field = field
        self.rule = rule
        self.value = str(value)[:80]
        self.example = example


@dataclass
class ChainJob:
    job_id: str
    family: str                 # evm | tron | solana | ton
    chain_id: int | None
    network: str                # printed name: "BNB Smart Chain Mainnet"
    pinned_block: int | None
    address: str | None
    unit_functions: frozenset[str] = frozenset()


@dataclass
class At:
    block: int
    head: int | None
    block_time: str | None
    note: str | None = None
    archive: bool = False       # older than the archive line (costs 2 RU per EVM item)


@dataclass
class Out:
    """Facts and per-item results of one tool call."""
    job: ChainJob
    at: At
    host: str = ""
    facts: list[dict[str, Any]] = field(default_factory=list)
    items: list[dict[str, Any]] = field(default_factory=list)

    def fact(self, key: str, value: Any, *, method: str, source: str, unit: str | None = None,
             text: bool = False) -> str:
        via = f" via {self.host}" if self.host else ""
        word = {"solana": "slot", "ton": "masterchain block"}.get(self.job.family, "block")
        self.facts.append(chain_fact(key, value, unit=unit, source=f"{source} at {word} {self.at.block:,}{via}",
                                     chain_id=self.job.chain_id, block=self.at.block, block_time=self.at.block_time,
                                     method=method, network=self.job.network, family=self.job.family,
                                     text_class=CHAIN_TEXT if text else None))
        return key


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def item_error(alias: str, kind: str, reason: str, detail: str) -> dict[str, Any]:
    """`detail` is server text only; a provider's own words go through `upstream_error`."""
    return {"alias": alias, "kind": kind, "ok": False, "error": {"reason": reason, "detail": detail[:200]}}


def upstream_error(alias: str, kind: str, provider_text: Any, origin: str = "provider error") -> dict[str, Any]:
    """A refusal by the provider: server sentence plus the provider's message as untrusted text
    (an error string can echo chain data, for example a revert reason)."""
    row = item_error(alias, kind, "upstream", "the free endpoint refused the read")
    if provider_text:
        row["error"]["provider_message"] = {"untrusted_text": untrusted_text(provider_text, origin, cap=REVERT_CAP)}
    return row


def revert_text(data: bytes, origin: str) -> str | dict[str, Any]:
    """A decoded revert for a result: server-built reasons (Panic, custom error selector) as plain
    text, an Error(string) reason, which the contract chose, as untrusted text."""
    rev = abi.decode_revert(data)
    if rev["kind"] == "error_string":
        return {"untrusted_text": untrusted_text(rev["reason"], origin, cap=REVERT_CAP)}
    return rev["reason"]


def _unavailable(exc: ChainUnavailable) -> tuple[str, str]:
    text = {"archive": "no free endpoint in the pool still holds the state of that block (most free endpoints "
                       "keep only recent blocks); read at latest instead",
            "rate_limited": "every free endpoint in the pool rate limited the call; retry in a few seconds",
            "budget": "this call reached its upstream call cap; send fewer items"}.get(
                exc.reason, "no free endpoint in the pool answered (outage or refusal)")
    return exc.reason, text


# ── values ─────────────────────────────────────────────────────────────────


def _flatten(prefix: str, types: list[str], values: list[Any], family: str) -> list[tuple[str, str, Any]]:
    """(key suffix, type, value) leaves; one value keeps the bare key, several get .0, .1, ..."""
    out: list[tuple[str, str, Any]] = []
    single = len(values) == 1

    def walk(sfx: str, t: str, v: Any, depth: int) -> None:
        if len(out) >= 40:
            return
        base, dim = abi._split_array(t)
        if dim is not None or base.startswith("("):
            inner = abi.split_types(base[1:-1]) if dim is None else [base] * len(v)
            out.append((sfx + ".count", "uint256", len(v))) if dim is not None else None
            for i, (it, iv) in enumerate(zip(inner, v, strict=False)):
                if depth < 3:
                    walk(f"{sfx}.{i}", it, iv, depth + 1)
            return
        if t == "address" and family == "tron":
            from ..adapters.tron.address import hex_to_b58
            v = hex_to_b58(v[2:])
        out.append((sfx, t, v))

    for i, (t, v) in enumerate(zip(types, values, strict=True)):
        walk(prefix if single else f"{prefix}.{i}", t, v, 0)
    return out


def _record_values(out: Out, key: str, types: list[str], values: list[Any], *, method: str, source: str,
                   unit: str | None, origin: str) -> tuple[list[str], list[Any], list[dict[str, Any]]]:
    keys, shown, texts = [], [], []
    for sfx, t, v in _flatten(key, types, values, out.job.family):
        if t == "string":
            ut = untrusted_text(v, origin)
            texts.append({"key": sfx, **ut})
            keys.append(out.fact(sfx, ut["value"], method=method, source=source, text=True))
            shown.append({"untrusted_text": ut})
            continue
        if isinstance(v, bool):
            val: Any = "true" if v else "false"
        elif isinstance(v, int):
            val = str(v)
        else:
            val = str(v)[:_VALUE_CAP]
        keys.append(out.fact(sfx, val, method=method, source=source,
                             unit=unit if t.startswith(("uint", "int")) else None))
        shown.append(val)
    return keys, shown, texts


# ── EVM ────────────────────────────────────────────────────────────────────


async def evm_resolve(px: ChainProxy, job: ChainJob, spec: Any) -> At:
    cid = int(job.chain_id or 0)
    head = int(await px.evm(cid, "eth_blockNumber", []), 16)
    note = None
    if spec in (None, "latest"):
        block = head - 1                 # one below the head: every endpoint of the pool has it
    elif spec == "pinned":
        if job.pinned_block is None:
            raise InputError("block", "this job has no pinned block", spec, "latest")
        block = int(job.pinned_block)
    else:
        block = int(spec)
        if block > head:
            raise InputError("block", f"block is after the chain head {head}", spec, str(head - 1))
    lim = limits()
    final = head - int((lim.get("finality_blocks") or {}).get("evm", 64))
    archive = block < head - int(lim.get("archive_line_blocks", 128))
    px.depth_hint = head - block
    if archive and not any(e.archive for e in px._endpoints("evm", cid)):
        note = (f"Block {block:,} is {head - block:,} blocks behind the head and no free endpoint in the pool is "
                "known to keep state that old for this chain; items may fail. Call again with block latest "
                "for current values.")
    block_time = None
    try:
        hdr = await px.evm(cid, "eth_getBlockByNumber", [hex(block), False], durable=block <= final)
        block_time = _iso(int(hdr["timestamp"], 16)) if isinstance(hdr, dict) else None
    except (ChainUnavailable, RpcFailure, KeyError, ValueError, TypeError):
        pass
    return At(block=block, head=head, block_time=block_time, note=note, archive=archive)


def _is_final(at: At, family: str = "evm") -> bool:
    if at.head is None:
        return False
    return at.block <= at.head - int((limits().get("finality_blocks") or {}).get(family, 64))


def _revert_bytes(exc: RpcFailure) -> bytes | None:
    data = exc.data
    if isinstance(data, dict):
        data = data.get("data") or data.get("result")
    if isinstance(data, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", data):
        return bytes.fromhex(data[2:])
    return None if data is not None else (b"" if "revert" in exc.message.lower() else None)


async def _has_multicall(px: ChainProxy, cid: int, at: At) -> bool:
    try:
        code = await px.evm(cid, "eth_getCode", [MULTICALL3, hex(at.block)], durable=_is_final(at))
    except (ChainUnavailable, RpcFailure):
        return False
    return isinstance(code, str) and len(code) > 2


async def evm_calls(px: ChainProxy, cid: int, at: At, calls: list[tuple[str, bytes]]) -> list[tuple[bool, bytes] | Exception]:
    """(success, return or revert bytes) per (address, calldata); Multicall3 when deployed at the
    block, else one eth_call each. A provider failure is the exception object for that call."""
    if not calls:
        return []
    if len(calls) > 1 and await _has_multicall(px, cid, at):
        try:
            data = abi.selector(_AGG3) + abi.encode(["(address,bool,bytes)[]"],
                                                   [[[a, True, "0x" + cd.hex()] for a, cd in calls]])
            raw = await px.evm(cid, "eth_call", [{"to": MULTICALL3, "data": "0x" + data.hex()}, hex(at.block)],
                               durable=_is_final(at))
            (results,) = abi.decode(["(bool,bytes)[]"], bytes.fromhex(str(raw)[2:]))
            if len(results) == len(calls):
                return [(bool(ok), bytes.fromhex(rd[2:])) for ok, rd in results]
        except ChainUnavailable as exc:
            return [exc] * len(calls)
        except (RpcFailure, abi.AbiError, ValueError):
            pass     # fall back to single calls
    out: list[tuple[bool, bytes] | Exception] = []
    for addr, cd in calls:
        try:
            raw = await px.evm(cid, "eth_call", [{"to": addr, "data": "0x" + cd.hex()}, hex(at.block)],
                               durable=_is_final(at))
            out.append((True, bytes.fromhex(str(raw or "0x")[2:])))
        except RpcFailure as exc:
            rb = _revert_bytes(exc)
            out.append((False, rb) if rb is not None else exc)
        except ChainUnavailable as exc:
            out.append(exc)
    return out


def _call_spec(item: dict[str, Any], family: str) -> tuple[str, list[str], str, bytes, list[str] | None]:
    try:
        name, types, canonical = abi.parse_signature(str(item.get("fn") or ""))
        args = list(item.get("args") or [])
        if family == "tron":
            args = [_tron_arg(t, a) for t, a in zip(types, args, strict=False)] + args[len(types):]
        data = abi.selector(canonical) + abi.encode(types, args)
        returns = abi.parse_returns(item.get("returns"))
    except abi.AbiError as exc:
        raise InputError("items.fn", str(exc), item.get("fn"), "balanceOf(address)") from exc
    return name, types, canonical, data, returns


def _tron_arg(t: str, a: Any) -> Any:
    if t == "address" and isinstance(a, str) and a.startswith("T"):
        from ..adapters.tron.address import TronAddressError, b58_to_hex
        try:
            return "0x" + b58_to_hex(a)
        except TronAddressError as exc:
            raise abi.AbiError(f"bad TRON address {a[:40]}") from exc
    return a


def _record_call(out: Out, item: dict[str, Any], name: str, canonical: str, returns: list[str] | None,
                 res: tuple[bool, bytes] | Exception, read: str) -> dict[str, Any]:
    alias, kind = item["alias"], "call"
    key = f"chain.{alias}.{item.get('field') or field_key(name)}"
    method = f"{read} {name}()"[:60]
    args_txt = ",".join(str(a)[:20] for a in (item.get("args") or []))
    source = f"{read} {name}({args_txt})"[:120]
    origin = f"{canonical}@{item['address']}"
    if isinstance(res, ChainUnavailable):
        reason, text = _unavailable(res)
        return item_error(alias, kind, reason, text)
    if isinstance(res, Exception):
        return item_error(alias, kind, "upstream", f"the provider refused the call ({type(res).__name__})")
    ok, data = res
    row: dict[str, Any] = {"alias": alias, "kind": kind, "fn": canonical, "ok": True, "raw": "0x" + data[:256].hex()}
    if not ok:
        rev = abi.decode_revert(data)
        sigs = [s for s in (item.get("errors") or []) if isinstance(s, str)][:20]
        if rev["kind"] == "custom_error" and sigs:
            named = abi.name_custom_error(rev["selector"], sigs)
            if named:
                rev["reason"] = f"custom error {named}"
        row["reverted"] = True
        keys = [out.fact(f"{key}.reverted", "true", method=method, source=source)]
        if rev["kind"] == "error_string":
            ut = untrusted_text(rev["reason"], origin + " revert", cap=REVERT_CAP)
            row["revert_reason"] = {"untrusted_text": ut}
            keys.append(out.fact(f"{key}.revert_reason", ut["value"], method=method, source=source, text=True))
        else:
            row["revert_reason"] = rev["reason"]
            keys.append(out.fact(f"{key}.revert_reason", rev["reason"], method=method, source=source))
        row["fact_keys"] = keys
        return row
    types = returns
    if types is None:
        if len(data) != 32:
            row["note"] = "no returns given and the answer is not one word: raw bytes only, no fact"
            row["fact_keys"] = []
            return row
        types = ["uint256"]
        row["decoded_as"] = "uint256 (no returns given)"
    try:
        values = abi.decode(types, data)
    except abi.AbiError as exc:
        return {**item_error(alias, kind, "decode", f"return data does not decode as {','.join(types)}: {exc}"),
                "raw": row["raw"]}
    keys, shown, _texts = _record_values(out, key, types, values, method=method, source=source,
                                        unit=item.get("unit"), origin=origin)
    row["value"] = shown[0] if len(shown) == 1 else shown
    row["fact_keys"] = keys
    return row


async def evm_read(px: ChainProxy, out: Out, items: list[dict[str, Any]]) -> None:
    cid = int(out.job.chain_id or 0)
    calls: list[tuple[int, dict[str, Any], tuple]] = []
    for i, it in enumerate(items):
        if it["kind"] == "call":
            try:
                calls.append((i, it, _call_spec(it, "evm")))
            except InputError as exc:
                out.items.append({**item_error(it["alias"], "call", "input", f"{exc.field}: {exc.rule}"), "_i": i})
    results = await evm_calls(px, cid, out.at, [(it["address"], spec[3]) for _i, it, spec in calls])
    for (i, it, (name, _t, canonical, _d, returns)), res in zip(calls, results, strict=True):
        out.items.append({**_record_call(out, it, name, canonical, returns, res, "eth_call"), "_i": i})
    for i, it in enumerate(items):
        if it["kind"] == "storage":
            out.items.append({**await _evm_storage(px, out, it), "_i": i})
        elif it["kind"] == "account":
            out.items.append({**await _evm_account(px, out, it), "_i": i})
        elif it["kind"] not in ("call",):
            out.items.append({**item_error(it["alias"], it["kind"], "input", f"kind {it['kind']} is not an EVM read"), "_i": i})


def _slot_hex(slot: Any) -> str:
    if isinstance(slot, int) and not isinstance(slot, bool) and slot >= 0:
        return "0x" + format(slot, "064x")
    if isinstance(slot, str) and SLOT_RE.match(slot):
        return "0x" + slot[2:].lower().rjust(64, "0")
    raise InputError("items.slot", "a storage slot is 0x hex (up to 32 bytes) or a non-negative integer", slot,
                     EIP1967_IMPL)


async def _evm_storage(px: ChainProxy, out: Out, it: dict[str, Any]) -> dict[str, Any]:
    alias = it["alias"]
    try:
        slot = _slot_hex(it.get("slot"))
    except InputError as exc:
        return item_error(alias, "storage", "input", exc.rule)
    try:
        word = await px.evm(int(out.job.chain_id or 0), "eth_getStorageAt", [it["address"], slot, hex(out.at.block)],
                            durable=_is_final(out.at))
    except ChainUnavailable as exc:
        return item_error(alias, "storage", *_unavailable(exc))
    except RpcFailure as exc:
        return upstream_error(alias, "storage", exc.message)
    word = "0x" + str(word)[2:].rjust(64, "0")[-64:]
    short = slot[2:].lstrip("0")[:8] or "0"
    key = f"chain.{alias}.{it.get('field') or 'slot_' + short}"
    src = f"eth_getStorageAt slot {slot[:10]}{'...' if len(slot.lstrip('0x')) > 8 else ''}"
    keys = [out.fact(key, word, method="eth_getStorageAt", source=src)]
    row = {"alias": alias, "kind": "storage", "slot": slot, "ok": True, "value": word, "as_uint": str(int(word, 16))}
    if int(word[2:26] or "0", 16) == 0 and int(word, 16):
        row["as_address"] = "0x" + word[-40:]
    row["fact_keys"] = keys
    return row


async def _evm_account(px: ChainProxy, out: Out, it: dict[str, Any]) -> dict[str, Any]:
    alias, cid, b = it["alias"], int(out.job.chain_id or 0), hex(out.at.block)
    final = _is_final(out.at)
    try:
        bal = await px.evm(cid, "eth_getBalance", [it["address"], b], durable=final)
        nonce = await px.evm(cid, "eth_getTransactionCount", [it["address"], b], durable=final)
        code = await px.evm(cid, "eth_getCode", [it["address"], b], durable=final)
    except ChainUnavailable as exc:
        return item_error(alias, "account", *_unavailable(exc))
    except RpcFailure as exc:
        return upstream_error(alias, "account", exc.message)
    raw = bytes.fromhex(str(code)[2:])
    from ..mapping.keccak import keccak256
    vals = {"balance": (str(int(bal, 16)), "wei", "eth_getBalance"), "nonce": (str(int(nonce, 16)), None, "eth_getTransactionCount"),
            "code_size": (str(len(raw)), "bytes", "eth_getCode"), "is_contract": ("true" if raw else "false", None, "eth_getCode")}
    if raw:
        vals["code_hash"] = ("0x" + keccak256(raw).hex(), None, "eth_getCode")
    keys = [out.fact(f"chain.{alias}.{k}", v, method=m, source=m, unit=u) for k, (v, u, m) in vals.items()]
    return {"alias": alias, "kind": "account", "ok": True, "value": {k: v for k, (v, _u, _m) in vals.items()},
            "fact_keys": keys}


# ── TRON ───────────────────────────────────────────────────────────────────


def tron_hex(addr: str) -> str:
    from ..adapters.tron.address import TronAddressError, b58_to_hex
    try:
        return b58_to_hex(addr)
    except TronAddressError as exc:
        raise InputError("address", "a TRON address is base58 and starts with T", addr, "TRegosVaS1o3DHG85nnW8xYzczPm3xL76K") from exc


async def tron_resolve(px: ChainProxy, job: ChainJob, spec: Any) -> At:
    blk = await px.tron("/wallet/getnowblock", {})
    hdr = ((blk or {}).get("block_header") or {}).get("raw_data") or {}
    number = int(hdr.get("number") or 0)
    note = None
    if spec not in (None, "latest"):
        note = (f"TRON nodes serve the latest state only: values are read at block {number:,}, not at "
                f"{'the pinned block' if spec == 'pinned' else 'block ' + str(spec)}.")
    ts = hdr.get("timestamp")
    return At(block=number, head=number, block_time=_iso(ts / 1000) if isinstance(ts, int) else None, note=note)


async def _tron_call(px: ChainProxy, addr: str, canonical: str, data: bytes) -> tuple[bool, bytes] | Exception:
    try:
        r = await px.tron("/wallet/triggerconstantcontract", {
            "owner_address": addr, "contract_address": addr, "function_selector": canonical,
            "parameter": data[4:].hex(), "visible": True})
    except (ChainUnavailable, RpcFailure) as exc:
        return exc
    if not isinstance(r, dict):
        return RpcFailure(-1, "not an object")
    res = r.get("result") or {}
    cr = (r.get("constant_result") or [""])[0] or ""
    ret = (((r.get("transaction") or {}).get("ret") or [{}])[0] or {}).get("ret")
    try:
        body = bytes.fromhex(cr)
    except ValueError:
        body = b""
    if res.get("result") is True and ret != "FAILED":
        return True, body
    msg = str(res.get("message") or "")
    if ret == "FAILED" or "REVERT" in msg.upper() or res.get("code") == "CONTRACT_EXE_ERROR":
        return False, body
    code = str(res.get("code") or "error")
    return RpcFailure(-1, "TronGrid " + (code if re.fullmatch(r"[A-Z_]{1,40}", code) else "error"))


async def tron_read(px: ChainProxy, out: Out, items: list[dict[str, Any]]) -> None:
    for i, it in enumerate(items):
        alias, kind = it["alias"], it["kind"]
        if kind == "call":
            try:
                name, _t, canonical, data, returns = _call_spec(it, "tron")
            except InputError as exc:
                out.items.append({**item_error(alias, kind, "input", exc.rule), "_i": i})
                continue
            res = await _tron_call(px, it["address"], canonical, data)
            out.items.append({**_record_call(out, it, name, canonical, returns, res, "triggerconstantcontract"), "_i": i})
        elif kind == "storage":
            try:
                slot = _slot_hex(it.get("slot"))
                word = await px.tron("/jsonrpc", {"jsonrpc": "2.0", "id": 1, "method": "eth_getStorageAt",
                                                  "params": ["0x" + tron_hex(it["address"]), slot, "latest"]})
            except InputError as exc:
                out.items.append({**item_error(alias, kind, "input", exc.rule), "_i": i})
                continue
            except ChainUnavailable as exc:
                out.items.append({**item_error(alias, kind, *_unavailable(exc)), "_i": i})
                continue
            except RpcFailure as exc:
                out.items.append({**upstream_error(alias, kind, exc.message), "_i": i})
                continue
            word = "0x" + str(word or "0x")[2:].rjust(64, "0")[-64:]
            key = f"chain.{alias}.{it.get('field') or 'slot_' + (slot[2:].lstrip('0')[:8] or '0')}"
            keys = [out.fact(key, word, method="eth_getStorageAt", source=f"TRON eth_getStorageAt slot {slot[:10]}")]
            out.items.append({"alias": alias, "kind": kind, "ok": True, "value": word, "fact_keys": keys, "_i": i})
        elif kind == "account":
            out.items.append({**await _tron_account(px, out, it), "_i": i})
        else:
            out.items.append({**item_error(alias, kind, "input", f"kind {kind} is not a TRON read"), "_i": i})


async def _tron_account(px: ChainProxy, out: Out, it: dict[str, Any], role_prefix: str | None = None) -> dict[str, Any]:
    alias = it["alias"]
    try:
        acc = await px.tron("/wallet/getaccount", {"address": it["address"], "visible": True})
        con = await px.tron("/wallet/getcontract", {"value": it["address"], "visible": True})
    except ChainUnavailable as exc:
        return item_error(alias, "account", *_unavailable(exc))
    except RpcFailure as exc:
        return upstream_error(alias, "account", exc.message)
    acc = acc if isinstance(acc, dict) else {}
    pre = role_prefix or f"chain.{alias}"
    vals: dict[str, tuple[str, str | None]] = {
        "balance": (str(int(acc.get("balance") or 0)), "sun"),
        "is_contract": ("true" if isinstance(con, dict) and con.get("bytecode") else "false", None),
    }
    own = acc.get("owner_permission") or {}
    if own:
        keys_ = own.get("keys") or []
        vals["owner_permission.threshold"] = (str(int(own.get("threshold") or 1)), None)
        vals["owner_permission.keys"] = (str(len(keys_)), None)
        if len(keys_) == 1:
            vals["owner_permission.key"] = (str(keys_[0].get("address") or ""), None)
    vals["active_permissions"] = (str(len(acc.get("active_permission") or [])), None)
    keys = [out.fact(f"{pre}.{k}", v, method="getaccount", source="TronGrid getaccount", unit=u)
            for k, (v, u) in vals.items()]
    return {"alias": alias, "kind": "account", "ok": True, "value": {k: v for k, (v, _u) in vals.items()},
            "fact_keys": keys}


# ── Solana ─────────────────────────────────────────────────────────────────

_SOL_TYPES = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u128": 16, "i64": 8, "bool": 1, "pubkey": 32}
_B58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
TOKEN_PROGRAMS = {"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
# review_chain_read classifies at most this many System-owned (wallet-like) accounts per call in full
# (signer history); the rest get the curve check only.
SOL_CLASSIFY_PER_CALL = 3


async def solana_resolve(px: ChainProxy, job: ChainJob, spec: Any) -> At:
    slot = int(await px.solana("getSlot", [{"commitment": "finalized"}]))
    note = None
    if spec not in (None, "latest"):
        note = (f"Solana JSON-RPC has no account state at a past slot: values are read at slot {slot:,}, not at "
                f"{'the pinned slot' if spec == 'pinned' else 'slot ' + str(spec)}.")
    return At(block=slot, head=slot, block_time=None, note=note)


def _sol_field(data: bytes, offset: int, t: str) -> str:
    n = _SOL_TYPES[t]
    chunk = data[offset:offset + n]
    if len(chunk) != n:
        raise ValueError("field outside the account data")
    if t == "pubkey":
        from ..adapters.solana.onchain import b58encode
        return b58encode(chunk)
    if t == "bool":
        return "true" if chunk[0] else "false"
    return str(int.from_bytes(chunk, "little", signed=t.startswith("i")))


async def solana_accounts(px: ChainProxy, addrs: list[str], data_slice: tuple[int, int] | None = None
                          ) -> tuple[int | None, list[dict[str, Any] | None]]:
    opts: dict[str, Any] = {"encoding": "base64", "commitment": "finalized"}
    if data_slice is not None:   # a program's ProgramData holds the whole ELF; the header is enough
        opts["dataSlice"] = {"offset": data_slice[0], "length": data_slice[1]}
    res = await px.solana("getMultipleAccounts", [addrs, opts])
    return (res.get("context") or {}).get("slot"), list(res.get("value") or [])


async def solana_read(px: ChainProxy, out: Out, items: list[dict[str, Any]]) -> None:
    acct_items = [(i, it) for i, it in enumerate(items) if it["kind"] == "account"]
    for i, it in enumerate(items):
        if it["kind"] != "account":
            out.items.append({**item_error(it["alias"], it["kind"], "input",
                                           "Solana reads are kind account (with optional fields)"), "_i": i})
    if not acct_items:
        return
    try:
        slot, accs = await solana_accounts(px, [it["address"] for _i, it in acct_items])
    except ChainUnavailable as exc:
        for i, it in acct_items:
            out.items.append({**item_error(it["alias"], "account", *_unavailable(exc)), "_i": i})
        return
    if isinstance(slot, int):
        out.at.block = slot
    full = 0
    for (i, it), acc in zip(acct_items, accs + [None] * (len(acct_items) - len(accs)), strict=False):
        row = _sol_record(out, it, acc)
        if acc is None or (str(acc.get("owner") or "") == SYSTEM_PROGRAM_ID and row["value"].get("data_len") == "0"):
            # System-owned with no data is what a keypair, a Squads vault and any PDA all look like
            full += 1
            n0 = len(out.facts)
            kind = await solana_authority(px, out, f"chain.{it['alias']}", it["address"], [it["address"]],
                                          acc=acc, lookup=full <= SOL_CLASSIFY_PER_CALL)
            row["authority_kind"] = kind
            row["value"]["authority_kind"] = kind["kind"]
            row["fact_keys"] = [*row.get("fact_keys", []), *(f["key"] for f in out.facts[n0:])]
        out.items.append({**row, "_i": i})


def _sol_record(out: Out, it: dict[str, Any], acc: dict[str, Any] | None) -> dict[str, Any]:
    alias = it["alias"]
    pre = f"chain.{alias}"
    if acc is None:
        keys = [out.fact(f"{pre}.exists", "false", method="getMultipleAccounts", source="getMultipleAccounts")]
        return {"alias": alias, "kind": "account", "ok": True, "value": {"exists": "false"}, "fact_keys": keys}
    data = base64.b64decode((acc.get("data") or ["", "base64"])[0] or "")
    vals = {"exists": "true", "lamports": str(int(acc.get("lamports") or 0)), "owner": str(acc.get("owner") or ""),
            "executable": "true" if acc.get("executable") else "false", "data_len": str(len(data)),
            "data_sha256": hashlib.sha256(data).hexdigest()}
    keys = [out.fact(f"{pre}.{k}", v, method="getMultipleAccounts", source="getMultipleAccounts",
                     unit="bytes" if k == "data_len" else None) for k, v in vals.items()]
    row: dict[str, Any] = {"alias": alias, "kind": "account", "ok": True, "value": dict(vals)}
    errs = []
    for fdef in (it.get("fields") or [])[:20]:
        try:
            name, off, t = str(fdef["name"]), int(fdef["offset"]), str(fdef["type"])
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name) or t not in _SOL_TYPES or not 0 <= off < 10_485_760:
                raise ValueError("field is {name: [a-z0-9_], offset: int, type: u8|u16|u32|u64|u128|i64|bool|pubkey}")
            v = _sol_field(data, off, t)
        except (KeyError, ValueError, TypeError) as exc:
            errs.append(str(exc)[:120])
            continue
        keys.append(out.fact(f"{pre}.{name}", v, method="getMultipleAccounts",
                             source=f"getMultipleAccounts data[{off}:{off + _SOL_TYPES[t]}] as {t}"))
        row["value"][name] = v
    if errs:
        row["field_errors"] = errs
    row["fact_keys"] = keys
    return row


# ── TON ────────────────────────────────────────────────────────────────────


async def ton_resolve(px: ChainProxy, job: ChainJob, spec: Any) -> At:
    info = await px.ton("getMasterchainInfo", None, http="GET")
    head = int(((info or {}).get("last") or {}).get("seqno") or 0)
    if spec in (None, "latest"):
        seqno = head
    elif spec == "pinned":
        if job.pinned_block is None:
            raise InputError("block", "this job has no pinned masterchain block", spec, "latest")
        seqno = int(job.pinned_block)
    else:
        seqno = int(spec)
        if seqno > head:
            raise InputError("block", f"seqno is after the masterchain head {head}", spec, str(head))
    return At(block=seqno, head=head, block_time=None)


async def ton_get_method(px: ChainProxy, at: At, address: str, method: str, args: list[Any]) -> dict[str, Any]:
    from .ton_codec import num_arg
    stack = [num_arg(a) for a in args]
    return await px.ton("runGetMethodStd", {"address": address, "method": method, "stack": stack, "seqno": at.block},
                        durable=at.head is not None and at.block < at.head)


def _ton_values(out: Out, key: str, entries: list[dict[str, Any]], method: str, source: str) -> list[str]:
    keys: list[str] = []
    single = len(entries) == 1

    def walk(k: str, e: dict[str, Any], depth: int) -> None:
        if len(keys) >= 40:
            return
        t = e.get("type")
        if t == "int":
            keys.append(out.fact(k, str(e["value"]), method=method, source=source))
        elif t == "address":
            keys.append(out.fact(k, e["friendly"], method=method, source=source))
        elif t in ("tuple", "list"):
            keys.append(out.fact(k + ".count", str(len(e.get("items") or [])), method=method, source=source))
            for j, sub in enumerate(e.get("items") or []):
                if depth < 3:
                    walk(f"{k}.{j}", sub, depth + 1)
        elif t in ("cell", "slice"):
            keys.append(out.fact(k + ".boc_sha256", e["boc_sha256"], method=method, source=source))

    for i, e in enumerate(entries):
        walk(key if single else f"{key}.{i}", e, 0)
    return keys


async def ton_read(px: ChainProxy, out: Out, items: list[dict[str, Any]]) -> None:
    from .ton_codec import decode_stack
    for i, it in enumerate(items):
        alias, kind = it["alias"], it["kind"]
        try:
            if kind == "get_method":
                m = str(it.get("method") or "")
                if not re.fullmatch(r"[a-z_][a-z0-9_]{0,63}", m):
                    raise InputError("items.method", "a TON get method name is [a-z0-9_]", m, "get_jetton_data")
                r = await ton_get_method(px, out.at, it["address"], m, list(it.get("args") or []))
                exit_code = int((r or {}).get("exit_code", -1))
                key = f"chain.{alias}.{it.get('field') or m}"
                method = f"runGetMethod {m}"[:60]
                if exit_code not in (0, 1):
                    keys = [out.fact(f"{key}.reverted", "true", method=method, source=method),
                            out.fact(f"{key}.exit_code", str(exit_code), method=method, source=method)]
                    out.items.append({"alias": alias, "kind": kind, "ok": True, "reverted": True,
                                      "revert_reason": f"TVM exit code {exit_code}", "fact_keys": keys, "_i": i})
                    continue
                entries = decode_stack((r or {}).get("stack"))
                keys = _ton_values(out, key, entries, method, method)
                out.items.append({"alias": alias, "kind": kind, "ok": True, "value": entries, "fact_keys": keys,
                                  "gas_used": (r or {}).get("gas_used"), "_i": i})
            elif kind == "account":
                info = await px.ton("getAddressInformation", {"address": it["address"], "seqno": out.at.block}, http="GET")
                vals = {"balance": (str(int((info or {}).get("balance") or 0)), "nanoton"),
                        "state": (str((info or {}).get("state") or "unknown")[:20], None)}
                code = (info or {}).get("code") or ""
                if code:
                    vals["code_sha256"] = (hashlib.sha256(base64.b64decode(code)).hexdigest(), None)
                keys = [out.fact(f"chain.{alias}.{k}", v, method="getAddressInformation",
                                 source="getAddressInformation", unit=u) for k, (v, u) in vals.items()]
                out.items.append({"alias": alias, "kind": kind, "ok": True,
                                  "value": {k: v for k, (v, _u) in vals.items()}, "fact_keys": keys, "_i": i})
            else:
                raise InputError("items.kind", "TON reads are get_method or account", kind, "get_method")
        except InputError as exc:
            out.items.append({**item_error(alias, kind, "input", exc.rule), "_i": i})
        except (ValueError, TypeError) as exc:
            out.items.append({**item_error(alias, kind, "input", str(exc)), "_i": i})
        except ChainUnavailable as exc:
            out.items.append({**item_error(alias, kind, *_unavailable(exc)), "_i": i})
        except RpcFailure as exc:
            out.items.append({**upstream_error(alias, kind, exc.message), "_i": i})


RESOLVERS = {"evm": evm_resolve, "tron": tron_resolve, "solana": solana_resolve, "ton": ton_resolve}
READERS = {"evm": evm_read, "tron": tron_read, "solana": solana_read, "ton": ton_read}


# ── roles (design 1.5) ─────────────────────────────────────────────────────


def _addr_of(word: bytes) -> str | None:
    if len(word) != 32 or int.from_bytes(word[:12], "big"):
        return None
    return "0x" + word[12:].hex()


async def _classify_holder(px: ChainProxy, out: Out, pre: str, holder: str) -> dict[str, Any]:
    """EOA, Safe (structural: proxy runtime plus a published singleton; threshold and owners read),
    or a contract (with getMinDelay when it answers, labelled as the contract's own answer)."""
    cid, b, final = int(out.job.chain_id or 0), hex(out.at.block), _is_final(out.at)
    try:
        code = await px.evm(cid, "eth_getCode", [holder, b], durable=final)
    except (ChainUnavailable, RpcFailure):
        return {}
    raw = bytes.fromhex(str(code)[2:])
    info: dict[str, Any] = {"code_size": len(raw)}
    kind = "eoa" if not raw else "contract"
    if raw and is_safe_proxy_code(raw):
        try:
            slot0 = await px.evm(cid, "eth_getStorageAt", [holder, "0x" + "0" * 64, b], durable=final)
            single = _addr_of(bytes.fromhex(str(slot0)[2:].rjust(64, "0")))
        except (ChainUnavailable, RpcFailure):
            single = None
        if single and single in _safe_singletons():
            kind = "safe"
    if kind == "safe":
        res = await evm_calls(px, cid, out.at, [(holder, abi.selector("getThreshold()")),
                                                (holder, abi.selector("getOwners()"))])
        if isinstance(res[0], tuple) and res[0][0] and len(res[0][1]) == 32:
            info["safe_threshold"] = int.from_bytes(res[0][1], "big")
        if isinstance(res[1], tuple) and res[1][0]:
            try:
                info["safe_owners"] = len(abi.decode(["address[]"], res[1][1])[0])
            except abi.AbiError:
                pass
    elif kind == "contract":
        res = await evm_calls(px, cid, out.at, [(holder, abi.selector("getMinDelay()"))])
        if isinstance(res[0], tuple) and res[0][0] and len(res[0][1]) == 32:
            info["min_delay_s"] = int.from_bytes(res[0][1], "big")
    info["kind"] = kind
    out.fact(f"{pre}.holder_kind", kind, method="eth_getCode", source="eth_getCode (and Safe singleton slot)")
    out.fact(f"{pre}.holder_code_size", str(len(raw)), method="eth_getCode", source="eth_getCode", unit="bytes")
    if "safe_threshold" in info:
        out.fact(f"{pre}.safe_threshold", str(info["safe_threshold"]), method="eth_call getThreshold()",
                 source="eth_call getThreshold() on the Safe")
    if "safe_owners" in info:
        out.fact(f"{pre}.safe_owners", str(info["safe_owners"]), method="eth_call getOwners()",
                 source="eth_call getOwners() on the Safe")
    if "min_delay_s" in info:
        out.fact(f"{pre}.min_delay", str(info["min_delay_s"]), method="eth_call getMinDelay()", unit="seconds",
                 source="eth_call getMinDelay() (the holder contract's own answer, not proof of a timelock)")
    return info


ROLE_GETTERS = ("owner", *HOLDER_GETTERS)
# hasRole pairs (role x candidate) per call, members read per role (getRoleMember) and holders classified
AC_MAX_PAIRS = 400
AC_MAX_ROLES = 24      # roles listed (and written as facts) per contract; the rest are counted
AC_MAX_MEMBERS = 10
AC_CLASSIFY = 8


def _word_bool(r: Any) -> bool | None:
    if isinstance(r, tuple) and r[0] and len(r[1]) == 32 and int.from_bytes(r[1], "big") in (0, 1):
        return bool(int.from_bytes(r[1], "big"))
    return None


async def _creation_block(px: ChainProxy, cid: int, address: str, at: At, max_calls: int = 34) -> int | None:
    """Lowest block with code at `address` (binary search over eth_getCode, archive hosts first), or None
    when the pool has no archive host or a probe fails. A contract re-created with CREATE2 reads as its
    latest creation."""
    if not any(e.archive for e in px._endpoints("evm", cid)):
        return None
    lo, hi, n = 0, at.block, 0
    while lo < hi:
        if n >= max_calls:
            return None
        mid = (lo + hi) // 2
        n += 1
        try:
            code = await px.evm(cid, "eth_getCode", [address, hex(mid)], durable=True,
                                depth=(at.head or at.block) - mid)
        except (ChainUnavailable, RpcFailure):
            return None
        if isinstance(code, str) and len(code) > 2:
            hi = mid
        else:
            lo = mid + 1
    return lo


async def evm_access_control(px: ChainProxy, out: Out, address: str, pre: str, named: list[tuple[str, bytes]],
                             candidates: list[str], creation_block: int | None, creation_tx: str | None,
                             wall_s: float | None = None, log_calls: int | None = None) -> dict[str, Any] | None:
    """OpenZeppelin AccessControl members of `address` (see chain.access_control), or None when the
    contract does not answer as AccessControl. `named` are role constants read on chain."""
    from . import access_control as acm
    from .endpoints import logs_chunk
    from .policy import MAX_LOG_RANGE
    cid, b = int(out.job.chain_id or 0), out.at.block
    lim = limits()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + float(wall_s if wall_s is not None else lim.get("role_wall_s", 25))
    probe = await evm_calls(px, cid, out.at, [
        (address, abi.selector("supportsInterface(bytes4)") + acm.IACCESS_CONTROL + b"\0" * 28),
        (address, abi.selector("supportsInterface(bytes4)") + acm.IACCESS_CONTROL_ENUMERABLE + b"\0" * 28),
        (address, abi.selector("hasRole(bytes32,address)") + acm.DEFAULT_ADMIN + b"\0" * 32),
        (address, abi.selector("getRoleMemberCount(bytes32)") + acm.DEFAULT_ADMIN),
        (address, abi.selector("getMinDelay()")),
        (address, abi.selector("getRoleAdmin(bytes32)") + acm.DEFAULT_ADMIN),
    ])
    iface, enum_iface, has0 = _word_bool(probe[0]), _word_bool(probe[1]), _word_bool(probe[2])
    count0 = probe[3][1] if isinstance(probe[3], tuple) and probe[3][0] and len(probe[3][1]) == 32 else None
    admin0 = isinstance(probe[5], tuple) and probe[5][0] and len(probe[5][1]) == 32
    if not (iface or (has0 is not None and admin0)):   # ERC-165, else both AccessControl getters answer
        return None
    enumerable = bool(enum_iface) or count0 is not None
    names: dict[bytes, tuple[str, str]] = {acm.DEFAULT_ADMIN: ("DEFAULT_ADMIN_ROLE", "OpenZeppelin constant")}
    for rid, n in acm.common_role_ids().items():
        names.setdefault(rid, (n, "keccak256 of a common role name"))
    for n, rid in named:
        names[rid] = (n, "contract constant")

    # ── logs: the creation receipt, then bounded getLogs windows at both ends ──
    events: list[acm.RoleEvent] = []
    scanned: list[tuple[int, int]] = []
    failed: list[tuple[int, int]] = []
    if creation_tx and re.fullmatch(r"0x[0-9a-fA-F]{64}", creation_tx):
        try:
            rcpt = await px.evm(cid, "eth_getTransactionReceipt", [creation_tx], durable=True)
            for lg in (rcpt.get("logs") or []) if isinstance(rcpt, dict) else []:
                ev = acm.parse_log(lg, address)
                if ev:
                    events.append(ev)
        except (ChainUnavailable, RpcFailure):
            pass
    if creation_block is None:
        creation_block = await _creation_block(px, cid, address, out.at)
    chunk = logs_chunk(cid, MAX_LOG_RANGE)
    plan = acm.ScanPlan(creation_block, b, chunk, log_calls or int(lim.get("role_log_calls", 24)))
    final = b - int((lim.get("finality_blocks") or {}).get("evm", 64))
    misses = 0
    for wi, (lo, hi) in enumerate(plan.windows):
        if wi == plan.split:
            misses = 0        # old ranges refused by every free host say nothing about recent ones
        if loop.time() > deadline or misses >= 3:
            failed.append((lo, hi))
            continue
        flt = {"address": address, "topics": [[acm.ROLE_GRANTED, acm.ROLE_REVOKED]], "fromBlock": hex(lo), "toBlock": hex(hi)}
        try:
            logs = await px.evm(cid, "eth_getLogs", [flt], durable=hi <= final, depth=(out.at.head or b) - lo)
        except (ChainUnavailable, RpcFailure) as exc:
            failed.append((lo, hi))
            # no free host holds logs that old: the rest of this end is not tried
            misses = 3 if getattr(exc, "reason", "") == "archive" else misses + 1
            continue
        if not isinstance(logs, list):
            failed.append((lo, hi))
            continue
        misses = 0
        scanned.append((lo, hi))
        for lg in logs:
            ev = acm.parse_log(lg, address)
            if ev:
                events.append(ev)
    logs_complete = acm.covered(scanned, creation_block, b)
    now, ever = acm.replay(events)

    # ── role ids and candidates ──
    role_ids: list[bytes] = list(dict.fromkeys([acm.DEFAULT_ADMIN, *(rid for _n, rid in named), *ever]))
    probe_ids = role_ids + [rid for rid in names if rid not in role_ids]   # common names: kept only with a member
    base = list(dict.fromkeys([*(c.lower() for c in candidates if c and EVM_ADDR.match(c)), address.lower(), acm.ZERO]))
    from_logs = sorted({a for accts in ever.values() for a in accts} - set(base))[:24]
    cand = base + from_logs
    named_ids = {acm.DEFAULT_ADMIN, *(rid for _n, rid in named)}
    members: dict[bytes, list[str]] = {}
    unverified: dict[bytes, set[str]] = {}
    complete_role: dict[bytes, bool] = {}
    counts: dict[bytes, int] = {}
    if enumerable:
        cres = await evm_calls(px, cid, out.at, [(address, abi.selector("getRoleMemberCount(bytes32)") + rid)
                                                 for rid in probe_ids])
        for rid, r in zip(probe_ids, cres, strict=True):
            if isinstance(r, tuple) and r[0] and len(r[1]) == 32:
                counts[rid] = int.from_bytes(r[1], "big")
        want = [(rid, j) for rid in probe_ids if counts.get(rid) for j in range(min(counts[rid], AC_MAX_MEMBERS))]
        mres = await evm_calls(px, cid, out.at, [
            (address, abi.selector("getRoleMember(bytes32,uint256)") + abi.encode(["bytes32", "uint256"], ["0x" + rid.hex(), j]))
            for rid, j in want])
        for (rid, _j), r in zip(want, mres, strict=True):
            a = _addr_of(r[1]) if isinstance(r, tuple) and r[0] else None
            if a:
                members.setdefault(rid, []).append(a)
        for rid, n in counts.items():
            complete_role[rid] = n <= AC_MAX_MEMBERS and len(members.get(rid, [])) == n
    else:
        # DEFAULT_ADMIN_ROLE and the contract's own constants: every candidate; a role seen in the logs: the
        # accounts the logs granted it and the getter holders; a common role name: every candidate (last)
        pairs = list(dict.fromkeys(
            [(rid, c) for rid in probe_ids if rid in named_ids for c in cand]
            + [(rid, c) for rid in probe_ids if rid in ever and rid not in named_ids
               for c in [*sorted(ever[rid]), *base]]
            + [(rid, c) for rid in probe_ids if rid not in ever and rid not in named_ids for c in cand]))[:AC_MAX_PAIRS]
        hres = await evm_calls(px, cid, out.at, [
            (address, abi.selector("hasRole(bytes32,address)") + rid + bytes.fromhex(c[2:].rjust(64, "0")))
            for rid, c in pairs])
        for (rid, c), r in zip(pairs, hres, strict=True):
            ok = _word_bool(r)
            if ok or (ok is None and c in now.get(rid, set())):   # hasRole failed: the logs' answer, marked
                members.setdefault(rid, []).append(c)
                if ok is None:
                    unverified.setdefault(rid, set()).add(c)
        for rid in probe_ids:
            counts[rid] = len(members.get(rid, []))
            complete_role[rid] = logs_complete
    every = [rid for rid in probe_ids if members.get(rid) or rid in ever or rid in named_ids]
    # named roles first, then by members held now
    listed = sorted(every, key=lambda r: (0 if r in named_ids else 1 if r in names else 2,
                                          -len(members.get(r, [])), every.index(r)))[:AC_MAX_ROLES]
    admins = await evm_calls(px, cid, out.at, [(address, abi.selector("getRoleAdmin(bytes32)") + rid) for rid in listed])

    # ── facts and result ──
    std = "AccessControlEnumerable" if enumerable else "AccessControl"
    complete = logs_complete and all(complete_role.get(r, logs_complete) for r in listed)
    src = ("getRoleMemberCount / getRoleMember" if enumerable
           else "RoleGranted / RoleRevoked logs, each member confirmed with hasRole")
    out.fact(f"{pre}.access_control", std, method="eth_call supportsInterface / hasRole",
             source="supportsInterface(IAccessControl) or a hasRole answer")
    min_delay = int.from_bytes(probe[4][1], "big") if isinstance(probe[4], tuple) and probe[4][0] \
        and len(probe[4][1]) == 32 else None
    if min_delay is not None:
        out.fact(f"{pre}.access_control.min_delay", str(min_delay), method="eth_call getMinDelay()", unit="seconds",
                 source="eth_call getMinDelay() (the contract's own answer)")
    out.fact(f"{pre}.access_control.complete", "true" if complete else "false", method="eth_getLogs",
             source="every block from creation to the read block was scanned for role logs")
    total = (b - creation_block + 1) if creation_block is not None else None
    out.fact(f"{pre}.access_control.log_blocks_scanned", str(acm.blocks_in(scanned)), method="eth_getLogs",
             source="blocks scanned for RoleGranted / RoleRevoked", unit="blocks")
    if creation_block is not None:
        out.fact(f"{pre}.access_control.creation_block", str(creation_block), method="Sourcify or eth_getCode",
                 source="creation block (Sourcify record, else the lowest block with code)")
    memo: dict[str, dict[str, Any]] = {}
    roles_out: list[dict[str, Any]] = []
    for rid, adm in zip(listed, admins, strict=True):
        nm, how = names.get(rid, (f"role_{rid.hex()[:8]}", "unnamed: no constant or common name matches the id"))
        rkey = f"{pre}.role.{field_key(nm)}"
        mem = members.get(rid, [])
        out.fact(f"{rkey}.count", str(counts.get(rid, len(mem))), method="eth_call getRoleMemberCount" if enumerable
                 else "eth_getLogs + eth_call hasRole", source=f"{src} ({nm})")
        details = []
        for j, a in enumerate(mem[:AC_MAX_MEMBERS]):
            out.fact(f"{rkey}.{j}", a, method="eth_call getRoleMember" if enumerable else "eth_call hasRole",
                     source=f"{nm} member {j} ({src})")
            d: dict[str, Any] = {"account": a}
            if a in unverified.get(rid, set()):
                d["unverified"] = "hasRole did not answer; member per the scanned logs"
            if a == acm.ZERO:
                d["kind"] = "zero_address"
            elif a == address.lower():
                d["kind"] = "self"
            elif a in memo:
                d.update(memo[a])
            elif len(memo) < AC_CLASSIFY:
                memo[a] = await _classify_holder(px, out, f"{rkey}.{j}", a)
                d.update(memo[a])
            details.append(d)
        row: dict[str, Any] = {"role": nm, "role_id": "0x" + rid.hex(), "name_from": how,
                               "count": counts.get(rid, len(mem)), "members": mem[:AC_MAX_MEMBERS],
                               "member_details": details, "complete": bool(complete_role.get(rid, False))}
        if acm.ZERO in mem:
            row["open"] = True
            out.fact(f"{rkey}.open", "true", method="eth_call hasRole(role, address(0))",
                     source=f"{nm} is granted to address(0): anyone holds it")
        if isinstance(adm, tuple) and adm[0] and len(adm[1]) == 32:
            an = names.get(adm[1], (f"role_{adm[1].hex()[:8]}", ""))[0]
            row["admin_role"] = an
            out.fact(f"{rkey}.admin_role", an, method="eth_call getRoleAdmin", source=f"getRoleAdmin({nm})")
        revoked = sorted(ever.get(rid, set()) - set(mem))
        if revoked:
            row["revoked"] = revoked[:AC_MAX_MEMBERS]
        roles_out.append(row)
    if logs_complete:
        note = f"Members from {src}. Every block from creation to the read block was scanned for role logs."
    else:
        span = f"{acm.blocks_in(scanned):,} of {total:,} blocks since creation" if total else \
            f"{acm.blocks_in(scanned):,} blocks (creation block unknown)"
        note = (f"Members from {src}. Partial: role logs were read for {span}. " + (
            "Members of each listed role are complete (getRoleMember), but a role whose id is neither a contract "
            "constant, a common role name nor in the scanned logs is not listed." if enumerable else
            "A role or member granted only in an unscanned range is missing; every member listed is confirmed by "
            "hasRole at the read block."))
    if len(every) > len(listed):
        note += (f" {len(every) - len(listed)} more roles with members or log entries are not listed (cap "
                 f"{AC_MAX_ROLES}); read one with review_chain_read hasRole(bytes32,address).")
    summary = {"standard": std, "enumerable": enumerable, "roles_total": len(every), "roles_listed": len(listed),
               **({"min_delay_s": min_delay} if min_delay is not None else {}),
               "complete": bool(complete), "members_source": src, "creation_block": creation_block, "log_blocks_scanned": acm.blocks_in(scanned),
               "log_blocks_total": total, "log_events": len({(e.block, e.index, e.tx) for e in events}),
               "scanned": [list(w) for w in acm.merge(scanned)][:10],
               "not_scanned": [list(w) for w in acm.merge(failed)][:10], "note": note[:700]}
    if not complete:
        summary["partial"] = True
    return {"summary": summary, "roles": roles_out}


async def evm_roles(px: ChainProxy, out: Out, address: str, alias: str, extra: list[str]) -> dict[str, Any]:
    cid, b, final = int(out.job.chain_id or 0), hex(out.at.block), _is_final(out.at)
    pre = f"chain.{alias}"
    result: dict[str, Any] = {"address": address, "proxy": {}, "holders": [], "roles": [], "deployment": None}
    for name, slot in (("implementation", EIP1967_IMPL), ("admin", EIP1967_ADMIN), ("beacon", EIP1967_BEACON)):
        try:
            word = await px.evm(cid, "eth_getStorageAt", [address, slot, b], durable=final)
        except ChainUnavailable as exc:
            result["proxy"]["error"] = _unavailable(exc)[1]
            break
        except RpcFailure:
            continue
        a = _addr_of(bytes.fromhex(str(word)[2:].rjust(64, "0")[-64:]))
        if a and int(a, 16):
            result["proxy"][name] = a
            out.fact(f"{pre}.eip1967.{name}", a, method="eth_getStorageAt", source=f"eth_getStorageAt EIP-1967 {name} slot")
    getters = list(dict.fromkeys([*ROLE_GETTERS, *extra]))
    role_consts = sorted(n for n in out.job.unit_functions if re.fullmatch(r"[A-Z][A-Z0-9_]{0,40}_ROLE", n)) \
        if address.lower() == str(out.job.address or "").lower() else []
    calls = [(address, abi.selector(f"{g}()")) for g in getters] + \
            [(address, abi.selector(f"{r}()")) for r in role_consts]
    res = await evm_calls(px, cid, out.at, calls)
    holders: list[tuple[str, str]] = []
    for g, r in zip(getters, res[:len(getters)], strict=True):
        if isinstance(r, tuple) and r[0] and len(r[1]) == 32:
            a = _addr_of(r[1])
            if a is not None:
                holders.append((g, a))
    named = []
    for rname, r in zip(role_consts, res[len(getters):], strict=True):
        if isinstance(r, tuple) and r[0] and len(r[1]) == 32:
            named.append((rname, r[1]))
    for g, a in holders:
        key = f"{pre}.{field_key(g)}"
        out.fact(key, a, method=f"eth_call {g}()", source=f"eth_call {g}()")
        row = {"getter": g, "holder": a, "fact_key": key}
        if int(a, 16):
            row.update(await _classify_holder(px, out, key, a))
        result["holders"].append(row)
    if out.job.chain_id:
        dep = await px.sourcify_deployment(int(out.job.chain_id), address)
        # third-party record: only well-formed values become facts (an address, a tx hash, a number)
        if dep and not (EVM_ADDR.match(str(dep.get("deployer") or ""))
                        and re.fullmatch(r"0x[0-9a-fA-F]{64}", str(dep.get("transactionHash") or ""))
                        and re.fullmatch(r"\d{1,12}", str(dep.get("blockNumber") or ""))):
            dep = None
        if dep and dep.get("deployer"):
            result["deployment"] = {"deployer": dep.get("deployer"), "creation_tx": dep.get("transactionHash"),
                                    "creation_block": dep.get("blockNumber")}
            for k, v, m in (("deployer", str(dep.get("deployer") or "").lower(), "Sourcify deployment"),
                            ("creation_tx", str(dep.get("transactionHash") or ""), "Sourcify deployment"),
                            ("creation_block", str(dep.get("blockNumber") or ""), "Sourcify deployment")):
                if v:
                    out.facts.append(chain_fact(f"{pre}.{k}", v, source="Sourcify verified deployment record",
                                                chain_id=out.job.chain_id, block=None, method=m, network=out.job.network,
                                                family="evm"))
            owner = next((a for g, a in holders if g == "owner"), None)
            if owner and str(dep.get("deployer") or "").lower():
                same = owner.lower() == str(dep.get("deployer")).lower()
                out.fact(f"{pre}.owner_is_deployer", "true" if same else "false", method="eth_call owner()",
                         source="owner() compared with the Sourcify deployer")
                result["owner_is_deployer"] = same
    # AccessControl (TimelockController included): role members from getRoleMember, else from the
    # RoleGranted/RoleRevoked logs confirmed by hasRole (chain.access_control)
    dep_rec = result.get("deployment") or {}
    cands = [a for _g, a in holders] + [str(dep_rec.get("deployer") or "").lower()]
    ac = await evm_access_control(px, out, address, pre, named, cands,
                                  int(dep_rec["creation_block"]) if dep_rec.get("creation_block") else None,
                                  str(dep_rec.get("creation_tx") or "") or None)
    if ac is not None:
        result["access_control"] = ac.pop("summary")
        result["roles"] = ac["roles"]
    # a holder that answers getMinDelay (a TimelockController owner, say): who proposes and executes
    tl = next((r for r in result["holders"] if r.get("kind") == "contract" and "min_delay_s" in r), None)
    if tl is not None:
        tdep = await px.sourcify_deployment(cid, tl["holder"]) if cid else None
        tblock = str((tdep or {}).get("blockNumber") or "")
        ttx = str((tdep or {}).get("transactionHash") or "")
        tac = await evm_access_control(px, out, tl["holder"], tl["fact_key"], [], [address.lower()],
                                       int(tblock) if re.fullmatch(r"\d{1,12}", tblock) else None,
                                       ttx if re.fullmatch(r"0x[0-9a-fA-F]{64}", ttx) else None,
                                       wall_s=12, log_calls=12)
        if tac is not None:
            tl["access_control"] = tac.pop("summary")
            tl["roles"] = tac["roles"]
    return result


async def tron_roles(px: ChainProxy, out: Out, address: str, alias: str, extra: list[str]) -> dict[str, Any]:
    from ..adapters.tron.address import hex_to_b58
    result: dict[str, Any] = {"address": address, "holders": [], "account": None}
    acct = await _tron_account(px, out, {"alias": alias, "address": address})
    result["account"] = acct.get("value") if acct.get("ok") else acct.get("error")
    for g in list(dict.fromkeys([*ROLE_GETTERS, *extra])):
        r = await _tron_call(px, address, f"{g}()", abi.selector(f"{g}()"))
        if not (isinstance(r, tuple) and r[0] and len(r[1]) == 32):
            continue
        a = _addr_of(r[1])
        if a is None:
            continue
        b58 = hex_to_b58(a[2:]) if int(a, 16) else a
        key = f"chain.{alias}.{field_key(g)}"
        out.fact(key, b58, method=f"triggerconstantcontract {g}()", source=f"triggerconstantcontract {g}()")
        row: dict[str, Any] = {"getter": g, "holder": b58, "fact_key": key}
        if int(a, 16):
            hold = await _tron_account(px, out, {"alias": alias, "address": b58}, role_prefix=key)
            row["account"] = hold.get("value") if hold.get("ok") else None
        result["holders"].append(row)
    return result


_SIG_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{64,90}$")


async def solana_authority(px: ChainProxy, out: Out, pre: str, address: str, history: list[str] | None = None,
                           acc: dict[str, Any] | None | bool = False, lookup: bool = True) -> dict[str, Any]:
    """Who can sign as `address` (see chain.sol_authority): a Squads vault re-derived from a multisig named
    in the signer history of `address` or of the accounts it controls (`history`, for example the ProgramData
    of a program, whose transactions are its deploys and upgrades), a PDA (off curve, no private key), a key
    on the curve, or unknown. Never "plain keypair" from System ownership: that is what every one of them
    looks like. `acc` is the account when the caller already read it (None: it does not exist); `lookup`
    False skips the signer history (curve check only)."""
    from . import sol_authority as sa
    try:
        curve = sa.on_curve(sa.pubkey(address))
    except ValueError:
        return {"kind": "unknown", "note": "not a 32-byte base58 public key"}
    info: dict[str, Any] = {"on_curve": curve}
    if acc is False:
        try:
            _s, accs = await solana_accounts(px, [address])
            acc = accs[0] if accs else None
        except ChainUnavailable:
            acc = False
    if acc is not False:
        info["owner_program"] = str(acc.get("owner") or "") if acc else None
        info["exists"] = acc is not None
    out.fact(f"{pre}.on_curve", "true" if curve else "false", method="ed25519 decompression",
             source="address bytes checked against the ed25519 curve (off curve = program-derived, no private key)")
    if curve:
        info.update(kind="on_curve_key", private_key_possible=True,
                    note=("On the ed25519 curve: a private key can exist for this address. Who holds it (one person, "
                          "an MPC or hardware setup) is not visible on chain; System ownership does not show a "
                          "single keypair."))
    else:
        info.update(kind="pda", private_key_possible=False)
        found = (await _squads_vault(px, address, [h for h in (history or []) if h != address] + [address])
                 if lookup else {"why": "The signer history was not read in this call (review_chain_roles on the "
                                        "address checks it for a Squads vault)."})
        if found.get("multisig"):
            info.update(found)
        else:
            info["note"] = ("Off the ed25519 curve: a program-derived address with no private key; it signs only "
                            "through the program that derived it. " + found.get("why", ""))[:300]
            if found.get("checked_txs") is not None:
                info["checked_txs"] = found["checked_txs"]
    out.fact(f"{pre}.authority_kind", info["kind"], method="getMultipleAccounts, getSignaturesForAddress",
             source="authority classification: curve check, Squads PDA re-derivation from signer history")
    ms = info.get("multisig")
    if ms:
        out.fact(f"{pre}.multisig", ms["address"], method="getMultipleAccounts multisig",
                 source=f"Squads {ms['version']} multisig whose vault PDA re-derives to the authority")
        for k, unit in (("threshold", None), ("members", None), ("voters", None), ("time_lock_s", "seconds"),
                        ("vault_index", None)):
            if ms.get(k) is not None:
                out.fact(f"{pre}.multisig_{k.removesuffix('_s')}", str(ms[k]), method="getMultipleAccounts multisig",
                         source=f"Squads {ms['version']} multisig account {k}", unit=unit)
        out.fact(f"{pre}.multisig_config_authority", ms.get("config_authority") or "none",
                 method="getMultipleAccounts multisig",
                 source="Squads multisig config authority (none = member changes need a multisig vote)")
        out.fact(f"{pre}.multisig_evidence_tx", ms["evidence_tx"], method="getTransaction",
                 source="transaction whose Squads instruction names the multisig")
    return info


async def _squads_vault(px: ChainProxy, address: str, history: list[str]) -> dict[str, Any]:
    from . import sol_authority as sa
    sigs: list[str] = []
    read_any = False
    for h in history[:3]:
        if len(sigs) >= sa.TX_LIMIT:
            break
        try:
            rows = await px.solana("getSignaturesForAddress", [h, {"limit": sa.SIG_LIMIT, "commitment": "finalized"}])
        except (ChainUnavailable, RpcFailure):
            continue
        read_any = True
        for r in rows if isinstance(rows, list) else []:
            sig = str(r.get("signature") or "") if isinstance(r, dict) else ""
            if _SIG_RE.match(sig) and not r.get("err") and sig not in sigs and len(sigs) < sa.TX_LIMIT:
                sigs.append(sig)
    if not read_any:
        return {"why": "The signer history could not be read, so a Squads vault was not checked."}
    checked = 0
    for sig in sigs[:sa.TX_LIMIT]:
        tx = None
        for attempt in range(2):   # the public RPC rate limits getTransaction hardest: one paced retry
            try:
                tx = await px.solana("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0,
                                                              "commitment": "finalized"}])
                break
            except ChainUnavailable as exc:
                if exc.reason != "rate_limited" or attempt:
                    break
                await asyncio.sleep(sa.RETRY_S)
            except RpcFailure:
                break
        if not isinstance(tx, dict):
            continue
        checked += 1
        for version, cand in sa.squads_candidates(tx, address):
            try:
                idx = next((i for i in sa.VAULT_INDICES if sa.squads_derive(version, cand, i) == address), None)
            except ValueError:
                continue
            if idx is None:
                continue
            try:
                _s, accs = await solana_accounts(px, [cand])
            except ChainUnavailable:
                accs = []
            macc = accs[0] if accs else None
            prog = sa.SQUADS_V4 if version == "v4" else sa.SQUADS_V3
            parsed = None
            if macc and str(macc.get("owner") or "") == prog:
                data = sa.account_data(macc)
                parsed = sa.parse_squads_v4(data) if version == "v4" else sa.parse_squads_v3(data)
            ms = {"version": version, "address": cand, "vault_index": idx, "evidence_tx": sig, "program": prog,
                  **(parsed or {})}
            kind = "squads_v4_vault" if version == "v4" else "squads_v3_authority"
            if parsed:
                cfg = ms.get("config_authority")
                note = (f"Squads {version} {'vault' if version == 'v4' else 'authority'} PDA (index {idx}) of multisig "
                        f"{cand}, re-derived from the multisig named in transaction {sig[:16]}...: threshold "
                        f"{ms['threshold']} of {ms['members']} members ({ms['voters']} can vote), time lock "
                        f"{ms['time_lock_s']} s; " + (f"config authority {cfg} can change members and threshold "
                                                      "without a vote." if cfg else "config authority none: changes "
                                                      "need a multisig vote."))
            else:
                note = (f"Squads {version} PDA (index {idx}) re-derived from {cand}, named in transaction {sig[:16]}...; "
                        "the multisig account could not be read, so threshold and members are unknown.")
            return {"kind": kind, "multisig": ms, "note": note[:400], "checked_txs": checked}
    if not sigs:
        return {"why": "It has no transaction history to check for a Squads vault.", "checked_txs": 0}
    return {"why": (f"No Squads instruction in the {checked} recent transaction{'s' if checked != 1 else ''} read "
                    f"({len(sigs)} listed) re-derives to it, so the deriving program is not identified."),
            "checked_txs": checked}


async def solana_roles(px: ChainProxy, out: Out, address: str, alias: str) -> dict[str, Any]:
    from ..adapters.solana.onchain import BPF_LOADER_UPGRADEABLE, PROGRAMDATA_HEADER, b58encode, parse_programdata
    pre = f"chain.{alias}"
    slot, accs = await solana_accounts(px, [address])
    if isinstance(slot, int):
        out.at.block = slot
    acc = accs[0] if accs else None
    result: dict[str, Any] = {"address": address}
    if acc is None:
        out.fact(f"{pre}.exists", "false", method="getMultipleAccounts", source="getMultipleAccounts")
        result["exists"] = False
        result["authority_kind"] = await solana_authority(px, out, pre, address, [], acc=None)
        return result
    owner = str(acc.get("owner") or "")
    data = base64.b64decode((acc.get("data") or [""])[0] or "")
    out.fact(f"{pre}.owner", owner, method="getMultipleAccounts", source="getMultipleAccounts owner")
    result["owner_program"] = owner
    if owner == BPF_LOADER_UPGRADEABLE and len(data) >= 36:
        pd_addr = b58encode(data[4:36])
        try:
            _s, pds = await solana_accounts(px, [pd_addr], data_slice=(0, PROGRAMDATA_HEADER))
        except ChainUnavailable as exc:
            result["upgrade_authority_error"] = _unavailable(exc)[1]
            pds = []
        pd = pds[0] if pds else None
        parsed = parse_programdata(base64.b64decode((pd.get("data") or [""])[0] or "")) if pd else None
        if parsed is not None:
            auth = parsed[0]
            out.fact(f"{pre}.upgrade_authority", auth or "none", method="getMultipleAccounts programdata",
                     source="ProgramData upgrade authority (none = immutable)")
            result["upgrade_authority"] = auth
            out.fact(f"{pre}.programdata", pd_addr, method="getMultipleAccounts", source="program account data")
            if auth:   # the ProgramData's own transactions are the deploys and upgrades the authority signed
                result["upgrade_authority_kind"] = await solana_authority(
                    px, out, f"{pre}.upgrade_authority", auth, [pd_addr, address])
    elif owner in TOKEN_PROGRAMS and len(data) >= 82:
        mint_auth = b58encode(data[4:36]) if int.from_bytes(data[0:4], "little") == 1 else "none"
        freeze = b58encode(data[50:82]) if int.from_bytes(data[46:50], "little") == 1 else "none"
        supply = int.from_bytes(data[36:44], "little")
        for k, v in (("mint_authority", mint_auth), ("freeze_authority", freeze), ("supply", str(supply)),
                     ("decimals", str(data[44]))):
            out.fact(f"{pre}.{k}", v, method="getMultipleAccounts mint", source=f"SPL mint {k}")
            result[k] = v
        for k in ("mint_authority", "freeze_authority"):
            if result[k] != "none":
                result[f"{k}_kind"] = await solana_authority(px, out, f"{pre}.{k}", result[k], [address])
    elif owner == SYSTEM_PROGRAM_ID or not data:
        # a wallet-like account (an authority read on its own): say what can sign for it
        result["authority_kind"] = await solana_authority(px, out, pre, address, [address], acc=acc)
    return result


async def ton_roles(px: ChainProxy, out: Out, address: str, alias: str, extra: list[str]) -> dict[str, Any]:
    from .ton_codec import decode_stack
    result: dict[str, Any] = {"address": address, "holders": []}
    methods = list(dict.fromkeys(["get_jetton_data", "get_owner", "owner", *extra]))[:6]
    for m in methods:
        try:
            r = await ton_get_method(px, out.at, address, m, [])
        except (ChainUnavailable, RpcFailure, ValueError, TypeError):
            continue
        if int((r or {}).get("exit_code", -1)) not in (0, 1):
            continue
        entries = decode_stack((r or {}).get("stack"))
        picks = [(2, entries[2])] if m == "get_jetton_data" and len(entries) > 2 else list(enumerate(entries))
        for j, e in picks:
            if e.get("type") == "address":
                name = "admin" if m == "get_jetton_data" else f"{m}_{j}" if len(entries) > 1 else m
                key = f"chain.{alias}.{field_key(name)}"
                out.fact(key, e["friendly"], method=f"runGetMethod {m}", source=f"runGetMethod {m} stack[{j}]")
                result["holders"].append({"getter": m, "holder": e["friendly"], "raw": e["value"], "fact_key": key})
    return result


# ── balances (design 1.4) ──────────────────────────────────────────────────


async def evm_balances(px: ChainProxy, out: Out, token: str, talias: str, holders: list[dict[str, Any]]) -> dict[str, Any]:
    cid, b, final = int(out.job.chain_id or 0), hex(out.at.block), _is_final(out.at)
    info: dict[str, Any] = {"token": token}
    if token == "native":
        for h in holders:
            try:
                bal = await px.evm(cid, "eth_getBalance", [h["address"], b], durable=final)
            except ChainUnavailable as exc:
                out.items.append(item_error(h["alias"], "balance", *_unavailable(exc)))
                continue
            except RpcFailure as exc:
                out.items.append(upstream_error(h["alias"], "balance", exc.message))
                continue
            key = out.fact(f"chain.{talias}.balance.{h['alias']}", str(int(bal, 16)), method="eth_getBalance",
                           source="eth_getBalance", unit="wei")
            out.items.append({"alias": h["alias"], "kind": "balance", "ok": True, "value": str(int(bal, 16)), "fact_keys": [key]})
        return info
    meta = await evm_calls(px, cid, out.at, [(token, abi.selector("decimals()")), (token, abi.selector("symbol()")),
                                            (token, abi.selector("totalSupply()"))])
    if isinstance(meta[0], tuple) and meta[0][0] and len(meta[0][1]) == 32:
        info["decimals"] = int.from_bytes(meta[0][1], "big")
        out.fact(f"chain.{talias}.decimals", str(info["decimals"]), method="eth_call decimals()", source="eth_call decimals()")
    if isinstance(meta[1], tuple) and meta[1][0]:
        try:
            (sym,) = abi.decode(["string"], meta[1][1])
        except abi.AbiError:
            sym = None
        if sym is not None:
            ut = untrusted_text(sym, f"symbol()@{token}", cap=32)
            info["symbol"] = {"untrusted_text": ut}
            out.fact(f"chain.{talias}.symbol", ut["value"], method="eth_call symbol()", source="eth_call symbol()", text=True)
    if isinstance(meta[2], tuple) and meta[2][0] and len(meta[2][1]) == 32:
        info["total_supply"] = str(int.from_bytes(meta[2][1], "big"))
        out.fact(f"chain.{talias}.total_supply", info["total_supply"], method="eth_call totalSupply()",
                 source="eth_call totalSupply()", unit="token_units")
    res = await evm_calls(px, cid, out.at, [(token, abi.selector("balanceOf(address)") + abi.encode(["address"], [h["address"]]))
                                           for h in holders])
    for h, r in zip(holders, res, strict=True):
        out.items.append(_balance_row(out, talias, h, r, "eth_call balanceOf"))
    return info


def _balance_row(out: Out, talias: str, h: dict[str, Any], r: tuple[bool, bytes] | Exception, read: str) -> dict[str, Any]:
    if isinstance(r, ChainUnavailable):
        return item_error(h["alias"], "balance", *_unavailable(r))
    if isinstance(r, Exception):
        return item_error(h["alias"], "balance", "upstream", type(r).__name__)
    ok, data = r
    if not ok or len(data) != 32:
        key = out.fact(f"chain.{talias}.balance.{h['alias']}.reverted", "true", method=f"{read}()", source=f"{read}(holder)")
        return {"alias": h["alias"], "kind": "balance", "ok": True, "reverted": True,
                "revert_reason": revert_text(data, f"balanceOf@{h['address']} revert") if not ok else "not one word",
                "fact_keys": [key]}
    v = str(int.from_bytes(data, "big"))
    key = out.fact(f"chain.{talias}.balance.{h['alias']}", v, method=f"{read}()", source=f"{read}({h['address'][:12]}...)",
                   unit="token_units")
    return {"alias": h["alias"], "kind": "balance", "ok": True, "value": v, "fact_keys": [key]}


async def tron_balances(px: ChainProxy, out: Out, token: str, talias: str, holders: list[dict[str, Any]]) -> dict[str, Any]:
    info: dict[str, Any] = {"token": token}
    if token == "native":
        for h in holders:
            try:
                acc = await px.tron("/wallet/getaccount", {"address": h["address"], "visible": True})
            except (ChainUnavailable, RpcFailure) as exc:
                out.items.append(item_error(h["alias"], "balance", *_unavailable(exc)) if isinstance(exc, ChainUnavailable)
                                 else upstream_error(h["alias"], "balance", exc.message))
                continue
            v = str(int((acc or {}).get("balance") or 0))
            key = out.fact(f"chain.{talias}.balance.{h['alias']}", v, method="getaccount", source="TronGrid getaccount", unit="sun")
            out.items.append({"alias": h["alias"], "kind": "balance", "ok": True, "value": v, "fact_keys": [key]})
        return info
    dec = await _tron_call(px, token, "decimals()", abi.selector("decimals()"))
    if isinstance(dec, tuple) and dec[0] and len(dec[1]) == 32:
        info["decimals"] = int.from_bytes(dec[1], "big")
        out.fact(f"chain.{talias}.decimals", str(info["decimals"]), method="triggerconstantcontract decimals()",
                 source="triggerconstantcontract decimals()")
    for h in holders:
        try:
            data = abi.selector("balanceOf(address)") + abi.encode(["address"], ["0x" + tron_hex(h["address"])])
        except InputError as exc:
            out.items.append(item_error(h["alias"], "balance", "input", exc.rule))
            continue
        r = await _tron_call(px, token, "balanceOf(address)", data)
        out.items.append(_balance_row(out, talias, h, r, "triggerconstantcontract balanceOf"))
    return info


async def solana_balances(px: ChainProxy, out: Out, token: str, talias: str, holders: list[dict[str, Any]]) -> dict[str, Any]:
    info: dict[str, Any] = {"token": token}
    for h in holders:
        try:
            if token == "native":
                r = await px.solana("getBalance", [h["address"], {"commitment": "finalized"}])
                v, unit, src = str(int((r or {}).get("value") or 0)), "lamports", "getBalance"
            else:
                r = await px.solana("getTokenAccountsByOwner", [h["address"], {"mint": token},
                                                                {"encoding": "jsonParsed", "commitment": "finalized"}])
                total = 0
                for acc in (r or {}).get("value") or []:
                    amt = ((((acc.get("account") or {}).get("data") or {}).get("parsed") or {}).get("info") or {}).get("tokenAmount") or {}
                    total += int(amt.get("amount") or 0)
                    info.setdefault("decimals", amt.get("decimals"))
                v, unit, src = str(total), "token_units", "getTokenAccountsByOwner (sum of the owner's accounts for the mint)"
            slot = ((r or {}).get("context") or {}).get("slot")
            if isinstance(slot, int):
                out.at.block = max(out.at.block, slot)
        except ChainUnavailable as exc:
            out.items.append(item_error(h["alias"], "balance", *_unavailable(exc)))
            continue
        except RpcFailure as exc:
            out.items.append(upstream_error(h["alias"], "balance", exc.message))
            continue
        key = out.fact(f"chain.{talias}.balance.{h['alias']}", v, method=src.split(" ")[0], source=src,
                       unit=unit if unit != "lamports" else None)
        out.items.append({"alias": h["alias"], "kind": "balance", "ok": True, "value": v, "fact_keys": [key]})
    return info


async def ton_balances(px: ChainProxy, out: Out, token: str, talias: str, holders: list[dict[str, Any]]) -> dict[str, Any]:
    from .ton_codec import decode_stack
    info: dict[str, Any] = {"token": token}
    for h in holders:
        try:
            if token == "native":
                r = await px.ton("getAddressInformation", {"address": h["address"], "seqno": out.at.block}, http="GET")
                v, src, unit = str(int((r or {}).get("balance") or 0)), "getAddressInformation balance", "nanoton"
            else:
                w = await ton_get_method(px, out.at, token, "get_wallet_address", [h["address"]])
                st = decode_stack((w or {}).get("stack"))
                if int((w or {}).get("exit_code", -1)) not in (0, 1) or not st or st[0].get("type") != "address":
                    raise RpcFailure(-1, "get_wallet_address did not return an address")
                d = await ton_get_method(px, out.at, st[0]["friendly"], "get_wallet_data", [])
                ds = decode_stack((d or {}).get("stack"))
                if int((d or {}).get("exit_code", -1)) not in (0, 1) or not ds or ds[0].get("type") != "int":
                    v = "0"
                    src = "jetton wallet not deployed (get_wallet_data failed), balance 0"
                else:
                    v = str(ds[0]["value"])
                    src = "jetton wallet get_wallet_data balance"
                unit = "token_units"
        except ChainUnavailable as exc:
            out.items.append(item_error(h["alias"], "balance", *_unavailable(exc)))
            continue
        except (RpcFailure, ValueError, TypeError) as exc:
            out.items.append(upstream_error(h["alias"], "balance", str(exc)))
            continue
        key = out.fact(f"chain.{talias}.balance.{h['alias']}", v, method=src[:60], source=src,
                       unit=unit if unit == "token_units" else None)
        out.items.append({"alias": h["alias"], "kind": "balance", "ok": True, "value": v, "fact_keys": [key]})
    return info


BALANCES = {"evm": evm_balances, "tron": tron_balances, "solana": solana_balances, "ton": ton_balances}
