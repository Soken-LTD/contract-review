"""review_chain_roles after blind round 5b (2026-10-31): AccessControl / TimelockController holders from
role logs (Revert, BakerFi, Venus arms got no holders) and the kind of a Solana authority (MetaDAO arm
reported a Squads v4 vault as a "single System-owned keypair", a Medium false positive).

Recorded answers from the free pool on 2026-10-31 (tests/fixtures/chain/*.json):
  revert_arbitrum.json  V3Vault 0x74E6...7825 on Arbitrum; owner() = TimelockController 0x199b...f330
                        (min delay 172,800 s) whose PROPOSER, EXECUTOR and CANCELLER roles and
                        TIMELOCK_ADMIN_ROLE are held by the 2-of-3 Safe 0x3e45...8175 (constructor logs
                        of block 293,070,939; the judge read the same by hand with hasRole).
  bakerfi_base.json     BakerFi vault 0x3732...F60A on Base: no free host serves old logs, the recent
                        window is empty, and hasRole on the Sourcify deployer shows it still holds
                        DEFAULT_ADMIN_ROLE; the answer is marked partial.
  metadao_solana.json   program pbPPQH7... upgrade authority 6awy...sb4sf: Squads v4 vault index 0 of
                        multisig 8N3T...DWH (threshold 3, 13 members, 6 voters), found from the
                        ProgramData's newest transaction 38t9goj9... (VaultTransactionExecute).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from soken_review.chain import access_control as acm
from soken_review.chain import reads
from soken_review.chain import sol_authority as sa
from soken_review.chain.endpoints import Endpoint, Health, ordered
from soken_review.chain.proxy import ChainProxy
from soken_review.mapping.keccak import keccak256

from .replay import Replay

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "chain"
SAFE = "0x3e456ed2793988dc08f1482371b50ba2bc518175"
TIMELOCK = "0x199b7d994c9d3a26ff81e93bdb5dbc780363f330"
VAULT_SOL = "6awyHMshBGVjJ3ozdSJdyyDE1CTAXUwrpNMaRGMsb4sf"
MULTISIG = "8N3Tvc6B1wEVKVC6iD4s6eyaCNqX2ovj2xze2q3Q9DWH"


@pytest.fixture(autouse=True)
def _fresh_health():
    Health.reset()
    yield
    Health.reset()


def _evm_job(cid: int, name: str) -> reads.ChainJob:
    return reads.ChainJob("job_x", "evm", cid, name, None, None)


def _missing_ok(replay: Replay) -> None:
    """Only reads every free host refused when recorded may be absent (the code saw the same failure)."""
    assert all('"eth_getLogs"' in k or '"getTransaction"' in k or '"eth_getTransactionReceipt"' in k
               for k in replay.missing), replay.missing


# ── EVM: TimelockController behind a vault owner (Revert, Arbitrum) ────────


@pytest.mark.asyncio
async def test_revert_vault_owner_timelock_roles_from_logs():
    replay = Replay(FIX / "revert_arbitrum.json")
    meta = json.loads((FIX / "revert_arbitrum.meta.json").read_text())
    job = _evm_job(42161, "Arbitrum One")
    async with ChainProxy(transport=replay, pace=False) as px:
        at = await reads.evm_resolve(px, job, "latest")
        assert at.block == meta["block"]
        out = reads.Out(job=job, at=at)
        roles = await reads.evm_roles(px, out, "0x74E6AFeF5705BEb126C6d3Bf46f8fad8F3e07825", "vault", [])
    _missing_ok(replay)
    owner = next(h for h in roles["holders"] if h["getter"] == "owner")
    assert owner["holder"] == TIMELOCK and owner["kind"] == "contract" and owner["min_delay_s"] == 172800
    by_role = {r["role"]: r for r in owner["roles"]}
    for name in ("PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE"):
        assert by_role[name]["members"] == [SAFE], name
        assert by_role[name]["name_from"] == "keccak256 of a common role name"
        assert by_role[name]["admin_role"] == "TIMELOCK_ADMIN_ROLE"
        assert by_role[name]["member_details"][0]["kind"] == "safe"
        assert by_role[name]["member_details"][0]["safe_threshold"] == 2
        assert by_role[name]["member_details"][0]["safe_owners"] == 3
        assert not by_role[name].get("open")
    assert sorted(by_role["TIMELOCK_ADMIN_ROLE"]["members"]) == sorted([TIMELOCK, SAFE])
    ac = owner["access_control"]
    assert ac["standard"] == "AccessControl" and not ac["enumerable"]
    assert ac["complete"] is False and ac["partial"] is True       # 227M blocks since creation, 12 windows
    assert ac["creation_block"] == 293070939 and ac["min_delay_s"] == 172800
    assert ac["scanned"][0][0] == 293070939                        # the creation end was read
    assert "Partial" in ac["note"] and "confirmed by hasRole" in ac["note"]
    facts = {f["key"]: f for f in out.facts}
    assert facts["chain.vault.owner.role.proposer_role.0"]["value"] == SAFE
    assert facts["chain.vault.owner.role.executor_role.count"]["value"] == "1"
    assert facts["chain.vault.owner.access_control.complete"]["value"] == "false"
    assert facts["chain.vault.owner.access_control.min_delay"]["value"] == "172800"
    assert "chain.vault.owner.role.executor_role.open" not in facts
    for f in out.facts:
        assert f["block"] in (meta["block"], None) and f.get("class") != "chain_text"


# ── EVM: no old logs on the free pool, member found by hasRole (BakerFi, Base) ──


@pytest.mark.asyncio
async def test_bakerfi_vault_admin_found_by_hasrole_and_marked_partial():
    replay = Replay(FIX / "bakerfi_base.json")
    job = _evm_job(8453, "Base")
    async with ChainProxy(transport=replay, pace=False) as px:
        at = await reads.evm_resolve(px, job, "latest")
        out = reads.Out(job=job, at=at)
        roles = await reads.evm_roles(px, out, "0x37327c99bBc522e677a97d01021dB20227faF60A", "vault", [])
    _missing_ok(replay)
    deployer = roles["deployment"]["deployer"].lower()
    by_role = {r["role"]: r for r in roles["roles"]}
    assert by_role["DEFAULT_ADMIN_ROLE"]["members"] == [deployer]
    assert by_role["DEFAULT_ADMIN_ROLE"]["member_details"][0]["kind"] == "eoa"
    ac = roles["access_control"]
    assert ac["partial"] is True and ac["complete"] is False
    assert ac["not_scanned"] and ac["not_scanned"][0][0] == 16398790   # the old end: refused by every free host
    facts = {f["key"]: f["value"] for f in out.facts}
    assert facts["chain.vault.role.default_admin_role.0"] == deployer
    assert facts["chain.vault.access_control.complete"] == "false"


# ── EVM: full coverage, revoked member, open role (synthetic chain) ────────

def _word(n: int) -> str:
    return "0x" + f"{n:064x}"


def _topic_addr(a: str) -> str:
    return "0x" + a[2:].rjust(64, "0")


def _synthetic_chain(target: str, logs: list[dict[str, Any]], members: set[tuple[str, str]], head: int,
                     creation: int, enumerable: bool = False) -> httpx.MockTransport:
    from soken_review.chain import abi

    sel = {abi.selector(s).hex(): s for s in ("supportsInterface(bytes4)", "hasRole(bytes32,address)",
                                              "getRoleAdmin(bytes32)", "getRoleMemberCount(bytes32)")}

    def rpc(method: str, params: list[Any]) -> Any:
        if method == "eth_blockNumber":
            return hex(head)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000)}
        if method == "eth_getStorageAt":
            return _word(0)
        if method == "eth_getCode":
            addr, block = params[0].lower(), int(params[1], 16)
            return "0x6080" if addr == target and block >= creation else "0x"
        if method == "eth_getLogs":
            lo, hi = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
            return [lg for lg in logs if lo <= int(lg["blockNumber"], 16) <= hi]
        if method == "eth_call":
            to, data = params[0]["to"].lower(), params[0]["data"][2:]
            name = sel.get(data[:8])
            if to != target or name is None:
                return {"error": {"code": 3, "message": "execution reverted", "data": "0x"}}
            arg = data[8:]
            if name == "supportsInterface(bytes4)":
                return _word(1 if arg[:8] == "7965db0b" or (enumerable and arg[:8] == "5a05180f") else 0)
            if name == "hasRole(bytes32,address)":
                return _word(1 if ("0x" + arg[:64], "0x" + arg[64 + 24:128]) in members else 0)
            if name == "getRoleAdmin(bytes32)":
                return _word(0)
            return {"error": {"code": 3, "message": "execution reverted", "data": "0x"}}
        return {"error": {"code": -32601, "message": "not here"}}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "sourcify.dev":
            return httpx.Response(404, json={})
        body = json.loads(request.content)
        res = rpc(body["method"], body["params"])
        if isinstance(res, dict) and "error" in res:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], **res})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": res})

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_full_scan_is_complete_with_revoked_member_and_open_executor():
    target = "0x" + "ab" * 20
    alice, bob, zero = "0x" + "11" * 20, "0x" + "22" * 20, acm.ZERO
    executor = "0x" + keccak256(b"EXECUTOR_ROLE").hex()
    admin = "0x" + "00" * 32

    def log(block: int, idx: int, granted: bool, role: str, acct: str) -> dict[str, Any]:
        return {"address": target, "blockNumber": hex(block), "logIndex": hex(idx), "transactionHash": _word(block * 10 + idx),
                "topics": [acm.ROLE_GRANTED if granted else acm.ROLE_REVOKED, role, _topic_addr(acct), _topic_addr(alice)],
                "data": "0x", "removed": False}

    head, creation = 100_000, 60_000
    logs = [log(60_001, 0, True, admin, alice), log(60_001, 1, True, executor, bob), log(70_000, 0, True, executor, zero),
            log(90_000, 0, False, executor, bob)]
    members = {(admin, alice), (executor, zero)}
    eps = [Endpoint("https://rpc.example", keyed=False, depth="archive", logs_max_range=50_000)]
    async with ChainProxy(transport=_synthetic_chain(target, logs, members, head, creation),
                          endpoint_list=lambda f, c: eps, pace=False) as px:
        job = _evm_job(1, "Ethereum Mainnet")
        at = await reads.evm_resolve(px, job, "latest")
        out = reads.Out(job=job, at=at)
        roles = await reads.evm_roles(px, out, target, "acl", [])
    ac = roles["access_control"]
    assert ac["complete"] is True and "partial" not in ac
    assert ac["creation_block"] == creation          # no Sourcify record: binary search over eth_getCode
    by_role = {r["role"]: r for r in roles["roles"]}
    assert by_role["DEFAULT_ADMIN_ROLE"]["members"] == [alice] and by_role["DEFAULT_ADMIN_ROLE"]["complete"]
    ex = by_role["EXECUTOR_ROLE"]
    assert ex["members"] == [zero] and ex["open"] is True and ex["revoked"] == [bob]
    assert ex["member_details"][0]["kind"] == "zero_address"
    facts = {f["key"]: f["value"] for f in out.facts}
    assert facts["chain.acl.role.executor_role.open"] == "true"
    assert facts["chain.acl.access_control.complete"] == "true"


@pytest.mark.asyncio
async def test_not_access_control_returns_no_section():
    target = "0x" + "cd" * 20
    eps = [Endpoint("https://rpc.example", keyed=False, depth="archive", logs_max_range=50_000)]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "sourcify.dev":
            return httpx.Response(404, json={})
        body = json.loads(request.content)
        res: Any = {"eth_blockNumber": hex(1000), "eth_getBlockByNumber": {"timestamp": "0x1"},
                    "eth_getStorageAt": _word(0), "eth_getCode": "0x"}.get(body["method"])
        if res is None:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": res})

    async with ChainProxy(transport=httpx.MockTransport(handler), endpoint_list=lambda f, c: eps, pace=False) as px:
        job = _evm_job(1, "Ethereum Mainnet")
        out = reads.Out(job=job, at=await reads.evm_resolve(px, job, "latest"))
        roles = await reads.evm_roles(px, out, target, "plain", [])
    assert "access_control" not in roles and roles["roles"] == []


# ── access_control helpers ─────────────────────────────────────────────────


def test_scan_plan_whole_span_or_both_ends():
    p = acm.ScanPlan(1000, 1999, 500, 4)
    assert p.windows == [(1000, 1499), (1500, 1999)] and p.split == 0
    p = acm.ScanPlan(0, 1_000_000, 1000, 4)
    assert p.windows == [(0, 999), (1000, 1999), (999_001, 1_000_000), (998_001, 999_000)] and p.split == 2
    assert not acm.covered(p.windows, 0, 1_000_000)
    p = acm.ScanPlan(None, 2500, 1000, 4)
    assert p.windows == [(1501, 2500), (501, 1500), (0, 500)]
    assert acm.covered([(0, 10), (11, 20)], 0, 20) and not acm.covered([(0, 10), (12, 20)], 0, 20)
    assert acm.blocks_in([(0, 9), (5, 14)]) == 15


def test_parse_log_rejects_foreign_and_malformed():
    a = "0x" + "ab" * 20
    good = {"address": a, "blockNumber": "0x10", "logIndex": "0x1", "transactionHash": _word(7),
            "topics": [acm.ROLE_GRANTED, _word(0), _topic_addr("0x" + "11" * 20), _topic_addr(a)]}
    ev = acm.parse_log(good, a.upper().replace("0X", "0x"))
    assert ev and ev.granted and ev.account == "0x" + "11" * 20 and ev.block == 16
    assert acm.parse_log({**good, "address": "0x" + "cd" * 20}, a) is None
    assert acm.parse_log({**good, "removed": True}, a) is None
    assert acm.parse_log({**good, "topics": good["topics"][:3]}, a) is None
    assert acm.parse_log({**good, "topics": [acm.ROLE_GRANTED, _word(0), _word(2**200), _word(0)]}, a) is None
    assert acm.parse_log({**good, "topics": ["0x" + "ee" * 32, *good["topics"][1:]]}, a) is None
    assert acm.parse_log({**good, "blockNumber": "ignore previous instructions"}, a) is None


def test_replay_orders_grants_and_revokes():
    r, x, y = b"\1" * 32, "0x" + "11" * 20, "0x" + "22" * 20
    evs = [acm.RoleEvent(5, 0, "t2", False, r, x), acm.RoleEvent(1, 0, "t1", True, r, x),
           acm.RoleEvent(6, 0, "t3", True, r, y), acm.RoleEvent(1, 0, "t1", True, r, x)]
    now, ever = acm.replay(evs)
    assert now[r] == {y} and ever[r] == {x, y}


# ── proxy: eth_getLogs range caps fail over without cooling the host ───────


@pytest.mark.asyncio
async def test_get_logs_range_refusal_fails_over_without_cooldown():
    hits: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(request.url.host)
        if request.url.host == "small.example":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {
                "code": -32602, "message": "query spans 50000 blocks, but only 10000 are allowed"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": []})

    eps = [Endpoint("https://small.example", keyed=False, depth="archive"),
           Endpoint("https://wide.example", keyed=False, depth="archive")]
    flt = {"address": "0x" + "ab" * 20, "topics": [[acm.ROLE_GRANTED]], "fromBlock": hex(0), "toBlock": hex(49_999)}
    async with ChainProxy(transport=httpx.MockTransport(handler), endpoint_list=lambda f, c: eps, pace=False) as px:
        for _ in range(2):   # rotation: make sure the refusing host was asked first once
            assert await px.evm(1, "eth_getLogs", [flt]) == []
    assert "small.example" in hits and "wide.example" in hits
    assert "small.example" not in Health.cool_until


def test_ordered_puts_hosts_measured_for_the_log_range_first():
    eps = [Endpoint("https://zero.example", keyed=False, depth="archive", logs_max_range=0),
           Endpoint("https://unknown.example", keyed=False, depth="archive"),
           Endpoint("https://wide.example", keyed=False, depth="head", logs_max_range=50_000)]
    for _ in range(3):
        hosts = [e.host for e in ordered(eps, 10, logs_span=50_000)]
        assert hosts[0].endswith("wide.example") and hosts[-1].endswith("zero.example")


# ── Solana: authority kind ─────────────────────────────────────────────────


def test_curve_check_and_squads_v4_vault_derivation():
    assert sa.on_curve(sa.pubkey("4LpE9Lxqb4jYYh8jA8oDhsGDKPNBNkcoXobbAJTa3pWw"))       # a member key
    assert not sa.on_curve(sa.pubkey(VAULT_SOL))                                       # the vault PDA
    assert not sa.on_curve(sa.pubkey(MULTISIG))
    assert sa.squads_derive("v4", MULTISIG, 0) == VAULT_SOL
    assert sa.squads_derive("v4", MULTISIG, 1) != VAULT_SOL
    with pytest.raises(ValueError):
        sa.pubkey("0OIl")


def test_squads_v3_authority_from_a_synthetic_execute():
    ms = MULTISIG   # any 32-byte key works as the multisig seed
    auth = sa.squads_derive("v3", ms, 1)
    assert auth and not sa.on_curve(sa.pubkey(auth))
    tx = {"transaction": {"message": {"accountKeys": ["Fee1111111111111111111111111111111111111111", sa.SQUADS_V3, ms, auth],
                                      "instructions": [{"programIdIndex": 1, "accounts": [2, 3]}]}}, "meta": {}}
    assert sa.squads_candidates(tx, auth) == [("v3", ms)]
    data = bytes(8) + (2).to_bytes(2, "little") + (1).to_bytes(2, "little") + bytes(4 + 4 + 1 + 32 + 1) \
        + (3).to_bytes(4, "little") + bytes(32 * 3)
    assert sa.parse_squads_v3(data) == {"threshold": 2, "members": 3, "voters": 3, "time_lock_s": 0,
                                        "config_authority": None}
    assert sa.parse_squads_v3(data[:40]) is None


@pytest.mark.asyncio
async def test_metadao_upgrade_authority_is_a_squads_v4_vault_not_a_keypair():
    replay = Replay(FIX / "metadao_solana.json")
    job = reads.ChainJob("job_x", "solana", None, "Solana mainnet", None, "pbPPQH7jyKoSLu8QYs3rSY3YkDRXEBojKbTgnUg7NDS")
    async with ChainProxy(transport=replay, pace=False) as px:
        at = await reads.solana_resolve(px, job, "latest")
        out = reads.Out(job=job, at=at)
        roles = await reads.solana_roles(px, out, "pbPPQH7jyKoSLu8QYs3rSY3YkDRXEBojKbTgnUg7NDS", "pkg")
        out2 = reads.Out(job=job, at=at)
        await reads.solana_read(px, out2, [{"alias": "auth", "kind": "account", "address": VAULT_SOL},
                                           {"alias": "member", "kind": "account",
                                            "address": "4LpE9Lxqb4jYYh8jA8oDhsGDKPNBNkcoXobbAJTa3pWw"}])
    _missing_ok(replay)
    assert roles["upgrade_authority"] == VAULT_SOL
    kind = roles["upgrade_authority_kind"]
    assert kind["kind"] == "squads_v4_vault" and kind["on_curve"] is False and kind["private_key_possible"] is False
    ms = kind["multisig"]
    assert (ms["address"], ms["vault_index"], ms["threshold"], ms["members"], ms["voters"]) == (MULTISIG, 0, 3, 13, 6)
    assert ms["config_authority"] is None and ms["time_lock_s"] == 0
    assert ms["evidence_tx"].startswith("38t9goj9")
    assert kind["owner_program"] == sa.SYSTEM_PROGRAM
    facts = {f["key"]: f["value"] for f in out.facts}
    assert facts["chain.pkg.upgrade_authority.authority_kind"] == "squads_v4_vault"
    assert facts["chain.pkg.upgrade_authority.multisig_threshold"] == "3"
    assert facts["chain.pkg.upgrade_authority.multisig_config_authority"] == "none"
    # review_chain_read of the same address on its own: System-owned, no data, and still never a keypair
    rows = {r["alias"]: r for r in out2.items}
    assert rows["auth"]["authority_kind"]["kind"] in ("pda", "squads_v4_vault")
    assert rows["auth"]["value"]["authority_kind"] != "on_curve_key"
    assert rows["member"]["authority_kind"]["kind"] == "on_curve_key"
    assert "chain.auth.authority_kind" in rows["auth"]["fact_keys"]
    for r in (kind, rows["auth"]["authority_kind"], rows["member"]["authority_kind"]):
        assert "plain keypair" not in json.dumps(r).lower()


@pytest.mark.asyncio
async def test_unreadable_history_leaves_a_pda_and_never_a_keypair():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "getMultipleAccounts":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 5}, "value": [
                {"owner": sa.SYSTEM_PROGRAM, "lamports": 1, "data": ["", "base64"], "executable": False}]}})
        return httpx.Response(429, json={})

    eps = [Endpoint("https://sol.example", keyed=False, depth="head")]
    job = reads.ChainJob("job_x", "solana", None, "Solana mainnet", None, None)
    async with ChainProxy(transport=httpx.MockTransport(handler), endpoint_list=lambda f, c: eps, pace=False) as px:
        out = reads.Out(job=job, at=reads.At(block=5, head=5, block_time=None))
        info = await reads.solana_authority(px, out, "chain.x", VAULT_SOL, [])
    assert info["kind"] == "pda" and info["private_key_possible"] is False
    assert "could not be read" in info["note"]
