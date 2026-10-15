"""Supervisor-side Solana chain reads for provenance (06 2.4, 3.2; F5, F30).

deployed_program(program_id) -> DeployedProgram
owner_linked_verify_pdas(program_id, signer) -> list[VerifyPda]

Everything here runs in the supervisor, never in a container: the deployed program hash and the
upgrade authority come from our own RPC read at a recorded slot, not from a registry (F3) or a
container file (09 3.5). Read-only public JSON-RPC; no keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import urllib.request
from dataclasses import dataclass, field
from typing import Any

_RPC_URL = os.environ.get("SOKEN_SOLANA_RPC", "https://api.mainnet-beta.solana.com")
_RPC_TIMEOUT = 60

BPF_LOADER_UPGRADEABLE = "BPFLoaderUpgradeab1e11111111111111111111111"
BPF_LOADER_V2 = "BPFLoader2111111111111111111111111111111111"
BPF_LOADER_V1 = "BPFLoader1111111111111111111111111111111111"
VERIFY_PROGRAM = "verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC"   # OtterSec verify PDAs (F30)
PROGRAMDATA_HEADER = 45                                        # loader v3 ProgramData metadata (F5)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def program_hash(program_bytes: bytes) -> str:
    """F5: SHA-256 of the program bytes with trailing zeros stripped (same as build._so_hash)."""
    return hashlib.sha256(program_bytes.rstrip(b"\x00")).hexdigest()


@dataclass
class DeployedProgram:
    program_id: str
    loader: str | None
    slot: int | None
    hash: str | None = None                 # F5 over the executable bytes; None when not hashable
    upgrade_authority: str | None = None    # None: immutable or not loader v3
    why: str | None = None                  # loader_unsupported / no_code / read_failed


@dataclass
class VerifyPda:
    address: str
    signer: str
    version: str
    git_url: str
    commit: str
    args: list[str] = field(default_factory=list)
    deployed_slot: int | None = None


def _rpc(method: str, params: list[Any]) -> dict[str, Any]:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(_RPC_URL, data=body, headers={"Content-Type": "application/json",
                                                               "User-Agent": "soken-review/1"})
    with urllib.request.urlopen(req, timeout=_RPC_TIMEOUT) as resp:
        out = json.loads(resp.read().decode())
    if "error" in out:
        raise RuntimeError(f"rpc {method}: {out['error']}")
    return out["result"]


def _account(address: str) -> tuple[int | None, dict[str, Any] | None]:
    res = _rpc("getAccountInfo", [address, {"encoding": "base64", "commitment": "finalized"}])
    return (res.get("context") or {}).get("slot"), res.get("value")


def parse_programdata(data: bytes) -> tuple[str | None, bytes] | None:
    """Loader v3 ProgramData: u32 tag 3, u64 slot, Option<Pubkey> authority, then the ELF."""
    if len(data) < PROGRAMDATA_HEADER or struct.unpack_from("<I", data, 0)[0] != 3:
        return None
    authority = b58encode(data[13:45]) if data[12] == 1 else None
    return authority, data[PROGRAMDATA_HEADER:]


def deployed_program(program_id: str) -> DeployedProgram:
    """Read the program account (and ProgramData for loader v3) at a finalized slot."""
    try:
        slot, acc = _account(program_id)
    except Exception as exc:  # noqa: BLE001 - read failures never lower a tier, they are reported
        return DeployedProgram(program_id, None, None, why=f"read_failed:{str(exc)[:120]}")
    if acc is None:
        return DeployedProgram(program_id, None, slot, why="no_code")
    loader = acc.get("owner")
    raw = base64.b64decode(acc["data"][0])
    if loader in (BPF_LOADER_V1, BPF_LOADER_V2):
        return DeployedProgram(program_id, loader, slot, hash=program_hash(raw))
    if loader != BPF_LOADER_UPGRADEABLE:
        return DeployedProgram(program_id, loader, slot, why="loader_unsupported")
    if len(raw) < 36 or struct.unpack_from("<I", raw, 0)[0] != 2:
        return DeployedProgram(program_id, loader, slot, why="no_code")
    pd_address = b58encode(raw[4:36])
    try:
        pd_slot, pd = _account(pd_address)
    except Exception as exc:  # noqa: BLE001
        return DeployedProgram(program_id, loader, slot, why=f"read_failed:{str(exc)[:120]}")
    parsed = parse_programdata(base64.b64decode(pd["data"][0])) if pd else None
    if parsed is None:
        return DeployedProgram(program_id, loader, pd_slot, why="no_code")
    authority, elf = parsed
    return DeployedProgram(program_id, loader, pd_slot, hash=program_hash(elf), upgrade_authority=authority)


def parse_verify_pda(address: str, data: bytes) -> VerifyPda | None:
    """Borsh {discriminator[8], address, signer, version, git_url, commit, args, deployed_slot, bump} (F30)."""
    pos = 8

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise ValueError("short")
        chunk = data[pos:pos + n]
        pos += n
        return chunk

    def string() -> str:
        return take(struct.unpack("<I", take(4))[0]).decode()

    try:
        take(32)  # program address, already filtered on
        signer = b58encode(take(32))
        version, git_url, commit = string(), string(), string()
        args = [string() for _ in range(struct.unpack("<I", take(4))[0])]
        deployed_slot = struct.unpack("<Q", take(8))[0]
    except (ValueError, UnicodeDecodeError, struct.error):
        return None
    return VerifyPda(address, signer, version, git_url, commit, args, deployed_slot)


def owner_linked_verify_pdas(program_id: str, signer: str) -> list[VerifyPda]:
    """Verify PDAs for program_id written by `signer` (the upgrade authority): the only source
    candidates a tier-A decision may use (06 2.4 owner-linked)."""
    filters = [{"memcmp": {"offset": 8, "bytes": program_id}}, {"memcmp": {"offset": 40, "bytes": signer}}]
    res = _rpc("getProgramAccounts", [VERIFY_PROGRAM, {"encoding": "base64", "filters": filters}])
    out = []
    for row in res:
        pda = parse_verify_pda(row["pubkey"], base64.b64decode(row["account"]["data"][0]))
        if pda is not None and pda.signer == signer:
            out.append(pda)
    return out
