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


# ---------------------------------------------------------------------------
# SPL token mint reads (token-safety for a deployed address that is a mint, not a program)
# ---------------------------------------------------------------------------
# A pump.fun / SPL token has no custom program to audit: it is an account owned by the SPL Token
# (or Token-2022) program. The reviewable surface is the mint account's authorities and, for
# Token-2022, its extensions. These are on-chain facts read here in the supervisor, never a
# registry value, so a finding built from them carries analyzer evidence (not reasoning only).

SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SPL_TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
_MINT_BASE_LEN = 82
# A Token-2022 mint is padded to the token-account size (165) then carries one account-type byte
# (1 = mint) and, from byte 166, TLV extension entries (u16 type, u16 length, then `length` bytes).
_T22_ACCOUNT_TYPE_OFFSET = 165
# spl-token account-type discriminator at _T22_ACCOUNT_TYPE_OFFSET (Uninitialized=0, Mint=1, Account=2).
_ACCOUNT_TYPE_MINT = 1

# Token-2022 ExtensionType ids (u16). Only ids that bear on holder / fund safety are named here;
# any other id is still reported by number so an unknown extension is never silently dropped.
# Ids verified against spl-token-2022 ExtensionType; naming an id wrongly would mislead a finding,
# so this map stays conservative and unverified ids fall through to name=None.
_T22_EXTENSION_NAMES: dict[int, str] = {
    1: "transfer_fee_config",
    3: "mint_close_authority",
    4: "confidential_transfer_mint",
    6: "default_account_state",
    9: "non_transferable",
    10: "interest_bearing_config",
    12: "permanent_delegate",
    14: "transfer_hook",
    18: "metadata_pointer",
    19: "token_metadata",
}


@dataclass
class SplMint:
    mint: str
    program: str = ""                 # owning token program (SPL_TOKEN_PROGRAM / SPL_TOKEN_2022_PROGRAM)
    is_token_2022: bool = False
    slot: int | None = None
    decimals: int | None = None
    supply: int | None = None
    is_initialized: bool = False
    mint_authority: str | None = None     # None: minting is permanently disabled (safe)
    freeze_authority: str | None = None   # None: no account can be frozen (safe)
    extensions: list[dict[str, Any]] = field(default_factory=list)  # [{type_id, name, length}]
    why: str | None = None                # None: a valid mint. else read_failed / absent / not_a_mint


def _coption_pubkey(data: bytes, tag_off: int) -> str | None:
    """COption<Pubkey>: a 4-byte LE discriminant (0 = None, 1 = Some) then a 32-byte pubkey."""
    if struct.unpack_from("<I", data, tag_off)[0] == 0:
        return None
    return b58encode(data[tag_off + 4:tag_off + 36])


def _parse_t22_extensions(data: bytes) -> list[dict[str, Any]]:
    """Walk the Token-2022 TLV extension region. Each entry is u16 type, u16 length, then data."""
    pos = _T22_ACCOUNT_TYPE_OFFSET + 1   # skip the one account-type byte
    out: list[dict[str, Any]] = []
    while pos + 4 <= len(data):
        type_id, length = struct.unpack_from("<HH", data, pos)
        pos += 4
        if type_id == 0:                 # Uninitialized: trailing padding, end of the TLV region
            break
        # Record the entry first so a risky extension is never dropped, then detect a declared
        # length that overruns the buffer: that is a truncated/malformed region, so mark it and
        # stop rather than silently presenting the list as a complete (and apparently clean) walk.
        truncated = pos + length > len(data)
        out.append({"type_id": type_id, "name": _T22_EXTENSION_NAMES.get(type_id),
                    "length": length, **({"truncated": True} if truncated else {})})
        if truncated:
            break
        pos += length
    return out


def _is_mint_account(data: bytes, is_t22: bool) -> bool:
    """Confirm `data` is a Mint account, not a token (holder) account or multisig of the same
    program. A classic SPL mint is exactly 82 bytes (Account=165, Multisig=355). A Token-2022
    mint is either exactly 82 bytes (no extensions) or padded past 165 with the account-type
    discriminator byte == Mint. Without this, a holder account (same owner program) would be
    misread as a mint and yield bogus authorities."""
    if not is_t22:
        return len(data) == _MINT_BASE_LEN
    if len(data) == _MINT_BASE_LEN:
        return True
    if len(data) <= _T22_ACCOUNT_TYPE_OFFSET:
        return False
    return data[_T22_ACCOUNT_TYPE_OFFSET] == _ACCOUNT_TYPE_MINT


def parse_mint(data: bytes, program: str) -> SplMint | None:
    """Parse an SPL Token / Token-2022 mint account. None when the bytes are not a Mint account
    (too short, or a token/holder account or multisig of the same program).

    Base layout: COption<Pubkey> mint_authority (36), u64 supply (8), u8 decimals, bool is_initialized,
    COption<Pubkey> freeze_authority (36) = 82 bytes.
    """
    if len(data) < _MINT_BASE_LEN:
        return None
    is_t22 = program == SPL_TOKEN_2022_PROGRAM
    if not _is_mint_account(data, is_t22):
        return None
    return SplMint(
        mint="",
        program=program,
        is_token_2022=is_t22,
        decimals=data[44],
        supply=struct.unpack_from("<Q", data, 36)[0],
        is_initialized=data[45] != 0,
        mint_authority=_coption_pubkey(data, 0),
        freeze_authority=_coption_pubkey(data, 46),
        extensions=_parse_t22_extensions(data) if is_t22 and len(data) > _T22_ACCOUNT_TYPE_OFFSET else [],
    )


def spl_mint(mint_address: str) -> SplMint:
    """Read a deployed address as an SPL mint. `why` is None only for a real, initialized mint;
    for a program-owned account it returns program=<loader> so the caller can route to the source
    flow, and absent / not_a_mint / read_failed otherwise (a read failure never looks like a safe
    mint)."""
    try:
        slot, acc = _account(mint_address)
    except Exception as exc:  # noqa: BLE001 - read failures are reported, never a safe default
        return SplMint(mint_address, why=f"read_failed:{str(exc)[:120]}")
    if acc is None:
        return SplMint(mint_address, slot=slot, why="absent")
    owner = acc.get("owner") or ""
    if owner not in (SPL_TOKEN_PROGRAM, SPL_TOKEN_2022_PROGRAM):
        return SplMint(mint_address, program=owner, slot=slot, why="not_a_mint")
    parsed = parse_mint(base64.b64decode(acc["data"][0]), owner)
    if parsed is None or not parsed.is_initialized:
        return SplMint(mint_address, program=owner, slot=slot,
                       is_token_2022=(owner == SPL_TOKEN_2022_PROGRAM), why="not_a_mint")
    parsed.mint = mint_address
    parsed.slot = slot
    return parsed
