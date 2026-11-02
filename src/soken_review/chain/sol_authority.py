"""What controls a Solana authority address (blind round 5b, MetaDAO M-002 false positive).

A System-owned account with no data is what an ordinary keypair looks like, and also what a Squads
vault, a governance treasury or any other PDA looks like: System ownership says nothing about who
can sign. This module classifies an authority from chain data only:

- `squads_v4_vault` / `squads_v3_authority`: a Squads instruction in the signer history of the
  address (or of the account it controls, such as the ProgramData of a program) names a multisig
  account, and re-deriving the vault (v4 `[multisig, ms, vault, index]`) or authority (v3
  `[squad, ms, index u32, authority]`) PDA from it gives exactly this address. The multisig
  account is then read: threshold, members, voters, time lock, config authority.
- `pda`: the address is off the ed25519 curve, so no private key exists; it signs only through
  the program that derived it. The deriving program is not always visible.
- `on_curve_key`: the address is on the curve, so a private key can exist. Whether one person,
  an MPC setup or a hardware wallet holds it is not visible on chain; never "plain keypair".
- `unknown`: the reads failed.

Every value printed comes from account bytes or transaction account lists (addresses), never from
log text; nothing here is chain text.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

SYSTEM_PROGRAM = "11111111111111111111111111111111"
SQUADS_V4 = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
SQUADS_V3 = "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu"
SQUADS = {SQUADS_V4: "v4", SQUADS_V3: "v3"}
# How far the signer history is followed: signatures per address and transactions fetched in total.
SIG_LIMIT = 10
TX_LIMIT = 4
RETRY_S = 2.0
VAULT_INDICES = range(16)

_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        i = _ALPH.find(c)
        if i < 0:
            raise ValueError("not base58")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _ALPH[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def pubkey(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) != 32:
        raise ValueError("a public key is 32 bytes")
    return raw


def on_curve(pk: bytes) -> bool:
    """True when the 32 bytes decompress to an ed25519 point (as curve25519-dalek's
    CompressedEdwardsY::decompress, which Solana's is_on_curve uses): x^2 = (y^2 - 1) / (d y^2 + 1)
    must be a square mod p. A PDA is by construction off the curve."""
    y = (int.from_bytes(pk, "little") & ((1 << 255) - 1)) % _P
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    if u == 0:
        return True
    x2 = u * pow(v, _P - 2, _P) % _P
    return pow(x2, (_P - 1) // 2, _P) == 1


def find_program_address(seeds: list[bytes], program: bytes) -> bytes | None:
    for bump in range(255, -1, -1):
        h = hashlib.sha256(b"".join(seeds) + bytes([bump]) + program + b"ProgramDerivedAddress").digest()
        if not on_curve(h):
            return h
    return None


def squads_derive(version: str, multisig: str, index: int) -> str | None:
    ms = pubkey(multisig)
    if version == "v4":
        pda = find_program_address([b"multisig", ms, b"vault", bytes([index])], pubkey(SQUADS_V4))
    else:
        pda = find_program_address([b"squad", ms, index.to_bytes(4, "little"), b"authority"], pubkey(SQUADS_V3))
    return b58encode(pda) if pda else None


def parse_squads_v4(data: bytes) -> dict[str, Any] | None:
    """Squads v4 `Multisig`: disc 8, create_key 32, config_authority 32, threshold u16, time_lock u32,
    transaction_index u64, stale_transaction_index u64, rent_collector Option<Pubkey>, bump u8,
    members Vec<{key 32, permissions u8}> (Initiate 1, Vote 2, Execute 4)."""
    try:
        o = 8 + 32
        config_authority = b58encode(data[o:o + 32])
        o += 32
        threshold = int.from_bytes(data[o:o + 2], "little")
        time_lock = int.from_bytes(data[o + 2:o + 6], "little")
        o += 2 + 4 + 8 + 8
        o += 1 + (32 if data[o] == 1 else 0)
        o += 1
        n = int.from_bytes(data[o:o + 4], "little")
        o += 4
        if n > 65535 or len(data) < o + 33 * n:
            return None
        perms = [data[o + 33 * i + 32] for i in range(n)]
    except IndexError:
        return None
    return {"threshold": threshold, "members": n, "voters": sum(1 for p in perms if p & 2),
            "time_lock_s": time_lock,
            "config_authority": None if config_authority == SYSTEM_PROGRAM else config_authority}


def parse_squads_v3(data: bytes) -> dict[str, Any] | None:
    """Squads v3 `Ms`: disc 8, threshold u16, authority_index u16, transaction_index u32,
    ms_change_index u32, bump u8, create_key 32, allow_external_execute bool, keys Vec<Pubkey>."""
    try:
        threshold = int.from_bytes(data[8:10], "little")
        o = 8 + 2 + 2 + 4 + 4 + 1 + 32 + 1
        n = int.from_bytes(data[o:o + 4], "little")
        if n > 65535 or len(data) < o + 4 + 32 * n:
            return None
    except IndexError:
        return None
    return {"threshold": threshold, "members": n, "voters": n, "time_lock_s": 0, "config_authority": None}


def tx_accounts(tx: dict[str, Any]) -> list[str]:
    msg = ((tx.get("transaction") or {}).get("message") or {})
    keys = [k if isinstance(k, str) else str((k or {}).get("pubkey") or "") for k in (msg.get("accountKeys") or [])]
    loaded = ((tx.get("meta") or {}).get("loadedAddresses") or {})
    return keys + list(loaded.get("writable") or []) + list(loaded.get("readonly") or [])


def squads_candidates(tx: dict[str, Any], address: str) -> list[tuple[str, str]]:
    """(version, multisig candidate) for each Squads instruction of `tx`, top level or inner, whose
    accounts include `address`; the multisig is among the first accounts of every Squads execute."""
    keys = tx_accounts(tx)
    ixs = list(((tx.get("transaction") or {}).get("message") or {}).get("instructions") or [])
    for inner in ((tx.get("meta") or {}).get("innerInstructions") or []):
        ixs.extend(inner.get("instructions") or [])
    out: list[tuple[str, str]] = []
    for ix in ixs:
        try:
            prog = keys[int(ix["programIdIndex"])]
            accs = [keys[int(a)] for a in ix.get("accounts") or []]
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        if prog in SQUADS and address in accs:
            for a in accs[:3]:
                if (SQUADS[prog], a) not in out and a != address:
                    out.append((SQUADS[prog], a))
    return out


def account_data(acc: dict[str, Any] | None) -> bytes:
    if not acc:
        return b""
    try:
        return base64.b64decode((acc.get("data") or [""])[0] or "")
    except (ValueError, TypeError):
        return b""
