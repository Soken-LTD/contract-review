"""Tests for the SPL / Token-2022 mint reader (onchain.parse_mint, spl_mint) and the deterministic
token-safety leads (mint.mint_safety_leads).

A pump.fun / SPL token has no custom program to audit; its reviewable surface is the mint account's
authorities and Token-2022 extensions. These are read on-chain (analyzer evidence), so a real risk
is not held to the reasoning-only Low cap. The leads validate against lead.v1.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import jsonschema
import pytest

from soken_review.adapters.solana.mint import mint_safety_leads, mint_source
from soken_review.adapters.solana.onchain import (
    SPL_TOKEN_2022_PROGRAM,
    SPL_TOKEN_PROGRAM,
    SplMint,
    parse_mint,
)

_PUBKEY = bytes(range(32))


def _mint_bytes(mint_auth: bool, freeze_auth: bool, *, supply: int = 10**15, decimals: int = 6,
                initialized: bool = True) -> bytes:
    """Build an 82-byte SPL mint account."""
    buf = bytearray(82)
    struct.pack_into("<I", buf, 0, 1 if mint_auth else 0)
    if mint_auth:
        buf[4:36] = _PUBKEY
    struct.pack_into("<Q", buf, 36, supply)
    buf[44] = decimals
    buf[45] = 1 if initialized else 0
    struct.pack_into("<I", buf, 46, 1 if freeze_auth else 0)
    if freeze_auth:
        buf[50:82] = _PUBKEY
    return bytes(buf)


def _t22_mint_with_extensions(ext_type_ids: list[int]) -> bytes:
    """An 82-byte base, padded to 165, an account-type byte (1 = mint), then TLV extension entries."""
    base = _mint_bytes(mint_auth=False, freeze_auth=False)
    buf = bytearray(base) + bytearray(165 - len(base))
    buf.append(1)  # account type: mint
    for type_id in ext_type_ids:
        buf += struct.pack("<HH", type_id, 8) + bytes(8)
    return bytes(buf)


def test_parse_mint_revoked_authorities():
    m = parse_mint(_mint_bytes(mint_auth=False, freeze_auth=False), SPL_TOKEN_PROGRAM)
    assert m is not None
    assert m.mint_authority is None and m.freeze_authority is None
    assert m.decimals == 6 and m.is_initialized and m.supply == 10**15
    assert not m.is_token_2022 and m.extensions == []


def test_parse_mint_live_authorities():
    m = parse_mint(_mint_bytes(mint_auth=True, freeze_auth=True), SPL_TOKEN_PROGRAM)
    assert m is not None
    assert m.mint_authority is not None and m.freeze_authority is not None


def test_parse_mint_too_short_is_none():
    assert parse_mint(b"\x00" * 40, SPL_TOKEN_PROGRAM) is None


def test_parse_mint_token2022_extensions_named_and_unknown():
    # 12 = permanent_delegate (named, risky), 18 = metadata_pointer (named, benign), 999 = unknown.
    m = parse_mint(_t22_mint_with_extensions([12, 18, 999]), SPL_TOKEN_2022_PROGRAM)
    assert m is not None and m.is_token_2022
    by_id = {e["type_id"]: e for e in m.extensions}
    assert by_id[12]["name"] == "permanent_delegate"
    assert by_id[18]["name"] == "metadata_pointer"
    assert by_id[999]["name"] is None  # unknown ids are reported by number, never mislabeled


def _validate(leads):
    schema = json.loads((Path(__file__).resolve().parents[3]
                         / "contract" / "rubric" / "schemas" / "lead.v1.json").read_text())
    for lead in leads:
        jsonschema.validate(lead, schema)


def test_leads_clean_token_is_one_info_lead():
    m = SplMint(mint="So1111", program=SPL_TOKEN_PROGRAM, decimals=6, supply=1, is_initialized=True)
    leads = mint_safety_leads(m)
    _validate(leads)
    assert len(leads) == 1
    assert leads[0]["category"] == "solana.token_posture"
    assert leads[0]["severity_norm"] == "Info"


def test_leads_live_authorities_are_high():
    m = SplMint(mint="So1111", program=SPL_TOKEN_PROGRAM, decimals=6, supply=1, is_initialized=True,
                mint_authority="Owner", freeze_authority="Owner")
    leads = mint_safety_leads(m)
    _validate(leads)
    cats = {lead["category"]: lead["severity_norm"] for lead in leads}
    assert cats["solana.mint_authority"] == "High"
    assert cats["solana.freeze_authority"] == "High"


def test_leads_risky_extension_and_line_anchors():
    m = SplMint(mint="So1111", program=SPL_TOKEN_2022_PROGRAM, decimals=6, supply=1,
                is_initialized=True, is_token_2022=True,
                extensions=[{"type_id": 12, "name": "permanent_delegate", "length": 8},
                            {"type_id": 18, "name": "metadata_pointer", "length": 8}])
    leads = mint_safety_leads(m)
    _validate(leads)
    cats = {lead["category"]: lead for lead in leads}
    assert cats["solana.permanent_delegate"]["severity_norm"] == "High"
    assert "solana.metadata_pointer" not in cats  # benign metadata extension raises no lead
    # the permanent_delegate lead anchors to the line that names it in the rendered source
    _fn, text, index = mint_source(m)
    assert cats["solana.permanent_delegate"]["start"] == index["ext:permanent_delegate"]
    assert text.splitlines()[index["ext:permanent_delegate"] - 1].strip().startswith("- permanent_delegate")


@pytest.mark.parametrize("program", [SPL_TOKEN_PROGRAM, SPL_TOKEN_2022_PROGRAM])
def test_mint_source_is_line_stable(program):
    m = SplMint(mint="So1111", program=program, decimals=6, supply=42, is_initialized=True,
                is_token_2022=(program == SPL_TOKEN_2022_PROGRAM))
    fn, text, index = mint_source(m)
    assert fn == "mint_state.txt"
    lines = text.splitlines()
    assert lines[index["mint_authority"] - 1].startswith("mint_authority:")
    assert lines[index["freeze_authority"] - 1].startswith("freeze_authority:")


# ── parser-differential: a non-mint account of the same program must not read as a mint ──────

def test_parse_mint_rejects_classic_token_account_sized_blob():
    # A classic SPL token (holder) account is 165 bytes and owned by the SAME program as a mint.
    # Reading its 82-byte prefix as a mint would invent authorities, so parse_mint must reject it.
    blob = bytes(_mint_bytes(mint_auth=True, freeze_auth=True)) + bytes(165 - 82)
    assert parse_mint(blob, SPL_TOKEN_PROGRAM) is None


def test_parse_mint_rejects_classic_multisig_sized_blob():
    assert parse_mint(bytes(355), SPL_TOKEN_PROGRAM) is None


def test_parse_mint_accepts_exact_82_byte_classic_mint():
    assert parse_mint(_mint_bytes(mint_auth=False, freeze_auth=False), SPL_TOKEN_PROGRAM) is not None


def test_parse_mint_token2022_rejects_account_type_byte():
    # Same bytes as a valid t22 mint but account-type discriminator = 2 (Account), not 1 (Mint).
    buf = bytearray(_t22_mint_with_extensions([12]))
    buf[165] = 2
    assert parse_mint(bytes(buf), SPL_TOKEN_2022_PROGRAM) is None


def test_parse_mint_token2022_base_82_is_valid_mint():
    base = _mint_bytes(mint_auth=False, freeze_auth=False)
    m = parse_mint(base, SPL_TOKEN_2022_PROGRAM)
    assert m is not None and m.is_token_2022 and m.extensions == []


def test_t22_extension_length_overrun_is_marked_truncated():
    import struct as _struct
    base = _mint_bytes(mint_auth=False, freeze_auth=False)
    buf = bytearray(base) + bytearray(165 - len(base)) + bytearray([1])
    # permanent_delegate header with a length that runs past the buffer end.
    buf += _struct.pack("<HH", 12, 9999)
    m = parse_mint(bytes(buf), SPL_TOKEN_2022_PROGRAM)
    assert m is not None
    assert m.extensions[-1]["type_id"] == 12 and m.extensions[-1].get("truncated") is True


# ── fail-closed: a mint we could not read never reports a "safe posture" ─────────────────────

@pytest.mark.parametrize("why", ["read_failed:timeout", "absent", "not_a_mint"])
def test_mint_safety_leads_refuses_unread_mint(why):
    from soken_review.adapters.solana.onchain import SplMint as _SplMint
    with pytest.raises(ValueError, match="requires a parsed mint"):
        mint_safety_leads(_SplMint(mint="x", why=why))
