"""Token-safety review of a deployed SPL mint that is not a custom program (06 token path).

A pump.fun / SPL token has no program source to audit: it is an account owned by the SPL Token or
Token-2022 program. Its reviewable surface is the mint account's authorities and, for Token-2022,
its extensions, read on-chain by the supervisor (onchain.spl_mint). This module renders that state
as a line-stable, readable source file so the normal review pipeline (map -> read_code -> findings
-> report) can cite exact lines, and emits deterministic leads that point at each risk. Because the
facts come from our own RPC read, a lead built here carries analyzer evidence, not reasoning only,
so a real risk (for example a live mint authority) is not held to the reasoning-only Low cap.
"""

from __future__ import annotations

from soken_review.adapters.base import Lead
from soken_review.adapters.solana.onchain import SPL_TOKEN_2022_PROGRAM, SplMint

MINT_SOURCE_FILE = "mint_state.txt"
_TOOL = "soken-spl-mint@1"

# Token-2022 extensions that bear on holder or fund safety, with the severity hint a reviewer
# starts from and a one-line reason. Extensions that only carry metadata (metadata_pointer,
# token_metadata) are recorded in the source file but raise no lead. severity_norm is only a hint:
# finalize recomputes the final severity from the matrix, and under the retail-token profile a live
# control over holder funds elevates accordingly.
_RISKY_EXTENSIONS: dict[str, tuple[str, str]] = {
    "permanent_delegate": ("High", "a fixed delegate can transfer or burn any holder balance"),
    "transfer_hook": ("Medium", "every transfer calls an owner-controlled program"),
    "transfer_fee_config": ("Medium", "a transfer fee applies and can be raised up to its maximum"),
    "mint_close_authority": ("Low", "the mint account can be closed by its authority"),
    "default_account_state": ("Medium", "new token accounts may default to frozen"),
    "non_transferable": ("Medium", "holders cannot transfer the token (soulbound)"),
    "interest_bearing_config": ("Low", "the displayed balance accrues an owner-set rate"),
    "confidential_transfer_mint": ("Low", "balances and transfers can be confidential"),
}


def mint_source(m: SplMint) -> tuple[str, str, dict[str, int]]:
    """Render the mint account as a readable source file.

    Returns (filename, text, line_index) where line_index maps a risk key to the 1-based line that
    describes it, so leads can anchor to an exact, stable line.
    """
    program = "SPL Token-2022" if m.program == SPL_TOKEN_2022_PROGRAM else "SPL Token"
    lines: list[str] = []
    index: dict[str, int] = {}

    def add(text: str, key: str | None = None) -> None:
        lines.append(text)
        if key is not None:
            index[key] = len(lines)  # 1-based

    add("SPL token mint safety review")
    add(f"mint: {m.mint}")
    add(f"program: {program}")
    add(f"decimals: {m.decimals}")
    add(f"supply_raw: {m.supply}")
    mint_auth = m.mint_authority or "none (minting permanently disabled)"
    add(f"mint_authority: {mint_auth}", "mint_authority")
    freeze_auth = m.freeze_authority or "none (no account can be frozen)"
    add(f"freeze_authority: {freeze_auth}", "freeze_authority")
    if m.is_token_2022:
        add("extensions:")
        for ext in m.extensions:
            name = ext.get("name") or f"unknown_type_{ext.get('type_id')}"
            add(f"  - {name} (type {ext.get('type_id')})", f"ext:{name}")
        if not m.extensions:
            add("  - none")
    text = "\n".join(lines) + "\n"
    return MINT_SOURCE_FILE, text, index


def _lead(idx: int, line: int, category: str, sev: str, rule: str) -> Lead:
    lead: Lead = {
        "id": f"LEAD-{idx:04d}",
        "rule_id": rule,
        "tools": [_TOOL],
        "category": category,
        "analyzer_severity_raw": sev.lower(),
        "severity_norm": sev,
        "file": MINT_SOURCE_FILE,
        "start": line,
        "end": line,
        "state": "open",
        "origin": "analyzer",
    }
    return lead


def mint_safety_leads(m: SplMint) -> list[Lead]:
    """Deterministic lead.v1 documents for a mint's token-safety surface.

    Risks (live authorities, risky Token-2022 extensions) each become a lead. A mint with no
    privileged authority and no risky extension still gets one informational lead recording the
    safe posture, so a clean token is never a zero-lead (apparently empty) review.
    """
    _filename, _text, index = mint_source(m)
    leads: list[Lead] = []
    n = 1

    if m.mint_authority:
        leads.append(_lead(n, index["mint_authority"], "solana.mint_authority", "High",
                           "mint_authority_not_revoked"))
        n += 1
    if m.freeze_authority:
        leads.append(_lead(n, index["freeze_authority"], "solana.freeze_authority", "High",
                           "freeze_authority_set"))
        n += 1

    for ext in m.extensions:
        name = ext.get("name")
        if name in _RISKY_EXTENSIONS:
            sev, _reason = _RISKY_EXTENSIONS[name]
            leads.append(_lead(n, index.get(f"ext:{name}", 1), f"solana.{name}", sev,
                               f"token2022_{name}"))
            n += 1

    if not leads:
        # Clean token: record the safe posture as one informational observation.
        leads.append(_lead(n, index["mint_authority"], "solana.token_posture", "Info",
                           "no_privileged_authorities"))
    return leads
