"""Parsed semantic layer for Solana programs (mapping/semantic_solana.py, build_map parsed_family)."""

from __future__ import annotations

from soken_review.mapping.build import build_map, validate_map
from soken_review.mapping.semantic_solana import build_semantic_solana
from soken_review.mapping.step import family_categories
from soken_review.tools import map_view

LIB = """use anchor_lang::prelude::*;

declare_id!("Fvm8Z25vd1Yauj6GB4jsrW7jJyUdNYGeDCWYqcuTtDek");

#[program]
pub mod vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        ctx.accounts.state.bump = bump;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        handle_withdraw(ctx, amount)
    }

    pub fn poke(ctx: Context<Poke>) -> Result<()> {
        ctx.accounts.state.counter += 1;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8 + 64, seeds = [b"state"], bump)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    /// CHECK: unchecked
    pub extra: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Poke<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    pub cranker: Signer<'info>,
}

#[account]
pub struct State {
    pub authority: Pubkey,
    pub counter: u64,
    pub bump: u8,
}
"""

HANDLER = """use anchor_lang::prelude::*;

pub fn handle_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require_keys_eq!(ctx.accounts.state.authority, ctx.accounts.authority.key());
    let left = ctx.accounts.state.counter - amount;
    anchor_spl::token::transfer(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), Transfer {}),
        amount,
    )?;
    ctx.accounts.state.counter = left;
    Ok(())
}
"""

NATIVE = """use solana_program::entrypoint;

entrypoint!(process_instruction);

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    helper(accounts)
}

fn helper(accounts: &[AccountInfo]) -> ProgramResult {
    invoke(&ix, accounts)?;
    Ok(())
}
"""

FILES = {"src/lib.rs": LIB, "src/instructions/withdraw.rs": HANDLER}
CATS = list(family_categories("solana", "solana"))


def _sem() -> dict:
    built = build_semantic_solana(FILES, CATS)
    assert built is not None
    return built[0]


def _fn(sem: dict, sid: str) -> dict:
    return next(f for f in sem["functions"] if f["span"] == sid)


def test_units_entries_and_program_id() -> None:
    sem = _sem()
    kinds = {u["name"]: u["kind"] for u in sem["units"]}
    assert kinds["vault"] == "program"
    assert kinds["State"] == "account"
    assert kinds["withdraw"] == "module"
    program = next(u for u in sem["units"] if u["kind"] == "program")
    assert program["address"] == "Fvm8Z25vd1Yauj6GB4jsrW7jJyUdNYGeDCWYqcuTtDek"
    entries = sorted(f["span"] for f in sem["functions"] if f["is_entry"])
    assert entries == ["vault.initialize", "vault.poke", "vault.withdraw"]
    assert not _fn(sem, "withdraw.handle_withdraw")["is_entry"]
    extras = sem["chain_extras"]["solana"]
    assert extras["layer"] == "parsed"
    assert {i["name"]: i["context"] for i in extras["instructions"]}["withdraw"] == "Withdraw"
    assert extras["contexts"]["Withdraw"]["accounts"][1] == {
        "name": "authority", "type": "Signer", "data": None, "line": 37, "signer": True, "mut": False, "flags": []}


def test_guards_from_context_and_callees() -> None:
    sem = _sem()
    withdraw = _fn(sem, "vault.withdraw")
    classes = sorted((g["class"], g.get("hint")) for g in withdraw["guards"])
    # has_one binding the Signer authority, and the require_keys_eq! in the handler it calls
    assert ("caller_check", "has_one authority") in classes
    assert ("caller_check", "require_keys_eq") in classes
    init = _fn(sem, "vault.initialize")
    assert [g["class"] for g in init["guards"]] == ["initializer_guard"]
    # a bare Signer (cranker) bound by nothing is not a caller check: poke is permissionless
    assert _fn(sem, "vault.poke")["guards"] == []


def test_calls_writes_state_vars_roles() -> None:
    sem = _sem()
    handler = _fn(sem, "withdraw.handle_withdraw")
    cpi = [c for c in handler["calls"] if c["kind"] == "cpi"]
    assert cpi == [{"kind": "cpi", "target": "token::transfer", "line": "src/instructions/withdraw.rs:6",
                    "value_bearing": True}]
    assert {"var": "counter", "line": "src/instructions/withdraw.rs:10"} in handler["writes"]
    assert {"kind": "internal", "target": "handle_withdraw", "line": "src/lib.rs:15"} in \
        _fn(sem, "vault.withdraw")["calls"]
    assert {v["name"] for v in sem["state_vars"]} == {"authority", "counter", "bump"}
    assert sem["roles"] == [{"name": "authority", "holder_kind": "unknown", "gated_functions": ["vault.withdraw"]}]
    assert sem["upgrade_surface"] == [{"unit": "src/lib.rs:vault", "mechanism": "bpf_loader_upgradeable",
                                       "authority_fact_key": "onchain.upgrade_authority"}]
    c2f = sem["category_to_functions"]
    assert c2f["solana.economic"] == ["vault.withdraw"]
    assert c2f["solana.missing_owner_check"] == ["vault.withdraw"]
    assert "vault.initialize" in c2f["solana.pda_seeds"]
    assert "vault.initialize" in c2f["solana.reinitialization"]
    assert c2f["solana.arithmetic"] == ["vault.withdraw"]


def test_native_entrypoint_macro() -> None:
    sem, _ = build_semantic_solana({"src/lib.rs": NATIVE}, CATS)
    entry = _fn(sem, "lib.process_instruction")
    assert entry["is_entry"]
    assert not _fn(sem, "lib.helper")["is_entry"]
    assert sem["category_to_functions"]["solana.arbitrary_cpi"] == ["lib.process_instruction"]


def test_no_rust_functions_gives_none() -> None:
    assert build_semantic_solana({"Cargo.toml": "[package]\nname = \"x\"\n"}, CATS) is None


def test_build_map_parsed_layer_is_partial_with_or_without_build() -> None:
    for build_ok in (False, True):
        art = build_map(FILES, None, CATS, build_ok=build_ok, parsed_family="solana")
        assert art.status == "partial"
        validate_map(art.doc)
        span_ids = {s["id"] for s in art.doc["spans"]}
        assert all(f["span"] in span_ids for f in art.doc["semantic"]["functions"])
        span = next(s for s in art.doc["spans"] if s["id"] == "vault.withdraw")
        assert span["unit"] == "src/lib.rs:vault" and span["file"] == "src/lib.rs"
    # without parsed_family (EVM path) a failed build stays lexical only
    assert "semantic" not in build_map(FILES, None, CATS, build_ok=False).doc


def test_contract_map_renders_program_entries() -> None:
    art = build_map(FILES, None, CATS, build_ok=False, parsed_family="solana")
    program = next(u for u in art.doc["semantic"]["units"] if u["kind"] == "program")
    text = "\n".join(map_view.render_unit(art.doc, program, [], True))
    assert "entries 3: initialize, poke, withdraw" in text
    assert "cpi token::transfer" in text
    assert "roles: authority holder unknown gates 1" in text
    assert "bpf_loader_upgradeable, authority {{fact:onchain.upgrade_authority}} (not read)" in text
