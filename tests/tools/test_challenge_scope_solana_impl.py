"""Solana scope for the `impl <Accounts> { validate, handle }` layout (MetaDAO blind run 2026-10-31).

`lib.rs` wraps every instruction as `pub fn complete_unlock(ctx) { CompleteUnlock::handle(ctx) }`
with `#[access_control(ctx.accounts.validate())]`, and the handler is a method of the Accounts
struct's impl taking `Context<Self>`. The entry_function scope of a finding located in the struct
was the struct alone (complete_unlock.rs:11-47), so quotes from the handler (65-191) came back
unverified; a location in the handler pulled every instruction's `handle` (bare call name).
"""

from __future__ import annotations

from typing import Any

from soken_review.mapping.build import build_map
from soken_review.mapping.step import family_categories
from soken_review.tools.challenge import _resolve_scope

CATS = list(family_categories("solana", "solana"))

LIB = """use anchor_lang::prelude::*;

pub mod instructions;
use instructions::*;

declare_id!("pbPPQH7jyKoSLu8QYs3rSY3YkDRXEBojKbTgnUg7NDS");

#[program]
pub mod pkg {
    use super::*;

    #[access_control(ctx.accounts.validate())]
    pub fn complete_unlock(ctx: Context<CompleteUnlock>) -> Result<()> {
        CompleteUnlock::handle(ctx)
    }

    #[access_control(ctx.accounts.validate())]
    pub fn start_unlock(ctx: Context<StartUnlock>) -> Result<()> {
        StartUnlock::handle(ctx)
    }
}
"""

COMPLETE = """use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CompleteUnlock<'info> {
    #[account(mut)]
    pub package: Account<'info, Package>,
    pub recipient: Signer<'info>,
}

impl CompleteUnlock<'_> {
    pub fn validate(&self) -> Result<()> {
        require!(self.package.started, ErrorCode::NotStarted);
        Ok(())
    }

    pub fn handle(ctx: Context<Self>) -> Result<()> {
        let pkg = &mut ctx.accounts.package;
        pkg.unlocked = pkg.unlocked + 1;
        Self::finish(pkg)
    }

    fn finish(pkg: &mut Package) -> Result<()> {
        pkg.done = true;
        Ok(())
    }
}
"""

START = """use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct StartUnlock<'info> {
    #[account(mut)]
    pub package: Account<'info, Package>,
}

impl StartUnlock<'_> {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }

    pub fn handle(ctx: Context<Self>) -> Result<()> {
        ctx.accounts.package.started = true;
        Ok(())
    }
}
"""

FILES = {"src/lib.rs": LIB, "src/instructions/complete_unlock.rs": COMPLETE,
         "src/instructions/start_unlock.rs": START, "src/instructions/mod.rs": "pub mod complete_unlock;\npub mod start_unlock;\n"}


def _line(text: str, needle: str) -> int:
    return next(i for i, line in enumerate(text.splitlines(), 1) if needle in line)


def _map() -> dict[str, Any]:
    doc = build_map(FILES, None, CATS, build_ok=False, parsed_family="solana").doc
    doc["_status"] = "partial"
    return doc


def _covers(ranges: list[str], path: str, line: int) -> bool:
    for r in ranges:
        p, span = r.rsplit(":", 1)
        s, e = (int(x) for x in span.split("-"))
        if p == path and s <= line <= e:
            return True
    return False


CU = "src/instructions/complete_unlock.rs"
SU = "src/instructions/start_unlock.rs"


def test_parsed_layer_resolves_the_qualified_handler_and_self_context():
    doc = _map()
    fns = {f["span"]: f for f in doc["semantic"]["functions"]}
    wrapper = next(f for sid, f in fns.items() if sid.endswith(".complete_unlock"))
    call = next(c for c in wrapper["calls"] if c["target"] == "handle")
    assert call["qualifier"] == "CompleteUnlock"
    assert wrapper["modifiers"] == ["validate"]          # not `ctx`, the first identifier


def test_location_in_the_struct_covers_handler_validate_and_wrapper():
    doc = _map()
    loc = [{"file": CU, "start": _line(COMPLETE, "pub recipient"), "end": _line(COMPLETE, "pub recipient")}]
    ranges, not_covered, source = _resolve_scope("entry_function", "solana", doc, loc)
    assert not not_covered and source == "semantic", ranges
    assert _covers(ranges, CU, _line(COMPLETE, "pkg.unlocked = pkg.unlocked + 1")), ranges   # the handler body
    assert _covers(ranges, CU, _line(COMPLETE, "require!(self.package.started")), ranges     # validate
    assert _covers(ranges, "src/lib.rs", _line(LIB, "CompleteUnlock::handle(ctx)")), ranges   # the wrapper
    assert not _covers(ranges, SU, _line(START, "ctx.accounts.package.started = true")), ranges


def test_location_in_the_handler_takes_its_struct_not_every_handle():
    doc = _map()
    ln = _line(COMPLETE, "pkg.unlocked = pkg.unlocked + 1")
    ranges, not_covered, _ = _resolve_scope("entry_function", "solana", doc, [{"file": CU, "start": ln, "end": ln}])
    assert not not_covered, ranges
    assert _covers(ranges, CU, _line(COMPLETE, "pub recipient")), ranges                 # the Accounts struct
    assert _covers(ranges, CU, _line(COMPLETE, "pkg.done = true")), ranges              # Self:: callee
    assert _covers(ranges, "src/lib.rs", _line(LIB, "CompleteUnlock::handle(ctx)")), ranges
    assert not _covers(ranges, SU, _line(START, "ctx.accounts.package.started = true")), ranges
