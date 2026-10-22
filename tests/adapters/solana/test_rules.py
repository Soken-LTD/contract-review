"""Tests for soken-solana-rules matcher."""

from soken_review.adapters.solana.rules.matcher import run_rules, version


class TestVersion:
    def test_version_string(self):
        v = version()
        assert v and isinstance(v, str)
        assert "." in v  # semantic version


class TestAnchorRules:
    def test_init_if_needed_detected(self):
        files = {
            "src/lib.rs": """
#[program]
pub mod counter {
    use super::*;
    #[derive(Accounts)]
    pub struct Init<'info> {
        #[account(init_if_needed, payer = user, space = 8 + 64)]
        pub account: Account<'info, Counter>,
        pub user: Signer<'info>,
        pub system_program: Program<'info, System>,
    }
}
""",
        }
        findings = run_rules(files, "anchor")
        rule_ids = [f["rule_id"] for f in findings]
        assert any("SOL-INIT-01" in r for r in rule_ids), f"Expected SOL-INIT-01 in {rule_ids}"

    def test_unchecked_account_in_context(self):
        files = {
            "src/lib.rs": """
#[derive(Accounts)]
pub struct Transfer<'info> {
    /// CHECK: user provides this
    pub token_account: UncheckedAccount<'info>,
    pub authority: AccountInfo<'info>,
}
""",
        }
        findings = run_rules(files, "anchor")
        # Should flag as missing signer check
        rule_ids = [f["rule_id"] for f in findings]
        assert any("SOL-ACC" in r for r in rule_ids)

    def test_arithmetic_overflow_off(self):
        files = {
            "src/lib.rs": "pub fn transfer(amount: u64) -> u64 { amount + 1 }",
        }
        findings = run_rules(files, "anchor", overflow_checks="off")
        rule_ids = [f["rule_id"] for f in findings]
        assert any("SOL-ARITH" in r for r in rule_ids)

    def test_arithmetic_overflow_on_no_finding(self):
        files = {
            "src/lib.rs": "pub fn transfer(amount: u64) -> u64 { amount + 1 }",
        }
        findings = run_rules(files, "anchor", overflow_checks="on")
        rule_ids = [f["rule_id"] for f in findings]
        assert not any("SOL-ARITH" in r for r in rule_ids)

    def test_introspection_absolute_index(self):
        files = {
            "src/lib.rs": "let ix = load_instruction_at(0, &ix_sysvar)?;",
        }
        findings = run_rules(files, "anchor")
        rule_ids = [f["rule_id"] for f in findings]
        assert any("SOL-INTRO" in r for r in rule_ids)


class TestNativeRules:
    def test_arbitrary_cpi_flagged(self):
        files = {
            "src/lib.rs": """
pub fn process(accounts: &[AccountInfo]) -> ProgramResult {
    invoke(&some_instruction, accounts)?;
    Ok(())
}
""",
        }
        findings = run_rules(files, "native")
        rule_ids = [f["rule_id"] for f in findings]
        assert any("SOL-CPI" in r for r in rule_ids)

    def test_reinitialization_flagged(self):
        files = {
            "src/lib.rs": """
let data = account.try_borrow_mut_data()?;
account_data.copy_from_slice(&new_data);
""",
        }
        findings = run_rules(files, "native")
        rule_ids = [f["rule_id"] for f in findings]
        assert any("SOL-INIT" in r for r in rule_ids)

    def test_clean_code_no_false_positives(self):
        files = {
            "src/lib.rs": """
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey,
};
pub fn process(_program_id: &Pubkey, _accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    Ok(())
}
""",
        }
        findings = run_rules(files, "native")
        # Clean minimal program should produce few or no findings
        high_findings = [f for f in findings if f.get("severity_raw") == "error"]
        assert len(high_findings) == 0, f"Unexpected high findings in clean code: {high_findings}"


def _rule_ids(findings):
    return [f["rule_id"] for f in findings]


class TestAccountConfusion:
    """SOL-ACC-02 (missing owner check) / SOL-ACC-03 (type confusion)."""

    def test_manual_deserialize_without_owner_or_discriminator(self):
        files = {
            "src/lib.rs": """
pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
    let data = ctx.accounts.config.try_borrow_data()?;
    let config = ConfigState::try_from_slice(&data)?;
    msg!("admin {}", config.admin);
    Ok(())
}
""",
        }
        rules = _rule_ids(run_rules(files, "anchor"))
        assert any("SOL-ACC-02" in r for r in rules), rules
        assert any("SOL-ACC-03" in r for r in rules), rules

    def test_owner_and_discriminator_checked_clean(self):
        files = {
            "src/lib.rs": """
pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
    let acc = &ctx.accounts.config;
    require_keys_eq!(*acc.owner, crate::ID);
    let data = acc.try_borrow_data()?;
    require!(&data[0..8] == ConfigState::DISCRIMINATOR, ErrorCode::Bad);
    let config = ConfigState::try_from_slice(&data[8..])?;
    msg!("admin {}", config.admin);
    Ok(())
}
""",
        }
        rules = _rule_ids(run_rules(files, "anchor"))
        assert not any("SOL-ACC-02" in r for r in rules), rules
        assert not any("SOL-ACC-03" in r for r in rules), rules

    def test_instruction_data_decode_not_flagged(self):
        # Plain instruction-data decoding (no account/borrow context) must not fire.
        files = {
            "src/lib.rs": "let args = MyArgs::try_from_slice(instruction_input)?;",
        }
        rules = _rule_ids(run_rules(files, "native"))
        assert not any("SOL-ACC-02" in r for r in rules), rules
        assert not any("SOL-ACC-03" in r for r in rules), rules


class TestNonCanonicalPda:
    """SOL-PDA-01 non-canonical bump."""

    def test_create_program_address_flagged(self):
        files = {
            "src/lib.rs": """
let vault = Pubkey::create_program_address(&[b"vault", &[bump]], program_id)?;
""",
        }
        rules = _rule_ids(run_rules(files, "native"))
        assert any("SOL-PDA-01" in r for r in rules), rules

    def test_find_program_address_clean(self):
        files = {
            "src/lib.rs": """
let (vault, bump) = Pubkey::find_program_address(&[b"vault"], program_id);
""",
        }
        rules = _rule_ids(run_rules(files, "native"))
        assert not any("SOL-PDA-01" in r for r in rules), rules


class TestInvokeSignedCpi:
    """SOL-CPI-01 arbitrary CPI via invoke_signed."""

    def test_invoke_signed_unchecked_program_flagged(self):
        files = {
            "src/lib.rs": """
pub fn forward(accounts: &[AccountInfo], seeds: &[&[u8]]) -> ProgramResult {
    invoke_signed(&ix, accounts, &[seeds])?;
    Ok(())
}
""",
        }
        rules = _rule_ids(run_rules(files, "native"))
        assert any("SOL-CPI-01" in r for r in rules), rules

    def test_invoke_signed_checked_program_clean(self):
        files = {
            "src/lib.rs": """
pub fn forward(accounts: &[AccountInfo], seeds: &[&[u8]]) -> ProgramResult {
    require!(token_program.key() == spl_token::id(), Err);
    invoke_signed(&ix, accounts, &[seeds])?;
    Ok(())
}
""",
        }
        rules = _rule_ids(run_rules(files, "native"))
        assert not any("SOL-CPI-01" in r for r in rules), rules


class TestCloseRevival:
    """SOL-CLOSE-01 manual close without zeroing data."""

    def test_lamports_drained_without_zeroing_flagged(self):
        files = {
            "src/lib.rs": """
pub fn close(ctx: Context<Close>) -> Result<()> {
    let target = &ctx.accounts.target;
    let dest = &ctx.accounts.dest;
    **dest.lamports.borrow_mut() = dest.lamports().checked_add(target.lamports()).unwrap();
    **target.lamports.borrow_mut() = 0;
    Ok(())
}
""",
        }
        rules = _rule_ids(run_rules(files, "anchor"))
        assert any("SOL-CLOSE-01" in r for r in rules), rules

    def test_close_with_data_zeroed_clean(self):
        files = {
            "src/lib.rs": """
pub fn close(ctx: Context<Close>) -> Result<()> {
    let target = &ctx.accounts.target;
    let mut data = target.try_borrow_mut_data()?;
    data.fill(0);
    **ctx.accounts.dest.lamports.borrow_mut() = ctx.accounts.dest.lamports();
    **target.lamports.borrow_mut() = 0;
    Ok(())
}
""",
        }
        rules = _rule_ids(run_rules(files, "anchor"))
        assert not any("SOL-CLOSE-01" in r for r in rules), rules


class TestFindingFormat:
    def test_finding_has_required_fields(self):
        files = {
            "src/lib.rs": "pub fn x(amount: u64) -> u64 { amount + 1 }",
        }
        findings = run_rules(files, "anchor", overflow_checks="off")
        for f in findings:
            assert "tool" in f
            assert "rule_id" in f
            assert "severity_raw" in f
            assert "file" in f
            assert "start" in f
            assert "end" in f
            assert "category" in f
            assert f["start"] >= 1
            assert f["end"] >= f["start"]
            assert f["tool"].startswith("soken-solana-rules@")
