pub mod constants;
pub mod error;
pub mod events;
pub mod instructions;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
pub use instructions::*;
pub use state::*;

declare_id!("GLWqQsSqUsDkPvkc8rxcoQUyro7ZQd5denht21NtdTTo");

#[cfg(all(feature = "custom-entrypoint", not(feature = "cpi")))]
anchor_lang::solana_program::entrypoint!(strict_entry);

/// Anchor 1.2.0 accepts trailing bytes after deserializing instruction arguments.
/// Reject them before dispatch so every public instruction has one canonical encoding.
#[cfg(all(feature = "custom-entrypoint", not(feature = "cpi")))]
fn strict_entry<'info>(
    program_id: &'info Pubkey,
    accounts: &'info [AccountInfo<'info>],
    data: &'info [u8],
) -> anchor_lang::solana_program::entrypoint::ProgramResult {
    use anchor_lang::solana_program::program_error::ProgramError;
    use anchor_lang::Discriminator;

    let expected_len = if data.starts_with(instruction::ConfigInit::DISCRIMINATOR) {
        Some(instruction::ConfigInit::DISCRIMINATOR.len() + 2)
    } else if data.starts_with(instruction::ConfigPropose::DISCRIMINATOR) {
        Some(instruction::ConfigPropose::DISCRIMINATOR.len() + 2)
    } else if data.starts_with(instruction::ConfigApply::DISCRIMINATOR) {
        Some(instruction::ConfigApply::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::ConfigCancel::DISCRIMINATOR) {
        Some(instruction::ConfigCancel::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::ConfigProposeAuthority::DISCRIMINATOR) {
        Some(instruction::ConfigProposeAuthority::DISCRIMINATOR.len() + 32)
    } else if data.starts_with(instruction::ConfigAcceptAuthority::DISCRIMINATOR) {
        Some(instruction::ConfigAcceptAuthority::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::FeeWithdraw::DISCRIMINATOR) {
        Some(instruction::FeeWithdraw::DISCRIMINATOR.len() + 8)
    } else if data.starts_with(instruction::EscrowInit::DISCRIMINATOR) {
        Some(instruction::EscrowInit::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::EscrowDeposit::DISCRIMINATOR) {
        Some(instruction::EscrowDeposit::DISCRIMINATOR.len() + 8)
    } else if data.starts_with(instruction::EscrowWithdrawRequest::DISCRIMINATOR) {
        Some(instruction::EscrowWithdrawRequest::DISCRIMINATOR.len() + 8)
    } else if data.starts_with(instruction::EscrowWithdrawCancel::DISCRIMINATOR) {
        Some(instruction::EscrowWithdrawCancel::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::EscrowWithdrawExecute::DISCRIMINATOR) {
        Some(instruction::EscrowWithdrawExecute::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::EscrowClose::DISCRIMINATOR) {
        Some(instruction::EscrowClose::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::DelegateSet::DISCRIMINATOR) {
        Some(instruction::DelegateSet::DISCRIMINATOR.len() + 32 + 8 + 8 + 1)
    } else if data.starts_with(instruction::DelegateRevoke::DISCRIMINATOR) {
        Some(instruction::DelegateRevoke::DISCRIMINATOR.len() + 32)
    } else if data.starts_with(instruction::DelegateClose::DISCRIMINATOR) {
        Some(instruction::DelegateClose::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::ChannelOpen::DISCRIMINATOR) {
        Some(instruction::ChannelOpen::DISCRIMINATOR.len() + 32 + 8)
    } else if data.starts_with(instruction::ChannelFund::DISCRIMINATOR) {
        Some(instruction::ChannelFund::DISCRIMINATOR.len() + 8)
    } else if data.starts_with(instruction::ChannelRedeem::DISCRIMINATOR) {
        Some(instruction::ChannelRedeem::DISCRIMINATOR.len() + 8)
    } else if data.starts_with(instruction::ChannelCloseRequest::DISCRIMINATOR) {
        Some(instruction::ChannelCloseRequest::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::ChannelCloseFinalize::DISCRIMINATOR) {
        Some(instruction::ChannelCloseFinalize::DISCRIMINATOR.len())
    } else if data.starts_with(instruction::TaskOpen::DISCRIMINATOR) {
        Some(instruction::TaskOpen::DISCRIMINATOR.len() + 32 + 32 + 8 + 8 + 32)
    } else if data.starts_with(instruction::TaskSubmit::DISCRIMINATOR) {
        Some(instruction::TaskSubmit::DISCRIMINATOR.len() + 32)
    } else if data.starts_with(instruction::TaskVerify::DISCRIMINATOR) {
        Some(instruction::TaskVerify::DISCRIMINATOR.len() + 1)
    } else if data.starts_with(instruction::TaskTimeout::DISCRIMINATOR) {
        Some(instruction::TaskTimeout::DISCRIMINATOR.len())
    } else {
        None
    };

    if expected_len.is_some_and(|expected| data.len() != expected) {
        return Err(ProgramError::InvalidInstructionData);
    }
    entry(program_id, accounts, data)
}

#[program]
pub mod nakshatra_pay {
    use super::*;

    pub fn config_init(ctx: Context<ConfigInitAccounts>, fee_bps: u16) -> Result<()> {
        instructions::handle_config_init(ctx, fee_bps)
    }
    pub fn config_propose(ctx: Context<ConfigProposeAccounts>, fee_bps: u16) -> Result<()> {
        instructions::handle_config_propose(ctx, fee_bps)
    }
    pub fn config_apply(ctx: Context<ConfigApplyAccounts>) -> Result<()> {
        instructions::handle_config_apply(ctx)
    }
    pub fn config_cancel(ctx: Context<ConfigAuthorityAccounts>) -> Result<()> {
        instructions::handle_config_cancel(ctx)
    }
    pub fn config_propose_authority(
        ctx: Context<ConfigAuthorityAccounts>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::handle_config_propose_authority(ctx, new_authority)
    }
    pub fn config_accept_authority(ctx: Context<ConfigAcceptAuthorityAccounts>) -> Result<()> {
        instructions::handle_config_accept_authority(ctx)
    }
    pub fn fee_withdraw(ctx: Context<FeeWithdrawAccounts>, amount: u64) -> Result<()> {
        instructions::handle_fee_withdraw(ctx, amount)
    }
    pub fn escrow_init(ctx: Context<EscrowInitAccounts>) -> Result<()> {
        instructions::handle_escrow_init(ctx)
    }
    pub fn escrow_deposit(ctx: Context<EscrowDepositAccounts>, amount: u64) -> Result<()> {
        instructions::handle_escrow_deposit(ctx, amount)
    }
    pub fn escrow_withdraw_request(ctx: Context<EscrowOwnerAccounts>, amount: u64) -> Result<()> {
        instructions::handle_escrow_withdraw_request(ctx, amount)
    }
    pub fn escrow_withdraw_cancel(ctx: Context<EscrowOwnerAccounts>) -> Result<()> {
        instructions::handle_escrow_withdraw_cancel(ctx)
    }
    pub fn escrow_withdraw_execute(ctx: Context<EscrowWithdrawExecuteAccounts>) -> Result<()> {
        instructions::handle_escrow_withdraw_execute(ctx)
    }
    pub fn escrow_close(ctx: Context<EscrowCloseAccounts>) -> Result<()> {
        instructions::handle_escrow_close(ctx)
    }
    pub fn delegate_set(
        ctx: Context<DelegateSetAccounts>,
        key: Pubkey,
        cap_total: u64,
        expires_at: i64,
        flags: u8,
    ) -> Result<()> {
        instructions::handle_delegate_set(ctx, key, cap_total, expires_at, flags)
    }
    pub fn delegate_revoke(ctx: Context<DelegateRevokeAccounts>, key: Pubkey) -> Result<()> {
        instructions::handle_delegate_revoke(ctx, key)
    }
    pub fn delegate_close(ctx: Context<DelegateCloseAccounts>) -> Result<()> {
        instructions::handle_delegate_close(ctx)
    }
    pub fn channel_open(ctx: Context<ChannelOpenAccounts>, worker: Pubkey, cap: u64) -> Result<()> {
        instructions::handle_channel_open(ctx, worker, cap)
    }
    pub fn channel_fund(ctx: Context<ChannelFundAccounts>, add: u64) -> Result<()> {
        instructions::handle_channel_fund(ctx, add)
    }
    pub fn channel_redeem(
        ctx: Context<ChannelRedeemAccounts>,
        cumulative_total: u64,
    ) -> Result<()> {
        instructions::handle_channel_redeem(ctx, cumulative_total)
    }
    pub fn channel_close_request(ctx: Context<ChannelCloseRequestAccounts>) -> Result<()> {
        instructions::handle_channel_close_request(ctx)
    }
    pub fn channel_close_finalize(ctx: Context<ChannelCloseFinalizeAccounts>) -> Result<()> {
        instructions::handle_channel_close_finalize(ctx)
    }
    pub fn task_open(
        ctx: Context<TaskOpenAccounts>,
        worker: Pubkey,
        verifier: Pubkey,
        amount: u64,
        deadline: i64,
        task_hash: [u8; 32],
    ) -> Result<()> {
        instructions::handle_task_open(ctx, worker, verifier, amount, deadline, task_hash)
    }
    pub fn task_submit(ctx: Context<TaskSubmitAccounts>, result_hash: [u8; 32]) -> Result<()> {
        instructions::handle_task_submit(ctx, result_hash)
    }
    pub fn task_verify(ctx: Context<TaskSettleAccounts>, verdict: Verdict) -> Result<()> {
        instructions::handle_task_verify(ctx, verdict)
    }
    pub fn task_timeout(ctx: Context<TaskSettleAccounts>) -> Result<()> {
        instructions::handle_task_timeout(ctx)
    }
}
