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
}
