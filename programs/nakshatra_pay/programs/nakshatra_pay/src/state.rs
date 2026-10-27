use anchor_lang::prelude::*;

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub fee_wallet: Pubkey,
    pub fee_bps: u16,
    pub withdraw_delay_s: i64,
    pub close_grace_s: i64,
    pub config_delay_s: i64,
    pub pending: Option<PendingConfig>,
    pub pending_authority: Option<Pubkey>,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, InitSpace, PartialEq, Eq)]
pub struct PendingConfig {
    pub fee_bps: u16,
    pub fee_wallet: Pubkey,
    pub effective_at: i64,
}

#[account]
#[derive(InitSpace)]
pub struct Escrow {
    pub owner: Pubkey,
    pub vault: Pubkey,
    pub committed: u64,
    pub open_channels: u32,
    pub open_tasks: u32,
    pub channel_seq: u64,
    pub pending_withdraw: Option<PendingWithdrawal>,
    pub rent_payer: Pubkey,
    pub bump: u8,
    pub vault_bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, InitSpace, PartialEq, Eq)]
pub struct PendingWithdrawal {
    pub amount: u64,
    pub withdraw_at: i64,
}

#[account]
#[derive(InitSpace)]
pub struct Delegate {
    pub escrow: Pubkey,
    pub key: Pubkey,
    pub cap_total: u64,
    pub spent: u64,
    pub expires_at: i64,
    pub flags: u8,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, InitSpace, PartialEq, Eq)]
pub enum ChannelStatus {
    Open,
    Closing,
}

#[account]
#[derive(InitSpace)]
pub struct Channel {
    pub escrow: Pubkey,
    pub seq: u64,
    pub worker: Pubkey,
    pub voucher_signer: Pubkey,
    pub delegate: Option<Pubkey>,
    pub cap: u64,
    pub redeemed: u64,
    pub fee_bps_snapshot: u16,
    pub status: ChannelStatus,
    pub close_at: i64,
    pub rent_payer: Pubkey,
    pub bump: u8,
}
