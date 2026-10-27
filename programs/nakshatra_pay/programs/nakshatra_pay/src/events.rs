use anchor_lang::prelude::*;

#[event]
pub struct ConfigInit {
    pub config: Pubkey,
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub fee_wallet: Pubkey,
    pub fee_bps: u16,
}

#[event]
pub struct ConfigProposed {
    pub config: Pubkey,
    pub fee_bps: u16,
    pub fee_wallet: Pubkey,
    pub effective_at: i64,
}

#[event]
pub struct ConfigApplied {
    pub config: Pubkey,
    pub fee_bps: u16,
    pub fee_wallet: Pubkey,
}

#[event]
pub struct ConfigCancelled {
    pub config: Pubkey,
}

#[event]
pub struct AuthorityProposed {
    pub config: Pubkey,
    pub current_authority: Pubkey,
    pub pending_authority: Pubkey,
}

#[event]
pub struct AuthorityAccepted {
    pub config: Pubkey,
    pub old_authority: Pubkey,
    pub new_authority: Pubkey,
}

#[event]
pub struct EscrowInit {
    pub config: Pubkey,
    pub escrow: Pubkey,
    pub owner: Pubkey,
    pub vault: Pubkey,
}

#[event]
pub struct Deposited {
    pub escrow: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
}

#[event]
pub struct WithdrawRequested {
    pub escrow: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub withdraw_at: i64,
}

#[event]
pub struct WithdrawCancelled {
    pub escrow: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct Withdrawn {
    pub escrow: Pubkey,
    pub owner: Pubkey,
    pub destination: Pubkey,
    pub amount: u64,
}

#[event]
pub struct EscrowClosed {
    pub escrow: Pubkey,
    pub owner: Pubkey,
    pub destination: Pubkey,
    pub amount: u64,
}

#[event]
pub struct DelegateSet {
    pub escrow: Pubkey,
    pub delegate: Pubkey,
    pub key: Pubkey,
    pub cap_total: u64,
    pub spent: u64,
    pub expires_at: i64,
    pub flags: u8,
}

#[event]
pub struct DelegateRevoked {
    pub escrow: Pubkey,
    pub delegate: Pubkey,
    pub key: Pubkey,
}

#[event]
pub struct DelegateClosed {
    pub escrow: Pubkey,
    pub delegate: Pubkey,
    pub key: Pubkey,
}

#[event]
pub struct ChannelOpened {
    pub escrow: Pubkey,
    pub channel: Pubkey,
    pub seq: u64,
    pub generation: u64,
    pub worker: Pubkey,
    pub voucher_signer: Pubkey,
    pub cap: u64,
    pub fee_bps_snapshot: u16,
}

#[event]
pub struct FeeWithdrawn {
    pub config: Pubkey,
    pub fee_wallet: Pubkey,
    pub amount: u64,
}

#[event]
pub struct ChannelFunded {
    pub channel: Pubkey,
    pub seq: u64,
    pub add: u64,
    pub cap: u64,
}

#[event]
pub struct Redeemed {
    pub channel: Pubkey,
    pub seq: u64,
    pub cumulative_total: u64,
    pub delta: u64,
    pub fee: u64,
    pub by: Pubkey,
}

#[event]
pub struct ChannelClosing {
    pub channel: Pubkey,
    pub seq: u64,
    pub close_at: i64,
}

#[event]
pub struct ChannelClosed {
    pub channel: Pubkey,
    pub seq: u64,
    pub released: u64,
    pub by: Pubkey,
}
