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
