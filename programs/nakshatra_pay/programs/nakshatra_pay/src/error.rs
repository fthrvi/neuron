use anchor_lang::prelude::*;

#[error_code]
pub enum PayError {
    #[msg("The signer is not authorized for this operation")]
    Unauthorized,
    #[msg("The fee exceeds the configured maximum")]
    FeeBpsTooHigh,
    #[msg("The mint must be owned by the classic SPL Token program")]
    InvalidMintOwner,
    #[msg("The classic SPL Token program is required")]
    InvalidTokenProgram,
    #[msg("The token account has the wrong mint")]
    WrongMint,
    #[msg("The token account has the wrong authority")]
    WrongTokenOwner,
    #[msg("No configuration change is pending")]
    NoPendingConfig,
    #[msg("The configuration delay has not elapsed")]
    ConfigDelayNotElapsed,
    #[msg("No authority transfer is pending")]
    NoPendingAuthority,
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("No withdrawal is pending")]
    NoPendingWithdrawal,
    #[msg("The withdrawal delay has not elapsed")]
    WithdrawalDelayNotElapsed,
    #[msg("The escrow does not have enough uncommitted funds")]
    InsufficientUncommittedFunds,
    #[msg("The escrow still has committed funds")]
    FundsCommitted,
    #[msg("The escrow still has open channels")]
    ChannelsOpen,
    #[msg("The escrow still has open tasks")]
    TasksOpen,
    #[msg("The pending withdrawal still has an active withdrawal window")]
    PendingWithdrawalActive,
    #[msg("The source and destination token accounts must be different")]
    DuplicateTokenAccount,
    #[msg("Arithmetic overflow or underflow")]
    ArithmeticOverflow,
}
