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
    #[msg("The delegate expiry must be in the future")]
    InvalidDelegateExpiry,
    #[msg("The delegate cap cannot be below its current spend")]
    DelegateCapBelowSpent,
    #[msg("The delegate flags contain unsupported bits")]
    InvalidDelegateFlags,
    #[msg("The delegate has expired")]
    DelegateExpired,
    #[msg("The delegate does not have the required permission")]
    DelegateFlagMissing,
    #[msg("The delegate cap would be exceeded")]
    DelegateCapExceeded,
    #[msg("The escrow vault does not fully collateralize this channel")]
    InsufficientCollateral,
    #[msg("The channel is not open")]
    ChannelNotOpen,
    #[msg("The channel close grace period has elapsed")]
    ChannelCloseElapsed,
    #[msg("The channel close grace period has not elapsed")]
    ChannelCloseNotElapsed,
    #[msg("The voucher total must strictly increase")]
    VoucherNotIncreasing,
    #[msg("The voucher total exceeds the channel cap")]
    VoucherExceedsCap,
    #[msg("The preceding instruction is not a valid Ed25519 verification")]
    InvalidEd25519Instruction,
    #[msg("The voucher signer is not authorized for this channel")]
    InvalidVoucherSigner,
    #[msg("The signed voucher message does not match this redemption")]
    InvalidVoucherMessage,
    #[msg("Channel redemption cannot be invoked through CPI")]
    RedeemViaCpi,
    #[msg("The supplied delegate account does not match the channel")]
    WrongDelegate,
}
