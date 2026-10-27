use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::get_stack_height;
use anchor_lang::solana_program::program_pack::Pack;
use anchor_spl::token::{
    self,
    spl_token::state::{Account as SplTokenAccount, Mint as SplMint},
    CloseAccount, InitializeAccount3, Token, TransferChecked,
};

use crate::{
    constants::*,
    error::PayError,
    events::*,
    state::{
        Channel, ChannelStatus, Config, Delegate, Escrow, OwnerState, PendingConfig,
        PendingWithdrawal,
    },
};

#[event_cpi]
#[derive(Accounts)]
pub struct ConfigInitAccounts<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = anchor_lang::solana_program::bpf_loader_upgradeable::ID,
        constraint = program_data.upgrade_authority_address == Some(authority.key()) @ PayError::Unauthorized
    )]
    pub program_data: Account<'info, ProgramData>,
    /// CHECK: classic SPL mint owner and layout checked in the handler.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: classic SPL token owner, layout, and mint checked in the handler.
    pub fee_wallet: UncheckedAccount<'info>,
    #[account(init, payer = authority, space = SplTokenAccount::LEN, owner = token_program.key(), seeds = [FEE_VAULT_SEED, config.key().as_ref()], bump)]
    /// CHECK: created at the canonical fee-vault PDA, assigned to classic SPL Token,
    /// and initialized with the config PDA as its authority.
    pub fee_vault: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub fn handle_config_init(ctx: Context<ConfigInitAccounts>, fee_bps: u16) -> Result<()> {
    require!(fee_bps <= FEE_BPS_MAX, PayError::FeeBpsTooHigh);
    require_keys_eq!(
        *ctx.accounts.mint.to_account_info().owner,
        anchor_spl::token::ID,
        PayError::InvalidMintOwner
    );
    load_mint(&ctx.accounts.mint)?;
    let fee_wallet = load_token(&ctx.accounts.fee_wallet)?;
    require_keys_eq!(
        fee_wallet.mint,
        ctx.accounts.mint.key(),
        PayError::WrongMint
    );
    token::initialize_account3(CpiContext::new(
        ctx.accounts.token_program.key(),
        InitializeAccount3 {
            account: ctx.accounts.fee_vault.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            authority: ctx.accounts.config.to_account_info(),
        },
    ))?;
    let config = &mut ctx.accounts.config;
    config.authority = ctx.accounts.authority.key();
    config.mint = ctx.accounts.mint.key();
    config.fee_wallet = ctx.accounts.fee_wallet.key();
    config.fee_bps = fee_bps;
    config.withdraw_delay_s = WITHDRAW_DELAY_S;
    config.close_grace_s = CLOSE_GRACE_S;
    config.config_delay_s = CONFIG_DELAY_S;
    config.pending = None;
    config.pending_authority = None;
    config.bump = ctx.bumps.config;
    config.fee_vault_bump = ctx.bumps.fee_vault;
    emit_cpi!(ConfigInit {
        config: config.key(),
        authority: config.authority,
        mint: config.mint,
        fee_wallet: config.fee_wallet,
        fee_bps: config.fee_bps
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct ConfigProposeAccounts<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ PayError::Unauthorized)]
    pub config: Account<'info, Config>,
    /// CHECK: classic SPL token owner, layout, and mint checked in the handler.
    pub fee_wallet: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
}

pub fn handle_config_propose(ctx: Context<ConfigProposeAccounts>, fee_bps: u16) -> Result<()> {
    require!(fee_bps <= FEE_BPS_MAX, PayError::FeeBpsTooHigh);
    let proposed_wallet = load_token(&ctx.accounts.fee_wallet)?;
    require_keys_eq!(
        proposed_wallet.mint,
        ctx.accounts.config.mint,
        PayError::WrongMint
    );
    let effective_at = Clock::get()?
        .unix_timestamp
        .checked_add(ctx.accounts.config.config_delay_s)
        .ok_or(PayError::ArithmeticOverflow)?;
    let fee_wallet = ctx.accounts.fee_wallet.key();
    ctx.accounts.config.pending = Some(PendingConfig {
        fee_bps,
        fee_wallet,
        effective_at,
    });
    emit_cpi!(ConfigProposed {
        config: ctx.accounts.config.key(),
        fee_bps,
        fee_wallet,
        effective_at
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct ConfigApplyAccounts<'info> {
    pub executor: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: key is pinned by the pending proposal; classic SPL layout and mint checked in handler.
    pub fee_wallet: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
}

pub fn handle_config_apply(ctx: Context<ConfigApplyAccounts>) -> Result<()> {
    let pending = ctx
        .accounts
        .config
        .pending
        .ok_or(PayError::NoPendingConfig)?;
    require_keys_eq!(
        ctx.accounts.fee_wallet.key(),
        pending.fee_wallet,
        PayError::Unauthorized
    );
    let fee_wallet = load_token(&ctx.accounts.fee_wallet)?;
    require_keys_eq!(
        fee_wallet.mint,
        ctx.accounts.config.mint,
        PayError::WrongMint
    );
    require!(
        Clock::get()?.unix_timestamp >= pending.effective_at,
        PayError::ConfigDelayNotElapsed
    );
    let config = &mut ctx.accounts.config;
    config.fee_bps = pending.fee_bps;
    config.fee_wallet = pending.fee_wallet;
    config.pending = None;
    emit_cpi!(ConfigApplied {
        config: config.key(),
        fee_bps: config.fee_bps,
        fee_wallet: config.fee_wallet
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct ConfigAuthorityAccounts<'info> {
    pub authority: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ PayError::Unauthorized)]
    pub config: Account<'info, Config>,
}

pub fn handle_config_cancel(ctx: Context<ConfigAuthorityAccounts>) -> Result<()> {
    require!(
        ctx.accounts.config.pending.is_some(),
        PayError::NoPendingConfig
    );
    ctx.accounts.config.pending = None;
    emit_cpi!(ConfigCancelled {
        config: ctx.accounts.config.key()
    });
    Ok(())
}

pub fn handle_config_propose_authority(
    ctx: Context<ConfigAuthorityAccounts>,
    new_authority: Pubkey,
) -> Result<()> {
    ctx.accounts.config.pending_authority = Some(new_authority);
    emit_cpi!(AuthorityProposed {
        config: ctx.accounts.config.key(),
        current_authority: ctx.accounts.authority.key(),
        pending_authority: new_authority
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct ConfigAcceptAuthorityAccounts<'info> {
    pub new_authority: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

pub fn handle_config_accept_authority(ctx: Context<ConfigAcceptAuthorityAccounts>) -> Result<()> {
    let pending = ctx
        .accounts
        .config
        .pending_authority
        .ok_or(PayError::NoPendingAuthority)?;
    require_keys_eq!(
        pending,
        ctx.accounts.new_authority.key(),
        PayError::Unauthorized
    );
    let old_authority = ctx.accounts.config.authority;
    ctx.accounts.config.authority = pending;
    ctx.accounts.config.pending_authority = None;
    emit_cpi!(AuthorityAccepted {
        config: ctx.accounts.config.key(),
        old_authority,
        new_authority: pending
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct FeeWithdrawAccounts<'info> {
    pub authority: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = authority @ PayError::Unauthorized)]
    pub config: Account<'info, Config>,
    /// CHECK: pinned by config; classic SPL mint layout checked in the handler.
    #[account(address = config.mint @ PayError::WrongMint)]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: canonical PDA; classic SPL token layout, mint, and authority checked in handler.
    #[account(mut, seeds = [FEE_VAULT_SEED, config.key().as_ref()], bump = config.fee_vault_bump)]
    pub fee_vault: UncheckedAccount<'info>,
    /// CHECK: current configured wallet; classic SPL token layout and mint checked in handler.
    #[account(mut, address = config.fee_wallet, constraint = fee_wallet.key() != fee_vault.key() @ PayError::DuplicateTokenAccount)]
    pub fee_wallet: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
}

pub fn handle_fee_withdraw(ctx: Context<FeeWithdrawAccounts>, amount: u64) -> Result<()> {
    require!(amount > 0, PayError::ZeroAmount);
    let mint = load_mint(&ctx.accounts.mint)?;
    let fee_vault = load_token(&ctx.accounts.fee_vault)?;
    let fee_wallet = load_token(&ctx.accounts.fee_wallet)?;
    require_token(
        &fee_vault,
        ctx.accounts.config.mint,
        ctx.accounts.config.key(),
    )?;
    require_keys_eq!(
        fee_wallet.mint,
        ctx.accounts.config.mint,
        PayError::WrongMint
    );
    let bump = [ctx.accounts.config.bump];
    let signer_seeds: &[&[u8]] = &[CONFIG_SEED, &bump];
    token::transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.fee_vault.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.fee_wallet.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            },
            &[signer_seeds],
        ),
        amount,
        mint.decimals,
    )?;
    emit_cpi!(FeeWithdrawn {
        config: ctx.accounts.config.key(),
        fee_wallet: ctx.accounts.fee_wallet.key(),
        amount
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct EscrowInitAccounts<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(init_if_needed, payer = owner, space = 8 + OwnerState::INIT_SPACE, seeds = [OWNER_STATE_SEED, config.key().as_ref(), owner.key().as_ref()], bump)]
    pub owner_state: Account<'info, OwnerState>,
    /// CHECK: pinned by config; classic SPL mint owner and layout checked in the handler.
    #[account(address = config.mint @ PayError::WrongMint)]
    pub mint: UncheckedAccount<'info>,
    #[account(init, payer = owner, space = 8 + Escrow::INIT_SPACE, seeds = [ESCROW_SEED, config.key().as_ref(), owner.key().as_ref()], bump)]
    pub escrow: Account<'info, Escrow>,
    #[account(init, payer = owner, space = SplTokenAccount::LEN, owner = token_program.key(), seeds = [VAULT_SEED, escrow.key().as_ref()], bump)]
    /// CHECK: created at the canonical vault PDA, assigned to classic SPL Token,
    /// and initialized as a token account before any state is committed.
    pub vault: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub fn handle_escrow_init(ctx: Context<EscrowInitAccounts>) -> Result<()> {
    require_keys_eq!(
        *ctx.accounts.mint.to_account_info().owner,
        anchor_spl::token::ID,
        PayError::InvalidMintOwner
    );
    load_mint(&ctx.accounts.mint)?;
    token::initialize_account3(CpiContext::new(
        ctx.accounts.token_program.key(),
        InitializeAccount3 {
            account: ctx.accounts.vault.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            authority: ctx.accounts.escrow.to_account_info(),
        },
    ))?;
    let owner_state = &mut ctx.accounts.owner_state;
    if owner_state.next_generation == 0 {
        owner_state.bump = ctx.bumps.owner_state;
    } else {
        require!(
            owner_state.bump == ctx.bumps.owner_state,
            PayError::Unauthorized
        );
    }
    let generation = owner_state.next_generation;
    owner_state.next_generation = generation
        .checked_add(1)
        .ok_or(PayError::ArithmeticOverflow)?;
    let escrow = &mut ctx.accounts.escrow;
    escrow.owner = ctx.accounts.owner.key();
    escrow.vault = ctx.accounts.vault.key();
    escrow.committed = 0;
    escrow.open_channels = 0;
    escrow.open_tasks = 0;
    escrow.channel_seq = 0;
    escrow.generation = generation;
    escrow.pending_withdraw = None;
    escrow.rent_payer = ctx.accounts.owner.key();
    escrow.bump = ctx.bumps.escrow;
    escrow.vault_bump = ctx.bumps.vault;
    emit_cpi!(EscrowInit {
        config: ctx.accounts.config.key(),
        escrow: escrow.key(),
        owner: escrow.owner,
        vault: escrow.vault
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct EscrowDepositAccounts<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: pinned by config; classic SPL mint owner and layout checked in the handler.
    #[account(address = config.mint @ PayError::WrongMint)]
    pub mint: UncheckedAccount<'info>,
    #[account(seeds = [ESCROW_SEED, config.key().as_ref(), owner.key().as_ref()], bump = escrow.bump, has_one = owner @ PayError::Unauthorized, has_one = vault)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: classic SPL token owner, layout, mint and authority checked in the handler.
    #[account(mut, constraint = source.key() != vault.key() @ PayError::DuplicateTokenAccount)]
    pub source: UncheckedAccount<'info>,
    /// CHECK: canonical PDA; classic SPL token owner, layout, mint and authority checked in handler.
    #[account(mut, seeds = [VAULT_SEED, escrow.key().as_ref()], bump = escrow.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
}

pub fn handle_escrow_deposit(ctx: Context<EscrowDepositAccounts>, amount: u64) -> Result<()> {
    require!(amount > 0, PayError::ZeroAmount);
    let mint = load_mint(&ctx.accounts.mint)?;
    let source = load_token(&ctx.accounts.source)?;
    let vault = load_token(&ctx.accounts.vault)?;
    require_token(&source, ctx.accounts.config.mint, ctx.accounts.owner.key())?;
    require_token(&vault, ctx.accounts.config.mint, ctx.accounts.escrow.key())?;
    token::transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.source.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.owner.to_account_info(),
            },
        ),
        amount,
        mint.decimals,
    )?;
    emit_cpi!(Deposited {
        escrow: ctx.accounts.escrow.key(),
        owner: ctx.accounts.owner.key(),
        amount
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct EscrowOwnerAccounts<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [ESCROW_SEED, config.key().as_ref(), owner.key().as_ref()], bump = escrow.bump, has_one = owner @ PayError::Unauthorized, has_one = vault)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: canonical PDA; classic SPL token owner, layout, mint and authority checked in handlers.
    #[account(seeds = [VAULT_SEED, escrow.key().as_ref()], bump = escrow.vault_bump)]
    pub vault: UncheckedAccount<'info>,
}

pub fn handle_escrow_withdraw_request(
    ctx: Context<EscrowOwnerAccounts>,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, PayError::ZeroAmount);
    let vault = load_token(&ctx.accounts.vault)?;
    require_token(&vault, ctx.accounts.config.mint, ctx.accounts.escrow.key())?;
    let withdraw_at = Clock::get()?
        .unix_timestamp
        .checked_add(ctx.accounts.config.withdraw_delay_s)
        .ok_or(PayError::ArithmeticOverflow)?;
    ctx.accounts.escrow.pending_withdraw = Some(PendingWithdrawal {
        amount,
        withdraw_at,
    });
    emit_cpi!(WithdrawRequested {
        escrow: ctx.accounts.escrow.key(),
        owner: ctx.accounts.owner.key(),
        amount,
        withdraw_at
    });
    Ok(())
}

pub fn handle_escrow_withdraw_cancel(ctx: Context<EscrowOwnerAccounts>) -> Result<()> {
    let vault = load_token(&ctx.accounts.vault)?;
    require_token(&vault, ctx.accounts.config.mint, ctx.accounts.escrow.key())?;
    require!(
        ctx.accounts.escrow.pending_withdraw.is_some(),
        PayError::NoPendingWithdrawal
    );
    ctx.accounts.escrow.pending_withdraw = None;
    emit_cpi!(WithdrawCancelled {
        escrow: ctx.accounts.escrow.key(),
        owner: ctx.accounts.owner.key()
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct EscrowWithdrawExecuteAccounts<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: pinned by config; classic SPL mint owner and layout checked in the handler.
    #[account(address = config.mint @ PayError::WrongMint)]
    pub mint: UncheckedAccount<'info>,
    #[account(mut, seeds = [ESCROW_SEED, config.key().as_ref(), owner.key().as_ref()], bump = escrow.bump, has_one = owner @ PayError::Unauthorized, has_one = vault)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: canonical PDA; classic SPL token owner, layout, mint and authority checked in handler.
    #[account(mut, seeds = [VAULT_SEED, escrow.key().as_ref()], bump = escrow.vault_bump, constraint = vault.key() != destination.key() @ PayError::DuplicateTokenAccount)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: classic SPL token owner, layout, mint and authority checked in the handler.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
}

pub fn handle_escrow_withdraw_execute(ctx: Context<EscrowWithdrawExecuteAccounts>) -> Result<()> {
    let mint = load_mint(&ctx.accounts.mint)?;
    let vault = load_token(&ctx.accounts.vault)?;
    let destination = load_token(&ctx.accounts.destination)?;
    require_token(&vault, ctx.accounts.config.mint, ctx.accounts.escrow.key())?;
    require_token(
        &destination,
        ctx.accounts.config.mint,
        ctx.accounts.owner.key(),
    )?;
    let pending = ctx
        .accounts
        .escrow
        .pending_withdraw
        .ok_or(PayError::NoPendingWithdrawal)?;
    require!(
        Clock::get()?.unix_timestamp >= pending.withdraw_at,
        PayError::WithdrawalDelayNotElapsed
    );
    let available = vault
        .amount
        .checked_sub(ctx.accounts.escrow.committed)
        .ok_or(PayError::ArithmeticOverflow)?;
    require!(
        pending.amount <= available,
        PayError::InsufficientUncommittedFunds
    );
    transfer_from_vault(
        &ctx.accounts.config,
        &ctx.accounts.escrow,
        &ctx.accounts.owner,
        &ctx.accounts.vault,
        &ctx.accounts.destination,
        &ctx.accounts.mint,
        &ctx.accounts.token_program,
        pending.amount,
        mint.decimals,
    )?;
    ctx.accounts.escrow.pending_withdraw = None;
    emit_cpi!(Withdrawn {
        escrow: ctx.accounts.escrow.key(),
        owner: ctx.accounts.owner.key(),
        destination: ctx.accounts.destination.key(),
        amount: pending.amount
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct EscrowCloseAccounts<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: pinned by config; classic SPL mint owner and layout checked in the handler.
    #[account(address = config.mint @ PayError::WrongMint)]
    pub mint: UncheckedAccount<'info>,
    #[account(mut, close = owner, seeds = [ESCROW_SEED, config.key().as_ref(), owner.key().as_ref()], bump = escrow.bump, has_one = owner @ PayError::Unauthorized, has_one = vault, constraint = escrow.rent_payer == owner.key() @ PayError::Unauthorized)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: canonical PDA; classic SPL token owner, layout, mint and authority checked in handler.
    #[account(mut, seeds = [VAULT_SEED, escrow.key().as_ref()], bump = escrow.vault_bump, constraint = vault.key() != destination.key() @ PayError::DuplicateTokenAccount)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: classic SPL token owner, layout, mint and authority checked in the handler.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
}

pub fn handle_escrow_close(ctx: Context<EscrowCloseAccounts>) -> Result<()> {
    let mint = load_mint(&ctx.accounts.mint)?;
    let vault = load_token(&ctx.accounts.vault)?;
    let destination = load_token(&ctx.accounts.destination)?;
    require_token(&vault, ctx.accounts.config.mint, ctx.accounts.escrow.key())?;
    require_token(
        &destination,
        ctx.accounts.config.mint,
        ctx.accounts.owner.key(),
    )?;
    require!(ctx.accounts.escrow.committed == 0, PayError::FundsCommitted);
    require!(
        ctx.accounts.escrow.open_channels == 0,
        PayError::ChannelsOpen
    );
    require!(ctx.accounts.escrow.open_tasks == 0, PayError::TasksOpen);
    if let Some(pending) = ctx.accounts.escrow.pending_withdraw {
        require!(
            Clock::get()?.unix_timestamp >= pending.withdraw_at,
            PayError::PendingWithdrawalActive
        );
    }
    let amount = vault.amount;
    if amount > 0 {
        transfer_from_vault(
            &ctx.accounts.config,
            &ctx.accounts.escrow,
            &ctx.accounts.owner,
            &ctx.accounts.vault,
            &ctx.accounts.destination,
            &ctx.accounts.mint,
            &ctx.accounts.token_program,
            amount,
            mint.decimals,
        )?;
    }
    let config_key = ctx.accounts.config.key();
    let owner_key = ctx.accounts.owner.key();
    let bump = [ctx.accounts.escrow.bump];
    let signer_seeds: &[&[u8]] = &[ESCROW_SEED, config_key.as_ref(), owner_key.as_ref(), &bump];
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.key(),
        CloseAccount {
            account: ctx.accounts.vault.to_account_info(),
            destination: ctx.accounts.owner.to_account_info(),
            authority: ctx.accounts.escrow.to_account_info(),
        },
        &[signer_seeds],
    ))?;
    emit_cpi!(EscrowClosed {
        escrow: ctx.accounts.escrow.key(),
        owner: ctx.accounts.owner.key(),
        destination: ctx.accounts.destination.key(),
        amount
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(key: Pubkey)]
pub struct DelegateSetAccounts<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(seeds = [ESCROW_SEED, config.key().as_ref(), owner.key().as_ref()], bump = escrow.bump, has_one = owner @ PayError::Unauthorized)]
    pub escrow: Account<'info, Escrow>,
    #[account(init_if_needed, payer = owner, space = 8 + Delegate::INIT_SPACE, seeds = [DELEGATE_SEED, escrow.key().as_ref(), key.as_ref()], bump)]
    pub delegate: Account<'info, Delegate>,
    pub system_program: Program<'info, System>,
}

pub fn handle_delegate_set(
    ctx: Context<DelegateSetAccounts>,
    key: Pubkey,
    cap_total: u64,
    expires_at: i64,
    flags: u8,
) -> Result<()> {
    require!(
        expires_at > Clock::get()?.unix_timestamp,
        PayError::InvalidDelegateExpiry
    );
    require!(
        flags & !DELEGATE_FLAGS_ALL == 0,
        PayError::InvalidDelegateFlags
    );
    let delegate = &mut ctx.accounts.delegate;
    if delegate.escrow == Pubkey::default() {
        delegate.escrow = ctx.accounts.escrow.key();
        delegate.key = key;
        delegate.generation = ctx.accounts.escrow.generation;
        delegate.cap_total = 0;
        delegate.spent = 0;
        delegate.expires_at = expires_at;
        delegate.flags = flags;
        delegate.open_channels = 0;
        delegate.disabled = false;
        delegate.bump = ctx.bumps.delegate;
    } else {
        require_keys_eq!(
            delegate.escrow,
            ctx.accounts.escrow.key(),
            PayError::WrongDelegate
        );
        require_keys_eq!(delegate.key, key, PayError::WrongDelegate);
        require!(delegate.bump == ctx.bumps.delegate, PayError::WrongDelegate);
        if delegate.generation == ctx.accounts.escrow.generation {
            require!(!delegate.disabled, PayError::DelegateDisabled);
        } else {
            require!(
                delegate.generation < ctx.accounts.escrow.generation,
                PayError::DelegateGenerationMismatch
            );
            require!(delegate.open_channels == 0, PayError::DelegateChannelsOpen);
            delegate.generation = ctx.accounts.escrow.generation;
            delegate.spent = 0;
            delegate.disabled = false;
        }
    }
    require!(cap_total >= delegate.spent, PayError::DelegateCapBelowSpent);
    delegate.cap_total = cap_total;
    delegate.expires_at = expires_at;
    delegate.flags = flags;
    emit_cpi!(DelegateSet {
        escrow: delegate.escrow,
        delegate: delegate.key(),
        key,
        cap_total,
        spent: delegate.spent,
        expires_at,
        flags
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(key: Pubkey)]
pub struct DelegateRevokeAccounts<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(seeds = [ESCROW_SEED, config.key().as_ref(), owner.key().as_ref()], bump = escrow.bump, has_one = owner @ PayError::Unauthorized)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut, seeds = [DELEGATE_SEED, escrow.key().as_ref(), key.as_ref()], bump = delegate.bump, constraint = delegate.escrow == escrow.key() @ PayError::WrongDelegate, constraint = delegate.key == key @ PayError::WrongDelegate)]
    pub delegate: Account<'info, Delegate>,
}

pub fn handle_delegate_revoke(ctx: Context<DelegateRevokeAccounts>, key: Pubkey) -> Result<()> {
    let delegate_key = ctx.accounts.delegate.key();
    ctx.accounts.delegate.disabled = true;
    ctx.accounts.delegate.cap_total = ctx.accounts.delegate.spent;
    emit_cpi!(DelegateRevoked {
        escrow: ctx.accounts.escrow.key(),
        delegate: delegate_key,
        key
    });
    if ctx.accounts.delegate.open_channels == 0 {
        ctx.accounts
            .delegate
            .close(ctx.accounts.owner.to_account_info())?;
    }
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct DelegateCloseAccounts<'info> {
    pub executor: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(seeds = [ESCROW_SEED, config.key().as_ref(), escrow.owner.as_ref()], bump = escrow.bump)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: receives delegate rent and is pinned to the escrow owner.
    #[account(mut, address = escrow.owner)]
    pub owner: UncheckedAccount<'info>,
    #[account(mut, close = owner, seeds = [DELEGATE_SEED, escrow.key().as_ref(), delegate.key.as_ref()], bump = delegate.bump, constraint = delegate.escrow == escrow.key() @ PayError::WrongDelegate)]
    pub delegate: Account<'info, Delegate>,
}

pub fn handle_delegate_close(ctx: Context<DelegateCloseAccounts>) -> Result<()> {
    require!(
        ctx.accounts.delegate.disabled
            || ctx.accounts.delegate.generation != ctx.accounts.escrow.generation,
        PayError::DelegateDisabled
    );
    require!(
        ctx.accounts.delegate.open_channels == 0,
        PayError::DelegateChannelsOpen
    );
    emit_cpi!(DelegateClosed {
        escrow: ctx.accounts.escrow.key(),
        delegate: ctx.accounts.delegate.key(),
        key: ctx.accounts.delegate.key
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(worker: Pubkey, cap: u64)]
pub struct ChannelOpenAccounts<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [ESCROW_SEED, config.key().as_ref(), escrow.owner.as_ref()], bump = escrow.bump, has_one = vault)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: classic SPL token layout, mint and authority checked in the handler.
    #[account(seeds = [VAULT_SEED, escrow.key().as_ref()], bump = escrow.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut)]
    pub delegate: Option<Account<'info, Delegate>>,
    #[account(init, payer = signer, space = 8 + Channel::INIT_SPACE, seeds = [CHANNEL_SEED, escrow.key().as_ref(), &escrow.generation.to_le_bytes(), &escrow.channel_seq.to_le_bytes()], bump)]
    pub channel: Account<'info, Channel>,
    pub system_program: Program<'info, System>,
}

pub fn handle_channel_open(
    ctx: Context<ChannelOpenAccounts>,
    worker: Pubkey,
    cap: u64,
) -> Result<()> {
    require!(cap > 0, PayError::ZeroAmount);
    let now = Clock::get()?.unix_timestamp;
    let delegate_key = authorize_channel_spend(
        ctx.accounts.signer.key(),
        &ctx.accounts.escrow,
        ctx.accounts.delegate.as_mut(),
        cap,
        now,
    )?;
    if delegate_key.is_some() {
        let delegate = ctx
            .accounts
            .delegate
            .as_mut()
            .ok_or(PayError::WrongDelegate)?;
        delegate.open_channels = delegate
            .open_channels
            .checked_add(1)
            .ok_or(PayError::ArithmeticOverflow)?;
    }
    let vault = load_token(&ctx.accounts.vault)?;
    require_token(&vault, ctx.accounts.config.mint, ctx.accounts.escrow.key())?;
    let committed = ctx
        .accounts
        .escrow
        .committed
        .checked_add(cap)
        .ok_or(PayError::ArithmeticOverflow)?;
    require!(vault.amount >= committed, PayError::InsufficientCollateral);
    let seq = ctx.accounts.escrow.channel_seq;
    let generation = ctx.accounts.escrow.generation;
    ctx.accounts.escrow.committed = committed;
    ctx.accounts.escrow.channel_seq = seq.checked_add(1).ok_or(PayError::ArithmeticOverflow)?;
    ctx.accounts.escrow.open_channels = ctx
        .accounts
        .escrow
        .open_channels
        .checked_add(1)
        .ok_or(PayError::ArithmeticOverflow)?;
    let channel = &mut ctx.accounts.channel;
    channel.escrow = ctx.accounts.escrow.key();
    channel.generation = generation;
    channel.seq = seq;
    channel.worker = worker;
    channel.voucher_signer = ctx.accounts.signer.key();
    channel.delegate = delegate_key;
    channel.cap = cap;
    channel.redeemed = 0;
    channel.fee_bps_snapshot = ctx.accounts.config.fee_bps;
    channel.status = ChannelStatus::Open;
    channel.close_at = 0;
    channel.rent_payer = ctx.accounts.signer.key();
    channel.bump = ctx.bumps.channel;
    emit_cpi!(ChannelOpened {
        escrow: channel.escrow,
        channel: channel.key(),
        seq,
        generation,
        worker,
        voucher_signer: channel.voucher_signer,
        cap,
        fee_bps_snapshot: channel.fee_bps_snapshot
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct ChannelFundAccounts<'info> {
    pub signer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [ESCROW_SEED, config.key().as_ref(), escrow.owner.as_ref()], bump = escrow.bump, has_one = vault)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: classic SPL token layout, mint and authority checked in the handler.
    #[account(seeds = [VAULT_SEED, escrow.key().as_ref()], bump = escrow.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(mut)]
    pub delegate: Option<Account<'info, Delegate>>,
    #[account(mut, seeds = [CHANNEL_SEED, escrow.key().as_ref(), &channel.generation.to_le_bytes(), &channel.seq.to_le_bytes()], bump = channel.bump, constraint = channel.escrow == escrow.key(), constraint = channel.generation == escrow.generation)]
    pub channel: Account<'info, Channel>,
}

pub fn handle_channel_fund(ctx: Context<ChannelFundAccounts>, add: u64) -> Result<()> {
    require!(add > 0, PayError::ZeroAmount);
    require!(
        ctx.accounts.channel.status == ChannelStatus::Open,
        PayError::ChannelNotOpen
    );
    require_keys_eq!(
        ctx.accounts.signer.key(),
        ctx.accounts.channel.voucher_signer,
        PayError::Unauthorized
    );
    let delegate_key = authorize_channel_spend(
        ctx.accounts.signer.key(),
        &ctx.accounts.escrow,
        ctx.accounts.delegate.as_mut(),
        add,
        Clock::get()?.unix_timestamp,
    )?;
    require!(
        delegate_key == ctx.accounts.channel.delegate,
        PayError::WrongDelegate
    );
    let vault = load_token(&ctx.accounts.vault)?;
    require_token(&vault, ctx.accounts.config.mint, ctx.accounts.escrow.key())?;
    let committed = ctx
        .accounts
        .escrow
        .committed
        .checked_add(add)
        .ok_or(PayError::ArithmeticOverflow)?;
    require!(vault.amount >= committed, PayError::InsufficientCollateral);
    ctx.accounts.escrow.committed = committed;
    ctx.accounts.channel.cap = ctx
        .accounts
        .channel
        .cap
        .checked_add(add)
        .ok_or(PayError::ArithmeticOverflow)?;
    emit_cpi!(ChannelFunded {
        channel: ctx.accounts.channel.key(),
        seq: ctx.accounts.channel.seq,
        add,
        cap: ctx.accounts.channel.cap
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct ChannelRedeemAccounts<'info> {
    pub by: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: pinned by config and classic SPL layout checked in the handler.
    #[account(address = config.mint @ PayError::WrongMint)]
    pub mint: UncheckedAccount<'info>,
    #[account(mut, seeds = [ESCROW_SEED, config.key().as_ref(), escrow.owner.as_ref()], bump = escrow.bump, has_one = vault)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut, seeds = [CHANNEL_SEED, escrow.key().as_ref(), &channel.generation.to_le_bytes(), &channel.seq.to_le_bytes()], bump = channel.bump, constraint = channel.escrow == escrow.key(), constraint = channel.generation == escrow.generation)]
    pub channel: Account<'info, Channel>,
    /// CHECK: canonical PDA and classic SPL layout checked in the handler.
    #[account(mut, seeds = [VAULT_SEED, escrow.key().as_ref()], bump = escrow.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    /// CHECK: classic SPL layout, worker authority and mint checked in the handler.
    #[account(mut, constraint = worker_token.key() != vault.key() @ PayError::DuplicateTokenAccount, constraint = worker_token.key() != fee_vault.key() @ PayError::DuplicateTokenAccount)]
    pub worker_token: UncheckedAccount<'info>,
    /// CHECK: canonical fee PDA; classic SPL layout, mint and config authority checked in handler.
    #[account(mut, seeds = [FEE_VAULT_SEED, config.key().as_ref()], bump = config.fee_vault_bump, constraint = fee_vault.key() != vault.key() @ PayError::DuplicateTokenAccount)]
    pub fee_vault: UncheckedAccount<'info>,
    /// CHECK: address pinned to the instructions sysvar.
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(address = anchor_spl::token::ID @ PayError::InvalidTokenProgram)]
    pub token_program: Program<'info, Token>,
}

pub fn handle_channel_redeem(
    ctx: Context<ChannelRedeemAccounts>,
    cumulative_total: u64,
) -> Result<()> {
    require!(get_stack_height() == 1, PayError::RedeemViaCpi);
    verify_voucher(
        &ctx.accounts.instructions_sysvar,
        &ctx.accounts.channel,
        ctx.accounts.escrow.owner,
        cumulative_total,
    )?;
    let now = Clock::get()?.unix_timestamp;
    match ctx.accounts.channel.status {
        ChannelStatus::Open => {}
        ChannelStatus::Closing => require!(
            now < ctx.accounts.channel.close_at,
            PayError::ChannelCloseElapsed
        ),
    }
    require!(
        cumulative_total > ctx.accounts.channel.redeemed,
        PayError::VoucherNotIncreasing
    );
    require!(
        cumulative_total <= ctx.accounts.channel.cap,
        PayError::VoucherExceedsCap
    );
    let mint = load_mint(&ctx.accounts.mint)?;
    let vault = load_token(&ctx.accounts.vault)?;
    let worker_token = load_token(&ctx.accounts.worker_token)?;
    let fee_vault = load_token(&ctx.accounts.fee_vault)?;
    require_token(&vault, ctx.accounts.config.mint, ctx.accounts.escrow.key())?;
    require_token(
        &worker_token,
        ctx.accounts.config.mint,
        ctx.accounts.channel.worker,
    )?;
    require_token(
        &fee_vault,
        ctx.accounts.config.mint,
        ctx.accounts.config.key(),
    )?;
    let delta = cumulative_total
        .checked_sub(ctx.accounts.channel.redeemed)
        .ok_or(PayError::ArithmeticOverflow)?;
    let cumulative_fee = (cumulative_total as u128)
        .checked_mul(ctx.accounts.channel.fee_bps_snapshot as u128)
        .ok_or(PayError::ArithmeticOverflow)?
        / 10_000;
    let redeemed_fee = (ctx.accounts.channel.redeemed as u128)
        .checked_mul(ctx.accounts.channel.fee_bps_snapshot as u128)
        .ok_or(PayError::ArithmeticOverflow)?
        / 10_000;
    let fee = u64::try_from(
        cumulative_fee
            .checked_sub(redeemed_fee)
            .ok_or(PayError::ArithmeticOverflow)?,
    )
    .map_err(|_| error!(PayError::ArithmeticOverflow))?;
    let worker_amount = delta.checked_sub(fee).ok_or(PayError::ArithmeticOverflow)?;
    if fee > 0 {
        transfer_from_vault_to(
            &ctx.accounts.config,
            &ctx.accounts.escrow,
            &ctx.accounts.vault,
            &ctx.accounts.fee_vault,
            &ctx.accounts.mint,
            &ctx.accounts.token_program,
            fee,
            mint.decimals,
        )?;
    }
    if worker_amount > 0 {
        transfer_from_vault_to(
            &ctx.accounts.config,
            &ctx.accounts.escrow,
            &ctx.accounts.vault,
            &ctx.accounts.worker_token,
            &ctx.accounts.mint,
            &ctx.accounts.token_program,
            worker_amount,
            mint.decimals,
        )?;
    }
    ctx.accounts.channel.redeemed = cumulative_total;
    ctx.accounts.escrow.committed = ctx
        .accounts
        .escrow
        .committed
        .checked_sub(delta)
        .ok_or(PayError::ArithmeticOverflow)?;
    emit_cpi!(Redeemed {
        channel: ctx.accounts.channel.key(),
        seq: ctx.accounts.channel.seq,
        cumulative_total,
        delta,
        fee,
        by: ctx.accounts.by.key()
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct ChannelCloseRequestAccounts<'info> {
    pub signer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(seeds = [ESCROW_SEED, config.key().as_ref(), escrow.owner.as_ref()], bump = escrow.bump)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut, seeds = [CHANNEL_SEED, escrow.key().as_ref(), &channel.generation.to_le_bytes(), &channel.seq.to_le_bytes()], bump = channel.bump, constraint = channel.escrow == escrow.key(), constraint = channel.generation == escrow.generation)]
    pub channel: Account<'info, Channel>,
}

pub fn handle_channel_close_request(ctx: Context<ChannelCloseRequestAccounts>) -> Result<()> {
    require!(
        ctx.accounts.channel.status == ChannelStatus::Open,
        PayError::ChannelNotOpen
    );
    let signer = ctx.accounts.signer.key();
    require!(
        signer == ctx.accounts.escrow.owner || signer == ctx.accounts.channel.voucher_signer,
        PayError::Unauthorized
    );
    let close_at = Clock::get()?
        .unix_timestamp
        .checked_add(ctx.accounts.config.close_grace_s)
        .ok_or(PayError::ArithmeticOverflow)?;
    ctx.accounts.channel.status = ChannelStatus::Closing;
    ctx.accounts.channel.close_at = close_at;
    emit_cpi!(ChannelClosing {
        channel: ctx.accounts.channel.key(),
        seq: ctx.accounts.channel.seq,
        close_at
    });
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
pub struct ChannelCloseFinalizeAccounts<'info> {
    pub executor: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [ESCROW_SEED, config.key().as_ref(), escrow.owner.as_ref()], bump = escrow.bump)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub delegate: Option<Account<'info, Delegate>>,
    /// CHECK: receives channel rent and is pinned to the recorded payer.
    #[account(mut, address = channel.rent_payer)]
    pub rent_payer: UncheckedAccount<'info>,
    #[account(mut, close = rent_payer, seeds = [CHANNEL_SEED, escrow.key().as_ref(), &channel.generation.to_le_bytes(), &channel.seq.to_le_bytes()], bump = channel.bump, constraint = channel.escrow == escrow.key(), constraint = channel.generation == escrow.generation)]
    pub channel: Account<'info, Channel>,
}

pub fn handle_channel_close_finalize(ctx: Context<ChannelCloseFinalizeAccounts>) -> Result<()> {
    require!(
        ctx.accounts.channel.status == ChannelStatus::Closing,
        PayError::ChannelNotOpen
    );
    let now = Clock::get()?.unix_timestamp;
    require!(
        ctx.accounts.executor.key() == ctx.accounts.channel.worker
            || now >= ctx.accounts.channel.close_at,
        PayError::ChannelCloseNotElapsed
    );
    let released = ctx
        .accounts
        .channel
        .cap
        .checked_sub(ctx.accounts.channel.redeemed)
        .ok_or(PayError::ArithmeticOverflow)?;
    ctx.accounts.escrow.committed = ctx
        .accounts
        .escrow
        .committed
        .checked_sub(released)
        .ok_or(PayError::ArithmeticOverflow)?;
    ctx.accounts.escrow.open_channels = ctx
        .accounts
        .escrow
        .open_channels
        .checked_sub(1)
        .ok_or(PayError::ArithmeticOverflow)?;
    if let Some(delegate_key) = ctx.accounts.channel.delegate {
        let delegate = ctx
            .accounts
            .delegate
            .as_mut()
            .ok_or(PayError::WrongDelegate)?;
        require_keys_eq!(delegate.key(), delegate_key, PayError::WrongDelegate);
        require_keys_eq!(
            delegate.escrow,
            ctx.accounts.escrow.key(),
            PayError::WrongDelegate
        );
        require_keys_eq!(
            delegate.key,
            ctx.accounts.channel.voucher_signer,
            PayError::WrongDelegate
        );
        let (expected, bump) = Pubkey::find_program_address(
            &[
                DELEGATE_SEED,
                ctx.accounts.escrow.key().as_ref(),
                delegate.key.as_ref(),
            ],
            &crate::ID,
        );
        require_keys_eq!(expected, delegate.key(), PayError::WrongDelegate);
        require!(delegate.bump == bump, PayError::WrongDelegate);
        delegate.spent = delegate
            .spent
            .checked_sub(released)
            .ok_or(PayError::ArithmeticOverflow)?;
        delegate.open_channels = delegate
            .open_channels
            .checked_sub(1)
            .ok_or(PayError::ArithmeticOverflow)?;
    } else {
        require!(ctx.accounts.delegate.is_none(), PayError::WrongDelegate);
    }
    emit_cpi!(ChannelClosed {
        channel: ctx.accounts.channel.key(),
        seq: ctx.accounts.channel.seq,
        released,
        by: ctx.accounts.executor.key()
    });
    Ok(())
}

fn authorize_channel_spend(
    signer: Pubkey,
    escrow: &Account<'_, Escrow>,
    delegate: Option<&mut Account<'_, Delegate>>,
    amount: u64,
    now: i64,
) -> Result<Option<Pubkey>> {
    if signer == escrow.owner {
        require!(delegate.is_none(), PayError::WrongDelegate);
        return Ok(None);
    }
    let delegate = delegate.ok_or(PayError::Unauthorized)?;
    require_keys_eq!(delegate.escrow, escrow.key(), PayError::WrongDelegate);
    require_keys_eq!(delegate.key, signer, PayError::Unauthorized);
    require!(
        delegate.generation == escrow.generation,
        PayError::DelegateGenerationMismatch
    );
    require!(!delegate.disabled, PayError::DelegateDisabled);
    let expected = Pubkey::find_program_address(
        &[DELEGATE_SEED, escrow.key().as_ref(), signer.as_ref()],
        &crate::ID,
    )
    .0;
    require_keys_eq!(delegate.key(), expected, PayError::WrongDelegate);
    require!(
        delegate.bump
            == Pubkey::find_program_address(
                &[DELEGATE_SEED, escrow.key().as_ref(), signer.as_ref()],
                &crate::ID
            )
            .1,
        PayError::WrongDelegate
    );
    require!(now < delegate.expires_at, PayError::DelegateExpired);
    require!(
        delegate.flags & DELEGATE_OPEN_CHANNEL != 0,
        PayError::DelegateFlagMissing
    );
    delegate.spent = delegate
        .spent
        .checked_add(amount)
        .ok_or(PayError::ArithmeticOverflow)?;
    require!(
        delegate.spent <= delegate.cap_total,
        PayError::DelegateCapExceeded
    );
    Ok(Some(delegate.key()))
}

fn verify_voucher(
    instructions_sysvar: &UncheckedAccount<'_>,
    channel: &Account<'_, Channel>,
    owner: Pubkey,
    cumulative_total: u64,
) -> Result<()> {
    let ix = solana_instructions_sysvar::get_instruction_relative(
        -1,
        &instructions_sysvar.to_account_info(),
    )
    .map_err(|_| error!(PayError::InvalidEd25519Instruction))?;
    require_keys_eq!(
        ix.program_id,
        solana_sdk_ids::ed25519_program::ID,
        PayError::InvalidEd25519Instruction
    );
    require!(ix.accounts.is_empty(), PayError::InvalidEd25519Instruction);
    let data = ix.data;
    require!(
        data.len() >= 16 && data[0] == 1,
        PayError::InvalidEd25519Instruction
    );
    let read_u16 = |offset: usize| -> u16 { u16::from_le_bytes([data[offset], data[offset + 1]]) };
    let signature_offset = read_u16(2) as usize;
    let signature_ix = read_u16(4);
    let pubkey_offset = read_u16(6) as usize;
    let pubkey_ix = read_u16(8);
    let message_offset = read_u16(10) as usize;
    let message_size = read_u16(12) as usize;
    let message_ix = read_u16(14);
    require!(
        signature_ix == u16::MAX && pubkey_ix == u16::MAX && message_ix == u16::MAX,
        PayError::InvalidEd25519Instruction
    );
    require!(
        message_size == VOUCHER_MESSAGE_LEN,
        PayError::InvalidEd25519Instruction
    );
    require!(
        signature_offset
            .checked_add(64)
            .is_some_and(|end| end <= data.len()),
        PayError::InvalidEd25519Instruction
    );
    require!(
        pubkey_offset
            .checked_add(32)
            .is_some_and(|end| end <= data.len()),
        PayError::InvalidEd25519Instruction
    );
    require!(
        message_offset
            .checked_add(message_size)
            .is_some_and(|end| end <= data.len()),
        PayError::InvalidEd25519Instruction
    );
    let signer = Pubkey::try_from(&data[pubkey_offset..pubkey_offset + 32])
        .map_err(|_| error!(PayError::InvalidEd25519Instruction))?;
    require!(
        signer == channel.voucher_signer || signer == owner,
        PayError::InvalidVoucherSigner
    );
    let mut expected = [0u8; VOUCHER_MESSAGE_LEN];
    expected[..16].copy_from_slice(VOUCHER_DOMAIN);
    expected[16..48].copy_from_slice(crate::ID.as_ref());
    expected[48..80].copy_from_slice(channel.key().as_ref());
    expected[80..].copy_from_slice(&cumulative_total.to_le_bytes());
    require!(
        data[message_offset..message_offset + message_size] == expected,
        PayError::InvalidVoucherMessage
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transfer_from_vault_to<'info>(
    config: &Account<'info, Config>,
    escrow: &Account<'info, Escrow>,
    vault: &UncheckedAccount<'info>,
    destination: &UncheckedAccount<'info>,
    mint: &UncheckedAccount<'info>,
    token_program: &Program<'info, Token>,
    amount: u64,
    decimals: u8,
) -> Result<()> {
    let config_key = config.key();
    let owner_key = escrow.owner;
    let bump = [escrow.bump];
    let signer_seeds: &[&[u8]] = &[ESCROW_SEED, config_key.as_ref(), owner_key.as_ref(), &bump];
    token::transfer_checked(
        CpiContext::new_with_signer(
            token_program.key(),
            TransferChecked {
                from: vault.to_account_info(),
                mint: mint.to_account_info(),
                to: destination.to_account_info(),
                authority: escrow.to_account_info(),
            },
            &[signer_seeds],
        ),
        amount,
        decimals,
    )
}

#[allow(clippy::too_many_arguments)]
fn transfer_from_vault<'info>(
    config: &Account<'info, Config>,
    escrow: &Account<'info, Escrow>,
    owner: &Signer<'info>,
    vault: &UncheckedAccount<'info>,
    destination: &UncheckedAccount<'info>,
    mint: &UncheckedAccount<'info>,
    token_program: &Program<'info, Token>,
    amount: u64,
    decimals: u8,
) -> Result<()> {
    let config_key = config.key();
    let owner_key = owner.key();
    let bump = [escrow.bump];
    let signer_seeds: &[&[u8]] = &[ESCROW_SEED, config_key.as_ref(), owner_key.as_ref(), &bump];
    token::transfer_checked(
        CpiContext::new_with_signer(
            token_program.key(),
            TransferChecked {
                from: vault.to_account_info(),
                mint: mint.to_account_info(),
                to: destination.to_account_info(),
                authority: escrow.to_account_info(),
            },
            &[signer_seeds],
        ),
        amount,
        decimals,
    )
}

fn load_mint(account: &UncheckedAccount<'_>) -> Result<SplMint> {
    require_keys_eq!(
        *account.to_account_info().owner,
        anchor_spl::token::ID,
        PayError::InvalidMintOwner
    );
    SplMint::unpack(&account.try_borrow_data()?).map_err(|_| error!(PayError::InvalidMintOwner))
}

fn load_token(account: &UncheckedAccount<'_>) -> Result<SplTokenAccount> {
    require_keys_eq!(
        *account.to_account_info().owner,
        anchor_spl::token::ID,
        PayError::InvalidTokenProgram
    );
    SplTokenAccount::unpack(&account.try_borrow_data()?)
        .map_err(|_| error!(PayError::InvalidTokenProgram))
}

fn require_token(account: &SplTokenAccount, mint: Pubkey, owner: Pubkey) -> Result<()> {
    require_keys_eq!(account.mint, mint, PayError::WrongMint);
    require_keys_eq!(account.owner, owner, PayError::WrongTokenOwner);
    Ok(())
}
