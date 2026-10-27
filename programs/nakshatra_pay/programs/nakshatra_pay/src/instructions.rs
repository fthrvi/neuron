use anchor_lang::prelude::*;
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
    state::{Config, Escrow, PendingConfig, PendingWithdrawal},
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
pub struct EscrowInitAccounts<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
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
    let escrow = &mut ctx.accounts.escrow;
    escrow.owner = ctx.accounts.owner.key();
    escrow.vault = ctx.accounts.vault.key();
    escrow.committed = 0;
    escrow.open_channels = 0;
    escrow.open_tasks = 0;
    escrow.channel_seq = 0;
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
