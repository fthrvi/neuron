use std::str::FromStr;

use anchor_lang::{
    prelude::{Clock, Pubkey},
    solana_program::{instruction::Instruction, program_pack::Pack, system_program},
    AccountDeserialize, AccountSerialize, InstructionData, ToAccountMetas,
};
use anchor_spl::token::spl_token::{
    self, instruction as token_instruction,
    state::{Account as SplAccount, AccountState, Mint as SplMint},
};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use nakshatra_pay::{
    constants::*,
    state::{Config, Escrow},
};

const INITIAL: u64 = 1_000_000;

fn event_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"__event_authority"], &nakshatra_pay::id()).0
}

fn send(svm: &mut LiteSVM, signer: &Keypair, ix: Instruction) -> bool {
    svm.expire_blockhash();
    let message =
        Message::new_with_blockhash(&[ix], Some(&signer.pubkey()), &svm.latest_blockhash());
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(message), &[signer]).unwrap();
    svm.send_transaction(tx).is_ok()
}

fn warp_seconds(svm: &mut LiteSVM, seconds: i64) {
    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp = clock.unix_timestamp.checked_add(seconds).unwrap();
    svm.set_sysvar(&clock);
    svm.expire_blockhash();
}

fn put_mint(svm: &mut LiteSVM, key: Pubkey, owner: Pubkey) {
    let mint = SplMint {
        decimals: 6,
        is_initialized: true,
        ..SplMint::default()
    };
    let mut data = vec![0; SplMint::LEN];
    SplMint::pack(mint, &mut data).unwrap();
    put_data_account(svm, key, owner, data);
}

fn put_token(svm: &mut LiteSVM, key: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let account = SplAccount {
        mint,
        owner,
        amount,
        state: AccountState::Initialized,
        ..SplAccount::default()
    };
    let mut data = vec![0; SplAccount::LEN];
    SplAccount::pack(account, &mut data).unwrap();
    put_data_account(svm, key, spl_token::ID, data);
}

fn put_data_account(svm: &mut LiteSVM, key: Pubkey, owner: Pubkey, data: Vec<u8>) {
    let mut account = svm.get_account(&system_program::ID).unwrap();
    account.lamports = svm.minimum_balance_for_rent_exemption(data.len());
    account.data = data;
    account.owner = owner;
    account.executable = false;
    account.rent_epoch = 0;
    svm.set_account(key, account).unwrap();
}

fn token_amount(svm: &LiteSVM, key: Pubkey) -> u64 {
    SplAccount::unpack(&svm.get_account(&key).unwrap().data)
        .unwrap()
        .amount
}

fn read_config(svm: &LiteSVM, key: Pubkey) -> Config {
    let account = svm.get_account(&key).unwrap();
    Config::try_deserialize(&mut account.data.as_slice()).unwrap()
}

fn read_escrow(svm: &LiteSVM, key: Pubkey) -> Escrow {
    let account = svm.get_account(&key).unwrap();
    Escrow::try_deserialize(&mut account.data.as_slice()).unwrap()
}

fn config_init_ix(
    authority: Pubkey,
    config: Pubkey,
    mint: Pubkey,
    fee_wallet: Pubkey,
    fee_bps: u16,
) -> Instruction {
    Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::ConfigInit { fee_bps }.data(),
        nakshatra_pay::accounts::ConfigInitAccounts {
            authority,
            config,
            mint,
            fee_wallet,
            token_program: spl_token::ID,
            system_program: system_program::ID,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    )
}

struct Fixture {
    svm: LiteSVM,
    authority: Keypair,
    owner: Keypair,
    other: Keypair,
    mint: Pubkey,
    fee_wallet: Pubkey,
    next_fee_wallet: Pubkey,
    source: Pubkey,
    destination: Pubkey,
    other_destination: Pubkey,
    wrong_destination: Pubkey,
    substitute_vault: Pubkey,
    config: Pubkey,
    escrow: Pubkey,
    vault: Pubkey,
}

impl Fixture {
    fn new(init_config: bool, init_escrow: bool) -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program(
            nakshatra_pay::id(),
            include_bytes!(concat!(
                env!("CARGO_TARGET_TMPDIR"),
                "/../deploy/nakshatra_pay.so"
            )),
        )
        .unwrap();
        let authority = Keypair::new();
        let owner = Keypair::new();
        let other = Keypair::new();
        for key in [authority.pubkey(), owner.pubkey(), other.pubkey()] {
            svm.airdrop(&key, 10_000_000_000).unwrap();
        }
        let mint = Pubkey::new_unique();
        let wrong_mint = Pubkey::new_unique();
        put_mint(&mut svm, mint, spl_token::ID);
        put_mint(&mut svm, wrong_mint, spl_token::ID);
        let fee_wallet = Pubkey::new_unique();
        let next_fee_wallet = Pubkey::new_unique();
        let source = Pubkey::new_unique();
        let destination = Pubkey::new_unique();
        let other_destination = Pubkey::new_unique();
        let wrong_destination = Pubkey::new_unique();
        let substitute_vault = Pubkey::new_unique();
        put_token(&mut svm, fee_wallet, mint, authority.pubkey(), 0);
        put_token(&mut svm, next_fee_wallet, mint, authority.pubkey(), 0);
        put_token(&mut svm, source, mint, owner.pubkey(), INITIAL);
        put_token(&mut svm, destination, mint, owner.pubkey(), 0);
        put_token(&mut svm, other_destination, mint, other.pubkey(), 0);
        put_token(&mut svm, wrong_destination, wrong_mint, owner.pubkey(), 0);
        put_token(&mut svm, substitute_vault, mint, owner.pubkey(), 0);
        let config = Pubkey::find_program_address(&[CONFIG_SEED], &nakshatra_pay::id()).0;
        let escrow = Pubkey::find_program_address(
            &[ESCROW_SEED, config.as_ref(), owner.pubkey().as_ref()],
            &nakshatra_pay::id(),
        )
        .0;
        let vault =
            Pubkey::find_program_address(&[VAULT_SEED, escrow.as_ref()], &nakshatra_pay::id()).0;
        if init_config {
            assert!(send(
                &mut svm,
                &authority,
                config_init_ix(
                    authority.pubkey(),
                    config,
                    mint,
                    fee_wallet,
                    DEFAULT_FEE_BPS
                )
            ));
        }
        if init_escrow {
            let ix = Instruction::new_with_bytes(
                nakshatra_pay::id(),
                &nakshatra_pay::instruction::EscrowInit {}.data(),
                nakshatra_pay::accounts::EscrowInitAccounts {
                    owner: owner.pubkey(),
                    config,
                    mint,
                    escrow,
                    vault,
                    token_program: spl_token::ID,
                    system_program: system_program::ID,
                    event_authority: event_authority(),
                    program: nakshatra_pay::id(),
                }
                .to_account_metas(None),
            );
            assert!(send(&mut svm, &owner, ix));
        }
        Self {
            svm,
            authority,
            owner,
            other,
            mint,
            fee_wallet,
            next_fee_wallet,
            source,
            destination,
            other_destination,
            wrong_destination,
            substitute_vault,
            config,
            escrow,
            vault,
        }
    }

    fn deposit_ix(&self, amount: u64) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowDeposit { amount }.data(),
            nakshatra_pay::accounts::EscrowDepositAccounts {
                owner: self.owner.pubkey(),
                config: self.config,
                mint: self.mint,
                escrow: self.escrow,
                source: self.source,
                vault: self.vault,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn request_ix(
        &self,
        signer: Pubkey,
        escrow: Pubkey,
        vault: Pubkey,
        amount: u64,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowWithdrawRequest { amount }.data(),
            nakshatra_pay::accounts::EscrowOwnerAccounts {
                owner: signer,
                config: self.config,
                escrow,
                vault,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn cancel_ix(&self) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowWithdrawCancel {}.data(),
            nakshatra_pay::accounts::EscrowOwnerAccounts {
                owner: self.owner.pubkey(),
                config: self.config,
                escrow: self.escrow,
                vault: self.vault,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn execute_ix(
        &self,
        signer: Pubkey,
        escrow: Pubkey,
        vault: Pubkey,
        destination: Pubkey,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowWithdrawExecute {}.data(),
            nakshatra_pay::accounts::EscrowWithdrawExecuteAccounts {
                owner: signer,
                config: self.config,
                mint: self.mint,
                escrow,
                vault,
                destination,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn close_ix(
        &self,
        signer: Pubkey,
        escrow: Pubkey,
        vault: Pubkey,
        destination: Pubkey,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowClose {}.data(),
            nakshatra_pay::accounts::EscrowCloseAccounts {
                owner: signer,
                config: self.config,
                mint: self.mint,
                escrow,
                vault,
                destination,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }
}

macro_rules! owner_tx {
    ($fixture:ident, $instruction:expr) => {{
        let instruction = $instruction;
        send(&mut $fixture.svm, &$fixture.owner, instruction)
    }};
}

macro_rules! other_tx {
    ($fixture:ident, $instruction:expr) => {{
        let instruction = $instruction;
        send(&mut $fixture.svm, &$fixture.other, instruction)
    }};
}

#[test]
fn m0_init_limits_singleton_and_token_2022_rejection() {
    let mut f = Fixture::new(false, false);
    assert!(!send(
        &mut f.svm,
        &f.authority,
        config_init_ix(
            f.authority.pubkey(),
            f.config,
            f.mint,
            f.fee_wallet,
            FEE_BPS_MAX + 1
        )
    ));
    assert!(send(
        &mut f.svm,
        &f.authority,
        config_init_ix(
            f.authority.pubkey(),
            f.config,
            f.mint,
            f.fee_wallet,
            DEFAULT_FEE_BPS
        )
    ));
    assert_eq!(read_config(&f.svm, f.config).fee_bps, 300);
    assert!(!send(
        &mut f.svm,
        &f.authority,
        config_init_ix(
            f.authority.pubkey(),
            f.config,
            f.mint,
            f.fee_wallet,
            DEFAULT_FEE_BPS
        )
    ));

    let mut g = Fixture::new(false, false);
    let token_2022 = Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb").unwrap();
    let mint_2022 = Pubkey::new_unique();
    put_mint(&mut g.svm, mint_2022, token_2022);
    let wallet_2022 = Pubkey::new_unique();
    put_token(&mut g.svm, wallet_2022, mint_2022, g.authority.pubkey(), 0);
    assert!(!send(
        &mut g.svm,
        &g.authority,
        config_init_ix(g.authority.pubkey(), g.config, mint_2022, wallet_2022, 300)
    ));
}

#[test]
fn m0_timelock_cancel_permissions_and_two_step_authority() {
    let mut f = Fixture::new(true, false);
    let propose = |authority, wallet, fee_bps| {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ConfigPropose { fee_bps }.data(),
            nakshatra_pay::accounts::ConfigProposeAccounts {
                authority,
                config: f.config,
                fee_wallet: wallet,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    };
    assert!(!send(
        &mut f.svm,
        &f.other,
        propose(f.other.pubkey(), f.next_fee_wallet, 250)
    ));
    assert!(send(
        &mut f.svm,
        &f.authority,
        propose(f.authority.pubkey(), f.next_fee_wallet, 250)
    ));
    let apply = || {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ConfigApply {}.data(),
            nakshatra_pay::accounts::ConfigApplyAccounts {
                executor: f.owner.pubkey(),
                config: f.config,
                fee_wallet: f.next_fee_wallet,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    };
    assert!(!send(&mut f.svm, &f.owner, apply()));
    warp_seconds(&mut f.svm, CONFIG_DELAY_S - 1);
    assert!(!send(&mut f.svm, &f.owner, apply()));
    warp_seconds(&mut f.svm, 1);
    assert!(send(&mut f.svm, &f.owner, apply()));
    assert_eq!(read_config(&f.svm, f.config).fee_wallet, f.next_fee_wallet);

    assert!(send(
        &mut f.svm,
        &f.authority,
        propose(f.authority.pubkey(), f.fee_wallet, 300)
    ));
    let cancel = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::ConfigCancel {}.data(),
        nakshatra_pay::accounts::ConfigAuthorityAccounts {
            authority: f.authority.pubkey(),
            config: f.config,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(send(&mut f.svm, &f.authority, cancel));
    assert!(read_config(&f.svm, f.config).pending.is_none());

    let propose_auth = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::ConfigProposeAuthority {
            new_authority: f.owner.pubkey(),
        }
        .data(),
        nakshatra_pay::accounts::ConfigAuthorityAccounts {
            authority: f.authority.pubkey(),
            config: f.config,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(send(&mut f.svm, &f.authority, propose_auth));
    let accept = |key| {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ConfigAcceptAuthority {}.data(),
            nakshatra_pay::accounts::ConfigAcceptAuthorityAccounts {
                new_authority: key,
                config: f.config,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    };
    assert!(!send(&mut f.svm, &f.other, accept(f.other.pubkey())));
    assert!(send(&mut f.svm, &f.owner, accept(f.owner.pubkey())));
    assert_eq!(read_config(&f.svm, f.config).authority, f.owner.pubkey());
}

#[test]
fn m1_deposit_request_exact_window_and_balances() {
    let mut f = Fixture::new(true, true);
    assert!(owner_tx!(f, f.deposit_ix(700)));
    assert_eq!(token_amount(&f.svm, f.source), INITIAL - 700);
    assert_eq!(token_amount(&f.svm, f.vault), 700);
    assert!(owner_tx!(
        f,
        f.request_ix(f.owner.pubkey(), f.escrow, f.vault, 300)
    ));
    warp_seconds(&mut f.svm, WITHDRAW_DELAY_S - 1);
    assert!(!owner_tx!(
        f,
        f.execute_ix(f.owner.pubkey(), f.escrow, f.vault, f.destination)
    ));
    warp_seconds(&mut f.svm, 1);
    assert!(owner_tx!(
        f,
        f.execute_ix(f.owner.pubkey(), f.escrow, f.vault, f.destination)
    ));
    assert_eq!(token_amount(&f.svm, f.destination), 300);
    assert_eq!(token_amount(&f.svm, f.vault), 400);
}

#[test]
fn m1_requests_replace_cancel_and_check_available_at_execute() {
    let mut f = Fixture::new(true, true);
    assert!(owner_tx!(f, f.deposit_ix(100)));
    assert!(owner_tx!(
        f,
        f.request_ix(f.owner.pubkey(), f.escrow, f.vault, 90)
    ));
    let first = read_escrow(&f.svm, f.escrow)
        .pending_withdraw
        .unwrap()
        .withdraw_at;
    warp_seconds(&mut f.svm, 10);
    assert!(owner_tx!(
        f,
        f.request_ix(f.owner.pubkey(), f.escrow, f.vault, 110)
    ));
    let second = read_escrow(&f.svm, f.escrow).pending_withdraw.unwrap();
    assert_eq!(second.amount, 110);
    assert!(second.withdraw_at > first);
    warp_seconds(&mut f.svm, WITHDRAW_DELAY_S);
    assert!(!owner_tx!(
        f,
        f.execute_ix(f.owner.pubkey(), f.escrow, f.vault, f.destination)
    ));
    assert!(owner_tx!(f, f.cancel_ix()));
    assert!(!owner_tx!(
        f,
        f.execute_ix(f.owner.pubkey(), f.escrow, f.vault, f.destination)
    ));
}

#[test]
fn m1_raw_transfer_is_counted_and_security_constraints_hold() {
    let mut f = Fixture::new(true, true);
    let raw = token_instruction::transfer_checked(
        &spl_token::ID,
        &f.source,
        &f.mint,
        &f.vault,
        &f.owner.pubkey(),
        &[],
        222,
        6,
    )
    .unwrap();
    assert!(send(&mut f.svm, &f.owner, raw));
    assert_eq!(token_amount(&f.svm, f.vault), 222);
    assert!(!other_tx!(
        f,
        f.request_ix(f.other.pubkey(), f.escrow, f.vault, 1)
    ));
    assert!(!owner_tx!(
        f,
        f.request_ix(f.owner.pubkey(), f.escrow, f.substitute_vault, 1)
    ));
    assert!(owner_tx!(
        f,
        f.request_ix(f.owner.pubkey(), f.escrow, f.vault, 222)
    ));
    warp_seconds(&mut f.svm, WITHDRAW_DELAY_S);
    assert!(!other_tx!(
        f,
        f.execute_ix(f.other.pubkey(), f.escrow, f.vault, f.other_destination)
    ));
    assert!(!owner_tx!(
        f,
        f.execute_ix(f.owner.pubkey(), f.escrow, f.vault, f.other_destination)
    ));
    assert!(!owner_tx!(
        f,
        f.execute_ix(f.owner.pubkey(), f.escrow, f.vault, f.wrong_destination)
    ));
    assert!(owner_tx!(
        f,
        f.execute_ix(f.owner.pubkey(), f.escrow, f.vault, f.destination)
    ));
    assert_eq!(token_amount(&f.svm, f.destination), 222);
}

#[test]
fn m1_close_enforces_window_sweeps_funds_and_returns_rent() {
    let mut f = Fixture::new(true, true);
    assert!(owner_tx!(f, f.deposit_ix(444)));
    assert!(owner_tx!(
        f,
        f.request_ix(f.owner.pubkey(), f.escrow, f.vault, 1)
    ));
    assert!(!owner_tx!(
        f,
        f.close_ix(f.owner.pubkey(), f.escrow, f.vault, f.destination)
    ));
    assert!(!other_tx!(
        f,
        f.close_ix(f.other.pubkey(), f.escrow, f.vault, f.other_destination)
    ));
    warp_seconds(&mut f.svm, WITHDRAW_DELAY_S);
    let before = f.svm.get_account(&f.owner.pubkey()).unwrap().lamports;
    assert!(owner_tx!(
        f,
        f.close_ix(f.owner.pubkey(), f.escrow, f.vault, f.destination)
    ));
    assert_eq!(token_amount(&f.svm, f.destination), 444);
    assert!(f.svm.get_account(&f.vault).is_none());
    assert!(f.svm.get_account(&f.escrow).is_none());
    assert!(f.svm.get_account(&f.owner.pubkey()).unwrap().lamports > before);
}

#[test]
fn m1_fake_config_owned_by_another_program_is_rejected() {
    let mut f = Fixture::new(true, false);
    let fake = Pubkey::new_unique();
    let real = read_config(&f.svm, f.config);
    let mut data = Vec::new();
    real.try_serialize(&mut data).unwrap();
    put_data_account(&mut f.svm, fake, Pubkey::new_unique(), data);
    let fake_escrow = Pubkey::find_program_address(
        &[ESCROW_SEED, fake.as_ref(), f.owner.pubkey().as_ref()],
        &nakshatra_pay::id(),
    )
    .0;
    let fake_vault =
        Pubkey::find_program_address(&[VAULT_SEED, fake_escrow.as_ref()], &nakshatra_pay::id()).0;
    let ix = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::EscrowInit {}.data(),
        nakshatra_pay::accounts::EscrowInitAccounts {
            owner: f.owner.pubkey(),
            config: fake,
            mint: f.mint,
            escrow: fake_escrow,
            vault: fake_vault,
            token_program: spl_token::ID,
            system_program: system_program::ID,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(!send(&mut f.svm, &f.owner, ix));
}

#[test]
fn core_guarantee_owner_always_gets_every_token_out_without_a_nakshatra_signer() {
    let mut f = Fixture::new(true, true);
    assert!(owner_tx!(f, f.deposit_ix(INITIAL)));
    assert!(owner_tx!(
        f,
        f.request_ix(f.owner.pubkey(), f.escrow, f.vault, INITIAL)
    ));
    warp_seconds(&mut f.svm, WITHDRAW_DELAY_S);
    assert!(owner_tx!(
        f,
        f.execute_ix(f.owner.pubkey(), f.escrow, f.vault, f.destination)
    ));
    assert_eq!(token_amount(&f.svm, f.destination), INITIAL);
    assert_eq!(token_amount(&f.svm, f.vault), 0);
}
