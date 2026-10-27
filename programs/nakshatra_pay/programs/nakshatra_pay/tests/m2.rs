use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anchor_lang::{
    prelude::{Clock, Pubkey},
    solana_program::{
        bpf_loader_upgradeable::{self, UpgradeableLoaderState},
        instruction::{AccountMeta, Instruction},
        program_pack::Pack,
        system_instruction, system_program,
    },
    AccountDeserialize, InstructionData, ToAccountMetas,
};
use anchor_spl::token::spl_token::{
    self,
    state::{Account as SplAccount, AccountState, Mint as SplMint},
};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use nakshatra_pay::{
    constants::*,
    state::{Channel, Delegate, Escrow, Task, Verdict},
};

const DEPOSIT: u64 = 1_000_000;
const CPI_PROGRAM_ID: Pubkey = Pubkey::new_from_array([7u8; 32]);

fn program_binary_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/nakshatra_pay.so")
}

fn cpi_program_binary_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/redeem_cpi.so")
}

fn newest_source_mtime(path: &Path) -> std::time::SystemTime {
    fn visit(path: &Path, newest: &mut Option<std::time::SystemTime>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, newest);
            } else {
                let modified = fs::metadata(path).unwrap().modified().unwrap();
                *newest = Some(newest.map_or(modified, |old| old.max(modified)));
            }
        }
    }
    let mut newest = None;
    visit(path, &mut newest);
    newest.unwrap()
}

fn assert_program_is_fresh() {
    static CHECK: OnceLock<()> = OnceLock::new();
    CHECK.get_or_init(|| {
        let binary = program_binary_path();
        let built = fs::metadata(&binary)
            .and_then(|metadata| metadata.modified())
            .unwrap_or_else(|_| {
                panic!("{} is missing; run `anchor build` first", binary.display())
            });
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        assert!(
            built >= newest_source_mtime(&source),
            "{} is older than program source; run `anchor build` first",
            binary.display()
        );
        let cpi_binary = cpi_program_binary_path();
        let cpi_built = fs::metadata(&cpi_binary)
            .and_then(|metadata| metadata.modified())
            .unwrap_or_else(|_| {
                panic!(
                    "{} is missing; run `./scripts/test.sh` first",
                    cpi_binary.display()
                )
            });
        let cpi_source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-support/redeem-cpi/src");
        assert!(
            cpi_built >= newest_source_mtime(&cpi_source),
            "{} is older than CPI test-program source; run `./scripts/test.sh` first",
            cpi_binary.display()
        );
    });
}

fn program_data_address() -> Pubkey {
    Pubkey::find_program_address(&[nakshatra_pay::id().as_ref()], &bpf_loader_upgradeable::ID).0
}

fn event_authority() -> Pubkey {
    Pubkey::find_program_address(&[b"__event_authority"], &nakshatra_pay::id()).0
}

fn set_program_upgrade_authority(svm: &mut LiteSVM, authority: Pubkey) {
    let address = program_data_address();
    let mut account = svm.get_account(&address).unwrap();
    let metadata_len = UpgradeableLoaderState::size_of_programdata_metadata();
    let clock: Clock = svm.get_sysvar();
    bincode::serialize_into(
        &mut account.data[..metadata_len],
        &UpgradeableLoaderState::ProgramData {
            slot: clock.slot,
            upgrade_authority_address: Some(authority),
        },
    )
    .unwrap();
    svm.set_account(address, account).unwrap();
}

fn send_ixs(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction]) -> bool {
    svm.expire_blockhash();
    let message = Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &svm.latest_blockhash());
    let Ok(tx) = VersionedTransaction::try_new(VersionedMessage::Legacy(message), &[payer]) else {
        return false;
    };
    svm.send_transaction(tx).is_ok()
}

fn warp_seconds(svm: &mut LiteSVM, seconds: i64) {
    let mut clock: Clock = svm.get_sysvar();
    clock.unix_timestamp += seconds;
    svm.set_sysvar(&clock);
    svm.expire_blockhash();
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

fn put_mint(svm: &mut LiteSVM, key: Pubkey) {
    let mint = SplMint {
        decimals: 6,
        is_initialized: true,
        ..SplMint::default()
    };
    let mut data = vec![0; SplMint::LEN];
    SplMint::pack(mint, &mut data).unwrap();
    put_data_account(svm, key, spl_token::ID, data);
}

fn put_token(svm: &mut LiteSVM, key: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let token = SplAccount {
        mint,
        owner,
        amount,
        state: AccountState::Initialized,
        ..SplAccount::default()
    };
    let mut data = vec![0; SplAccount::LEN];
    SplAccount::pack(token, &mut data).unwrap();
    put_data_account(svm, key, spl_token::ID, data);
}

fn token_amount(svm: &LiteSVM, key: Pubkey) -> u64 {
    SplAccount::unpack(&svm.get_account(&key).unwrap().data)
        .unwrap()
        .amount
}

fn freeze_token(svm: &mut LiteSVM, key: Pubkey) {
    let mut account = svm.get_account(&key).unwrap();
    let mut token = SplAccount::unpack(&account.data).unwrap();
    token.state = AccountState::Frozen;
    SplAccount::pack(token, &mut account.data).unwrap();
    svm.set_account(key, account).unwrap();
}

fn close_account_for_test(svm: &mut LiteSVM, key: Pubkey) {
    let mut account = svm.get_account(&system_program::ID).unwrap();
    account.lamports = 0;
    account.data.clear();
    account.owner = system_program::ID;
    account.executable = false;
    svm.set_account(key, account).unwrap();
}

fn read_escrow(svm: &LiteSVM, key: Pubkey) -> Escrow {
    Escrow::try_deserialize(&mut svm.get_account(&key).unwrap().data.as_slice()).unwrap()
}

fn read_delegate(svm: &LiteSVM, key: Pubkey) -> Delegate {
    Delegate::try_deserialize(&mut svm.get_account(&key).unwrap().data.as_slice()).unwrap()
}

fn read_channel(svm: &LiteSVM, key: Pubkey) -> Channel {
    Channel::try_deserialize(&mut svm.get_account(&key).unwrap().data.as_slice()).unwrap()
}

fn read_task(svm: &LiteSVM, key: Pubkey) -> Task {
    Task::try_deserialize(&mut svm.get_account(&key).unwrap().data.as_slice()).unwrap()
}

fn voucher_message(program: Pubkey, channel: Pubkey, total: u64) -> [u8; VOUCHER_MESSAGE_LEN] {
    let mut message = [0u8; VOUCHER_MESSAGE_LEN];
    message[..16].copy_from_slice(VOUCHER_DOMAIN);
    message[16..48].copy_from_slice(program.as_ref());
    message[48..80].copy_from_slice(channel.as_ref());
    message[80..].copy_from_slice(&total.to_le_bytes());
    message
}

fn verdict_message(
    program: Pubkey,
    task: Pubkey,
    result_hash: [u8; 32],
    verdict: Verdict,
) -> [u8; VERDICT_MESSAGE_LEN] {
    let mut message = [0u8; VERDICT_MESSAGE_LEN];
    message[..16].copy_from_slice(VERDICT_DOMAIN);
    message[16..48].copy_from_slice(program.as_ref());
    message[48..80].copy_from_slice(task.as_ref());
    message[80..112].copy_from_slice(&result_hash);
    message[112] = verdict as u8;
    message
}

// This is the fixed layout produced by Solana's ed25519 instruction helper.
fn ed25519_ix(signer: &Keypair, message: &[u8]) -> Instruction {
    let signature = signer.sign_message(message);
    let public_key_offset = 16u16;
    let signature_offset = 48u16;
    let message_offset = 112u16;
    let mut data = vec![1, 0];
    for value in [
        signature_offset,
        u16::MAX,
        public_key_offset,
        u16::MAX,
        message_offset,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&value.to_le_bytes());
    }
    data.extend_from_slice(signer.pubkey().as_ref());
    data.extend_from_slice(signature.as_ref());
    data.extend_from_slice(message);
    Instruction {
        program_id: solana_sdk_ids::ed25519_program::ID,
        accounts: vec![],
        data,
    }
}

struct Fixture {
    svm: LiteSVM,
    authority: Keypair,
    owner: Keypair,
    delegate: Keypair,
    worker: Keypair,
    other: Keypair,
    mint: Pubkey,
    fee_wallet: Pubkey,
    fee_vault: Pubkey,
    owner_state: Pubkey,
    owner_destination: Pubkey,
    worker_token: Pubkey,
    wrong_worker_token: Pubkey,
    config: Pubkey,
    escrow: Pubkey,
    vault: Pubkey,
}

impl Fixture {
    fn new() -> Self {
        Self::new_with_prefund(false)
    }

    fn new_with_prefund(prefund: bool) -> Self {
        assert_program_is_fresh();
        let mut svm = LiteSVM::new();
        let authority = Keypair::new();
        let owner = Keypair::new();
        let delegate = Keypair::new();
        let worker = Keypair::new();
        let other = Keypair::new();
        svm.add_program(
            nakshatra_pay::id(),
            &fs::read(program_binary_path()).unwrap(),
        )
        .unwrap();
        svm.add_program(
            CPI_PROGRAM_ID,
            &fs::read(cpi_program_binary_path()).unwrap(),
        )
        .unwrap();
        set_program_upgrade_authority(&mut svm, authority.pubkey());
        for key in [
            authority.pubkey(),
            owner.pubkey(),
            delegate.pubkey(),
            worker.pubkey(),
            other.pubkey(),
        ] {
            svm.airdrop(&key, 10_000_000_000).unwrap();
        }
        let mint = Pubkey::new_unique();
        put_mint(&mut svm, mint);
        let fee_wallet = Pubkey::new_unique();
        let source = Pubkey::new_unique();
        let owner_destination = Pubkey::new_unique();
        let worker_token = Pubkey::new_unique();
        let wrong_worker_token = Pubkey::new_unique();
        put_token(&mut svm, fee_wallet, mint, authority.pubkey(), 0);
        put_token(&mut svm, source, mint, owner.pubkey(), DEPOSIT);
        put_token(&mut svm, owner_destination, mint, owner.pubkey(), 0);
        put_token(&mut svm, worker_token, mint, worker.pubkey(), 0);
        put_token(&mut svm, wrong_worker_token, mint, other.pubkey(), 0);
        let config = Pubkey::find_program_address(&[CONFIG_SEED], &nakshatra_pay::id()).0;
        let fee_vault =
            Pubkey::find_program_address(&[FEE_VAULT_SEED, config.as_ref()], &nakshatra_pay::id())
                .0;
        let escrow = Pubkey::find_program_address(
            &[ESCROW_SEED, config.as_ref(), owner.pubkey().as_ref()],
            &nakshatra_pay::id(),
        )
        .0;
        let vault =
            Pubkey::find_program_address(&[VAULT_SEED, escrow.as_ref()], &nakshatra_pay::id()).0;
        let owner_state = Pubkey::find_program_address(
            &[OWNER_STATE_SEED, config.as_ref(), owner.pubkey().as_ref()],
            &nakshatra_pay::id(),
        )
        .0;
        if prefund {
            let delegate_pda = Pubkey::find_program_address(
                &[DELEGATE_SEED, escrow.as_ref(), delegate.pubkey().as_ref()],
                &nakshatra_pay::id(),
            )
            .0;
            let channel_pda = Pubkey::find_program_address(
                &[
                    CHANNEL_SEED,
                    escrow.as_ref(),
                    &0u64.to_le_bytes(),
                    &0u64.to_le_bytes(),
                ],
                &nakshatra_pay::id(),
            )
            .0;
            for pda in [
                config,
                fee_vault,
                owner_state,
                escrow,
                vault,
                delegate_pda,
                channel_pda,
            ] {
                assert!(send_ixs(
                    &mut svm,
                    &other,
                    &[system_instruction::transfer(&other.pubkey(), &pda, 1)]
                ));
            }
        }
        let config_ix = Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ConfigInit {
                fee_bps: DEFAULT_FEE_BPS,
            }
            .data(),
            nakshatra_pay::accounts::ConfigInitAccounts {
                authority: authority.pubkey(),
                config,
                program_data: program_data_address(),
                mint,
                fee_wallet,
                fee_vault,
                token_program: spl_token::ID,
                system_program: system_program::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        );
        assert!(send_ixs(&mut svm, &authority, &[config_ix]));
        let init_ix = Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowInit {}.data(),
            nakshatra_pay::accounts::EscrowInitAccounts {
                owner: owner.pubkey(),
                config,
                owner_state,
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
        assert!(send_ixs(&mut svm, &owner, &[init_ix]));
        let deposit_ix = Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowDeposit { amount: DEPOSIT }.data(),
            nakshatra_pay::accounts::EscrowDepositAccounts {
                owner: owner.pubkey(),
                config,
                mint,
                escrow,
                source,
                vault,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        );
        assert!(send_ixs(&mut svm, &owner, &[deposit_ix]));
        Self {
            svm,
            authority,
            owner,
            delegate,
            worker,
            other,
            mint,
            fee_wallet,
            fee_vault,
            owner_state,
            owner_destination,
            worker_token,
            wrong_worker_token,
            config,
            escrow,
            vault,
        }
    }

    fn delegate_pda(&self, key: Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[DELEGATE_SEED, self.escrow.as_ref(), key.as_ref()],
            &nakshatra_pay::id(),
        )
        .0
    }

    fn channel_pda(&self, seq: u64) -> Pubkey {
        let generation = read_escrow(&self.svm, self.escrow).generation;
        Pubkey::find_program_address(
            &[
                CHANNEL_SEED,
                self.escrow.as_ref(),
                &generation.to_le_bytes(),
                &seq.to_le_bytes(),
            ],
            &nakshatra_pay::id(),
        )
        .0
    }

    fn task_pda(&self, task_hash: [u8; 32]) -> Pubkey {
        let generation = read_escrow(&self.svm, self.escrow).generation;
        Pubkey::find_program_address(
            &[
                TASK_SEED,
                self.escrow.as_ref(),
                &generation.to_le_bytes(),
                &task_hash,
            ],
            &nakshatra_pay::id(),
        )
        .0
    }

    fn delegate_set_ix(
        &self,
        key: Pubkey,
        cap_total: u64,
        expires_at: i64,
        flags: u8,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::DelegateSet {
                key,
                cap_total,
                expires_at,
                flags,
            }
            .data(),
            nakshatra_pay::accounts::DelegateSetAccounts {
                owner: self.owner.pubkey(),
                config: self.config,
                escrow: self.escrow,
                delegate: self.delegate_pda(key),
                system_program: system_program::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn delegate_revoke_ix(&self, key: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::DelegateRevoke { key }.data(),
            nakshatra_pay::accounts::DelegateRevokeAccounts {
                owner: self.owner.pubkey(),
                config: self.config,
                escrow: self.escrow,
                delegate: self.delegate_pda(key),
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn delegate_close_ix(&self, executor: Pubkey, key: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::DelegateClose {}.data(),
            nakshatra_pay::accounts::DelegateCloseAccounts {
                executor,
                config: self.config,
                escrow: self.escrow,
                owner: self.owner.pubkey(),
                delegate: self.delegate_pda(key),
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn fee_withdraw_ix(&self, authority: Pubkey, amount: u64) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::FeeWithdraw { amount }.data(),
            nakshatra_pay::accounts::FeeWithdrawAccounts {
                authority,
                config: self.config,
                mint: self.mint,
                fee_vault: self.fee_vault,
                fee_wallet: self.fee_wallet,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn open_ix(
        &self,
        signer: Pubkey,
        delegate: Option<Pubkey>,
        worker: Pubkey,
        cap: u64,
        seq: u64,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ChannelOpen { worker, cap }.data(),
            nakshatra_pay::accounts::ChannelOpenAccounts {
                signer,
                config: self.config,
                escrow: self.escrow,
                vault: self.vault,
                delegate,
                channel: self.channel_pda(seq),
                system_program: system_program::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn fund_ix(
        &self,
        signer: Pubkey,
        delegate: Option<Pubkey>,
        channel: Pubkey,
        add: u64,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ChannelFund { add }.data(),
            nakshatra_pay::accounts::ChannelFundAccounts {
                signer,
                config: self.config,
                escrow: self.escrow,
                vault: self.vault,
                delegate,
                channel,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn redeem_ix(
        &self,
        by: Pubkey,
        channel: Pubkey,
        total: u64,
        worker_token: Pubkey,
        fee_vault: Pubkey,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ChannelRedeem {
                cumulative_total: total,
            }
            .data(),
            nakshatra_pay::accounts::ChannelRedeemAccounts {
                by,
                config: self.config,
                mint: self.mint,
                escrow: self.escrow,
                channel,
                vault: self.vault,
                worker_token,
                fee_vault,
                instructions_sysvar: solana_instructions_sysvar::ID,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn close_request_ix(&self, signer: Pubkey, channel: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ChannelCloseRequest {}.data(),
            nakshatra_pay::accounts::ChannelCloseRequestAccounts {
                signer,
                config: self.config,
                escrow: self.escrow,
                channel,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn close_finalize_ix(
        &self,
        executor: Pubkey,
        delegate: Option<Pubkey>,
        rent_payer: Pubkey,
        channel: Pubkey,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::ChannelCloseFinalize {}.data(),
            nakshatra_pay::accounts::ChannelCloseFinalizeAccounts {
                executor,
                config: self.config,
                escrow: self.escrow,
                delegate,
                rent_payer,
                channel,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn redeem_with(
        &mut self,
        tx_payer: &Keypair,
        voucher_signer: &Keypair,
        channel: Pubkey,
        total: u64,
    ) -> bool {
        let ed = ed25519_ix(
            voucher_signer,
            &voucher_message(nakshatra_pay::id(), channel, total),
        );
        let redeem = self.redeem_ix(
            tx_payer.pubkey(),
            channel,
            total,
            self.worker_token,
            self.fee_vault,
        );
        send_ixs(&mut self.svm, tx_payer, &[ed, redeem])
    }

    #[allow(clippy::too_many_arguments)]
    fn task_open_ix(
        &self,
        signer: Pubkey,
        delegate: Option<Pubkey>,
        worker: Pubkey,
        verifier: Pubkey,
        amount: u64,
        deadline: i64,
        task_hash: [u8; 32],
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::TaskOpen {
                worker,
                verifier,
                amount,
                deadline,
                task_hash,
            }
            .data(),
            nakshatra_pay::accounts::TaskOpenAccounts {
                signer,
                config: self.config,
                escrow: self.escrow,
                vault: self.vault,
                delegate,
                task: self.task_pda(task_hash),
                system_program: system_program::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn task_submit_ix(&self, worker: Pubkey, task: Pubkey, result_hash: [u8; 32]) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::TaskSubmit { result_hash }.data(),
            nakshatra_pay::accounts::TaskSubmitAccounts {
                worker,
                config: self.config,
                escrow: self.escrow,
                task,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn task_verify_ix(
        &self,
        executor: Pubkey,
        delegate: Option<Pubkey>,
        rent_payer: Pubkey,
        task: Pubkey,
        verdict: Verdict,
        worker_token: Pubkey,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::TaskVerify { verdict }.data(),
            nakshatra_pay::accounts::TaskSettleAccounts {
                executor,
                config: self.config,
                mint: self.mint,
                escrow: self.escrow,
                delegate,
                rent_payer,
                task,
                vault: self.vault,
                worker_token,
                fee_vault: self.fee_vault,
                instructions_sysvar: solana_instructions_sysvar::ID,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn task_timeout_ix(
        &self,
        executor: Pubkey,
        delegate: Option<Pubkey>,
        rent_payer: Pubkey,
        task: Pubkey,
        worker_token: Pubkey,
    ) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::TaskTimeout {}.data(),
            nakshatra_pay::accounts::TaskSettleAccounts {
                executor,
                config: self.config,
                mint: self.mint,
                escrow: self.escrow,
                delegate,
                rent_payer,
                task,
                vault: self.vault,
                worker_token,
                fee_vault: self.fee_vault,
                instructions_sysvar: solana_instructions_sysvar::ID,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_task_with(
        &mut self,
        tx_payer: &Keypair,
        verifier: &Keypair,
        delegate: Option<Pubkey>,
        rent_payer: Pubkey,
        task: Pubkey,
        result_hash: [u8; 32],
        verdict: Verdict,
        worker_token: Pubkey,
    ) -> bool {
        let ed = ed25519_ix(
            verifier,
            &verdict_message(nakshatra_pay::id(), task, result_hash, verdict),
        );
        let verify = self.task_verify_ix(
            tx_payer.pubkey(),
            delegate,
            rent_payer,
            task,
            verdict,
            worker_token,
        );
        send_ixs(&mut self.svm, tx_payer, &[ed, verify])
    }

    fn escrow_close_ix(&self) -> Instruction {
        Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowClose {}.data(),
            nakshatra_pay::accounts::EscrowCloseAccounts {
                owner: self.owner.pubkey(),
                config: self.config,
                mint: self.mint,
                escrow: self.escrow,
                vault: self.vault,
                destination: self.owner_destination,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        )
    }

    fn reinit_and_deposit(&mut self, amount: u64) {
        let init = Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowInit {}.data(),
            nakshatra_pay::accounts::EscrowInitAccounts {
                owner: self.owner.pubkey(),
                config: self.config,
                owner_state: self.owner_state,
                mint: self.mint,
                escrow: self.escrow,
                vault: self.vault,
                token_program: spl_token::ID,
                system_program: system_program::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        );
        assert!(send_ixs(&mut self.svm, &self.owner, &[init]));
        let source = Pubkey::new_unique();
        put_token(
            &mut self.svm,
            source,
            self.mint,
            self.owner.pubkey(),
            amount,
        );
        let deposit = Instruction::new_with_bytes(
            nakshatra_pay::id(),
            &nakshatra_pay::instruction::EscrowDeposit { amount }.data(),
            nakshatra_pay::accounts::EscrowDepositAccounts {
                owner: self.owner.pubkey(),
                config: self.config,
                mint: self.mint,
                escrow: self.escrow,
                source,
                vault: self.vault,
                token_program: spl_token::ID,
                event_authority: event_authority(),
                program: nakshatra_pay::id(),
            }
            .to_account_metas(None),
        );
        assert!(send_ixs(&mut self.svm, &self.owner, &[deposit]));
    }
}

macro_rules! tx {
    ($fixture:ident, $signer:ident, $instruction:expr) => {{
        let instruction = $instruction;
        send_ixs(&mut $fixture.svm, &$fixture.$signer, &[instruction])
    }};
}

#[test]
fn owner_and_delegate_happy_paths_redeem_close_and_exit() {
    let mut f = Fixture::new();
    let channel0 = f.channel_pda(0);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 10_000, 0)
    ));
    assert_eq!(read_channel(&f.svm, channel0).fee_bps_snapshot, 300);
    let owner = Keypair::try_from(f.owner.to_bytes().as_slice()).unwrap();
    let other = Keypair::try_from(f.other.to_bytes().as_slice()).unwrap();
    assert!(f.redeem_with(&other, &owner, channel0, 101));
    assert!(f.redeem_with(&other, &owner, channel0, 201));
    assert_eq!(token_amount(&f.svm, f.worker_token), 195);
    assert_eq!(token_amount(&f.svm, f.fee_vault), 6);
    assert_eq!(token_amount(&f.svm, f.fee_wallet), 0);
    assert!(tx!(
        f,
        owner,
        f.close_request_ix(f.owner.pubkey(), channel0)
    ));
    assert!(tx!(
        f,
        worker,
        f.close_finalize_ix(f.worker.pubkey(), None, f.owner.pubkey(), channel0)
    ));
    assert!(f.svm.get_account(&channel0).is_none());

    let now: Clock = f.svm.get_sysvar();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            1_000,
            now.unix_timestamp + 10_000,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    let channel1 = f.channel_pda(1);
    assert!(tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            500,
            1
        )
    ));
    assert_eq!(read_delegate(&f.svm, delegate_pda).spent, 500);
    assert!(tx!(f, owner, f.delegate_revoke_ix(f.delegate.pubkey())));
    assert!(read_delegate(&f.svm, delegate_pda).disabled);
    let delegate = Keypair::try_from(f.delegate.to_bytes().as_slice()).unwrap();
    let other = Keypair::try_from(f.other.to_bytes().as_slice()).unwrap();
    assert!(f.redeem_with(&other, &delegate, channel1, 123));
    assert!(tx!(
        f,
        owner,
        f.close_request_ix(f.owner.pubkey(), channel1)
    ));
    assert!(!tx!(
        f,
        other,
        f.close_finalize_ix(
            f.other.pubkey(),
            Some(delegate_pda),
            f.delegate.pubkey(),
            channel1
        )
    ));
    warp_seconds(&mut f.svm, CLOSE_GRACE_S);
    assert!(tx!(
        f,
        other,
        f.close_finalize_ix(
            f.other.pubkey(),
            Some(delegate_pda),
            f.delegate.pubkey(),
            channel1
        )
    ));
    let escrow = read_escrow(&f.svm, f.escrow);
    assert_eq!((escrow.committed, escrow.open_channels), (0, 0));
    assert!(tx!(
        f,
        other,
        f.delegate_close_ix(f.other.pubkey(), f.delegate.pubkey())
    ));
    assert!(f.svm.get_account(&delegate_pda).is_none());
    assert!(tx!(
        f,
        authority,
        f.fee_withdraw_ix(f.authority.pubkey(), 9)
    ));
    assert_eq!(token_amount(&f.svm, f.fee_wallet), 9);
    assert_eq!(token_amount(&f.svm, f.fee_vault), 0);

    let close = f.escrow_close_ix();
    assert!(send_ixs(&mut f.svm, &f.owner, &[close]));
    assert_eq!(
        token_amount(&f.svm, f.owner_destination),
        DEPOSIT - 201 - 123
    );
    assert!(f.svm.get_account(&f.escrow).is_none());
}

#[test]
fn voucher_parser_and_cumulative_guards_reject_adversarial_inputs() {
    let mut f = Fixture::new();
    let a = f.channel_pda(0);
    let b = f.channel_pda(1);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 1_000, 0)
    ));
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 1_000, 1)
    ));
    let redeem_100 = f.redeem_ix(f.other.pubkey(), a, 100, f.worker_token, f.fee_vault);

    let wrong = ed25519_ix(&f.other, &voucher_message(nakshatra_pay::id(), a, 100));
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[wrong, redeem_100.clone()]
    ));
    let mut bad_signature = ed25519_ix(&f.owner, &voucher_message(nakshatra_pay::id(), a, 100));
    bad_signature.data[48] ^= 1;
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[bad_signature, redeem_100.clone()]
    ));
    let short = ed25519_ix(&f.owner, &[7u8; VOUCHER_MESSAGE_LEN - 1]);
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[short, redeem_100.clone()]
    ));
    let mut out_of_bounds = ed25519_ix(&f.owner, &voucher_message(nakshatra_pay::id(), a, 100));
    out_of_bounds.data[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[out_of_bounds, redeem_100.clone()]
    ));
    let tampered = ed25519_ix(&f.owner, &voucher_message(nakshatra_pay::id(), a, 100));
    let redeem_200 = f.redeem_ix(f.other.pubkey(), a, 200, f.worker_token, f.fee_vault);
    assert!(!send_ixs(&mut f.svm, &f.other, &[tampered, redeem_200]));
    let replay_a_on_b = ed25519_ix(&f.owner, &voucher_message(nakshatra_pay::id(), a, 100));
    let redeem_b = f.redeem_ix(f.other.pubkey(), b, 100, f.worker_token, f.fee_vault);
    assert!(!send_ixs(&mut f.svm, &f.other, &[replay_a_on_b, redeem_b]));
    let other_program = ed25519_ix(&f.owner, &voucher_message(Pubkey::new_unique(), a, 100));
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[other_program, redeem_100.clone()]
    ));
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        std::slice::from_ref(&redeem_100)
    ));
    let ed = ed25519_ix(&f.owner, &voucher_message(nakshatra_pay::id(), a, 100));
    let unrelated = system_instruction::transfer(&f.other.pubkey(), &f.owner.pubkey(), 1);
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[ed, unrelated, redeem_100.clone()]
    ));

    let ed = ed25519_ix(&f.owner, &voucher_message(nakshatra_pay::id(), a, 100));
    let mut cpi_redeem = redeem_100.clone();
    cpi_redeem.program_id = CPI_PROGRAM_ID;
    cpi_redeem
        .accounts
        .push(AccountMeta::new_readonly(nakshatra_pay::id(), false));
    f.svm.expire_blockhash();
    let message = Message::new_with_blockhash(
        &[ed, cpi_redeem],
        Some(&f.other.pubkey()),
        &f.svm.latest_blockhash(),
    );
    let transaction =
        VersionedTransaction::try_new(VersionedMessage::Legacy(message), &[&f.other]).unwrap();
    let failure = f.svm.send_transaction(transaction).unwrap_err();
    let redeem_via_cpi: u32 = nakshatra_pay::error::PayError::RedeemViaCpi.into();
    assert!(
        format!("{:?}", failure.err).contains(&format!("Custom({redeem_via_cpi})")),
        "unexpected CPI failure: {:?}",
        failure.err
    );

    // The second precompile verifies bytes in the first instruction. It succeeds,
    // but the program rejects its non-local instruction indexes.
    let real = ed25519_ix(&f.owner, &voucher_message(nakshatra_pay::id(), a, 100));
    let mut cross = real.clone();
    cross.data.truncate(16);
    for offset in [4usize, 8, 14] {
        cross.data[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
    }
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[real, cross, redeem_100.clone()]
    ));

    let owner = Keypair::try_from(f.owner.to_bytes().as_slice()).unwrap();
    let other = Keypair::try_from(f.other.to_bytes().as_slice()).unwrap();
    assert!(f.redeem_with(&other, &owner, a, 100));
    assert!(!f.redeem_with(&other, &owner, a, 100));
    assert!(!f.redeem_with(&other, &owner, a, 99));
    assert!(!f.redeem_with(&other, &owner, a, 1_001));
}

#[test]
fn delegate_collateral_close_and_withdraw_invariants_hold() {
    let mut f = Fixture::new();
    let now: Clock = f.svm.get_sysvar();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    assert!(!tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            100,
            now.unix_timestamp,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(f.delegate.pubkey(), 100, now.unix_timestamp + 10, 0)
    ));
    assert!(!tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            1,
            0
        )
    ));
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            100,
            now.unix_timestamp + 10,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    assert!(!tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            101,
            0
        )
    ));
    warp_seconds(&mut f.svm, 10);
    assert!(!tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            100,
            0
        )
    ));

    let now: Clock = f.svm.get_sysvar();
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            500,
            now.unix_timestamp + 10_000,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    let channel = f.channel_pda(0);
    assert!(tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            300,
            0
        )
    ));
    assert!(tx!(
        f,
        delegate,
        f.fund_ix(f.delegate.pubkey(), Some(delegate_pda), channel, 100)
    ));
    assert_eq!(read_delegate(&f.svm, delegate_pda).spent, 400);
    assert!(!tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            399,
            now.unix_timestamp + 10_000,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    assert!(!tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), DEPOSIT, 1)
    ));

    let request = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::EscrowWithdrawRequest { amount: DEPOSIT }.data(),
        nakshatra_pay::accounts::EscrowOwnerAccounts {
            owner: f.owner.pubkey(),
            config: f.config,
            escrow: f.escrow,
            vault: f.vault,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(send_ixs(&mut f.svm, &f.owner, &[request]));
    warp_seconds(&mut f.svm, WITHDRAW_DELAY_S);
    let execute = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::EscrowWithdrawExecute {}.data(),
        nakshatra_pay::accounts::EscrowWithdrawExecuteAccounts {
            owner: f.owner.pubkey(),
            config: f.config,
            mint: f.mint,
            escrow: f.escrow,
            vault: f.vault,
            destination: f.owner_destination,
            token_program: spl_token::ID,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(!send_ixs(&mut f.svm, &f.owner, &[execute]));

    let request_uncommitted = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::EscrowWithdrawRequest {
            amount: DEPOSIT - 400,
        }
        .data(),
        nakshatra_pay::accounts::EscrowOwnerAccounts {
            owner: f.owner.pubkey(),
            config: f.config,
            escrow: f.escrow,
            vault: f.vault,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(send_ixs(&mut f.svm, &f.owner, &[request_uncommitted]));
    warp_seconds(&mut f.svm, WITHDRAW_DELAY_S);
    let execute_uncommitted = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::EscrowWithdrawExecute {}.data(),
        nakshatra_pay::accounts::EscrowWithdrawExecuteAccounts {
            owner: f.owner.pubkey(),
            config: f.config,
            mint: f.mint,
            escrow: f.escrow,
            vault: f.vault,
            destination: f.owner_destination,
            token_program: spl_token::ID,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(send_ixs(&mut f.svm, &f.owner, &[execute_uncommitted]));
    assert_eq!(token_amount(&f.svm, f.owner_destination), DEPOSIT - 400);
    assert_eq!(token_amount(&f.svm, f.vault), 400);

    let escrow_close = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::EscrowClose {}.data(),
        nakshatra_pay::accounts::EscrowCloseAccounts {
            owner: f.owner.pubkey(),
            config: f.config,
            mint: f.mint,
            escrow: f.escrow,
            vault: f.vault,
            destination: f.owner_destination,
            token_program: spl_token::ID,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(!send_ixs(&mut f.svm, &f.owner, &[escrow_close]));
    assert!(tx!(f, owner, f.close_request_ix(f.owner.pubkey(), channel)));
    assert!(tx!(
        f,
        worker,
        f.close_finalize_ix(
            f.worker.pubkey(),
            Some(delegate_pda),
            f.delegate.pubkey(),
            channel
        )
    ));
    assert_eq!(read_delegate(&f.svm, delegate_pda).spent, 0);
    assert_eq!(read_escrow(&f.svm, f.escrow).committed, 0);
}

#[test]
fn worker_fee_wallet_close_deadline_and_strict_lengths_are_enforced() {
    let mut f = Fixture::new();
    let channel = f.channel_pda(0);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 1_000, 0)
    ));
    let msg = voucher_message(nakshatra_pay::id(), channel, 100);
    let ed = ed25519_ix(&f.owner, &msg);
    let wrong_worker = f.redeem_ix(
        f.other.pubkey(),
        channel,
        100,
        f.wrong_worker_token,
        f.fee_vault,
    );
    assert!(!send_ixs(&mut f.svm, &f.other, &[ed.clone(), wrong_worker]));
    let duplicate = f.redeem_ix(
        f.other.pubkey(),
        channel,
        100,
        f.worker_token,
        f.worker_token,
    );
    assert!(!send_ixs(&mut f.svm, &f.other, &[ed.clone(), duplicate]));
    let substitute_fee = Pubkey::new_unique();
    put_token(&mut f.svm, substitute_fee, f.mint, f.authority.pubkey(), 0);
    let substitute = f.redeem_ix(
        f.other.pubkey(),
        channel,
        100,
        f.worker_token,
        substitute_fee,
    );
    assert!(!send_ixs(&mut f.svm, &f.other, &[ed, substitute]));
    assert!(tx!(f, owner, f.close_request_ix(f.owner.pubkey(), channel)));
    warp_seconds(&mut f.svm, CLOSE_GRACE_S);
    let ed = ed25519_ix(&f.owner, &msg);
    let late = f.redeem_ix(f.other.pubkey(), channel, 100, f.worker_token, f.fee_vault);
    assert!(!send_ixs(&mut f.svm, &f.other, &[ed, late]));

    let now: Clock = f.svm.get_sysvar();
    let delegate = f.delegate_pda(f.delegate.pubkey());
    let mut instructions = vec![
        f.delegate_set_ix(
            f.delegate.pubkey(),
            100,
            now.unix_timestamp + 100,
            DELEGATE_OPEN_CHANNEL,
        ),
        f.delegate_revoke_ix(f.delegate.pubkey()),
        f.delegate_close_ix(f.owner.pubkey(), f.delegate.pubkey()),
        f.fee_withdraw_ix(f.owner.pubkey(), 1),
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 1, 1),
        f.fund_ix(f.owner.pubkey(), None, channel, 1),
        f.redeem_ix(f.owner.pubkey(), channel, 1, f.worker_token, f.fee_vault),
        f.close_request_ix(f.owner.pubkey(), channel),
        f.close_finalize_ix(f.owner.pubkey(), Some(delegate), f.owner.pubkey(), channel),
    ];
    for instruction in &mut instructions {
        instruction.data.push(0);
        f.svm.expire_blockhash();
        let message = Message::new_with_blockhash(
            std::slice::from_ref(instruction),
            Some(&f.owner.pubkey()),
            &f.svm.latest_blockhash(),
        );
        let transaction =
            VersionedTransaction::try_new(VersionedMessage::Legacy(message), &[&f.owner]).unwrap();
        let failure = f.svm.send_transaction(transaction).unwrap_err();
        assert_eq!(
            format!("{:?}", failure.err),
            "InstructionError(0, InvalidInstructionData)"
        );
    }
}

#[test]
fn closed_escrow_generation_prevents_old_voucher_replay() {
    let mut f = Fixture::new();
    let old_channel = f.channel_pda(0);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 10_000, 0)
    ));
    let old_voucher = ed25519_ix(
        &f.owner,
        &voucher_message(nakshatra_pay::id(), old_channel, 5_000),
    );
    let owner = Keypair::try_from(f.owner.to_bytes().as_slice()).unwrap();
    let worker = Keypair::try_from(f.worker.to_bytes().as_slice()).unwrap();
    assert!(f.redeem_with(&worker, &owner, old_channel, 5_000));
    assert!(tx!(
        f,
        owner,
        f.close_request_ix(f.owner.pubkey(), old_channel)
    ));
    assert!(tx!(
        f,
        worker,
        f.close_finalize_ix(f.worker.pubkey(), None, f.owner.pubkey(), old_channel)
    ));
    let close = f.escrow_close_ix();
    assert!(send_ixs(&mut f.svm, &f.owner, &[close]));

    f.reinit_and_deposit(100_000);
    assert_eq!(read_escrow(&f.svm, f.escrow).generation, 1);
    let new_channel = f.channel_pda(0);
    assert_ne!(old_channel, new_channel);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 10_000, 0)
    ));
    let before = token_amount(&f.svm, f.worker_token);
    let redeem = f.redeem_ix(
        f.worker.pubkey(),
        new_channel,
        5_000,
        f.worker_token,
        f.fee_vault,
    );
    assert!(!send_ixs(&mut f.svm, &f.worker, &[old_voucher, redeem]));
    assert_eq!(token_amount(&f.svm, f.worker_token), before);
}

#[test]
fn stale_delegate_cannot_spend_after_escrow_reopen_and_can_be_closed() {
    let mut f = Fixture::new();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    let now: Clock = f.svm.get_sysvar();
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            500,
            now.unix_timestamp + 30 * 86_400,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    assert_eq!(read_delegate(&f.svm, delegate_pda).generation, 0);
    assert!(tx!(f, owner, f.escrow_close_ix()));

    f.reinit_and_deposit(100_000);
    assert_eq!(read_escrow(&f.svm, f.escrow).generation, 1);
    assert!(!tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.other.pubkey(),
            500,
            0
        )
    ));

    let owner_channel = f.channel_pda(0);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 100, 0)
    ));
    assert!(!tx!(
        f,
        delegate,
        f.fund_ix(f.delegate.pubkey(), Some(delegate_pda), owner_channel, 1)
    ));
    assert!(tx!(
        f,
        other,
        f.delegate_close_ix(f.other.pubkey(), f.delegate.pubkey())
    ));
    assert!(f.svm.get_account(&delegate_pda).is_none());
}

#[test]
fn delegate_set_resets_a_closed_escrow_generation() {
    let mut f = Fixture::new();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    let now: Clock = f.svm.get_sysvar();
    let expires_at = now.unix_timestamp + 30 * 86_400;
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(f.delegate.pubkey(), 100, expires_at, DELEGATE_OPEN_CHANNEL)
    ));
    let channel = f.channel_pda(0);
    assert!(tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            100,
            0
        )
    ));
    let delegate = Keypair::try_from(f.delegate.to_bytes().as_slice()).unwrap();
    let worker = Keypair::try_from(f.worker.to_bytes().as_slice()).unwrap();
    assert!(f.redeem_with(&worker, &delegate, channel, 100));
    assert!(tx!(
        f,
        delegate,
        f.close_request_ix(f.delegate.pubkey(), channel)
    ));
    assert!(tx!(
        f,
        worker,
        f.close_finalize_ix(
            f.worker.pubkey(),
            Some(delegate_pda),
            f.delegate.pubkey(),
            channel
        )
    ));
    let old_delegate = read_delegate(&f.svm, delegate_pda);
    assert_eq!((old_delegate.generation, old_delegate.spent), (0, 100));
    assert_eq!(old_delegate.open_channels, 0);
    assert!(tx!(f, owner, f.escrow_close_ix()));

    f.reinit_and_deposit(100_000);
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(f.delegate.pubkey(), 50, expires_at, DELEGATE_OPEN_CHANNEL)
    ));
    let reset_delegate = read_delegate(&f.svm, delegate_pda);
    assert_eq!(reset_delegate.generation, 1);
    assert_eq!((reset_delegate.spent, reset_delegate.open_channels), (0, 0));
    assert!(!reset_delegate.disabled);
    assert_eq!(reset_delegate.cap_total, 50);
}

#[test]
fn delegate_revoke_cannot_reset_cap_while_old_channel_is_live() {
    let mut f = Fixture::new();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    let now: Clock = f.svm.get_sysvar();
    let expires_at = now.unix_timestamp + 1_000_000;
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(f.delegate.pubkey(), 100, expires_at, DELEGATE_OPEN_CHANNEL)
    ));
    assert!(tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            100,
            0
        )
    ));
    assert_eq!(read_delegate(&f.svm, delegate_pda).open_channels, 1);
    assert!(tx!(f, owner, f.delegate_revoke_ix(f.delegate.pubkey())));
    assert!(!tx!(
        f,
        owner,
        f.delegate_set_ix(f.delegate.pubkey(), 100, expires_at, DELEGATE_OPEN_CHANNEL)
    ));
    assert!(!tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            1,
            1
        )
    ));
    let delegate = read_delegate(&f.svm, delegate_pda);
    assert_eq!((delegate.cap_total, delegate.spent), (100, 100));
    assert!(delegate.disabled);
}

#[test]
fn delegated_channel_finalize_requires_delegate_and_restores_counters() {
    let mut f = Fixture::new();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    let now: Clock = f.svm.get_sysvar();
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            100,
            now.unix_timestamp + 1_000_000,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    let channel = f.channel_pda(0);
    assert!(tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            100,
            0
        )
    ));
    assert!(tx!(f, owner, f.delegate_revoke_ix(f.delegate.pubkey())));
    assert!(tx!(f, owner, f.close_request_ix(f.owner.pubkey(), channel)));
    warp_seconds(&mut f.svm, CLOSE_GRACE_S);
    assert!(!tx!(
        f,
        other,
        f.close_finalize_ix(f.other.pubkey(), None, f.delegate.pubkey(), channel)
    ));
    assert_eq!(read_delegate(&f.svm, delegate_pda).spent, 100);
    assert!(tx!(
        f,
        other,
        f.close_finalize_ix(
            f.other.pubkey(),
            Some(delegate_pda),
            f.delegate.pubkey(),
            channel
        )
    ));
    let delegate = read_delegate(&f.svm, delegate_pda);
    assert_eq!((delegate.spent, delegate.open_channels), (0, 0));
    assert!(tx!(
        f,
        other,
        f.delegate_close_ix(f.other.pubkey(), f.delegate.pubkey())
    ));
}

#[test]
fn one_lamport_prefunds_do_not_block_any_pda_initialization() {
    let mut f = Fixture::new_with_prefund(true);
    let now: Clock = f.svm.get_sysvar();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            100,
            now.unix_timestamp + 1_000,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    assert!(tx!(
        f,
        delegate,
        f.open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            100,
            0
        )
    ));
    assert_eq!(read_escrow(&f.svm, f.escrow).generation, 0);
    assert_eq!(read_delegate(&f.svm, delegate_pda).open_channels, 1);
}

#[test]
fn frozen_fee_wallet_cannot_block_redeem_and_fees_withdraw_separately() {
    let mut f = Fixture::new();
    freeze_token(&mut f.svm, f.fee_wallet);
    let channel = f.channel_pda(0);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 100, 0)
    ));
    let owner = Keypair::try_from(f.owner.to_bytes().as_slice()).unwrap();
    let worker = Keypair::try_from(f.worker.to_bytes().as_slice()).unwrap();
    assert!(f.redeem_with(&worker, &owner, channel, 100));
    assert_eq!(token_amount(&f.svm, f.worker_token), 97);
    assert_eq!(token_amount(&f.svm, f.fee_vault), 3);
    assert!(!tx!(
        f,
        authority,
        f.fee_withdraw_ix(f.authority.pubkey(), 3)
    ));
    close_account_for_test(&mut f.svm, f.fee_wallet);
    let closed_wallet_channel = f.channel_pda(1);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 100, 1)
    ));
    assert!(f.redeem_with(&worker, &owner, closed_wallet_channel, 100));
    assert_eq!(token_amount(&f.svm, f.worker_token), 194);
    assert_eq!(token_amount(&f.svm, f.fee_vault), 6);
    put_token(&mut f.svm, f.fee_wallet, f.mint, f.authority.pubkey(), 0);
    assert!(tx!(
        f,
        authority,
        f.fee_withdraw_ix(f.authority.pubkey(), 6)
    ));
    assert_eq!(token_amount(&f.svm, f.fee_wallet), 6);
}

#[test]
fn cumulative_fee_rounding_is_split_invariant() {
    let mut f = Fixture::new();
    let split = f.channel_pda(0);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 100, 0)
    ));
    let once = f.channel_pda(1);
    assert!(tx!(
        f,
        owner,
        f.open_ix(f.owner.pubkey(), None, f.worker.pubkey(), 100, 1)
    ));
    let owner = Keypair::try_from(f.owner.to_bytes().as_slice()).unwrap();
    let worker = Keypair::try_from(f.worker.to_bytes().as_slice()).unwrap();
    for total in 1..=100 {
        assert!(f.redeem_with(&worker, &owner, split, total));
    }
    assert!(f.redeem_with(&worker, &owner, once, 100));
    assert_eq!(token_amount(&f.svm, f.fee_vault), 6);
    assert_eq!(token_amount(&f.svm, f.worker_token), 194);
}

#[test]
fn tasks_owner_pass_and_fail_settle_exactly() {
    let mut f = Fixture::new();
    let now: Clock = f.svm.get_sysvar();
    let pass_hash = [1u8; 32];
    let pass_result = [2u8; 32];
    let pass_task = f.task_pda(pass_hash);
    assert!(tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            10_001,
            now.unix_timestamp + 1_000,
            pass_hash
        )
    ));
    let opened = read_task(&f.svm, pass_task);
    assert_eq!(opened.verifier, f.delegate.pubkey());
    assert_eq!(opened.fee_bps_snapshot, DEFAULT_FEE_BPS);
    assert_eq!(read_escrow(&f.svm, f.escrow).open_tasks, 1);
    assert!(tx!(
        f,
        worker,
        f.task_submit_ix(f.worker.pubkey(), pass_task, pass_result)
    ));
    let submitted = read_task(&f.svm, pass_task);
    assert_eq!(submitted.result_hash, pass_result);
    let verifier = Keypair::try_from(f.delegate.to_bytes().as_slice()).unwrap();
    let relayer = Keypair::try_from(f.other.to_bytes().as_slice()).unwrap();
    assert!(f.verify_task_with(
        &relayer,
        &verifier,
        None,
        f.owner.pubkey(),
        pass_task,
        pass_result,
        Verdict::Pass,
        f.worker_token,
    ));
    assert!(f.svm.get_account(&pass_task).is_none());
    assert_eq!(token_amount(&f.svm, f.worker_token), 9_701);
    assert_eq!(token_amount(&f.svm, f.fee_vault), 300);

    let fail_hash = [3u8; 32];
    let fail_result = [4u8; 32];
    let fail_task = f.task_pda(fail_hash);
    let now: Clock = f.svm.get_sysvar();
    assert!(tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            500,
            now.unix_timestamp + 1_000,
            fail_hash
        )
    ));
    assert!(tx!(
        f,
        worker,
        f.task_submit_ix(f.worker.pubkey(), fail_task, fail_result)
    ));
    assert!(f.verify_task_with(
        &relayer,
        &verifier,
        None,
        f.owner.pubkey(),
        fail_task,
        fail_result,
        Verdict::Fail,
        f.wrong_worker_token,
    ));
    assert_eq!(token_amount(&f.svm, f.worker_token), 9_701);
    assert_eq!(token_amount(&f.svm, f.fee_vault), 300);
    let escrow = read_escrow(&f.svm, f.escrow);
    assert_eq!((escrow.committed, escrow.open_tasks), (0, 0));
}

#[test]
fn delegated_tasks_restore_refunds_but_consume_paid_spend() {
    let mut f = Fixture::new();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    let now: Clock = f.svm.get_sysvar();
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            3_000,
            now.unix_timestamp + 1_000_000,
            DELEGATE_OPEN_TASK
        )
    ));
    let paid_hash = [10u8; 32];
    let paid_result = [11u8; 32];
    let paid_task = f.task_pda(paid_hash);
    assert!(tx!(
        f,
        delegate,
        f.task_open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            f.other.pubkey(),
            1_000,
            now.unix_timestamp + 10_000,
            paid_hash
        )
    ));
    let delegate = read_delegate(&f.svm, delegate_pda);
    assert_eq!((delegate.spent, delegate.open_tasks), (1_000, 1));
    assert!(tx!(f, owner, f.delegate_revoke_ix(f.delegate.pubkey())));
    assert!(f.svm.get_account(&delegate_pda).is_some());
    assert!(!tx!(
        f,
        other,
        f.delegate_close_ix(f.other.pubkey(), f.delegate.pubkey())
    ));
    assert!(tx!(
        f,
        worker,
        f.task_submit_ix(f.worker.pubkey(), paid_task, paid_result)
    ));
    warp_seconds(&mut f.svm, CLOSE_GRACE_S);
    assert!(tx!(
        f,
        other,
        f.task_timeout_ix(
            f.other.pubkey(),
            Some(delegate_pda),
            f.delegate.pubkey(),
            paid_task,
            f.worker_token
        )
    ));
    let delegate = read_delegate(&f.svm, delegate_pda);
    assert_eq!((delegate.spent, delegate.open_tasks), (1_000, 0));
    assert_eq!(token_amount(&f.svm, f.worker_token), 970);
    assert_eq!(token_amount(&f.svm, f.fee_vault), 30);
    assert!(tx!(
        f,
        other,
        f.delegate_close_ix(f.other.pubkey(), f.delegate.pubkey())
    ));

    let now: Clock = f.svm.get_sysvar();
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            700,
            now.unix_timestamp + 1_000_000,
            DELEGATE_OPEN_TASK
        )
    ));
    let refund_hash = [12u8; 32];
    let refund_task = f.task_pda(refund_hash);
    assert!(!tx!(
        f,
        delegate,
        f.task_open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            f.other.pubkey(),
            701,
            now.unix_timestamp + TASK_DEADLINE_MIN_S,
            [13u8; 32]
        )
    ));
    assert!(tx!(
        f,
        delegate,
        f.task_open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            f.other.pubkey(),
            700,
            now.unix_timestamp + TASK_DEADLINE_MIN_S,
            refund_hash
        )
    ));
    assert!(!tx!(
        f,
        other,
        f.task_timeout_ix(
            f.other.pubkey(),
            Some(delegate_pda),
            f.delegate.pubkey(),
            refund_task,
            f.wrong_worker_token
        )
    ));
    warp_seconds(&mut f.svm, TASK_DEADLINE_MIN_S + 1);
    assert!(tx!(
        f,
        other,
        f.task_timeout_ix(
            f.other.pubkey(),
            Some(delegate_pda),
            f.delegate.pubkey(),
            refund_task,
            f.wrong_worker_token
        )
    ));
    let delegate = read_delegate(&f.svm, delegate_pda);
    assert_eq!((delegate.spent, delegate.open_tasks), (0, 0));
}

#[test]
fn task_verdict_parser_rejects_substitution_cross_indexes_and_cpi() {
    let mut f = Fixture::new();
    let now: Clock = f.svm.get_sysvar();
    let unsubmitted_hash = [19u8; 32];
    let unsubmitted = f.task_pda(unsubmitted_hash);
    assert!(tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            100,
            now.unix_timestamp + 10_000,
            unsubmitted_hash
        )
    ));
    let premature_ed = ed25519_ix(
        &f.delegate,
        &verdict_message(nakshatra_pay::id(), unsubmitted, [0u8; 32], Verdict::Pass),
    );
    let premature_verify = f.task_verify_ix(
        f.other.pubkey(),
        None,
        f.owner.pubkey(),
        unsubmitted,
        Verdict::Pass,
        f.worker_token,
    );
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[premature_ed, premature_verify]
    ));
    let task_hash = [20u8; 32];
    let result_hash = [21u8; 32];
    let task = f.task_pda(task_hash);
    assert!(tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            1_000,
            now.unix_timestamp + 10_000,
            task_hash
        )
    ));
    assert!(tx!(
        f,
        worker,
        f.task_submit_ix(f.worker.pubkey(), task, result_hash)
    ));
    let verify = f.task_verify_ix(
        f.other.pubkey(),
        None,
        f.owner.pubkey(),
        task,
        Verdict::Pass,
        f.worker_token,
    );
    let wrong_signer = ed25519_ix(
        &f.other,
        &verdict_message(nakshatra_pay::id(), task, result_hash, Verdict::Pass),
    );
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[wrong_signer, verify.clone()]
    ));
    let wrong_result = ed25519_ix(
        &f.delegate,
        &verdict_message(nakshatra_pay::id(), task, [99u8; 32], Verdict::Pass),
    );
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[wrong_result, verify.clone()]
    ));
    let wrong_program = ed25519_ix(
        &f.delegate,
        &verdict_message(Pubkey::new_unique(), task, result_hash, Verdict::Pass),
    );
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[wrong_program, verify.clone()]
    ));
    let wrong_task = ed25519_ix(
        &f.delegate,
        &verdict_message(
            nakshatra_pay::id(),
            Pubkey::new_unique(),
            result_hash,
            Verdict::Pass,
        ),
    );
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[wrong_task, verify.clone()]
    ));

    let real = ed25519_ix(
        &f.delegate,
        &verdict_message(nakshatra_pay::id(), task, result_hash, Verdict::Pass),
    );
    let mut cross = real.clone();
    cross.data.truncate(16);
    for offset in [4usize, 8, 14] {
        cross.data[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
    }
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[real.clone(), cross, verify.clone()]
    ));
    let unrelated = system_instruction::transfer(&f.other.pubkey(), &f.owner.pubkey(), 1);
    assert!(!send_ixs(
        &mut f.svm,
        &f.other,
        &[real.clone(), unrelated, verify.clone()]
    ));

    let mut cpi_verify = verify.clone();
    cpi_verify.program_id = CPI_PROGRAM_ID;
    cpi_verify
        .accounts
        .push(AccountMeta::new_readonly(nakshatra_pay::id(), false));
    assert!(!send_ixs(&mut f.svm, &f.other, &[real.clone(), cpi_verify]));
    assert!(send_ixs(
        &mut f.svm,
        &f.other,
        &[real.clone(), verify.clone()]
    ));
    assert!(!send_ixs(&mut f.svm, &f.other, &[real, verify]));
}

#[test]
fn task_deadlines_collateral_worker_and_commitment_guards_hold() {
    let mut f = Fixture::new();
    let now: Clock = f.svm.get_sysvar();
    assert!(!tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            1,
            now.unix_timestamp + TASK_DEADLINE_MIN_S - 1,
            [30u8; 32]
        )
    ));
    assert!(!tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            1,
            now.unix_timestamp + TASK_DEADLINE_MAX_S + 1,
            [31u8; 32]
        )
    ));
    assert!(!tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            DEPOSIT + 1,
            now.unix_timestamp + 1_000,
            [32u8; 32]
        )
    ));

    let task_hash = [33u8; 32];
    let task = f.task_pda(task_hash);
    let late_hash = [35u8; 32];
    let late_task = f.task_pda(late_hash);
    assert!(tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            1,
            now.unix_timestamp + TASK_DEADLINE_MIN_S,
            late_hash
        )
    ));
    assert!(tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.delegate.pubkey(),
            400_000,
            now.unix_timestamp + WITHDRAW_DELAY_S + 1_000,
            task_hash
        )
    ));
    assert!(!tx!(f, owner, f.escrow_close_ix()));
    let request = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::EscrowWithdrawRequest { amount: DEPOSIT }.data(),
        nakshatra_pay::accounts::EscrowOwnerAccounts {
            owner: f.owner.pubkey(),
            config: f.config,
            escrow: f.escrow,
            vault: f.vault,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(send_ixs(&mut f.svm, &f.owner, &[request]));
    warp_seconds(&mut f.svm, WITHDRAW_DELAY_S);
    let execute = Instruction::new_with_bytes(
        nakshatra_pay::id(),
        &nakshatra_pay::instruction::EscrowWithdrawExecute {}.data(),
        nakshatra_pay::accounts::EscrowWithdrawExecuteAccounts {
            owner: f.owner.pubkey(),
            config: f.config,
            mint: f.mint,
            escrow: f.escrow,
            vault: f.vault,
            destination: f.owner_destination,
            token_program: spl_token::ID,
            event_authority: event_authority(),
            program: nakshatra_pay::id(),
        }
        .to_account_metas(None),
    );
    assert!(!send_ixs(&mut f.svm, &f.owner, &[execute]));
    assert!(!tx!(
        f,
        worker,
        f.task_submit_ix(f.worker.pubkey(), late_task, [36u8; 32])
    ));
    assert!(tx!(
        f,
        other,
        f.task_timeout_ix(
            f.other.pubkey(),
            None,
            f.owner.pubkey(),
            late_task,
            f.wrong_worker_token
        )
    ));
    assert!(!tx!(
        f,
        other,
        f.task_submit_ix(f.other.pubkey(), task, [34u8; 32])
    ));
    assert!(!tx!(
        f,
        other,
        f.task_timeout_ix(
            f.other.pubkey(),
            None,
            f.owner.pubkey(),
            task,
            f.worker_token
        )
    ));
    assert!(tx!(
        f,
        worker,
        f.task_submit_ix(f.worker.pubkey(), task, [34u8; 32])
    ));
    let verifier = Keypair::try_from(f.delegate.to_bytes().as_slice()).unwrap();
    let relayer = Keypair::try_from(f.other.to_bytes().as_slice()).unwrap();
    assert!(!f.verify_task_with(
        &relayer,
        &verifier,
        None,
        f.owner.pubkey(),
        task,
        [34u8; 32],
        Verdict::Pass,
        f.wrong_worker_token,
    ));
    assert!(!tx!(
        f,
        other,
        f.task_timeout_ix(
            f.other.pubkey(),
            None,
            f.owner.pubkey(),
            task,
            f.worker_token
        )
    ));
    warp_seconds(&mut f.svm, CLOSE_GRACE_S);
    let late_ed = ed25519_ix(
        &verifier,
        &verdict_message(nakshatra_pay::id(), task, [34u8; 32], Verdict::Pass),
    );
    let late_verify = f.task_verify_ix(
        f.other.pubkey(),
        None,
        f.owner.pubkey(),
        task,
        Verdict::Pass,
        f.worker_token,
    );
    assert!(!send_ixs(&mut f.svm, &f.other, &[late_ed, late_verify]));
    assert!(tx!(
        f,
        other,
        f.task_timeout_ix(
            f.other.pubkey(),
            None,
            f.owner.pubkey(),
            task,
            f.worker_token
        )
    ));
    assert_eq!(token_amount(&f.svm, f.worker_token), 388_000);
    assert_eq!(token_amount(&f.svm, f.fee_vault), 12_000);
}

#[test]
fn task_generation_delegate_permissions_prefund_and_strict_lengths_hold() {
    let mut f = Fixture::new();
    let now: Clock = f.svm.get_sysvar();
    let delegate_pda = f.delegate_pda(f.delegate.pubkey());
    assert!(tx!(
        f,
        owner,
        f.delegate_set_ix(
            f.delegate.pubkey(),
            100,
            now.unix_timestamp + 1_000,
            DELEGATE_OPEN_CHANNEL
        )
    ));
    assert!(!tx!(
        f,
        delegate,
        f.task_open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            f.other.pubkey(),
            100,
            now.unix_timestamp + 1_000,
            [40u8; 32]
        )
    ));
    warp_seconds(&mut f.svm, 1_000);
    assert!(!tx!(
        f,
        delegate,
        f.task_open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            f.other.pubkey(),
            100,
            now.unix_timestamp + 2_000,
            [41u8; 32]
        )
    ));

    let hash = [42u8; 32];
    let old_task = f.task_pda(hash);
    let now: Clock = f.svm.get_sysvar();
    assert!(send_ixs(
        &mut f.svm,
        &f.other,
        &[system_instruction::transfer(
            &f.other.pubkey(),
            &old_task,
            1
        )]
    ));
    assert!(tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.other.pubkey(),
            100,
            now.unix_timestamp + TASK_DEADLINE_MIN_S,
            hash
        )
    ));
    warp_seconds(&mut f.svm, TASK_DEADLINE_MIN_S + 1);
    assert!(tx!(
        f,
        other,
        f.task_timeout_ix(
            f.other.pubkey(),
            None,
            f.owner.pubkey(),
            old_task,
            f.worker_token
        )
    ));

    let mut strict = vec![
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.other.pubkey(),
            1,
            now.unix_timestamp + 10_000,
            [43u8; 32],
        ),
        f.task_submit_ix(f.worker.pubkey(), old_task, [44u8; 32]),
        f.task_verify_ix(
            f.owner.pubkey(),
            None,
            f.owner.pubkey(),
            old_task,
            Verdict::Pass,
            f.worker_token,
        ),
        f.task_timeout_ix(
            f.owner.pubkey(),
            None,
            f.owner.pubkey(),
            old_task,
            f.worker_token,
        ),
    ];
    for instruction in &mut strict {
        instruction.data.push(0);
        for account in &mut instruction.accounts {
            account.is_signer = account.pubkey == f.owner.pubkey();
        }
        f.svm.expire_blockhash();
        let message = Message::new_with_blockhash(
            std::slice::from_ref(instruction),
            Some(&f.owner.pubkey()),
            &f.svm.latest_blockhash(),
        );
        let transaction =
            VersionedTransaction::try_new(VersionedMessage::Legacy(message), &[&f.owner]).unwrap();
        let failure = f.svm.send_transaction(transaction).unwrap_err();
        assert_eq!(
            format!("{:?}", failure.err),
            "InstructionError(0, InvalidInstructionData)"
        );
    }

    assert!(tx!(f, owner, f.escrow_close_ix()));
    f.reinit_and_deposit(1_000);
    let new_task = f.task_pda(hash);
    assert_ne!(old_task, new_task);
    let now: Clock = f.svm.get_sysvar();
    assert!(!tx!(
        f,
        delegate,
        f.task_open_ix(
            f.delegate.pubkey(),
            Some(delegate_pda),
            f.worker.pubkey(),
            f.other.pubkey(),
            1,
            now.unix_timestamp + 1_000,
            [45u8; 32]
        )
    ));
    assert!(tx!(
        f,
        owner,
        f.task_open_ix(
            f.owner.pubkey(),
            None,
            f.worker.pubkey(),
            f.other.pubkey(),
            100,
            now.unix_timestamp + 1_000,
            hash
        )
    ));
    assert_eq!(read_task(&f.svm, new_task).generation, 1);
}
