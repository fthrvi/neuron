use solana_account_info::AccountInfo;
use solana_cpi::invoke;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_entrypoint::{entrypoint, ProgramResult};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (target, forwarded) = accounts
        .split_last()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let metas = forwarded
        .iter()
        .map(|account| match (account.is_writable, account.is_signer) {
            (true, true) => AccountMeta::new(*account.key, true),
            (true, false) => AccountMeta::new(*account.key, false),
            (false, true) => AccountMeta::new_readonly(*account.key, true),
            (false, false) => AccountMeta::new_readonly(*account.key, false),
        })
        .collect();
    invoke(
        &Instruction {
            program_id: *target.key,
            accounts: metas,
            data: instruction_data.to_vec(),
        },
        accounts,
    )
}
