use anchor_lang::prelude::*;

#[constant]
pub const CONFIG_SEED: &[u8] = b"config";
#[constant]
pub const OWNER_STATE_SEED: &[u8] = b"owner_state";
#[constant]
pub const ESCROW_SEED: &[u8] = b"escrow";
#[constant]
pub const VAULT_SEED: &[u8] = b"vault";
#[constant]
pub const DELEGATE_SEED: &[u8] = b"delegate";
#[constant]
pub const CHANNEL_SEED: &[u8] = b"channel";
#[constant]
pub const TASK_SEED: &[u8] = b"task";
#[constant]
pub const FEE_VAULT_SEED: &[u8] = b"fee_vault";

pub const DELEGATE_OPEN_CHANNEL: u8 = 1;
pub const DELEGATE_OPEN_TASK: u8 = 2;
pub const DELEGATE_FLAGS_ALL: u8 = DELEGATE_OPEN_CHANNEL | DELEGATE_OPEN_TASK;

pub const VOUCHER_DOMAIN: &[u8; 16] = b"NAK_PAY_VOUCHER1";
pub const VOUCHER_MESSAGE_LEN: usize = 88;
pub const VERDICT_DOMAIN: &[u8; 16] = b"NAK_PAY_VERDICT1";
pub const VERDICT_MESSAGE_LEN: usize = 113;

#[constant]
pub const FEE_BPS_MAX: u16 = 1_000;
#[constant]
pub const DEFAULT_FEE_BPS: u16 = 300;
#[constant]
pub const WITHDRAW_DELAY_S: i64 = 21_600;
#[constant]
pub const CLOSE_GRACE_S: i64 = 86_400;
#[constant]
pub const CONFIG_DELAY_S: i64 = 172_800;
pub const TASK_DEADLINE_MIN_S: i64 = 60;
pub const TASK_DEADLINE_MAX_S: i64 = 30 * 86_400;
