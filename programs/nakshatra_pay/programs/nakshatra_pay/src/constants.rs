use anchor_lang::prelude::*;

#[constant]
pub const CONFIG_SEED: &[u8] = b"config";
#[constant]
pub const ESCROW_SEED: &[u8] = b"escrow";
#[constant]
pub const VAULT_SEED: &[u8] = b"vault";

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
