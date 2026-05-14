// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org>

// Substrate and Polkadot dependencies
use frame_support::{
	derive_impl, parameter_types,
	traits::{ConstBool, ConstU128, ConstU32, ConstU64, ConstU8, VariantCountOf},
	weights::{
		constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
		IdentityFee, Weight,
	},
};
use frame_system::limits::{BlockLength, BlockWeights};
use pallet_transaction_payment::{ConstFeeMultiplier, FungibleAdapter, Multiplier};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_runtime::{traits::One, Perbill};
use sp_version::RuntimeVersion;

// Local module imports
use super::{
	AccountId, Aura, Balance, Balances, Block, BlockNumber, Hash, Nonce, PalletInfo, Runtime,
	RuntimeCall, RuntimeEvent, RuntimeFreezeReason, RuntimeHoldReason, RuntimeOrigin, RuntimeTask,
	System, EXISTENTIAL_DEPOSIT, SLOT_DURATION, VERSION,
};

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
	pub const BlockHashCount: BlockNumber = 2400;
	pub const Version: RuntimeVersion = VERSION;

	/// We allow for 2 seconds of compute with a 6 second average block time.
	pub RuntimeBlockWeights: BlockWeights = BlockWeights::with_sensible_defaults(
		Weight::from_parts(2u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
		NORMAL_DISPATCH_RATIO,
	);
	pub RuntimeBlockLength: BlockLength = BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
	pub const SS58Prefix: u8 = 42;
}

/// The default types are being injected by [`derive_impl`](`frame_support::derive_impl`) from
/// [`SoloChainDefaultConfig`](`struct@frame_system::config_preludes::SolochainDefaultConfig`),
/// but overridden as needed.
#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
	/// The block type for the runtime.
	type Block = Block;
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = RuntimeBlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = RuntimeBlockLength;
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The type for storing how many extrinsics an account has signed.
	type Nonce = Nonce;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RocksDbWeight;
	/// Version of the runtime.
	type Version = Version;
	/// The data to be stored in an account.
	type AccountData = pallet_balances::AccountData<Balance>;
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

impl pallet_aura::Config for Runtime {
	type AuthorityId = AuraId;
	type DisabledValidators = ();
	type MaxAuthorities = ConstU32<32>;
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

impl pallet_grandpa::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;

	type WeightInfo = ();
	type MaxAuthorities = ConstU32<32>;
	type MaxNominators = ConstU32<0>;
	type MaxSetIdSessionEntries = ConstU64<0>;

	type KeyOwnerProof = sp_core::Void;
	type EquivocationReportSystem = ();
}

impl pallet_timestamp::Config for Runtime {
	/// A timestamp: milliseconds since the unix epoch.
	type Moment = u64;
	type OnTimestampSet = Aura;
	type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
	type WeightInfo = ();
}

impl pallet_balances::Config for Runtime {
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	/// The type for recording an account's balance.
	type Balance = Balance;
	/// The ubiquitous event type.
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ConstU128<EXISTENTIAL_DEPOSIT>;
	type AccountStore = System;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type DoneSlashHandler = ();
}

parameter_types! {
	pub FeeMultiplier: Multiplier = Multiplier::one();
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type OnChargeTransaction = FungibleAdapter<Balances, ()>;
	type OperationalFeeMultiplier = ConstU8<5>;
	type WeightToFee = IdentityFee<Balance>;
	type LengthToFee = IdentityFee<Balance>;
	type FeeMultiplierUpdate = ConstFeeMultiplier<FeeMultiplier>;
	type WeightInfo = pallet_transaction_payment::weights::SubstrateWeight<Runtime>;
}

impl pallet_sudo::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeCall = RuntimeCall;
	type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

/// Configure the pallet-template in pallets/template.
impl pallet_template::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = pallet_template::weights::SubstrateWeight<Runtime>;
}

/// Find the Aura block author and convert to AccountId.
pub struct AuraAccountAdapter;
impl frame_support::traits::FindAuthor<AccountId> for AuraAccountAdapter {
	fn find_author<'a, I>(digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (frame_support::ConsensusEngineId, &'a [u8])>,
	{
		// AuraAuthorId returns the Sr25519 public key of the block author
		let author_pubkey = pallet_aura::AuraAuthorId::<Runtime>::find_author(digests)?;
		// Convert Sr25519 public key bytes to AccountId (both are 32 bytes)
		let raw: &[u8] = author_pubkey.as_ref();
		let bytes: [u8; 32] = raw.try_into().ok()?;
		Some(AccountId::new(bytes))
	}
}

/// Wire node-registry data into emission pallet.
extern crate alloc;
use alloc::vec::Vec;

pub struct NodeRegistryAdapter;
impl pallet_emission::NodeInfoProvider<AccountId> for NodeRegistryAdapter {
	fn active_node_count() -> u32 {
		pallet_node_registry::Pallet::<Runtime>::active_node_count()
	}
	fn online_nodes() -> Vec<AccountId> {
		// Collect all online node accounts from storage
		pallet_node_registry::Nodes::<Runtime>::iter()
			.filter(|(_, r)| r.state == pallet_node_registry::NodeState::Online)
			.map(|(who, _)| who)
			.collect()
	}
}

/// Wire compute-jobs data into emission pallet.
pub struct ComputeJobsAdapter;
impl pallet_emission::JobInfoProvider<AccountId> for ComputeJobsAdapter {
	fn recent_workers() -> Vec<(AccountId, u64)> {
		// v2 SAFETY GATE (2026-04-29): return empty until pallet-workers ships
		// with stake / slashing / spot-check verification. Without those, light
		// workers can free-ride on the chain's emission without contributing to
		// network operation, and a compromised coordinator could fabricate
		// receipts to mint NRN to fake worker keypairs. Receipts still flow to
		// chain via submit_receipt_batch and accumulate in WorkerJobs/WorkerTokens
		// (audit trail intact); compute-share emission just doesn't auto-mint
		// from them. Block author still gets the full emission for now.
		//
		// Re-enable by replacing this with the iterator below once v2 economics lands:
		//   pallet_compute_jobs::WorkerJobs::<Runtime>::iter()
		//       .filter(|(_, count)| *count > 0)
		//       .collect()
		Vec::new()
	}
}

/// Configure pallet-emission for NRN block rewards.
impl pallet_emission::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type FindAuthor = AuraAccountAdapter;
	type NodeInfo = NodeRegistryAdapter;
	type JobInfo = ComputeJobsAdapter;
}

/// Configure pallet-node-registry for GPU node tracking.
/// DegradedThreshold: ~15 blocks (1 min at 4s/block) without heartbeat = degraded.
/// OfflineThreshold: ~75 blocks (5 min) without heartbeat = offline.
parameter_types! {
	pub const DegradedThreshold: u32 = 15;
	pub const OfflineThreshold: u32 = 75;
}

impl pallet_node_registry::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type DegradedThreshold = DegradedThreshold;
	type OfflineThreshold = OfflineThreshold;
}

/// Configure pallet-compute-jobs.
/// JobTimeout: ~150 blocks (10 min) for an open job to be claimed.
/// ExecutionTimeout: ~450 blocks (30 min) for a claimed job to complete.
parameter_types! {
	pub const JobTimeout: u32 = 150;
	pub const ExecutionTimeout: u32 = 450;
}

/// Bridge: node-registry's is_compute() → compute-jobs' NodeCapabilityProvider.
pub struct NodeRegistryCapability;
impl pallet_compute_jobs::NodeCapabilityProvider<sp_runtime::AccountId32> for NodeRegistryCapability {
	fn can_compute(who: &sp_runtime::AccountId32) -> bool {
		pallet_node_registry::Pallet::<Runtime>::is_compute(who)
	}
}

impl pallet_compute_jobs::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type NodeCapability = NodeRegistryCapability;
	type JobTimeout = JobTimeout;
	type ExecutionTimeout = ExecutionTimeout;
}

/// Configure pallet-fees — on-chain inference fee recording.
impl pallet_fees::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
}

// Demurrage removed — taxing idle tokens is stealing, not economics.
// Staking credits removed — users pay NRN directly per inference.
// No credits, no staking, no demurrage. Simple like Bitcoin.
