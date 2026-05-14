//! # NRN Emission Pallet
//!
//! Smooth decay emission — like Cardano's reserve model.
//!
//!   emission_per_block = remaining_supply × R
//!
//! Where:
//!   R = 0.000000027 (tuned for ~3M NRN year 1)
//!   remaining_supply = HARD_CAP - total_minted
//!
//! Smooth. No halving shocks. Asymptotically approaches 21M.
//!
//! Split per block:
//!   70% → Compute rewards (GPU jobs completed)
//!   30% → Availability rewards (online GPU nodes)
//!    0% → Validators (validate to protect own tokens)
//!
//! Hard cap: 21,000,000 NRN

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

#[frame_support::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, FindAuthor},
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Zero;

    /// NRN has 12 decimal places.
    const NRN_DECIMALS: u128 = 1_000_000_000_000;

    /// Hard cap = 21,000,000 NRN (in smallest unit)
    const HARD_CAP: u128 = 21_000_000 * NRN_DECIMALS;

    /// Release rate R = 0.000000027 per block
    /// Expressed as parts-per-billion for integer math:
    /// R = 27 / 1_000_000_000
    const R_NUMERATOR: u128 = 27;
    const R_DENOMINATOR: u128 = 1_000_000_000;

    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    /// Trait for querying node info from the node-registry pallet.
    pub trait NodeInfoProvider<AccountId> {
        fn active_node_count() -> u32;
        fn online_nodes() -> Vec<AccountId>;
    }

    /// Trait for querying job info from the compute-jobs pallet.
    pub trait JobInfoProvider<AccountId> {
        fn recent_workers() -> Vec<(AccountId, u64)>;
    }

    impl<A> NodeInfoProvider<A> for () {
        fn active_node_count() -> u32 { 1 }
        fn online_nodes() -> Vec<A> { Vec::new() }
    }

    impl<A> JobInfoProvider<A> for () {
        fn recent_workers() -> Vec<(A, u64)> { Vec::new() }
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type Currency: Currency<Self::AccountId>;
        type FindAuthor: FindAuthor<Self::AccountId>;
        type NodeInfo: NodeInfoProvider<Self::AccountId>;
        type JobInfo: JobInfoProvider<Self::AccountId>;
    }

    // --- Storage ---

    /// Total NRN minted since genesis (smallest unit).
    #[pallet::storage]
    #[pallet::getter(fn total_minted)]
    pub type TotalMinted<T> = StorageValue<_, u128, ValueQuery>;

    /// Total blocks produced.
    #[pallet::storage]
    #[pallet::getter(fn blocks_produced)]
    pub type BlocksProduced<T> = StorageValue<_, u64, ValueQuery>;

    // --- Events ---

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// NRN minted this block.
        BlockReward {
            block_number: BlockNumberFor<T>,
            emission: u128,
            compute_reward: u128,
            availability_reward: u128,
            remaining_supply: u128,
            total_minted: u128,
        },
        /// Hard cap reached.
        HardCapReached { total_minted: u128 },
    }

    // --- Errors ---

    #[pallet::error]
    pub enum Error<T> {
        HardCapReached,
    }

    // --- No extrinsics needed — emission is automatic ---

    #[pallet::call]
    impl<T: Config> Pallet<T> {}

    // --- Block hooks ---

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T>
    where
        BalanceOf<T>: From<u128>,
    {
        fn on_finalize(block_number: BlockNumberFor<T>) {
            BlocksProduced::<T>::mutate(|b| *b = b.saturating_add(1));

            let total = TotalMinted::<T>::get();
            if total >= HARD_CAP {
                return;
            }

            // === SMOOTH DECAY: emission = remaining_supply × R ===
            let remaining = HARD_CAP.saturating_sub(total);
            let emission = remaining
                .saturating_mul(R_NUMERATOR)
                / R_DENOMINATOR;

            // Don't exceed hard cap
            let emission = emission.min(remaining);

            if emission.is_zero() {
                Self::deposit_event(Event::HardCapReached { total_minted: total });
                return;
            }

            // === SPLIT: 70% compute / 30% availability ===
            let compute_share = emission * 70 / 100;
            let availability_share = emission.saturating_sub(compute_share);

            // Find block author (fallback recipient)
            let author = T::FindAuthor::find_author(
                frame_system::Pallet::<T>::digest()
                    .logs
                    .iter()
                    .filter_map(|d| d.as_pre_runtime()),
            );

            // --- 70% compute: split among workers by jobs completed ---
            let workers = T::JobInfo::recent_workers();
            if !workers.is_empty() {
                let total_jobs: u64 = workers.iter().map(|(_, c)| *c).sum();
                if total_jobs > 0 {
                    for (worker, count) in &workers {
                        let worker_reward = compute_share * (*count as u128) / (total_jobs as u128);
                        if worker_reward > 0 {
                            let amount: BalanceOf<T> = worker_reward.into();
                            let _ = T::Currency::deposit_creating(worker, amount);
                        }
                    }
                }
            } else if let Some(ref author) = author {
                // No workers → block author gets compute share (bootstrapping)
                let amount: BalanceOf<T> = compute_share.into();
                let _ = T::Currency::deposit_creating(author, amount);
            }

            // --- 30% availability: split among online GPU nodes ---
            let online_nodes = T::NodeInfo::online_nodes();
            if !online_nodes.is_empty() {
                let per_node = availability_share / online_nodes.len() as u128;
                if per_node > 0 {
                    for node in &online_nodes {
                        let amount: BalanceOf<T> = per_node.into();
                        let _ = T::Currency::deposit_creating(node, amount);
                    }
                }
            } else if let Some(ref author) = author {
                let amount: BalanceOf<T> = availability_share.into();
                let _ = T::Currency::deposit_creating(author, amount);
            }

            // Update total minted
            let new_total = total.saturating_add(emission);
            TotalMinted::<T>::put(new_total);

            Self::deposit_event(Event::BlockReward {
                block_number,
                emission,
                compute_reward: compute_share,
                availability_reward: availability_share,
                remaining_supply: HARD_CAP.saturating_sub(new_total),
                total_minted: new_total,
            });
        }
    }

    // --- Public API ---

    impl<T: Config> Pallet<T> {
        /// Current emission rate per block (for display).
        pub fn current_emission_rate() -> u128 {
            let remaining = HARD_CAP.saturating_sub(TotalMinted::<T>::get());
            remaining.saturating_mul(R_NUMERATOR) / R_DENOMINATOR
        }

        /// Remaining supply that can be minted.
        pub fn remaining_supply() -> u128 {
            HARD_CAP.saturating_sub(TotalMinted::<T>::get())
        }
    }
}
