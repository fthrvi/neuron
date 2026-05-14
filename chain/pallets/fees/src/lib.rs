//! # NRN Fees Pallet
//!
//! Records every inference fee payment on-chain.
//!
//! When a user runs inference through the gateway:
//!   1. Gateway calculates fee based on tokens used
//!   2. 95% goes to the GPU operator (on-chain transfer)
//!   3. 5% is burned (sent to dead address)
//!   4. This pallet records the fee permanently on-chain
//!
//! Storage:
//!   - Every fee payment with payer, operator, model, tokens, amounts
//!   - Running totals: fees collected, burned, operator earnings
//!   - Per-account stats: total spent, total earned
//!
//! Anyone can query the chain to verify fee history — full transparency.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

#[frame_support::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    /// NRN has 12 decimal places.
    const NRN_DECIMALS: u128 = 1_000_000_000_000;

    /// A fee payment record stored on-chain.
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug)]
    #[scale_info(skip_type_params(T))]
    pub struct FeeRecord<T: Config> {
        /// Who paid the fee.
        pub payer: T::AccountId,
        /// GPU operator who earned the fee.
        pub operator: T::AccountId,
        /// Total fee in smallest NRN units.
        pub total_fee: u128,
        /// Amount burned (5%).
        pub burned: u128,
        /// Amount paid to operator (95%).
        pub operator_earned: u128,
        /// Number of tokens processed (prompt + completion).
        pub tokens: u32,
        /// Model identifier hash (first 8 bytes of model name).
        pub model_hash: [u8; 8],
        /// Block when fee was recorded.
        pub block: BlockNumberFor<T>,
    }

    /// Per-account fee statistics.
    #[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug, Default)]
    pub struct AccountFeeStats {
        /// Total NRN spent on inference fees.
        pub total_spent: u128,
        /// Total NRN earned from operating GPU.
        pub total_earned: u128,
        /// Total NRN burned from this account's fees.
        pub total_burned: u128,
        /// Number of inferences paid for.
        pub inference_count: u32,
        /// Number of inferences served (as operator).
        pub served_count: u32,
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    // --- Storage ---

    /// Total NRN collected in fees (smallest unit).
    #[pallet::storage]
    #[pallet::getter(fn total_fees)]
    pub type TotalFees<T> = StorageValue<_, u128, ValueQuery>;

    /// Total NRN burned from fees.
    #[pallet::storage]
    #[pallet::getter(fn total_burned)]
    pub type TotalBurned<T> = StorageValue<_, u128, ValueQuery>;

    /// Total NRN paid to operators.
    #[pallet::storage]
    #[pallet::getter(fn total_operator_earnings)]
    pub type TotalOperatorEarnings<T> = StorageValue<_, u128, ValueQuery>;

    /// Total number of fee payments recorded.
    #[pallet::storage]
    #[pallet::getter(fn total_payments)]
    pub type TotalPayments<T> = StorageValue<_, u64, ValueQuery>;

    /// Per-account fee statistics.
    #[pallet::storage]
    #[pallet::getter(fn account_stats)]
    pub type AccountStats<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, AccountFeeStats, ValueQuery>;

    /// Recent fee records (last N, ring buffer style).
    /// Key: sequential index (mod MAX_RECENT).
    #[pallet::storage]
    pub type RecentFees<T: Config> =
        StorageMap<_, Twox64Concat, u64, FeeRecord<T>, OptionQuery>;

    /// Next index for the recent fees ring buffer.
    #[pallet::storage]
    pub type RecentIndex<T> = StorageValue<_, u64, ValueQuery>;

    // --- Events ---

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Inference fee recorded on-chain.
        FeeRecorded {
            payer: T::AccountId,
            operator: T::AccountId,
            total_fee: u128,
            burned: u128,
            operator_earned: u128,
            tokens: u32,
        },
    }

    // --- Errors ---

    #[pallet::error]
    pub enum Error<T> {
        /// Fee amount must be greater than zero.
        ZeroFee,
    }

    // --- Extrinsics ---

    /// Max recent fee records kept on-chain (ring buffer).
    const MAX_RECENT: u64 = 1000;

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Record an inference fee payment on-chain.
        ///
        /// Called by the gateway after each inference.
        /// The actual NRN transfer happens via Balances pallet —
        /// this just records the metadata permanently.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn record_fee(
            origin: OriginFor<T>,
            operator: T::AccountId,
            total_fee: u128,
            burned: u128,
            tokens: u32,
            model_hash: [u8; 8],
        ) -> DispatchResult {
            let payer = ensure_signed(origin)?;
            ensure!(total_fee > 0, Error::<T>::ZeroFee);

            let operator_earned = total_fee.saturating_sub(burned);

            // Update running totals
            TotalFees::<T>::mutate(|t| *t = t.saturating_add(total_fee));
            TotalBurned::<T>::mutate(|t| *t = t.saturating_add(burned));
            TotalOperatorEarnings::<T>::mutate(|t| *t = t.saturating_add(operator_earned));
            TotalPayments::<T>::mutate(|t| *t = t.saturating_add(1));

            // Update payer stats
            AccountStats::<T>::mutate(&payer, |s| {
                s.total_spent = s.total_spent.saturating_add(total_fee);
                s.total_burned = s.total_burned.saturating_add(burned);
                s.inference_count = s.inference_count.saturating_add(1);
            });

            // Update operator stats
            AccountStats::<T>::mutate(&operator, |s| {
                s.total_earned = s.total_earned.saturating_add(operator_earned);
                s.served_count = s.served_count.saturating_add(1);
            });

            // Store in ring buffer
            let block = frame_system::Pallet::<T>::block_number();
            let idx = RecentIndex::<T>::get();
            RecentFees::<T>::insert(idx % MAX_RECENT, FeeRecord {
                payer: payer.clone(),
                operator: operator.clone(),
                total_fee,
                burned,
                operator_earned,
                tokens,
                model_hash,
                block,
            });
            RecentIndex::<T>::put(idx.wrapping_add(1));

            Self::deposit_event(Event::FeeRecorded {
                payer,
                operator,
                total_fee,
                burned,
                operator_earned,
                tokens,
            });

            Ok(())
        }
    }

    // --- Public API ---

    impl<T: Config> Pallet<T> {
        /// Network-wide fee summary.
        pub fn fee_summary() -> (u128, u128, u128, u64) {
            (
                TotalFees::<T>::get(),
                TotalBurned::<T>::get(),
                TotalOperatorEarnings::<T>::get(),
                TotalPayments::<T>::get(),
            )
        }
    }
}
