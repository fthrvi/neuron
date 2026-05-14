//! # Staking Credits Pallet
//!
//! Stake NRN → earn compute credits.
//!
//!   C(s) = s × 10 × (1 + rep/1000) per day
//!
//! Credits are:
//!   - Non-transferable (can't sell them)
//!   - Expire in 30 days (use it or lose it)
//!   - Spent on compute only (paying for GPU jobs)
//!
//! This separates the tradeable token (NRN) from the utility (credits).
//! Staking locks NRN — you can unstake but there's a 7-day unbonding period.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

#[frame_support::pallet]
pub mod pallet {
    use codec::DecodeWithMemTracking;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Saturating;

    /// A staking position.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, Default)]
    pub struct StakePosition<BlockNumber> {
        /// Amount of NRN staked (in smallest units).
        pub amount: u128,
        /// Block when stake was created.
        pub staked_at: BlockNumber,
        /// Block when unstake was requested (0 = not unstaking).
        pub unbonding_at: BlockNumber,
    }

    /// Compute credits balance.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, Default)]
    pub struct CreditBalance<BlockNumber> {
        /// Current credits available.
        pub credits: u128,
        /// Block when credits were last accrued.
        pub last_accrual: BlockNumber,
        /// Block when credits expire (30 days from last accrual).
        pub expires_at: BlockNumber,
    }

    // --- Config ---

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Blocks in the unbonding period (~7 days at 4s/block = 151,200).
        #[pallet::constant]
        type UnbondingPeriod: Get<u32>;

        /// Blocks until credits expire (~30 days = 648,000).
        #[pallet::constant]
        type CreditExpiry: Get<u32>;

        /// Blocks per accrual period (~1 day = 21,600).
        #[pallet::constant]
        type AccrualPeriod: Get<u32>;
    }

    // --- Storage ---

    /// Staking positions per account.
    #[pallet::storage]
    #[pallet::getter(fn stakes)]
    pub type Stakes<T: Config> = StorageMap<
        _, Blake2_128Concat, T::AccountId,
        StakePosition<BlockNumberFor<T>>,
    >;

    /// Credit balances per account.
    #[pallet::storage]
    #[pallet::getter(fn credits)]
    pub type Credits<T: Config> = StorageMap<
        _, Blake2_128Concat, T::AccountId,
        CreditBalance<BlockNumberFor<T>>,
    >;

    /// Total NRN staked across all accounts.
    #[pallet::storage]
    #[pallet::getter(fn total_staked)]
    pub type TotalStaked<T> = StorageValue<_, u128, ValueQuery>;

    // --- Events ---

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// NRN staked.
        Staked { who: T::AccountId, amount: u128 },
        /// Unstake requested (starts unbonding).
        UnstakeRequested { who: T::AccountId, amount: u128 },
        /// Unstake completed after unbonding period.
        Unstaked { who: T::AccountId, amount: u128 },
        /// Credits accrued from stake.
        CreditsAccrued { who: T::AccountId, credits: u128 },
        /// Credits spent on compute.
        CreditsSpent { who: T::AccountId, amount: u128, remaining: u128 },
        /// Credits expired.
        CreditsExpired { who: T::AccountId, amount: u128 },
    }

    // --- Errors ---

    #[pallet::error]
    pub enum Error<T> {
        /// No active stake.
        NotStaked,
        /// Already staking.
        AlreadyStaked,
        /// Still in unbonding period.
        StillUnbonding,
        /// Insufficient credits.
        InsufficientCredits,
        /// Credits have expired.
        CreditsExpired,
        /// Invalid amount (zero).
        InvalidAmount,
    }

    // --- Calls ---

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Stake NRN to earn compute credits.
        ///
        /// Locks the specified amount. Credits accrue daily based on:
        ///   C(s) = s × 10 × (1 + rep/1000)
        /// (rep integration is Phase 2 — currently fixed at 1.0)
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(30_000, 0))]
        pub fn stake(origin: OriginFor<T>, amount: u128) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(amount > 0, Error::<T>::InvalidAmount);
            ensure!(!Stakes::<T>::contains_key(&who), Error::<T>::AlreadyStaked);

            let now = frame_system::Pallet::<T>::block_number();

            Stakes::<T>::insert(&who, StakePosition {
                amount,
                staked_at: now,
                unbonding_at: Default::default(),
            });

            TotalStaked::<T>::mutate(|s| *s = s.saturating_add(amount));

            Self::deposit_event(Event::Staked { who, amount });
            Ok(())
        }

        /// Request unstake — starts the unbonding period.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(20_000, 0))]
        pub fn request_unstake(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = frame_system::Pallet::<T>::block_number();

            Stakes::<T>::try_mutate(&who, |maybe_stake| -> DispatchResult {
                let stake = maybe_stake.as_mut().ok_or(Error::<T>::NotStaked)?;
                stake.unbonding_at = now;

                Self::deposit_event(Event::UnstakeRequested {
                    who: who.clone(),
                    amount: stake.amount,
                });
                Ok(())
            })
        }

        /// Complete unstake after unbonding period.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(25_000, 0))]
        pub fn complete_unstake(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = frame_system::Pallet::<T>::block_number();

            let stake = Stakes::<T>::get(&who).ok_or(Error::<T>::NotStaked)?;
            let unbonding_at: u32 = stake.unbonding_at.try_into().unwrap_or(0);
            ensure!(unbonding_at > 0, Error::<T>::NotStaked);

            let elapsed: u32 = now.saturating_sub(stake.unbonding_at)
                .try_into().unwrap_or(0);
            ensure!(elapsed >= T::UnbondingPeriod::get(), Error::<T>::StillUnbonding);

            let amount = stake.amount;
            Stakes::<T>::remove(&who);
            TotalStaked::<T>::mutate(|s| *s = s.saturating_sub(amount));

            // Clear credits too
            Credits::<T>::remove(&who);

            Self::deposit_event(Event::Unstaked { who, amount });
            Ok(())
        }

        /// Accrue credits from stake (called periodically by daemon or manually).
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(20_000, 0))]
        pub fn accrue_credits(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = frame_system::Pallet::<T>::block_number();

            let stake = Stakes::<T>::get(&who).ok_or(Error::<T>::NotStaked)?;

            // Don't accrue if unstaking
            let unbonding: u32 = stake.unbonding_at.try_into().unwrap_or(0);
            ensure!(unbonding == 0, Error::<T>::StillUnbonding);

            // Check if enough time has passed since last accrual
            let credit = Credits::<T>::get(&who).unwrap_or_default();
            let since_last: u32 = now.saturating_sub(credit.last_accrual)
                .try_into().unwrap_or(0);
            ensure!(since_last >= T::AccrualPeriod::get(), Error::<T>::InvalidAmount);

            // C(s) = s × 10 × (1 + rep/1000) per day
            // Phase 1: rep = 0, so C(s) = s × 10
            // Convert to smallest unit: s is in NRN_DECIMALS (10^12)
            let nrn_amount = stake.amount / 1_000_000_000_000u128; // convert to whole NRN
            let new_credits = nrn_amount.saturating_mul(10);

            let expiry = T::CreditExpiry::get();
            let updated = CreditBalance {
                credits: credit.credits.saturating_add(new_credits),
                last_accrual: now,
                expires_at: now.saturating_add(expiry.into()),
            };

            Credits::<T>::insert(&who, updated);

            Self::deposit_event(Event::CreditsAccrued {
                who,
                credits: new_credits,
            });
            Ok(())
        }

        /// Spend credits on a compute job (called by compute-jobs pallet via sudo).
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(15_000, 0))]
        pub fn spend_credits(
            origin: OriginFor<T>,
            who: T::AccountId,
            amount: u128,
        ) -> DispatchResult {
            ensure_root(origin)?;

            Credits::<T>::try_mutate(&who, |maybe_credit| -> DispatchResult {
                let credit = maybe_credit.as_mut().ok_or(Error::<T>::InsufficientCredits)?;
                ensure!(credit.credits >= amount, Error::<T>::InsufficientCredits);

                credit.credits = credit.credits.saturating_sub(amount);

                Self::deposit_event(Event::CreditsSpent {
                    who: who.clone(),
                    amount,
                    remaining: credit.credits,
                });
                Ok(())
            })
        }
    }

    // --- Public API ---

    impl<T: Config> Pallet<T> {
        pub fn get_credits(who: &T::AccountId) -> u128 {
            Credits::<T>::get(who).map(|c| c.credits).unwrap_or(0)
        }

        pub fn get_stake(who: &T::AccountId) -> u128 {
            Stakes::<T>::get(who).map(|s| s.amount).unwrap_or(0)
        }
    }
}
