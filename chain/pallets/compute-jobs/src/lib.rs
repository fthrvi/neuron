//! # Compute Jobs Pallet
//!
//! On-chain tracking of GPU compute jobs in the Neuron Network.
//!
//! Lifecycle:
//!   1. Submitter creates job on-chain (job_type, input_hash, vram_required)
//!   2. Worker claims the job (locks it to their account)
//!   3. Worker completes the job (submits result_hash, duration)
//!   4. Verification (optional spot-check, future: ZK proof)
//!   5. Credits settled: submitter pays, worker earns
//!
//! Job content is NEVER on-chain — only hashes and metadata.
//! The actual computation happens P2P via the Python daemon.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

extern crate alloc;

#[frame_support::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use codec::DecodeWithMemTracking;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Saturating;

    // --- Types ---

    /// Job status lifecycle.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug)]
    pub enum JobStatus {
        /// Created, waiting for a worker to claim.
        Open,
        /// Claimed by a worker, execution in progress.
        Claimed,
        /// Worker submitted result, awaiting verification.
        Completed,
        /// Verified correct — credits settled.
        Verified,
        /// Failed or timed out.
        Failed,
        /// Disputed — verification mismatch.
        Disputed,
    }

    impl Default for JobStatus {
        fn default() -> Self {
            JobStatus::Open
        }
    }

    /// One receipt inside a pathway-C batch submission.
    /// The worker's account is its 32-byte Ed25519 pubkey reinterpreted as AccountId32.
    /// `signature` is the worker's 64-byte Ed25519 signature over a deterministic encoding
    /// of the rest — verification is deferred to v2 (kept on-chain for retroactive audit).
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug)]
    pub struct ReceiptRecord<AccountId, BlockNumber> {
        pub worker: AccountId,
        /// Coordinator-assigned job id (e.g. "chatcmpl-abc123" or 16-hex).
        pub job_id: BoundedVec<u8, ConstU32<64>>,
        /// SHA-256 of the canonical request payload (32 bytes hex-decoded).
        pub input_hash: BoundedVec<u8, ConstU32<32>>,
        /// SHA-256 of the canonical response payload.
        pub output_hash: BoundedVec<u8, ConstU32<32>>,
        /// Compute class served (e.g. "qwen3-coder-30b").
        pub compute_class: BoundedVec<u8, ConstU32<32>>,
        pub tokens_generated: u32,
        pub duration_ms: u32,
        /// Worker's wall-clock timestamp (unix epoch seconds).
        pub timestamp: u64,
        /// Worker's Ed25519 signature; verified in v2.
        pub signature: BoundedVec<u8, ConstU32<64>>,
        /// Block number when the receipt was admitted on-chain.
        pub recorded_at: BlockNumber,
    }

    /// On-chain job record.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, Default)]
    pub struct JobRecord<AccountId, BlockNumber> {
        /// Who submitted the job.
        pub submitter: AccountId,
        /// Who claimed/executed the job (None if Open).
        pub worker: Option<AccountId>,
        /// Job type (e.g., "inference", "benchmark"). Bounded to 32 bytes.
        pub job_type: BoundedVec<u8, ConstU32<32>>,
        /// Hash of job input (proves what was requested without revealing content).
        pub input_hash: BoundedVec<u8, ConstU32<64>>,
        /// Hash of job result (proves what was computed).
        pub result_hash: BoundedVec<u8, ConstU32<64>>,
        /// VRAM required (MB).
        pub vram_required_mb: u32,
        /// Current status.
        pub status: JobStatus,
        /// Block when job was created.
        pub created_at: BlockNumber,
        /// Block when job was claimed.
        pub claimed_at: BlockNumber,
        /// Block when job was completed.
        pub completed_at: BlockNumber,
        /// Execution duration in milliseconds.
        pub duration_ms: u32,
        /// Credits charged for this job.
        pub cost: u128,
    }

    // --- Traits ---

    /// Trait for checking node capabilities. Wired from node-registry in runtime.
    pub trait NodeCapabilityProvider<AccountId> {
        /// Can this node execute compute jobs? (False for pure Pillar nodes.)
        fn can_compute(who: &AccountId) -> bool;
    }

    /// Default: all nodes can compute (backward compatible).
    impl<A> NodeCapabilityProvider<A> for () {
        fn can_compute(_who: &A) -> bool { true }
    }

    // --- Config ---

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Node capability checker — prevents pillar nodes from claiming GPU jobs.
        type NodeCapability: NodeCapabilityProvider<Self::AccountId>;

        /// Max blocks a job can be open before it expires.
        #[pallet::constant]
        type JobTimeout: Get<u32>;

        /// Max blocks a claimed job can run before timeout.
        #[pallet::constant]
        type ExecutionTimeout: Get<u32>;
    }

    // --- Storage ---

    /// All jobs. Key = auto-incrementing job ID.
    #[pallet::storage]
    #[pallet::getter(fn jobs)]
    pub type Jobs<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        JobRecord<T::AccountId, BlockNumberFor<T>>,
    >;

    /// Next job ID (auto-increment).
    #[pallet::storage]
    #[pallet::getter(fn next_job_id)]
    pub type NextJobId<T> = StorageValue<_, u64, ValueQuery>;

    /// Total jobs completed.
    #[pallet::storage]
    #[pallet::getter(fn total_completed)]
    pub type TotalCompleted<T> = StorageValue<_, u64, ValueQuery>;

    /// Total jobs failed.
    #[pallet::storage]
    #[pallet::getter(fn total_failed)]
    pub type TotalFailed<T> = StorageValue<_, u64, ValueQuery>;

    /// Jobs per worker (for reward calculation).
    #[pallet::storage]
    #[pallet::getter(fn worker_jobs)]
    pub type WorkerJobs<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        u64,
        ValueQuery,
    >;

    // --- Pathway-C receipt storage ---

    /// All ingested pathway-C receipts. Key = auto-incrementing receipt id.
    #[pallet::storage]
    #[pallet::getter(fn receipts)]
    pub type Receipts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u64,
        ReceiptRecord<T::AccountId, BlockNumberFor<T>>,
    >;

    /// Next receipt id (auto-increment).
    #[pallet::storage]
    #[pallet::getter(fn next_receipt_id)]
    pub type NextReceiptId<T> = StorageValue<_, u64, ValueQuery>;

    /// Total tokens generated by each worker (cumulative).
    /// Drives NRN emission once wired to the emission pallet.
    #[pallet::storage]
    #[pallet::getter(fn worker_tokens)]
    pub type WorkerTokens<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        u64,
        ValueQuery,
    >;

    /// Total receipts ingested across all workers.
    #[pallet::storage]
    #[pallet::getter(fn total_receipts)]
    pub type TotalReceipts<T> = StorageValue<_, u64, ValueQuery>;

    // --- Events ---

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New job created.
        JobCreated {
            job_id: u64,
            submitter: T::AccountId,
            job_type: Vec<u8>,
            vram_required_mb: u32,
        },
        /// Job claimed by a worker.
        JobClaimed {
            job_id: u64,
            worker: T::AccountId,
        },
        /// Job completed with result.
        JobCompleted {
            job_id: u64,
            worker: T::AccountId,
            duration_ms: u32,
            result_hash: Vec<u8>,
        },
        /// Job verified correct.
        JobVerified {
            job_id: u64,
            worker: T::AccountId,
        },
        /// Job failed or timed out.
        JobFailed {
            job_id: u64,
            reason: Vec<u8>,
        },
        /// A pathway-C receipt batch was admitted on-chain.
        ReceiptBatchSubmitted {
            submitter: T::AccountId,
            count: u32,
            total_tokens: u64,
        },
        /// A single receipt was recorded (one per element of the batch).
        ReceiptRecorded {
            receipt_id: u64,
            worker: T::AccountId,
            tokens_generated: u32,
            compute_class: Vec<u8>,
        },
    }

    // --- Errors ---

    #[pallet::error]
    pub enum Error<T> {
        /// Job not found.
        JobNotFound,
        /// Job is not in the expected status.
        InvalidStatus,
        /// Only the assigned worker can complete this job.
        NotWorker,
        /// Job has timed out.
        JobTimedOut,
        /// Pillar nodes cannot claim compute jobs. Bones don't flex.
        NotComputeNode,
        /// Receipt batch was empty.
        EmptyBatch,
        /// Receipt batch exceeded the per-call cap.
        BatchTooLarge,
    }

    // --- Calls ---

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a new compute job.
        ///
        /// Called by the Python daemon when a job request arrives.
        /// Job content stays off-chain — only hash + metadata on-chain.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(30_000, 0))]
        pub fn submit_job(
            origin: OriginFor<T>,
            job_type: BoundedVec<u8, ConstU32<32>>,
            input_hash: BoundedVec<u8, ConstU32<64>>,
            vram_required_mb: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = frame_system::Pallet::<T>::block_number();
            let job_id = NextJobId::<T>::get();

            let record = JobRecord {
                submitter: who.clone(),
                worker: None,
                job_type: job_type.clone(),
                input_hash: input_hash.clone(),
                result_hash: BoundedVec::default(),
                vram_required_mb,
                status: JobStatus::Open,
                created_at: now,
                claimed_at: now,
                completed_at: now,
                duration_ms: 0,
                cost: 0,
            };

            Jobs::<T>::insert(job_id, record);
            NextJobId::<T>::put(job_id + 1);

            Self::deposit_event(Event::JobCreated {
                job_id,
                submitter: who,
                job_type: job_type.into_inner(),
                vram_required_mb,
            });

            Ok(())
        }

        /// Claim a job for execution.
        ///
        /// Called by the worker node that will execute the job.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(20_000, 0))]
        pub fn claim_job(
            origin: OriginFor<T>,
            job_id: u64,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = frame_system::Pallet::<T>::block_number();

            // Pillar nodes cannot claim compute jobs. Bones hold, muscles work.
            ensure!(T::NodeCapability::can_compute(&who), Error::<T>::NotComputeNode);

            Jobs::<T>::try_mutate(job_id, |maybe_job| -> DispatchResult {
                let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
                ensure!(job.status == JobStatus::Open, Error::<T>::InvalidStatus);

                job.worker = Some(who.clone());
                job.status = JobStatus::Claimed;
                job.claimed_at = now;

                Self::deposit_event(Event::JobClaimed {
                    job_id,
                    worker: who,
                });

                Ok(())
            })
        }

        /// Complete a job with result hash and duration.
        ///
        /// Called by the worker after GPU execution finishes.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(25_000, 0))]
        pub fn complete_job(
            origin: OriginFor<T>,
            job_id: u64,
            result_hash: BoundedVec<u8, ConstU32<64>>,
            duration_ms: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let now = frame_system::Pallet::<T>::block_number();

            Jobs::<T>::try_mutate(job_id, |maybe_job| -> DispatchResult {
                let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
                ensure!(job.status == JobStatus::Claimed, Error::<T>::InvalidStatus);
                ensure!(job.worker.as_ref() == Some(&who), Error::<T>::NotWorker);

                job.status = JobStatus::Completed;
                job.completed_at = now;
                job.result_hash = result_hash.clone();
                job.duration_ms = duration_ms;

                TotalCompleted::<T>::mutate(|c| *c = c.saturating_add(1));
                WorkerJobs::<T>::mutate(&who, |c| *c = c.saturating_add(1));

                Self::deposit_event(Event::JobCompleted {
                    job_id,
                    worker: who,
                    duration_ms,
                    result_hash: result_hash.into_inner(),
                });

                Ok(())
            })
        }

        /// Pathway-C: submit a batch of signed worker receipts.
        ///
        /// The caller is the coordinator (any signed origin in v1 — coordinator's
        /// chain account is the trust gate). Each receipt records that a worker
        /// completed an inference job off-chain; the worker's Ed25519 signature
        /// is stored verbatim for retroactive audit (per-receipt verification
        /// lands in v2 once the worker-side signing format is canonicalized).
        ///
        /// Storage effects per accepted receipt:
        ///   - Receipts[next_receipt_id] = record
        ///   - WorkerJobs[worker] += 1
        ///   - WorkerTokens[worker] += tokens_generated
        ///   - TotalReceipts += 1
        ///
        /// Future v2 will gate sig-verify failures via `Error::InvalidSignature`
        /// and feed `WorkerTokens` into the emission pallet for NRN minting.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(50_000, 0).saturating_add(
            Weight::from_parts(10_000, 0).saturating_mul(batch.len() as u64)
        ))]
        pub fn submit_receipt_batch(
            origin: OriginFor<T>,
            batch: BoundedVec<ReceiptRecord<T::AccountId, BlockNumberFor<T>>, ConstU32<128>>,
        ) -> DispatchResult {
            let submitter = ensure_signed(origin)?;
            ensure!(!batch.is_empty(), Error::<T>::EmptyBatch);

            let now = frame_system::Pallet::<T>::block_number();
            let mut total_tokens: u64 = 0;
            let count = batch.len() as u32;

            for mut record in batch.into_iter() {
                let receipt_id = NextReceiptId::<T>::get();
                NextReceiptId::<T>::put(receipt_id.saturating_add(1));

                record.recorded_at = now;
                let worker = record.worker.clone();
                let tokens = record.tokens_generated;
                let compute_class_bytes = record.compute_class.clone().into_inner();

                Receipts::<T>::insert(receipt_id, record);

                WorkerJobs::<T>::mutate(&worker, |c| *c = c.saturating_add(1));
                WorkerTokens::<T>::mutate(&worker, |c| *c = c.saturating_add(tokens as u64));
                TotalReceipts::<T>::mutate(|c| *c = c.saturating_add(1));
                total_tokens = total_tokens.saturating_add(tokens as u64);

                Self::deposit_event(Event::ReceiptRecorded {
                    receipt_id,
                    worker,
                    tokens_generated: tokens,
                    compute_class: compute_class_bytes,
                });
            }

            Self::deposit_event(Event::ReceiptBatchSubmitted {
                submitter,
                count,
                total_tokens,
            });

            Ok(())
        }

        /// Verify a completed job (sudo in Phase 1, automated in Phase 2).
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(15_000, 0))]
        pub fn verify_job(
            origin: OriginFor<T>,
            job_id: u64,
            passed: bool,
        ) -> DispatchResult {
            ensure_root(origin)?;

            Jobs::<T>::try_mutate(job_id, |maybe_job| -> DispatchResult {
                let job = maybe_job.as_mut().ok_or(Error::<T>::JobNotFound)?;
                ensure!(job.status == JobStatus::Completed, Error::<T>::InvalidStatus);

                if passed {
                    job.status = JobStatus::Verified;
                    if let Some(ref worker) = job.worker {
                        Self::deposit_event(Event::JobVerified {
                            job_id,
                            worker: worker.clone(),
                        });
                    }
                } else {
                    job.status = JobStatus::Disputed;
                    TotalFailed::<T>::mutate(|c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::JobFailed {
                        job_id,
                        reason: b"verification_failed".to_vec(),
                    });
                }

                Ok(())
            })
        }
    }

    // --- Block Hooks ---

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(now: BlockNumberFor<T>) {
            let job_timeout = T::JobTimeout::get();
            let exec_timeout = T::ExecutionTimeout::get();

            // Expire stale jobs
            for (job_id, mut job) in Jobs::<T>::iter() {
                let age: u32 = now.saturating_sub(job.created_at).try_into().unwrap_or(u32::MAX);

                match job.status {
                    JobStatus::Open if age >= job_timeout => {
                        job.status = JobStatus::Failed;
                        TotalFailed::<T>::mutate(|c| *c = c.saturating_add(1));
                        Jobs::<T>::insert(job_id, job);
                        Self::deposit_event(Event::JobFailed {
                            job_id,
                            reason: b"open_timeout".to_vec(),
                        });
                    }
                    JobStatus::Claimed => {
                        let claimed_age: u32 = now.saturating_sub(job.claimed_at)
                            .try_into().unwrap_or(u32::MAX);
                        if claimed_age >= exec_timeout {
                            job.status = JobStatus::Failed;
                            TotalFailed::<T>::mutate(|c| *c = c.saturating_add(1));
                            Jobs::<T>::insert(job_id, job);
                            Self::deposit_event(Event::JobFailed {
                                job_id,
                                reason: b"execution_timeout".to_vec(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // --- Public API ---

    impl<T: Config> Pallet<T> {
        /// Total completed jobs (for emission reward calculation).
        pub fn completed_count() -> u64 {
            TotalCompleted::<T>::get()
        }

        /// Jobs completed by a specific worker.
        pub fn worker_completed(who: &T::AccountId) -> u64 {
            WorkerJobs::<T>::get(who)
        }
    }
}
