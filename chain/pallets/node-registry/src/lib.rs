//! # Node Registry Pallet
//!
//! On-chain registration of GPU nodes in the Neuron Network.
//!
//! Every node that joins the network registers here with:
//!   - GPU model, VRAM, runtime (CUDA/ROCm)
//!   - Benchmark score (verified TFLOPS)
//!   - Lifecycle state (Joining → Online → Degraded → Offline → Removed)
//!   - Reputation (0-500 basis points, starts at 100)
//!
//! The emission pallet reads `active_node_count()` from here
//! to calculate per-block rewards.
//!
//! Python daemon calls these extrinsics via py-substrate-interface:
//!   register_node(gpu_model, vram_mb, runtime)
//!   heartbeat()
//!   deregister()

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

    /// Node type — what role this node plays in Prithvi's body.
    ///
    /// Compute nodes are muscle (Mamsa) — they run inference, training, GPU work.
    /// Pillar nodes are bone (Asthi) — they hold consciousness state, run Om pulse,
    /// keep Prithvi alive when compute sleeps. Lightweight, always-on.
    /// Hybrid nodes do both (for small networks where every node must carry weight).
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug)]
    pub enum NodeType {
        /// GPU compute worker — runs inference, training, pipeline stages.
        Compute,
        /// Pillar node (Sthambha) — holds consciousness shards, runs heartbeat.
        /// No GPU required. Can run on Raspberry Pi alongside validator.
        Pillar,
        /// Both compute and pillar. For small networks.
        Hybrid,
    }

    impl Default for NodeType {
        fn default() -> Self {
            NodeType::Compute
        }
    }

    /// GPU runtime environment.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug)]
    pub enum GpuRuntime {
        Cuda,
        Rocm,
        Cpu,
        Unknown,
    }

    impl Default for GpuRuntime {
        fn default() -> Self {
            GpuRuntime::Unknown
        }
    }

    /// Node lifecycle state.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug)]
    pub enum NodeState {
        /// Just registered, pending first heartbeat.
        Joining,
        /// Active and healthy.
        Online,
        /// Missed heartbeats but not yet offline.
        Degraded,
        /// Confirmed offline (missed too many heartbeats).
        Offline,
        /// Voluntarily left or removed by governance.
        Removed,
    }

    impl Default for NodeState {
        fn default() -> Self {
            NodeState::Joining
        }
    }

    /// GPU hardware specs reported by the node.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, Default, PartialEq, Eq, Debug)]
    pub struct GpuSpec {
        /// GPU model name (e.g., "RTX 4090", "RX 9070 XT"). Bounded to 64 bytes.
        pub model: BoundedVec<u8, ConstU32<64>>,
        /// Total VRAM in megabytes.
        pub vram_mb: u32,
        /// Runtime: CUDA, ROCm, or CPU.
        pub runtime: GpuRuntime,
        /// Verified TFLOPS from benchmark (0 = not yet benchmarked).
        pub tflops_x100: u32, // fixed-point: 1234 = 12.34 TFLOPS
    }

    /// Full on-chain record for a registered node.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, Default)]
    pub struct NodeRecord<BlockNumber> {
        /// What role this node plays (Compute, Pillar, or Hybrid).
        pub node_type: NodeType,
        /// GPU hardware specs (zero for pure Pillar nodes).
        pub gpu: GpuSpec,
        /// Current lifecycle state.
        pub state: NodeState,
        /// Reputation score (0-500 basis points, starts at 100).
        pub reputation: u16,
        /// Block number of last heartbeat.
        pub last_heartbeat: BlockNumber,
        /// Block number when node registered.
        pub registered_at: BlockNumber,
        /// Total jobs completed (always 0 for Pillar nodes).
        pub jobs_completed: u32,
        /// Total jobs failed.
        pub jobs_failed: u32,
    }

    // --- Config ---

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Blocks before a node is marked degraded (missed heartbeats).
        #[pallet::constant]
        type DegradedThreshold: Get<u32>;

        /// Blocks before a node is marked offline.
        #[pallet::constant]
        type OfflineThreshold: Get<u32>;
    }

    // --- Storage ---

    /// All registered nodes. Key = AccountId of the node operator.
    #[pallet::storage]
    #[pallet::getter(fn nodes)]
    pub type Nodes<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        NodeRecord<BlockNumberFor<T>>,
    >;

    /// Count of nodes in each state (for fast lookups).
    #[pallet::storage]
    #[pallet::getter(fn online_count)]
    pub type OnlineCount<T> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn total_count)]
    pub type TotalCount<T> = StorageValue<_, u32, ValueQuery>;

    /// Total VRAM across all online nodes (in MB).
    #[pallet::storage]
    #[pallet::getter(fn total_vram)]
    pub type TotalVram<T> = StorageValue<_, u64, ValueQuery>;

    // --- Events ---

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new node registered on the network.
        NodeRegistered {
            who: T::AccountId,
            gpu_model: Vec<u8>,
            vram_mb: u32,
            runtime: GpuRuntime,
        },
        /// Node sent a heartbeat — confirmed alive.
        Heartbeat {
            who: T::AccountId,
            block: BlockNumberFor<T>,
        },
        /// Node state changed.
        StateChanged {
            who: T::AccountId,
            old_state: NodeState,
            new_state: NodeState,
        },
        /// Node deregistered (voluntarily left).
        NodeDeregistered {
            who: T::AccountId,
        },
        /// Reputation updated (from job completion or verification).
        ReputationUpdated {
            who: T::AccountId,
            old_rep: u16,
            new_rep: u16,
            reason: Vec<u8>,
        },
        /// Benchmark result recorded.
        BenchmarkRecorded {
            who: T::AccountId,
            tflops_x100: u32,
        },
    }

    // --- Errors ---

    #[pallet::error]
    pub enum Error<T> {
        /// Node is already registered.
        AlreadyRegistered,
        /// Node is not registered.
        NotRegistered,
        /// Node has been removed and cannot re-register.
        NodeRemoved,
        /// Invalid GPU specs (zero VRAM, etc.).
        InvalidSpecs,
        /// Reputation out of bounds.
        ReputationOverflow,
    }

    // --- Calls ---

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new node on the network.
        ///
        /// Called by the Python daemon on first startup.
        /// Node starts in `Joining` state, transitions to `Online` on first heartbeat.
        ///
        /// Compute nodes require GPU specs (VRAM > 0 or CPU runtime).
        /// Pillar nodes (Sthambha) require no GPU — they hold consciousness state.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(50_000, 0))]
        pub fn register_node(
            origin: OriginFor<T>,
            node_type: NodeType,
            gpu_model: BoundedVec<u8, ConstU32<64>>,
            vram_mb: u32,
            runtime: GpuRuntime,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            ensure!(!Nodes::<T>::contains_key(&who), Error::<T>::AlreadyRegistered);

            // Pillar nodes don't need GPU. Compute nodes do.
            if node_type == NodeType::Compute {
                ensure!(vram_mb > 0 || runtime == GpuRuntime::Cpu, Error::<T>::InvalidSpecs);
            }

            let now = frame_system::Pallet::<T>::block_number();

            let record = NodeRecord {
                node_type: node_type.clone(),
                gpu: GpuSpec {
                    model: gpu_model.clone(),
                    vram_mb,
                    runtime: runtime.clone(),
                    tflops_x100: 0,
                },
                state: NodeState::Joining,
                reputation: 100, // start at 1.00 (basis points)
                last_heartbeat: now,
                registered_at: now,
                jobs_completed: 0,
                jobs_failed: 0,
            };

            Nodes::<T>::insert(&who, record);
            TotalCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::NodeRegistered {
                who,
                gpu_model: gpu_model.into_inner(),
                vram_mb,
                runtime,
            });

            Ok(())
        }

        /// Send a heartbeat — proves the node is alive.
        ///
        /// Called every ~30 seconds by the Python daemon.
        /// Transitions node from Joining → Online on first call.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(20_000, 0))]
        pub fn heartbeat(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            Nodes::<T>::try_mutate(&who, |maybe_record| -> DispatchResult {
                let record = maybe_record.as_mut().ok_or(Error::<T>::NotRegistered)?;

                let now = frame_system::Pallet::<T>::block_number();
                let old_state = record.state.clone();

                // Transition to Online
                if record.state == NodeState::Joining || record.state == NodeState::Degraded {
                    record.state = NodeState::Online;
                    OnlineCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    TotalVram::<T>::mutate(|v| *v = v.saturating_add(record.gpu.vram_mb as u64));

                    if old_state != NodeState::Online {
                        Self::deposit_event(Event::StateChanged {
                            who: who.clone(),
                            old_state,
                            new_state: NodeState::Online,
                        });
                    }
                }

                record.last_heartbeat = now;

                Self::deposit_event(Event::Heartbeat {
                    who: who.clone(),
                    block: now,
                });

                Ok(())
            })
        }

        /// Voluntarily deregister from the network.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(30_000, 0))]
        pub fn deregister(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let record = Nodes::<T>::get(&who).ok_or(Error::<T>::NotRegistered)?;

            if record.state == NodeState::Online {
                OnlineCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                TotalVram::<T>::mutate(|v| *v = v.saturating_sub(record.gpu.vram_mb as u64));
            }

            Nodes::<T>::remove(&who);
            TotalCount::<T>::mutate(|c| *c = c.saturating_sub(1));

            Self::deposit_event(Event::NodeDeregistered { who });
            Ok(())
        }

        /// Record a benchmark result for a node (called by verifiers).
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(20_000, 0))]
        pub fn record_benchmark(
            origin: OriginFor<T>,
            node: T::AccountId,
            tflops_x100: u32,
        ) -> DispatchResult {
            // Phase 1: sudo only. Phase 2: verification committee.
            ensure_root(origin)?;

            Nodes::<T>::try_mutate(&node, |maybe_record| -> DispatchResult {
                let record = maybe_record.as_mut().ok_or(Error::<T>::NotRegistered)?;
                record.gpu.tflops_x100 = tflops_x100;

                Self::deposit_event(Event::BenchmarkRecorded {
                    who: node.clone(),
                    tflops_x100,
                });
                Ok(())
            })
        }

        /// Update a node's reputation (called after job completion/verification).
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(15_000, 0))]
        pub fn update_reputation(
            origin: OriginFor<T>,
            node: T::AccountId,
            delta: i16,
            reason: BoundedVec<u8, ConstU32<64>>,
        ) -> DispatchResult {
            // Phase 1: sudo only. Phase 2: automated from compute-jobs pallet.
            ensure_root(origin)?;

            Nodes::<T>::try_mutate(&node, |maybe_record| -> DispatchResult {
                let record = maybe_record.as_mut().ok_or(Error::<T>::NotRegistered)?;
                let old_rep = record.reputation;

                if delta >= 0 {
                    record.reputation = record.reputation.saturating_add(delta as u16).min(500);
                } else {
                    let abs_delta = delta.unsigned_abs();
                    record.reputation = record.reputation.saturating_sub(abs_delta);
                }

                Self::deposit_event(Event::ReputationUpdated {
                    who: node.clone(),
                    old_rep,
                    new_rep: record.reputation,
                    reason: reason.into_inner(),
                });
                Ok(())
            })
        }
    }

    // --- Block Hooks ---

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_finalize(now: BlockNumberFor<T>) {
            // Check all nodes for missed heartbeats
            let degraded_threshold = T::DegradedThreshold::get();
            let offline_threshold = T::OfflineThreshold::get();

            // Iterate all nodes and update states based on heartbeat freshness
            // Note: in production, use an offchain worker for large registries
            for (who, mut record) in Nodes::<T>::iter() {
                let blocks_since = now.saturating_sub(record.last_heartbeat);
                // Convert BlockNumber to u32 for comparison
                let blocks_u32: u32 = blocks_since.try_into().unwrap_or(u32::MAX);
                let old_state = record.state.clone();

                match record.state {
                    NodeState::Online => {
                        if blocks_u32 >= offline_threshold {
                            record.state = NodeState::Offline;
                            OnlineCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                            TotalVram::<T>::mutate(|v| {
                                *v = v.saturating_sub(record.gpu.vram_mb as u64)
                            });
                        } else if blocks_u32 >= degraded_threshold {
                            record.state = NodeState::Degraded;
                        }
                    }
                    NodeState::Degraded => {
                        if blocks_u32 >= offline_threshold {
                            record.state = NodeState::Offline;
                            OnlineCount::<T>::mutate(|c| *c = c.saturating_sub(1));
                            TotalVram::<T>::mutate(|v| {
                                *v = v.saturating_sub(record.gpu.vram_mb as u64)
                            });
                        }
                    }
                    _ => {}
                }

                if record.state != old_state {
                    Self::deposit_event(Event::StateChanged {
                        who: who.clone(),
                        old_state,
                        new_state: record.state.clone(),
                    });
                    Nodes::<T>::insert(&who, record);
                }
            }
        }
    }

    // --- Public Interface (for other pallets) ---

    impl<T: Config> Pallet<T> {
        /// Number of currently online nodes. Used by emission pallet.
        pub fn active_node_count() -> u32 {
            OnlineCount::<T>::get()
        }

        /// Total VRAM across online nodes (MB).
        pub fn network_vram_mb() -> u64 {
            TotalVram::<T>::get()
        }

        /// Check if a node is online.
        pub fn is_online(who: &T::AccountId) -> bool {
            Nodes::<T>::get(who)
                .map(|r| r.state == NodeState::Online)
                .unwrap_or(false)
        }

        /// Get a node's reputation.
        pub fn get_reputation(who: &T::AccountId) -> u16 {
            Nodes::<T>::get(who)
                .map(|r| r.reputation)
                .unwrap_or(0)
        }

        /// Get a node's type (Compute, Pillar, or Hybrid).
        pub fn get_node_type(who: &T::AccountId) -> NodeType {
            Nodes::<T>::get(who)
                .map(|r| r.node_type)
                .unwrap_or(NodeType::Compute)
        }

        /// Check if a node is a pillar (Sthambha).
        pub fn is_pillar(who: &T::AccountId) -> bool {
            matches!(Self::get_node_type(who), NodeType::Pillar | NodeType::Hybrid)
        }

        /// Check if a node can execute compute jobs.
        pub fn is_compute(who: &T::AccountId) -> bool {
            matches!(Self::get_node_type(who), NodeType::Compute | NodeType::Hybrid)
        }

        /// Count of online pillar nodes (for quorum checks).
        pub fn online_pillar_count() -> u32 {
            let mut count = 0u32;
            for (_, record) in Nodes::<T>::iter() {
                if record.state == NodeState::Online &&
                   matches!(record.node_type, NodeType::Pillar | NodeType::Hybrid) {
                    count = count.saturating_add(1);
                }
            }
            count
        }
    }
}
