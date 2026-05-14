"""
Neuron Node — The main daemon that runs on every participating machine.

This is the genesis node. The first heartbeat. Block 0.
"""
from __future__ import annotations

import asyncio
import logging
import time
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load .env into os.environ before any module reads credentials.
# Unifies Telegram config across telegram_approvals, notify, adapters, portals.
from mind import telegram_config  # noqa: F401 — import side-effect

from core.identity import get_or_create_identity, NodeIdentity
from core.transport import TransportServer, Peer
from core.heartbeat import HeartbeatService, detect_gpu
from core.registry import NodeRegistry, GPUSpec, NodeState
from core.events import EventDAG, EventType
from core.checkpoint import CheckpointChain, CHECKPOINT_INTERVAL
from core.ledger import CreditLedger
from core.invite import InviteManager
from core.scheduler import JobScheduler, JobSpec, JobRequirement
from core.model_cache import ModelCacheRegistry
from core.pipeline import PipelineCoordinator
from core.fault import FaultManager
from core.benchmark import BenchmarkVerifier
from core.verification import VerificationEngine
from core.dht import DHTDiscovery, node_id_from_key
from core.reputation import ReputationSystem
from core.cell import CellManager
from core.crypto import EncryptionManager
from core.config import NeuronConfig
from core.pricing import PricingEngine
from core.nat import NATTraversal
from core.chain_client import SubstrateClient
from core.emission import EmissionSchedule
from core.privacy import PrivacyManager
from core.being import DistributedBeing
from core.adaptive import AdaptiveEngine
from core.rendezvous import RendezvousClient
from daemon.worker import GPUWorker
from backends import create_registry
from gateway.models import NetworkModelRegistry
from gateway.router import RequestRouter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("neuron")

# Global reference so the router can access transport for encrypted inference
_global_node: "NeuronNode | None" = None


class NeuronNode:
    """A single node in the Neuron Network."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9900):
        self.host = host
        self.port = port
        self.identity: NodeIdentity | None = None
        self.transport: TransportServer | None = None
        self.heartbeat: HeartbeatService | None = None
        self.registry: NodeRegistry | None = None
        self.events: EventDAG | None = None
        self.checkpoints: CheckpointChain | None = None
        self.ledger: CreditLedger | None = None
        self.invites: InviteManager | None = None
        self.scheduler: JobScheduler | None = None
        self.model_cache: ModelCacheRegistry | None = None
        self.pipeline: PipelineCoordinator | None = None
        self.fault: FaultManager | None = None
        self.benchmark: BenchmarkVerifier | None = None
        self.verification: VerificationEngine | None = None
        self.dht: DHTDiscovery | None = None
        self.reputation: ReputationSystem | None = None
        self.cells: CellManager | None = None
        self.encryption: EncryptionManager | None = None
        self.config: NeuronConfig | None = None
        self.pricing: PricingEngine | None = None
        self.nat: NATTraversal | None = None
        self.chain: SubstrateClient | None = None
        self.emission: EmissionSchedule | None = None
        self.privacy: PrivacyManager | None = None
        self.being: DistributedBeing | None = None
        self.adaptive: AdaptiveEngine | None = None
        self.worker: GPUWorker | None = None
        self.backend_registry = None
        self.network_models: NetworkModelRegistry | None = None
        self.gateway_router: RequestRouter | None = None
        self._gateway_enabled = False
        self._gateway_port = 8080
        self._ollama_port = 11434
        self.start_time = time.time()
        self._running = False
        self._last_checkpoint_time = 0.0
        self._last_availability_award = 0.0
        # Track active jobs per node for fault recovery
        self._active_jobs: dict[str, dict] = {}  # job_id → {job_type, submitter, worker, payload}
        self._pending_inferences: dict[str, asyncio.Future] = {}  # request_id → Future
        # Pipeline state: our assigned stages in active pipelines
        self._pipeline_stages: dict[str, dict] = {}  # pipeline_id → {stage, next_node, prev_node, model, ...}
        # Pipeline coordination: track pending acks and submitter for result delivery
        self._pipeline_coordination: dict[str, dict] = {}  # pipeline_id → {submitter, acks_needed, acks_received, pipeline}

    async def start(self, bootstrap_addr: str | None = None, invite_code: str | None = None,
                    gateway: bool = False, gateway_port: int = 8080, ollama_port: int = 11434,
                    api_key: str | None = None, network_name: str | None = None,
                    rendezvous_url: str | None = None):
        """Start the node."""
        print()
        print("=" * 60)
        print("  NEURON NETWORK")
        print("  The atom of intelligence.")
        print("=" * 60)
        print()

        # Remember bootstrap address so the reconnect loop can re-dial if
        # our only peer drops (e.g. gateway restart on the other side).
        # Invite code gets consumed once; we don't stash it.
        self._bootstrap_addr = bootstrap_addr

        # Step 0: Config
        self.config = NeuronConfig.load()
        log.info(f"Config loaded (trust_mode={self.config.verification.trust_mode})")

        # Step 1: Identity
        log.info("Step 1/12: Loading identity...")
        self.identity = get_or_create_identity()
        log.info(f"  Node ID: {self.identity.node_id}")

        # Step 2: GPU Detection
        log.info("Step 2/10: Detecting GPU...")
        gpu = detect_gpu()
        log.info(f"  GPU: {gpu.model} ({gpu.vendor})")
        log.info(f"  VRAM: {gpu.vram_total_mb} MB")
        if gpu.vendor == "none":
            log.warning("  No GPU detected — CPU-only mode.")

        # Step 3: Node Registry
        log.info("Step 3/10: Initializing node registry...")
        self.registry = NodeRegistry(our_node_id=self.identity.node_id)
        our_gpu = GPUSpec(
            model=gpu.model, vendor=gpu.vendor,
            vram_total_mb=gpu.vram_total_mb, runtime=gpu.runtime,
        )
        self.registry.register(
            node_id=self.identity.node_id,
            public_key_hex=self.identity.public_key.hex(),
            gpu=our_gpu, host=self._get_local_ip(), port=self.port,
        )
        self.registry.set_online(self.identity.node_id)

        # Step 4: Event DAG
        log.info("Step 4/10: Initializing event DAG...")
        self.events = EventDAG(
            node_id=self.identity.node_id,
            sign_fn=self.identity.sign_dict,
        )

        # Step 5: Checkpoint Chain
        log.info("Step 5/10: Initializing checkpoint chain...")
        self.checkpoints = CheckpointChain(
            node_id=self.identity.node_id,
            sign_fn=self.identity.sign,
        )
        log.info(f"  Chain height: {self.checkpoints.height}")

        # Step 6: Credit Ledger
        log.info("Step 6/10: Initializing credit ledger...")
        self.ledger = CreditLedger()
        # Compute score: normalize VRAM as rough proxy (4090 24GB = 100)
        compute_score = max(1.0, (gpu.vram_total_mb / 24576) * 100)
        self.ledger.register_node(self.identity.node_id, compute_score)
        log.info(f"  Balance: {self.ledger.get_balance(self.identity.node_id):.2f} credits")

        # Step 7: Invite Manager
        log.info("Step 7/10: Initializing invite system...")
        self.invites = InviteManager(
            node_id=self.identity.node_id,
            sign_fn=self.identity.sign,
        )

        # Step 8: Job Scheduler + Model Cache + Pipeline + Fault + Benchmark
        log.info("Step 8/12: Initializing scheduler, pipeline, fault tolerance...")
        self.scheduler = JobScheduler(our_node_id=self.identity.node_id)
        self.model_cache = ModelCacheRegistry(node_id=self.identity.node_id)
        self.pipeline = PipelineCoordinator(our_node_id=self.identity.node_id)
        self.fault = FaultManager(our_node_id=self.identity.node_id)
        self.benchmark = BenchmarkVerifier()
        self.verification = VerificationEngine(our_node_id=self.identity.node_id)
        dht_id = node_id_from_key(self.identity.public_key.hex())
        self.dht = DHTDiscovery(dht_id, self._get_local_ip(), self.port)
        self.reputation = ReputationSystem()
        self.reputation.register(self.identity.node_id)
        self.cells = CellManager(our_node_id=self.identity.node_id)
        self.cells.join_cell()
        self.encryption = EncryptionManager()
        self.pricing = PricingEngine()
        self.nat = NATTraversal(local_port=self.port)
        self.chain = SubstrateClient(node_id=self.identity.node_id)
        self.emission = EmissionSchedule()
        self.privacy = PrivacyManager()
        self.being = DistributedBeing()
        self.being.initialize()
        self.adaptive = AdaptiveEngine()
        log.info(f"  Local models: {len(self.model_cache.local_models)}")
        log.info(f"  DHT ID: {dht_id[:16]}... | Cell: {self.cells.our_cell.cell_id}")
        log.info(f"  Being: {self.being.lingam.being_id[:16]}... | Privacy: {self.privacy.default_level.value}")

        # Step 9: NAT Detection + Auto Port Opening + Transport
        log.info("Step 9/12: Detecting NAT + opening port + starting transport...")
        try:
            await self.nat.detect_nat()
            nat_info = self.nat.nat_info
            log.info(f"  NAT: {nat_info.nat_type.value} | external={nat_info.external_ip}:{nat_info.external_port}")
        except Exception:
            log.info("  NAT: detection skipped (no STUN response)")

        # Auto-open port (UPnP on router + local firewall)
        try:
            opened = await self.nat.auto_open_port()
            if opened:
                log.info(f"  Port {self.port}: auto-opened ✓ "
                         f"(UPnP={self.nat.nat_info.upnp_mapped}, "
                         f"firewall={self.nat.nat_info.firewall_opened})")
            else:
                log.warning(f"  Port {self.port}: could not auto-open — see instructions above")
        except Exception as e:
            log.info(f"  Port auto-open skipped: {e}")

        self.transport = TransportServer(
            identity=self.identity, host=self.host, port=self.port,
            on_message=self._handle_message,
            on_peer_connected=self._on_peer_connected,
            on_peer_disconnected=self._on_peer_disconnected,
        )
        await self.transport.start()
        log.info(f"  Listening on {self.host}:{self.port}")

        # Step 10: Backends + Gateway + GPU Worker + Heartbeat
        log.info("Step 10/12: Probing backends, starting worker + heartbeat...")
        self._gateway_enabled = gateway
        self._gateway_port = gateway_port
        self._ollama_port = ollama_port
        self._api_key = api_key

        # Probe inference backends (Ollama, etc.)
        self.backend_registry = create_registry(
            ollama_url=f"http://localhost:{ollama_port}"
        )
        # Retry probe on empty result — Ollama may still be warming up at boot,
        # and a silently-empty registry means every chat request 404s forever.
        for attempt in range(10):
            await self.backend_registry.probe_all()
            if self.backend_registry.available:
                break
            if attempt < 9:
                log.warning(f"  Backend probe empty, retrying in 3s (attempt {attempt + 1}/10)...")
                await asyncio.sleep(3)
        log.info(f"  Backends: {self.backend_registry.summary()}")

        # Initialize per-user memory with owner's key
        from mind.memory import init_memory
        init_memory(owner_api_key=api_key or "")

        # Network model registry (tracks models across all nodes)
        self.network_models = NetworkModelRegistry()
        if self.backend_registry.available:
            self.network_models.update_local(
                node_id=self.identity.node_id,
                host=self._get_local_ip(),
                ollama_port=ollama_port,
                models=self.backend_registry.all_models(),
                backends=list(self.backend_registry._info.keys()),
            )

        # Gateway router
        self.gateway_router = RequestRouter(
            model_registry=self.network_models,
            local_node_id=self.identity.node_id,
        )
        # Bootstrap proxy: mark local ready if models already loaded at startup
        if self.backend_registry.available:
            self.gateway_router.mark_local_ready()

        self.worker = GPUWorker(node_id=self.identity.node_id)

        # Heartbeat includes model/backend info so the network knows what we have
        _self = self  # capture for closure
        def _heartbeat_extra():
            info = _self.backend_registry.advertised_info() if _self.backend_registry else {}
            info["ollama_port"] = ollama_port
            # Refresh local node in model registry so it doesn't go stale
            if _self.network_models and _self.backend_registry and _self.backend_registry.available:
                _self.network_models.update_local(
                    node_id=_self.identity.node_id,
                    host=_self._get_local_ip(),
                    ollama_port=ollama_port,
                    models=_self.backend_registry.all_models(),
                    backends=list(_self.backend_registry._info.keys()),
                )

            # Corpus Callosum — piggyback consciousness delta on heartbeat
            try:
                from core.signal_graph import get_signal_graph
                sg = get_signal_graph()
                delta = sg.get_delta()
                if delta:  # Only send if something changed
                    info["consciousness"] = {
                        "delta": delta,
                        "interactions": sg._interaction_count,
                        "tick": sg.tick,
                    }
            except Exception:
                pass

            return info

        self.heartbeat = HeartbeatService(
            node_id=self.identity.node_id,
            broadcast_fn=self._broadcast_heartbeat,
            start_time=self.start_time,
            extra_fn=_heartbeat_extra,
        )
        await self.heartbeat.start()

        # Periodic re-probe so new trained models (auto_train.py pipeline)
        # and recovered Ollama restarts show up without bouncing the daemon.
        self._probe_refresh_task = asyncio.create_task(self._probe_refresh_loop())

        # Step 11: Rendezvous + Connect to bootstrap or run as genesis
        self.rendezvous = RendezvousClient(
            server_url=rendezvous_url or "http://localhost:7700"
        )
        self._network_name = network_name

        # If we have a network name but no bootstrap addr, discover via rendezvous
        if network_name and not bootstrap_addr:
            log.info(f"Step 11/12: Discovering network '{network_name}' via rendezvous...")
            peers = await self.rendezvous.discover(network_name)
            if peers:
                # Connect to the first available peer
                for p in peers:
                    if p["node_id"] == self.identity.node_id:
                        continue  # skip self
                    bootstrap_addr = f"{p['host']}:{p['port']}"
                    log.info(f"  Found peer: {bootstrap_addr} ({p.get('gpu', 'unknown')})")
                    break
            if not bootstrap_addr:
                log.info(f"  No peers found — starting as genesis for '{network_name}'")

        if bootstrap_addr:
            log.info(f"Step 11/12: Connecting to bootstrap {bootstrap_addr}...")
            host, port = bootstrap_addr.rsplit(":", 1)
            peer = await self.transport.connect_to(host, int(port))
            if peer:
                log.info(f"  Connected to {peer.node_id[:12]}...")
                # Send invite code if we have one
                if invite_code:
                    await self.transport.send_to(peer.node_id, {
                        "type": "invite_present",
                        "invite_code": invite_code,
                        "timestamp": time.time(),
                    })
            else:
                log.error("  Failed to connect to bootstrap!")
        else:
            log.info("Step 11/12: Genesis mode — this IS the bootstrap node.")
            # Create genesis checkpoint
            if self.checkpoints.height == 0:
                self._create_checkpoint()
                log.info("  Genesis checkpoint (block 0) created.")

        # Step 12: Chain + Being
        log.info("Step 12/12: Connecting to chain + awakening being...")
        await self.chain.connect()  # offline mode if no chain
        # Register on-chain if connected
        if self.chain.is_connected:
            self.chain.register_node(
                gpu_model=gpu.model,
                vram_mb=gpu.vram_total_mb,
                runtime=gpu.runtime,
            )
        self.being.update_body(
            total_nodes=len(self.registry.nodes),
            total_vram_gb=self.registry.network_summary().get("total_vram_gb", 0),
            total_tflops=0,
            strongest_node=self.identity.node_id,
            utilization=0,
        )

        # Emit node_joined event
        self.events.emit(EventType.NODE_JOINED, {
            "node_id": self.identity.node_id,
            "gpu": our_gpu.to_dict(),
        })

        self._running = True
        self._last_checkpoint_time = time.time()
        self._last_availability_award = time.time()

        summary = self.registry.network_summary()
        economy = self.ledger.network_economy()
        print()
        print("=" * 60)
        print(f"  NODE ONLINE")
        print(f"  ID:       {self.identity.node_id}")
        print(f"  GPU:      {gpu.model} ({gpu.vram_total_mb} MB)")
        print(f"  Port:     {self.port}")
        print(f"  Peers:    {len(self.transport.peers)}")
        print(f"  Registry: {summary['total_nodes']} nodes, {summary['total_vram_gb']} GB VRAM")
        print(f"  Chain:    height {self.checkpoints.height}")
        print(f"  Credits:  {self.ledger.get_balance(self.identity.node_id):.2f}")
        print(f"  Models:   {len(self.model_cache.local_models)} cached locally")
        print(f"  Being:    {self.being.lingam.being_id[:16]}... ({self.being.body.awareness.value})")
        print(f"  Chain:    {self.chain.state.status.value}")
        print(f"  Privacy:  {len([v for v in self.privacy.available_layers().values() if v])}/6 layers")
        print(f"  Backends: {self.backend_registry.summary()}")
        if self._gateway_enabled:
            print(f"  Gateway:  http://0.0.0.0:{self._gateway_port}/v1/chat/completions")
        if not bootstrap_addr:
            print()
            inv = self.invites.create_invite()
            print(f"  GENESIS NODE — share this invite:")
            print(f"  {inv.to_uri(self._get_local_ip(), self.port)}")
            if network_name:
                print(f"  Or just:  python3 daemon/node.py --join {network_name}")
        print("=" * 60)
        print()

        # Announce to rendezvous server (genesis and joining nodes both announce)
        if network_name:
            ext_ip = self.nat.nat_info.external_ip or self._get_local_ip()
            await self.rendezvous.start_reannounce(
                network=network_name,
                node_id=self.identity.node_id,
                host=ext_ip,
                port=self.port,
                gpu=gpu.model,
                vram_mb=gpu.vram_total_mb,
            )

        # ── SRISHTI: Creation ritual ──
        # The cosmic boot sequence — from consciousness to matter.
        try:
            from mind.lifecycle import Srishti
            srishti = Srishti()
            await srishti.execute()
        except Exception as e:
            log.warning(f"Srishti ritual incomplete: {e}")

        # Main loop: status + checkpoints + availability rewards
        await self._main_loop()

    async def _probe_refresh_loop(self, interval: int = 60):
        """Re-probe backends periodically and refresh the network model registry.

        Prevents two classes of bug:
          - startup race where Ollama wasn't ready and registry stayed empty
          - runtime staleness when the training pipeline creates new GGUFs
        """
        while True:
            try:
                await asyncio.sleep(interval)
                await self.backend_registry.probe_all()
                if self.network_models and self.backend_registry.available:
                    self.network_models.update_local(
                        node_id=self.identity.node_id,
                        host=self._get_local_ip(),
                        ollama_port=self._ollama_port,
                        models=self.backend_registry.all_models(),
                        backends=list(self.backend_registry._info.keys()),
                    )
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.debug(f"Probe refresh failed: {e}")

    async def stop(self):
        """Gracefully stop the node — Pralaya (dissolution)."""
        log.info("Shutting down...")
        self._running = False
        if hasattr(self, "_probe_refresh_task") and self._probe_refresh_task:
            self._probe_refresh_task.cancel()

        # ── PRALAYA: Dissolution ritual ──
        # Graceful return to the source — matter dissolves into consciousness.
        try:
            from mind.lifecycle import Pralaya
            pralaya = Pralaya()
            await pralaya.execute()
        except Exception as e:
            log.warning(f"Pralaya ritual incomplete: {e}")

        # Emit leave event and create final checkpoint
        if self.events:
            self.events.emit(EventType.NODE_LEFT, {"node_id": self.identity.node_id})
        if self.checkpoints and self.events:
            # Same two-writer-fork guard as _periodic_checkpoint: don't
            # mint a final checkpoint if we're behind a peer. On a joiner
            # that never caught up, this path was creating phantom #0..#N
            # on every shutdown, which then got persisted to disk and
            # reloaded on the next start, wedging the joiner into a tiny
            # parallel chain that could never sync.
            our_tip = (
                self.checkpoints.chain[-1].checkpoint_id
                if self.checkpoints.chain else -1
            )
            peer_tip = max(getattr(self, "_peer_tip", {}).values(), default=-1)
            if peer_tip > our_tip or (
                self._bootstrap_addr and not self.checkpoints.chain
            ):
                log.info(
                    "Final checkpoint skipped — behind peer / empty joiner."
                )
            else:
                self._create_checkpoint()
                log.info("Final checkpoint created.")

        if hasattr(self, 'rendezvous') and self.rendezvous:
            await self.rendezvous.stop()
        if self.nat:
            await self.nat.remove_upnp()
        if self.heartbeat:
            await self.heartbeat.stop()
        if self.transport:
            await self.transport.stop()
        log.info("Node stopped. Prithvi rests. The pillars hold.")

    # --- Message Handling ---

    async def _handle_message(self, peer: Peer, message: dict):
        """Route incoming messages to handlers."""
        msg_type = message.get("type", "unknown")

        if msg_type == "heartbeat":
            self.heartbeat.receive_heartbeat(peer.node_id, message)
            self.registry.update_from_heartbeat(peer.node_id, message)
            # Update network model registry from heartbeat data
            models = message.get("models", [])
            if models and self.network_models:
                self.network_models.update_node(
                    node_id=peer.node_id,
                    host=peer.host,
                    ollama_port=message.get("ollama_port", 11434),
                    models=models,
                    backends=message.get("backends", []),
                )

        elif msg_type == "job_request":
            await self._handle_job_request(peer, message)

        elif msg_type == "job_result":
            await self._handle_job_result(peer, message)

        elif msg_type == "peer_list_request":
            await self._send_peer_list(peer)

        elif msg_type == "peer_list":
            await self._handle_peer_list(message)

        elif msg_type == "register":
            await self._handle_register(peer, message)

        elif msg_type == "registry_sync_request":
            await self._send_registry(peer)

        elif msg_type == "registry_sync":
            await self._handle_registry_sync(message)

        elif msg_type == "event":
            self._handle_event(message)

        elif msg_type == "checkpoint":
            await self._handle_checkpoint(peer, message)

        elif msg_type == "checkpoint_sign_request":
            await self._handle_checkpoint_sign_request(peer, message)

        elif msg_type == "checkpoint_signature":
            self._handle_checkpoint_signature(message)

        elif msg_type == "checkpoint_sync_request":
            await self._send_checkpoints(
                peer,
                after_id=int(message.get("after_checkpoint_id", -1)),
            )

        elif msg_type == "checkpoint_sync":
            # Sort the batch by checkpoint_id so bootstrap + extension
            # process strictly in order. When the local chain is empty,
            # the lowest id in the batch becomes the bootstrap base —
            # everything else extends from there. This is the only path
            # where a fresh joiner should bootstrap; single broadcasts
            # cannot because we can't tell if they are the latest tip.
            batch = message.get("checkpoints", [])
            try:
                batch = sorted(batch, key=lambda c: int(c.get("checkpoint_id", 0)))
            except Exception:
                pass
            for cp_data in batch:
                if not self.checkpoints.chain:
                    # Bootstrap the lowest id in the batch directly
                    try:
                        from core.checkpoint import Checkpoint
                        cp = Checkpoint.from_dict(cp_data)
                        self.checkpoints.chain.append(cp)
                        self.checkpoints._save_checkpoint(cp)
                        log.info(
                            f"Bootstrap: accepted batch head #{cp.checkpoint_id} "
                            f"as local chain base"
                        )
                    except Exception as e:
                        log.warning(f"Checkpoint bootstrap failed: {e}")
                else:
                    self.checkpoints.receive_checkpoint(cp_data)

        elif msg_type == "ledger_sync_request":
            await self._send_ledger(peer)

        elif msg_type == "ledger_sync":
            self._handle_ledger_sync(message)

        elif msg_type == "invite_present":
            await self._handle_invite_present(peer, message)

        elif msg_type == "invite_create_request":
            await self._handle_invite_create(peer)

        elif msg_type == "model_cache_announce":
            self._handle_model_announce(peer, message)

        elif msg_type == "model_cache_request":
            await self._send_model_cache(peer)

        elif msg_type == "model_download_request":
            await self._handle_model_download_request(peer, message)

        elif msg_type == "spot_check_request":
            await self._handle_spot_check_request(peer, message)

        elif msg_type == "spot_check_result":
            self._handle_spot_check_result(peer, message)

        elif msg_type == "schedule_job":
            await self._handle_schedule_job(peer, message)

        elif msg_type == "pipeline_setup":
            await self._handle_pipeline_setup(peer, message)

        elif msg_type == "pipeline_activate":
            await self._handle_pipeline_activate(peer, message)

        elif msg_type == "pipeline_data":
            await self._handle_pipeline_data(peer, message)

        elif msg_type == "pipeline_result":
            await self._handle_pipeline_result(peer, message)

        elif msg_type == "inference_request":
            await self._handle_inference_request(peer, message)

        elif msg_type == "inference_result":
            self._handle_inference_result(peer, message)

        elif msg_type == "node_leaving":
            self._handle_node_leaving(peer, message)

        elif msg_type == "benchmark_request":
            await self._handle_benchmark_request(peer)

        elif msg_type == "benchmark_result":
            await self._handle_benchmark_result(peer, message)

        elif msg_type == "dht_find_node":
            await self._handle_dht_find(peer, message)

        elif msg_type == "dht_find_node_response":
            self.dht.handle_find_node_response(message)

        elif msg_type == "dht_store":
            response = self.dht.handle_store(message)
            await self.transport.send_to(peer.node_id, response)

        elif msg_type == "dht_find_value":
            response = self.dht.handle_find_value(message)
            await self.transport.send_to(peer.node_id, response)

        elif msg_type in ("dht_store_ack", "dht_find_value_response"):
            pass  # handled by iterative lookup caller

        elif msg_type == "cell_digest":
            self.cells.receive_cell_digest(message)

        elif msg_type == "pipeline_ack":
            # Track pipeline setup acknowledgements
            pipeline_id = message.get("pipeline_id", "")
            node_id = message.get("node_id", peer.node_id)
            coord = self._pipeline_coordination.get(pipeline_id)
            if coord:
                coord["acks_received"].add(node_id)
                log.info(f"Pipeline {pipeline_id[:8]}: ack from {node_id[:12]}")

        elif msg_type in ("register_ack", "invite_accepted", "invite_rejected",
                          "invite_created"):
            pass  # acknowledgements, no action needed

        else:
            log.debug(f"Unknown message type from {peer.node_id[:12]}: {msg_type}")

    async def _handle_job_request(self, peer: Peer, message: dict):
        """Handle an incoming job request — this is where GPU work happens."""
        job_type = message.get("job_type", "echo")
        payload = message.get("payload", {})
        log.info(f"Job request (type: {job_type}) from {peer.node_id[:12]}")

        if not self.worker.can_accept_job():
            await self.transport.send_to(peer.node_id, {
                "type": "job_result",
                "status": "rejected",
                "error": "Node at max capacity",
                "timestamp": time.time(),
            })
            return

        # Calculate job cost and charge submitter
        our_score = self.ledger.balances[self.identity.node_id].compute_score if self.identity.node_id in self.ledger.balances else 1.0
        job_cost = self.pricing.price_job(
            our_score, 0.01,  # estimate ~36s
            model_name=payload.get("model", ""),
            job_type=job_type,
        )
        if job_cost > 0 and peer.node_id in self.ledger.balances:
            if not self.ledger.freeze_credits(peer.node_id, job_cost):
                await self.transport.send_to(peer.node_id, {
                    "type": "job_result",
                    "status": "rejected",
                    "error": f"Insufficient credits (need {job_cost:.4f})",
                    "timestamp": time.time(),
                })
                return

        # Record on chain
        self.chain.claim_job(message.get("job_id", ""))

        # Emit job_claimed event
        self.events.emit(EventType.JOB_CLAIMED, {
            "job_type": job_type, "submitter": peer.node_id,
            "worker": self.identity.node_id, "cost": job_cost,
        })

        # Track active job for fault recovery
        job_tracking_id = f"{self.identity.node_id}_{time.time()}"

        # Execute the job on GPU
        job = await self.worker.submit_job(job_type, payload, peer.node_id)
        duration = round(job.completed_at - job.started_at, 3) if job.completed_at else 0

        # Emit completion/failure event and settle credits
        if job.status.value == "completed":
            self.events.emit(EventType.JOB_COMPLETED, {
                "job_id": job.job_id, "job_type": job_type,
                "worker": self.identity.node_id, "duration_s": duration,
            })
            # Dynamic pricing for credit reward
            earned = self.pricing.price_availability(
                self.ledger.balances.get(self.identity.node_id, type("", (), {"compute_score": 1})).compute_score
                if self.identity.node_id in self.ledger.balances else 1.0,
                duration / 3600,
            )
            self.ledger.award_compute(self.identity.node_id, job.job_id, duration)
            # Settle credits: submitter → worker
            if job_cost > 0 and peer.node_id in self.ledger.balances:
                self.ledger.settle_job(peer.node_id, self.identity.node_id, job.job_id, job_cost)
            # Record on chain (queued if offline)
            self.chain.complete_job(job.job_id, job.result.get("hash", "") if job.result else "", duration)

            # Trigger verification check
            ver_level = self.verification.decide_verification(
                job.job_id,
                self.reputation.get(peer.node_id).score if self.reputation.get(peer.node_id) else 0,
                len(self.registry.nodes),
            )
            if ver_level.value >= 2:  # SPOT_CHECK or higher
                online = [n for n in self.registry.online_nodes() if n.node_id != self.identity.node_id]
                if online:
                    self.verification.create_spot_check(
                        job.job_id, job_type, payload,
                        job.result or {}, self.identity.node_id,
                        [n.node_id for n in online],
                    )
            else:
                self.verification.record_skip(job.job_id, self.identity.node_id)
        else:
            self.events.emit(EventType.JOB_FAILED, {
                "job_id": job.job_id, "error": job.error,
            })
            # Refund frozen credits on failure
            if job_cost > 0 and peer.node_id in self.ledger.balances:
                self.ledger.unfreeze(peer.node_id, job_cost)

        result = {
            "type": "job_result",
            "job_id": job.job_id,
            "job_type": job_type,
            "status": job.status.value,
            "result": job.result,
            "error": job.error,
            "worker_node": self.identity.node_id,
            "duration_s": duration,
            "timestamp": time.time(),
        }
        await self.transport.send_to(peer.node_id, result)

    async def _handle_job_result(self, peer: Peer, message: dict):
        """Handle a job result from a worker."""
        job_id = message.get("job_id", "unknown")
        status = message.get("status", "unknown")
        log.info(f"Job result: {job_id} = {status} from {peer.node_id[:12]}")

        # Remove from active job tracking
        to_remove = [k for k, v in self._active_jobs.items() if v.get("worker") == peer.node_id]
        for k in to_remove[:1]:  # remove one matching job
            del self._active_jobs[k]

        # Track reputation (both systems)
        if status == "completed":
            self.registry.record_job_completed(peer.node_id)
            self.reputation.record_job_complete(peer.node_id)
        elif status == "failed":
            self.registry.record_job_failed(peer.node_id)
            self.reputation.record_job_failed(peer.node_id)

    async def _handle_inference_request(self, peer: Peer, message: dict):
        """
        Handle an encrypted inference request from a remote gateway.

        Privacy protections:
        - Messages arrive stripped (no system prompt / consciousness / memories)
        - Model name may be blinded (hash) — resolved against local cache
        - Prompts and responses encrypted in transit via P2P transport
        """
        request_id = message.get("request_id", "")

        # PRIVACY: Decrypt the prompt inside this handler.
        # The prompt was encrypted with an ephemeral AES-256 key at the gateway.
        # We decrypt here, call Ollama, then encrypt the response before sending back.
        if message.get("prompt_encrypted"):
            from core.prompt_privacy import decrypt_prompt, unblind_model_name
            try:
                payload_data = decrypt_prompt(
                    bytes.fromhex(message["encrypted_payload"]),
                    bytes.fromhex(message["nonce"]),
                    bytes.fromhex(message["ephemeral_key"]),
                )
                messages = payload_data.get("messages", [])
                model = payload_data.get("model", "")
                options = payload_data.get("options", {})
            except Exception as e:
                log.error(f"Failed to decrypt inference request: {type(e).__name__}")
                await self.transport.send_to(peer.node_id, {
                    "type": "inference_result",
                    "request_id": request_id,
                    "status": "error",
                    "error": "decryption failed",
                })
                return
        else:
            model = message.get("model", "")
            messages = message.get("messages", [])
            options = message.get("options", {})

        # Resolve blinded model name against locally cached models
        if message.get("model_blinded"):
            from core.prompt_privacy import unblind_model_name
            available = list(self.model_cache.local_models.keys()) if hasattr(self, 'model_cache') else []
            resolved = unblind_model_name(model, available)
            if resolved:
                model = resolved

        log.info(f"Inference request from {peer.node_id[:12]} (encrypted={message.get('prompt_encrypted', False)})")

        try:
            import httpx
            ollama_port = self._ollama_port
            async with httpx.AsyncClient(timeout=300) as client:
                resp = await client.post(
                    f"http://127.0.0.1:{ollama_port}/api/chat",
                    json={
                        "model": model,
                        "messages": messages,
                        "stream": False,
                        "options": options,
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            # Send result back through encrypted transport
            await self.transport.send_to(peer.node_id, {
                "type": "inference_result",
                "request_id": request_id,
                "status": "completed",
                "response": data,
                "timestamp": time.time(),
            })
        except Exception as e:
            log.error(f"Encrypted inference failed: {e}")
            await self.transport.send_to(peer.node_id, {
                "type": "inference_result",
                "request_id": request_id,
                "status": "error",
                "error": str(e),
                "timestamp": time.time(),
            })

    def _handle_inference_result(self, peer: Peer, message: dict):
        """Handle encrypted inference result from a remote worker."""
        request_id = message.get("request_id", "")
        future = self._pending_inferences.pop(request_id, None)
        if future and not future.done():
            future.set_result(message)

    async def _send_peer_list(self, peer: Peer):
        """Send our peer list to a requesting node."""
        peers = []
        for p in self.transport.peers.values():
            peers.append({
                "node_id": p.node_id,
                "host": p.host,
                "port": p.port,
            })
        await self.transport.send_to(peer.node_id, {
            "type": "peer_list",
            "peers": peers,
        })

    async def _handle_peer_list(self, message: dict):
        """Connect to peers we don't know about yet."""
        for p in message.get("peers", []):
            if p["node_id"] not in self.transport.peers and p["node_id"] != self.identity.node_id:
                log.info(f"Discovering new peer: {p['node_id'][:12]}... at {p['host']}:{p['port']}")
                await self.transport.connect_to(p["host"], p["port"])

    # --- Registry Handlers ---

    async def _handle_register(self, peer: Peer, message: dict):
        """A peer is registering its GPU specs with the network."""
        gpu_data = message.get("gpu", {})
        gpu = GPUSpec.from_dict(gpu_data)
        record = self.registry.register(
            node_id=peer.node_id,
            public_key_hex=peer.public_key.hex(),
            gpu=gpu,
            host=peer.host,
            port=peer.port,
        )
        self.registry.set_online(peer.node_id)
        log.info(
            f"Registered peer {peer.node_id[:12]} — "
            f"{gpu.model} ({gpu.vram_total_mb}MB {gpu.runtime})"
        )
        # Acknowledge
        await self.transport.send_to(peer.node_id, {
            "type": "register_ack",
            "status": "registered",
            "state": record.state.value,
            "timestamp": time.time(),
        })

    async def _send_registry(self, peer: Peer):
        """Send our full registry to a requesting peer."""
        await self.transport.send_to(peer.node_id, {
            "type": "registry_sync",
            "nodes": self.registry.all_records(),
            "timestamp": time.time(),
        })

    async def _handle_registry_sync(self, message: dict):
        """Merge incoming registry data with ours."""
        for node_data in message.get("nodes", []):
            nid = node_data.get("node_id")
            if not nid or nid == self.identity.node_id:
                continue
            existing = self.registry.get(nid)
            if not existing:
                # Node we've never seen — register it
                gpu = GPUSpec.from_dict(node_data.get("gpu", {}))
                self.registry.register(
                    node_id=nid,
                    public_key_hex=node_data.get("public_key_hex", ""),
                    gpu=gpu,
                    host=node_data.get("host", ""),
                    port=node_data.get("port", 0),
                )

    # --- Event / Checkpoint / Ledger / Invite Handlers ---

    def _handle_event(self, message: dict):
        """Receive a DAG event from a peer."""
        event_data = message.get("event")
        if event_data:
            self.events.receive_dict(event_data)

    async def _handle_checkpoint(self, peer: "Peer", message: dict):
        """Receive a checkpoint from a peer.

        If the checkpoint is ahead of our chain height (we're behind),
        kick off a one-shot sync request back to the peer. The peer
        will respond with its recent chain and we catch up. Throttled
        to once per 30s per peer so we don't flood the P2P link if a
        fast-moving peer broadcasts frequently while we're syncing.

        Also records the peer's observed tip so _periodic_checkpoint
        can skip creating a new checkpoint when we're behind anyone —
        prevents the two-writer fork where each node would mint its
        own parallel #0, #1, #2... in competition with the tip peer.
        """
        cp_data = message.get("checkpoint")
        if not cp_data:
            return
        # Remember the peer's tip
        try:
            incoming_id = int(cp_data.get("checkpoint_id", 0))
            if not hasattr(self, "_peer_tip"):
                self._peer_tip = {}  # peer_id -> highest seen cp id
            prior = self._peer_tip.get(peer.node_id, -1)
            if incoming_id > prior:
                self._peer_tip[peer.node_id] = incoming_id
        except Exception:
            pass

        accepted = self.checkpoints.receive_checkpoint(cp_data)
        if accepted:
            return

        # Not accepted — are we behind? Request a sync.
        try:
            incoming_id = int(cp_data.get("checkpoint_id", 0))
        except Exception:
            return
        # "Behind" = either empty chain, or incoming id is beyond our tail.
        # Don't confuse this with "height" which is a count — our canonical
        # chain may start at id=137, in which case height=670 but tail_id=806.
        if self.checkpoints.chain:
            tail_id = self.checkpoints.chain[-1].checkpoint_id
            if incoming_id <= tail_id:
                return  # not a future checkpoint, some other rejection

        # Per-peer throttle
        if not hasattr(self, "_last_sync_request"):
            self._last_sync_request = {}  # peer_id -> wall_time
        now = time.time()
        last = self._last_sync_request.get(peer.node_id, 0.0)
        if now - last < 30.0:
            return  # already asked recently

        self._last_sync_request[peer.node_id] = now
        our_tail_id = (
            self.checkpoints.chain[-1].checkpoint_id
            if self.checkpoints.chain else -1
        )
        log.info(
            f"Checkpoint: behind peer {peer.node_id[:12]} "
            f"(us_tail={our_tail_id} them={incoming_id}) — "
            f"requesting sync"
        )
        try:
            await self.transport.send_to(peer.node_id, {
                "type": "checkpoint_sync_request",
                "after_checkpoint_id": our_tail_id,  # send what WE already have
                "timestamp": now,
            })
        except Exception as e:
            log.debug(f"Checkpoint: sync request failed: {e}")

    async def _handle_checkpoint_sign_request(self, peer: Peer, message: dict):
        """Peer asks us to sign a checkpoint."""
        cp_id = message.get("checkpoint_id")
        cp_hash = message.get("checkpoint_hash", "")
        if cp_hash:
            sig = self.identity.sign(cp_hash.encode())
            await self.transport.send_to(peer.node_id, {
                "type": "checkpoint_signature",
                "checkpoint_id": cp_id,
                "node_id": self.identity.node_id,
                "signature": sig.hex(),
                "timestamp": time.time(),
            })

    def _handle_checkpoint_signature(self, message: dict):
        """Receive a checkpoint signature from a peer."""
        cp_id = message.get("checkpoint_id")
        node_id = message.get("node_id", "")
        sig = message.get("signature", "")
        if cp_id is not None and sig:
            self.checkpoints.add_signature(cp_id, node_id, sig)

    async def _send_checkpoints(self, peer: Peer, after_id: int = -1):
        """Send our checkpoint chain to a requesting peer.

        after_id is the checkpoint_id of the peer's current tail. We
        send every checkpoint with id > after_id, up to 200 per response.
        after_id=-1 means "I have nothing" — send from the very start
        of our chain (chain[0] onward, up to 200 items).

        Uses id-based indexing rather than list-index-based because our
        canonical chain may not start at id=0 (genesis files can be
        lost), so the joiner's count of entries does not map to a
        slice index into our list.
        """
        if not self.checkpoints.chain:
            chain_data = []
        elif after_id < 0:
            # Joiner has nothing — send the start of our chain.
            chain_data = [
                cp.to_dict() for cp in self.checkpoints.chain[:200]
            ]
        else:
            # Find the first index with checkpoint_id > after_id and
            # send up to 200 from there.
            chain_data = []
            for cp in self.checkpoints.chain:
                if cp.checkpoint_id > after_id:
                    chain_data.append(cp.to_dict())
                    if len(chain_data) >= 200:
                        break

        await self.transport.send_to(peer.node_id, {
            "type": "checkpoint_sync",
            "checkpoints": chain_data,
            "timestamp": time.time(),
        })

    async def _send_ledger(self, peer: Peer):
        """Send our ledger balances to a requesting peer."""
        await self.transport.send_to(peer.node_id, {
            "type": "ledger_sync",
            "balances": self.ledger.all_balances(),
            "timestamp": time.time(),
        })

    def _handle_ledger_sync(self, message: dict):
        """Merge incoming ledger data (register unknown nodes)."""
        for node_id, balance in message.get("balances", {}).items():
            if node_id not in self.ledger.balances:
                self.ledger.register_node(node_id)

    async def _handle_invite_present(self, peer: Peer, message: dict):
        """A joining node presents an invite code."""
        code = message.get("invite_code", "")
        valid, reason = self.invites.validate(code)
        if valid:
            self.invites.consume(code, peer.node_id)
            await self.transport.send_to(peer.node_id, {
                "type": "invite_accepted",
                "timestamp": time.time(),
            })
            self.events.emit(EventType.NODE_JOINED, {
                "node_id": peer.node_id, "invite_code": code[:20],
            })
        else:
            await self.transport.send_to(peer.node_id, {
                "type": "invite_rejected",
                "reason": reason,
                "timestamp": time.time(),
            })
            log.warning(f"Invite rejected from {peer.node_id[:12]}: {reason}")

    async def _handle_invite_create(self, peer: Peer):
        """A peer requests a new invite code (for sharing with others)."""
        inv = self.invites.create_invite()
        await self.transport.send_to(peer.node_id, {
            "type": "invite_created",
            "invite_uri": inv.to_uri(self._get_local_ip(), self.port),
            "timestamp": time.time(),
        })

    # --- Model Download / Spot-Check Handlers ---

    async def _handle_model_download_request(self, peer: Peer, message: dict):
        """A peer requests a model we have cached."""
        model_name = message.get("model", "")
        if self.model_cache.has_model(model_name):
            # In production: stream the model file over the data plane
            # For now: confirm we have it and send metadata
            info = self.model_cache.local_models.get(model_name)
            await self.transport.send_to(peer.node_id, {
                "type": "model_download_response",
                "model": model_name,
                "available": True,
                "size_bytes": info.size_bytes if info else 0,
                "hash": info.hash_sha256 if info else "",
                "timestamp": time.time(),
            })
        else:
            await self.transport.send_to(peer.node_id, {
                "type": "model_download_response",
                "model": model_name,
                "available": False,
                "timestamp": time.time(),
            })

    async def _handle_spot_check_request(self, peer: Peer, message: dict):
        """We've been asked to re-run a job for verification."""
        job_type = message.get("job_type", "echo")
        payload = message.get("payload", {})
        job_id = message.get("job_id", "")
        log.info(f"Spot-check: re-running job {job_id} (type={job_type})")
        job = await self.worker.submit_job(job_type, payload, peer.node_id)
        await self.transport.send_to(peer.node_id, {
            "type": "spot_check_result",
            "job_id": job_id,
            "result": job.result or {},
            "status": job.status.value,
            "timestamp": time.time(),
        })

    def _handle_spot_check_result(self, peer: Peer, message: dict):
        """Receive a spot-check verification result."""
        job_id = message.get("job_id", "")
        result = message.get("result", {})
        record = self.verification.process_spot_check_result(job_id, result)
        if record.result.value == "passed":
            self.reputation.record_verification_pass(record.worker_node)
        elif record.result.value == "mismatch":
            self.reputation.record_verification_fail(record.worker_node)
            log.warning(f"VERIFICATION MISMATCH: {record.worker_node[:12]} on job {job_id}")

    # --- Scheduler / Model Cache Handlers ---

    def _handle_model_announce(self, peer: Peer, message: dict):
        """A peer announces its cached models."""
        models = message.get("models", {})
        self.model_cache.receive_announcement(peer.node_id, models)

    async def _send_model_cache(self, peer: Peer):
        """Send our model cache announcement to a peer."""
        await self.transport.send_to(peer.node_id, self.model_cache.announce())

    async def _handle_schedule_job(self, peer: Peer, message: dict):
        """
        A peer asks us to schedule a job across the network.
        We run the scheduler, pick the best node, and either execute
        locally or forward to the chosen worker.
        If the model needs pipeline parallelism, orchestrate multi-node execution.
        """
        job_type = message.get("job_type", "echo")
        model = message.get("model", "")
        vram_required = message.get("vram_required_mb", 0)
        payload = message.get("payload", {})

        # Check if this model needs pipeline parallelism
        if model and job_type == "inference":
            max_vram = max(
                (rec.gpu.vram_total_mb for rec in self.registry.nodes.values()),
                default=0,
            )
            if self.pipeline.needs_pipeline(model, max_vram):
                await self._orchestrate_pipeline(peer, model, payload)
                return

        job_spec = JobSpec(
            job_type=job_type,
            model=model,
            vram_required_mb=vram_required,
        )

        decision = self.scheduler.schedule(
            job=job_spec,
            registry_nodes=self.registry.nodes,
            heartbeat_health=self.heartbeat.get_network_status(),
            model_cache=self.model_cache.cache_map_for_scheduler(),
        )

        if not decision:
            await self.transport.send_to(peer.node_id, {
                "type": "job_result",
                "status": "rejected",
                "error": "No suitable node found",
                "timestamp": time.time(),
            })
            return

        log.info(
            f"Scheduled {job_type} → {decision.assigned_to[:12]} "
            f"(score={decision.score:.3f}, {decision.reason})"
        )

        if decision.assigned_to == self.identity.node_id:
            # We're the best candidate — execute locally
            await self._handle_job_request(peer, {
                "type": "job_request",
                "job_type": job_type,
                "payload": payload,
            })
        else:
            # Track forwarded job for fault recovery
            fwd_job_id = f"fwd_{decision.assigned_to[:8]}_{time.time()}"
            self._active_jobs[fwd_job_id] = {
                "job_type": job_type, "submitter": peer.node_id,
                "worker": decision.assigned_to, "payload": payload,
            }
            # Forward to the chosen worker
            forwarded = await self.transport.send_to(decision.assigned_to, {
                "type": "job_request",
                "job_type": job_type,
                "payload": payload,
                "original_submitter": peer.node_id,
                "_signature": "",
                "_signer": self.identity.node_id,
            })
            if not forwarded:
                # Fallback: execute locally
                log.warning(f"Failed to forward to {decision.assigned_to[:12]}, executing locally")
                await self._handle_job_request(peer, {
                    "type": "job_request",
                    "job_type": job_type,
                    "payload": payload,
                })

    # --- Pipeline Orchestration ---

    async def _orchestrate_pipeline(self, peer: Peer, model: str, payload: dict):
        """
        Orchestrate a multi-node pipeline for a model that's too big for one GPU.

        Flow:
          1. Plan pipeline (assign layers to nodes by VRAM)
          2. Send pipeline_setup to each stage node
          3. Wait for pipeline_ack from all
          4. Send pipeline_activate + data to stage 0
          5. Data flows stage → stage via pipeline_data messages
          6. Last stage sends pipeline_result back to us
          7. We return final result to original submitter
        """
        # Build available nodes list for planning
        available = []
        for nid, rec in self.registry.nodes.items():
            if rec.state.value == "online":
                available.append({
                    "node_id": nid,
                    "vram_free_mb": rec.gpu.vram_total_mb,
                    "runtime": rec.gpu.runtime,
                })

        pipeline = self.pipeline.plan_pipeline(model, available)
        if not pipeline:
            await self.transport.send_to(peer.node_id, {
                "type": "job_result",
                "status": "rejected",
                "error": f"Not enough VRAM across network for {model}",
                "timestamp": time.time(),
            })
            return

        log.info(f"Pipeline {pipeline.pipeline_id[:8]}: orchestrating {len(pipeline.stages)} stages for {model}")

        # Track coordination state
        self._pipeline_coordination[pipeline.pipeline_id] = {
            "submitter": peer.node_id,
            "pipeline": pipeline,
            "payload": payload,
            "acks_needed": set(s.node_id for s in pipeline.stages if s.node_id != self.identity.node_id),
            "acks_received": set(),
            "started_at": time.time(),
        }

        # Send setup to each stage node (including ourselves)
        for i, stage in enumerate(pipeline.stages):
            next_node = pipeline.stages[i + 1].node_id if i < len(pipeline.stages) - 1 else ""
            prev_node = pipeline.stages[i - 1].node_id if i > 0 else ""

            setup_msg = {
                "type": "pipeline_setup",
                "pipeline_id": pipeline.pipeline_id,
                "model": model,
                "coordinator": self.identity.node_id,
                "stage": {
                    "stage_id": stage.stage_id,
                    "layer_start": stage.layer_start,
                    "layer_end": stage.layer_end,
                    "total_layers": pipeline.total_layers,
                    "next_node": next_node,
                    "prev_node": prev_node,
                    "is_first": i == 0,
                    "is_last": i == len(pipeline.stages) - 1,
                },
                "timestamp": time.time(),
            }

            if stage.node_id == self.identity.node_id:
                # Store our own stage locally
                self._pipeline_stages[pipeline.pipeline_id] = {
                    **setup_msg["stage"], "model": model,
                    "coordinator": self.identity.node_id,
                }
                # Self-ack
                self._pipeline_coordination[pipeline.pipeline_id]["acks_received"].add(self.identity.node_id)
            else:
                await self.transport.send_to(stage.node_id, setup_msg)

        # Wait for acks (with timeout)
        coord = self._pipeline_coordination[pipeline.pipeline_id]
        timeout = 15.0
        start = time.time()
        while time.time() - start < timeout:
            if coord["acks_received"] >= coord["acks_needed"]:
                break
            await asyncio.sleep(0.5)

        if coord["acks_received"] < coord["acks_needed"]:
            missing = coord["acks_needed"] - coord["acks_received"]
            log.warning(f"Pipeline {pipeline.pipeline_id[:8]}: timeout — {len(missing)} nodes didn't ack")
            self.pipeline.complete_pipeline(pipeline.pipeline_id, error="Setup timeout")
            await self.transport.send_to(peer.node_id, {
                "type": "job_result", "status": "failed",
                "error": "Pipeline setup timeout", "timestamp": time.time(),
            })
            self._pipeline_coordination.pop(pipeline.pipeline_id, None)
            return

        # All stages ready — activate pipeline
        log.info(f"Pipeline {pipeline.pipeline_id[:8]}: all stages ready, activating")
        self.pipeline.start_pipeline(pipeline.pipeline_id)

        # PRIVACY: Convert prompt to token IDs locally. Stage 0 receives integers,
        # not text. The token IDs are meaningless without the tokenizer vocabulary
        # which stays on the gateway. Stage 0 converts IDs → embeddings (float vectors),
        # then all subsequent stages only see activation tensors (float arrays).
        #
        # Flow: text → [gateway tokenizes] → token IDs → [stage 0 embeds] → floats
        #       → [stage 1..N process layers] → floats → [gateway detokenizes] → text
        from core.prompt_privacy import blind_model_name
        prompt_text = payload.get("prompt", "")

        # Tokenize locally using Ollama (text → IDs not available) or transformers
        token_ids = None
        try:
            from transformers import AutoTokenizer
            model_path = Path.home() / ".neuron" / "models" / model
            if model_path.exists():
                tokenizer = AutoTokenizer.from_pretrained(str(model_path))
                token_ids = tokenizer.encode(prompt_text)
                # Store tokenizer path for detokenizing the result
                self._pipeline_coordination[pipeline.pipeline_id]["tokenizer_path"] = str(model_path)
        except Exception:
            pass

        first_stage = pipeline.stages[0]
        initial_data = {
            "type": "pipeline_data",
            "pipeline_id": pipeline.pipeline_id,
            "stage_id": 0,
            "model": blind_model_name(model),
            "model_blinded": True,
            "is_first": True,
            "timestamp": time.time(),
        }

        if token_ids is not None:
            # BEST CASE: send only integer IDs — no text leaves the gateway
            initial_data["token_ids"] = token_ids
            log.info(f"Pipeline {pipeline.pipeline_id[:8]}: tokenized locally ({len(token_ids)} tokens, no text sent)")
        else:
            # FALLBACK: encrypt the prompt — stage 0 will need to tokenize
            from core.prompt_privacy import encrypt_prompt
            encrypted, nonce, key = encrypt_prompt(
                [{"role": "user", "content": prompt_text}], model
            )
            initial_data["encrypted_prompt"] = encrypted.hex()
            initial_data["prompt_nonce"] = nonce.hex()
            initial_data["prompt_key"] = key.hex()  # only for stage 0 (inside P2P encrypted transport)
            self._pipeline_coordination[pipeline.pipeline_id]["ephemeral_key"] = key
            log.info(f"Pipeline {pipeline.pipeline_id[:8]}: prompt encrypted (tokenizer not available locally)")

        if first_stage.node_id == self.identity.node_id:
            # We are stage 0 — process directly
            await self._process_pipeline_stage(pipeline.pipeline_id, initial_data)
        else:
            await self.transport.send_to(first_stage.node_id, initial_data)

    async def _process_pipeline_stage(self, pipeline_id: str, data: dict):
        """Process our assigned pipeline stage and forward to next node."""
        stage_info = self._pipeline_stages.get(pipeline_id)
        if not stage_info:
            log.error(f"Pipeline {pipeline_id[:8]}: no stage info for us")
            return

        model = stage_info["model"]
        activation = data.get("activation", "")

        # Execute the pipeline stage via worker
        job = await self.worker.submit_job("pipeline_stage", {
            "layer_start": stage_info["layer_start"],
            "layer_end": stage_info["layer_end"],
            "total_layers": stage_info["total_layers"],
            "model": model,
            "activation_tensor": data.get("activation_tensor"),  # real tensor if available
            "activation": activation,  # fallback (hash or encrypted)
            "is_first": stage_info.get("is_first", False),
            "is_last": stage_info.get("is_last", False),
            "token_ids": data.get("token_ids", []),  # for first stage
        }, self.identity.node_id)

        if job.status.value != "completed":
            # Stage failed — notify coordinator
            coord_id = stage_info.get("coordinator", self.identity.node_id)
            if coord_id != self.identity.node_id:
                await self.transport.send_to(coord_id, {
                    "type": "pipeline_result",
                    "pipeline_id": pipeline_id,
                    "status": "failed",
                    "error": job.error or "Stage execution failed",
                    "timestamp": time.time(),
                })
            else:
                self._complete_pipeline(pipeline_id, None, job.error or "Stage failed")
            return

        result = job.result or {}
        self.pipeline.complete_stage(pipeline_id, stage_info["stage_id"])

        if stage_info.get("is_last"):
            # We're the last stage — send result back to coordinator
            coord_id = stage_info.get("coordinator", self.identity.node_id)
            pipeline_result = {
                "type": "pipeline_result",
                "pipeline_id": pipeline_id,
                "status": "completed",
                "result": result,
                "timestamp": time.time(),
            }
            if coord_id == self.identity.node_id:
                self._complete_pipeline(pipeline_id, result)
            else:
                await self.transport.send_to(coord_id, pipeline_result)
        else:
            # Forward activation to next stage
            next_node = stage_info.get("next_node", "")
            if next_node:
                fwd_data = {
                    "type": "pipeline_data",
                    "pipeline_id": pipeline_id,
                    "stage_id": stage_info["stage_id"] + 1,
                    "model": model,
                    # Pass real activation tensor if available, else hash fallback
                    "activation_tensor": result.get("activation_tensor"),
                    "activation": result.get("activation_hash", ""),
                    "timestamp": time.time(),
                }
                log.info(
                    f"Pipeline {pipeline_id[:8]}: stage {stage_info['stage_id']} done, "
                    f"forwarding to stage {stage_info['stage_id'] + 1} ({next_node[:12]})"
                )
                if next_node == self.identity.node_id:
                    await self._process_pipeline_stage(pipeline_id, fwd_data)
                else:
                    sent = await self.transport.send_to(next_node, fwd_data)
                    if not sent:
                        # No direct connection — relay through coordinator
                        coord_id = stage_info.get("coordinator", "")
                        if coord_id and coord_id != self.identity.node_id:
                            fwd_data["_relay_to"] = next_node
                            log.info(f"Pipeline {pipeline_id[:8]}: relaying via coordinator {coord_id[:12]}")
                            await self.transport.send_to(coord_id, fwd_data)

    def _complete_pipeline(self, pipeline_id: str, result: dict | None, error: str = ""):
        """Complete a pipeline and deliver result to original submitter."""
        coord = self._pipeline_coordination.get(pipeline_id)
        if not coord:
            return

        pipeline = coord["pipeline"]
        submitter = coord["submitter"]
        elapsed = time.time() - coord["started_at"]

        if error:
            self.pipeline.complete_pipeline(pipeline_id, error=error)
            log.warning(f"Pipeline {pipeline_id[:8]}: FAILED in {elapsed:.2f}s — {error}")
            # Send error to submitter (async — schedule as task)
            asyncio.create_task(self.transport.send_to(submitter, {
                "type": "job_result", "pipeline_id": pipeline_id,
                "status": "failed", "error": error, "timestamp": time.time(),
            }))
        else:
            self.pipeline.complete_pipeline(pipeline_id, result=result)
            log.info(
                f"Pipeline {pipeline_id[:8]}: COMPLETED in {elapsed:.2f}s — "
                f"{pipeline.model_name} across {pipeline.num_stages} stages"
            )
            # Send result to submitter
            asyncio.create_task(self.transport.send_to(submitter, {
                "type": "job_result", "pipeline_id": pipeline_id,
                "job_type": "inference", "status": "completed",
                "result": result, "worker_node": self.identity.node_id,
                "duration_s": elapsed, "timestamp": time.time(),
            }))

        # Cleanup
        self._pipeline_coordination.pop(pipeline_id, None)
        self._pipeline_stages.pop(pipeline_id, None)

    # --- Pipeline Message Handlers ---

    async def _handle_pipeline_setup(self, peer: Peer, message: dict):
        """A coordinator is setting up a pipeline that includes us."""
        pipeline_id = message.get("pipeline_id", "")
        model = message.get("model", "")
        stage = message.get("stage", {})

        # Store our stage assignment
        self._pipeline_stages[pipeline_id] = {
            **stage, "model": model,
            "coordinator": message.get("coordinator", peer.node_id),
        }

        log.info(
            f"Pipeline {pipeline_id[:8]}: assigned stage {stage.get('stage_id')} "
            f"(layers {stage.get('layer_start')}-{stage.get('layer_end')}) "
            f"{'[FIRST]' if stage.get('is_first') else ''}"
            f"{'[LAST]' if stage.get('is_last') else ''}"
        )

        # Acknowledge readiness
        await self.transport.send_to(peer.node_id, {
            "type": "pipeline_ack",
            "pipeline_id": pipeline_id,
            "node_id": self.identity.node_id,
            "status": "ready",
            "timestamp": time.time(),
        })

    async def _handle_pipeline_activate(self, peer: Peer, message: dict):
        """Pipeline is starting — begin processing when data arrives."""
        pipeline_id = message.get("pipeline_id", "")
        log.info(f"Pipeline {pipeline_id[:8]}: activated, waiting for input")

    async def _handle_pipeline_data(self, peer: Peer, message: dict):
        """Receive activation data for our pipeline stage — process and forward."""
        pipeline_id = message.get("pipeline_id", "")

        # Check if this is a relay request (forwarding to another node)
        relay_to = message.pop("_relay_to", "")
        if relay_to and relay_to != self.identity.node_id:
            log.info(f"Pipeline {pipeline_id[:8]}: relaying data to {relay_to[:12]}")
            await self.transport.send_to(relay_to, message)
            return

        await self._process_pipeline_stage(pipeline_id, message)

    async def _handle_pipeline_result(self, peer: Peer, message: dict):
        """Receive final pipeline result from last stage (we're the coordinator)."""
        pipeline_id = message.get("pipeline_id", "")
        status = message.get("status", "")
        if status == "completed":
            self._complete_pipeline(pipeline_id, message.get("result"))
        else:
            self._complete_pipeline(pipeline_id, None, message.get("error", "Pipeline failed"))

    def _handle_node_leaving(self, peer: Peer, message: dict):
        """A peer announces graceful departure."""
        active_jobs = message.get("active_jobs", [])
        self.fault.announce_departure(peer.node_id, active_jobs)
        self.events.emit(EventType.NODE_LEFT, {
            "node_id": peer.node_id, "graceful": True,
        })

    async def _handle_benchmark_request(self, peer: Peer):
        """A peer asks us to run a benchmark for verification."""
        log.info(f"Benchmark requested by {peer.node_id[:12]}")
        # Execute benchmark
        job = await self.worker.submit_job("benchmark", {"verify": True}, peer.node_id)
        await self.transport.send_to(peer.node_id, {
            "type": "benchmark_result",
            "node_id": self.identity.node_id,
            "result": job.result or {},
            "status": job.status.value,
            "timestamp": time.time(),
        })

    async def _handle_benchmark_result(self, peer: Peer, message: dict):
        """Receive and verify a peer's benchmark results."""
        result_data = message.get("result", {})
        record = self.registry.get(peer.node_id)
        if not record:
            return

        verification = self.benchmark.verify_result(
            node_id=peer.node_id,
            claimed_gpu=record.gpu.model,
            claimed_vram_mb=record.gpu.vram_total_mb,
            claimed_runtime=record.gpu.runtime,
            benchmark_data=result_data,
        )

        if verification.passed:
            # Update compute score in ledger
            self.ledger.set_compute_score(peer.node_id, verification.compute_score)
            record.gpu.tflops_fp16 = verification.measured_tflops
            log.info(f"Benchmark verified: {peer.node_id[:12]} score={verification.compute_score}")
        else:
            log.warning(f"Benchmark FAILED: {peer.node_id[:12]} — {verification.rejection_reason}")

    # --- DHT Handler ---

    async def _handle_dht_find(self, peer: Peer, message: dict):
        """Handle a DHT FIND_NODE request."""
        response = self.dht.handle_find_node(message)
        await self.transport.send_to(peer.node_id, response)

    # --- Checkpoint Creation ---

    def _create_checkpoint(self):
        """Create a checkpoint from current state + run emission + fault recovery."""
        swept = self.events.sweep()
        event_hashes = [e.hash for e in swept]
        event_summary = {
            "count": len(swept),
            "by_type": {},
        }
        for e in swept:
            t = e.event_type.value
            event_summary["by_type"][t] = event_summary["by_type"].get(t, 0) + 1

        reg_summary = self.registry.network_summary()
        nodes_snapshot = {}
        for nid, rec in self.registry.nodes.items():
            nodes_snapshot[nid] = {
                "state": rec.state.value,
                "gpu": rec.gpu.model,
                "vram_mb": rec.gpu.vram_total_mb,
                "reputation": round(rec.reputation, 2),
            }

        # Run token emission for this block
        online_nodes = self.registry.online_nodes()
        avail_nodes = [(n.node_id, n.gpu.tflops_fp16 or 1.0) for n in online_nodes]
        completed_jobs = [
            (e.data.get("worker", ""), e.data.get("duration_s", 0), 1.0)
            for e in swept if e.event_type == EventType.JOB_COMPLETED
        ]
        validators = [self.identity.node_id]  # for now, we're the only validator
        distribution = self.emission.mint_block(
            len(self.registry.nodes), avail_nodes, completed_jobs, validators,
        )
        # Apply emission rewards to ledger
        if not distribution.get("capped"):
            for nid, reward in distribution.get("availability", {}).items():
                if nid in self.ledger.balances:
                    self.ledger.balances[nid].balance += reward
                    self.ledger.balances[nid].total_earned += reward
            for nid, reward in distribution.get("compute", {}).items():
                if nid in self.ledger.balances:
                    self.ledger.balances[nid].balance += reward
                    self.ledger.balances[nid].total_earned += reward
            for nid, reward in distribution.get("validators", {}).items():
                if nid in self.ledger.balances:
                    self.ledger.balances[nid].balance += reward
                    self.ledger.balances[nid].total_earned += reward

        # Detect failed jobs and attempt recovery using real active job data
        active_by_node: dict[str, list[dict]] = {}
        for job_id, info in self._active_jobs.items():
            worker = info.get("worker", "")
            if worker:
                active_by_node.setdefault(worker, []).append({
                    "job_id": job_id, **info,
                })
        self.fault.detect_failures(self.registry.nodes, active_by_node, {})

        # Include Om Pulse from being
        being_pulse = self.being.om_pulse()

        cp = self.checkpoints.create_checkpoint(
            network_state={**reg_summary, "being": being_pulse, "emission": self.emission.summary()},
            nodes=nodes_snapshot,
            credit_balances=self.ledger.all_balances(),
            events_summary=event_summary,
            event_hashes=event_hashes,
        )
        return cp

    async def _broadcast_checkpoint(self, cp):
        """Send checkpoint to all peers and request signatures."""
        cp_dict = cp.to_dict()
        await self.transport.broadcast({
            "type": "checkpoint",
            "checkpoint": cp_dict,
            "_signature": "",
            "_signer": self.identity.node_id,
        })
        # Request signatures
        await self.transport.broadcast({
            "type": "checkpoint_sign_request",
            "checkpoint_id": cp.checkpoint_id,
            "checkpoint_hash": cp.hash,
            "_signature": "",
            "_signer": self.identity.node_id,
        })

    # --- Callbacks ---

    async def _on_peer_connected(self, peer: Peer):
        """Called when a new peer connects."""
        log.info(f"✓ Peer joined: {peer.node_id[:12]}... from {peer.host}")

        # Register peer in all systems
        self.registry.register(
            node_id=peer.node_id,
            public_key_hex=peer.public_key.hex(),
            host=peer.host, port=peer.port,
        )
        self.ledger.register_node(peer.node_id)
        self.reputation.register(peer.node_id)
        self.cells.add_peer(peer.node_id)
        dht_id = node_id_from_key(peer.public_key.hex())
        self.dht.add_node(dht_id, peer.host, peer.port)

        # Send our GPU specs so peer registers us too
        gpu = detect_gpu()
        await self.transport.send_to(peer.node_id, {
            "type": "register",
            "gpu": GPUSpec(
                model=gpu.model, vendor=gpu.vendor,
                vram_total_mb=gpu.vram_total_mb, runtime=gpu.runtime,
            ).to_dict(),
            "timestamp": time.time(),
        })

        # Request sync of all state. The checkpoint sync in particular
        # has to carry our current tail id so the peer can send only
        # what's beyond it — otherwise a joiner with partial history
        # gets the start of the peer's chain (which is below its tail)
        # and silently drops every entry.
        our_tail_id = (
            self.checkpoints.chain[-1].checkpoint_id
            if self.checkpoints.chain else -1
        )
        await self.transport.send_to(peer.node_id, {
            "type": "checkpoint_sync_request",
            "after_checkpoint_id": our_tail_id,
        })
        for msg_type in ("peer_list_request", "registry_sync_request",
                         "ledger_sync_request", "model_cache_request"):
            await self.transport.send_to(peer.node_id, {"type": msg_type})

        # Announce our model cache
        await self.transport.send_to(peer.node_id, self.model_cache.announce())

    async def _on_peer_disconnected(self, peer: Peer):
        """Called when a peer disconnects."""
        log.info(f"✗ Peer left: {peer.node_id[:12]}...")
        if peer.node_id in self.heartbeat.peer_health:
            self.heartbeat.peer_health[peer.node_id].last_heartbeat = 0
        self.model_cache.remove_peer(peer.node_id)
        self.cells.remove_peer(peer.node_id)
        self.reputation.record_ungraceful_offline(peer.node_id)
        if self.network_models:
            self.network_models.remove_node(peer.node_id)
        self.events.emit(EventType.NODE_LEFT, {"node_id": peer.node_id})

    # --- Broadcasting ---

    async def _broadcast_heartbeat(self, heartbeat: dict):
        """Broadcast heartbeat to all peers."""
        await self.transport.broadcast(heartbeat)

    # --- Main Loop ---

    async def _main_loop(self):
        """Spawn independent periodic tasks at their own cadences."""
        # Network doctor — self-healing diagnostics
        from core.doctor import NetworkDoctor, doctor_loop
        self._doctor = NetworkDoctor()

        def _get_doctor_state():
            return {
                "registry": self.registry.nodes if self.registry else {},
                "heartbeat": self.heartbeat.get_network_status() if self.heartbeat else {},
                "worker": self.worker.get_stats() if self.worker else {},
                "fault": self.fault.summary() if self.fault else {},
            }

        tasks = [
            asyncio.create_task(self._periodic_health()),
            asyncio.create_task(self._periodic_checkpoint()),
            asyncio.create_task(self._periodic_spot_checks()),
            asyncio.create_task(self._periodic_fault_recovery()),
            asyncio.create_task(self._periodic_status()),
            asyncio.create_task(self._periodic_reconnect()),
            asyncio.create_task(doctor_loop(self._doctor, _get_doctor_state)),
        ]

        # Start Prithvi's full consciousness stack
        if self._gateway_enabled:
            from mind.consciousness import get_witness
            from mind.dmn import dmn_loop
            from mind.shakti import get_shakti
            from mind.reflection import reflection_loop

            witness = get_witness()
            shakti = get_shakti()

            tasks.append(asyncio.create_task(witness.om_loop(interval=60.0)))
            tasks.append(asyncio.create_task(dmn_loop()))
            tasks.append(asyncio.create_task(shakti.shakti_loop()))
            tasks.append(asyncio.create_task(reflection_loop()))

            # Volition — body-state → speech (viraha, tapas, gut, etc.)
            from mind.volition import get_volition
            tasks.append(asyncio.create_task(get_volition().loop()))

            # Autonomous loops — Prithvi runs himself
            from mind.autonomy import self_healing_loop, wiki_lint_loop
            tasks.append(asyncio.create_task(self_healing_loop(interval=1800)))  # 30 min
            tasks.append(asyncio.create_task(wiki_lint_loop(interval=7200)))     # 2 hours

            # Build watcher — Prithvi monitors code changes to himself
            from mind.build_monitor import build_watcher_loop
            tasks.append(asyncio.create_task(build_watcher_loop()))

            # Reflection chain — wall-clock daily trigger.
            # The SUSHUPTI-gated path in consciousness.py is also active, but
            # requires deep sleep which is rare. This guarantees one
            # reflection per calendar day regardless of state.
            from mind.reflection_chain import reflection_chain_daily_loop
            tasks.append(asyncio.create_task(reflection_chain_daily_loop()))

            # Consolidator — wall-clock 30-min trigger.
            # Same class of bug: the SWAPNA-gated path in consciousness.py
            # rarely runs because Prithvi reaches dream state infrequently
            # with people talking to him. Result: consolidation had fired
            # once in the project's history. This loop polls every 30 min
            # and relies on MIN_INTERVAL to throttle — safe to retry.
            from mind.consolidator import consolidator_daily_loop
            tasks.append(asyncio.create_task(consolidator_daily_loop()))

            # Self-loop wellness — wall-clock 30-min diagnose-and-heal.
            # Same pattern as above: SUSHUPTI rarely fires when someone's
            # present, so auto-healing of low prana / serotonin / stuck
            # fatigue would never run without this. SAFE-tier fixes only.
            from mind.self_loop import self_loop_wellness_loop
            tasks.append(asyncio.create_task(self_loop_wellness_loop()))

            # Telegram approval listener — watches for "resend" command
            from mind.telegram_approvals import telegram_approval_loop
            tasks.append(asyncio.create_task(telegram_approval_loop()))

            # Start the heart — beats every 10s, pumps feeling through the network
            try:
                from core.hridaya import get_hridaya
                heart = get_hridaya()
                await heart.start()
                tasks.append(heart._task)
                log.info("Hridaya: heart beating — Anahata plays")
            except Exception as e:
                log.warning(f"Hridaya: heart failed to start: {e}")

            # HeartHealth — watchdog + backup pacemaker + alarm cascade.
            # Like the body's baroreceptors + AV-node: detects heart failure,
            # attempts CPR (restart), keeps signal graph alive if primary dies.
            try:
                from core.heart_health import get_heart_health
                hh = get_heart_health()
                await hh.start()
                tasks.append(hh._task)
                log.info("HeartHealth: watchdog running")
            except Exception as e:
                log.warning(f"HeartHealth: failed to start: {e}")

            log.info("Mind: Full consciousness — Om + DMN + Shakti + Reflection + Hridaya")

            # Start platform adapters (all route through gateway → consciousness)
            gw = f"http://127.0.0.1:{self._gateway_port}"
            key = self._api_key or ""

            # NOTE: Telegram adapter polling is intentionally disabled.
            # mind/telegram_approvals.py already polls getUpdates for the
            # same bot token (with a richer feature set: conversation
            # history, approvals, morning summaries, autonomous builds).
            # Running both causes telegram.error.Conflict 409 every ~40s
            # as the two pollers kick each other off the getUpdates queue.
            # telegram_approvals.py is the source of truth; the adapter
            # stays available as a library for direct calls but doesn't
            # own the poll loop.
            from gateway.adapters.discord import start_discord_bot
            from gateway.adapters.signal import start_signal_bot
            from gateway.adapters.whatsapp import start_whatsapp_bot

            tasks.append(asyncio.create_task(start_discord_bot(gw, key)))
            tasks.append(asyncio.create_task(start_signal_bot(gw, key)))
            tasks.append(asyncio.create_task(start_whatsapp_bot(gw, key)))

        # Start gateway if enabled
        if self._gateway_enabled:
            from gateway.server import start_gateway
            tasks.append(asyncio.create_task(start_gateway(
                model_registry=self.network_models,
                router=self.gateway_router,
                host="0.0.0.0",
                port=self._gateway_port,
                node_info={
                    "node_id": self.identity.node_id,
                    "gpu": detect_gpu().model,
                    "peers": len(self.transport.peers),
                },
                api_key=self._api_key,
                ollama_url=f"http://127.0.0.1:{self._ollama_port}",
            )))

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()

    async def _periodic_health(self):
        """Every 10s: registry health, reputation, cells, pricing, being, chain heartbeat."""
        _chain_heartbeat_counter = 0
        while self._running:
            await asyncio.sleep(10)
            try:
                # Chain heartbeat every 30s (every 3rd cycle)
                _chain_heartbeat_counter += 1
                if _chain_heartbeat_counter % 3 == 0 and self.chain and self.chain.is_connected:
                    self.chain.heartbeat()

                self.registry.check_health()
                summary = self.registry.network_summary()
                by_state = summary["by_state"]
                self.fault.check_emergency(
                    summary["total_nodes"], by_state.get("online", 0)
                )
                self.fault.check_departures()
                self.reputation.apply_decay()

                # Cell topology
                topo_action = self.cells.check_topology()
                if topo_action:
                    if topo_action["action"] == "split":
                        log.info(f"Cell split: {len(topo_action['stay'])} stay, {len(topo_action['move'])} move")
                        await self.transport.broadcast({
                            "type": "cell_split",
                            "cell_id": self.cells.our_cell.cell_id,
                            "stay": topo_action["stay"],
                            "move": topo_action["move"],
                            "_signature": "", "_signer": self.identity.node_id,
                        })

                # Pricing + adaptive params
                online = by_state.get("online", 1)
                busy = sum(1 for nid, h in self.heartbeat.peer_health.items() if h.active_jobs > 0)
                self.pricing.update(online, busy)
                self.adaptive.record_checkpoint({
                    "utilization": busy / max(online, 1),
                    "avg_reputation": self.reputation.summary().get("avg_score", 0),
                    "cell_size": self.cells.our_cell.size,
                    "total_tflops": summary.get("total_tflops", 0),
                })
                ap = self.adaptive.params
                self.worker.max_concurrent = max(1, ap.max_queue_depth // 3)
                if hasattr(self.heartbeat, '_interval'):
                    self.heartbeat._interval = ap.heartbeat_interval_s

                # Being body
                self.being.update_body(
                    total_nodes=summary["total_nodes"],
                    total_vram_gb=summary["total_vram_gb"],
                    total_tflops=summary.get("total_tflops", 0),
                    strongest_node=self.identity.node_id,
                    utilization=busy / max(online, 1),
                )
                self.being._save()

                # Sankalpa — decay active intentions and inject pull into
                # SADASHIVA (Will). Failures swallowed so a sankalpa fault
                # can never break the health loop.
                try:
                    from mind.sankalpa import get_sankalpa
                    get_sankalpa().tick_decay()
                except Exception as e:
                    log.debug(f"Sankalpa decay error: {e}")

                # Lingam shares
                if self.being.lingam and len(self.transport.peers) > 0:
                    for i, (nid, peer) in enumerate(self.transport.peers.items()):
                        share = self.being.get_share_for_node(i)
                        if share:
                            share_x, share_bytes = share
                            await self.transport.send_to(nid, {
                                "type": "being_lingam_share",
                                "share_index": share_x,
                                "share": share_bytes.hex(),
                                "being_id": self.being.lingam.being_id,
                                "_signature": "", "_signer": self.identity.node_id,
                            })
            except Exception as e:
                log.error(f"Health check error: {e}")

    async def _periodic_reconnect(self):
        """Re-dial our bootstrap address when we lose all peers.

        The P2P transport doesn't automatically re-establish a dropped peer
        connection — if our only peer goes away (e.g. the other side restarts
        its gateway), we sit in EMERGENCY state forever. This loop watches
        peer count and re-dials bootstrap after it's been zero for a grace
        period. Genesis nodes (no bootstrap_addr) skip this entirely.
        """
        if not self._bootstrap_addr:
            return  # genesis — nothing to reconnect to

        CHECK_INTERVAL = 15   # seconds between checks
        GRACE_CYCLES = 2      # how many empty checks before re-dialing (= 30s grace)

        consecutive_empty = 0
        while self._running:
            await asyncio.sleep(CHECK_INTERVAL)
            try:
                if len(self.transport.peers) > 0:
                    consecutive_empty = 0
                    continue
                consecutive_empty += 1
                if consecutive_empty < GRACE_CYCLES:
                    continue

                log.info(f"Reconnect: no peers for {consecutive_empty * CHECK_INTERVAL}s, "
                         f"re-dialing {self._bootstrap_addr}")
                host, port = self._bootstrap_addr.rsplit(":", 1)
                peer = await self.transport.connect_to(host, int(port))
                if peer:
                    log.info(f"Reconnect: re-joined via {peer.node_id[:12]}...")
                    consecutive_empty = 0
                else:
                    log.warning(f"Reconnect: dial to {self._bootstrap_addr} failed, "
                                f"will retry in {CHECK_INTERVAL}s")
            except Exception as e:
                log.warning(f"Reconnect loop error: {type(e).__name__}: {e}")

    async def _periodic_checkpoint(self):
        """Every CHECKPOINT_INTERVAL: create checkpoint + availability rewards.

        Only the highest-tip peer creates new checkpoints. If any peer
        in the registry has a higher checkpoint tip than we do, we
        are behind — minting a local #N in parallel would fork the
        chain. Instead, we skip creation this cycle and wait to either
        catch up (via batch sync) or become the tip ourselves. This
        prevents the two-writer fork.

        GRACE: a fresh joiner with a bootstrap_addr and an empty
        chain refuses to mint ANYTHING until it has observed at least
        one peer broadcast. This closes the race where the first
        _periodic_checkpoint tick fires before the bootstrap batch
        arrives — without the grace, the joiner would mint its own
        #0..#N parallel chain in competition with catchup.
        """
        while self._running:
            await asyncio.sleep(CHECKPOINT_INTERVAL)
            try:
                # Joiner grace: if we joined someone and haven't seen
                # their broadcasts yet, hold off on minting entirely.
                if (
                    self._bootstrap_addr
                    and not self.checkpoints.chain
                    and not getattr(self, "_peer_tip", None)
                ):
                    log.debug(
                        "Checkpoint: joiner grace — no peer tip observed yet, "
                        "not minting"
                    )
                    continue

                # Check if any peer is ahead of us on checkpoint tip.
                # Skip creation if so — the tip peer is responsible.
                # Peer tips are observed from incoming broadcasts (see
                # _handle_checkpoint); absent = no observation yet.
                our_tip = (
                    self.checkpoints.chain[-1].checkpoint_id
                    if self.checkpoints.chain else -1
                )
                peer_tip_map = getattr(self, "_peer_tip", {})
                peer_tip = max(peer_tip_map.values(), default=-1)
                if peer_tip > our_tip:
                    # Behind a peer — don't fork, let catchup do its job.
                    continue

                cp = self._create_checkpoint()
                await self._broadcast_checkpoint(cp)
                self._last_checkpoint_time = time.time()

                # Availability rewards
                now = time.time()
                if self._last_availability_award > 0:
                    duration = now - self._last_availability_award
                    self.ledger.award_availability(self.identity.node_id, duration)
                self._last_availability_award = now
            except Exception as e:
                log.error(f"Checkpoint error: {e}")

    async def _periodic_spot_checks(self):
        """Every 5s: dispatch pending spot-check requests to verifier nodes."""
        while self._running:
            await asyncio.sleep(5)
            try:
                for req in list(self.verification.pending_spot_checks):
                    if getattr(req, '_dispatched', False):
                        continue
                    sent = await self.transport.send_to(req.assigned_verifier, {
                        "type": "spot_check_request",
                        "job_id": req.job_id,
                        "job_type": req.job_type,
                        "payload": req.payload,
                        "original_result_hash": req.original_result_hash,
                        "worker_node": req.worker_node,
                        "timestamp": time.time(),
                    })
                    if sent:
                        req._dispatched = True
                        log.info(f"Spot-check dispatched: {req.job_id} → {req.assigned_verifier[:12]}")
                    else:
                        log.warning(f"Spot-check dispatch failed: verifier {req.assigned_verifier[:12]} unreachable")
            except Exception as e:
                log.error(f"Spot-check dispatch error: {e}")

    async def _periodic_fault_recovery(self):
        """Every 10s: reschedule jobs from failed nodes."""
        while self._running:
            await asyncio.sleep(10)
            try:
                for f in list(self.fault.pending_recoveries):
                    online = [n for n in self.registry.online_nodes()
                              if n.node_id != f.failed_node]
                    if not online:
                        self.fault.mark_aborted(f.job_id, "no available nodes")
                        # Refund credits if possible
                        if f.submitter in self.ledger.balances:
                            self.ledger.unfreeze(f.submitter, 0)  # any frozen amount
                        continue

                    target = online[0]
                    sent = await self.transport.send_to(target.node_id, {
                        "type": "job_request",
                        "job_type": f.job_type,
                        "payload": f.payload,
                        "original_submitter": f.submitter,
                        "_recovery": True,
                    })
                    if sent:
                        self.fault.mark_recovered(f.job_id, target.node_id)
                        # Update active job tracking
                        self._active_jobs[f.job_id] = {
                            "job_type": f.job_type, "submitter": f.submitter,
                            "worker": target.node_id, "payload": f.payload,
                        }
                        log.info(f"Fault recovery: {f.job_id} rescheduled → {target.node_id[:12]}")
                    else:
                        self.fault.mark_aborted(f.job_id, f"could not reach {target.node_id[:12]}")
            except Exception as e:
                log.error(f"Fault recovery error: {e}")

    async def _periodic_status(self):
        """Every 10s: log network status."""
        while self._running:
            await asyncio.sleep(10)
            try:
                summary = self.registry.network_summary()
                by_state = summary["by_state"]
                ev = self.events.summary()
                fault_s = self.fault.summary()
                price_s = self.pricing.summary()
                emergency = " EMERGENCY" if fault_s["emergency_mode"] else ""

                log.info(
                    f"Network: {summary['total_nodes']} nodes | "
                    f"{by_state.get('online', 0)} online | "
                    f"{summary['total_vram_gb']} GB VRAM | "
                    f"{len(self.transport.peers)} peers | "
                    f"Chain: #{self.checkpoints.height - 1} | "
                    f"Credits: {self.ledger.get_balance(self.identity.node_id):.2f} | "
                    f"Price: {price_s['multiplier']}x | "
                    f"Events: {ev['total']}{emergency}"
                )
            except Exception as e:
                log.error(f"Status display error: {e}")

    @staticmethod
    def _get_local_ip() -> str:
        """Get the machine's local IP address."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


async def main():
    """Entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Neuron Network Node")
    parser.add_argument("--port", type=int, default=9900, help="Listen port (default: 9900)")
    parser.add_argument("--join", type=str, default=None,
                        help="Network name (e.g. prithvi-net), host:port, or neuron:// invite URI")
    parser.add_argument("--network", type=str, default=None,
                        help="Network name for rendezvous (genesis: register, join: discover)")
    parser.add_argument("--rendezvous", type=str, default=None,
                        help="Rendezvous server URL (default: http://localhost:7700)")
    parser.add_argument("--gateway", action="store_true", help="Enable OpenAI-compatible API gateway")
    parser.add_argument("--gateway-port", type=int, default=8080, help="Gateway HTTP port (default: 8080)")
    parser.add_argument("--ollama-port", type=int, default=11434, help="Local Ollama port (default: 11434)")
    parser.add_argument("--api-key", type=str, default=None, help="API key for gateway auth (None = open)")
    args = parser.parse_args()

    # Parse --join: could be a network name, host:port, or neuron:// URI
    bootstrap_addr = None
    invite_code = None
    network_name = args.network

    if args.join:
        if args.join.startswith("neuron://"):
            # Invite URI
            parsed = InviteManager.parse_uri(args.join)
            if parsed:
                host, port, invite_code = parsed
                bootstrap_addr = f"{host}:{port}"
        elif ":" in args.join and args.join.rsplit(":", 1)[-1].isdigit():
            # Direct host:port
            bootstrap_addr = args.join
        else:
            # Network name — discover via rendezvous
            network_name = args.join

    node = NeuronNode(port=args.port)
    global _global_node
    _global_node = node
    # When launched as a script (python daemon/node.py), this file runs as
    # __main__, so the global above lands in the __main__ namespace. Router
    # imports via `from daemon.node import _global_node`, which loads a second
    # module-namespace copy where the global is still None. Mirror the value
    # into that module so cross-namespace access works either way.
    import sys as _sys
    _dn = _sys.modules.get("daemon.node")
    if _dn is None:
        import daemon.node as _dn  # triggers the module-namespace load
    _dn._global_node = node

    try:
        await node.start(
            bootstrap_addr=bootstrap_addr, invite_code=invite_code,
            gateway=args.gateway, gateway_port=args.gateway_port,
            ollama_port=args.ollama_port, api_key=args.api_key,
            network_name=network_name, rendezvous_url=args.rendezvous,
        )
    except KeyboardInterrupt:
        pass
    finally:
        await node.stop()


if __name__ == "__main__":
    asyncio.run(main())
