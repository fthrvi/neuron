"""
Substrate Chain Client — Bridge between Python daemon and on-chain pallets.

Connects to a Substrate node via WebSocket RPC. Signs and submits
real extrinsics using the node operator's keypair.

Pallets:
  NodeRegistry: register_node, heartbeat, deregister, record_benchmark
  Emission: queries only (emission happens automatically per block)

When no chain is running, operates in offline mode (all state local).
When chain is available, state is persisted on-chain.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)


class ChainStatus(Enum):
    OFFLINE = "offline"
    CONNECTING = "connecting"
    CONNECTED = "connected"


@dataclass
class ChainState:
    status: ChainStatus = ChainStatus.OFFLINE
    url: str = ""
    block_height: int = 0
    last_sync: float = 0.0


@dataclass
class Extrinsic:
    pallet: str
    call: str
    params: dict
    hash: str = ""
    block: int = 0
    status: str = "pending"
    timestamp: float = 0.0


class SubstrateClient:
    """
    Client for the Neuron Network Substrate chain.

    Signs and submits real extrinsics when connected.
    Queues and replays when offline.
    """

    def __init__(self, node_id: str, url: str = "ws://127.0.0.1:9944",
                 seed_phrase: str = "", is_genesis: bool = False):
        self.node_id = node_id
        self.url = url
        self.is_genesis = is_genesis  # genesis node controls Alice (validator)
        self.state = ChainState(url=url)
        self._substrate = None
        self._keypair = None  # this node's keypair
        self._alice = None    # Alice keypair (for genesis node to fund others)
        self._seed_phrase = seed_phrase
        self._pending: list[Extrinsic] = []
        self._history: list[Extrinsic] = []
        self._keypair_path = Path.home() / ".neuron" / "chain_key.json"

    @property
    def is_connected(self) -> bool:
        return self.state.status == ChainStatus.CONNECTED

    async def connect(self) -> bool:
        """Connect to Substrate node and set up keypair."""
        self.state.status = ChainStatus.CONNECTING
        try:
            from substrateinterface import SubstrateInterface, Keypair

            # Connect to chain
            self._substrate = SubstrateInterface(url=self.url)
            head = self._substrate.get_chain_head()
            self.state.block_height = self._substrate.get_block_number(head) or 0
            self.state.last_sync = time.time()

            # Load keypair: validator key > seed phrase > chain_key.json > generate new
            if self._seed_phrase:
                self._keypair = Keypair.create_from_mnemonic(self._seed_phrase)
            elif self._keypair_path.exists():
                data = json.loads(self._keypair_path.read_text())
                seed = data.get("secretSeed") or data.get("mnemonic", "")
                if seed.startswith("0x"):
                    self._keypair = Keypair.create_from_seed(seed)
                else:
                    self._keypair = Keypair.create_from_mnemonic(seed)
                log.info(f"Chain: loaded keypair {self._keypair.ss58_address}")
            else:
                # Generate new keypair
                mnemonic = Keypair.generate_mnemonic()
                self._keypair = Keypair.create_from_mnemonic(mnemonic)
                self._keypair_path.parent.mkdir(parents=True, exist_ok=True)
                self._keypair_path.write_text(json.dumps({
                    "mnemonic": mnemonic,
                    "address": self._keypair.ss58_address,
                    "node_id": self.node_id,
                    "created_at": time.time(),
                }))
                log.info(f"Chain: generated new keypair {self._keypair.ss58_address}")

            self.state.status = ChainStatus.CONNECTED
            log.info(
                f"Chain: connected to {self.url} "
                f"(block #{self.state.block_height}, account={self._keypair.ss58_address})"
            )

            # Flush queued extrinsics
            await self._flush_pending()
            return True

        except ImportError:
            log.info("Chain: substrate-interface not installed — offline mode")
            self.state.status = ChainStatus.OFFLINE
            return False
        except Exception as e:
            log.info(f"Chain: connection failed ({e}) — offline mode")
            self.state.status = ChainStatus.OFFLINE
            return False

    def _fund_from_alice(self, amount_nrn: float):
        """Fund this node's account from Alice (dev mode only)."""
        if not self._substrate or not self._alice:
            return
        try:
            amount = int(amount_nrn * 1_000_000_000_000)  # 12 decimals
            call = self._substrate.compose_call(
                call_module="Balances",
                call_function="transfer_keep_alive",
                call_params={"dest": self._keypair.ss58_address, "value": amount},
            )
            extrinsic = self._substrate.create_signed_extrinsic(call=call, keypair=self._alice)
            self._substrate.submit_extrinsic(extrinsic)
            log.info(f"Chain: funded {self._keypair.ss58_address} with {amount_nrn} NRN from Alice")
        except Exception as e:
            log.warning(f"Chain: funding failed: {e}")

    # --- Node Registry ---

    def register_node(self, gpu_model: str, vram_mb: int, runtime: str,
                       node_type: str = "Compute"):
        """Register this node on-chain with GPU specs and node type.

        Args:
            node_type: "Compute" (GPU worker), "Pillar" (consciousness holder),
                       or "Hybrid" (both).
        """
        runtime_map = {"cuda": "Cuda", "rocm": "Rocm", "cpu": "Cpu"}
        runtime_variant = runtime_map.get(runtime.lower(), "Unknown")

        # Validate node_type
        valid_types = {"Compute", "Pillar", "Hybrid"}
        if node_type not in valid_types:
            node_type = "Compute"

        self._submit("NodeRegistry", "register_node", {
            "node_type": node_type,
            "gpu_model": gpu_model.encode()[:64],  # BoundedVec<u8, 64>
            "vram_mb": vram_mb,
            "runtime": runtime_variant,
        })

    def heartbeat(self):
        """Send heartbeat to chain — proves node is alive."""
        self._submit("NodeRegistry", "heartbeat", {})

    def deregister(self):
        """Voluntarily leave the network."""
        self._submit("NodeRegistry", "deregister", {})

    # --- Transfers (NRN fee payments) ---

    def transfer(self, to_address: str, amount_nrn: float) -> bool:
        """Transfer NRN from this node's account to another address."""
        if amount_nrn <= 0:
            return False
        amount_raw = int(amount_nrn * 1_000_000_000_000)  # 12 decimals
        if not self.is_connected or not self._substrate or not self._keypair:
            log.warning(f"Chain: transfer queued (offline) — {amount_nrn} NRN to {to_address[:16]}")
            self._submit("Balances", "transfer_keep_alive", {
                "dest": to_address, "value": amount_raw,
            })
            return True
        try:
            call = self._substrate.compose_call(
                call_module="Balances",
                call_function="transfer_keep_alive",
                call_params={"dest": to_address, "value": amount_raw},
            )
            extrinsic = self._substrate.create_signed_extrinsic(
                call=call, keypair=self._keypair,
            )
            self._substrate.submit_extrinsic(extrinsic)
            log.info(f"Chain: transferred {amount_nrn:.6f} NRN to {to_address[:16]}...")
            return True
        except Exception as e:
            log.warning(f"Chain: transfer failed: {e}")
            return False

    def burn(self, amount_nrn: float) -> bool:
        """
        Burn NRN by sending to a dead address (no private key exists).

        Uses SS58 encoding of 32 zero bytes — provably unspendable.
        """
        if amount_nrn <= 0:
            return False
        # Dead address: SS58 encode of 0x000...000 (no one has the key)
        dead_address = "5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM"
        log.info(f"Chain: burning {amount_nrn:.6f} NRN")
        return self.transfer(dead_address, amount_nrn)

    # --- Fees (on-chain fee recording) ---

    def record_fee(self, operator: str, total_fee_nrn: float,
                   burned_nrn: float, tokens: int, model: str):
        """Record an inference fee payment on-chain via the Fees pallet."""
        total_raw = int(total_fee_nrn * 1_000_000_000_000)
        burned_raw = int(burned_nrn * 1_000_000_000_000)
        # Model hash: first 8 bytes of model name
        model_bytes = model.encode()[:8]
        model_hash = list(model_bytes) + [0] * (8 - len(model_bytes))

        self._submit("Fees", "record_fee", {
            "operator": operator,
            "total_fee": total_raw,
            "burned": burned_raw,
            "tokens": tokens,
            "model_hash": model_hash,
        })

    # --- Compute Jobs (Phase 2 — queue for now) ---

    def claim_job(self, job_id: str):
        self._submit("ComputeJobs", "claim_job", {"job_id": job_id})

    def complete_job(self, job_id: str, result_hash: str, duration_s: float):
        self._submit("ComputeJobs", "complete_job", {
            "job_id": job_id,
            "result_hash": result_hash,
            "duration_s": round(duration_s, 3),
        })

    # --- Queries ---

    def query_nodes(self) -> list[dict]:
        """Query all registered nodes from chain."""
        if not self.is_connected or not self._substrate:
            return []
        try:
            result = self._substrate.query_map("NodeRegistry", "Nodes")
            return [{"account": str(k.value), "record": v.value} for k, v in result]
        except Exception as e:
            log.debug(f"Chain query NodeRegistry.Nodes failed: {e}")
            return []

    def query_online_count(self) -> int:
        """Query active node count from chain."""
        if not self.is_connected or not self._substrate:
            return 0
        try:
            result = self._substrate.query("NodeRegistry", "OnlineCount")
            return int(result.value) if result else 0
        except Exception:
            return 0

    def query_total_vram(self) -> int:
        """Query total VRAM across online nodes (MB)."""
        if not self.is_connected or not self._substrate:
            return 0
        try:
            result = self._substrate.query("NodeRegistry", "TotalVram")
            return int(result.value) if result else 0
        except Exception:
            return 0

    def query_emission_rate(self) -> int:
        """Query current emission rate per block."""
        if not self.is_connected or not self._substrate:
            return 0
        try:
            result = self._substrate.query("Emission", "TotalMinted")
            return int(result.value) if result else 0
        except Exception:
            return 0

    def query_balance(self, address: str = "") -> int:
        """Query NRN balance (raw units, 12 decimals)."""
        if not self.is_connected or not self._substrate:
            return 0
        try:
            addr = address or (self._keypair.ss58_address if self._keypair else "")
            result = self._substrate.query("System", "Account", [addr])
            if result:
                return result.value.get("data", {}).get("free", 0)
            return 0
        except Exception:
            return 0

    def query_balance_nrn(self, address: str = "") -> float:
        """Query NRN balance in human-readable units."""
        raw = self.query_balance(address)
        return round(raw / 1_000_000_000_000, 4)

    @property
    def address(self) -> str:
        """This node's chain address."""
        return self._keypair.ss58_address if self._keypair else ""

    def query_block_height(self) -> int:
        if not self.is_connected or not self._substrate:
            return self.state.block_height
        try:
            head = self._substrate.get_chain_head()
            height = self._substrate.get_block_number(head)
            self.state.block_height = height or 0
            return self.state.block_height
        except Exception:
            return self.state.block_height

    # --- Internal ---

    def _submit(self, pallet: str, call: str, params: dict):
        """Sign and submit an extrinsic, or queue if offline."""
        ext = Extrinsic(
            pallet=pallet, call=call, params=params,
            hash=hashlib.sha256(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest()[:16],
            timestamp=time.time(),
        )

        if self.is_connected and self._substrate and self._keypair:
            self._execute(ext)
        else:
            ext.status = "pending"
            self._pending.append(ext)

    def _execute(self, ext: Extrinsic):
        """Sign and submit an extrinsic to the chain."""
        try:
            # Compose the call
            call = self._substrate.compose_call(
                call_module=ext.pallet,
                call_function=ext.call,
                call_params=ext.params,
            )

            # Create signed extrinsic
            extrinsic = self._substrate.create_signed_extrinsic(
                call=call,
                keypair=self._keypair,
            )

            # Submit (fire and forget — don't wait for block inclusion)
            receipt = self._substrate.submit_extrinsic(extrinsic)

            ext.status = "submitted"
            ext.hash = str(getattr(receipt, "extrinsic_hash", "") or "")
            ext.block = self.state.block_height
            log.info(f"Chain: {ext.pallet}.{ext.call} submitted (tx={ext.hash[:16]})")

        except Exception as e:
            ext.status = "failed"
            log.warning(f"Chain: {ext.pallet}.{ext.call} failed: {e}")

        self._history.append(ext)

    async def _flush_pending(self):
        """Submit all queued extrinsics now that we're connected."""
        if not self._pending:
            return
        count = len(self._pending)
        log.info(f"Chain: flushing {count} pending extrinsics")
        for ext in self._pending:
            self._execute(ext)
        self._pending.clear()

    def touch_demurrage(self):
        """Mark account as active to reset demurrage timer."""
        if not self._substrate:
            return
        try:
            self._submit("Demurrage", "touch", {})
        except Exception as e:
            log.debug(f"Chain: touch failed — {e}")

    def query_pending_demurrage(self, address: str = "") -> float:
        """Query pending demurrage in NRN."""
        if not self._substrate:
            return 0.0
        try:
            addr = address or self._keypair.ss58_address
            result = self._substrate.query("Demurrage", "LastActivity", [addr])
            # Actual calculation done on-chain, this is approximate
            return 0.0
        except Exception:
            return 0.0

    def summary(self) -> dict:
        return {
            "status": self.state.status.value,
            "url": self.url,
            "block_height": self.state.block_height,
            "account": self._keypair.ss58_address if self._keypair else "",
            "pending": len(self._pending),
            "submitted": len(self._history),
        }
