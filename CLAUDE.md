# Neuron — Build Instructions

## What this project is

Neuron is the **L1 chain & economic substrate** in a four-project architecture. Holds the Substrate blockchain (FRAME pallets, NRN token, on-chain accounting) plus the Python-side chain integration that other layers (Nakshatra workers, Prithvi gateway) talk to.

**Status:** PAUSED at the project level. Extracted from `Prithvi-/` on 2026-05-14 for architectural hygiene. Active development resumes when Sthambha (L3) fabric Mode C is operational. Until then, this code sits frozen — read it, don't add to it.

## Where Neuron sits in the stack

- **L1 Neuron** *(this repo)* — chain & economics. Substrate validator, NRN token, on-chain accounting.
- **L2 Nakshatra** — distributed inference engine (`fthrvi/nakshatra`).
- **L3 Sthambha** — substrate: registry, identity, fabric, layer cache (`fthrvi/sthambha`).
- **L4 Prithvi** — agent / consciousness / voice (`fthrvi/Prithvi-`).

The full architecture decision lives at `Sthambha/docs/four-project-architecture.md` (canonical, in the Sthambha repo).

## What belongs in Neuron, what does not

**Belongs in Neuron:**
- Substrate runtime, pallets, node binary (`chain/`)
- NRN token issuance, emission schedule, hard-cap math
- On-chain accounting (compute-jobs pallet, fees pallet, node-registry pallet)
- Python chain client (Substrate WebSocket RPC, signed extrinsics)
- Job receipts (Ed25519-signed per-job records workers emit to the coordinator)
- BLS threshold signatures for job-completion attestation
- Genesis node daemon (`python/daemon/node.py`)
- Operator CLIs against the chain (`python/cli/chain.py`, `ledger.py`, `submit_job.py`, `invite.py`)

**Does NOT belong in Neuron:**
- Model compute or inference — that's Nakshatra
- Peer registry, identity, pillar daemon, fabric — that's Sthambha
- Consciousness, voice, gateway, OpenAI-compatible API — that's Prithvi
- Anything time-sensitive on the inference path (the chain is the *settlement* layer, not the dispatch layer; Nakshatra dispatches, Sthambha plans, Neuron settles)

## When un-pausing

If you're reading this because the project is being un-paused, do these in order:

1. Confirm Mode C is operational on Sthambha (`docs/network-fabric.md` §11 multi-tenant isolation done; pubkey-derived identity in production).
2. Lock the accounting unit decision — per-token? per-step? per-session? — this changes the pallet schema and the receipt format.
3. Refactor any Prithvi-side or Nakshatra-side code that *imports* Neuron Python modules to instead call HTTP endpoints exposed by `python/daemon/node.py`. Direct imports across project boundaries are out of scope post-extraction.
4. Update the existing pallets against the locked accounting unit. Most of the FRAME work survives; the schemas need tightening.

## Build (Rust chain)

```bash
cd chain
cargo build --release             # x86_64
./deploy-pi.sh user@pi-ip         # cross-compile to ARM64 for Pi validator
```

See `chain/README.md` for the pre-extraction-era setup notes; some paths reference `Prithvi-/neuron-chain/` and need updating once development resumes.

## Sanskrit / vocabulary discipline

The chain itself does **not** use Sanskrit naming the way Sthambha and Prithvi do. NRN, Neuron, node-registry, compute-jobs, emission — these are the canonical names. If you see Sanskrit vocabulary in a file here, it likely got copied alongside something that imports from `core/being.py` or `core/dikpala.py` and should be cleaned up at refactor time.
