# Neuron — L1 Chain & Economic Substrate

The L1 layer of the four-project stack. Holds the Substrate-based blockchain (NRN token, node-registry, emission, compute-jobs, fees) plus the Python-side chain integration (chain client, wallet, fees, emission, receipts, governance, admission).

## Status

**PAUSED.** Extracted from `Prithvi-/` on 2026-05-14 for architectural hygiene. Active development resumes when Sthambha (L3) fabric Mode C is operational — that's when the network actually has untrusted peers to economize over.

## Where Neuron sits

| Layer | Project | Role |
|---|---|---|
| **L1** | **Neuron** *(this repo)* | Chain & economic substrate (NRN token, on-chain accounting, validator) |
| L2 | [Nakshatra](https://github.com/fthrvi/nakshatra) | Distributed inference engine |
| L3 | [Sthambha](https://github.com/fthrvi/sthambha) | Substrate (registry, identity, fabric, layer cache) |
| L4 | [Prithvi](https://github.com/fthrvi/Prithvi-) | Agent / consciousness / voice |

## Repo layout

- `chain/` — Rust/Substrate L1 chain (FRAME pallets: node-registry, emission, compute-jobs, fees)
- `python/core/` — Python chain integration (chain_client, emission, fees, demand, governance, game, admission, receipt, bls, wallet, privacy)
- `python/daemon/` — `node.py`: the genesis-node daemon (the first heartbeat, Block 0)
- `python/cli/` — operator surface (`chain`, `ledger`, `submit_job`, `invite`)
- `python/tests/` — chain-specific tests

## Why it's paused

The chain economizes over untrusted public peers. Today's 5-machine trusted cluster doesn't need economic incentives — the participants know each other. The chain becomes load-bearing when Sthambha fabric Mode C opens the network to anyone. Until then, this code sits frozen.

When it un-pauses, the work is not "build from scratch" — most of the substrate is here. The work is:
- Validate against Mode C's actual accounting unit (per-token? per-step? per-session?)
- Wire the receipt flow to Nakshatra workers
- Wire the fee charging to Prithvi's gateway via HTTP (not direct import — see the four-project boundary)

## See also

- Project architecture: `Sthambha/docs/four-project-architecture.md` (canonical)
- Mode C / public-network goal: `Sthambha/docs/network-fabric.md` §3 and §11
