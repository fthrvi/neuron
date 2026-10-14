# Neuron — L1 Chain & Economic Substrate

The L1 layer of the four-project stack. Holds the Substrate-based blockchain (NRN token, node-registry, emission, compute-jobs, fees) plus the Python-side chain integration (chain client, wallet, fees, emission, receipts, governance, admission).

## Status

**PAUSED.** Extracted from `prithvi/` on 2026-05-14 for architectural hygiene. Active development resumes when Sthambha (L3) fabric Mode C is operational — that's when the network actually has untrusted peers to economize over.

## Where Neuron sits

| Layer | Project | Role |
|---|---|---|
| **L1** | **Neuron** *(this repo)* | Chain & economic substrate (NRN token, on-chain accounting, validator) |
| L2 | [Nakshatra](https://github.com/fthrvi/nakshatra) | Distributed inference engine |
| L3 | [Sthambha](https://github.com/fthrvi/sthambha) | Substrate (registry, identity, fabric, layer cache) |
| L4 | [Prithvi](https://github.com/fthrvi/prithvi) | Agent / consciousness / voice |

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

## Solana deposit indexer trust boundary

`python/chain/indexer.py` indexes finalized SPL-token deposits on devnet or a
loopback-only local validator. Devnet is pinned by `getGenesisHash` to
`EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`; the default may be overridden
with `NAK_SOLANA_DEVNET_GENESIS` for an intentional future migration. The
mainnet-beta genesis is always refused. Non-loopback RPC URLs must use HTTPS.

Without `NAK_SOLANA_RPC_CONFIRM`, the primary RPC is a trust root for minting:
an endpoint that lies consistently about both transactions and account balance
can create false ledger credit. Set `NAK_SOLANA_RPC_CONFIRM` to a genuinely
independent second RPC to require exact agreement on every candidate
transaction and agreement on token-account mint, decimals, and raw balance
before the ledger commits. The primary and confirmation URLs must differ.

Candidate deposits remain quarantined until the already-indexed total plus the
entire candidate batch equals the finalized on-chain balance. Credits and the
account cursor are then written in one SQLite transaction; mismatch commits
neither, pauses the account, and records an alert.
