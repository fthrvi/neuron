# Solana USDC credit operations

These services are devnet-only. `localnet` exists solely for offline validator tests;
`mainnet-beta` is refused in code. Do not aim these units at mainnet or reuse a mainnet
treasury key.

## Install order

The unit files in `chain/systemd/` are examples and are not installed or enabled by the
repository.

1. Install and configure `nak-indexer.service` first. It is read-only and must be healthy
   before money routes are exposed.
2. Install `nak-treasury.service` with `NAK_FUNDS=off`. Confirm its vault, mint, caps, and
   kill-file path before turning funds on.
3. Install `nak-reconcile.service` and `nak-reconcile.timer` last. Run the service once by
   hand, verify the signed report, then enable the daily timer.

Indexer, treasury, and reconcile must use the same ledger, cluster, mint, RPC, and vault
configuration. Reconcile writes `~/.neuron/credits/reconcile/<UTC-date>.json`, signs it
with `~/.nakshatra/keys/worker.ed25519`, checks every finalized withdrawal (not a sample),
and appends mismatches to `reconcile/alerts.jsonl`. It uses only read RPC methods and does
not need `solders`; `/usr/bin/python3` is sufficient when Neuron's normal Python
dependencies are installed. `NAK_SOLANA_RPC_CONFIRM` enables an independent second read
for account, status, and transaction agreement.

Verify a report without contacting Solana:

```bash
python3 /opt/neuron/python/chain/reconcile.py \
  --verify-report "$HOME/.neuron/credits/reconcile/$(date -u +%F).json"
```

## Safety switches

- `NAK_FUNDS=off` is the payout worker's safe default. Only `on` permits treasury writes.
- `NAK_FUNDS_ROUTES=on` exposes the wallet/withdraw HTTP routes. Leave it unset or `off`
  until the indexer, treasury, and first reconciliation are healthy.
- `NAK_PAYOUT_KILL_FILE` defaults to `~/.neuron/credits/payout.off`. Its presence halts
  payouts immediately. Reconciliation creates it on any mismatch and never removes it.

The reconcile alert path calls Trisul's existing
`/home/prithvi/trisul/infra/mesh-agent/buzz-say.sh` helper when present. That helper reuses
the host's existing Buzz identity; reconcile does not acquire or store new credentials.
Delivery success or failure is recorded in the signed report and durable alert record.

## Rollback and incident response

To roll back S6, disable the timer (and stop an in-progress service):

```bash
systemctl --user disable --now nak-reconcile.timer
systemctl --user stop nak-reconcile.service
```

For any money incident, set `NAK_FUNDS=off`, set `NAK_FUNDS_ROUTES=off`, and create the
configured payout kill file before investigating. Preserve the SQLite ledger, WAL/SHM,
signed reports, and alert log. Reconciliation never repairs balances; resolve the chain or
journal discrepancy by an audited append-only operation, run reconciliation again, and
remove the kill file only after a human has verified a clean signed report. Disabling the
timer is the code rollback; it does not roll back journal rows or on-chain transfers.
