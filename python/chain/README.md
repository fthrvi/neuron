# Solana USDC credit operations

These services are devnet-only. `localnet` exists solely for offline validator tests;
`mainnet-beta` is refused in code. Do not aim these units at mainnet or reuse a mainnet
treasury key.

## Install order

The unit files in `chain/systemd/` are examples and are not installed or enabled by the
repository.

1. Install and configure `nak-indexer.service` first. It is read-only and must be healthy
   before money routes are exposed.
2. Install `nak-treasury.service` with `NAK_FUNDS=off`. Confirm its vault, mint, sweep
   minimum, caps, and kill-file path before turning funds on. Do not add mount sandboxing
   (`Private*`, `Protect*`, `*Paths`, `TemporaryFileSystem`, ...) to this user unit, or to any user
   unit that calls `enclave_gate`: it puts the worker in a user namespace where the root-owned approver pin reads as owned by
   `nobody`, so every Face ID request is refused and over-cap payouts wait forever.
3. Install `nak-reconcile.service` and `nak-reconcile.timer` last. Run the service once by
   hand, verify the signed report, then enable the daily timer.

Indexer, treasury, and reconcile must use the same ledger, cluster, mint, RPC, and vault
configuration. Reconcile writes `~/.neuron/credits/reconcile/<UTC-date>.json`, signs it
with `~/.nakshatra/keys/worker.ed25519`, checks every finalized withdrawal (not a sample),
validates every pending/approved/sent/expired/finalized/released hold and lifecycle journal,
and appends mismatches or inconclusive collections to `reconcile/alerts.jsonl`. It opens
the existing ledger through SQLite's `file:...?mode=ro` URI, performs the complete ledger
read in an explicit read transaction, verifies every finalized deposit-to-vault sweep,
and never runs `LedgerStore` initialization or
migrations. A missing, unreadable, or old-schema ledger is therefore a collection error
and creates the payout kill file rather than a new database.

An indexer account paused by a mismatch stays paused until a human operator repairs the
cause and runs the hub-local CLI:

```bash
python3 python/chain/indexer.py unpause \
  --token-account TOKEN_ACCOUNT \
  --reason "what was repaired and how it was verified"
```

This command is intentionally only a CLI; it is not exposed through HTTP or an agent/MCP
tool. It reads the token account at finalized commitment and refuses unless that balance
equals the account's indexed deposits minus every finalized or still-in-flight sweep. It
has no force option. A successful unpause and the most recent prior indexer alert are
written together to the append-only `chain_indexer_unpause_audit` table in the same
transaction that clears `chain_indexer_accounts.paused`.

It uses only read RPC methods and does not need `solders`; `/usr/bin/python3` is sufficient
when Neuron's normal Python dependencies are installed. Every collection brackets one
transactional ledger image with two finalized `getMultipleAccounts` reads and batches all
withdrawal and sweep statuses into one `getSignatureStatuses` call. A changing chain/ledger
view or a deposit visible on chain before the indexer records it is `inconclusive`, not a mismatch.
The service retries three times by default, alerts without killing after an inconclusive
run, and creates the kill file after three consecutive inconclusive runs. Configure these
budgets with `NAK_RECONCILE_SNAPSHOT_ATTEMPTS`, `NAK_RECONCILE_RETRY_DELAY_S`, and
`NAK_RECONCILE_INCONCLUSIVE_KILL_RUNS`. `NAK_SOLANA_RPC_CONFIRM` enables an independent
second read for account, status, and transaction agreement.

## Spend-ledger namespace preflight

Before deploying the spend escrow schema against an existing ledger, run the read-only
namespace check. It opens the supplied database with SQLite `mode=ro` and does not run
ledger initialization or migrations:

```bash
python3 python/chain/spend_preflight.py /path/to/ledger.sqlite
```

Exit status `0` means clear, `1` means one or more collisions were found, and `2` means
the database could not be checked. Add `--json` for automation. A collision is an account
whose name begins with the reserved `__spend_hold__` stem but is not backed by a spend
hold escrow row. Do not deploy until every collision is remediated. The colliding account
must first have a zero balance; then rename it outside the reserved namespace or remove
the zero-balance account row through the normal audited ledger-maintenance procedure.
Merely transferring its balance to zero is insufficient because the account row itself
still blocks schema startup.

Verification must use a hub public key pinned independently of the report. The report's
embedded `keyid` is informational and is never a trust root. Store the expected raw
32-byte Ed25519 public key as 64 lowercase hex characters in a root/operator-managed
configuration file, then verify without contacting Solana:

```bash
python3 /opt/neuron/python/chain/reconcile.py \
  --verify-report "$HOME/.neuron/credits/reconcile/$(date -u +%F).json" \
  --expect-pubkey-file "$HOME/.config/nakshatra/reconcile-hub.pub"
```

`--expect-pubkey <hex>` is equivalent for automation. Verification requires the pinned
key and also checks the fixed `Sthambha-Ed25519` scheme, `REPORT` method, reconciliation
path, and `nak-credit-reconciliation-v1` purpose inside the signed payload.

Paid task holds that predate the immutable `funded` snapshot must be named explicitly in
`~/.config/nakshatra/reconcile-grandfathered-holds.txt`, or in the file selected by
`--grandfathered-holds-file PATH` / `NAK_RECONCILE_GRANDFATHERED_HOLDS`. Each line has
`hold_id amount payer_account worker_account`; the id is 32 lowercase hex, blank lines and
`#` comments are allowed, and all four fields must exactly match the paid hold. A missing
file is an empty list. Reconciliation refuses a symlink, a file not owned by the current
user, or a file or parent directory that is group/world-writable. It reconstructs each
paid hold's funding decision from the complete deposit, withdrawal, matured-earning, and
funded-spending provenance at authorization. A listed row is accepted only when the stored
migration default is `funded=1` but reconstruction is unfunded. Missing, unpaid,
already-matching, mismatched, or otherwise ineligible entries are mismatches.
The accepted ids and amounts are included in the signed report. This exception file is an
operator-pinned migration record: after an entry is retired it should be removed, and the
list should only ever shrink.

## Safety switches

- `NAK_FUNDS=off` is the payout worker's safe default. Only `on` permits treasury writes.
- `NAK_SWEEP_MIN_MICRO` is the smallest deposit-account balance the treasury consolidates
  into `NAK_TREASURY_USDC_ACCOUNT`; it defaults to `1000000` (1 USDC). Sweeps run before
  payouts and use the same `NAK_FUNDS` and kill-file gates, but not payout caps or presence.
  An account is swept only when its finalized balance is fully indexed. The signed intent
  is durable before broadcast, and an unresolved intent prevents both another sweep and
  indexer cursor advancement for that account.
- `NAK_SWEEP_STALE_BLOCKS` defaults to `300`. A sweep signature that remains visible but
  unfinalized beyond its last valid block height plus this allowance is never re-signed or
  marked failed merely for age: the treasury logs it on every pass, while reconciliation
  treats it as a mismatch and creates the payout kill file and alert. If a sweep was
  confirmed but never finalized and becomes stale this way, recovery is a human checking
  that signature on chain before deciding how to resolve the immutable in-flight row and
  remove the kill file.
- `NAK_FUNDS_ROUTES=on` exposes the wallet/withdraw HTTP routes. Leave it unset or `off`
  until the indexer, treasury, and first reconciliation are healthy.
- `NAK_SPEND_ROUTES=on` exposes the signed loopback-only `/spend/*` routes. It defaults
  off; disabled routes return the same JSON 404 as an unknown route. The authenticated
  claim-capability probe is `GET /spend/ready`. The expiry worker continues closing any
  already-created holds after this switch is turned off so rollback cannot strand escrow.
- `NAK_PAYOUT_KILL_FILE` defaults to `~/.neuron/credits/payout.off`. Its presence halts
  payouts immediately. Reconciliation creates it on any stable mismatch, collection
  exception, or repeated inconclusive result and never removes it. Creation is exclusive,
  does not follow symlinks, and replaces a symlink/special-file obstruction with a real
  regular kill file.
- Withdrawals above the automatic/day caps use the existing write-gate presence flow, but
  the treasury worker never waits synchronously for Face ID. It durably records the exact
  withdrawal id, amount, address, challenge, broker request, and expiry, then checks that
  same request on later passes. Broker-reported expiry can shorten, but never extend, the
  persisted local deadline. A transactional election permits only one worker to enqueue the
  request. Automatic-cap eligibility and approval are likewise one write transaction, so
  concurrent workers cannot both consume the same daily allowance. Because the broker result
  is one-shot, the raw signed response is committed before verification and is re-verified
  from that durable copy after a restart. Restarts therefore neither prompt twice nor lose an
  answer consumed just before a crash. Only a locally verified, unexpired answer matching the
  withdrawal id, amount, and address can approve the withdrawal. Those bindings and the exact
  approval expiry remain on the withdrawal; the worker rechecks them after the final mutable
  safety gate and immediately before each broadcast or rebroadcast. An expired approval
  returns through the normal fresh-approval path. Denial, expiry, malformed approval,
  broker/configuration errors, and storage-transition errors all fail closed for that
  withdrawal. Other withdrawals, sweeps, and account creation continue in the pass.

The reconcile alert path calls Trisul's existing
`/home/prithvi/trisul/infra/mesh-agent/buzz-say.sh` helper when present. That helper reuses
the host's existing Buzz identity; reconcile does not acquire or store new credentials.
Delivery success or failure is recorded in the signed report and durable alert record.

## Spend HTTP routes

The spend API is disabled unless `NAK_SPEND_ROUTES=on`, and even then it is served only to
loopback clients. Its exact route set is `POST /spend/authorize`, `/spend/claim`,
`/spend/settle`, `/spend/abandon`, and `/spend/release`, plus `GET /spend/status` and
`/spend/ready`. Every route requires the existing signed envelope. Spend GET requests must
have an empty body; all request bodies are capped at 64 KiB.

When the ledger's primary listener must remain on its mesh address, start it with
`--loopback-port PORT` to expose the same in-process service on loopback as well. Point the
VPS reverse tunnel's hub-side target at `127.0.0.1:<loopback-port>`, not at the mesh listener.
Both listeners share one store, roster cache, nonce table, and expiry sweeper; the
`/spend/*` routes continue to return the unknown-route 404 to non-loopback clients.

The authorization claim token is returned once and only its SHA-256 digest is stored. An
identical authorization retry before any worker has claimed rotates to a fresh token on the
same hold and atomically invalidates the previous token. After any worker claim, the retry
returns a conflict instead of a token. There is no token-recovery key or backup dependency.

Each ledger store has a neighboring `.spend-sweeper.lock` advisory-lock file. Exactly one
service instance holds that lock and runs the expiry sweeper; other instances continue
serving without a sweeper. The kernel releases ownership if the process exits or crashes,
so a subsequently started instance takes over without deleting the lock file.

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

To roll back the sweep worker, first turn `NAK_FUNDS=off` and create the kill file, then
disable sweep initiation while retaining the sweep-aware indexer, reconciliation code, and
`chain_sweeps` table. Never delete or edit a sweep row: finalized rows are reconciliation
proof, and `sent` rows must be resolved as finalized or failed. Do not deploy a pre-sweep
indexer after any finalized sweep; it cannot account for the deposit account's lower
balance. A sweep already finalized on chain is irreversible; rollback changes automation
only, not token location or liability.
