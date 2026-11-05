# nakshatra_pay

This Anchor workspace contains the Nakshatra non-custodial payment program and its LiteSVM tests.

## Build and test

Run the checked-in test driver from this directory:

```sh
./scripts/test.sh
```

It builds the SBF program and the test-only CPI fixture with the pinned platform tools before
running `cargo test`. The tests compare both binaries with their Rust sources and fail with a
freshness message rather than testing stale code. The CPI fixture is loaded only into LiteSVM; it
is not listed in `Anchor.toml` and is not part of the payment program's IDL or deployment set.

The workspace includes a test-only `agave-precompiles` compatibility crate because the pinned
offline LiteSVM cache omits that optional package. It exposes LiteSVM's expected callback API and
performs actual Ed25519 signature and cross-instruction-offset verification with `ed25519-dalek`.

The exact reviewed devnet binary build starts from neuron `forgejo/main` commit
`568318f4a3715b619c277362c000080ea5b913f5` and is:

```sh
git -C /home/prithvi/neuron worktree add --detach /tmp/nakshatra-pay-build 568318f4a3715b619c277362c000080ea5b913f5
cd /tmp/nakshatra-pay-build/programs/nakshatra_pay
anchor build --arch v0 --tools-version v1.57
sha256sum target/deploy/nakshatra_pay.so
```

The hash printed by the last command is an explicit input to `build-check`; deployment will not
accept a different file or file length. Remove the temporary worktree with
`git -C /home/prithvi/neuron worktree remove /tmp/nakshatra-pay-build` after independently recording
the reviewed hash.

## Devnet deployment under Squads v4

`scripts/devnet_deploy.py` is devnet-only. Production accepts only the exact RPC URL
`https://api.devnet.solana.com`; userinfo, alternate ports, paths, queries and every other URL are
rejected during argument parsing. `--rehearsal` instead accepts only
`http://127.0.0.1:<port>`. Every chain mutation also checks `getGenesisHash` and refuses any
cluster except devnet or the literal-loopback rehearsal validator.

The tool never gives an external CLI that allowlisted upstream URL. Before each `solana` or
`spl-token` write, it starts an ephemeral in-process `127.0.0.1` JSON-RPC forwarder, repeats the
genesis check, and relays POST bodies with redirects disabled. The `solana` CLI also receives the
same proxy as a `ws://127.0.0.1:<ephemeral>` URL, where websocket GET/upgrade requests are rejected
without forwarding; `spl-token` has no websocket option. Confirmation is therefore authoritative
only after the Python client re-reads the ProgramData or token account and
checks its owner, exact code length and hash, and expected authority. The implementation uses only
Python's standard library and the pinned Solana command-line tools, and hand-encodes the Squads v4
Anchor/Borsh instructions.

Set local shell variables to public or local-path values, then run this exact sequence. The three
member key files stay on their respective operators' machines; they are shown together only to make
the ordering explicit. `PAY_SO_SHA256` is the independently reviewed build hash, not a hash produced
on the deployment machine without review.

```sh
PAY_TOOL=/home/prithvi/neuron/programs/nakshatra_pay/scripts/devnet_deploy.py
PAY_SO=/ABSOLUTE/PATH/TO/nakshatra_pay.so
PAY_SO_SHA256=REVIEWED_64_HEX_SHA256
PROGRAM_KEYPAIR=/home/prithvi/wt/neu-pay/programs/nakshatra_pay/target/deploy/nakshatra_pay-keypair.json
DEPLOYER_KEYPAIR=/ABSOLUTE/PATH/TO/DEVNET_DEPLOYER.json
MEMBER_1=MEMBER_1_PUBKEY
MEMBER_2=MEMBER_2_PUBKEY
MEMBER_3=MEMBER_3_PUBKEY
MEMBER_KEYPAIR=/ABSOLUTE/PATH/TO/THIS_OPERATORS_MEMBER.json
MULTISIG=MULTISIG_PUBKEY_FROM_MULTISIG_CREATE_REPORT
ACCEPT_TRANSACTION_INDEX=TRANSACTION_INDEX_FROM_PROPOSE_REPORT

python3 "$PAY_TOOL" --url https://api.devnet.solana.com build-check \
  --so "$PAY_SO" --expect-sha256 "$PAY_SO_SHA256"
python3 "$PAY_TOOL" --url https://api.devnet.solana.com deploy \
  --so "$PAY_SO" --program-keypair "$PROGRAM_KEYPAIR" --payer "$DEPLOYER_KEYPAIR"
python3 "$PAY_TOOL" --url https://api.devnet.solana.com config-init \
  --fee-bps 300 --payer "$DEPLOYER_KEYPAIR"
python3 "$PAY_TOOL" --url https://api.devnet.solana.com multisig-create \
  --member "$MEMBER_1" --member "$MEMBER_2" --member "$MEMBER_3" \
  --threshold 2 --time-lock 172800 --payer "$DEPLOYER_KEYPAIR"
python3 "$PAY_TOOL" --url https://api.devnet.solana.com handover \
  --payer "$DEPLOYER_KEYPAIR"
python3 "$PAY_TOOL" --url https://api.devnet.solana.com accept-config-authority propose \
  --member-key "$MEMBER_KEYPAIR"
python3 "$PAY_TOOL" --url https://api.devnet.solana.com accept-config-authority approve \
  --multisig "$MULTISIG" --transaction-index "$ACCEPT_TRANSACTION_INDEX" \
  --member-key "$MEMBER_KEYPAIR"
# A different member runs the preceding approve command with that member's key file.
# After the JSON report shows time_lock_remaining=0 (at least 48 hours after approval):
python3 "$PAY_TOOL" --url https://api.devnet.solana.com accept-config-authority execute \
  --multisig "$MULTISIG" --transaction-index "$ACCEPT_TRANSACTION_INDEX" \
  --member-key "$MEMBER_KEYPAIR"
python3 "$PAY_TOOL" --url https://api.devnet.solana.com verify
```

Every subcommand emits one JSON report. Non-secret idempotency state and the randomly generated
Squads `create_key` are kept with mode `0600` below
`~/.local/state/nakshatra-pay-devnet`; override that location with `--state-dir`. Never copy that
directory into the repository. Run the complete real-program local rehearsal with:

```sh
HOME="$(mktemp -d)" ./scripts/rehearse_devnet_deploy.sh
```

## Trust assumptions

- The program upgrade authority can replace the code and therefore change any rule or move funds. Mainnet deployment requires the design's Squads multisig and announced 48-hour time-lock.
- The USDC mint freeze authority (Circle) can freeze any USDC token account, including an escrow vault.
- Nothing in this program can prevent either authority from exercising those powers.

## Withdrawal, channel, and task commitments

A pending six-hour withdrawal request does not reserve funds. Opening or funding a channel may
commit balance that was uncommitted when the request was made. Opening a task does the same for its
fixed amount. Withdrawal execution always checks
the current `vault.amount - escrow.committed`, so such a request fails rather than consuming funds
that secure an open channel or task.

## Replay-resistant channel identities

Each owner has a persistent `owner_state` PDA containing a generation counter. Escrow creation
claims and increments that counter, and channel addresses use
`["channel", escrow, generation_u64_le, channel_seq_u64_le]`. Closing and recreating an escrow
therefore cannot recreate an old channel address. Because vouchers sign the channel address, a
voucher from a closed escrow generation cannot be replayed after reinitialization.

## Delegate revocation

Revocation disables a delegate immediately and clamps its cap to its recorded spend. A delegate
record stays alive while any channel it opened remains live, so it cannot be replaced with a fresh
zero-spend record and must be supplied when that channel is finalized. Once its open-channel count
reaches zero, anyone may call `delegate_close`; rent always returns to the escrow owner.

The same lifecycle applies to delegated tasks through a separate open-task count. A failed or
expired task restores the delegate's spend; a paid task consumes it permanently.

## Verified task settlement

Task addresses use `['task', escrow, generation_u64_le, task_seq_u64_le]`, where the escrow assigns
and increments the sequence without resetting it within a generation. The task hash remains stored
metadata, so duplicate hashes are safe. The worker submits a result hash, then the named verifier
can sign a fixed, domain-separated verdict over the program, task, worker, amount, result hash, and
pass/fail byte. Anyone may relay that Ed25519 instruction immediately before
`task_verify`. A pass pays the worker and a fail refunds the commitment. An open task expires just
after its deadline; a submitted task pays by silence once `Config.close_grace_s` has elapsed.
`close_grace_s` is intentionally reused as the verdict window and defaults to 86,400 seconds.

## Fee custody and rounding

Redemptions send fees to the canonical `fee_vault` token-account PDA controlled by the config PDA,
never directly to the configurable treasury wallet. Thus a missing, frozen, or unusable treasury
wallet cannot block a worker payout. The config authority can later call `fee_withdraw(amount)` to
move accrued fees to the current `config.fee_wallet`.

Fees use cumulative accounting:

`floor(cumulative_total * fee_bps / 10_000) - floor(redeemed * fee_bps / 10_000)`

Splitting one voucher total across many redemptions therefore produces exactly the same fee as a
single redemption to that total.
