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

## Trust assumptions

- The program upgrade authority can replace the code and therefore change any rule or move funds. Mainnet deployment requires the design's Squads multisig and announced 48-hour time-lock.
- The USDC mint freeze authority (Circle) can freeze any USDC token account, including an escrow vault.
- Nothing in this program can prevent either authority from exercising those powers.

## Withdrawal and channel commitments

A pending six-hour withdrawal request does not reserve funds. Opening or funding a channel may
commit balance that was uncommitted when the request was made. Withdrawal execution always checks
the current `vault.amount - escrow.committed`, so such a request fails rather than consuming funds
that secure an open channel.

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

## Fee custody and rounding

Redemptions send fees to the canonical `fee_vault` token-account PDA controlled by the config PDA,
never directly to the configurable treasury wallet. Thus a missing, frozen, or unusable treasury
wallet cannot block a worker payout. The config authority can later call `fee_withdraw(amount)` to
move accrued fees to the current `config.fee_wallet`.

Fees use cumulative accounting:

`floor(cumulative_total * fee_bps / 10_000) - floor(redeemed * fee_bps / 10_000)`

Splitting one voucher total across many redemptions therefore produces exactly the same fee as a
single redemption to that total.
