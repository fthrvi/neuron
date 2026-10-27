# nakshatra_pay

This Anchor workspace contains the Nakshatra non-custodial payment program and its LiteSVM tests.

## Build and test

Run the checked-in test driver from this directory:

```sh
./scripts/test.sh
```

It builds the SBF program with the pinned platform tools before running `cargo test`. The tests also compare `target/deploy/nakshatra_pay.so` with every Rust source file and fail with a `run \`anchor build\` first` message rather than testing stale code.

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
