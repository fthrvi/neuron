# nakshatra_pay

This Anchor workspace contains the Nakshatra non-custodial payment program and its LiteSVM tests.

## Build and test

Run the checked-in test driver from this directory:

```sh
./scripts/test.sh
```

It builds the SBF program with the pinned platform tools before running `cargo test`. The tests also compare `target/deploy/nakshatra_pay.so` with every Rust source file and fail with a `run \`anchor build\` first` message rather than testing stale code.

## Trust assumptions

- The program upgrade authority can replace the code and therefore change any rule or move funds. Mainnet deployment requires the design's Squads multisig and announced 48-hour time-lock.
- The USDC mint freeze authority (Circle) can freeze any USDC token account, including an escrow vault.
- Nothing in this program can prevent either authority from exercising those powers.
