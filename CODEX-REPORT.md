## M2 ledger: fixed-price task holds (2026-10-18)

Built:

- Added an additive, idempotent `task_holds` / `task_earnings` schema beside inference holds. Task authorization snapshots the roster-derived payer and worker accounts, moves the fixed amount into a reserved zero-sum hold account, enforces the payer's existing tier/eligible-capacity policy, and preserves nonce and open-task uniqueness.
- Added atomic CAS transitions `open -> paid | refunded`. Pay credits the named worker exactly once and records earnings with the existing seven-day maturity clock; refund returns the entire hold to the payer. Replays are idempotent, opposite terminal transitions conflict, and every terminal hold account is empty.
- Extended the existing bounded expiry sweep to refund task holds at `deadline + 24h`, sharing the same transaction serialization as pay so a race produces exactly one terminal outcome.
- Added the four signed, loopback-only `/spend/task/*` routes behind `NAK_SPEND_ROUTES`, with duplicate/unknown JSON fields rejected, roster-derived identities, payer/worker-scoped status, payer-only mutations, and indistinguishable 404s outside scope.
- Added `python/tests/test_task_holds.py` covering happy paths, replays, conflicts, party privacy, validation and capacity failures, nonce/task uniqueness, maturity and conservation, threaded pay-vs-sweep races, route gating/signing/strict schemas, and an idempotent migration from a database created by the actual `forgejo/main` store source.

Tests:

- Same-command inference baseline before and after: `python3 -m pytest -q python/tests/test_spend_api.py python/tests/test_spend_escrow.py python/tests/test_spend_receipts.py` — **83 passed before, 83 passed after**.
- New task-hold suite: `python3 -m pytest -q python/tests/test_task_holds.py` — **8 passed**.
- Combined inference + task-hold suite — **91 passed**.
- Broad runnable Python suite, excluding only the three pre-existing validator/payout files that require the unavailable optional `solders` package — **255 passed**.
- The unfiltered `python3 -m pytest -q python/tests` cannot collect in this checkout because `solders` is not installed; it reports three import errors in `test_chain_payout_validator.py`, `test_chain_reconcile_validator.py`, and `test_payout.py`.

Contract ambiguities noted (contract unchanged):

- `TASK_MAX_AMOUNT` has no numeric definition in the shared contract. Implemented it as the ledger's existing `MAX_UNITS` cap, `10^12`, which also matches the node-side M2 reward/budget decision.
- Exact success bodies for pay and refund are not enumerated. Implemented the authorize hold fields (`v`, `hold_id`, `task_hash`, `worker_keyid`, `amount`, `deadline`, `state`) plus the contract-required `replayed` boolean.
- “Past deadline + 24 h” does not state inclusive/exclusive boundary behavior. Implemented expiry at `now >= deadline + 24h`, matching the existing inference sweep's deadline convention.
