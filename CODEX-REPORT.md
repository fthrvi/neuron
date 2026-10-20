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

## Fix round 1

Review: rv-m2.md. Suites: `python3 -m pytest -q python/tests/test_task_holds.py test_spend_api test_spend_escrow test_spend_receipts test_ledger_store test_ledger_server`: before 162 passed, after 165 passed.

| Finding | Change | Proven by |
|---|---|---|
| 3 Rollback blocker | Task escrow accounts moved from `__spend_hold__:task:<id>` to `__task_hold__:<id>` (`_TASK_HOLD_STEM`, `_task_hold_account`); `is_reserved` covers the new stem; a startup check refuses any `__task_hold__` account not backed by `task_holds.escrow_account` (same shape as the spend-hold check, which still tolerates legacy task rows under the old stem). | `test_forgejo_main_code_still_opens_a_store_with_paid_and_open_task_holds` (one paid + one open hold, opened by `git show forgejo/main:python/core/ledger_store.py` in a subprocess: starts, balances sum 0 and match), `test_task_accounts_use_their_own_reserved_stem_and_unbacked_ones_refuse_startup`; forward migration test unchanged and passing. Mutation (stem reverted) fails both. |
| 7 Authorize replay near deadline | `ledger_server.authorize_task_hold` probes `LedgerStore.has_task_hold_nonce(payer, nonce)`; on a replay the +60 s floor is skipped and the store answers (same hold, or 409 if any field differs). New holds still need the window. | `test_identical_authorize_replay_near_the_deadline_returns_the_same_hold` (mutation fails it). |

Note: a replay of a hold that has since been refunded/paid returns that terminal state; the adapter rejects it as not open (fail closed).

## Fix round 2

Review: rv2-m2.md. No ledger behaviour change was required in round 2 (all blocking/nit work is on the Nakshatra side). Only change: `has_task_hold_nonce` docstring now records the invariant it relies on (task_holds rows are never deleted; a trigger forbids it; if that ever changed the probe would return False and the full deadline window would apply, i.e. fail closed). The round-1 replay-near-deadline fix is what lets the poster's recovery re-run the identical authorize and get the same hold (`test_identical_authorize_replay_near_the_deadline_returns_the_same_hold`). Suite: 165 passed before and after.

## M2.1 ledger: submitted mark and silence-pays sweep (2026-10-20)

Built:

- Added the signed, loopback-only, `NAK_SPEND_ROUTES`-gated `POST /spend/task/submit` route. Only the named worker can mark an open hold; the 64-lowercase-hex result hash is immutable, identical replay is idempotent, a different hash conflicts, and terminal conflicts return the hold state.
- Added rollback-safe `submitted_at` and `result_hash` columns with defaults and transition-validating triggers. Task status now returns both fields, using `0` and `""` before submission.
- Changed the existing deadline+24h sweep so a submitted open hold pays the named worker (including the normal task-earnings maturity record) while an unsubmitted hold retains the M2 refund behavior. Pay/refund/sweep still serialize through the same transaction and zero-sum check.
- Kept payer refund available after submission and made it auditable with the `refund_after_submit` journal kind plus the same boolean in both journal details. Sweep payments carry `paid_by_silence` in their journal details.

Compatibility and tests:

- The ledger-focused regression command recorded in the prior report now passes **167 tests**, versus **165** at `4ee5314`; the two added tests cover submission policy/state and post-submit refund marking. All runs used temporary HOME/database/roster paths.
- The broad runnable Python suite passes **260 tests** when excluding the same three validator/payout files whose optional `solders` dependency is unavailable.
- The exact required `python -m pytest -q tests/` command was run before and after. It still stops at collection with the same three `ModuleNotFoundError: solders` errors in `test_chain_payout_validator.py`, `test_chain_reconcile_validator.py`, and `test_payout.py`; no test body runs under that unfiltered command.
- Forward migration was exercised from a database created by `git show 4ee5314:python/core/ledger_store.py` with existing inference and task holds. Reverse rollback was exercised by opening a new-schema database containing paid and submitted-open task holds with that exact old store source; balances and the zero sum were unchanged.
- The threaded three-way pay/refund/sweep race ran 12 times and always produced one terminal accounting event (exactly two balanced journal legs), never duplicate earnings, and a zero total.

Mutation check (all killed):

1. Replacing the submit scope from `worker_keyid` to `payer_keyid` failed `test_worker_submit_is_idempotent_hash_bound_and_terminal_aware`.
2. Disabling the submitted branch in the expiry sweep failed `test_expiry_sweep_pays_submitted_and_refunds_unsubmitted` (`refunded` instead of `paid`).
3. Disabling post-submit refund detection failed `test_refund_after_submit_is_distinct_in_the_journal` (ordinary refund kinds instead of `refund_after_submit`).

## Fix round 1 (M2.1)

Review: `rv-verdict.md` (B1, B2, N7).

- B1: the matured-task earnings proof now accepts exactly the two canonical journal details emitted by ordinary pay and silence pay: `{"hold_id":...}` and `{"hold_id":...,"paid_by_silence":true}`. Both journal legs must still agree and every other provenance check remains unchanged. The sweep test proves the silence-paid amount becomes withdrawable after maturity and that adding an extra detail field makes it unproven again.
- B2: task submission no longer advances the hold as a side effect. A mark at the task deadline is accepted (the deadline is inclusive); the first instant after it returns HTTP 409 with `state: "open"` and `error: "deadline passed"`, leaving the hold, journal, and balances unchanged. The ordinary bounded sweep remains responsible for the later `deadline + 24h` transition.
- N7: `GET /spend/task/status` now exposes `refund_after_submit` as a boolean derived from the immutable submission mark and refunded terminal state, including to the scoped worker.

Verification:

- Focused task-hold suite: **14 passed**.
- Broad required suite from `python/`, excluding only `test_chain_payout_validator.py`, `test_chain_reconcile_validator.py`, and `test_payout.py` because the optional `solders` package is unavailable: **261 passed**.
- Explicit reverse-compatibility rollback test (`test_forgejo_main_code_still_opens_a_store_with_paid_and_open_task_holds`): **1 passed**.
- All test runs used a temporary `HOME`; no live ledger, deployment, or push was performed.

## Fix round 2 (delivery receipt)

Implemented the ledger delivery receipt from the shared contract:

- Added the signed, loopback-only, `NAK_SPEND_ROUTES`-gated `POST /spend/task/received` route. Only the named payer can acknowledge a result; worker/stranger calls are hidden as 404, identical replay is idempotent, a different replay hash is 409, and terminal holds return the existing state-bearing 409.
- Added rollback-safe `received_at` and `received_hash` task-hold columns, status fields, and fail-closed insert/transition triggers. A receipt requires an existing submission whose mark is at or before the task deadline, while the receipt itself may arrive after the deadline.
- Replaced the sweep condition with the exact receipt rule: silence-pay occurs only for an on-time submission plus a receipt with the same hash. Submitted-only, received-only/partial, and unequal-hash holds refund. Explicit payer pay/refund behavior and the strict two-shape B1 earnings proof are unchanged.
- Extended tests for receipt scope, strict bodies and route gating, no/late submission refusal, after-deadline acceptance, idempotency/conflicts, terminal behavior, status exposure, the four-case sweep matrix, zero-sum accounting, strict maturity provenance, and a four-way pay/refund/received/sweep race.
- Forward migration defaults were verified from a database made by the real `4ee5314` store. Reverse rollback was verified by opening a new-schema database containing an open hold with both submission and receipt marks using that exact old store source; balances and zero-sum accounting were unchanged.

Verification (every run used a temporary `HOME`):

- Focused task-hold suite: **15 passed**.
- Required ledger regression command (`test_task_holds`, spend API/escrow/receipts, ledger store/server): **169 passed**.
- Broad runnable Python suite, excluding only the three modules requiring unavailable optional `solders`: **262 passed**.
- The exact unfiltered `python3 -m pytest -q tests/` command still stops during collection on the same three pre-existing `ModuleNotFoundError: solders` errors in `test_chain_payout_validator.py`, `test_chain_reconcile_validator.py`, and `test_payout.py`.

Mutation check (both killed):

1. Reverting the sweep predicate to submitted-only failed `test_expiry_sweep_pays_only_matching_submitted_and_received_matrix` (`submitted only` paid instead of refunded).
2. Changing receipt ownership from `payer_keyid` to `worker_keyid` failed `test_payer_received_is_scoped_idempotent_hash_bound_and_accepts_late_delivery` (the worker could reach the mutation while the payer was hidden).
