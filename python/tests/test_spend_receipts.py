"""N2 strict usage receipts, maturity, shared economics, and S6 mutations."""
import hashlib
import json
import os
import sys
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chain.reconcile import Reconciler  # noqa: E402
from core.ledger_store import (  # noqa: E402
    HOLD_S,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    SpendConflict,
    SpendStateError,
)
from ledger_auth import ReceiptError, verify_receipt  # noqa: E402
from tests.test_chain_reconcile import (  # noqa: E402
    VAULT,
    FakeReconcileRPC,
    _check,
    _config,
    _write_key,
)


def _private(label):
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode()).digest()
    )


def _public(label):
    return _private(label).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _authorize(store, *, payer_account="payer", nonce="n", session="s", tokens=10):
    return store.authorize_spend(
        payer_keyid="payer-key",
        payer_account=payer_account,
        tier="self",
        client_nonce=nonce,
        session_id=session,
        model_id="model",
        billing_mode="greedy-direct-v1",
        max_prompt_tokens=tokens,
        max_output_tokens=tokens,
        workers=[{
            "worker_keyid": _public("worker"),
            "worker_account": "worker",
            "layer_start": 0,
            "layer_end": 2,
            "price_multiplier": 1,
        }],
    )


def _receipt(store, hold_id, prompt, generated, *, final=False, **changes):
    status = store.spend_status(hold_id)
    entry = status["workers"][0]
    token_layers = (prompt + generated) * entry["layers"]
    receipt = {
        "v": 2,
        "kind": "nakshatra-worker-usage",
        "receipt_id": "",
        "hold_id": hold_id,
        "claim_response_sha256": entry["claim_response_sha256"],
        "payer_keyid": status["payer_keyid"],
        "payer_account_at_authorize": status["payer_account_at_authorize"],
        "worker_keyid": entry["worker_keyid"],
        "worker_account_at_authorize": entry["worker_account_at_authorize"],
        "billable": entry["billable"],
        "session_id": status["session_id"],
        "model_id": status["model_id"],
        "billing_mode": status["billing_mode"],
        "layer_start": entry["layer_start"],
        "layer_end": entry["layer_end"],
        "sequence": entry["receipt_sequence"] + 1,
        "cumulative_prompt_tokens": prompt,
        "cumulative_generated_tokens": generated,
        "cumulative_token_layers": token_layers,
        "cumulative_cost": token_layers if entry["billable"] else 0,
        "work_completed_at": min(store._now(), status["execution_deadline"]),
        "final": final,
        "termination": "completed" if final else "checkpoint",
        "output_sha256": "",
    }
    receipt.update(changes)
    receipt["receipt_id"] = store.spend_receipt_id(receipt)
    canonical = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return receipt, _private("worker").sign(canonical).hex()


def _claim(store, hold_id):
    return store.claim_spend_worker(hold_id, _public("worker"), "claim")


def _settle(store, signed, *, relayer=None):
    return store.settle_spend_usage(
        *signed, relayer_keyid=relayer or _public("worker")
    )


def test_strict_v2_replay_sequence_conflicts_and_single_zero_delta_final(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        hold = _authorize(store)
        _claim(store, hold["hold_id"])
        first = _receipt(store, hold["hold_id"], 3, 1)
        accepted = _settle(store, first)
        assert accepted["accepted_delta"] == 8
        assert _settle(store, first, relayer="payer-key")["replayed"] is True
        assert store.balance("worker") == 8

        same_sequence = _receipt(
            store, hold["hold_id"], 3, 2, sequence=1
        )
        with pytest.raises(SpendConflict, match="sequence"):
            _settle(store, same_sequence)
        regression = _receipt(
            store, hold["hold_id"], 3, 0, sequence=2
        )
        with pytest.raises(SpendConflict, match="regressed"):
            _settle(store, regression)

        final = _receipt(store, hold["hold_id"], 3, 1, final=True)
        result = _settle(store, final)
        assert result["accepted_delta"] == 0
        assert result["state"] == "settled"
        assert _settle(store, final)["replayed"] is True

        post_final = dict(final[0], sequence=3, termination="again")
        post_final["receipt_id"] = store.spend_receipt_id(post_final)
        canonical = json.dumps(post_final, sort_keys=True, separators=(",", ":")).encode()
        with pytest.raises(SpendStateError):
            store.settle_spend_usage(
                post_final,
                _private("worker").sign(canonical).hex(),
                relayer_keyid=_public("worker"),
            )


def test_receipt_schema_hash_signature_and_hold_worker_binding_are_strict(tmp_path):
    with LedgerStore(tmp_path / "ledger.db") as store:
        hold = _authorize(store)
        _claim(store, hold["hold_id"])
        receipt, signature = _receipt(store, hold["hold_id"], 1, 0)

        with pytest.raises(LedgerValueError, match="strict v2"):
            store.settle_spend_usage(
                {**receipt, "extra": 1}, signature, relayer_keyid=_public("worker")
            )
        with pytest.raises(LedgerValueError, match="domain hash"):
            store.settle_spend_usage(
                {**receipt, "receipt_id": "sha256:" + "0" * 64},
                signature,
                relayer_keyid=_public("worker"),
            )
        with pytest.raises(LedgerValueError, match="signature"):
            store.settle_spend_usage(
                receipt, "00" * 64, relayer_keyid=_public("worker")
            )
        with pytest.raises(SpendStateError, match="relayer"):
            store.settle_spend_usage(
                receipt, signature, relayer_keyid=_public("attacker")
            )

        wrong_worker = dict(receipt, worker_keyid=_public("attacker"))
        wrong_worker["receipt_id"] = store.spend_receipt_id(wrong_worker)
        canonical = json.dumps(wrong_worker, sort_keys=True, separators=(",", ":")).encode()
        with pytest.raises(SpendStateError, match="not part"):
            store.settle_spend_usage(
                wrong_worker,
                _private("attacker").sign(canonical).hex(),
                relayer_keyid=_public("attacker"),
            )


def test_v1_and_v2_settlement_namespaces_reject_each_other(tmp_path):
    legacy = {
        "v": 1,
        "run_id": "run",
        "n_generated": 0,
        "generated_tokens": [],
        "output_sha256": hashlib.sha256(b"").hexdigest(),
        "chain": [{"node_id": "worker", "layer_start": 0, "layer_end": 1}],
        "worker_signatures": [],
    }
    roster = {"payer-key": {"pubkey": "payer-key", "operator": "payer"}}
    assert verify_receipt(legacy, "payer-key", roster)[2] == 0
    for mutation in (
        {**legacy, "v": 2},
        {**legacy, "hold_id": "hold"},
        {**legacy, "usage_receipts": []},
        {"v": 2, "kind": "nakshatra-run-aggregate", "usage_receipts": []},
    ):
        with pytest.raises(ReceiptError):
            verify_receipt(mutation, "payer-key", roster)

    with LedgerStore(tmp_path / "ledger.db") as store:
        with pytest.raises(LedgerValueError, match="strict v2"):
            store.settle_spend_usage(
                legacy, "00" * 64, relayer_keyid="payer-key"
            )


def test_terminal_anchored_maturity_withdrawal_boundary_and_restricted_capacity(tmp_path):
    clock = [1_000_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 2_000_000, 1)
        hold = _authorize(store, tokens=500_000)
        _claim(store, hold["hold_id"])
        result = _settle(
            store, _receipt(store, hold["hold_id"], 500_000, 0, final=True)
        )
        terminal = result["terminal_at"]
        assert store.balance("worker") == 1_000_000
        economic = store.economic_receipts("worker")
        assert economic[0]["hold_terminal_at"] == terminal
        assert economic[0]["matures_at"] == terminal + HOLD_S

        with pytest.raises(CreditLimitError):
            store.authorize_spend(
                payer_keyid="worker-payer", payer_account="worker", tier="stranger",
                client_nonce="restricted", session_id="restricted", model_id="model",
                billing_mode="greedy-direct-v1", max_prompt_tokens=1_000_001,
                max_output_tokens=0,
                workers=[{"worker_keyid": _public("other"), "worker_account": "other",
                          "layer_start": 0, "layer_end": 1, "price_multiplier": 1}],
            )

        store._db.execute("UPDATE accounts SET tier='known' WHERE id='worker'")
        clock[0] = terminal + HOLD_S
        assert store.withdrawable("worker") == 0
        with pytest.raises(CreditLimitError):
            store.withdraw_hold("worker", 1_000_000, "address", "at-boundary")
        assert store.dispute_spend_hold(hold["hold_id"]) is True
        store.deposit("worker-independent", "worker", 500, 2)
        assert store.eligible_spend_capacity("worker", "stranger") == 1_000_500

    # A separate earning proves strictly-after withdrawal without being clawed back.
    clock[0] = 2_000_000
    with LedgerStore(tmp_path / "after.db", clock=lambda: clock[0]) as store:
        store.deposit("funding", "payer", 2_000_000, 1)
        hold = _authorize(store, tokens=500_000)
        _claim(store, hold["hold_id"])
        terminal = _settle(
            store, _receipt(store, hold["hold_id"], 500_000, 0, final=True)
        )["terminal_at"]
        store._db.execute("UPDATE accounts SET tier='known' WHERE id='worker'")
        clock[0] = terminal + HOLD_S + 1
        assert store.withdrawable("worker") == 1_000_000
        assert store.withdraw_hold(
            "worker", 1_000_000, "address", "after-boundary"
        ) == "after-boundary"
        with pytest.raises(SpendStateError, match="matured"):
            store.dispute_spend_hold(hold["hold_id"])


def test_namespace_eligibility_matches_legacy_base_at_exact_hold_boundary(tmp_path):
    clock = [3_000_000]
    with LedgerStore(tmp_path / "boundary.db", clock=lambda: clock[0]) as store:
        store.deposit("legacy-funding", "legacy-payer", 100, 1)
        store.settle(
            "legacy-earning", "legacy-payer", {"legacy-worker": 40}, 40, "self"
        )
        legacy_earned_at = clock[0]

        store.deposit("v2-funding", "payer", 100, 2)
        hold = _authorize(store, tokens=10)
        _claim(store, hold["hold_id"])
        terminal = _settle(
            store, _receipt(store, hold["hold_id"], 3, 1, final=True)
        )["terminal_at"]

        clock[0] = legacy_earned_at + HOLD_S
        assert store.withdrawable("legacy-worker") == 40  # 28952fb behavior
        clock[0] = terminal + HOLD_S
        assert store.withdrawable("worker") == 0
        clock[0] += 1
        assert store.withdrawable("worker") == 8


def test_disputed_legacy_earning_is_not_double_restricted_from_capacity(tmp_path):
    clock = [4_000_000]
    with LedgerStore(tmp_path / "capacity.db", clock=lambda: clock[0]) as store:
        store.deposit("payer-funding", "consumer", 100, 1)
        store.settle("disputed", "consumer", {"worker": 100}, 100, "self")
        assert store.dispute("disputed") is True
        store.deposit("worker-funding", "worker", 500, 2)

        assert store.balance("worker") == 500
        assert store.withdrawable("worker") == 500
        assert store.eligible_spend_capacity("worker", "stranger") == 1_000_500


def _seed_reconcilable_spend(path):
    store = LedgerStore(path)
    store._db.execute(
        "INSERT INTO deposit_accounts(operator, token_account, created_ts) VALUES ('payer', ?, 1)",
        (VAULT,),
    )
    store.deposit_batch("payer", VAULT, [("deposit", 100 * 100, 1)], 100 * 100)
    hold = _authorize(store)
    _claim(store, hold["hold_id"])
    _settle(store, _receipt(store, hold["hold_id"], 3, 1, final=True))
    return store, hold


def _run_s6_and_assert_kill(path, tmp_path, *, vault_amount=100):
    config = _config(tmp_path)
    _write_key(config.signing_key)
    envelope, _ = Reconciler(
        path,
        FakeReconcileRPC({VAULT: vault_amount}),
        config,
        notify=lambda *_: {"attempted": False},
    ).run()
    assert envelope["report"]["outcome"] == "mismatch"
    assert config.kill_file.is_file()
    return envelope["report"]


@pytest.mark.parametrize(
    ("assignment", "value"),
    [
        ("receipt_sequence", 2),
        ("last_receipt_id", "sha256:" + "1" * 64),
        ("cumulative_prompt_tokens", 4),
        ("cumulative_generated_tokens", 2),
        ("cumulative_token_layers", 9),
        ("cumulative_cost", 9),
        ("final", 0),
        ("final_receipt_id", "sha256:" + "2" * 64),
    ],
)
def test_s6_entry_summary_is_derived_from_final_verified_receipt(
    tmp_path, assignment, value
):
    path = tmp_path / f"summary-{assignment}.sqlite"
    store, _hold = _seed_reconcilable_spend(path)
    try:
        store._db.execute(
            f"UPDATE spend_hold_workers SET {assignment}=?", (value,)
        )
    finally:
        store.close()

    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 100}), _config(tmp_path)
    ).collect()
    assert report["outcome"] == "mismatch"
    assert _check(report, "spend_usage_linkage")["ok"] is False


def test_s6_entry_state_is_derived_from_final_verified_receipt(tmp_path):
    path = tmp_path / "summary-state.sqlite"
    store, _hold = _seed_reconcilable_spend(path)
    try:
        store._db.execute(
            "UPDATE spend_hold_workers SET final=0, final_receipt_id=NULL, state='claimed'"
        )
    finally:
        store.close()

    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 100}), _config(tmp_path)
    ).collect()
    assert report["outcome"] == "mismatch"
    assert _check(report, "spend_usage_linkage")["ok"] is False


def test_s6_rejects_entry_summary_plus_unauthorized_release_bypass(tmp_path):
    path = tmp_path / "entry-release-bypass.sqlite"
    store = LedgerStore(path)
    try:
        store._db.execute(
            "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
            "VALUES ('payer', ?, 1)",
            (VAULT,),
        )
        store.deposit_batch("payer", VAULT, [("deposit", 100 * 100, 1)], 100 * 100)
        hold = _authorize(store)
        _claim(store, hold["hold_id"])
        _settle(store, _receipt(store, hold["hold_id"], 3, 1))

        store._db.execute(
            "UPDATE spend_hold_workers SET cumulative_cost=18 WHERE hold_id=?",
            (hold["hold_id"],),
        )
        store._db.execute(
            "UPDATE accounts SET balance=balance-10 WHERE id=?",
            (hold["escrow_account"],),
        )
        store._db.execute("UPDATE accounts SET balance=balance+10 WHERE id='payer'")
        event_id = f"spend-release:{hold['hold_id']}:settled"
        detail = json.dumps(
            {"hold_id": hold["hold_id"], "reason": "settled"},
            sort_keys=True,
            separators=(",", ":"),
        )
        store._db.execute(
            "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, amount, detail) "
            "VALUES (1, 'spend_release_debit', ?, ?, 'payer', -10, ?)",
            (event_id, hold["escrow_account"], detail),
        )
        store._db.execute(
            "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, amount, detail) "
            "VALUES (1, 'spend_release_credit', ?, 'payer', ?, 10, ?)",
            (event_id, hold["escrow_account"], detail),
        )
        assert store._db.execute("SELECT SUM(balance) FROM accounts").fetchone()[0] == 0
    finally:
        store.close()

    report = _run_s6_and_assert_kill(path, tmp_path)
    assert _check(report, "spend_liabilities")["ok"] is False
    assert _check(report, "spend_release_lifecycle")["ok"] is False


def test_s6_rejects_release_amount_not_matching_lifecycle(tmp_path):
    path = tmp_path / "release-amount.sqlite"
    store, hold = _seed_reconcilable_spend(path)
    try:
        store._db.execute("DROP TRIGGER journal_no_update")
        store._db.execute(
            "UPDATE journal SET amount=CASE WHEN amount<0 THEN amount+1 ELSE amount-1 END "
            "WHERE receipt_id=?",
            (f"spend-release:{hold['hold_id']}:settled",),
        )
    finally:
        store.close()

    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 100}), _config(tmp_path)
    ).collect()
    assert report["outcome"] == "mismatch"
    assert _check(report, "spend_release_lifecycle")["ok"] is False


def test_legacy_funded_flag_flip_is_ineligible_and_kills_s6(tmp_path):
    clock = [5_000_000]
    path = tmp_path / "legacy-funded-bypass.sqlite"
    with LedgerStore(path, clock=lambda: clock[0]) as store:
        store.settle("unfunded", "consumer", {"worker": 50}, 50, "self")
        clock[0] += HOLD_S + 1
        assert store.withdrawable("worker") == 0
        store._db.execute("DROP TRIGGER journal_no_update")
        store._db.execute(
            "UPDATE journal SET detail=? "
            "WHERE receipt_id='unfunded' AND kind='earn'",
            (json.dumps({"funded": True}, separators=(",", ":")),),
        )
        assert store.withdrawable("worker") == 0

    report = _run_s6_and_assert_kill(path, tmp_path, vault_amount=0)
    view = _check(report, "economic_receipt_view")
    assert view["ok"] is False
    assert any("funded marker" in error for error in view["errors"])


def test_legacy_funding_requires_exact_receipt_journal_pair(tmp_path):
    clock = [6_000_000]
    path = tmp_path / "legacy-pair.sqlite"
    with LedgerStore(path, clock=lambda: clock[0]) as store:
        store._db.execute(
            "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
            "VALUES ('consumer', ?, 1)",
            (VAULT,),
        )
        store.deposit_batch("consumer", VAULT, [("funding", 100, 1)], 100)
        store.settle("earning", "consumer", {"worker": 40}, 40, "self")
        clock[0] += HOLD_S
        assert store.withdrawable("worker") == 40

        store._db.execute("DROP TRIGGER journal_no_update")
        store._db.execute(
            "UPDATE journal SET amount=-39 WHERE receipt_id='earning' AND kind='spend'"
        )
        assert store.withdrawable("worker") == 0

    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 1}), _config(tmp_path)
    ).collect()
    assert report["outcome"] == "mismatch"
    view = _check(report, "economic_receipt_view")
    assert any("exact earn/spend journal pair" in error for error in view["errors"])


def test_s6_rejects_dispute_refund_not_matching_exact_receipt_amount(tmp_path):
    path = tmp_path / "dispute-refund.sqlite"
    store, hold = _seed_reconcilable_spend(path)
    try:
        assert store.dispute_spend_hold(hold["hold_id"]) is True
        store._db.execute("DROP TRIGGER journal_no_update")
        store._db.execute(
            "UPDATE journal SET amount=amount+1 "
            "WHERE kind='spend_dispute_refund'"
        )
    finally:
        store.close()

    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 100}), _config(tmp_path)
    ).collect()
    assert report["outcome"] == "mismatch"
    view = _check(report, "economic_receipt_view")
    assert any("equal-and-opposite" in error for error in view["errors"])


def test_s6_detects_symmetric_double_accounting_mutation(tmp_path):
    path = tmp_path / "ledger.sqlite"
    store, hold = _seed_reconcilable_spend(path)
    try:
        assert store.dispute_spend_hold(hold["hold_id"]) is True
        config = _config(tmp_path)
        clean = Reconciler(path, FakeReconcileRPC({VAULT: 100}), config).collect()
        assert clean["outcome"] == "match"
        receipt = store._db.execute(
            "SELECT receipt_id, accepted_delta FROM spend_usage_receipts"
        ).fetchone()
        amount = int(receipt["accepted_delta"])
        escrow = hold["escrow_account"]
        store._db.execute("UPDATE accounts SET balance=balance-? WHERE id=?", (amount, escrow))
        store._db.execute("UPDATE accounts SET balance=balance+? WHERE id='worker'", (amount,))
        detail = json.dumps({"hold_id": hold["hold_id"], "mutation": True})
        store._db.execute(
            "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, amount, detail) "
            "VALUES (1, 'spend_settle_debit', ?, ?, 'worker', ?, ?)",
            (receipt["receipt_id"], escrow, -amount, detail),
        )
        store._db.execute(
            "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, amount, detail) "
            "VALUES (1, 'spend_earn', ?, 'worker', ?, ?, ?)",
            (receipt["receipt_id"], escrow, amount, detail),
        )
        assert store._db.execute("SELECT SUM(balance) FROM accounts").fetchone()[0] == 0
    finally:
        store.close()

    config = _config(tmp_path)
    _write_key(config.signing_key)
    envelope, _ = Reconciler(
        path,
        FakeReconcileRPC({VAULT: 100}),
        config,
        notify=lambda *_: {"attempted": False},
    ).run()
    report = envelope["report"]
    assert report["outcome"] == "mismatch"
    assert config.kill_file.is_file()
    assert _check(report, "zero_sum_balances")["ok"] is True
    linkage = _check(report, "spend_usage_linkage")
    assert linkage["ok"] is False
    assert any("orphan or duplicate" in error for error in linkage["errors"])


def test_s6_reconciles_10k_receipts_under_two_seconds(tmp_path):
    path = tmp_path / "ten-thousand.sqlite"
    with LedgerStore(path) as store:
        store._db.execute(
            "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
            "VALUES ('payer', ?, 1)",
            (VAULT,),
        )
        store.deposit_batch("payer", VAULT, [("deposit", 1_000_000, 1)], 1_000_000)
        hold = _authorize(store, tokens=10_000)
        _claim(store, hold["hold_id"])
        for sequence in range(1, 10_001):
            _settle(
                store,
                _receipt(
                    store,
                    hold["hold_id"],
                    1,
                    sequence - 1,
                    final=sequence == 10_000,
                ),
            )

    started = time.perf_counter()
    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 10_000}), _config(tmp_path)
    ).collect()
    elapsed = time.perf_counter() - started

    assert report["outcome"] == "match"
    assert _check(report, "spend_usage_linkage")["checked"] == 10_000
    assert elapsed < 2.0, f"10k-receipt S6 took {elapsed:.3f}s"
