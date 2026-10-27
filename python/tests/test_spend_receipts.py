"""N2 strict usage receipts, maturity, shared economics, and S6 mutations."""
import hashlib
import json
import os
import random
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chain.reconcile import (  # noqa: E402
    ReconcileError,
    Reconciler,
    _replay_funding_backed_balance,
)
from core.ledger_store import (  # noqa: E402
    HOLD_S,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    SpendConflict,
    SpendNotFound,
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


def _authorize(
    store,
    *,
    payer_account="payer",
    nonce="n",
    session="s",
    tokens=10,
    worker_label="worker",
    worker_account="worker",
):
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
            "worker_keyid": _public(worker_label),
            "worker_account": worker_account,
            "layer_start": 0,
            "layer_end": 2,
            "price_multiplier": 1,
        }],
    )


def _receipt(
    store, hold_id, prompt, generated, *, final=False, worker_label="worker", **changes
):
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
    return receipt, _private(worker_label).sign(canonical).hex()


def _claim(store, hold_id, worker_label="worker"):
    return store.claim_spend_worker(hold_id, _public(worker_label), "claim")


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


def test_v2_starter_backed_hold_credits_spendable_but_uncashable_earnings(tmp_path):
    clock = [900_000]
    path = tmp_path / "ledger.db"
    with LedgerStore(path, clock=lambda: clock[0]) as store:
        store.grant_starter(
            "starter", "grantor", "payer", "a" * 64, 40, "self", "self"
        )
        hold = _authorize(store)
        assert hold["funded"] == 0
        with pytest.raises(sqlite3.IntegrityError, match="snapshot is immutable"):
            store._db.execute(
                "UPDATE spend_holds SET funded=1 WHERE hold_id=?",
                (hold["hold_id"],),
            )
        _claim(store, hold["hold_id"])
        result = _settle(
            store, _receipt(store, hold["hold_id"], 1, 0, final=True)
        )
        assert result["state"] == "settled"
        economic = store._db.execute(
            "SELECT funded FROM spend_economic_receipts"
        ).fetchone()
        assert economic is not None and economic["funded"] == 0
        assert store.economic_receipts("worker")[0]["funded"] == 0

        terminal = int(result["terminal_at"])
        clock[0] = terminal + HOLD_S + 1
        assert store.balance("worker") == 2
        assert store.withdrawable("worker") == 0

    report = Reconciler(path, FakeReconcileRPC({VAULT: 0}), _config(tmp_path)).collect()
    assert report["outcome"] == "match", report


def test_unfunded_v2_earnings_cannot_fund_a_colluder_chain(tmp_path):
    clock = [950_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        first = _authorize(
            store,
            payer_account="stranger",
            nonce="overdraft-hop",
            session="overdraft-session",
            worker_label="worker-one",
            worker_account="worker-one",
        )
        assert first["funded"] == 0
        _claim(store, first["hold_id"], "worker-one")
        _settle(
            store,
            _receipt(
                store,
                first["hold_id"],
                1,
                0,
                final=True,
                worker_label="worker-one",
            ),
            relayer=_public("worker-one"),
        )

        second = _authorize(
            store,
            payer_account="worker-one",
            nonce="colluder-hop",
            session="colluder-session",
            worker_label="worker-two",
            worker_account="worker-two",
        )
        assert second["funded"] == 0
        _claim(store, second["hold_id"], "worker-two")
        result = _settle(
            store,
            _receipt(
                store,
                second["hold_id"],
                1,
                0,
                final=True,
                worker_label="worker-two",
            ),
            relayer=_public("worker-two"),
        )

        clock[0] = int(result["terminal_at"]) + HOLD_S + 1
        assert store.balance("worker-two") == 2
        assert store.withdrawable("worker-two") == 0


def test_unmatured_funded_v2_earnings_do_not_back_a_payment(tmp_path):
    clock = [975_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        store.deposit("deposit", "payer", 40, 1)
        first = _authorize(
            store,
            nonce="funded-hop",
            session="funded-session",
            worker_label="worker-one",
            worker_account="worker-one",
        )
        assert first["funded"] == 1
        _claim(store, first["hold_id"], "worker-one")
        _settle(
            store,
            _receipt(
                store,
                first["hold_id"],
                10,
                10,
                worker_label="worker-one",
            ),
            relayer=_public("worker-one"),
        )
        assert store.withdrawable("worker-one") == 0

        second = _authorize(
            store,
            payer_account="worker-one",
            nonce="earning-hop",
            session="earning-session",
            worker_label="worker-two",
            worker_account="worker-two",
        )
        assert second["funded"] == 0  # still disputable: spendable, not backing


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
        with pytest.raises(SpendNotFound, match="not found"):
            store.settle_spend_usage(
                receipt, signature, relayer_keyid=_public("attacker")
            )

        wrong_worker = dict(receipt, worker_keyid=_public("attacker"))
        wrong_worker["receipt_id"] = store.spend_receipt_id(wrong_worker)
        canonical = json.dumps(wrong_worker, sort_keys=True, separators=(",", ":")).encode()
        with pytest.raises(SpendNotFound, match="not found"):
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
        assert store.eligible_spend_capacity("legacy-worker", "stranger") == 1_000_000
        clock[0] = terminal + HOLD_S
        assert store.withdrawable("worker") == 0
        clock[0] += 1
        assert store.withdrawable("worker") == 8
        assert store.eligible_spend_capacity("legacy-worker", "stranger") == 1_000_040
        assert store.eligible_spend_capacity("worker", "stranger") == 1_000_008


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


def _duplicate_v2_economic_row(db):
    """Rebuild the source table without its PK to model raw storage corruption."""
    view_sql = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='view' AND name='economic_receipts'"
    ).fetchone()[0]
    db.execute("DROP VIEW economic_receipts")
    db.execute("ALTER TABLE spend_economic_receipts RENAME TO original_economic")
    db.execute(
        "CREATE TABLE spend_economic_receipts AS "
        "SELECT * FROM original_economic WHERE 0"
    )
    db.execute(
        "INSERT INTO spend_economic_receipts SELECT * FROM original_economic"
    )
    db.execute(
        "INSERT INTO spend_economic_receipts SELECT * FROM original_economic"
    )
    db.execute(view_sql)


@pytest.mark.parametrize(
    "inconsistent_state",
    [
        "economic_without_usage",
        "amount_differs",
        "worker_differs",
        "maturity_differs",
        "duplicate_economic",
        "usage_without_economic",
        "journal_pair_without_receipt",
        "legacy_economic_without_provenance",
    ],
)
def test_inconsistent_economic_states_fail_closed(
    tmp_path, inconsistent_state
):
    """Every row of the N2 inconsistent-state table stays fail closed."""
    path = tmp_path / f"fail-closed-{inconsistent_state}.sqlite"
    store, hold = _seed_reconcilable_spend(path)
    receipt_id = store._db.execute(
        "SELECT receipt_id FROM spend_usage_receipts"
    ).fetchone()[0]
    terminal = int(store.spend_status(hold["hold_id"])["terminal_at"])
    store._clock = lambda: terminal + HOLD_S + (
        1 if inconsistent_state == "duplicate_economic" else 0
    )
    withdrawable_before = store.withdrawable("worker")
    capacity_before = store.eligible_spend_capacity("worker", "stranger")
    if inconsistent_state == "duplicate_economic":
        assert withdrawable_before == 8
    else:
        assert withdrawable_before == 0

    try:
        if inconsistent_state == "economic_without_usage":
            fabricated_id = "sha256:" + "e" * 64
            store._db.execute("PRAGMA foreign_keys=OFF")
            store._db.execute(
                "INSERT INTO spend_economic_receipts "
                "SELECT ?, hold_id, payer_account, worker_account, amount, funded, "
                "earned_at, hold_terminal_at, matures_at, dispute_state, "
                "debit_journal_seq, credit_journal_seq "
                "FROM spend_economic_receipts WHERE receipt_id=?",
                (fabricated_id, receipt_id),
            )
        elif inconsistent_state == "amount_differs":
            store._db.execute("DROP TRIGGER spend_economic_core_immutable")
            store._db.execute(
                "UPDATE spend_economic_receipts SET amount=amount-1"
            )
        elif inconsistent_state == "worker_differs":
            store._db.execute("DROP TRIGGER spend_economic_core_immutable")
            store._db.execute(
                "UPDATE spend_economic_receipts SET worker_account='other-worker'"
            )
        elif inconsistent_state == "maturity_differs":
            store._db.execute(
                "UPDATE spend_economic_receipts SET "
                "hold_terminal_at=hold_terminal_at+1, matures_at=matures_at+1"
            )
        elif inconsistent_state == "duplicate_economic":
            _duplicate_v2_economic_row(store._db)
        elif inconsistent_state == "usage_without_economic":
            store._db.execute("DROP TRIGGER spend_economic_receipts_no_delete")
            store._db.execute("DELETE FROM spend_economic_receipts")
        elif inconsistent_state == "journal_pair_without_receipt":
            fake_id = "sha256:" + "a" * 64
            detail = json.dumps({"hold_id": hold["hold_id"], "mutation": True})
            store._db.execute(
                "UPDATE accounts SET balance=balance-8 WHERE id=?",
                (hold["escrow_account"],),
            )
            store._db.execute(
                "UPDATE accounts SET balance=balance+8 WHERE id='worker'"
            )
            store._db.execute(
                "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, "
                "amount, detail) VALUES (?, 'spend_settle_debit', ?, ?, 'worker', -8, ?)",
                (terminal, fake_id, hold["escrow_account"], detail),
            )
            store._db.execute(
                "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, "
                "amount, detail) VALUES (?, 'spend_earn', ?, 'worker', ?, 8, ?)",
                (terminal, fake_id, hold["escrow_account"], detail),
            )
        elif inconsistent_state == "legacy_economic_without_provenance":
            fake_id = "legacy-without-receipt"
            store._db.execute(
                "UPDATE accounts SET balance=balance-8 WHERE id='payer'"
            )
            store._db.execute(
                "UPDATE accounts SET balance=balance+8 WHERE id='worker'"
            )
            store._db.execute(
                "INSERT INTO journal(ts, kind, receipt_id, account, amount, detail) "
                "VALUES (?, 'spend', ?, 'payer', -8, ?)",
                (terminal, fake_id, json.dumps({"tier": "self"})),
            )
            store._db.execute(
                "INSERT INTO journal(ts, kind, receipt_id, account, counterparty, "
                "amount, detail) VALUES (?, 'earn', ?, 'worker', 'payer', 8, ?)",
                (terminal, fake_id, json.dumps({"funded": True})),
            )
    finally:
        withdrawable_after = store.withdrawable("worker")
        capacity_after = store.eligible_spend_capacity("worker", "stranger")
        store.close()

    assert withdrawable_after == withdrawable_before
    assert capacity_after <= capacity_before

    report = _run_s6_and_assert_kill(path, tmp_path)
    if inconsistent_state != "journal_pair_without_receipt":
        assert _check(report, "economic_receipt_view")["ok"] is False
    if inconsistent_state in {
        "economic_without_usage", "duplicate_economic", "usage_without_economic"
    }:
        assert any(
            "raw v2 cardinality" in error
            for error in _check(report, "economic_receipt_view")["errors"]
        )


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


@pytest.fixture
def legacy_task_reconcile_fixture(tmp_path):
    """A live-shaped ledger with pre-marker v1 earns and both task funding states."""
    path = tmp_path / "legacy-task.sqlite"
    clock = [7_000_000]
    with LedgerStore(path, clock=lambda: clock[0]) as store:
        store._db.execute(
            "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
            "VALUES ('task-payer', ?, 1)",
            (VAULT,),
        )
        store.deposit_batch(
            "task-payer", VAULT, [("task-funding", 10_000, 1)], 10_000
        )
        for receipt_id, charged in (
            ("31257cea-live-shape", 280),
            ("bdfc57bf-live-shape", 280),
            ("789f8804-live-shape", 168),
        ):
            store.settle(
                receipt_id,
                "self",
                {f"legacy-worker-{receipt_id[:8]}": charged},
                charged,
                "self",
            )

        funded = store.authorize_task_hold(
            payer_keyid="task-payer-key",
            payer_account="task-payer",
            tier="self",
            client_nonce="funded-task",
            task_hash="1" * 64,
            worker_keyid="funded-worker-key",
            worker_account="funded-task-worker",
            amount=100,
            deadline=clock[0] + 60,
        )
        assert funded["funded"] == 1
        store.pay_task_hold(funded["hold_id"], "task-payer-key")

        unfunded = store.authorize_task_hold(
            payer_keyid="unfunded-payer-key",
            payer_account="unfunded-payer",
            tier="stranger",
            client_nonce="unfunded-task",
            task_hash="2" * 64,
            worker_keyid="unfunded-worker-key",
            worker_account="unfunded-task-worker",
            amount=80,
            deadline=clock[0] + 60,
        )
        assert unfunded["funded"] == 0
        store.pay_task_hold(unfunded["hold_id"], "unfunded-payer-key")

        store._db.execute("DROP TRIGGER journal_no_update")
        store._db.execute(
            "UPDATE journal SET detail='{}' "
            "WHERE kind='earn' AND receipt_id LIKE '%-live-shape'"
        )

    return path


def test_full_reconcile_accepts_legacy_markers_and_task_economics(
    tmp_path, legacy_task_reconcile_fixture
):
    config = _config(tmp_path)
    _write_key(config.signing_key)
    envelope, _ = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        config,
        notify=lambda *_: {"attempted": False},
    ).run()

    report = envelope["report"]
    assert report["outcome"] == "match", report
    assert _check(report, "economic_receipt_view")["ok"] is True


def test_present_wrong_legacy_marker_still_fails(
    tmp_path, legacy_task_reconcile_fixture
):
    with sqlite3.connect(legacy_task_reconcile_fixture) as db:
        db.execute(
            "UPDATE journal SET detail=? WHERE receipt_id='31257cea-live-shape' "
            "AND kind='earn'",
            (json.dumps({"funded": True}, separators=(",", ":")),),
        )

    report = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        _config(tmp_path),
    ).collect()
    view = _check(report, "economic_receipt_view")
    assert report["outcome"] == "mismatch"
    assert any("funded marker" in error for error in view["errors"])


def test_empty_legacy_marker_is_rejected_for_funded_projection(tmp_path):
    path = tmp_path / "funded-empty-marker.sqlite"
    clock = [7_100_000]
    with LedgerStore(path, clock=lambda: clock[0]) as store:
        store._db.execute(
            "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
            "VALUES ('payer', ?, 1)", (VAULT,),
        )
        store.deposit_batch("payer", VAULT, [("funded-marker", 500, 1)], 500)
        store.settle("funded-receipt", "payer", {"worker": 100}, 100, "self")
        assert store._db.execute(
            "SELECT funded FROM legacy_funding_projection "
            "WHERE receipt_id='funded-receipt'"
        ).fetchone()[0] == 1
        store._db.execute("DROP TRIGGER journal_no_update")
        store._db.execute(
            "UPDATE journal SET detail='{}' WHERE receipt_id='funded-receipt' "
            "AND kind='earn'"
        )

    report = Reconciler(path, FakeReconcileRPC({VAULT: 5}), _config(tmp_path)).collect()
    assert report["outcome"] == "mismatch"
    assert any(
        "funded marker" in error
        for error in _check(report, "economic_receipt_view")["errors"]
    )


@pytest.mark.parametrize("mutation", ["missing", "mismatching"])
def test_empty_legacy_marker_requires_matching_projection(
    tmp_path, legacy_task_reconcile_fixture, mutation
):
    with sqlite3.connect(legacy_task_reconcile_fixture) as db:
        if mutation == "missing":
            db.execute("DROP TRIGGER legacy_funding_projection_no_delete")
            db.execute(
                "DELETE FROM legacy_funding_projection "
                "WHERE receipt_id='31257cea-live-shape'"
            )
        else:
            db.execute("DROP TRIGGER legacy_funding_projection_no_update")
            db.execute(
                "UPDATE legacy_funding_projection SET funded=1 "
                "WHERE receipt_id='31257cea-live-shape'"
            )

    report = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        _config(tmp_path),
    ).collect()
    view = _check(report, "economic_receipt_view")
    assert report["outcome"] == "mismatch"
    assert any("funding projection" in error for error in view["errors"])
    assert any("funded marker" in error for error in view["errors"])


def _materialize_economic_view(db):
    db.execute(
        "CREATE TABLE tampered_economic_receipts AS SELECT * FROM economic_receipts"
    )
    db.execute("DROP VIEW economic_receipts")
    db.execute(
        "ALTER TABLE tampered_economic_receipts RENAME TO economic_receipts"
    )


@pytest.mark.parametrize(
    "mutation",
    ["wrong_amount", "wrong_funded", "missing", "extra"],
)
def test_tampered_task_economic_view_fails(
    tmp_path, legacy_task_reconcile_fixture, mutation
):
    with sqlite3.connect(legacy_task_reconcile_fixture) as db:
        _materialize_economic_view(db)
        first_task = (
            "SELECT economic_id FROM economic_receipts "
            "WHERE namespace='task' ORDER BY economic_id LIMIT 1"
        )
        if mutation == "wrong_amount":
            db.execute(
                f"UPDATE economic_receipts SET amount=amount+1 "
                f"WHERE economic_id=({first_task})"
            )
        elif mutation == "wrong_funded":
            db.execute(
                f"UPDATE economic_receipts SET funded=1-funded "
                f"WHERE economic_id=({first_task})"
            )
        elif mutation == "missing":
            db.execute(
                f"DELETE FROM economic_receipts WHERE economic_id=({first_task})"
            )
        else:
            db.execute(
                "INSERT INTO economic_receipts "
                "SELECT 'task:extra', namespace, receipt_id, hold_id, payer_account, "
                "worker_account, amount, funded, earned_at, hold_terminal_at, "
                "matures_at, eligible_at, dispute_state, debit_journal_seq, "
                "credit_journal_seq FROM economic_receipts "
                "WHERE namespace='task' ORDER BY economic_id LIMIT 1"
            )

    report = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        _config(tmp_path),
    ).collect()
    view = _check(report, "economic_receipt_view")
    assert report["outcome"] == "mismatch"
    assert view["ok"] is False
    if mutation in {"wrong_amount", "wrong_funded"}:
        assert any("task economic projection differs" in error for error in view["errors"])
    else:
        assert any("task economic rows do not exactly" in error for error in view["errors"])


def _paid_task_id(path, funded):
    with sqlite3.connect(path) as db:
        return db.execute(
            "SELECT hold_id FROM task_holds WHERE state='paid' AND funded=? ",
            (funded,),
        ).fetchone()[0]


def _flip_task_funded(path, hold_id):
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER task_holds_snapshots_immutable")
        db.execute(
            "UPDATE task_holds SET funded=1-funded WHERE hold_id=?", (hold_id,)
        )


def _write_grandfather_file(config, contents):
    config.grandfathered_holds_file.write_text(contents, encoding="ascii")
    config.grandfathered_holds_file.chmod(0o600)


def _grandfather_line(path, hold_id):
    with sqlite3.connect(path) as db:
        amount, payer, worker = db.execute(
            "SELECT amount, payer_account, worker_account FROM task_holds "
            "WHERE hold_id=?", (hold_id,),
        ).fetchone()
    return f"{hold_id} {amount} {payer} {worker}"


def test_task_funded_flip_requires_explicit_grandfather(
    tmp_path, legacy_task_reconcile_fixture
):
    hold_id = _paid_task_id(legacy_task_reconcile_fixture, 0)
    _flip_task_funded(legacy_task_reconcile_fixture, hold_id)

    report = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        _config(tmp_path),
    ).collect()

    view = _check(report, "economic_receipt_view")
    assert report["outcome"] == "mismatch"
    assert any("stored task funding differs" in error for error in view["errors"])


def test_transferred_unbacked_balance_does_not_forge_task_funding(tmp_path):
    path = tmp_path / "transferred-unbacked.sqlite"
    clock = [7_200_000]
    with LedgerStore(path, clock=lambda: clock[0]) as store:
        store.transfer("source", "payer", 200, "self")
        hold = store.authorize_task_hold(
            payer_keyid="payer-key", payer_account="payer", tier="self",
            client_nonce="transfer-funded", task_hash="3" * 64,
            worker_keyid="worker-key", worker_account="worker", amount=100,
            deadline=clock[0] + 60,
        )
        assert hold["funded"] == 0
        store.pay_task_hold(hold["hold_id"], "payer-key")

    clean = Reconciler(path, FakeReconcileRPC({VAULT: 0}), _config(tmp_path)).collect()
    assert clean["outcome"] == "match", clean

    _flip_task_funded(path, hold["hold_id"])
    forged = Reconciler(path, FakeReconcileRPC({VAULT: 0}), _config(tmp_path)).collect()
    assert forged["outcome"] == "mismatch"
    assert any(
        "stored task funding differs" in error
        for error in _check(forged, "economic_receipt_view")["errors"]
    )


def test_explicit_grandfather_is_reported_and_accepts_only_funded_migration(
    tmp_path, legacy_task_reconcile_fixture
):
    hold_id = _paid_task_id(legacy_task_reconcile_fixture, 0)
    _flip_task_funded(legacy_task_reconcile_fixture, hold_id)
    config = _config(tmp_path)
    _write_grandfather_file(
        config,
        f"# migration exception\n{_grandfather_line(legacy_task_reconcile_fixture, hold_id)}"
        "  # verified hold\n",
    )
    _write_key(config.signing_key)

    envelope, _ = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        config,
        notify=lambda *_: {"attempted": False},
    ).run()
    report = envelope["report"]

    assert report["outcome"] == "match", report
    assert report["grandfathered_task_holds"] == {
        "ids": [hold_id],
        "amounts": [{"hold_id": hold_id, "credits": 80}],
        "total_credits": 80,
    }


@pytest.mark.parametrize("entry", ["missing", "already_matches"])
def test_stale_grandfather_entry_is_a_mismatch(
    tmp_path, legacy_task_reconcile_fixture, entry
):
    if entry == "missing":
        hold_id = "f" * 32
    else:
        hold_id = _paid_task_id(legacy_task_reconcile_fixture, 1)
    config = _config(tmp_path)
    if entry == "missing":
        line = f"{hold_id} 1 missing-payer missing-worker"
    else:
        line = _grandfather_line(legacy_task_reconcile_fixture, hold_id)
    _write_grandfather_file(config, line + "\n")

    report = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        config,
    ).collect()

    assert report["outcome"] == "mismatch"
    assert any(
        "grandfather list entry" in error
        for error in _check(report, "economic_receipt_view")["errors"]
    )


@pytest.mark.parametrize("field", ["amount", "payer", "worker"])
def test_grandfather_entry_must_match_all_hold_fields(
    tmp_path, legacy_task_reconcile_fixture, field
):
    hold_id = _paid_task_id(legacy_task_reconcile_fixture, 0)
    _flip_task_funded(legacy_task_reconcile_fixture, hold_id)
    line = _grandfather_line(legacy_task_reconcile_fixture, hold_id).split()
    line[{"amount": 1, "payer": 2, "worker": 3}[field]] = {
        "amount": "81", "payer": "wrong-payer", "worker": "wrong-worker",
    }[field]
    config = _config(tmp_path)
    _write_grandfather_file(config, " ".join(line) + "\n")

    report = Reconciler(
        legacy_task_reconcile_fixture, FakeReconcileRPC({VAULT: 100}), config
    ).collect()
    assert report["outcome"] == "mismatch"
    assert any(
        "grandfather list entry" in error
        for error in _check(report, "economic_receipt_view")["errors"]
    )


@pytest.mark.parametrize(
    "mutation", ["funded_flip", "payment_detail", "leftover_escrow"]
)
def test_task_cashability_tampering_is_a_mismatch(
    tmp_path, legacy_task_reconcile_fixture, mutation
):
    with sqlite3.connect(legacy_task_reconcile_fixture) as db:
        db.row_factory = sqlite3.Row
        hold = db.execute(
            "SELECT * FROM task_holds WHERE state='paid' AND funded=0"
        ).fetchone()
        if mutation == "funded_flip":
            db.execute("DROP TRIGGER task_holds_snapshots_immutable")
            db.execute(
                "UPDATE task_holds SET funded=1 WHERE hold_id=?", (hold["hold_id"],)
            )
        elif mutation == "payment_detail":
            db.execute(
                "UPDATE journal SET detail=? WHERE receipt_id=?",
                ('{"hold_id":"wrong"}', f"task-pay:{hold['hold_id']}"),
            )
        else:
            db.execute(
                "UPDATE accounts SET balance=balance+1 WHERE id=?",
                (hold["escrow_account"],),
            )
            db.execute(
                "UPDATE accounts SET balance=balance-1 WHERE id=?",
                (hold["worker_account"],),
            )

    report = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        _config(tmp_path),
    ).collect()
    view = _check(report, "economic_receipt_view")
    assert report["outcome"] == "mismatch"
    assert view["ok"] is False
    if mutation == "funded_flip":
        assert any("stored task funding differs" in error for error in view["errors"])
    else:
        assert any("exact payment provenance" in error for error in view["errors"])


def test_task_authorization_journal_is_verified(
    tmp_path, legacy_task_reconcile_fixture
):
    hold_id = _paid_task_id(legacy_task_reconcile_fixture, 0)
    with sqlite3.connect(legacy_task_reconcile_fixture) as db:
        db.execute(
            "UPDATE journal SET detail=? WHERE receipt_id=?",
            ('{"hold_id":"wrong"}', f"task-authorize:{hold_id}"),
        )

    report = Reconciler(
        legacy_task_reconcile_fixture,
        FakeReconcileRPC({VAULT: 100}),
        _config(tmp_path),
    ).collect()
    assert report["outcome"] == "mismatch"
    assert any(
        "authorization journal provenance" in error
        for error in _check(report, "economic_receipt_view")["errors"]
    )


@pytest.mark.parametrize(
    "unsafe", ["symlink", "world_writable", "writable_parent", "wrong_owner"]
)
def test_grandfather_file_must_be_operator_safe(
    tmp_path, legacy_task_reconcile_fixture, unsafe, monkeypatch
):
    config = _config(tmp_path)
    target = tmp_path / "grandfather-target.txt"
    target.write_text("# empty\n", encoding="ascii")
    if unsafe == "symlink":
        config.grandfathered_holds_file.symlink_to(target)
    else:
        config.grandfathered_holds_file.write_text("# empty\n", encoding="ascii")
        config.grandfathered_holds_file.chmod(0o600)
        if unsafe == "world_writable":
            config.grandfathered_holds_file.chmod(0o666)
        elif unsafe == "writable_parent":
            tmp_path.chmod(0o777)
        elif unsafe == "wrong_owner":
            monkeypatch.setattr(os, "getuid", lambda: os.stat(target).st_uid + 1)

    with pytest.raises(ReconcileError, match="grandfathered task hold"):
        Reconciler(
            legacy_task_reconcile_fixture,
            FakeReconcileRPC({VAULT: 100}),
            config,
        ).collect()


@pytest.mark.parametrize("seed", range(8))
def test_seeded_funding_replay_matches_authorization_snapshots(tmp_path, seed):
    """Cross-check the independent replay against real authorization decisions."""
    rng = random.Random(seed)
    seed_dir = tmp_path / f"history-{seed}"
    seed_dir.mkdir()
    path = seed_dir / "ledger.sqlite"
    clock = [8_000_000 + seed * 100_000]
    with LedgerStore(path, clock=lambda: clock[0]) as store:
        store._db.execute(
            "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
            "VALUES ('bank', ?, 1)", (VAULT,),
        )
        deposit = 20_000 + rng.randrange(5_000)
        store.deposit_batch("bank", VAULT, [(f"deposit-{seed}", deposit, seed)], deposit)

        # Transfers and starter grants increase balance but never entitlement.
        store.transfer("bank", "transfer-payer", 300 + rng.randrange(100), "self")
        store.grant_starter(
            f"invite-{seed}", "bank", "starter-payer", f"starter-key-{seed}",
            100 + rng.randrange(50), "self", "known",
        )
        for label, payer in (
            ("transfer", "transfer-payer"), ("starter", "starter-payer")
        ):
            result = store.authorize_task_hold(
                payer_keyid=f"{label}-key-{seed}", payer_account=payer, tier="self",
                client_nonce=f"{label}-{seed}",
                task_hash=("1" if label == "transfer" else "2") * 64,
                worker_keyid=f"{label}-worker-key-{seed}",
                worker_account=f"{label}-worker-{seed}", amount=50,
                deadline=clock[0] + 60,
            )
            assert result["funded"] == 0

        # A funded task earning is not backing until strictly after maturity.
        earning = store.authorize_task_hold(
            payer_keyid=f"bank-key-{seed}", payer_account="bank", tier="self",
            client_nonce=f"earning-{seed}", task_hash="3" * 64,
            worker_keyid=f"earner-key-{seed}", worker_account=f"earner-{seed}",
            amount=200 + rng.randrange(50), deadline=clock[0] + 60,
        )
        store.pay_task_hold(earning["hold_id"], f"bank-key-{seed}")
        before_maturity = store.authorize_task_hold(
            payer_keyid=f"earner-key-{seed}", payer_account=f"earner-{seed}", tier="self",
            client_nonce=f"unmatured-{seed}", task_hash="4" * 64,
            worker_keyid=f"early-worker-key-{seed}", worker_account=f"early-worker-{seed}",
            amount=40, deadline=clock[0] + 60,
        )
        assert before_maturity["funded"] == 0
        clock[0] += HOLD_S + 1
        after_maturity = store.authorize_task_hold(
            payer_keyid=f"earner-key-{seed}", payer_account=f"earner-{seed}", tier="self",
            client_nonce=f"matured-{seed}", task_hash="5" * 64,
            worker_keyid=f"late-worker-key-{seed}", worker_account=f"late-worker-{seed}",
            amount=40, deadline=clock[0] + 60,
        )
        assert after_maturity["funded"] == 1

        # Refunded holds restore both balance and unconsumed entitlement.
        refundable = store.authorize_task_hold(
            payer_keyid=f"bank-key-{seed}", payer_account="bank", tier="self",
            client_nonce=f"refund-{seed}", task_hash="6" * 64,
            worker_keyid=f"refund-worker-key-{seed}", worker_account=f"refund-worker-{seed}",
            amount=150 + rng.randrange(50), deadline=clock[0] + 60,
        )
        store.refund_task_hold(
            refundable["hold_id"], f"bank-key-{seed}", "operator_refund"
        )

        # Pending and released withdrawal holds exercise both historical states.
        withdrawal_id = store.withdraw_hold(
            "bank", 100 + rng.randrange(50), f"address-{seed}", f"withdrawal-{seed}"
        )
        store.authorize_task_hold(
            payer_keyid=f"bank-key-{seed}", payer_account="bank", tier="self",
            client_nonce=f"held-withdrawal-{seed}", task_hash="7" * 64,
            worker_keyid=f"held-worker-key-{seed}", worker_account=f"held-worker-{seed}",
            amount=30, deadline=clock[0] + 60,
        )
        store.withdraw_release(withdrawal_id)

        # Mature legacy and v2 earnings cover all three funded earning namespaces.
        store.settle(
            f"legacy-{seed}", "bank", {f"legacy-earner-{seed}": 120}, 120, "self"
        )
        v2 = _authorize(
            store, payer_account="bank", nonce=f"v2-{seed}", session=f"v2-{seed}",
            tokens=20, worker_label=f"v2-worker-{seed}",
            worker_account=f"v2-earner-{seed}",
        )
        _claim(store, v2["hold_id"], worker_label=f"v2-worker-{seed}")
        _settle(
            store,
            _receipt(
                store, v2["hold_id"], 5, 5, final=True,
                worker_label=f"v2-worker-{seed}",
            ),
            relayer=_public(f"v2-worker-{seed}"),
        )
        clock[0] += HOLD_S + 1
        for namespace, payer in (
            ("legacy", f"legacy-earner-{seed}"),
            ("v2", f"v2-earner-{seed}"),
        ):
            matured = store.authorize_task_hold(
                payer_keyid=f"{namespace}-payer-key-{seed}", payer_account=payer,
                tier="self", client_nonce=f"{namespace}-matured-{seed}",
                task_hash=("8" if namespace == "legacy" else "9") * 64,
                worker_keyid=f"{namespace}-worker-key-{seed}",
                worker_account=f"{namespace}-worker-{seed}", amount=20,
                deadline=clock[0] + 60,
            )
            assert matured["funded"] == 1

    reconciler = Reconciler(path, FakeReconcileRPC({VAULT: deposit // 100}), _config(seed_dir))
    ledger = reconciler._ledger_snapshot()
    holds = {row["hold_id"]: row for row in ledger["task_holds"]}
    authorization_debits = [
        row for row in ledger["journal"] if row["kind"] == "task_authorize_debit"
    ]
    assert len(authorization_debits) >= 9
    for debit in authorization_debits:
        hold_id = debit["receipt_id"].removeprefix("task-authorize:")
        hold = holds[hold_id]
        replayed = _replay_funding_backed_balance(
            ledger, hold["payer_account"], int(debit["seq"]), int(hold["authorized_at"])
        )
        assert int(replayed >= int(hold["amount"])) == int(hold["funded"]), (
            seed, hold_id, replayed, hold["amount"], hold["funded"]
        )


LIVE_LEDGER = Path(
    "/tmp/claude-1000/-home-prithvi-trisul/"
    "61bd987d-366b-47a9-a50b-3114778d4416/scratchpad/s9/live-copy.sqlite"
)
LIVE_GRANDFATHERED_TASK_HOLDS = {
    "18651685cf2b43f297a6e23d0d41f19f": (200_000, "op-3ac68dc17064d7ab", "op-686a9540"),
    "7e50341708194104a981e41c8669534d": (15_000_000, "self", "op-686a9540"),
    "9786afd19ca14d5fa2a55374cdbdfe12": (1_000, "self", "op-686a9540"),
    "dfdf065ca1d445689a4d83cf06846e6f": (20_000_000, "self", "op-686a9540"),
}


@pytest.mark.skipif(not LIVE_LEDGER.is_file(), reason="review ledger is unavailable")
def test_live_copy_requires_exact_grandfather_list(tmp_path):
    copied = tmp_path / "live-copy.sqlite"
    shutil.copy2(LIVE_LEDGER, copied)
    config = _config(tmp_path)

    without = Reconciler(
        copied, FakeReconcileRPC({VAULT: 0}), config
    ).collect()
    assert without["outcome"] == "mismatch"
    funding_errors = [
        error for error in _check(without, "economic_receipt_view")["errors"]
        if "stored task funding differs" in error
    ]
    assert len(funding_errors) == 4

    _write_grandfather_file(
        config,
        "\n".join(
            f"{hold_id} {amount} {payer} {worker}"
            for hold_id, (amount, payer, worker)
            in LIVE_GRANDFATHERED_TASK_HOLDS.items()
        ) + "\n",
    )
    with_exact = Reconciler(
        copied, FakeReconcileRPC({VAULT: 0}), config
    ).collect()
    assert with_exact["outcome"] == "match", with_exact
    section = with_exact["grandfathered_task_holds"]
    assert section["ids"] == sorted(LIVE_GRANDFATHERED_TASK_HOLDS)
    assert section["total_credits"] == 35_201_000

    _write_grandfather_file(
        config, f"{'f' * 32} 1 missing-payer missing-worker\n"
    )
    wrong = Reconciler(copied, FakeReconcileRPC({VAULT: 0}), config).collect()
    assert wrong["outcome"] == "mismatch"


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


def test_orphan_mature_v2_economic_row_is_not_withdrawable_and_kills_s6(tmp_path):
    path = tmp_path / "orphan-v2-economic.sqlite"
    store, hold = _seed_reconcilable_spend(path)
    try:
        terminal = int(store.spend_status(hold["hold_id"])["terminal_at"])
        store._clock = lambda: terminal
        assert store.withdrawable("worker") == 0

        fabricated_id = "sha256:" + "f" * 64
        store._db.execute("PRAGMA foreign_keys=OFF")
        store._db.execute(
            "INSERT INTO spend_economic_receipts("
            "receipt_id, hold_id, payer_account, worker_account, amount, funded, "
            "earned_at, hold_terminal_at, matures_at, dispute_state, "
            "debit_journal_seq, credit_journal_seq) "
            "VALUES (?, ?, 'payer', 'worker', 8, 1, ?, ?, ?, 'none', NULL, NULL)",
            (fabricated_id, hold["hold_id"], terminal - HOLD_S - 1,
             terminal - HOLD_S - 1, terminal - 1),
        )

        # The fabricated mature row has enough value to unlock the worker's
        # whole balance under the old economic-view-only calculation.
        assert store.balance("worker") == 8
        assert store.withdrawable("worker") == 0
    finally:
        store.close()

    report = _run_s6_and_assert_kill(path, tmp_path)
    view = _check(report, "economic_receipt_view")
    assert view["ok"] is False
    assert any("bidirectionally match" in error for error in view["errors"])
    assert any(fabricated_id in error for error in view["errors"])


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


def test_legacy_10k_earnings_withdrawable_and_s6_are_bounded(tmp_path):
    path = tmp_path / "legacy-ten-thousand.sqlite"
    clock = [7_000_000]
    with LedgerStore(path, clock=lambda: clock[0]) as store:
        store._db.execute(
            "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
            "VALUES ('payer', ?, 1)",
            (VAULT,),
        )
        store.deposit_batch("payer", VAULT, [("funding", 10_000, 1)], 10_000)
        for sequence in range(10_000):
            store.settle(
                f"legacy-earning-{sequence}", "payer", {"worker": 1}, 1, "self"
            )
        clock[0] += HOLD_S

        started = time.perf_counter()
        assert store.withdrawable("worker") == 10_000
        withdrawable_elapsed = time.perf_counter() - started

    started = time.perf_counter()
    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 100}), _config(tmp_path)
    ).collect()
    s6_elapsed = time.perf_counter() - started

    assert report["outcome"] == "match"
    assert withdrawable_elapsed < 2.0, (
        f"10k legacy withdrawable took {withdrawable_elapsed:.3f}s"
    )
    assert s6_elapsed < 5.0, f"10k legacy S6 took {s6_elapsed:.3f}s"
