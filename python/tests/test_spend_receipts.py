"""N2 strict usage receipts, maturity, shared economics, and S6 mutations."""
import hashlib
import json
import os
import sys

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
