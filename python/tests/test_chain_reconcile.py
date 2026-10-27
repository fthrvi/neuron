"""Adversarial unit coverage for S6 reconciliation invariants."""
import json
import os
import sqlite3
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chain.reconcile import (  # noqa: E402
    REPORT_PURPOSE,
    REPORT_SCHEME,
    ReconcileConfig,
    ReconcileError,
    Reconciler,
    sign_report,
    verify_report,
)
from core.ledger_store import RATE, LedgerStore  # noqa: E402


FIXTURE = Path(__file__).parent / "fixtures" / "solana_indexer.json"
ADDRESSES = json.loads(FIXTURE.read_text())["addresses"]
MINT = ADDRESSES["mint"]
VAULT = ADDRESSES["deposit"]
SECOND_ACCOUNT = ADDRESSES["source"]
OWNER = ADDRESSES["other_mint"]


class FakeReconcileRPC:
    def __init__(self, amounts, *, snapshots=None, statuses=None, transactions=None):
        self.amounts = dict(amounts)
        self.snapshots = list(snapshots or [])
        self.statuses = statuses or {}
        self.transactions = transactions or {}
        self.calls = []
        self.slot = 100
        self.height = 100

    def get_genesis_hash(self):
        self.calls.append(("genesis",))
        return MINT

    def get_token_accounts(self, addresses):
        self.calls.append(("accounts", tuple(addresses)))
        amounts = self.snapshots.pop(0) if self.snapshots else self.amounts
        self.slot += 1
        return {
            "slot": self.slot,
            "accounts": [
                {
                    "token_account": address,
                    "mint": MINT,
                    "amount": amounts[address],
                    "decimals": 6,
                    "owner": OWNER,
                }
                for address in addresses
            ],
        }

    def get_signature_statuses(self, signatures):
        self.calls.append(("statuses", tuple(signatures)))
        return {signature: deepcopy(self.statuses.get(signature)) for signature in signatures}

    def get_block_height(self):
        self.calls.append(("height",))
        return self.height

    def get_transaction(self, signature):
        self.calls.append(("transaction", signature))
        return deepcopy(self.transactions.get(signature))


def _write_key(path):
    private = ed25519.Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _config(tmp_path, **changes):
    values = {
        "cluster": "localnet",
        "mint": MINT,
        "rpc_url": "http://127.0.0.1:18899",
        "vault_account": VAULT,
        "report_dir": tmp_path / "reports",
        "kill_file": tmp_path / "payout.off",
        "signing_key": tmp_path / "worker.ed25519",
        "buzz_helper": None,
        "snapshot_attempts": 1,
        "snapshot_retry_delay_s": 0,
    }
    values.update(changes)
    return ReconcileConfig(**values)


def _ledger(path, deposits=(("alice", VAULT, "deposit-a", 100),)):
    store = LedgerStore(path)
    store._db.execute(
        "CREATE TABLE chain_indexer_accounts "
        "(token_account TEXT PRIMARY KEY, cursor TEXT, "
        "paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0, 1)), "
        "updated_ts INTEGER NOT NULL)"
    )
    for operator, token_account, ref, micro_usdc in deposits:
        store._db.execute(
            "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
            "VALUES (?, ?, 1)",
            (operator, token_account),
        )
        store._db.execute(
            "INSERT OR IGNORE INTO chain_indexer_accounts"
            "(token_account, cursor, updated_ts) VALUES (?, ?, 1)",
            (token_account, ref),
        )
        store.deposit_batch(
            operator,
            token_account,
            [(ref, micro_usdc * RATE, 10)],
            micro_usdc * RATE,
        )
    return store


def _check(report, check_id):
    return next(check for check in report["checks"] if check["id"] == check_id)


def _sweep_transaction(source, destination, amount_micro):
    return {
        "slot": 20,
        "transaction": {
            "signatures": ["sweep-signature"],
            "message": {
                "accountKeys": [],
                "instructions": [
                    {
                        "program": "spl-token",
                        "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                        "parsed": {
                            "type": "transferChecked",
                            "info": {
                                "source": source,
                                "destination": destination,
                                "mint": MINT,
                                "tokenAmount": {
                                    "amount": str(amount_micro),
                                    "decimals": 6,
                                },
                            },
                        },
                    }
                ],
            },
        },
        "meta": {"err": None, "innerInstructions": []},
    }


def test_read_only_snapshot_and_batched_stable_collection(tmp_path):
    path = tmp_path / "ledger.sqlite"
    with _ledger(path) as store:
        before_rows = store._db.execute("SELECT COUNT(*) FROM journal").fetchone()[0]
    before_mtime = path.stat().st_mtime_ns
    rpc = FakeReconcileRPC({VAULT: 100})

    report = Reconciler(path, rpc, _config(tmp_path)).collect()

    assert report["outcome"] == "match"
    assert report["snapshot"]["balance_rpc"] == "getMultipleAccounts"
    assert [call[0] for call in rpc.calls] == [
        "genesis",
        "accounts",
        "statuses",
        "accounts",
    ]
    assert rpc.calls[1][1] == (VAULT,)
    assert rpc.calls[3][1] == (VAULT,)
    assert path.stat().st_mtime_ns == before_mtime
    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as db:
        assert db.execute("SELECT COUNT(*) FROM journal").fetchone()[0] == before_rows


def test_finalized_sweep_moves_expectation_to_vault_without_changing_backing(tmp_path):
    path = tmp_path / "swept.sqlite"
    with _ledger(path, (("alice", SECOND_ACCOUNT, "deposit-a", 100),)) as store:
        store.begin_sweep(
            "sweep-a", "alice", SECOND_ACCOUNT, 100,
            "sweep-signature", "blockhash", 100,
        )
        store.finalize_sweep("sweep-a")
    status = {"err": None, "confirmationStatus": "finalized"}
    rpc = FakeReconcileRPC(
        {VAULT: 100, SECOND_ACCOUNT: 0},
        statuses={"sweep-signature": status},
        transactions={
            "sweep-signature": _sweep_transaction(SECOND_ACCOUNT, VAULT, 100)
        },
    )
    report = Reconciler(path, rpc, _config(tmp_path)).collect()
    assert report["outcome"] == "match"
    assert _check(report, "chain_sweeps")["ok"] is True
    assert _check(report, "treasury_backing")["ok"] is True
    assert report["chain_sweep_summary"]["verified_credits"] == 100 * RATE
    assert rpc.calls[2] == ("statuses", ("sweep-signature",))


@pytest.mark.parametrize("bad_proof", ["missing", "wrong_source"])
def test_finalized_sweep_requires_matching_chain_proof(tmp_path, bad_proof):
    path = tmp_path / f"sweep-{bad_proof}.sqlite"
    with _ledger(path, (("alice", SECOND_ACCOUNT, "deposit-a", 100),)) as store:
        store.begin_sweep(
            "sweep-a", "alice", SECOND_ACCOUNT, 100,
            "sweep-signature", "blockhash", 100,
        )
        store.finalize_sweep("sweep-a")
    status = {"err": None, "confirmationStatus": "finalized"}
    transaction = None
    if bad_proof == "wrong_source":
        transaction = _sweep_transaction(VAULT, VAULT, 100)
    rpc = FakeReconcileRPC(
        {VAULT: 100, SECOND_ACCOUNT: 0},
        statuses={"sweep-signature": status},
        transactions={"sweep-signature": transaction},
    )
    report = Reconciler(path, rpc, _config(tmp_path)).collect()
    assert report["outcome"] == "mismatch"
    assert _check(report, "chain_sweeps")["ok"] is False


def test_stale_in_flight_sweep_fails_check_and_fires_kill_alert(tmp_path):
    path = tmp_path / "stale-sweep.sqlite"
    with _ledger(path, (("alice", SECOND_ACCOUNT, "deposit-a", 100),)) as store:
        store.begin_sweep(
            "sweep-stale", "alice", SECOND_ACCOUNT, 100,
            "sweep-signature", "blockhash", 100,
        )
    status = {"err": None, "confirmationStatus": "confirmed"}
    rpc = FakeReconcileRPC(
        {VAULT: 0, SECOND_ACCOUNT: 100},
        statuses={"sweep-signature": status},
    )
    rpc.height = 104
    cfg = _config(tmp_path, sweep_stale_blocks=3)
    _write_key(cfg.signing_key)

    envelope, _report_path = Reconciler(path, rpc, cfg).run()

    report = envelope["report"]
    sweep_check = _check(report, "chain_sweeps")
    assert report["outcome"] == "mismatch"
    assert sweep_check["ok"] is False
    assert sweep_check["errors"] == ["stale in-flight sweep sweep-stale"]
    assert cfg.kill_file.is_file()
    assert report["alerts"][0]["event"] == "nak_reconcile_mismatch"
    assert "chain_sweeps" in report["alerts"][0]["failed_checks"]


@pytest.mark.parametrize(
    ("status", "amounts", "transactions", "expected_error"),
    [
        (
            {
                "err": {"InstructionError": [0, "Custom"]},
                "confirmationStatus": "finalized",
            },
            {VAULT: 0, SECOND_ACCOUNT: 100},
            {},
            "sent sweep sweep-stale finalized with an error",
        ),
        (
            {"err": None, "confirmationStatus": "finalized"},
            {VAULT: 100, SECOND_ACCOUNT: 0},
            {
                "sweep-signature": _sweep_transaction(
                    SECOND_ACCOUNT, VAULT, 100
                )
            },
            "stale in-flight sweep sweep-stale",
        ),
    ],
)
def test_finalized_sent_sweep_is_a_worker_health_mismatch(
    tmp_path, status, amounts, transactions, expected_error
):
    path = tmp_path / "finalized-sent.sqlite"
    with _ledger(path, (("alice", SECOND_ACCOUNT, "deposit-a", 100),)) as store:
        store.begin_sweep(
            "sweep-stale", "alice", SECOND_ACCOUNT, 100,
            "sweep-signature", "blockhash", 100,
        )
    rpc = FakeReconcileRPC(
        amounts,
        statuses={"sweep-signature": status},
        transactions=transactions,
    )
    rpc.height = 104

    report = Reconciler(
        path, rpc, _config(tmp_path, sweep_stale_blocks=3)
    ).collect()

    assert report["outcome"] == "mismatch"
    assert expected_error in _check(report, "chain_sweeps")["errors"]


def test_transient_chain_change_retries_without_mismatch(tmp_path):
    path = tmp_path / "ledger.sqlite"
    with _ledger(path):
        pass
    rpc = FakeReconcileRPC(
        {VAULT: 100},
        snapshots=[{VAULT: 100}, {VAULT: 101}, {VAULT: 100}, {VAULT: 100}],
    )
    config = _config(tmp_path, snapshot_attempts=2)

    report = Reconciler(path, rpc, config).collect()

    assert report["outcome"] == "match"
    assert report["snapshot"]["attempt"] == 2
    assert len([call for call in rpc.calls if call[0] == "accounts"]) == 4


def test_repeated_indexer_lag_is_inconclusive_then_kills(tmp_path):
    path = tmp_path / "ledger.sqlite"
    with _ledger(path):
        pass
    _write_key(tmp_path / "worker.ed25519")
    config = _config(tmp_path, inconclusive_kill_runs=3)

    for expected_count in (1, 2, 3):
        rpc = FakeReconcileRPC({VAULT: 101})
        envelope, _ = Reconciler(
            path, rpc, config, notify=lambda *_: {"attempted": False}
        ).run()
        report = envelope["report"]
        assert report["outcome"] == "inconclusive"
        assert report["consecutive_inconclusive_runs"] == expected_count
        assert (tmp_path / "payout.off").exists() is (expected_count == 3)


def test_deposit_deficit_with_vault_excess_is_mismatch_and_kills(tmp_path):
    path = tmp_path / "deficit-plus-excess.sqlite"
    with _ledger(path, (("alice", SECOND_ACCOUNT, "deposit-a", 100),)) as store:
        store.begin_sweep(
            "failed-sweep", "alice", SECOND_ACCOUNT, 100,
            "failed-signature", "blockhash", 100,
        )
        store.fail_sweep("failed-sweep")
    config = _config(tmp_path)
    _write_key(config.signing_key)
    rpc = FakeReconcileRPC({SECOND_ACCOUNT: 0, VAULT: 100})

    envelope, _ = Reconciler(
        path, rpc, config, notify=lambda *_: {"attempted": False}
    ).run()

    report = envelope["report"]
    assert report["outcome"] == "mismatch"
    assert report["snapshot"]["stable"] is True
    assert config.kill_file.is_file()
    assert report["alerts"][0]["event"] == "nak_reconcile_mismatch"
    provenance = _check(report, "deposit_provenance")
    assert any("exceed chain balance" in error for error in provenance["errors"])


def test_missing_ledger_fails_closed_and_replaces_kill_symlink(tmp_path):
    key = tmp_path / "worker.ed25519"
    _write_key(key)
    target = tmp_path / "not-a-kill-file"
    kill = tmp_path / "payout.off"
    kill.symlink_to(target)
    config = _config(tmp_path)

    rpc = FakeReconcileRPC({VAULT: 0})
    with pytest.raises(ReconcileError, match="ledger does not exist"):
        Reconciler(
            tmp_path / "missing.sqlite",
            rpc,
            config,
            notify=lambda *_: {"attempted": False},
        ).run()

    assert not (tmp_path / "missing.sqlite").exists()
    assert rpc.calls == []
    assert kill.is_file()
    assert not kill.is_symlink()
    alert = json.loads((tmp_path / "reports" / "alerts.jsonl").read_text())
    assert alert["event"] == "nak_reconcile_collection_error"


@pytest.mark.parametrize("corruption", ["approved_without_hold", "released_without_return"])
def test_all_withdrawal_states_require_exact_hold_lifecycle(tmp_path, corruption):
    path = tmp_path / f"{corruption}.sqlite"
    amount = 25 * RATE
    with _ledger(path) as store:
        store.withdraw_hold("alice", amount, OWNER, "withdrawal-a")
        if corruption == "approved_without_hold":
            store.withdraw_approve("withdrawal-a", "human:test")
        else:
            store.withdraw_release("withdrawal-a")
        # Preserve zero-sum while recreating the reviewer's corrupted state.
        direction = 1 if corruption == "approved_without_hold" else -1
        store._db.execute(
            "UPDATE accounts SET balance=balance+? WHERE id='alice'",
            (direction * amount,),
        )
        store._db.execute(
            "UPDATE accounts SET balance=balance-? WHERE id=?",
            (direction * amount, "__withdrawal_hold__:withdrawal-a"),
        )

    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 100}), _config(tmp_path)
    ).collect()
    assert report["outcome"] == "mismatch"
    lifecycle = _check(report, "withdrawal_lifecycle")
    assert lifecycle["ok"] is False
    assert any("hold balance" in error for error in lifecycle["errors"])


def test_pending_approved_sent_expired_released_lifecycle_states(tmp_path):
    path = tmp_path / "lifecycle.sqlite"
    amount = 25 * RATE
    store = _ledger(path)
    try:
        store.withdraw_hold("alice", amount, OWNER, "withdrawal-a")

        def assert_match():
            report = Reconciler(
                path, FakeReconcileRPC({VAULT: 100}), _config(tmp_path)
            ).collect()
            assert report["outcome"] == "match"
            assert _check(report, "withdrawal_lifecycle")["ok"] is True

        assert_match()
        store.withdraw_approve("withdrawal-a", "human:test")
        assert_match()
        store.withdraw_mark_sent(
            "withdrawal-a", "signature-a", "blockhash-a", 1000, "wire-a"
        )
        assert_match()
        store.withdraw_mark_expired("withdrawal-a")
        assert_match()
        store.withdraw_release("withdrawal-a")
        assert_match()
    finally:
        store.close()


def test_swapped_deposit_refs_fail_per_ref_provenance(tmp_path):
    path = tmp_path / "swapped.sqlite"
    deposits = (
        ("alice", VAULT, "deposit-a", 100),
        ("bob", SECOND_ACCOUNT, "deposit-b", 100),
    )
    with _ledger(path, deposits) as store:
        store._db.execute("DROP TRIGGER journal_no_update")
        rows = store._db.execute(
            "SELECT seq, detail FROM journal WHERE kind='deposit' ORDER BY seq"
        ).fetchall()
        first = json.loads(rows[0]["detail"])
        second = json.loads(rows[1]["detail"])
        first["ref"], second["ref"] = second["ref"], first["ref"]
        store._db.execute(
            "UPDATE journal SET detail=? WHERE seq=?",
            (json.dumps(first, sort_keys=True, separators=(",", ":")), rows[0]["seq"]),
        )
        store._db.execute(
            "UPDATE journal SET detail=? WHERE seq=?",
            (json.dumps(second, sort_keys=True, separators=(",", ":")), rows[1]["seq"]),
        )

    report = Reconciler(
        path,
        FakeReconcileRPC({VAULT: 100, SECOND_ACCOUNT: 100}),
        _config(tmp_path),
    ).collect()
    provenance = _check(report, "deposit_provenance")
    assert provenance["ok"] is False
    assert provenance["chain_ref_credits"] == provenance["journal_credits"]


def test_chain_drain_and_compensating_ledger_edit_still_mismatches(tmp_path):
    path = tmp_path / "drain.sqlite"
    drained = 10 * RATE
    with _ledger(path) as store:
        store._db.execute(
            "UPDATE accounts SET balance=balance+? WHERE id='treasury'", (drained,)
        )
        store._db.execute(
            "UPDATE accounts SET balance=balance-? WHERE id='alice'", (drained,)
        )
        store._db.execute(
            "INSERT INTO journal(ts, kind, account, counterparty, amount, detail) "
            "VALUES (1, 'withdraw', 'treasury', 'alice', ?, '{}')",
            (drained,),
        )

    report = Reconciler(
        path, FakeReconcileRPC({VAULT: 90}), _config(tmp_path)
    ).collect()
    assert report["outcome"] == "mismatch"
    assert _check(report, "zero_sum_balances")["ok"] is True
    backing = _check(report, "treasury_backing")
    assert backing["left_credits"] == backing["right_credits"]
    assert _check(report, "deposit_provenance")["ok"] is False
    treasury = _check(report, "treasury_provenance")
    assert treasury["ok"] is False
    assert any("no finalized proof" in error for error in treasury["errors"])


def test_report_verification_requires_pinned_key_scheme_and_purpose(tmp_path):
    hub_key = tmp_path / "hub.ed25519"
    attacker_key = tmp_path / "attacker.ed25519"
    hub_public = _write_key(hub_key)
    attacker_public = _write_key(attacker_key)
    report = {
        "date": "2026-10-14",
        "generated_at_unix": 1,
        "signature_contract": {
            "scheme": REPORT_SCHEME,
            "purpose": REPORT_PURPOSE,
        },
    }
    envelope = sign_report(report, attacker_key)

    assert verify_report(envelope, None) is False
    assert verify_report(envelope, hub_public) is False
    assert verify_report(envelope, attacker_public) is True
    forged = deepcopy(envelope)
    forged["report"]["signature_contract"]["purpose"] = "something-else"
    assert verify_report(forged, attacker_public) is False



def test_unwritable_inconclusive_counter_fails_closed(tmp_path):
    # Reviewer's counterexample: the streak file is a directory, so reading/writing it fails every run.
    # That failure must itself turn payouts off instead of silently keeping a real problem un-killed.
    path = tmp_path / "ledger.sqlite"
    with _ledger(path):
        pass
    _write_key(tmp_path / "worker.ed25519")
    config = _config(tmp_path, inconclusive_kill_runs=3)
    config.report_dir.mkdir(parents=True, exist_ok=True)
    (config.report_dir / ".inconclusive-state.json").mkdir()

    rpc = FakeReconcileRPC({VAULT: 101})   # the same lag that makes a run inconclusive above
    with pytest.raises(Exception):
        Reconciler(path, rpc, config, notify=lambda *_: {"attempted": False}).run()
    assert (tmp_path / "payout.off").is_file()
    assert "nak_reconcile_post_collection_error" in (config.report_dir / "alerts.jsonl").read_text()


def test_corrupt_inconclusive_counter_fails_closed(tmp_path):
    path = tmp_path / "ledger.sqlite"
    with _ledger(path):
        pass
    _write_key(tmp_path / "worker.ed25519")
    config = _config(tmp_path, inconclusive_kill_runs=3)
    config.report_dir.mkdir(parents=True, exist_ok=True)
    (config.report_dir / ".inconclusive-state.json").write_text('{"consecutive": "lots"}')

    rpc = FakeReconcileRPC({VAULT: 101})
    with pytest.raises(Exception):
        Reconciler(path, rpc, config, notify=lambda *_: {"attempted": False}).run()
    assert (tmp_path / "payout.off").is_file()
