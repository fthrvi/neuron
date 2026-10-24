"""Unit tests for the fail-closed treasury payout state machine."""
import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.token import ID as TOKEN_PROGRAM_ID
from solders.token.associated import get_associated_token_address
from solders.transaction import Transaction

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chain.indexer import DEVNET_GENESIS_HASH  # noqa: E402
from chain.payout import (  # noqa: E402
    MICRO_USDC,
    PayoutError,
    PayoutConfig,
    PayoutEngine,
    PayoutProcessLock,
    SignedTransaction,
    SoldersTreasuryBackend,
)
import core.ledger_store as ledger_store_module  # noqa: E402
from core.ledger_store import (  # noqa: E402
    HOLD_S,
    RATE,
    CreditLimitError,
    LedgerStore,
    WithdrawalStateError,
)


MINT = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
VAULT_ACCOUNT = "11111111111111111111111111111111"
RECIPIENT = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
RECIPIENT_ATA = "SysvarRent111111111111111111111111111111111"
BLOCKHASHES = [
    "SysvarC1ock11111111111111111111111111111111",
    "SysvarRecentB1ockHashes11111111111111111111",
    "SysvarS1otHashes111111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111",
]


def credits(usdc):
    return int(usdc * MICRO_USDC * RATE)


class FakeRPC:
    def __init__(self):
        self.height = 10
        self.blockhash_index = 0
        self.statuses = {}
        self.wire_signatures = {}
        self.broadcasts = []
        self.existing_accounts = {RECIPIENT_ATA}
        self.before_send = None
        self.status_calls = []

    def pin_genesis(self, expected=None):
        assert expected in (None, DEVNET_GENESIS_HASH)
        return DEVNET_GENESIS_HASH

    def account_exists(self, address):
        return address in self.existing_accounts

    def get_latest_blockhash(self):
        blockhash = BLOCKHASHES[self.blockhash_index]
        self.blockhash_index += 1
        return {"blockhash": blockhash, "last_valid_block_height": self.height + 2}

    def get_signature_status(self, signature):
        self.status_calls.append(signature)
        return self.statuses.get(signature)

    def get_block_height(self):
        return self.height

    def send_transaction(self, wire):
        if self.before_send is not None:
            self.before_send(wire)
        self.broadcasts.append(wire)
        return self.wire_signatures[wire]


class FakeBackend:
    def __init__(self, rpc):
        self.rpc = rpc
        self.builds = []
        self.created_atas = []
        self.deposit_accounts = []

    def recipient_ata(self, owner):
        assert owner == RECIPIENT
        return RECIPIENT_ATA

    def create_recipient_ata(self, owner, may_act):
        may_act()
        self.created_atas.append(owner)
        self.rpc.existing_accounts.add(RECIPIENT_ATA)
        return RECIPIENT_ATA

    def build_transfer(self, recipient, destination, micro_usdc, blockhash, last_valid):
        assert recipient == RECIPIENT
        attempt = len(self.builds) + 1
        signature = f"signature-{attempt}"
        wire = f"wire-{attempt}"
        self.rpc.wire_signatures[wire] = signature
        signed = SignedTransaction(signature, wire, blockhash, last_valid)
        self.builds.append((destination, micro_usdc, signed))
        return signed

    def create_deposit_account(self, may_act):
        may_act()
        account = BLOCKHASHES[len(self.deposit_accounts)]
        self.deposit_accounts.append(account)
        self.rpc.existing_accounts.add(account)
        return account


def config(tmp_path, **overrides):
    roster = tmp_path / "roster.tsv"
    if not roster.exists():
        roster.write_text("", encoding="utf-8")
    values = {
        "cluster": "localnet",
        "mint": MINT,
        "rpc_url": "http://127.0.0.1:18899",
        "vault_account": VAULT_ACCOUNT,
        "enabled": True,
        "kill_file": tmp_path / "payout.off",
        "roster_path": roster,
    }
    values.update(overrides)
    return PayoutConfig(**values)


def test_payout_config_refuses_mainnet_and_non_loopback_localnet(tmp_path):
    with pytest.raises(ValueError, match="mainnet-beta is refused"):
        config(tmp_path, cluster="mainnet-beta")
    with pytest.raises(ValueError, match="loopback"):
        config(tmp_path, rpc_url="https://rpc.example.invalid")


def held(store, amount, withdrawal_id="withdrawal-1", operator="alice"):
    store.deposit(f"deposit-{withdrawal_id}", operator, amount, 1)
    return store.withdraw_hold(operator, amount, RECIPIENT, withdrawal_id)


def row(store, withdrawal_id="withdrawal-1"):
    return dict(
        store._db.execute(
            "SELECT * FROM withdrawals WHERE id=?", (withdrawal_id,)
        ).fetchone()
    )


def test_store_payout_transitions_are_strict_and_attempts_are_durable(tmp_path):
    amount = credits(1)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, amount)
        assert store.withdraw_approve("withdrawal-1", "auto:test") == amount
        assert store.withdraw_mark_sent(
            "withdrawal-1", "sig-1", BLOCKHASHES[0], 12, "wire-1"
        ) == 1
        assert row(store)["state"] == "sent"
        assert store.withdraw_mark_expired("withdrawal-1") == 1
        assert store.withdraw_mark_sent(
            "withdrawal-1", "sig-2", BLOCKHASHES[1], 15, "wire-2"
        ) == 2
        assert store.withdraw_finalize("withdrawal-1") == amount
        assert row(store)["state"] == "finalized"
        attempts = store._db.execute(
            "SELECT attempt, tx_sig, state FROM withdrawal_attempts ORDER BY attempt"
        ).fetchall()
        assert [tuple(item) for item in attempts] == [
            (1, "sig-1", "expired"),
            (2, "sig-2", "finalized"),
        ]
        assert store.balance("alice") == 0
        assert store._db.execute(
            "SELECT COALESCE(SUM(balance), 0) FROM accounts"
        ).fetchone()[0] == 0
        with pytest.raises(WithdrawalStateError):
            store.withdraw_mark_expired("withdrawal-1")


def test_vault_secret_stays_in_memory_and_real_signature_verifies():
    loaded = []
    treasury = Keypair()
    mint = Pubkey.new_unique()
    vault = Pubkey.new_unique()
    recipient = Pubkey.new_unique()
    recipient_ata = get_associated_token_address(recipient, mint)
    blockhash = str(Hash.new_unique())

    def fake_vault(name):
        loaded.append(name)
        return treasury.to_json()

    backend = SoldersTreasuryBackend(
        FakeRPC(),
        str(mint),
        str(vault),
        secret_loader=fake_vault,
    )
    signed = backend.build_transfer(
        str(recipient), str(recipient_ata), 1, blockhash, 10
    )
    assert loaded == ["nak-treasury-secret"]
    transaction = Transaction.from_bytes(base64.b64decode(signed.wire_b64))
    assert str(transaction.signatures[0]) == signed.signature
    assert transaction.signatures[0].verify(treasury.pubkey(), bytes(transaction.message))
    assert transaction.verify_with_results() == [True]


def test_tampered_transfer_messages_are_refused():
    treasury = Keypair()
    mint = Pubkey.new_unique()
    vault = Pubkey.new_unique()
    recipient = Pubkey.new_unique()
    destination = get_associated_token_address(recipient, mint)
    blockhash = Hash.new_unique()
    backend = SoldersTreasuryBackend(
        FakeRPC(),
        str(mint),
        str(vault),
        secret_loader=lambda _name: treasury.to_json(),
    )

    def message(*, program=TOKEN_PROGRAM_ID, ix_mint=mint, amount=7):
        instruction = Instruction(
            program,
            b"\x0c" + amount.to_bytes(8, "little") + b"\x06",
            [
                AccountMeta(vault, False, True),
                AccountMeta(ix_mint, False, False),
                AccountMeta(destination, False, True),
                AccountMeta(treasury.pubkey(), True, False),
            ],
        )
        return Message.new_with_blockhash([instruction], treasury.pubkey(), blockhash)

    cases = [
        (message(), str(Pubkey.new_unique())),
        (message(amount=8), str(recipient)),
        (message(ix_mint=Pubkey.new_unique()), str(recipient)),
        (message(program=Pubkey.new_unique()), str(recipient)),
    ]
    for tampered, expected_recipient in cases:
        with pytest.raises(PayoutError):
            backend._assert_transfer_message(
                tampered,
                expected_recipient,
                str(destination),
                7,
                str(blockhash),
            )


def test_auto_cap_day_cap_and_injected_presence(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    presence_calls = []

    def presence(record, description, wait_s):
        presence_calls.append((record["id"], description, wait_s))
        return True, {"challenge": f"approved-{record['id']}"}

    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(5), "at-cap", "alice")
        held(store, credits(6), "over-cap", "bob")
        engine = PayoutEngine(
            store, rpc, config(tmp_path), backend=backend, presence=presence
        )
        engine.poll_once()
        assert row(store, "at-cap")["approval_ref"] == "auto:devnet-caps-v1"
        assert row(store, "over-cap")["approval_ref"] == "human:approved-over-cap"
        assert [call[0] for call in presence_calls] == ["over-cap"]
        assert "operator=bob" in presence_calls[0][1]
        assert "address=" + RECIPIENT in presence_calls[0][1]

    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    presence_calls.clear()
    with LedgerStore(tmp_path / "day.sqlite") as store:
        held(store, credits(3), "first", "alice")
        held(store, credits(3), "second", "bob")
        engine = PayoutEngine(
            store,
            rpc,
            config(tmp_path, auto_cap=credits(10), day_cap=credits(5)),
            backend=backend,
            presence=presence,
        )
        engine.poll_once()
        assert row(store, "first")["approval_ref"] == "auto:devnet-caps-v1"
        assert row(store, "second")["approval_ref"] == "human:approved-second"
        assert [call[0] for call in presence_calls] == ["second"]


def test_suspended_account_withdrawal_stays_pending_until_unsuspended(
    tmp_path, caplog
):
    roster = tmp_path / "roster.tsv"
    roster.write_text("key-a\tnode-a\talice\tsuspended\ttest\n", encoding="utf-8")
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        engine = PayoutEngine(
            store,
            rpc,
            config(tmp_path, roster_path=roster),
            backend=backend,
        )
        with caplog.at_level("INFO", logger="nak-treasury"):
            assert engine.poll_once() == 0
        assert row(store)["state"] == "pending"
        assert backend.builds == []
        assert sum(
            "withdrawal-1 is frozen" in record.getMessage()
            for record in caplog.records
        ) == 1

        roster.write_text("key-a\tnode-a\talice\tknown\ttest\n", encoding="utf-8")
        assert engine.poll_once() == 2
        assert row(store)["state"] == "sent"
        assert len(backend.builds) == 1


def test_more_than_one_page_of_frozen_withdrawals_cannot_starve_normal_one(
    tmp_path,
):
    roster = tmp_path / "roster.tsv"
    roster.write_text(
        "key-frozen\tnode-frozen\tfrozen\tsuspended\ttest\n",
        encoding="utf-8",
    )
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        for index in range(101):
            held(
                store,
                credits(1),
                f"frozen-{index:03d}",
                "frozen",
            )
        held(store, credits(1), "zz-normal", "normal")
        engine = PayoutEngine(
            store,
            rpc,
            config(tmp_path, roster_path=roster),
            backend=backend,
        )

        assert engine.poll_once() == 2
        assert row(store, "zz-normal")["state"] == "sent"
        assert all(
            row(store, f"frozen-{index:03d}")["state"] == "pending"
            for index in range(101)
        )
        assert len(backend.builds) == 1


def test_two_unanswered_presence_requests_release_hold(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(6))
        engine = PayoutEngine(
            store,
            rpc,
            config(tmp_path),
            backend=backend,
            presence=lambda *_args: (False, {"error": "no approval"}),
        )
        engine.poll_once()
        assert row(store)["state"] == "pending"
        assert row(store)["presence_attempts"] == 1
        engine.poll_once()
        assert row(store)["state"] == "released"
        assert store.balance("alice") == credits(6)
        assert backend.builds == []


def test_kill_file_halts_before_approval_or_broadcast(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    kill = tmp_path / "payout.off"
    kill.write_text("stop")
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        assert engine.poll_once() == 0
        assert row(store)["state"] == "pending"
        assert rpc.broadcasts == []
        assert backend.builds == []


def test_mid_pass_kill_stops_all_further_broadcasts(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    kill = tmp_path / "payout.off"
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1), "a-first", "alice")
        held(store, credits(1), "b-second", "bob")
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)

        def kill_after_first_send(_wire):
            kill.write_text("stop")

        rpc.before_send = kill_after_first_send
        with pytest.raises(PayoutError, match="kill file"):
            engine.poll_once()
        assert rpc.broadcasts == ["wire-1"]


def test_dry_run_never_loads_signer_or_broadcasts(tmp_path):
    rpc = FakeRPC()
    loaded = []
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        engine = PayoutEngine(
            store,
            rpc,
            config(tmp_path, enabled=False),
            backend_factory=lambda: loaded.append(True),
        )
        engine.poll_once()
        assert row(store)["state"] == "approved"
        assert loaded == []
        assert rpc.broadcasts == []


def test_expired_blockhash_rebuilds_and_exactly_one_transfer_lands(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)

        def assert_durable_before_broadcast(wire):
            durable = row(store)
            assert durable["state"] == "sent"
            assert durable["tx_wire"] == wire
            assert durable["tx_sig"] == rpc.wire_signatures[wire]

        rpc.before_send = assert_durable_before_broadcast

        engine.poll_once()
        first = row(store)
        assert first["state"] == "sent"
        assert first["tx_sig"] == "signature-1"

        rpc.height = first["last_valid_block_height"] + 1
        engine.poll_once()
        assert rpc.status_calls.count("signature-1") == 2
        second = row(store)
        assert second["state"] == "sent"
        assert second["tx_sig"] == "signature-2"
        assert second["expiry_count"] == 1
        assert backend.builds[0][2].blockhash != backend.builds[1][2].blockhash

        # The first signature is absent only after its validity window; only
        # the rebuilt transaction can become finalized.
        rpc.statuses["signature-2"] = {
            "confirmationStatus": "finalized",
            "err": None,
        }
        engine.poll_once()
        assert row(store)["state"] == "finalized"
        assert rpc.broadcasts == ["wire-1", "wire-2"]
        assert sum(
            status is not None and status.get("err") is None
            for status in rpc.statuses.values()
        ) == 1
        assert store.balance("alice") == 0
        assert store._db.execute(
            "SELECT COALESCE(SUM(balance), 0) FROM accounts"
        ).fetchone()[0] == 0


def test_processed_failure_stays_sent_and_is_not_rebroadcast(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        engine.poll_once()
        rpc.statuses["signature-1"] = {
            "confirmationStatus": "processed",
            "err": {"InstructionError": [0, "Custom"]},
        }
        engine.poll_once()
        assert row(store)["state"] == "sent"
        assert row(store)["tx_sig"] == "signature-1"
        assert rpc.broadcasts == ["wire-1"]
        assert len(backend.builds) == 1


def test_finalized_failure_rebuilds_under_existing_attempt_limit(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        engine.poll_once()
        rpc.statuses["signature-1"] = {
            "confirmationStatus": "finalized",
            "err": {"InstructionError": [0, "Custom"]},
        }
        engine.poll_once()
        assert row(store)["state"] == "sent"
        assert row(store)["tx_sig"] == "signature-2"
        assert row(store)["expiry_count"] == 1
        assert rpc.broadcasts == ["wire-1", "wire-2"]


def test_recipient_ata_creation_is_idempotent(tmp_path):
    rpc = FakeRPC()
    rpc.existing_accounts.clear()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        engine.poll_once()
        assert backend.created_atas == [RECIPIENT]
        assert row(store)["state"] == "sent"
        engine.poll_once()
        assert backend.created_atas == [RECIPIENT]


def test_landed_unfinalized_signature_is_never_rebuilt_after_expiry_height(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        engine.poll_once()
        current = row(store)
        rpc.height = current["last_valid_block_height"] + 100
        rpc.statuses[current["tx_sig"]] = {
            "confirmationStatus": "confirmed",
            "err": None,
        }
        engine.poll_once()
        assert row(store)["state"] == "sent"
        assert row(store)["expiry_count"] == 0
        assert len(backend.builds) == 1


def test_three_expiries_release_and_deposit_queue_is_consumed(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        held(store, credits(1))
        assert store.queue_deposit_account("operator-2") is True
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        engine.poll_once()
        assert store.pending_deposit_accounts() == []
        assert store._db.execute(
            "SELECT token_account FROM deposit_accounts WHERE operator='operator-2'"
        ).fetchone()[0] == BLOCKHASHES[0]

        for expected in (1, 2):
            current = row(store)
            rpc.height = current["last_valid_block_height"] + 1
            engine.poll_once()
            assert row(store)["expiry_count"] == expected
            assert row(store)["state"] == "sent"
        current = row(store)
        rpc.height = current["last_valid_block_height"] + 1
        engine.poll_once()
        assert row(store)["expiry_count"] == 3
        assert row(store)["state"] == "released"
        assert store.balance("alice") == credits(1)


def test_stranger_can_withdraw_deposit_but_not_matured_earnings(tmp_path, monkeypatch):
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        store.deposit("own", "stranger", credits(1), 1)
        store.withdraw_hold("stranger", credits(1), RECIPIENT, "own-withdrawal")

        store.deposit("funding", "consumer", credits(1), 2)
        monkeypatch.setattr(ledger_store_module.time, "time", lambda: 1)
        store.settle(
            "earning", "consumer", {"stranger": credits(1)}, credits(1), "self"
        )
        monkeypatch.setattr(ledger_store_module.time, "time", lambda: HOLD_S + 2)
        store.withdraw_release("own-withdrawal")
        # The returned own deposit remains cashable, but anything above that
        # would consume earnings and therefore requires known+.
        with pytest.raises(CreditLimitError, match="known or higher"):
            store.withdraw_hold("stranger", credits(2), RECIPIENT, "earnings")
        store._db.execute("UPDATE accounts SET tier='known' WHERE id='stranger'")
        store.withdraw_hold("stranger", credits(2), RECIPIENT, "known-earnings")


def test_second_process_exits_zero_when_singleton_lock_is_held(tmp_path):
    lock_path = tmp_path / "payout.lock"
    first = PayoutProcessLock.acquire(lock_path)
    assert first is not None
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parents[1] / "chain" / "payout.py"),
                "--once",
                "--lock-file",
                str(lock_path),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0
        assert "payout worker already running" in result.stderr
    finally:
        first.close()
