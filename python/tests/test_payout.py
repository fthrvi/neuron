"""Unit tests for the fail-closed treasury payout state machine."""
import base64
import json
import os
import sqlite3
import subprocess
import sys
import threading
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
    WriteGatePresence,
)
import chain.payout as payout_module  # noqa: E402
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
TREASURY = RECIPIENT
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
        self.token_accounts = {}
        self.token_account_metadata = {}
        self.account_signatures = {}
        self.signature_address_calls = []

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

    def get_token_account(self, address):
        account = {
            "mint": MINT,
            "amount": self.token_accounts.get(address, 0),
            "decimals": 6,
            "owner": TREASURY,
            "slot": 100,
        }
        account.update(self.token_account_metadata.get(address, {}))
        return account

    def get_signatures_for_address(
        self, address, *, before=None, until=None, limit=1000,
        min_context_slot=None,
    ):
        assert before is None
        assert until is None
        self.signature_address_calls.append((address, limit, min_context_slot))
        return self.account_signatures.get(
            address, [{"signature": f"deposit-{address}"}]
        )[:limit]

    def send_transaction(self, wire):
        if self.before_send is not None:
            self.before_send(wire)
        self.broadcasts.append(wire)
        return self.wire_signatures[wire]


class FakeBackend:
    def __init__(self, rpc):
        self.rpc = rpc
        self.pubkey = TREASURY
        self.builds = []
        self.created_atas = []
        self.deposit_accounts = []
        self.sweeps = []

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

    def build_sweep(self, source, micro_usdc, blockhash, last_valid):
        signature = f"sweep-signature-{len(self.sweeps) + 1}"
        wire = f"sweep-wire-{len(self.sweeps) + 1}"
        self.rpc.wire_signatures[wire] = signature
        signed = SignedTransaction(signature, wire, blockhash, last_valid)
        self.sweeps.append((source, micro_usdc, signed))
        return signed


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


def indexed_account(store, account, amount_micro, operator="alice"):
    store._db.execute(
        "CREATE TABLE IF NOT EXISTS chain_indexer_accounts "
        "(token_account TEXT PRIMARY KEY, cursor TEXT, "
        "paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0, 1)), "
        "updated_ts INTEGER NOT NULL)"
    )
    store._db.execute(
        "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
        "VALUES (?, ?, 1)",
        (operator, account),
    )
    store._db.execute(
        "INSERT INTO chain_indexer_accounts(token_account, cursor, updated_ts) "
        "VALUES (?, ?, 1)",
        (account, f"deposit-{account}"),
    )
    store.deposit_batch(
        operator,
        account,
        [(f"deposit-{operator}:0", amount_micro * RATE, 1)],
        amount_micro * RATE,
    )


def test_sweep_is_persisted_before_send_and_later_finalized_once(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    amount = 1_000_000
    with LedgerStore(tmp_path / "sweep.sqlite") as store:
        indexed_account(store, account, amount)
        rpc.token_accounts[account] = amount

        def assert_persisted(_wire):
            assert store._db.execute(
                "SELECT 1 FROM chain_sweeps WHERE token_account=? AND state='sent'",
                (account,),
            ).fetchone()

        rpc.before_send = assert_persisted
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        assert engine.poll_once() == 1
        sweep = dict(store._db.execute("SELECT * FROM chain_sweeps").fetchone())
        assert rpc.broadcasts == ["sweep-wire-1"]
        assert len(backend.sweeps) == 1

        rpc.before_send = None
        rpc.statuses[sweep["signature"]] = {
            "err": None,
            "confirmationStatus": "finalized",
        }
        rpc.token_accounts[account] = 0
        assert engine.poll_once() == 1
        assert store._db.execute(
            "SELECT state FROM chain_sweeps WHERE id=?", (sweep["id"],)
        ).fetchone()[0] == "finalized"
        assert len(backend.sweeps) == 1
        assert rpc.broadcasts == ["sweep-wire-1"]

        # Once the indexer advances over the outgoing sweep and indexes a new
        # deposit, the account is eligible for its next sweep.
        rpc.account_signatures[account] = [{"signature": "deposit-next"}]
        rpc.token_accounts[account] = amount
        store.deposit_batch(
            "alice",
            account,
            [("deposit-next:0", amount * RATE, 2)],
            amount * RATE,
            cursor="deposit-next",
        )
        assert engine.poll_once() == 1
        assert len(backend.sweeps) == 2
        assert rpc.broadcasts == ["sweep-wire-1", "sweep-wire-2"]


def test_sweep_skips_net_balance_match_when_indexer_cursor_is_behind(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    amount = 1_000_000
    with LedgerStore(tmp_path / "cursor-behind.sqlite") as store:
        indexed_account(store, account, amount)
        # An unexplained outflow and an unindexed inflow can net to the exact
        # expected balance. The newer chain signature still blocks sweeping.
        rpc.token_accounts[account] = amount
        rpc.account_signatures[account] = [{"signature": "unindexed-inflow"}]
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)

        assert engine.poll_once() == 0
        assert rpc.signature_address_calls == [(account, 1, 100)]
        assert backend.sweeps == []
        assert store._db.execute("SELECT COUNT(*) FROM chain_sweeps").fetchone()[0] == 0


def test_sweep_rechecks_balance_after_context_fenced_signature_history(tmp_path):
    class ChangingBalanceRPC(FakeRPC):
        def __init__(self):
            super().__init__()
            self.reads = iter([1_000_000, 1_000_001])

        def get_token_account(self, address):
            account = super().get_token_account(address)
            account["amount"] = next(self.reads)
            return account

    rpc = ChangingBalanceRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    with LedgerStore(tmp_path / "balance-changed.sqlite") as store:
        indexed_account(store, account, 1_000_000)
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)

        assert engine.poll_once() == 0
        assert rpc.signature_address_calls == [(account, 1, 100)]
        assert backend.sweeps == []
        assert rpc.broadcasts == []


def test_sweep_fails_closed_when_rpc_cannot_honor_min_context_slot(tmp_path):
    class UnfencedHistoryRPC(FakeRPC):
        def get_signatures_for_address(
            self, address, *, before=None, until=None, limit=1000,
            min_context_slot=None,
        ):
            assert min_context_slot == 100
            raise RPCError("minimum context slot is not reached")

    rpc = UnfencedHistoryRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    with LedgerStore(tmp_path / "unsupported-context-fence.sqlite") as store:
        indexed_account(store, account, 1_000_000)
        rpc.token_accounts[account] = 1_000_000
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)

        assert engine.poll_once() == 0
        assert backend.sweeps == []
        assert rpc.broadcasts == []


def test_processed_sweep_failure_stays_sent_without_second_broadcast(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    with LedgerStore(tmp_path / "processed-sweep-error.sqlite") as store:
        indexed_account(store, account, 1_000_000)
        rpc.token_accounts[account] = 1_000_000
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        assert engine.poll_once() == 1
        sweep = dict(store._db.execute("SELECT * FROM chain_sweeps").fetchone())
        rpc.statuses[sweep["signature"]] = {
            "confirmationStatus": "processed",
            "err": {"InstructionError": [0, "Custom"]},
        }

        assert engine.poll_once() == 0
        assert store._db.execute(
            "SELECT state FROM chain_sweeps WHERE id=?", (sweep["id"],)
        ).fetchone()[0] == "sent"
        assert rpc.broadcasts == ["sweep-wire-1"]
        assert len(backend.sweeps) == 1


@pytest.mark.parametrize(
    ("metadata", "detail"),
    [
        ({"owner": "not-the-treasury"}, "source owner"),
        ({"delegate": "unexpected-delegate"}, "has delegate"),
    ],
)
def test_sweep_refuses_untrusted_source_authority(
    tmp_path, caplog, metadata, detail
):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    with LedgerStore(tmp_path / f"source-{detail.replace(' ', '-')}.sqlite") as store:
        indexed_account(store, account, 1_000_000)
        rpc.token_accounts[account] = 1_000_000
        rpc.token_account_metadata[account] = metadata
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)

        with caplog.at_level("ERROR", logger="nak-treasury"):
            assert engine.poll_once() == 0

        assert store._db.execute("SELECT COUNT(*) FROM chain_sweeps").fetchone()[0] == 0
        assert backend.sweeps == []
        assert rpc.broadcasts == []
        messages = [record.getMessage() for record in caplog.records]
        assert any('"event":"chain_sweep_alert"' in message for message in messages)
        assert any(detail in message for message in messages)


def test_stale_visible_sweep_logs_each_pass_without_resigning(tmp_path, caplog):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    with LedgerStore(tmp_path / "stale-sweep.sqlite") as store:
        indexed_account(store, account, 1_000_000)
        rpc.token_accounts[account] = 1_000_000
        engine = PayoutEngine(
            store,
            rpc,
            config(tmp_path, sweep_stale_blocks=3),
            backend=backend,
        )
        assert engine.poll_once() == 1
        sweep = dict(store._db.execute("SELECT * FROM chain_sweeps").fetchone())
        rpc.statuses[sweep["signature"]] = {
            "confirmationStatus": "confirmed",
            "err": None,
        }
        rpc.height = int(sweep["last_valid_block_height"]) + 4

        with caplog.at_level("ERROR", logger="nak-treasury"):
            assert engine.poll_once() == 0
            assert engine.poll_once() == 0

        assert store._db.execute(
            "SELECT state FROM chain_sweeps WHERE id=?", (sweep["id"],)
        ).fetchone()[0] == "sent"
        assert len(backend.sweeps) == 1
        assert rpc.broadcasts == ["sweep-wire-1"]
        assert sum(
            f"stale in-flight sweep {sweep['id']}" in record.getMessage()
            for record in caplog.records
        ) == 2


@pytest.mark.parametrize("mode", ["funds_off", "kill", "lag", "paused", "below_min"])
def test_sweep_safety_skips(tmp_path, mode):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    amount = 1_000_000
    with LedgerStore(tmp_path / f"{mode}.sqlite") as store:
        indexed_account(store, account, amount)
        rpc.token_accounts[account] = amount
        cfg = config(tmp_path)
        if mode == "funds_off":
            cfg = config(tmp_path, enabled=False)
        elif mode == "kill":
            cfg.kill_file.touch()
        elif mode == "lag":
            rpc.token_accounts[account] += 1
        elif mode == "paused":
            store._db.execute(
                "UPDATE chain_indexer_accounts SET paused=1 WHERE token_account=?",
                (account,),
            )
        elif mode == "below_min":
            cfg = config(tmp_path, sweep_min_micro=amount + 1)
        engine = PayoutEngine(store, rpc, cfg, backend=backend)
        assert engine.poll_once() == 0
        assert backend.sweeps == []
        assert rpc.broadcasts == []


def test_sweep_crash_after_persist_is_not_rebuilt_or_double_sent(tmp_path):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    with LedgerStore(tmp_path / "crash.sqlite") as store:
        indexed_account(store, account, 1_000_000)
        rpc.token_accounts[account] = 1_000_000
        rpc.before_send = lambda _wire: (_ for _ in ()).throw(RuntimeError("crash"))
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        assert engine.poll_once() == 0
        assert store._db.execute(
            "SELECT state FROM chain_sweeps"
        ).fetchone()[0] == "sent"
        assert len(backend.sweeps) == 1
        assert rpc.broadcasts == []

        rpc.before_send = None
        assert engine.poll_once() == 0
        assert len(backend.sweeps) == 1
        assert rpc.broadcasts == []


@pytest.mark.parametrize(
    ("guard", "status", "expected_state"),
    [
        ("funds_off", {"err": None, "confirmationStatus": "finalized"}, "finalized"),
        (
            "kill",
            {
                "err": {"InstructionError": [0, "Custom"]},
                "confirmationStatus": "finalized",
            },
            "failed",
        ),
    ],
)
def test_sent_sweep_resolves_while_new_money_movement_is_disabled(
    tmp_path, guard, status, expected_state
):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]
    with LedgerStore(tmp_path / f"resolve-{guard}.sqlite") as store:
        indexed_account(store, account, 1_000_000)
        store.begin_sweep(
            "crash-after-broadcast", "alice", account, 1_000_000,
            "sweep-signature-1", BLOCKHASHES[1], 12,
        )
        rpc.statuses["sweep-signature-1"] = status
        cfg = config(tmp_path, enabled=guard != "funds_off")
        if guard == "kill":
            cfg.kill_file.touch()

        engine = PayoutEngine(store, rpc, cfg, backend=backend)
        assert engine.poll_once() == 1

        assert store._db.execute(
            "SELECT state FROM chain_sweeps WHERE id='crash-after-broadcast'"
        ).fetchone()[0] == expected_state
        assert backend.sweeps == []
        assert backend.builds == []
        assert rpc.broadcasts == []


def test_one_sweep_account_failure_does_not_stop_another(tmp_path):
    rpc = FakeRPC()

    class FailingBackend(FakeBackend):
        def build_sweep(self, source, micro_usdc, blockhash, last_valid):
            if source == BLOCKHASHES[0]:
                raise PayoutError("one bad account")
            return super().build_sweep(source, micro_usdc, blockhash, last_valid)

    backend = FailingBackend(rpc)
    with LedgerStore(tmp_path / "isolated.sqlite") as store:
        indexed_account(store, BLOCKHASHES[0], 1_000_000, "alice")
        indexed_account(store, BLOCKHASHES[1], 2_000_000, "bob")
        rpc.token_accounts.update(
            {BLOCKHASHES[0]: 1_000_000, BLOCKHASHES[1]: 2_000_000}
        )
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)
        assert engine.poll_once() == 1
        sweep = store._db.execute(
            "SELECT operator, token_account, state FROM chain_sweeps"
        ).fetchone()
        assert tuple(sweep) == ("bob", BLOCKHASHES[1], "sent")
        assert rpc.broadcasts == ["sweep-wire-1"]


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


def test_real_sweep_signature_and_transfer_checked_message_verify():
    treasury = Keypair()
    mint = Pubkey.new_unique()
    vault = Pubkey.new_unique()
    source = Pubkey.new_unique()
    blockhash = str(Hash.new_unique())
    backend = SoldersTreasuryBackend(
        FakeRPC(),
        str(mint),
        str(vault),
        secret_loader=lambda _name: treasury.to_json(),
    )
    signed = backend.build_sweep(str(source), 1_234_567, blockhash, 10)
    transaction = Transaction.from_bytes(base64.b64decode(signed.wire_b64))
    assert str(transaction.signatures[0]) == signed.signature
    assert transaction.verify_with_results() == [True]
    compiled = transaction.message.instructions[0]
    assert transaction.message.account_keys[compiled.program_id_index] == TOKEN_PROGRAM_ID
    assert backend._resolved_accounts(transaction.message, compiled) == [
        source, mint, vault, treasury.pubkey()
    ]
    assert compiled.data == b"\x0c" + (1_234_567).to_bytes(8, "little") + b"\x06"


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


def test_concurrent_engines_atomically_claim_daily_auto_approval(tmp_path):
    path = tmp_path / "auto-cap-race.sqlite"
    barrier = threading.Barrier(2)

    class RacingStore(LedgerStore):
        def withdraw_auto_approve(self, *args, **kwargs):
            barrier.wait(timeout=5)
            return super().withdraw_auto_approve(*args, **kwargs)

    with LedgerStore(path) as seed:
        held(seed, credits(3), "first", "alice")
        held(seed, credits(3), "second", "bob")

    stores = [RacingStore(path), RacingStore(path)]
    shared = {"prepared": 0, "enqueued": 0, "checked": 0}
    engines = [
        PayoutEngine(
            store,
            FakeRPC(),
            config(tmp_path, auto_cap=credits(5), day_cap=credits(5)),
            backend=FakeBackend(FakeRPC()),
            presence=AsyncPresence(shared),
        )
        for store in stores
    ]
    rows = [
        stores[0].withdrawals("pending")[0],
        stores[1].withdrawals("pending")[1],
    ]
    errors = []

    def approve(engine, pending):
        try:
            engine._approve_one(pending)
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [
        threading.Thread(target=approve, args=pair)
        for pair in zip(engines, rows)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    try:
        assert errors == []
        assert all(not thread.is_alive() for thread in threads)
        states = [
            row(stores[0], withdrawal_id)
            for withdrawal_id in ("first", "second")
        ]
        assert sum(
            item["approval_ref"] == "auto:devnet-caps-v1" for item in states
        ) == 1
        human_needed = [
            item for item in states if item["approval_ref"] != "auto:devnet-caps-v1"
        ]
        assert len(human_needed) == 1
        assert stores[0].withdrawal_presence(human_needed[0]["id"]) is not None
    finally:
        for store in stores:
            store.close()


class AsyncPresence:
    def __init__(self, shared, result=None):
        self.shared = shared
        self.result = result or ("pending", {})

    def prepare(self, record, description, wait_s):
        self.shared["prepared"] += 1
        return {
            "keyid": "test-owner",
            "nonce": f"nonce:{record['id']}",
            "challenge": f"challenge:{record['id']}",
            "description": description,
            "expires_ts": 4_000_000_000,
        }

    def enqueue(self, request, _wait_s):
        if request.get("request_id"):
            return request
        self.shared["enqueued"] += 1
        return {
            **request,
            "request_id": f"request:{request['withdrawal_id']}",
        }

    def check(self, request):
        self.shared["checked"] += 1
        status, detail = self.result
        if status == "approved":
            detail = {
                "withdrawal_id": request["withdrawal_id"],
                "amount": int(request["amount"]),
                "address": request["address"],
                "challenge": request["challenge"],
                **detail,
            }
        return status, detail


def test_presence_config_exception_isolated_while_other_payout_and_sweep_continue(
    tmp_path, caplog
):
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    account = BLOCKHASHES[0]

    class ConfigFailure(AsyncPresence):
        def prepare(self, record, description, wait_s):
            if record["id"] == "a-config-failure":
                raise RuntimeError("MissingMeshConfig")
            return super().prepare(record, description, wait_s)

    shared = {"prepared": 0, "enqueued": 0, "checked": 0}
    with LedgerStore(tmp_path / "isolated-presence.sqlite") as store:
        held(store, credits(6), "a-config-failure", "alice")
        held(store, credits(1), "b-automatic", "bob")
        indexed_account(store, account, 1_000_000, "carol")
        rpc.token_accounts[account] = 1_000_000
        before = row(store, "a-config-failure")
        engine = PayoutEngine(
            store, rpc, config(tmp_path), backend=backend,
            presence=ConfigFailure(shared),
        )

        with caplog.at_level("ERROR", logger="nak-treasury"):
            engine.poll_once()

        after = row(store, "a-config-failure")
        assert after == before
        assert store.withdrawal_presence("a-config-failure") is None
        assert row(store, "b-automatic")["state"] == "sent"
        assert store._db.execute(
            "SELECT state FROM chain_sweeps WHERE token_account=?", (account,)
        ).fetchone()[0] == "sent"
        assert len(backend.builds) == 1
        assert len(backend.sweeps) == 1
        assert "MissingMeshConfig" in caplog.text


def test_pending_presence_survives_restart_without_second_request(tmp_path):
    path = tmp_path / "restart-presence.sqlite"
    shared = {"prepared": 0, "enqueued": 0, "checked": 0}
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(path) as store:
        held(store, credits(6))
        first = PayoutEngine(
            store, rpc, config(tmp_path), backend=backend,
            presence=AsyncPresence(shared),
        )
        first.poll_once()
        request = store.withdrawal_presence("withdrawal-1")
        assert request["request_id"] == "request:withdrawal-1"
        assert row(store)["state"] == "pending"
        assert shared == {"prepared": 1, "enqueued": 1, "checked": 0}

    with LedgerStore(path) as reopened:
        restarted = PayoutEngine(
            reopened, rpc, config(tmp_path), backend=backend,
            presence=AsyncPresence(shared, ("approved", {})),
        )
        restarted.poll_once()
        assert row(reopened)["state"] == "sent"
        assert reopened.withdrawal_presence("withdrawal-1") is None
        assert shared == {"prepared": 1, "enqueued": 1, "checked": 1}
        assert len(backend.builds) == 1


def test_expired_human_approval_is_re_requested_after_restart_without_send(tmp_path):
    path = tmp_path / "approval-expiry.sqlite"
    clock = [100]
    shared = {"prepared": 0, "enqueued": 0, "checked": 0}
    rpc = FakeRPC()

    class ExpiringPresence(AsyncPresence):
        def prepare(self, record, description, wait_s):
            prepared = super().prepare(record, description, wait_s)
            prepared["expires_ts"] = clock[0] + 5
            return prepared

    class CrashBeforeSign(FakeBackend):
        def build_transfer(self, *_args):
            raise RuntimeError("crash before signing")

    with LedgerStore(path, clock=lambda: clock[0]) as store:
        held(store, credits(6))
        presence = ExpiringPresence(shared, ("approved", {}))
        engine = PayoutEngine(
            store, rpc, config(tmp_path), backend=CrashBeforeSign(rpc),
            presence=presence, now=lambda: clock[0],
        )
        engine.poll_once()
        engine.poll_once()
        approved = row(store)
        assert approved["state"] == "approved"
        assert approved["approval_expires_ts"] == 105
        assert approved["approved_withdrawal_id"] == "withdrawal-1"
        assert approved["approved_amount"] == credits(6)
        assert approved["approved_address"] == RECIPIENT
        assert rpc.broadcasts == []

    clock[0] = 106
    backend = FakeBackend(rpc)
    with LedgerStore(path, clock=lambda: clock[0]) as reopened:
        restarted = PayoutEngine(
            reopened, rpc, config(tmp_path), backend=backend,
            presence=ExpiringPresence(shared), now=lambda: clock[0],
        )
        restarted.poll_once()
        assert row(reopened)["state"] == "pending"
        assert row(reopened)["approval_ref"] is None
        assert reopened.withdrawal_presence("withdrawal-1") is not None
        assert rpc.broadcasts == []
        assert backend.builds == []
        assert shared["prepared"] == 2
        assert shared["enqueued"] == 2
        assert rpc.broadcasts == []


def test_broker_expiry_cannot_extend_persisted_local_deadline(tmp_path):
    clock = [100]
    shared = {"prepared": 0, "enqueued": 0, "checked": 0}

    class ExtendingBrokerPresence(AsyncPresence):
        def prepare(self, record, description, wait_s):
            prepared = super().prepare(record, description, wait_s)
            prepared["expires_ts"] = clock[0] + 5
            return prepared

        def enqueue(self, request, wait_s):
            enqueued = super().enqueue(request, wait_s)
            enqueued["expires_ts"] = 4_000_000_000
            return enqueued

    with LedgerStore(
        tmp_path / "clamped-expiry.sqlite", clock=lambda: clock[0]
    ) as store:
        held(store, credits(6))
        engine = PayoutEngine(
            store,
            FakeRPC(),
            config(tmp_path),
            backend=FakeBackend(FakeRPC()),
            presence=ExtendingBrokerPresence(shared),
            now=lambda: clock[0],
        )

        engine.poll_once()

        request = store.withdrawal_presence("withdrawal-1")
        assert request["request_id"] == "request:withdrawal-1"
        assert request["expires_ts"] == 105


def test_enqueue_recovery_uses_local_deadline_when_broker_omits_expiry(
    monkeypatch,
):
    request = {
        "withdrawal_id": "withdrawal-1",
        "amount": credits(6),
        "address": RECIPIENT,
        "keyid": "test-owner",
        "nonce": "nonce:withdrawal-1",
        "challenge": "challenge:withdrawal-1",
        "description": "approve withdrawal-1",
        "expires_ts": 12345,
    }

    class OrdinaryBroker:
        @staticmethod
        def _broker_call(method, path):
            assert method == "GET"
            assert path == "/pending?keyid=test-owner"
            return {
                "requests": [
                    {
                        "request_id": "broker-request-1",
                        "challenge": "challenge:withdrawal-1",
                        "description": "approve withdrawal-1",
                        "created": 12000,
                    }
                ]
            }

    monkeypatch.setattr(payout_module, "_write_gate", lambda: OrdinaryBroker)

    recovered = WriteGatePresence.recover(request, wait_s=180)

    assert recovered["request_id"] == "broker-request-1"
    assert recovered["expires_ts"] == request["expires_ts"]


def test_signed_broker_result_survives_crash_before_verification(tmp_path):
    path = tmp_path / "one-shot-result.sqlite"
    shared = {"prepared": 0, "enqueued": 0, "fetched": 0, "verified": 0}
    rpc = FakeRPC()
    backend = FakeBackend(rpc)

    class RawPresence(AsyncPresence):
        def fetch(self, request):
            self.shared["fetched"] += 1
            return {
                "status": "signed",
                "signature": "raw-signature",
                "signer": "test-owner",
            }

        def verify(self, request, result):
            self.shared["verified"] += 1
            assert result["signature"] == "raw-signature"
            return "approved", {
                "withdrawal_id": request["withdrawal_id"],
                "amount": int(request["amount"]),
                "address": request["address"],
                "signature": result["signature"],
            }

    class CrashAfterResultStore(LedgerStore):
        crashed = False

        def withdraw_presence_store_result(self, withdrawal_id, result):
            stored = super().withdraw_presence_store_result(withdrawal_id, result)
            if not self.crashed:
                self.crashed = True
                raise RuntimeError("crash after broker GET")
            return stored

    presence = RawPresence(shared)
    with CrashAfterResultStore(path) as store:
        held(store, credits(6))
        engine = PayoutEngine(
            store, rpc, config(tmp_path), backend=backend, presence=presence
        )
        engine.poll_once()
        engine.poll_once()
        request = store.withdrawal_presence("withdrawal-1")
        assert json.loads(request["broker_result_json"])["signature"] == "raw-signature"
        assert row(store)["state"] == "pending"
        assert shared["fetched"] == 1
        assert shared["verified"] == 0

    with LedgerStore(path) as reopened:
        restarted = PayoutEngine(
            reopened, rpc, config(tmp_path), backend=backend, presence=presence
        )
        restarted.poll_once()
        assert row(reopened)["state"] == "sent"
        assert shared["fetched"] == 1
        assert shared["verified"] == 1
        assert rpc.broadcasts == ["wire-1"]


def test_enqueue_cas_elects_only_one_engine_to_prompt(tmp_path):
    path = tmp_path / "enqueue-election.sqlite"
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    shared = {"prepared": 0, "enqueued": 0, "checked": 0}

    class RacingPresence(AsyncPresence):
        def prepare(self, record, description, wait_s):
            prepared = super().prepare(record, description, wait_s)
            barrier.wait(timeout=5)
            return prepared

        def enqueue(self, request, wait_s):
            with lock:
                return super().enqueue(request, wait_s)

    with LedgerStore(path) as seed:
        held(seed, credits(6))
    stores = [LedgerStore(path), LedgerStore(path)]
    engines = [
        PayoutEngine(
            store, FakeRPC(), config(tmp_path), backend=FakeBackend(FakeRPC()),
            presence=RacingPresence(shared),
        )
        for store in stores
    ]
    errors = []

    def run(engine):
        try:
            engine._approve_pending(set())
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(engine,)) for engine in engines]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    try:
        assert errors == []
        assert all(not thread.is_alive() for thread in threads)
        assert shared["enqueued"] == 1
    finally:
        for store in stores:
            store.close()


def test_storage_transition_failure_isolated_from_rest_of_pass(tmp_path, caplog):
    class OneBrokenTransitionStore(LedgerStore):
        def withdraw_auto_approve(self, withdrawal_id, approval_ref, **kwargs):
            if withdrawal_id == "a-broken":
                raise sqlite3.OperationalError("injected transition failure")
            return super().withdraw_auto_approve(
                withdrawal_id, approval_ref, **kwargs
            )

    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    sweep_account = BLOCKHASHES[1]
    with OneBrokenTransitionStore(tmp_path / "isolated-transition.sqlite") as store:
        held(store, credits(1), "a-broken", "alice")
        held(store, credits(1), "b-good", "bob")
        indexed_account(store, sweep_account, 1_000_000, "carol")
        rpc.token_accounts[sweep_account] = 1_000_000
        assert store.queue_deposit_account("dave") is True
        engine = PayoutEngine(store, rpc, config(tmp_path), backend=backend)

        with caplog.at_level("ERROR", logger="nak-treasury"):
            engine.poll_once()

        assert row(store, "a-broken")["state"] == "pending"
        assert row(store, "b-good")["state"] == "sent"
        assert store._db.execute(
            "SELECT state FROM chain_sweeps WHERE token_account=?",
            (sweep_account,),
        ).fetchone()[0] == "sent"
        assert store._db.execute(
            "SELECT token_account FROM deposit_accounts WHERE operator='dave'"
        ).fetchone()[0] == BLOCKHASHES[0]
        assert "injected transition failure" in caplog.text


@pytest.mark.parametrize(
    "mismatch", [{"amount": credits(7)}, {"address": VAULT_ACCOUNT}]
)
def test_presence_approval_for_different_payout_is_rejected(tmp_path, mismatch):
    shared = {"prepared": 0, "enqueued": 0, "checked": 0}
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(tmp_path / "mismatched-approval.sqlite") as store:
        held(store, credits(6))
        presence = AsyncPresence(shared, ("approved", mismatch))
        engine = PayoutEngine(
            store, rpc, config(tmp_path), backend=backend, presence=presence
        )
        engine.poll_once()
        engine.poll_once()

        assert row(store)["state"] == "pending"
        assert row(store)["approval_ref"] is None
        assert row(store)["presence_attempts"] == 1
        assert backend.builds == []


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


def test_new_broadcast_rechecks_approval_after_slow_safety_gate(tmp_path):
    clock = [100]
    rpc = FakeRPC()
    backend = FakeBackend(rpc)
    with LedgerStore(
        tmp_path / "slow-gate-new.sqlite", clock=lambda: clock[0]
    ) as store:
        held(store, credits(6))
        store.withdraw_approve(
            "withdrawal-1",
            "human:test",
            expires_ts=101,
            approved_withdrawal_id="withdrawal-1",
            approved_amount=credits(6),
            approved_address=RECIPIENT,
        )
        engine = PayoutEngine(
            store, rpc, config(tmp_path), backend=backend, now=lambda: clock[0]
        )
        gate_calls = 0

        def slow_second_gate():
            nonlocal gate_calls
            gate_calls += 1
            if gate_calls == 2:
                clock[0] = 102

        engine._may_act = slow_second_gate

        assert engine._build_and_send(row(store)) == 1
        assert gate_calls == 2
        assert row(store)["state"] == "sent"
        assert rpc.broadcasts == []


def test_ata_broadcast_rechecks_approval_after_slow_safety_gate(tmp_path):
    clock = [100]
    rpc = FakeRPC()
    rpc.existing_accounts.remove(RECIPIENT_ATA)
    backend = FakeBackend(rpc)
    with LedgerStore(
        tmp_path / "slow-gate-ata.sqlite", clock=lambda: clock[0]
    ) as store:
        held(store, credits(6))
        store.withdraw_approve(
            "withdrawal-1",
            "human:test",
            expires_ts=101,
            approved_withdrawal_id="withdrawal-1",
            approved_amount=credits(6),
            approved_address=RECIPIENT,
        )
        engine = PayoutEngine(
            store, rpc, config(tmp_path), backend=backend, now=lambda: clock[0]
        )

        def slow_gate():
            clock[0] = 102

        engine._may_act = slow_gate

        assert engine._build_and_send(row(store)) == 1
        assert row(store)["state"] == "pending"
        assert backend.created_atas == []
        assert backend.builds == []
        assert rpc.broadcasts == []


def test_rebroadcast_rechecks_approval_after_slow_safety_gate(tmp_path):
    clock = [100]
    rpc = FakeRPC()
    with LedgerStore(
        tmp_path / "slow-gate-rebroadcast.sqlite", clock=lambda: clock[0]
    ) as store:
        held(store, credits(6))
        store.withdraw_approve(
            "withdrawal-1",
            "human:test",
            expires_ts=101,
            approved_withdrawal_id="withdrawal-1",
            approved_amount=credits(6),
            approved_address=RECIPIENT,
        )
        store.withdraw_mark_sent(
            "withdrawal-1", "signature-1", BLOCKHASHES[0], 12, "wire-1"
        )
        rpc.wire_signatures["wire-1"] = "signature-1"
        engine = PayoutEngine(
            store,
            rpc,
            config(tmp_path),
            backend=FakeBackend(rpc),
            now=lambda: clock[0],
        )

        def slow_gate():
            clock[0] = 102

        engine._may_act = slow_gate

        assert engine._advance_sent(row(store)) == 0
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
