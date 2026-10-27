"""Unit tests against captured jsonParsed Solana RPC shapes."""
import json
import os
import sqlite3
import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chain.indexer import (  # noqa: E402
    DEVNET_GENESIS_HASH,
    MAINNET_GENESIS_HASH,
    DepositIndexer,
    IndexerConfig,
    UnpauseRefused,
    _parser,
)
from chain.solana_rpc import RPCError, decode_base58, validate_pubkey  # noqa: E402
from core.ledger_store import RATE, LedgerStore  # noqa: E402


FIXTURE = Path(__file__).parent / "fixtures" / "solana_indexer.json"


class FakeRPC:
    def __init__(self, fixture, *, balance=15, genesis=None):
        self.addresses = fixture["addresses"]
        self.signatures = deepcopy(fixture["signatures"])
        self.transactions = deepcopy(fixture["transactions"])
        self.balance = balance
        self.genesis = genesis or fixture["addresses"]["mint"]
        self.calls = []

    def get_genesis_hash(self):
        self.calls.append(("genesis",))
        return self.genesis

    def get_signatures_for_address(self, address, *, before=None, until=None, limit=1000):
        self.calls.append(("signatures", address, before, until, limit))
        records = self.signatures
        start = 0
        end = len(records)
        names = [record["signature"] for record in records]
        if before in names:
            start = names.index(before) + 1
        if until in names:
            end = names.index(until)
        return deepcopy(records[start:end][:limit])

    def get_transaction(self, signature):
        self.calls.append(("transaction", signature))
        return deepcopy(self.transactions[signature])

    def get_token_account(self, address):
        self.calls.append(("account", address))
        return {
            "mint": self.addresses["mint"],
            "amount": self.balance,
            "decimals": 6,
            "slot": 20,
        }


@pytest.fixture
def recorded():
    return json.loads(FIXTURE.read_text())


def _config(recorded, **changes):
    values = {
        "cluster": "localnet",
        "mint": recorded["addresses"]["mint"],
        "rpc_url": "http://127.0.0.1:18899",
    }
    values.update(changes)
    return IndexerConfig(**values)


def _register(store, recorded, operator="alice"):
    store._db.execute(
        "INSERT INTO deposit_accounts(operator, token_account, created_ts) VALUES (?, ?, 1)",
        (operator, recorded["addresses"]["deposit"]),
    )


def test_accepts_transfer_checked_and_inner_but_ignores_noise(recorded, tmp_path):
    rpc = FakeRPC(recorded)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        _register(store, recorded)
        indexer = DepositIndexer(store, rpc, _config(recorded))
        assert indexer.poll_once() == 3

        refs = dict(store._db.execute("SELECT ref, amount FROM chain_refs ORDER BY ref"))
        assert refs == {
            "sig-checked:0": 5 * RATE,
            "sig-inner:2": 7 * RATE,
            "sig-transfer:0": 3 * RATE,
        }
        assert store.balance("alice") == 15 * RATE
        assert store._balance_in(store._db, "treasury") == -15 * RATE
        assert store._db.execute(
            "SELECT paused FROM chain_indexer_accounts"
        ).fetchone()[0] == 0


def test_replay_is_idempotent_and_restart_resumes_from_cursor(recorded, tmp_path):
    path = tmp_path / "ledger.sqlite"
    rpc = FakeRPC(recorded)
    with LedgerStore(path) as store:
        _register(store, recorded)
        indexer = DepositIndexer(store, rpc, _config(recorded))
        indexer.poll_once()
        assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 3

        # Force a full RPC replay: LedgerStore.deposit(ref) remains the last line of defence.
        store._db.execute("UPDATE chain_indexer_accounts SET cursor=NULL")
        assert indexer.poll_once() == 3
        assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 3
        assert store.balance("alice") == 15 * RATE

    restarted_rpc = FakeRPC(recorded)
    with LedgerStore(path) as reopened:
        restarted = DepositIndexer(reopened, restarted_rpc, _config(recorded))
        assert restarted.poll_once() == 0
        assert not [call for call in restarted_rpc.calls if call[0] == "transaction"]
        cursor = reopened._db.execute(
            "SELECT cursor FROM chain_indexer_accounts"
        ).fetchone()[0]
        assert cursor == "sig-failed"


@pytest.mark.parametrize("signature", ["sig-wrong-mint", "sig-outgoing", "sig-failed"])
def test_wrong_mint_outgoing_and_failed_transactions_are_ignored(
    recorded, tmp_path, signature
):
    recorded["signatures"] = [
        item for item in recorded["signatures"] if item["signature"] == signature
    ]
    rpc = FakeRPC(recorded, balance=0)
    with LedgerStore(tmp_path / f"{signature}.sqlite") as store:
        _register(store, recorded)
        assert DepositIndexer(store, rpc, _config(recorded)).poll_once() == 0
        assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 0
        assert store._db.execute(
            "SELECT paused FROM chain_indexer_accounts"
        ).fetchone()[0] == 0


def test_balance_mismatch_pauses_account_and_writes_alert(recorded, tmp_path, caplog):
    recorded["signatures"] = [
        item for item in recorded["signatures"] if item["signature"] == "sig-checked"
    ]
    rpc = FakeRPC(recorded, balance=4)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        _register(store, recorded)
        indexer = DepositIndexer(store, rpc, _config(recorded))
        assert indexer.poll_once() == 0

        state = store._db.execute(
            "SELECT paused, cursor FROM chain_indexer_accounts"
        ).fetchone()
        assert tuple(state) == (1, None)
        assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 0
        assert store.balance("alice") == 0
        alert = store._db.execute(
            "SELECT kind, expected, actual, detail FROM chain_indexer_alerts"
        ).fetchone()
        assert tuple(alert) == (
            "balance_mismatch",
            5,
            4,
            "on-chain balance does not equal indexed deposits",
        )
        calls = len(rpc.calls)
        assert indexer.poll_once() == 0
        assert len(rpc.calls) == calls
        assert "chain_indexer_alert" in caplog.text


def test_operator_unpause_refuses_mismatch_then_succeeds_and_audits(
    recorded, tmp_path
):
    rpc = FakeRPC(recorded, balance=9)
    account = recorded["addresses"]["deposit"]
    with LedgerStore(tmp_path / "unpause.sqlite") as store:
        _register(store, recorded)
        indexer = DepositIndexer(store, rpc, _config(recorded))
        assert [item.token_account for item in indexer._accounts()] == [account]
        store.deposit_batch(
            "alice", account, [("indexed:0", 15 * RATE, 1)], 15 * RATE
        )
        store.begin_sweep(
            "sweep", "alice", account, 5, "sweep-sig", "blockhash", 99
        )
        store.finalize_sweep("sweep")
        store._db.execute(
            "UPDATE chain_indexer_accounts SET paused=1 WHERE token_account=?",
            (account,),
        )
        store._db.execute(
            "INSERT INTO chain_indexer_alerts"
            "(ts, token_account, operator, kind, expected, actual, detail) "
            "VALUES (1, ?, 'alice', 'balance_mismatch', 10, 9, 'repair required')",
            (account,),
        )

        with pytest.raises(UnpauseRefused, match="expected 10, actual 9"):
            indexer.unpause_account(account, "fixed the missing transfer")
        assert store._db.execute(
            "SELECT paused FROM chain_indexer_accounts WHERE token_account=?",
            (account,),
        ).fetchone()[0] == 1
        assert store._db.execute(
            "SELECT COUNT(*) FROM chain_indexer_unpause_audit"
        ).fetchone()[0] == 0

        rpc.balance = 10
        result = indexer.unpause_account(account, "fixed the missing transfer")
        assert result["expected"] == result["actual"] == 10
        assert store._db.execute(
            "SELECT paused FROM chain_indexer_accounts WHERE token_account=?",
            (account,),
        ).fetchone()[0] == 0
        audit = store._db.execute(
            "SELECT token_account, reason, prior_alert "
            "FROM chain_indexer_unpause_audit"
        ).fetchone()
        assert audit["token_account"] == account
        assert audit["reason"] == "fixed the missing transfer"
        assert json.loads(audit["prior_alert"])["detail"] == "repair required"
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._db.execute("DELETE FROM chain_indexer_unpause_audit")


def test_unpause_cli_is_explicit_operator_subcommand(recorded):
    account = recorded["addresses"]["deposit"]
    args = _parser().parse_args(
        ["unpause", "--token-account", account, "--reason", "repaired"]
    )
    assert args.command == "unpause"
    assert args.token_account == account
    assert args.reason == "repaired"


def test_finalized_sweep_then_new_deposit_is_credited(recorded, tmp_path):
    recorded["signatures"] = [
        item for item in recorded["signatures"] if item["signature"] == "sig-checked"
    ]
    rpc = FakeRPC(recorded, balance=5)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        _register(store, recorded)
        account = recorded["addresses"]["deposit"]
        indexer = DepositIndexer(store, rpc, _config(recorded))
        assert [state.token_account for state in indexer._accounts()] == [account]
        store.deposit_batch("alice", account, [("old:0", 10 * RATE, 1)], 10 * RATE)
        store.begin_sweep("sweep", "alice", account, 10, "sweep-sig", "hash", 99)
        store.finalize_sweep("sweep")
        assert indexer.poll_once() == 1
        assert store.balance("alice") == 15 * RATE
        assert store._db.execute(
            "SELECT paused FROM chain_indexer_accounts WHERE token_account=?", (account,)
        ).fetchone()[0] == 0


def test_sent_sweep_defers_account_without_pause_or_cursor_advance(recorded, tmp_path):
    rpc = FakeRPC(recorded, balance=0)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        _register(store, recorded)
        account = recorded["addresses"]["deposit"]
        indexer = DepositIndexer(store, rpc, _config(recorded))
        assert [state.token_account for state in indexer._accounts()] == [account]
        store.begin_sweep("sweep", "alice", account, 10, "sweep-sig", "hash", 99)
        assert indexer.poll_once() == 0
        state = store._db.execute(
            "SELECT paused, cursor FROM chain_indexer_accounts WHERE token_account=?",
            (account,),
        ).fetchone()
        assert tuple(state) == (0, None)


def test_mainnet_and_malformed_keys_are_refused(recorded, tmp_path):
    with pytest.raises(ValueError, match="mainnet-beta is refused"):
        _config(recorded, cluster="mainnet-beta")
    with pytest.raises(ValueError, match="loopback"):
        _config(recorded, rpc_url="https://api.mainnet-beta.solana.com")
    with pytest.raises(ValueError, match="must use https"):
        IndexerConfig(
            cluster="devnet",
            mint=recorded["addresses"]["mint"],
            rpc_url="http://rpc.example.invalid",
        )
    with pytest.raises(ValueError, match="loopback"):
        _config(recorded, rpc_url="https://rpc.example.invalid")
    with pytest.raises(ValueError, match="different endpoint"):
        _config(
            recorded,
            confirm_rpc_url="http://127.0.0.1:18899/",
        )
    with LedgerStore(tmp_path / "mainnet.sqlite") as store:
        with pytest.raises(ValueError, match="mainnet-beta genesis"):
            DepositIndexer(
                store,
                FakeRPC(recorded, genesis=MAINNET_GENESIS_HASH),
                _config(recorded),
            )
    with pytest.raises(ValueError, match="32 bytes"):
        validate_pubkey("1234")
    assert len(decode_base58(recorded["addresses"]["mint"])) == 32


def test_signature_page_ceiling_never_advances_cursor(recorded, tmp_path):
    recorded["signatures"] = recorded["signatures"][:2]
    rpc = FakeRPC(recorded, balance=0)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        _register(store, recorded)
        config = _config(recorded, page_size=1, max_pages_per_account=1)
        assert DepositIndexer(store, rpc, config).poll_once() == 0
        assert store._db.execute(
            "SELECT cursor FROM chain_indexer_accounts"
        ).fetchone()[0] is None
        assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 0


def test_transient_rpc_failure_does_not_pause_account(recorded, tmp_path):
    class UnavailableRPC(FakeRPC):
        def get_token_account(self, address):
            raise RPCError("temporary local RPC failure")

    rpc = UnavailableRPC(recorded)
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        _register(store, recorded)
        indexer = DepositIndexer(store, rpc, _config(recorded))
        assert indexer.poll_once() == 0
        assert store._db.execute(
            "SELECT paused FROM chain_indexer_accounts"
        ).fetchone()[0] == 0
        assert store._db.execute(
            "SELECT COUNT(*) FROM chain_indexer_alerts"
        ).fetchone()[0] == 0


@pytest.mark.parametrize("malformation", ["meta", "err"])
def test_missing_meta_or_err_is_alerted_and_never_credited(
    recorded, tmp_path, malformation
):
    recorded["signatures"] = [
        item for item in recorded["signatures"] if item["signature"] == "sig-checked"
    ]
    if malformation == "meta":
        recorded["transactions"]["sig-checked"].pop("meta")
    else:
        recorded["transactions"]["sig-checked"]["meta"].pop("err")
    rpc = FakeRPC(recorded, balance=0)
    with LedgerStore(tmp_path / f"missing-{malformation}.sqlite") as store:
        _register(store, recorded)
        assert DepositIndexer(store, rpc, _config(recorded)).poll_once() == 0
        assert store.balance("alice") == 0
        assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 0
        state = store._db.execute(
            "SELECT cursor, paused FROM chain_indexer_accounts"
        ).fetchone()
        assert tuple(state) == ("sig-checked", 0)
        alert = store._db.execute(
            "SELECT kind, detail FROM chain_indexer_alerts"
        ).fetchone()
        assert alert["kind"] == "malformed_transaction"
        assert malformation in alert["detail"]


def test_confirm_rpc_transaction_disagreement_pauses_without_credit(recorded, tmp_path):
    recorded["signatures"] = [
        item for item in recorded["signatures"] if item["signature"] == "sig-checked"
    ]
    primary = FakeRPC(recorded, balance=5)
    confirmation = FakeRPC(recorded, balance=5)
    confirmation.transactions["sig-checked"]["slot"] = 999
    config = _config(recorded, confirm_rpc_url="http://127.0.0.1:18900")
    with LedgerStore(tmp_path / "confirm-transaction.sqlite") as store:
        _register(store, recorded)
        indexer = DepositIndexer(store, primary, config, confirmation)
        assert indexer.poll_once() == 0
        assert store.balance("alice") == 0
        assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 0
        assert store._db.execute(
            "SELECT paused FROM chain_indexer_accounts"
        ).fetchone()[0] == 1
        assert store._db.execute(
            "SELECT kind FROM chain_indexer_alerts"
        ).fetchone()[0] == "rpc_disagreement"


def test_confirm_rpc_balance_disagreement_pauses_without_credit(recorded, tmp_path):
    primary = FakeRPC(recorded, balance=15)
    confirmation = FakeRPC(recorded, balance=14)
    config = _config(recorded, confirm_rpc_url="http://127.0.0.1:18900")
    with LedgerStore(tmp_path / "confirm-balance.sqlite") as store:
        _register(store, recorded)
        indexer = DepositIndexer(store, primary, config, confirmation)
        assert indexer.poll_once() == 0
        assert store.balance("alice") == 0
        assert store._db.execute(
            "SELECT kind FROM chain_indexer_alerts"
        ).fetchone()[0] == "rpc_disagreement"


def test_genesis_is_pinned_for_devnet_and_confirm_must_match(recorded, tmp_path):
    config = IndexerConfig(
        cluster="devnet",
        mint=recorded["addresses"]["mint"],
        rpc_url="https://rpc.example.invalid",
        confirm_rpc_url="https://confirm.example.invalid",
    )
    with LedgerStore(tmp_path / "genesis.sqlite") as store:
        with pytest.raises(ValueError, match="confirmation RPC client"):
            DepositIndexer(
                store,
                FakeRPC(recorded, genesis=DEVNET_GENESIS_HASH),
                config,
            )
        with pytest.raises(ValueError, match="does not match expected"):
            DepositIndexer(
                store,
                FakeRPC(recorded),
                config,
                FakeRPC(recorded, genesis=DEVNET_GENESIS_HASH),
            )
        primary = FakeRPC(recorded, genesis=DEVNET_GENESIS_HASH)
        wrong = FakeRPC(recorded, genesis=recorded["addresses"]["mint"])
        with pytest.raises(ValueError, match="does not match expected"):
            DepositIndexer(store, primary, config, wrong)
        assert ("genesis",) in primary.calls
        assert ("genesis",) in wrong.calls


def test_paginates_more_than_one_thousand_signatures(recorded, tmp_path):
    records = [
        {
            "signature": f"page-{index}",
            "slot": 10_000 - index,
            "err": {"InstructionError": [0, "Custom"]},
            "confirmationStatus": "finalized",
        }
        for index in range(1001)
    ]
    failed = {
        "slot": 1,
        "transaction": {"message": {"instructions": []}},
        "meta": {"err": {"InstructionError": [0, "Custom"]}},
    }
    recorded["signatures"] = records
    recorded["transactions"] = {
        item["signature"]: deepcopy(failed) for item in records
    }
    rpc = FakeRPC(recorded, balance=0)
    config = _config(
        recorded,
        max_pages_per_account=2,
        max_rpc_calls_per_poll=1100,
    )
    with LedgerStore(tmp_path / "pagination.sqlite") as store:
        _register(store, recorded)
        assert DepositIndexer(store, rpc, config).poll_once() == 0
        assert store._db.execute(
            "SELECT cursor FROM chain_indexer_accounts"
        ).fetchone()[0] == "page-0"
        signature_calls = [call for call in rpc.calls if call[0] == "signatures"]
        assert len(signature_calls) == 2
        assert signature_calls[1][2] == "page-999"


def test_user_unit_contains_required_supported_hardening():
    unit = (
        Path(__file__).parents[1] / "chain" / "systemd" / "nak-indexer.service"
    ).read_text()
    for directive in (
        "UMask=0077",
        "NoNewPrivileges=yes",
        "ProtectHome=tmpfs",
        "BindPaths=%h/.neuron/credits",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "LockPersonality=yes",
        "RestrictRealtime=yes",
        "SystemCallFilter=@system-service",
        "DevicePolicy=closed",
        "InaccessiblePaths=/dev",
    ):
        assert directive in unit
    assert "ExecStart=/usr/bin/python3 /home/" not in unit


def test_treasury_unit_avoids_user_namespace_sandboxing():
    unit = (
        Path(__file__).parents[1] / "chain" / "systemd" / "nak-treasury.service"
    ).read_text()
    directives = {
        line.split("=", 1)[0]
        for line in unit.splitlines()
        if line and not line.startswith("#") and "=" in line
    }
    # Each of these makes a user manager map root-owned trust pins to nobody.
    for directive in ("PrivateTmp", "ProtectSystem", "ProtectHome", "ReadWritePaths"):
        assert directive not in directives
    for directive in (
        "UMask=0077",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "SystemCallFilter=@system-service",
    ):
        assert directive in unit
