"""Unit tests against captured jsonParsed Solana RPC shapes."""
import json
import os
import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chain.indexer import DepositIndexer, IndexerConfig  # noqa: E402
from chain.solana_rpc import RPCError, decode_base58, validate_pubkey  # noqa: E402
from core.ledger_store import RATE, LedgerStore  # noqa: E402


FIXTURE = Path(__file__).parent / "fixtures" / "solana_indexer.json"


class FakeRPC:
    def __init__(self, fixture, *, balance=15):
        self.addresses = fixture["addresses"]
        self.signatures = deepcopy(fixture["signatures"])
        self.transactions = deepcopy(fixture["transactions"])
        self.balance = balance
        self.calls = []

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
        assert store.balance("treasury") == -15 * RATE
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
        assert indexer.poll_once() == 1

        state = store._db.execute(
            "SELECT paused, cursor FROM chain_indexer_accounts"
        ).fetchone()
        assert tuple(state) == (1, "sig-checked")
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


def test_mainnet_and_malformed_keys_are_refused(recorded):
    with pytest.raises(ValueError, match="mainnet-beta is refused"):
        _config(recorded, cluster="mainnet-beta")
    with pytest.raises(ValueError, match="mainnet RPC"):
        _config(recorded, rpc_url="https://api.mainnet-beta.solana.com")
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
