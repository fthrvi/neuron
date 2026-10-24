"""Frozen-operator rebroadcast guard for `sent` withdrawals (runs without solders)."""
import os
import sys
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:  # chain.payout needs solders at import time; only its logic is under test here.
    import solders  # noqa: F401
except ImportError:
    for _name in (
        "solders", "solders.hash", "solders.instruction", "solders.keypair",
        "solders.message", "solders.pubkey", "solders.system_program",
        "solders.token", "solders.token.associated", "solders.transaction",
    ):
        sys.modules.setdefault(_name, mock.MagicMock())

from chain.payout import PayoutEngine  # noqa: E402
from core.ledger_store import LedgerStore  # noqa: E402


class _RPC:
    def __init__(self, status=None, height=5):
        self.status, self.height, self.sent = status, height, []

    def get_signature_status(self, sig):
        return self.status

    def get_block_height(self):
        return self.height

    def send_transaction(self, wire):
        self.sent.append(wire)
        return "sig"


def _engine(rpc):
    store = mock.Mock()
    return SimpleNamespace(rpc=rpc, store=store, _may_act=lambda: None), store


ROW = {"id": "w1", "tx_sig": "sig", "tx_wire": "wire", "last_valid_block_height": 10}


def test_frozen_sent_row_is_not_rebroadcast():
    rpc = _RPC()
    eng, _ = _engine(rpc)
    assert PayoutEngine._advance_sent(eng, ROW, frozen=True) == 0
    assert rpc.sent == []


def test_unfrozen_sent_row_still_rebroadcasts():
    rpc = _RPC()
    eng, _ = _engine(rpc)
    PayoutEngine._advance_sent(eng, ROW, frozen=False)
    assert rpc.sent == ["wire"]


def test_frozen_sent_row_still_finalizes_and_expires():
    rpc = _RPC(status={"confirmationStatus": "finalized", "err": None})
    eng, store = _engine(rpc)
    assert PayoutEngine._advance_sent(eng, ROW, frozen=True) == 1
    store.withdraw_finalize.assert_called_once_with("w1")

    rpc = _RPC(status=None, height=11)
    eng, store = _engine(rpc)
    assert PayoutEngine._advance_sent(eng, ROW, frozen=True) == 1
    store.withdraw_mark_expired.assert_called_once_with("w1")
    assert rpc.sent == []


def test_frozen_sent_page_cannot_starve_unfrozen_row(tmp_path):
    advanced = []
    with LedgerStore(tmp_path / "ledger.sqlite") as store:
        store._db.executemany(
            "INSERT INTO withdrawals(id, operator, amount, address, state, "
            "created_ts, updated_ts) VALUES (?, ?, 1, 'addr', 'sent', ?, ?)",
            [
                (f"frozen-{index:03d}", "frozen", index, index)
                for index in range(101)
            ]
            + [("zz-normal", "normal", 999, 999)],
        )
        engine = SimpleNamespace(
            config=SimpleNamespace(
                kill_file=tmp_path / "payout.off", enabled=True
            ),
            store=store,
            _frozen_operators=lambda: {"frozen"},
            _approve_pending=lambda _frozen: 0,
            _create_deposit_accounts=lambda: 0,
            _advance_sent=lambda row, *, frozen: advanced.append(
                (row["id"], frozen)
            ) or 0,
            _build_and_send=lambda _row: 0,
        )

        assert PayoutEngine.poll_once(engine) == 0
        assert advanced == [("zz-normal", False)]
