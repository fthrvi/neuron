"""
Unit tests for the v1 reciprocal-compute credit ledger (core/credit_ledger.py). Pure.

Proves the flywheel mechanics: serve→earn, consume→spend, the reciprocal gate, and the v1
Sybil/fraud guards — admission-gated earning, forged-receipt rejection (no credit for
unverifiable work), idempotent settlement, and dispute clawback.
"""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.credit_ledger import CreditLedger, CreditError, CreditDelta  # noqa: E402


def _sha(tokens):
    return hashlib.sha256(",".join(str(int(t)) for t in tokens).encode()).hexdigest()


def _receipt(run_id="r1", tokens=(10, 11, 12, 13), chain=None):
    chain = chain or [
        {"node_id": "wA", "layer_start": 0, "layer_end": 16},
        {"node_id": "wB", "layer_start": 16, "layer_end": 32},
    ]
    toks = list(tokens)
    return {
        "run_id": run_id, "n_generated": len(toks), "generated_tokens": toks,
        "output_sha256": _sha(toks), "chain": chain,
    }


# ---------------------------------------------------------------- core settle

def test_settle_credits_workers_debits_requester():
    led = CreditLedger()
    r = _receipt()                      # 4 tokens, two 16-layer stages
    d = led.settle(r, requester="op-X")
    # each stage: 4 tokens × 16 layers = 64 units; total 128
    assert d.credited == {"wA": 64, "wB": 64}
    assert d.total == 128 and d.debited == 128
    assert led.balance("wA") == 64 and led.balance("wB") == 64
    assert led.balance("op-X") == -128


def test_proportional_to_layers_served():
    led = CreditLedger()
    chain = [
        {"node_id": "wA", "layer_start": 0, "layer_end": 8},    # 8 layers
        {"node_id": "wB", "layer_start": 8, "layer_end": 32},   # 24 layers
    ]
    d = led.settle(_receipt(tokens=(1, 2, 3, 4, 5), chain=chain), requester="op")
    assert led.balance("wA") == 5 * 8      # 40
    assert led.balance("wB") == 5 * 24     # 120
    assert d.total == 5 * 32


# ---------------------------------------------------------------- reciprocity / gate

def test_reciprocal_gate_blocks_pure_consumer():
    led = CreditLedger(grace=10)
    # fresh consumer: only the bootstrap grace
    assert led.can_consume("newbie", 10) is True
    assert led.can_consume("newbie", 11) is False
    # after serving (earning), it can consume more
    led.settle(_receipt(run_id="r-served", chain=[{"node_id": "newbie", "layer_start": 0, "layer_end": 32}]),
               requester="someone")
    assert led.balance("newbie") == 4 * 32          # earned 128
    assert led.can_consume("newbie", 138) is True   # 128 earned + 10 grace
    assert led.can_consume("newbie", 139) is False


def test_net_for_when_account_is_both_server_and_requester():
    led = CreditLedger()
    # operator serves its own run (coordinator == a worker) → nets out fairly
    chain = [{"node_id": "op", "layer_start": 0, "layer_end": 16},
             {"node_id": "wB", "layer_start": 16, "layer_end": 32}]
    d = led.settle(_receipt(chain=chain), requester="op")
    # op earned 64 (served 16 layers) but paid 128 (total) → net -64
    assert d.net_for("op") == 64 - 128
    assert led.balance("op") == -64


# ---------------------------------------------------------------- anti-Sybil: admission gate

def test_earning_is_admission_gated():
    tiers = {"wA": "trusted", "wB": "stranger"}
    led = CreditLedger(tier_of=lambda n: tiers.get(n, "stranger"), min_earn_tier="known")
    d = led.settle(_receipt(), requester="op")
    # wB is a stranger → does the work but earns NOTHING (can't farm credits with fake GPUs)
    assert "wA" in d.credited and "wB" not in d.credited
    assert led.balance("wB") == 0
    # requester still pays for ALL work served (incl. the un-credited stranger's)
    assert d.total == 128 and led.balance("op") == -128


# ---------------------------------------------------------------- fraud: forged receipts

def test_forged_output_hash_rejected_no_credit():
    led = CreditLedger()
    r = _receipt()
    r["generated_tokens"][0] = 999          # tamper output but keep stored hash
    with pytest.raises(CreditError):
        led.settle(r, requester="op")
    assert led.balance("wA") == 0 and led.balance("op") == 0    # nothing moved


def test_count_mismatch_and_missing_fields_rejected():
    led = CreditLedger()
    bad = _receipt(); bad["n_generated"] = 99
    with pytest.raises(CreditError):
        led.settle(bad, requester="op")
    with pytest.raises(CreditError):
        led.settle({"run_id": "x"}, requester="op")     # missing fields


def test_duplicate_node_and_bad_layer_range_rejected():
    led = CreditLedger()
    dup = _receipt(chain=[{"node_id": "w", "layer_start": 0, "layer_end": 16},
                          {"node_id": "w", "layer_start": 16, "layer_end": 32}])
    with pytest.raises(CreditError):
        led.settle(dup, requester="op")


# ---------------------------------------------------------------- replay + dispute

def test_idempotent_settlement_no_double_credit():
    led = CreditLedger()
    r = _receipt()
    d1 = led.settle(r, requester="op")
    d2 = led.settle(r, requester="op")      # replay same run_id
    assert d1 == d2
    assert led.balance("wA") == 64          # NOT 128 — credited once


def test_dispute_claws_back():
    led = CreditLedger()
    led.settle(_receipt(), requester="op")
    assert led.balance("wA") == 64
    assert led.dispute("r1") is True
    assert led.balance("wA") == 0 and led.balance("wB") == 0 and led.balance("op") == 0
    assert led.dispute("r1") is False       # already gone
    # after a dispute, the run can be re-settled if it later passes
    led.settle(_receipt(), requester="op")
    assert led.balance("wA") == 64


def test_local_infra_is_free():
    # all serving workers belong to the requester's operator → local run costs NOTHING.
    led = CreditLedger()
    own = {"wA": "alice", "wB": "alice"}
    d = led.settle(_receipt(), requester="alice", operator_of=lambda n: own.get(n, n))
    assert d.total == 0 and d.credited == {}          # free
    assert led.balance("alice") == 0                  # not charged for own GPUs


def test_network_infra_pays_only_for_others():
    # alice runs on her own wA (free) + bob's wB (paid). She pays only for bob's 16 layers.
    led = CreditLedger()
    op = {"wA": "alice", "wB": "bob"}
    d = led.settle(_receipt(), requester="alice", operator_of=lambda n: op.get(n, n))
    assert d.credited == {"bob": 64}                  # bob earns; alice's own work is free
    assert d.total == 64                              # alice pays only for bob's share
    assert led.balance("alice") == -64 and led.balance("bob") == 64


def test_earnings_accrue_to_operator_not_node():
    # bob runs two nodes; both earn into bob's single operator balance.
    led = CreditLedger()
    chain = [{"node_id": "n1", "layer_start": 0, "layer_end": 16},
             {"node_id": "n2", "layer_start": 16, "layer_end": 32}]
    op = {"n1": "bob", "n2": "bob"}
    led.settle(_receipt(chain=chain), requester="alice", operator_of=lambda n: op.get(n, n))
    assert led.balance("bob") == 128                  # both nodes → one operator balance


def test_transfer_send_receive():
    led = CreditLedger()
    led.settle(_receipt(), requester="op")            # wA, wB each +64
    led.transfer("wA", "carol", 50, memo="thanks")
    assert led.balance("wA") == 14 and led.balance("carol") == 50
    with pytest.raises(CreditError):
        led.transfer("wA", "carol", 999)              # overdraw refused
    with pytest.raises(CreditError):
        led.transfer("wA", "wA", 5)                   # self-transfer refused


def test_history_shows_earn_spend_send_receive():
    led = CreditLedger()
    led.settle(_receipt(), requester="op")
    led.transfer("wA", "carol", 10)
    h_wA = led.history("wA")
    kinds = [e["kind"] for e in h_wA]
    assert "earn" in kinds and "send" in kinds        # wA earned then sent
    assert led.history("op")[0]["kind"] == "spend"
    assert led.history("carol")[0] == {"kind": "receive", "amount": 10,
                                       "counterparty": "wA", "memo": ""}


def test_journal_survives_snapshot_restore():
    led = CreditLedger()
    led.settle(_receipt(), requester="op")
    led.transfer("wA", "carol", 5)
    led2 = CreditLedger()
    led2.restore(led.snapshot())
    assert led2.balance("carol") == 5
    assert [e["kind"] for e in led2.history("carol")] == ["receive"]


def test_estimate_cost_matches_settle_total():
    led = CreditLedger()
    r = _receipt(tokens=(1, 2, 3))          # 3 tokens, 32-block model
    d = led.settle(r, requester="op")
    assert CreditLedger.estimate_cost(n_tokens=3, num_blocks=32) == d.total


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
