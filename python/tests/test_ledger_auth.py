"""Pure tests for signed ledger envelopes and Nakshatra run receipts."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))

from ledger_auth import (  # noqa: E402
    InMemoryNonceStore,
    ReceiptError,
    SettlementFrozen,
    canonical_string,
    load_roster,
    verify_envelope,
    verify_receipt,
)


def _keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return private, public_hex


def _row(pubkey, name, operator, tier="known"):
    return {
        "pubkey": pubkey,
        "name": name,
        "operator": operator,
        "tier": tier,
        "tenant": "test",
        "coord": None,
    }


def _auth_header(private, keyid, method, path, body, timestamp):
    signature = private.sign(canonical_string(method, path, body, timestamp))
    encoded = base64.b64encode(signature).decode("ascii")
    return f'Sthambha-Ed25519 keyid="{keyid}",sig="{encoded}",ts="{timestamp}"'


def _receipt(run_id="run-1", tokens=(10, 11, 12, 13)):
    generated = list(tokens)
    output_hash = hashlib.sha256(
        ",".join(str(token) for token in generated).encode("utf-8")
    ).hexdigest()
    return {
        "v": 1,
        "run_id": run_id,
        "n_generated": len(generated),
        "generated_tokens": generated,
        "output_sha256": output_hash,
        "chain": [
            {"node_id": "worker-a", "layer_start": 0, "layer_end": 8},
            {"node_id": "worker-b", "layer_start": 8, "layer_end": 24},
        ],
        "worker_signatures": [],
    }


def _participation(private, pubkey, receipt, node_id, start, end, *, output_hash=None):
    output_hash = output_hash or receipt["output_sha256"]
    message = (
        f'{receipt["run_id"]}|{node_id}|[{start},{end})|{output_hash}'
    ).encode("utf-8")
    return {
        "node_id": node_id,
        "pubkey": pubkey,
        "layer_start": start,
        "layer_end": end,
        "sig": base64.b64encode(private.sign(message)).decode("ascii"),
    }


@pytest.fixture
def identities():
    requester_private, requester_pub = _keypair()
    worker_a_private, worker_a_pub = _keypair()
    worker_b_private, worker_b_pub = _keypair()
    roster = {
        requester_pub: _row(requester_pub, "requester-node", "alice", "trusted"),
        worker_a_pub: _row(worker_a_pub, "worker-a", "bob"),
        worker_b_pub: _row(worker_b_pub, "worker-b", "carol"),
    }
    return {
        "requester": (requester_private, requester_pub),
        "worker_a": (worker_a_private, worker_a_pub),
        "worker_b": (worker_b_private, worker_b_pub),
        "roster": roster,
    }


def test_unsigned_envelope_gives_none(identities):
    _, requester_pub = identities["requester"]
    assert verify_envelope(
        {}, "POST", "/settle", b"{}", identities["roster"], InMemoryNonceStore(), 100
    ) is None


def test_wrong_key_gives_none(identities):
    wrong_private, _ = _keypair()
    _, requester_pub = identities["requester"]
    body = b'{"receipt":{}}'
    headers = {
        "Authorization": _auth_header(
            wrong_private, requester_pub, "POST", "/settle", body, 100
        )
    }
    assert verify_envelope(
        headers, "POST", "/settle", body, identities["roster"], InMemoryNonceStore(), 100
    ) is None


def test_stale_timestamp_gives_none(identities):
    private, requester_pub = identities["requester"]
    body = b"{}"
    headers = {
        "Authorization": _auth_header(private, requester_pub, "POST", "/settle", body, 100)
    }
    assert verify_envelope(
        headers, "POST", "/settle", body, identities["roster"], InMemoryNonceStore(), 161
    ) is None


def test_replayed_signature_gives_none(identities):
    private, requester_pub = identities["requester"]
    body = b"{}"
    headers = {
        "authorization": _auth_header(private, requester_pub, "POST", "/settle", body, 100)
    }
    nonces = InMemoryNonceStore()
    assert verify_envelope(
        headers, "POST", "/settle", body, identities["roster"], nonces, 100
    ) == requester_pub
    assert verify_envelope(
        headers, "POST", "/settle", body, identities["roster"], nonces, 100
    ) is None


def test_tampered_body_gives_none(identities):
    private, requester_pub = identities["requester"]
    signed_body = json.dumps({"amount": 1}).encode("utf-8")
    headers = {
        "Authorization": _auth_header(
            private, requester_pub, "POST", "/transfer", signed_body, 100
        )
    }
    assert verify_envelope(
        headers,
        "POST",
        "/transfer",
        json.dumps({"amount": 2}).encode("utf-8"),
        identities["roster"],
        InMemoryNonceStore(),
        100,
    ) is None


def test_unrostered_signer_gives_none(identities):
    private, public = _keypair()
    body = b"{}"
    headers = {
        "Authorization": _auth_header(private, public, "POST", "/settle", body, 100)
    }
    assert verify_envelope(
        headers, "POST", "/settle", body, identities["roster"], InMemoryNonceStore(), 100
    ) is None


def test_forged_receipt_without_worker_signatures_credits_nothing(identities):
    _, requester_pub = identities["requester"]
    receipt = _receipt()
    receipt_id, credited, units = verify_receipt(receipt, requester_pub, identities["roster"])
    assert len(receipt_id) == 64
    assert credited == {}
    assert units == 0


def test_unrostered_worker_key_credits_nothing(identities):
    _, requester_pub = identities["requester"]
    outsider_private, outsider_pub = _keypair()
    receipt = _receipt()
    receipt["worker_signatures"] = [
        _participation(outsider_private, outsider_pub, receipt, "worker-a", 0, 8)
    ]
    _, credited, units = verify_receipt(receipt, requester_pub, identities["roster"])
    assert credited == {}
    assert units == 0


def test_valid_receipt_credits_exactly_signed_stages(identities):
    _, requester_pub = identities["requester"]
    worker_a_private, worker_a_pub = identities["worker_a"]
    receipt = _receipt()
    receipt["worker_signatures"] = [
        _participation(worker_a_private, worker_a_pub, receipt, "worker-a", 0, 8)
    ]
    _, credited, units = verify_receipt(receipt, requester_pub, identities["roster"])
    assert credited == {"bob": 4 * 8}
    assert units == 4 * 8


def test_two_genuine_runs_of_identical_output_are_distinct_receipts(identities):
    """Deterministic output: two real runs of one prompt must both be payable (distinct ids)."""
    _, requester_pub = identities["requester"]
    first_id, _, _ = verify_receipt(_receipt("run-one"), requester_pub, identities["roster"])
    second_id, _, _ = verify_receipt(_receipt("run-two"), requester_pub, identities["roster"])
    assert first_id != second_id


def test_replaying_one_signed_run_under_a_new_run_id_credits_nothing(identities):
    """The double-credit attack the old content key prevented: still prevented, by the signature."""
    _, requester_pub = identities["requester"]
    worker_a_private, worker_a_pub = identities["worker_a"]
    real = _receipt("run-real")
    sig = _participation(worker_a_private, worker_a_pub, real, "worker-a", 0, 8)
    replay = _receipt("run-invented")
    replay["worker_signatures"] = [sig]          # the signature binds run-real, not run-invented
    assert verify_receipt(replay, requester_pub, identities["roster"])[1] == {}


def test_signature_for_different_output_hash_is_rejected(identities):
    _, requester_pub = identities["requester"]
    worker_a_private, worker_a_pub = identities["worker_a"]
    receipt = _receipt()
    receipt["worker_signatures"] = [
        _participation(
            worker_a_private,
            worker_a_pub,
            receipt,
            "worker-a",
            0,
            8,
            output_hash="0" * 64,
        )
    ]
    _, credited, units = verify_receipt(receipt, requester_pub, identities["roster"])
    assert credited == {}
    assert units == 0


def test_structurally_invalid_receipt_is_rejected(identities):
    _, requester_pub = identities["requester"]
    receipt = _receipt()
    receipt["chain"][1]["layer_start"] = 9
    with pytest.raises(ReceiptError, match="gap or overlap"):
        verify_receipt(receipt, requester_pub, identities["roster"])


def test_roster_loader_skips_comments_blank_and_short_rows(tmp_path):
    _, first_pub = _keypair()
    _, second_pub = _keypair()
    roster_path = tmp_path / "peers.tsv"
    roster_path.write_text(
        "# admission roster\n\n"
        f"{first_pub}\tworker-a\tbob\ttrusted\ttenant-a\t10.0.0.1:9000\n"
        "too short\n"
        f"{second_pub} worker-b carol mystery tenant-b\n",
        encoding="utf-8",
    )
    roster = load_roster(roster_path)
    assert roster[first_pub] == {
        "pubkey": first_pub,
        "name": "worker-a",
        "operator": "bob",
        "tier": "trusted",
        "tenant": "tenant-a",
        "coord": "10.0.0.1:9000",
    }
    assert roster[second_pub]["tier"] == "stranger"
    assert roster[second_pub]["coord"] is None


def test_roster_loader_preserves_suspended_tier(tmp_path):
    _, suspended_pub = _keypair()
    roster_path = tmp_path / "peers.tsv"
    roster_path.write_text(
        f"{suspended_pub}\tsuspended-node\talice\tsuspended\ttenant-a\n",
        encoding="utf-8",
    )

    assert load_roster(roster_path)[suspended_pub]["tier"] == "suspended"


@pytest.mark.parametrize("tier", ["Suspended", "SUSPENDED", "suspended ", " Suspended"])
def test_roster_loader_normalises_suspended_variants(tmp_path, tier):
    _, pub = _keypair()
    roster_path = tmp_path / "peers.tsv"
    roster_path.write_text(f"{pub}\tn\talice\t{tier}\ttenant-a\n", encoding="utf-8")

    assert load_roster(roster_path)[pub]["tier"] == "suspended"


@pytest.mark.parametrize("tier", ["SELF", "Self", "TRUSTED", "Trusted", "Known", "banned"])
def test_roster_loader_does_not_widen_non_exact_tiers(tmp_path, tier):
    # Only "suspended" is case-normalised; any other non-exact tier stays stranger.
    _, pub = _keypair()
    roster_path = tmp_path / "peers.tsv"
    roster_path.write_text(f"{pub}\tn\talice\t{tier}\tt\n", encoding="utf-8")

    assert load_roster(roster_path)[pub]["tier"] == "stranger"


@pytest.mark.parametrize("tier", ["self", "trusted", "known", "stranger"])
def test_roster_loader_exact_tiers_unchanged(tmp_path, tier):
    _, pub = _keypair()
    roster_path = tmp_path / "peers.tsv"
    roster_path.write_text(f"{pub}\tn\talice\t{tier}\tt\n", encoding="utf-8")

    assert load_roster(roster_path)[pub]["tier"] == tier


@pytest.mark.parametrize("tier", ["suspended", "Suspended", "SUSPENDED", " suspended "])
def test_suspended_worker_signature_freezes_whole_receipt(identities, tier):
    _, requester_pub = identities["requester"]
    a_private, a_pub = identities["worker_a"]
    roster = {k: dict(v) for k, v in identities["roster"].items()}
    roster[a_pub]["tier"] = tier
    receipt = _receipt()
    receipt["worker_signatures"] = [
        _participation(a_private, a_pub, receipt, "worker-a", 0, 8)
    ]
    with pytest.raises(
        SettlementFrozen,
        match="a participant is suspended; settlement is frozen",
    ):
        verify_receipt(receipt, requester_pub, roster)


def test_suspended_worker_freezes_other_valid_worker_shares_too(identities):
    _, requester_pub = identities["requester"]
    a_private, a_pub = identities["worker_a"]
    b_private, b_pub = identities["worker_b"]
    roster = {k: dict(v) for k, v in identities["roster"].items()}
    roster[a_pub]["tier"] = "suspended"
    receipt = _receipt()
    receipt["worker_signatures"] = [
        _participation(a_private, a_pub, receipt, "worker-a", 0, 8),
        _participation(b_private, b_pub, receipt, "worker-b", 8, 24),
    ]
    with pytest.raises(SettlementFrozen):
        verify_receipt(receipt, requester_pub, roster)


def test_suspended_sibling_key_freezes_operator_receipt_share(identities):
    _, requester_pub = identities["requester"]
    a_private, a_pub = identities["worker_a"]
    _, sibling_pub = _keypair()
    roster = {k: dict(v) for k, v in identities["roster"].items()}
    roster[sibling_pub] = _row(
        sibling_pub, "worker-a-suspended", "bob", "suspended"
    )
    receipt = _receipt()
    receipt["worker_signatures"] = [
        _participation(a_private, a_pub, receipt, "worker-a", 0, 8)
    ]

    with pytest.raises(SettlementFrozen):
        verify_receipt(receipt, requester_pub, roster)


def test_roster_loader_skips_short_row_so_key_is_not_admitted(tmp_path):
    # Documents current behaviour: <5 fields => row dropped, key unrostered.
    _, pub = _keypair()
    roster_path = tmp_path / "peers.tsv"
    roster_path.write_text(f"{pub}\tn\talice\tsuspended\n", encoding="utf-8")

    assert pub not in load_roster(roster_path)


def test_roster_loader_warns_and_ignores_reserved_operators(tmp_path):
    _, treasury_pub = _keypair()
    _, hold_pub = _keypair()
    _, valid_pub = _keypair()
    roster_path = tmp_path / "peers.tsv"
    roster_path.write_text(
        f"{treasury_pub}\tnode-a\ttreasury\tself\ttenant-a\n"
        f"{hold_pub}\tnode-b\t__withdrawal_hold__spoof\tknown\ttenant-b\n"
        f"{valid_pub}\tnode-c\talice\ttrusted\ttenant-c\n",
        encoding="utf-8",
    )

    with pytest.warns(RuntimeWarning, match="operator .* is reserved") as caught:
        roster = load_roster(roster_path)

    assert len(caught) == 2
    assert set(roster) == {valid_pub}
    assert roster[valid_pub]["operator"] == "alice"


def test_release_worker_shape_short_chain_id_and_pubkey_node_id_is_credited():
    """The real shape (bro, 2026-10-13): the chain names the stage by a 14-hex SHORT id, the worker
    signs with its full node id == its public key, and the roster name is a human label."""
    req_private, req_pub = _keypair()
    w_private, w_pub = _keypair()
    roster = {req_pub: _row(req_pub, "hub-node", "self", "self"),
              w_pub: _row(w_pub, "bro", "op-bro", "known")}
    receipt = _receipt()
    receipt["chain"] = [{"node_id": w_pub[:14], "layer_start": 0, "layer_end": 28}]
    receipt["worker_signatures"] = [_participation(w_private, w_pub, receipt, w_pub, 0, 28)]
    _, credited, units = verify_receipt(receipt, req_pub, roster)
    assert credited == {"op-bro": 4 * 28} and units == 4 * 28


def test_short_id_match_never_crosses_layer_ranges_or_short_prefixes():
    req_private, req_pub = _keypair()
    w_private, w_pub = _keypair()
    roster = {req_pub: _row(req_pub, "hub-node", "self", "self"),
              w_pub: _row(w_pub, "bro", "op-bro", "known")}
    receipt = _receipt()
    # a different layer range than the signed one: nothing is credited
    receipt["chain"] = [{"node_id": w_pub[:14], "layer_start": 0, "layer_end": 20},
                        {"node_id": "other-node", "layer_start": 20, "layer_end": 28}]
    receipt["worker_signatures"] = [_participation(w_private, w_pub, receipt, w_pub, 0, 28)]
    assert verify_receipt(receipt, req_pub, roster)[1] == {}
    # an id prefix shorter than 12 hex chars never matches
    receipt["chain"] = [{"node_id": w_pub[:8], "layer_start": 0, "layer_end": 28}]
    receipt["worker_signatures"] = [_participation(w_private, w_pub, receipt, w_pub, 0, 28)]
    assert verify_receipt(receipt, req_pub, roster)[1] == {}


def test_a_signer_cannot_claim_another_nodes_short_id():
    """A rostered key signing as a node id that is NOT its own key and NOT its roster name earns nothing."""
    req_private, req_pub = _keypair()
    w_private, w_pub = _keypair()
    victim_private, victim_pub = _keypair()
    roster = {req_pub: _row(req_pub, "hub-node", "self", "self"),
              w_pub: _row(w_pub, "bro", "op-bro", "known"),
              victim_pub: _row(victim_pub, "victim", "op-victim", "known")}
    receipt = _receipt()
    receipt["chain"] = [{"node_id": victim_pub[:14], "layer_start": 0, "layer_end": 28}]
    receipt["worker_signatures"] = [_participation(w_private, w_pub, receipt, victim_pub, 0, 28)]
    assert verify_receipt(receipt, req_pub, roster)[1] == {}
