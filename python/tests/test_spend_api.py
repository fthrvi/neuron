"""N3 signed loopback spend routes, opaque claims, and deadline behavior."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ledger_store import (  # noqa: E402
    SPEND_EXECUTION_S,
    SPEND_SETTLEMENT_GRACE_S,
    LedgerValueError,
    SpendConflict,
    SpendExpired,
)
from ledger_auth import canonical_string  # noqa: E402
from ledger_server import V2LedgerService, _make_v2_handler  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402


def _identity(label: str) -> dict[str, object]:
    private = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode()).digest()
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return {"private": private, "public": public}


@pytest.fixture
def identities(tmp_path):
    result = {}
    rows = []
    for label, operator, tier in (
        ("payer", "payer", "trusted"),
        ("worker", "worker", "known"),
        ("worker2", "worker2", "known"),
        ("outsider", "outsider", "known"),
    ):
        result[label] = _identity(label)
        rows.append(
            f"{result[label]['public']}\t{label}\t{operator}\t{tier}\ttest"
        )
    roster = tmp_path / "roster.tsv"
    roster.write_text("\n".join(rows) + "\n", encoding="utf-8")
    result["roster"] = roster
    return result


def _authorize_body(identities, *, nonce="nonce", session="session", workers=None):
    return {
        "client_nonce": nonce,
        "session_id": session,
        "model_id": "model",
        "billing_mode": "greedy-direct-v1",
        "max_prompt_tokens": 5,
        "max_output_tokens": 5,
        "workers": workers or [
            {
                "worker_keyid": identities["worker"]["public"],
                "layer_start": 0,
                "layer_end": 4,
            }
        ],
    }


def _usage(service, claim, private, *, prompt=2, generated=1, final=True,
           completed_at=None):
    layers = claim["layer_end"] - claim["layer_start"]
    token_layers = (prompt + generated) * layers
    receipt = {
        "v": 2,
        "kind": "nakshatra-worker-usage",
        "receipt_id": "",
        "hold_id": claim["hold_id"],
        "claim_response_sha256": claim["claim_response_sha256"],
        "payer_keyid": claim["payer_keyid"],
        "payer_account_at_authorize": claim["payer_account_at_authorize"],
        "worker_keyid": claim["worker_keyid"],
        "worker_account_at_authorize": claim["worker_account_at_authorize"],
        "billable": claim["billable"],
        "session_id": claim["session_id"],
        "model_id": claim["model_id"],
        "billing_mode": claim["billing_mode"],
        "layer_start": claim["layer_start"],
        "layer_end": claim["layer_end"],
        "sequence": 1,
        "cumulative_prompt_tokens": prompt,
        "cumulative_generated_tokens": generated,
        "cumulative_token_layers": token_layers,
        "cumulative_cost": token_layers * claim["price_multiplier"],
        "work_completed_at": (
            claim["execution_deadline"] if completed_at is None else completed_at
        ),
        "final": final,
        "termination": "completed" if final else "checkpoint",
        "output_sha256": "",
    }
    receipt["receipt_id"] = service.store.spend_receipt_id(receipt)
    canonical = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return {"receipt": receipt, "signature": private.sign(canonical).hex()}


def _service(tmp_path, identities, clock, **kwargs):
    return V2LedgerService(
        tmp_path / "ledger.sqlite",
        identities["roster"],
        clock=lambda: clock[0],
        token_key_path=tmp_path / "token.key",
        start_sweeper=False,
        **kwargs,
    )


def test_opaque_claim_is_worker_bound_persisted_and_restart_idempotent(
    tmp_path, identities
):
    clock = [1_000_000]
    body = _authorize_body(identities)
    payer = identities["payer"]["public"]
    worker = identities["worker"]["public"]
    service = _service(tmp_path, identities, clock)
    try:
        roster = service.rosters.snapshot()
        authorization = service.authorize_spend(body, payer, roster)
        token = authorization["claim_token"]
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        row = service.store._db.execute(
            "SELECT token_digest FROM spend_holds WHERE hold_id=?",
            (authorization["hold_id"],),
        ).fetchone()
        recovery = service.store._db.execute(
            "SELECT sealed_token FROM spend_authorize_recovery WHERE hold_id=?",
            (authorization["hold_id"],),
        ).fetchone()
        assert row["token_digest"] == token_digest
        assert token not in recovery["sealed_token"]
        assert token.encode() not in (tmp_path / "ledger.sqlite").read_bytes()
        assert (tmp_path / "token.key").stat().st_mode & 0o777 == 0o600

        with pytest.raises(PermissionError, match="listed worker"):
            service.claim_spend(
                {"claim_token": token, "claim_instance": "wrong-worker"},
                identities["outsider"]["public"], roster,
            )
        claim = service.claim_spend(
            {"claim_token": token, "claim_instance": "instance-1"}, worker, roster
        )
        digest_input = dict(claim)
        response_digest = digest_input.pop("claim_response_sha256")
        expected = hashlib.sha256(
            json.dumps(digest_input, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert response_digest == expected
        assert claim["token_sha256"] == token_digest
        assert claim["payer_keyid"] == payer
        assert claim["worker_keyid"] == worker
        assert claim["worker_account_at_authorize"] == "worker"
        assert claim["billable"] is True

        public_status = service.spend_status(
            authorization["hold_id"], payer, roster
        )
        assert token not in json.dumps(public_status)
        assert "token_digest" not in public_status
        assert "claim_token" not in public_status

        persisted = service.store.spend_status(authorization["hold_id"])["workers"][0]
        assert persisted["claim_instance"] == "instance-1"
        assert persisted["claim_response_sha256"] == response_digest
    finally:
        service.close()

    reopened = _service(tmp_path, identities, clock)
    try:
        replay = reopened.authorize_spend(
            body, payer, reopened.rosters.snapshot()
        )
        assert replay["hold_id"] == authorization["hold_id"]
        assert replay["claim_token"] == token
        assert reopened.claim_spend(
            {"claim_token": token, "claim_instance": "instance-1"},
            worker, reopened.rosters.snapshot(),
        ) == claim
        with pytest.raises(SpendConflict, match="another instance"):
            reopened.claim_spend(
                {"claim_token": token, "claim_instance": "instance-2"},
                worker, reopened.rosters.snapshot(),
            )
    finally:
        reopened.close()


def test_execution_and_settlement_deadlines_and_24h_fault_clock(
    tmp_path, identities
):
    clock = [2_000_000]
    service = _service(tmp_path, identities, clock)
    try:
        roster = service.rosters.snapshot()
        payer = identities["payer"]["public"]
        worker = identities["worker"]["public"]

        authorization = service.authorize_spend(
            _authorize_body(identities), payer, roster
        )
        claim = service.claim_spend(
            {"claim_token": authorization["claim_token"], "claim_instance": "claim"},
            worker, roster,
        )
        assert claim["execution_deadline"] == 2_000_000 + SPEND_EXECUTION_S
        assert claim["settlement_deadline"] == (
            claim["execution_deadline"] + SPEND_SETTLEMENT_GRACE_S
        )
        receipt = _usage(service, claim, identities["worker"]["private"])
        clock[0] = claim["settlement_deadline"] - 1
        paid = service.settle_spend(receipt, worker, roster)
        assert paid["accepted_delta"] == 12
        assert paid["state"] == "settled"

        late_auth = service.authorize_spend(
            _authorize_body(identities, nonce="late", session="late"), payer, roster
        )
        late_claim = service.claim_spend(
            {"claim_token": late_auth["claim_token"], "claim_instance": "late"},
            worker, roster,
        )
        late_receipt = _usage(
            service, late_claim, identities["worker"]["private"]
        )
        clock[0] = late_claim["settlement_deadline"]
        with pytest.raises(SpendExpired, match="deadline"):
            service.settle_spend(late_receipt, worker, roster)
        assert service.store.spend_status(late_auth["hold_id"])["state"] == "expired"

        unclaimed = service.authorize_spend(
            _authorize_body(identities, nonce="unclaimed", session="unclaimed"),
            payer, roster,
        )
        clock[0] = unclaimed["execution_deadline"]
        with pytest.raises(SpendExpired, match="deadline"):
            service.claim_spend(
                {"claim_token": unclaimed["claim_token"], "claim_instance": "too-late"},
                worker, roster,
            )
        status = service.store.spend_status(unclaimed["hold_id"])
        assert status["state"] == "cancelled"
        assert status["escrow_balance"] == 0
    finally:
        service.close()


def test_all_spend_request_schemas_are_strict_and_bounded(tmp_path, identities):
    clock = [3_000_000]
    service = _service(tmp_path, identities, clock)
    try:
        roster = service.rosters.snapshot()
        payer = identities["payer"]["public"]
        worker = identities["worker"]["public"]
        body = _authorize_body(identities)
        for field, value in (
            ("payer", "forged"),
            ("price_multiplier", 999),
            ("billable", False),
        ):
            invalid = dict(body)
            invalid[field] = value
            with pytest.raises(LedgerValueError, match="unknown"):
                service.authorize_spend(invalid, payer, roster)
        invalid = dict(body, client_nonce="x" * 257)
        with pytest.raises(LedgerValueError, match="256 bytes"):
            service.authorize_spend(invalid, payer, roster)
        invalid = dict(body, max_prompt_tokens=True)
        with pytest.raises(LedgerValueError, match="integer"):
            service.authorize_spend(invalid, payer, roster)

        authorization = service.authorize_spend(body, payer, roster)
        with pytest.raises(LedgerValueError, match="unknown"):
            service.claim_spend(
                {
                    "claim_token": authorization["claim_token"],
                    "claim_instance": "claim",
                    "hold_id": authorization["hold_id"],
                },
                worker, roster,
            )
        with pytest.raises(LedgerValueError, match="strict spend release"):
            service.release_spend(
                {"hold_id": authorization["hold_id"], "payer": "forged"},
                payer, roster,
            )
        with pytest.raises(LedgerValueError, match="strict spend abandon"):
            service.abandon_spend(
                {"hold_id": authorization["hold_id"]}, payer, roster
            )
    finally:
        service.close()


def test_abandon_release_status_and_payer_receipt_relay(tmp_path, identities):
    clock = [3_500_000]
    service = _service(tmp_path, identities, clock)
    try:
        roster = service.rosters.snapshot()
        payer = identities["payer"]["public"]
        worker = identities["worker"]["public"]
        worker2 = identities["worker2"]["public"]
        authorization = service.authorize_spend(
            _authorize_body(
                identities,
                workers=[
                    {"worker_keyid": worker, "layer_start": 0, "layer_end": 2},
                    {"worker_keyid": worker2, "layer_start": 2, "layer_end": 4},
                ],
            ),
            payer,
            roster,
        )
        claim = service.claim_spend(
            {"claim_token": authorization["claim_token"], "claim_instance": "used"},
            worker,
            roster,
        )
        abandoned = service.abandon_spend(
            {"hold_id": authorization["hold_id"], "worker_keyid": worker2},
            payer,
            roster,
        )
        assert [entry["state"] for entry in abandoned["workers"]] == [
            "claimed", "abandoned",
        ]
        relayed = service.settle_spend(
            _usage(service, claim, identities["worker"]["private"]),
            payer,
            roster,
        )
        assert relayed["state"] == "settled"
        assert service.spend_status(
            authorization["hold_id"], worker, roster
        )["state"] == "settled"
        with pytest.raises(PermissionError, match="scope"):
            service.spend_status(
                authorization["hold_id"], identities["outsider"]["public"], roster
            )

        unused = service.authorize_spend(
            _authorize_body(identities, nonce="release", session="release"),
            payer,
            roster,
        )
        released = service.release_spend(
            {"hold_id": unused["hold_id"]}, payer, roster
        )
        assert released["state"] == "cancelled"
        assert released["escrow_balance"] == 0
    finally:
        service.close()


def test_periodic_sweeper_uses_bounded_batch(tmp_path, identities, monkeypatch):
    monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
    clock = [4_000_000]
    service = V2LedgerService(
        tmp_path / "ledger.sqlite",
        identities["roster"],
        clock=lambda: clock[0],
        token_key_path=tmp_path / "token.key",
        sweep_interval=0.01,
    )
    try:
        authorization = service.authorize_spend(
            _authorize_body(identities),
            identities["payer"]["public"],
            service.rosters.snapshot(),
        )
        monkeypatch.delenv("NAK_SPEND_ROUTES", raising=False)
        clock[0] = authorization["execution_deadline"]
        deadline = time.monotonic() + 2
        while service.store.spend_status(authorization["hold_id"])["state"] == "open":
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert service.store.spend_status(authorization["hold_id"])["state"] == "cancelled"
    finally:
        service.close()


@contextmanager
def _running(service):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_v2_handler(service))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(base, method, path, identity=None, obj=None):
    body = json.dumps(obj, separators=(",", ":")).encode() if obj is not None else b""
    headers = {}
    if identity is not None:
        timestamp = int(time.time())
        signature = identity["private"].sign(
            canonical_string(method, path, body, timestamp)
        )
        headers["Authorization"] = (
            f'Sthambha-Ed25519 keyid="{identity["public"]}",'
            f'sig="{base64.b64encode(signature).decode()}",ts="{timestamp}"'
        )
    request = urllib.request.Request(
        base + path,
        data=body if method == "POST" else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_signed_http_routes_flag_off_golden_and_readiness(
    tmp_path, identities, monkeypatch
):
    service = V2LedgerService(
        tmp_path / "ledger.sqlite", identities["roster"], start_sweeper=False
    )
    try:
        with _running(service) as base:
            monkeypatch.delenv("NAK_SPEND_ROUTES", raising=False)
            assert _request(base, "GET", "/health") == (
                200, b'{"ok":true,"store":"sqlite","signed":true}'
            )
            assert _request(base, "GET", "/balances") == (
                403, b'{"error":"all-account balances are disabled"}'
            )
            # Golden bytes captured from base a2c42b1.  The disabled N3 slice
            # must not perturb any pre-existing route, signed or unsigned.
            assert _request(
                base, "GET", "/balance", identities["payer"]
            ) == (200, b'{"account":"payer","balance":0}')
            assert _request(
                base, "GET", "/history", identities["payer"]
            ) == (200, b'{"account":"payer","balance":0,"history":[]}')
            assert _request(
                base, "GET", "/can_consume?cost=1", identities["payer"]
            ) == (
                200,
                b'{"account":"payer","cost":1,"ok":true,"balance":0}',
            )
            assert _request(base, "GET", "/wallet") == (
                404, b'{"error":"not found"}'
            )
            assert _request(base, "POST", "/transfer", obj={}) == (
                401, b'{"error":"invalid or replayed signed envelope"}'
            )
            not_found = (404, b'{"error":"not found"}')
            assert _request(base, "POST", "/spend/authorize", obj={}) == not_found
            assert _request(base, "POST", "/spend/claim", obj={}) == not_found
            assert _request(base, "POST", "/spend/settle", obj={}) == not_found
            assert _request(base, "POST", "/spend/abandon", obj={}) == not_found
            assert _request(base, "POST", "/spend/release", obj={}) == not_found
            assert _request(base, "GET", "/spend/status?hold_id=x") == not_found
            assert _request(base, "GET", "/spend/ready") == not_found

            monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
            assert _request(base, "GET", "/spend/ready")[0] == 401
            code, raw = _request(
                base, "GET", "/spend/ready", identities["worker"]
            )
            assert code == 200
            ready = json.loads(raw)
            assert set(ready) == {"v", "ready", "capability", "server_time"}
            assert ready["ready"] is True
            assert ready["capability"] == "spend_online_claim_v1"

            code, raw = _request(
                base, "POST", "/spend/authorize", identities["payer"],
                _authorize_body(identities),
            )
            assert code == 200
            authorization = json.loads(raw)
            code, raw = _request(
                base, "POST", "/spend/claim", identities["worker"],
                {
                    "claim_token": authorization["claim_token"],
                    "claim_instance": "http-worker",
                },
            )
            assert code == 200
            claim = json.loads(raw)
            assert claim["payer_keyid"] == identities["payer"]["public"]
            assert claim["worker_keyid"] == identities["worker"]["public"]
    finally:
        service.close()
