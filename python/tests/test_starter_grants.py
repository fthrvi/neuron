"""Signed starter grants: strict wire contract and spend-only accounting."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.ledger_store import (  # noqa: E402
    HOLD_S,
    STARTER_MAX,
    TIER_LIMITS,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    SpendConflict,
)
from ledger_auth import canonical_string  # noqa: E402
from ledger_server import V2LedgerService, _make_v2_handler  # noqa: E402


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
    result: dict[str, object] = {}
    rows = []
    for label, operator, tier in (
        ("inviter", "inviter", "known"),
        ("inviter2", "inviter2", "trusted"),
        ("recipient", "recipient", "known"),
        ("same_account", "inviter", "known"),
        ("outsider", "outsider", "stranger"),
    ):
        identity = _identity(f"starter-{label}")
        result[label] = identity
        rows.append(f"{identity['public']}\t{label}\t{operator}\t{tier}\ttest")
    roster = tmp_path / "roster.tsv"
    roster.write_text("\n".join(rows) + "\n", encoding="utf-8")
    result["roster"] = roster
    return result


def _service(tmp_path, identities, clock):
    return V2LedgerService(
        tmp_path / "ledger.sqlite",
        identities["roster"],
        clock=lambda: clock[0],
        start_sweeper=False,
    )


def _body(identities, **changes):
    body = {
        "invite_id": "invite_1",
        "to_keyid": identities["recipient"]["public"],
        "amount": 100,
    }
    body.update(changes)
    return body


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
        timestamp = max(int(time.time()), getattr(_request, "last_timestamp", 0) + 1)
        _request.last_timestamp = timestamp
        signature = identity["private"].sign(
            canonical_string(method, path, body, timestamp)
        )
        headers["Authorization"] = (
            f'Sthambha-Ed25519 keyid="{identity["public"]}",'
            f'sig="{base64.b64encode(signature).decode()}",ts="{timestamp}"'
        )
    request = urllib.request.Request(
        base + path,
        data=body if obj is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_store_grant_is_atomic_zero_sum_idempotent_and_spend_only(tmp_path):
    clock = [1_000_000]
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: clock[0]) as store:
        first = store.grant_starter(
            "invite", "source", "recipient", "a" * 64, 100, "known", "trusted"
        )
        assert first == {
            "invite_id": "invite",
            "src_account": "source",
            "dst_account": "recipient",
            "to_keyid": "a" * 64,
            "amount": 100,
            "ts": clock[0],
            "replayed": False,
        }
        assert store.grant_starter(
            "invite", "source", "recipient", "a" * 64, 100, "known", "trusted"
        ) == {**first, "replayed": True}
        assert store.balance("source") == -100
        assert store.balance("recipient") == 100
        assert store._db.execute(
            "SELECT COALESCE(SUM(balance), 0) FROM accounts"
        ).fetchone()[0] == 0
        rows = store._db.execute(
            "SELECT kind, account, counterparty, amount, detail FROM journal ORDER BY seq"
        ).fetchall()
        assert [tuple(row[:4]) for row in rows] == [
            ("starter_send", "source", "recipient", -100),
            ("starter_receive", "recipient", "source", 100),
        ]
        assert all(
            json.loads(row["detail"])
            == {"invite_id": "invite", "spend_only": True}
            for row in rows
        )
        assert store.economic_receipts("recipient") == []
        clock[0] += HOLD_S + 1
        assert store.withdrawable("recipient") == 0


def test_store_conflicts_limits_reserved_accounts_and_rolls_back(tmp_path):
    with LedgerStore(tmp_path / "ledger.db", clock=lambda: 2_000_000) as store:
        store.grant_starter("one", "source", "recipient", "a" * 64, 10,
                            "known", "known")
        with pytest.raises(SpendConflict, match="starter invite conflicts"):
            store.grant_starter("one", "source", "other", "b" * 64, 10,
                                "known", "known")
        with pytest.raises(SpendConflict, match="recipient already has a starter grant"):
            store.grant_starter("two", "other-source", "recipient", "a" * 64, 10,
                                "trusted", "known")
        with pytest.raises(CreditLimitError):
            store.grant_starter("large", "limited", "new", "c" * 64,
                                TIER_LIMITS["stranger"] + 1, "stranger", "known")
        for src, dst in (("same", "same"), ("treasury", "dst"), ("src", "treasury")):
            with pytest.raises(LedgerValueError):
                store.grant_starter("bad", src, dst, "d" * 64, 1,
                                    "self", "known")

        store._db.execute(
            "CREATE TRIGGER refuse_test_grant BEFORE INSERT ON starter_grants "
            "WHEN NEW.invite_id='rollback' BEGIN SELECT RAISE(ABORT, 'test'); END"
        )
        before = store._db.execute("SELECT COUNT(*) FROM journal").fetchone()[0]
        with pytest.raises(Exception, match="test"):
            store.grant_starter("rollback", "rollback-src", "rollback-dst",
                                "e" * 64, 5, "known", "known")
        assert store.balance("rollback-src") == store.balance("rollback-dst") == 0
        assert store._db.execute("SELECT COUNT(*) FROM journal").fetchone()[0] == before


def test_service_validation_replay_one_per_recipient_and_status_scope(
    tmp_path, identities
):
    clock = [3_000_000]
    service = _service(tmp_path, identities, clock)
    try:
        roster = service.rosters.snapshot()
        inviter = identities["inviter"]["public"]
        body = _body(identities)
        first = service.grant_starter(body, inviter, roster)
        assert first == {
            "v": 1,
            "invite_id": "invite_1",
            "from_account": "inviter",
            "to_account": "recipient",
            "to_keyid": identities["recipient"]["public"],
            "amount": 100,
            "ts": clock[0],
            "replayed": False,
        }
        assert service.grant_starter(body, inviter, roster) == {
            **first, "replayed": True
        }
        assert service.starter_status("invite_1", inviter, roster) == {
            key: value for key, value in first.items() if key != "replayed"
        }
        with pytest.raises(LookupError, match="starter grant not found"):
            service.starter_status(
                "invite_1", identities["outsider"]["public"], roster
            )
        with pytest.raises(SpendConflict, match="starter invite conflicts"):
            service.grant_starter(dict(body, amount=101), inviter, roster)
        with pytest.raises(SpendConflict, match="recipient already has"):
            service.grant_starter(
                dict(body, invite_id="other"), identities["inviter2"]["public"], roster
            )
        with pytest.raises(LedgerValueError, match="same account"):
            service.grant_starter(
                dict(body, invite_id="self", to_keyid=identities["same_account"]["public"]),
                inviter,
                roster,
            )

        for changes in (
            {"invite_id": ""},
            {"invite_id": "x" * 65},
            {"invite_id": "not valid"},
            {"to_keyid": "A" * 64},
            {"amount": 0},
            {"amount": STARTER_MAX + 1},
            {"amount": True},
            {"extra": 1},
        ):
            with pytest.raises(LedgerValueError):
                invalid = dict(body, invite_id="unused")
                invalid.update(changes)
                service.grant_starter(invalid, inviter, roster)
        with pytest.raises(LookupError, match="recipient not in roster"):
            service.grant_starter(
                dict(body, invite_id="missing", to_keyid="f" * 64), inviter, roster
            )
        reserved_roster = dict(roster)
        reserved_roster[identities["recipient"]["public"]] = {
            "operator": "treasury", "tier": "self"
        }
        with pytest.raises(LedgerValueError, match="reserved"):
            service.grant_starter(dict(body, invite_id="reserved"), inviter, reserved_roster)
    finally:
        service.close()


def test_http_routes_are_signed_gated_strict_and_fixture_is_captured(
    tmp_path, identities, monkeypatch
):
    clock = [1_700_000_000]
    service = _service(tmp_path, identities, clock)
    try:
        with _running(service) as base:
            body = {
                "invite_id": "fixture_invite",
                "to_keyid": identities["recipient"]["public"],
                "amount": 12345,
            }
            monkeypatch.delenv("NAK_SPEND_ROUTES", raising=False)
            assert _request(base, "POST", "/spend/starter", obj=body) == (
                404, {"error": "not found"}
            )
            assert _request(
                base, "GET", "/spend/starter/status?invite_id=fixture_invite"
            ) == (404, {"error": "not found"})

            monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
            assert _request(base, "POST", "/spend/starter", obj=body)[0] == 401
            unrostered = _identity("starter-unrostered")
            assert _request(
                base, "POST", "/spend/starter", unrostered, body
            )[0] == 401
            assert _request(
                base, "POST", "/spend/starter", identities["inviter"],
                dict(body, to_keyid="f" * 64),
            ) == (404, {"error": "recipient not in roster"})
            for invalid in (
                dict(body, extra=True),
                {"invite_id": body["invite_id"], "to_keyid": body["to_keyid"]},
                dict(body, amount=0),
            ):
                assert _request(
                    base, "POST", "/spend/starter", identities["inviter"], invalid
                )[0] == 422
            assert _request(
                base,
                "POST",
                "/spend/starter",
                identities["inviter"],
                dict(
                    body,
                    invite_id="self",
                    to_keyid=identities["same_account"]["public"],
                ),
            )[0] == 422

            grant = _request(
                base, "POST", "/spend/starter", identities["inviter"], body
            )
            replay = _request(
                base, "POST", "/spend/starter", identities["inviter"], body
            )
            status = _request(
                base,
                "GET",
                "/spend/starter/status?invite_id=fixture_invite",
                identities["inviter"],
            )
            assert grant[0] == replay[0] == status[0] == 200
            captured = {"grant": grant[1], "replay": replay[1], "status": status[1]}
            fixture = json.loads(
                (Path(__file__).parent / "fixtures" / "starter_replies.json").read_text()
            )
            assert captured == fixture
            assert _request(
                base,
                "GET",
                "/spend/starter/status?invite_id=fixture_invite",
                identities["outsider"],
            ) == (404, {"error": "starter grant not found"})
            assert _request(
                base,
                "POST",
                "/spend/starter",
                identities["inviter"],
                dict(body, amount=12346),
            )[0] == 409
            assert _request(
                base,
                "POST",
                "/spend/starter",
                identities["inviter2"],
                dict(body, invite_id="another"),
            ) == (409, {"error": "recipient already has a starter grant"})

            # Reserved mappings cannot come from load_roster(), but exercise
            # the HTTP boundary against an injected malformed cache snapshot.
            service.rosters._roster[identities["recipient"]["public"]][
                "operator"
            ] = "treasury"
            assert _request(
                base,
                "POST",
                "/spend/starter",
                identities["inviter2"],
                dict(body, invite_id="reserved-dst"),
            )[0] == 422
            service.rosters._roster[identities["inviter2"]["public"]][
                "operator"
            ] = "treasury"
            assert _request(
                base,
                "POST",
                "/spend/starter",
                identities["inviter2"],
                dict(body, invite_id="reserved-src"),
            )[0] == 422
    finally:
        service.close()


def test_http_tier_limit_is_402(tmp_path, identities, monkeypatch):
    monkeypatch.setenv("NAK_SPEND_ROUTES", "on")
    service = _service(tmp_path, identities, [4_000_000])
    try:
        with _running(service) as base:
            code, _body_json = _request(
                base,
                "POST",
                "/spend/starter",
                identities["outsider"],
                _body(identities, invite_id="too_large",
                      amount=TIER_LIMITS["stranger"] + 1),
            )
            assert code == 402
    finally:
        service.close()


def test_0f16873_store_opens_database_containing_starter_grant(tmp_path):
    database = tmp_path / "ledger.db"
    with LedgerStore(database, clock=lambda: 5_000_000) as store:
        store.grant_starter(
            "rollback", "source", "recipient", "a" * 64, 20, "known", "known"
        )
        expected = dict(store._db.execute("SELECT id, balance FROM accounts"))

    base_module = tmp_path / "base_ledger_store.py"
    base_module.write_text(
        subprocess.check_output(
            ["git", "show", "0f16873:python/core/ledger_store.py"], text=True
        ),
        encoding="utf-8",
    )
    driver = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('base_ledger_store', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
with module.LedgerStore(sys.argv[2], clock=lambda: 5000000) as store:
    balances = dict(store._db.execute('SELECT id, balance FROM accounts'))
    print(json.dumps({'balances': balances, 'total': sum(balances.values())}))
"""
    opened = subprocess.run(
        [sys.executable, "-c", driver, str(base_module), str(database)],
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(opened.stdout.strip().splitlines()[-1])
    assert result == {"balances": expected, "total": 0}
