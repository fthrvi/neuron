"""
ledger_server.py — the v1 credit-ledger service (the integration seam).

Wraps core.credit_ledger.CreditLedger with JSON persistence + a small HTTP API, so the live
inference serve can talk to it over HTTP (the four-project data boundary — no cross-project
import). The flow the serve uses:

  before a run:   GET  /can_consume?account=<requester>&cost=<estimate>   → {"ok": bool}
  after a run:    POST /settle      {"receipt": <#20 receipt dict>, "requester": <id>}  → {"delta": ...}
  on bad spotcheck: POST /dispute   {"run_id": <id>}                       → {"clawed": bool}
  inspect:        GET  /balance?account=<id>   ·   GET /balances

`LedgerService` holds the logic + persistence and is unit-testable without a socket; the
HTTP handler is a thin dispatch over it. Persistence is an atomic JSON write per mutation to
~/.neuron/credits/ledger.json (survives restart).

Anti-Sybil: pass a roster-backed `tier_of` (peers.tsv from the control plane) to gate earning
to known+ peers when the network opens to strangers. Default (None) = no gating, fine for the
current trusted mesh.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Mapping, Optional
from urllib.parse import parse_qs, urlparse

import sys
sys.path.insert(0, os.path.dirname(__file__))
from core.credit_ledger import CreditLedger, CreditError  # noqa: E402
from core.ledger_store import (  # noqa: E402
    MAX_UNITS,
    MIN_WITHDRAW_CREDITS,
    RATE,
    TIER_LIMITS,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    PayoutAddressError,
    ReceiptStateError,
    WithdrawalRateLimitError,
    WithdrawalTierError,
    is_reserved,
)
from ledger_auth import (  # noqa: E402
    TIER_RANK,
    ReceiptError,
    load_roster,
    verify_envelope,
    verify_receipt,
)

DEFAULT_PATH = os.path.expanduser("~/.neuron/credits/ledger.json")
DEFAULT_ROSTER = os.path.expanduser("~/.nakshatra/admission-peers.tsv")
MAX_BODY_BYTES = 64 * 1024
_BASE58_ALPHABET = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


class LedgerService:
    """Persistent wrapper over CreditLedger — load on init, atomic-save on every mutation."""

    def __init__(self, path: str = DEFAULT_PATH, *,
                 tier_of: Optional[Callable[[str], str]] = None,
                 min_earn_tier: str = "known", grace: int = 0):
        self.path = Path(path)
        self.led = CreditLedger(tier_of=tier_of, min_earn_tier=min_earn_tier, grace=grace)
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self.led.restore(json.loads(self.path.read_text()))
            except Exception:
                pass  # corrupt snapshot → start fresh rather than crash the service

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.led.snapshot(), f)
            os.replace(tmp, self.path)          # atomic
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ---- operations (return JSON-able dicts) ----
    def settle(self, receipt: dict, requester: str, own_nodes=None) -> dict:
        # own_nodes = the requester's OWN worker node-ids → that work is free (local doesn't cost).
        own = set(own_nodes or [])
        op_of = (lambda nid: requester if nid in own else nid) if own else None
        d = self.led.settle(receipt, requester, operator_of=op_of)   # raises CreditError on bad receipt
        self._save()
        return {"run_id": d.run_id, "credited": d.credited, "requester": d.requester,
                "debited": d.debited, "total": d.total}

    def transfer(self, frm: str, to: str, amount: int, memo: str = "") -> dict:
        rec = self.led.transfer(frm, to, int(amount), memo=memo)
        self._save()
        return {**rec, "balances": {frm: self.led.balance(frm), to: self.led.balance(to)}}

    def history(self, account: str, limit: int = 50) -> dict:
        return {"account": account, "balance": self.led.balance(account),
                "history": self.led.history(account, limit=limit)}

    def can_consume(self, account: str, cost: int) -> dict:
        return {"account": account, "cost": int(cost),
                "ok": self.led.can_consume(account, int(cost)),
                "balance": self.led.balance(account)}

    def balance(self, account: str) -> dict:
        return {"account": account, "balance": self.led.balance(account)}

    def dispute(self, run_id: str) -> dict:
        clawed = self.led.dispute(run_id)
        if clawed:
            self._save()
        return {"run_id": run_id, "clawed": clawed}

    def balances(self) -> dict:
        return {"balances": self.led.balances()}


def _make_handler(svc: LedgerService):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            return json.loads(self.rfile.read(n) or b"{}") if n else {}

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path == "/can_consume":
                    return self._send(200, svc.can_consume(q.get("account", [""])[0],
                                                           int(q.get("cost", ["0"])[0])))
                if u.path == "/balance":
                    return self._send(200, svc.balance(q.get("account", [""])[0]))
                if u.path == "/balances":
                    return self._send(200, svc.balances())
                if u.path == "/history":
                    return self._send(200, svc.history(q.get("account", [""])[0],
                                                       int(q.get("limit", ["50"])[0])))
                if u.path == "/health":
                    return self._send(200, {"ok": True})
                return self._send(404, {"error": "not found"})
            except Exception as e:
                return self._send(500, {"error": repr(e)})

        def do_POST(self):
            u = urlparse(self.path)
            try:
                b = self._body()
                if u.path == "/settle":
                    try:
                        return self._send(200, {"delta": svc.settle(
                            b["receipt"], b["requester"], own_nodes=b.get("own_nodes"))})
                    except CreditError as e:
                        return self._send(422, {"error": str(e)})   # bad/forged receipt
                if u.path == "/transfer":
                    try:
                        return self._send(200, svc.transfer(b["from"], b["to"], b["amount"],
                                                            b.get("memo", "")))
                    except CreditError as e:
                        return self._send(422, {"error": str(e)})
                if u.path == "/dispute":
                    return self._send(200, svc.dispute(b["run_id"]))
                return self._send(404, {"error": "not found"})
            except Exception as e:
                return self._send(500, {"error": repr(e)})
    return H


class RosterCache:
    """Thread-safe admission roster that is refreshed at most once per minute."""

    def __init__(self, path: str | Path, *, refresh_seconds: float = 60.0):
        self.path = Path(path)
        self.refresh_seconds = refresh_seconds
        self._lock = threading.Lock()
        self._roster = load_roster(self.path)
        self._loaded_at = time.monotonic()

    def snapshot(self) -> dict[str, dict[str, str | None]]:
        with self._lock:
            now = time.monotonic()
            if now - self._loaded_at >= self.refresh_seconds:
                # Fail closed if the roster cannot be refreshed.  In particular,
                # do not continue accepting a key that may have been revoked.
                self._roster = load_roster(self.path)
                self._loaded_at = now
            return dict(self._roster)


def _row_identity(
    keyid: str, roster: Mapping[str, Mapping[str, object]]
) -> tuple[str, str]:
    row = roster.get(keyid)
    if not isinstance(row, Mapping):
        raise PermissionError("signing key is not rostered")
    operator = row.get("operator")
    tier = row.get("tier")
    if not isinstance(operator, str) or not operator:
        raise PermissionError("signing key has no roster operator")
    if is_reserved(operator):
        raise PermissionError("signing key maps to a reserved operator")
    return operator, tier if isinstance(tier, str) else "stranger"


def _operator_tiers(
    roster: Mapping[str, Mapping[str, object]],
) -> dict[str, str]:
    tiers: dict[str, str] = {}
    for row in roster.values():
        if not isinstance(row, Mapping):
            continue
        operator = row.get("operator")
        if not isinstance(operator, str) or not operator:
            continue
        tier = row.get("tier")
        normalized = tier if isinstance(tier, str) and tier in TIER_RANK else "stranger"
        if TIER_RANK[normalized] > TIER_RANK.get(tiers.get(operator, ""), -1):
            tiers[operator] = normalized
    return tiers


def _query_integer(value: str, name: str, *, low: int, high: int) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise LedgerValueError(f"{name} must be an integer")
    parsed = int(value)
    if parsed < low or parsed > high:
        raise LedgerValueError(f"{name} must be between {low} and {high}")
    return parsed


def _funds_routes_enabled() -> bool:
    return os.environ.get("NAK_FUNDS_ROUTES", "").strip().lower() == "on"


def _solana_address(value: object) -> str:
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        raise LedgerValueError("address must be a Solana base58 public key")
    if any(char not in _BASE58_ALPHABET for char in value):
        raise LedgerValueError("address must be a Solana base58 public key")
    leading_zeroes = len(value) - len(value.lstrip("1"))
    number = 0
    for char in value:
        number = number * 58 + "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".index(char)
    decoded = (b"\x00" * leading_zeroes) + (
        number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    )
    if len(decoded) != 32:
        raise LedgerValueError("address must decode to a 32-byte Solana public key")
    return value


def _credits_as_usdc(credits: int) -> str:
    sign = "-" if credits < 0 else ""
    whole, fraction = divmod(abs(credits), RATE * 1_000_000)
    return f"{sign}{whole}.{fraction:08d}"


class V2LedgerService:
    """Authenticated service boundary for the durable SQLite ledger."""

    def __init__(self, store_path: str | Path, roster_path: str | Path):
        self.store = LedgerStore(store_path)
        self.rosters = RosterCache(roster_path)

    def close(self) -> None:
        self.store.close()

    def settle(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        if not isinstance(body, dict) or not isinstance(body.get("receipt"), dict):
            raise ReceiptError("body.receipt must be an object")
        requester, tier = _row_identity(keyid, roster)
        receipt_id, credited, charged = verify_receipt(body["receipt"], keyid, roster)
        delta = self.store.settle(
            receipt_id, requester, credited, charged, tier,
            account_tiers=_operator_tiers(roster),
        )
        return {
            "receipt_id": receipt_id,
            "requester": requester,
            "credited": credited,
            "charged": charged,
            "delta": delta,
        }

    def transfer(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        if not isinstance(body, dict):
            raise LedgerValueError("request body must be an object")
        src, tier = _row_identity(keyid, roster)
        dst = body.get("to", body.get("dst"))
        amount = body.get("amount")
        moved = self.store.transfer(src, dst, amount, tier)
        return {
            "from": src,
            "to": dst,
            "amount": moved,
            "balances": {src: self.store.balance(src), dst: self.store.balance(dst)},
        }

    def dispute(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        if not isinstance(body, dict):
            raise LedgerValueError("request body must be an object")
        receipt_id = body.get("receipt_id")
        if not isinstance(receipt_id, str) or not receipt_id:
            raise LedgerValueError("receipt_id must be a non-empty string")
        operator, tier = _row_identity(keyid, roster)
        requester = self.store.receipt_requester(receipt_id)
        if requester is None:
            raise LookupError("receipt not found")
        # The central operator key is represented by the roster's self tier.
        if operator != requester and tier != "self":
            raise PermissionError("only the requester or operator key may dispute")
        return {"receipt_id": receipt_id, "clawed": self.store.dispute(receipt_id)}

    def balance(self, operator: str) -> dict[str, object]:
        return {"account": operator, "balance": self.store.balance(operator)}

    def history(self, operator: str, limit: int) -> dict[str, object]:
        return {
            "account": operator,
            "balance": self.store.balance(operator),
            "history": self.store.history(operator, limit),
        }

    def can_consume(self, operator: str, tier: str, cost: int) -> dict[str, object]:
        balance = self.store.balance(operator)
        limit = TIER_LIMITS.get(tier, TIER_LIMITS["stranger"])
        allowed = limit is None or balance - cost >= -limit
        return {"account": operator, "cost": cost, "ok": allowed, "balance": balance}

    def wallet(
        self,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        operator, _tier = _row_identity(keyid, roster)
        return {"account": operator, **self.store.wallet(operator)}

    def bind_wallet(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        if not isinstance(body, dict):
            raise LedgerValueError("request body must be an object")
        operator, _tier = _row_identity(keyid, roster)
        address = _solana_address(body.get("address"))
        return {"account": operator, **self.store.bind_payout_address(operator, address)}

    def withdraw(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        if not isinstance(body, dict):
            raise LedgerValueError("request body must be an object")
        operator, tier = _row_identity(keyid, roster)
        amount = body.get("amount")
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise LedgerValueError("amount must be an integer number of credits")
        requested_address = body.get("address")
        if requested_address is not None:
            requested_address = _solana_address(requested_address)
        withdrawal_id = self.store.request_withdrawal(
            operator, amount, tier, address=requested_address
        )
        return {
            "id": withdrawal_id,
            "account": operator,
            "amount": amount,
            "amount_usdc": _credits_as_usdc(amount),
            "state": "pending",
        }

    def wallet_status(
        self,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        operator, tier = _row_identity(keyid, roster)
        status = self.store.wallet_status(operator)
        return {
            "account": operator,
            "tier": tier,
            **status,
            "balance_usdc": _credits_as_usdc(int(status["balance"])),
            "withdrawable_usdc": _credits_as_usdc(int(status["withdrawable"])),
            "rate": {
                "credits_per_micro_usdc": RATE,
                "minimum_withdrawal_credits": MIN_WITHDRAW_CREDITS,
            },
        }


def _make_v2_handler(svc: V2LedgerService):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, obj: object) -> None:
            payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _raw_body(self) -> bytes | None:
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                self._send(400, {"error": "invalid Content-Length"})
                return None
            if length < 0:
                self._send(400, {"error": "invalid Content-Length"})
                return None
            if length > MAX_BODY_BYTES:
                self._send(413, {"error": "request body exceeds 64 KB"})
                return None
            return self.rfile.read(length)

        def _authenticate(
            self, method: str, body: bytes
        ) -> tuple[str, Mapping[str, Mapping[str, object]]] | None:
            try:
                roster = svc.rosters.snapshot()
            except Exception:
                self._send(503, {"error": "admission roster unavailable"})
                return None
            keyid = verify_envelope(
                self.headers, method, self.path, body, roster, svc.store
            )
            if keyid is None:
                self._send(401, {"error": "invalid or replayed signed envelope"})
                return None
            return keyid, roster

        def do_GET(self) -> None:
            target = urlparse(self.path)
            if target.path == "/health":
                self._send(200, {"ok": True, "store": "sqlite", "signed": True})
                return
            if target.path == "/balances":
                self._send(403, {"error": "all-account balances are disabled"})
                return
            funds_path = target.path in ("/wallet", "/wallet/status")
            if funds_path and not _funds_routes_enabled():
                self._send(404, {"error": "not found"})
                return
            if target.path not in (
                "/balance", "/history", "/can_consume", "/wallet", "/wallet/status"
            ):
                self._send(404, {"error": "not found"})
                return
            authenticated = self._authenticate("GET", b"")
            if authenticated is None:
                return
            keyid, roster = authenticated
            try:
                operator, tier = _row_identity(keyid, roster)
                query = parse_qs(target.query, keep_blank_values=True)
                # The answer is ALWAYS about the signer's own operator account; a v1-era client still
                # sends ?account=<old requester name> (Prithvi's gateway: "prithvi"), and refusing it
                # silently disabled the credit gate (fail-open). Ignoring it cannot reveal anyone else.
                if target.path == "/balance":
                    result = svc.balance(operator)
                elif target.path == "/history":
                    limit_text = query.get("limit", ["50"])[0]
                    limit = _query_integer(limit_text, "limit", low=1, high=1000)
                    result = svc.history(operator, limit)
                elif target.path == "/can_consume":
                    cost_text = query.get("cost", [None])[0]
                    if cost_text is None:
                        raise LedgerValueError("cost is required")
                    cost = _query_integer(cost_text, "cost", low=0, high=MAX_UNITS)
                    result = svc.can_consume(operator, tier, cost)
                elif target.path == "/wallet":
                    result = svc.wallet(keyid, roster)
                else:
                    result = svc.wallet_status(keyid, roster)
                self._send(200, result)
            except PermissionError as exc:
                self._send(403, {"error": str(exc)})
            except LedgerValueError as exc:
                self._send(422, {"error": str(exc)})

        def do_POST(self) -> None:
            target = urlparse(self.path)
            funds_path = target.path in ("/wallet/bind", "/withdraw")
            if funds_path and not _funds_routes_enabled():
                self._send(404, {"error": "not found"})
                return
            body_bytes = self._raw_body()
            if body_bytes is None:
                return
            authenticated = self._authenticate("POST", body_bytes)
            if authenticated is None:
                return
            keyid, roster = authenticated
            if target.path not in (
                "/settle", "/transfer", "/dispute", "/wallet/bind", "/withdraw"
            ):
                self._send(404, {"error": "not found"})
                return
            try:
                body = json.loads(body_bytes or b"{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send(400, {"error": "body must be valid JSON"})
                return
            try:
                if target.path == "/settle":
                    result = svc.settle(body, keyid, roster)
                elif target.path == "/transfer":
                    result = svc.transfer(body, keyid, roster)
                elif target.path == "/dispute":
                    result = svc.dispute(body, keyid, roster)
                elif target.path == "/wallet/bind":
                    result = svc.bind_wallet(body, keyid, roster)
                else:
                    result = svc.withdraw(body, keyid, roster)
                self._send(200, result)
            except CreditLimitError as exc:
                self._send(422 if target.path == "/withdraw" else 402,
                           {"error": str(exc)})
            except (PayoutAddressError, WithdrawalTierError) as exc:
                self._send(403, {"error": str(exc)})
            except WithdrawalRateLimitError as exc:
                self._send(429, {"error": str(exc)})
            except ReceiptStateError as exc:
                self._send(409, {"error": str(exc)})
            except PermissionError as exc:
                self._send(403, {"error": str(exc)})
            except LookupError as exc:
                self._send(404, {"error": str(exc)})
            except (ReceiptError, LedgerValueError, KeyError) as exc:
                self._send(422, {"error": str(exc)})

    return H


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8093)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--path", default=DEFAULT_PATH)
    ap.add_argument("--store", help="enable v2 with this SQLite ledger path")
    ap.add_argument("--roster", default=DEFAULT_ROSTER,
                    help="v2 admission roster TSV (reloaded once per minute)")
    ap.add_argument("--grace", type=int, default=0, help="bootstrap consume allowance per account")
    args = ap.parse_args()
    if args.store:
        svc = V2LedgerService(args.store, args.roster)
        handler = _make_v2_handler(svc)
        description = args.store
    else:
        svc = LedgerService(args.path, grace=args.grace)
        handler = _make_handler(svc)
        description = args.path
    srv = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"[ledger] serving on {args.host}:{args.port}  store={description}", flush=True)
    try:
        srv.serve_forever()
    finally:
        if isinstance(svc, V2LedgerService):
            svc.close()


if __name__ == "__main__":
    main()
