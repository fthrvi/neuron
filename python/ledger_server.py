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

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
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
    STARTER_MAX,
    TIER_LIMITS,
    CreditLimitError,
    LedgerStore,
    LedgerValueError,
    PayoutAddressError,
    ReceiptStateError,
    SPEND_EXPIRY_BATCH_SIZE,
    SPEND_USAGE_FIELDS,
    TASK_DEADLINE_MAX_S,
    TASK_DEADLINE_MIN_S,
    TASK_MAX_AMOUNT,
    SpendConflict,
    SpendExpired,
    SpendNotFound,
    SpendStateError,
    TaskHoldNotOpen,
    TaskSubmittedLocked,
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
MAX_SPEND_IDENTIFIER_BYTES = 256
MAX_SPEND_WORKERS = 128
MAX_SPEND_PROMPT_TOKENS = 1_000_000
MAX_SPEND_OUTPUT_TOKENS = 1_000_000
MAX_SPEND_LAYERS = 1_000_000
SPEND_PRICE_MULTIPLIER = 1
SPEND_SWEEP_INTERVAL_S = 30.0
SPEND_CAPABILITY = "spend_online_claim_v1"
_BASE58_ALPHABET = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
_SPEND_POST_PATHS = frozenset(
    {
        "/spend/authorize",
        "/spend/claim",
        "/spend/settle",
        "/spend/abandon",
        "/spend/release",
        "/spend/task/authorize",
        "/spend/task/submit",
        "/spend/task/received",
        "/spend/task/pay",
        "/spend/task/refund",
        "/spend/task/dispute",
        "/spend/task/resolve",
        "/spend/starter",
    }
)
_SPEND_GET_PATHS = frozenset(
    {"/spend/status", "/spend/ready", "/spend/task/status", "/spend/starter/status"}
)
_SPEND_PATHS = _SPEND_POST_PATHS | _SPEND_GET_PATHS


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


def _spend_routes_enabled() -> bool:
    return os.environ.get("NAK_SPEND_ROUTES", "").strip().lower() == "on"


def _strict_json_object(body: bytes) -> dict[str, object]:
    """Decode one JSON object while rejecting duplicate object keys."""
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LedgerValueError(f"duplicate field {key!r}")
            result[key] = value
        return result

    try:
        decoded = json.loads(body or b"{}", object_pairs_hook=object_pairs)
    except LedgerValueError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerValueError("body must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise LedgerValueError("request body must be an object")
    return decoded


def _strict_fields(
    body: object, expected: set[str] | frozenset[str], *, name: str = "request"
) -> dict[str, object]:
    if not isinstance(body, dict):
        raise LedgerValueError(f"{name} body must be an object")
    actual = set(body)
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        unknown = sorted(actual - set(expected))
        detail = f"missing {missing[0]!r}" if missing else f"unknown {unknown[0]!r}"
        raise LedgerValueError(f"strict {name} schema: {detail}")
    return body


def _bounded_text(value: object, name: str, *, maximum: int = MAX_SPEND_IDENTIFIER_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise LedgerValueError(f"{name} must be a non-empty string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise LedgerValueError(f"{name} must be valid UTF-8") from exc
    if size > maximum:
        raise LedgerValueError(f"{name} exceeds {maximum} bytes")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise LedgerValueError(f"{name} contains a control character")
    return value


def _bounded_note(value: object, name: str = "note", *, maximum: int = 280) -> str:
    if not isinstance(value, str):
        raise LedgerValueError(f"{name} must be a string")
    if len(value) > maximum:
        raise LedgerValueError(f"{name} exceeds {maximum} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise LedgerValueError(f"{name} must be valid UTF-8") from exc
    return value


def _bounded_integer(value: object, name: str, *, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerValueError(f"{name} must be an integer")
    if value < low or value > high:
        raise LedgerValueError(f"{name} must be between {low} and {high}")
    return value


def _ed25519_keyid(value: object, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise LedgerValueError(f"{name} must be a lowercase Ed25519 public key")
    return value


def _claim_token(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None:
        raise LedgerValueError("claim_token must be 256-bit unpadded base64url")
    return value


def _exact_query(target, expected: set[str]) -> dict[str, str]:
    parsed = parse_qs(target.query, keep_blank_values=True)
    if set(parsed) != expected or any(len(values) != 1 for values in parsed.values()):
        missing = sorted(expected - set(parsed))
        unknown = sorted(set(parsed) - expected)
        if missing:
            detail = f"missing {missing[0]!r}"
        elif unknown:
            detail = f"unknown {unknown[0]!r}"
        else:
            detail = "duplicate query field"
        raise LedgerValueError(f"strict query schema: {detail}")
    return {key: values[0] for key, values in parsed.items()}


def _loopback_client(address: object) -> bool:
    try:
        host = address[0]  # type: ignore[index]
        return ipaddress.ip_address(host).is_loopback
    except (IndexError, TypeError, ValueError):
        return False


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

    def __init__(
        self,
        store_path: str | Path,
        roster_path: str | Path,
        *,
        clock: Callable[[], float] | None = None,
        sweep_interval: float = SPEND_SWEEP_INTERVAL_S,
        start_sweeper: bool = True,
    ):
        self.store = LedgerStore(store_path, clock=clock)
        self.rosters = RosterCache(roster_path)
        self._sweep_interval = max(0.01, float(sweep_interval))
        self._sweep_stop = threading.Event()
        self._sweep_error: str | None = None
        self._sweeper: threading.Thread | None = None
        self._sweep_lock_path = Path(str(store_path) + ".spend-sweeper.lock")
        self._sweep_lock_fd: int | None = None
        if start_sweeper and self._acquire_sweeper_lock():
            self._sweeper = threading.Thread(
                target=self._sweep_spend_holds,
                name="neuron-spend-expiry",
                daemon=True,
            )
            self._sweeper.start()

    def close(self) -> None:
        self._sweep_stop.set()
        if self._sweeper is not None:
            self._sweeper.join(timeout=max(1.0, self._sweep_interval * 2))
        if self._sweep_lock_fd is not None:
            fcntl.flock(self._sweep_lock_fd, fcntl.LOCK_UN)
            os.close(self._sweep_lock_fd)
            self._sweep_lock_fd = None
        self.store.close()

    def _acquire_sweeper_lock(self) -> bool:
        self._sweep_lock_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self._sweep_lock_path, flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        self._sweep_lock_fd = fd
        return True

    def _sweep_spend_holds(self) -> None:
        while not self._sweep_stop.wait(self._sweep_interval):
            try:
                self.store.expire_spend_holds(SPEND_EXPIRY_BATCH_SIZE)
                self._sweep_error = None
            except Exception as exc:
                # The readiness result goes false; the daemon stays alive so a
                # transient SQLite failure can recover on the next bounded tick.
                self._sweep_error = type(exc).__name__

    @staticmethod
    def _status_response(status: Mapping[str, object]) -> dict[str, object]:
        workers = []
        for raw in status["workers"]:  # type: ignore[index]
            entry = raw  # type: ignore[assignment]
            workers.append(
                {
                    "worker_keyid": entry["worker_keyid"],
                    "worker_account_at_authorize": entry["worker_account_at_authorize"],
                    "billable": bool(entry["billable"]),
                    "layer_start": int(entry["layer_start"]),
                    "layer_end": int(entry["layer_end"]),
                    "price_multiplier": int(entry["price_multiplier"]),
                    "max_prompt_tokens": int(entry["max_prompt_tokens"]),
                    "max_output_tokens": int(entry["max_output_tokens"]),
                    "max_token_layers": int(entry["max_token_layers"]),
                    "max_cost": int(entry["max_cost"]),
                    "state": entry["state"],
                    "claimed_at": entry["claimed_at"],
                    "cumulative_prompt_tokens": int(entry["cumulative_prompt_tokens"]),
                    "cumulative_generated_tokens": int(entry["cumulative_generated_tokens"]),
                    "cumulative_token_layers": int(entry["cumulative_token_layers"]),
                    "cumulative_cost": int(entry["cumulative_cost"]),
                    "final": bool(entry["final"]),
                    "final_receipt_id": entry["final_receipt_id"],
                    "claim_response_sha256": entry["claim_response_sha256"],
                }
            )
        return {
            "v": 1,
            "hold_id": status["hold_id"],
            "payer_keyid": status["payer_keyid"],
            "payer_account_at_authorize": status["payer_account_at_authorize"],
            "session_id": status["session_id"],
            "model_id": status["model_id"],
            "billing_mode": status["billing_mode"],
            "max_prompt_tokens": int(status["max_prompt_tokens"]),
            "max_output_tokens": int(status["max_output_tokens"]),
            "max_token_layers": int(status["max_token_layers"]),
            "max_cost": int(status["max_cost"]),
            "state": status["state"],
            "release_requested": bool(status["release_requested"]),
            "authorized_at": int(status["authorized_at"]),
            "execution_deadline": int(status["execution_deadline"]),
            "settlement_deadline": int(status["settlement_deadline"]),
            "terminal_at": status["terminal_at"],
            "escrow_balance": int(status["escrow_balance"]),
            "workers": workers,
        }

    @staticmethod
    def _claim_response(
        status: Mapping[str, object], worker_keyid: str
    ) -> dict[str, object]:
        entry = next(
            worker
            for worker in status["workers"]  # type: ignore[index]
            if worker["worker_keyid"] == worker_keyid
        )
        if entry["claimed_at"] is None or entry["claim_response_sha256"] is None:
            raise SpendStateError("worker claim snapshot was not persisted")
        return {
            "v": 1,
            "hold_id": status["hold_id"],
            "token_sha256": status["token_digest"],
            "claim_instance": entry["claim_instance"],
            "payer_keyid": status["payer_keyid"],
            "payer_account_at_authorize": status["payer_account_at_authorize"],
            "worker_keyid": entry["worker_keyid"],
            "worker_account_at_authorize": entry["worker_account_at_authorize"],
            "billable": bool(entry["billable"]),
            "session_id": status["session_id"],
            "model_id": status["model_id"],
            "billing_mode": status["billing_mode"],
            "layer_start": int(entry["layer_start"]),
            "layer_end": int(entry["layer_end"]),
            "price_multiplier": int(entry["price_multiplier"]),
            "max_prompt_tokens": int(entry["max_prompt_tokens"]),
            "max_output_tokens": int(entry["max_output_tokens"]),
            "max_token_layers": int(entry["max_token_layers"]),
            "max_cost": int(entry["max_cost"]),
            "execution_deadline": int(status["execution_deadline"]),
            "settlement_deadline": int(status["settlement_deadline"]),
            "server_time": int(entry["claimed_at"]),
            "claim_response_sha256": entry["claim_response_sha256"],
        }

    def authorize_spend(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        request = _strict_fields(
            body,
            {
                "client_nonce", "session_id", "model_id", "billing_mode",
                "max_prompt_tokens", "max_output_tokens", "workers",
            },
            name="spend authorize",
        )
        payer_account, payer_tier = _row_identity(keyid, roster)
        client_nonce = _bounded_text(request["client_nonce"], "client_nonce")
        session_id = _bounded_text(request["session_id"], "session_id")
        model_id = _bounded_text(request["model_id"], "model_id")
        billing_mode = _bounded_text(request["billing_mode"], "billing_mode")
        if billing_mode != "greedy-direct-v1":
            raise LedgerValueError("billing_mode must be greedy-direct-v1")
        prompt_cap = _bounded_integer(
            request["max_prompt_tokens"], "max_prompt_tokens",
            low=0, high=MAX_SPEND_PROMPT_TOKENS,
        )
        output_cap = _bounded_integer(
            request["max_output_tokens"], "max_output_tokens",
            low=0, high=MAX_SPEND_OUTPUT_TOKENS,
        )
        if prompt_cap + output_cap == 0:
            raise LedgerValueError("prompt and output caps cannot both be zero")
        raw_workers = request["workers"]
        if not isinstance(raw_workers, list):
            raise LedgerValueError("workers must be a list")
        if not 1 <= len(raw_workers) <= MAX_SPEND_WORKERS:
            raise LedgerValueError(
                f"workers must contain between 1 and {MAX_SPEND_WORKERS} entries"
            )
        workers = []
        seen: set[str] = set()
        for index, raw in enumerate(raw_workers):
            worker = _strict_fields(
                raw,
                {"worker_keyid", "layer_start", "layer_end"},
                name=f"spend authorize worker[{index}]",
            )
            worker_keyid = _ed25519_keyid(worker["worker_keyid"], "worker_keyid")
            if worker_keyid in seen:
                raise LedgerValueError("worker_keyid entries must be unique")
            seen.add(worker_keyid)
            worker_account, _worker_tier = _row_identity(worker_keyid, roster)
            layer_start = _bounded_integer(
                worker["layer_start"], "layer_start", low=0, high=MAX_SPEND_LAYERS - 1
            )
            layer_end = _bounded_integer(
                worker["layer_end"], "layer_end", low=1, high=MAX_SPEND_LAYERS
            )
            if layer_end <= layer_start:
                raise LedgerValueError("layer_end must be greater than layer_start")
            workers.append(
                {
                    "worker_keyid": worker_keyid,
                    "worker_account": worker_account,
                    "layer_start": layer_start,
                    "layer_end": layer_end,
                    "price_multiplier": SPEND_PRICE_MULTIPLIER,
                }
            )

        token = secrets.token_urlsafe(32)
        token_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        status = self.store.authorize_spend(
            payer_keyid=keyid,
            payer_account=payer_account,
            tier=payer_tier,
            client_nonce=client_nonce,
            session_id=session_id,
            model_id=model_id,
            billing_mode=billing_mode,
            max_prompt_tokens=prompt_cap,
            max_output_tokens=output_cap,
            workers=workers,
            token_digest=token_digest,
        )
        return {
            "v": 1,
            "claim_token": token,
            "hold_id": status["hold_id"],
            "max_token_layers": int(status["max_token_layers"]),
            "max_cost": int(status["max_cost"]),
            "execution_deadline": int(status["execution_deadline"]),
            "settlement_deadline": int(status["settlement_deadline"]),
            "workers": [
                {
                    "worker_keyid": worker["worker_keyid"],
                    "billable": bool(worker["billable"]),
                    "max_token_layers": int(worker["max_token_layers"]),
                    "max_cost": int(worker["max_cost"]),
                }
                for worker in status["workers"]
            ],
        }

    def claim_spend(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(
            body, {"claim_token", "claim_instance"}, name="spend claim"
        )
        token = _claim_token(request["claim_token"])
        claim_instance = _bounded_text(request["claim_instance"], "claim_instance")
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        status = self.store.claim_spend_worker_for_token(
            digest, keyid, claim_instance
        )
        return self._claim_response(status, keyid)

    def settle_spend(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(
            body, {"receipt", "signature"}, name="spend settle"
        )
        receipt = request["receipt"]
        signature = request["signature"]
        if not isinstance(receipt, dict):
            raise LedgerValueError("receipt must be an object")
        if set(receipt) == SPEND_USAGE_FIELDS:
            _ed25519_keyid(receipt["payer_keyid"], "payer_keyid")
            _ed25519_keyid(receipt["worker_keyid"], "worker_keyid")
            for field in (
                "hold_id", "payer_account_at_authorize",
                "worker_account_at_authorize", "session_id", "model_id",
                "billing_mode",
            ):
                _bounded_text(receipt[field], field)
            _bounded_text(receipt["termination"], "termination", maximum=64)
            if keyid not in {receipt["worker_keyid"], receipt["payer_keyid"]}:
                raise SpendNotFound("spend hold not found")
        if (
            not isinstance(signature, str)
            or re.fullmatch(r"[0-9a-f]{128}", signature) is None
        ):
            raise LedgerValueError("signature must be 64-byte lowercase hex")
        status = self.store.settle_spend_usage(
            receipt, signature, relayer_keyid=keyid
        )
        worker = next(
            entry for entry in status["workers"]
            if entry["worker_keyid"] == receipt.get("worker_keyid")
        )
        return {
            "v": 1,
            "hold_id": status["hold_id"],
            "receipt_id": status["receipt_id"],
            "accepted_delta": int(status["accepted_delta"]),
            "cumulative_charge": int(worker["cumulative_cost"]),
            "replayed": bool(status["replayed"]),
            "state": status["state"],
        }

    def abandon_spend(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(
            body, {"hold_id", "worker_keyid"}, name="spend abandon"
        )
        hold_id = _bounded_text(request["hold_id"], "hold_id")
        worker_keyid = _ed25519_keyid(request["worker_keyid"], "worker_keyid")
        status = self.store.abandon_spend_worker(hold_id, worker_keyid, keyid)
        return self._status_response(status)

    def release_spend(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(body, {"hold_id"}, name="spend release")
        hold_id = _bounded_text(request["hold_id"], "hold_id")
        status = self.store.request_spend_release(hold_id, keyid)
        return self._status_response(status)

    @staticmethod
    def _task_hold_response(
        status: Mapping[str, object], *, replayed: bool | None = None
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "v": 1,
            "hold_id": status["hold_id"],
            "task_hash": status["task_hash"],
            "worker_keyid": status["worker_keyid"],
            "amount": int(status["amount"]),
            "deadline": int(status["deadline"]),
            "state": status["state"],
        }
        if replayed is not None:
            result["replayed"] = replayed
        return result

    def authorize_task_hold(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        request = _strict_fields(
            body,
            {"client_nonce", "task_hash", "worker_keyid", "amount", "deadline"},
            name="task authorize",
        )
        payer_account, payer_tier = _row_identity(keyid, roster)
        client_nonce = _bounded_text(
            request["client_nonce"], "client_nonce", maximum=128
        )
        task_hash = request["task_hash"]
        if not isinstance(task_hash, str) or re.fullmatch(r"[0-9a-f]{64}", task_hash) is None:
            raise LedgerValueError("task_hash must be 64 lowercase hex")
        worker_keyid = _ed25519_keyid(request["worker_keyid"], "worker_keyid")
        worker_account, _worker_tier = _row_identity(worker_keyid, roster)
        if worker_account == payer_account:
            raise LedgerValueError("task hold cannot pay the payer's own account")
        amount = _bounded_integer(
            request["amount"], "amount", low=1, high=TASK_MAX_AMOUNT
        )
        now = self.store._now()
        # An identical replay of an already-authorized (payer, client_nonce) is answered by the
        # store (same hold, or 409 if any field differs) BEFORE the new-hold deadline window, so a
        # crash-recovery re-assign close to the deadline gets its hold back instead of a 422.
        replay = self.store.has_task_hold_nonce(keyid, client_nonce)
        deadline = _bounded_integer(
            request["deadline"],
            "deadline",
            low=0 if replay else now + TASK_DEADLINE_MIN_S,
            high=now + TASK_DEADLINE_MAX_S,
        )
        status = self.store.authorize_task_hold(
            payer_keyid=keyid,
            payer_account=payer_account,
            tier=payer_tier,
            client_nonce=client_nonce,
            task_hash=task_hash,
            worker_keyid=worker_keyid,
            worker_account=worker_account,
            amount=amount,
            deadline=deadline,
        )
        return self._task_hold_response(status)

    def pay_task_hold(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(body, {"hold_id"}, name="task pay")
        hold_id = _bounded_text(request["hold_id"], "hold_id")
        status = self.store.pay_task_hold(hold_id, keyid)
        return self._task_hold_response(status, replayed=bool(status["replayed"]))

    def submit_task_hold(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(
            body, {"hold_id", "result_hash"}, name="task submit"
        )
        hold_id = _bounded_text(request["hold_id"], "hold_id")
        result_hash = request["result_hash"]
        if (
            not isinstance(result_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", result_hash) is None
        ):
            raise LedgerValueError("result_hash must be 64 lowercase hex")
        status = self.store.submit_task_hold(hold_id, keyid, result_hash)
        result = self._task_hold_response(
            status, replayed=bool(status["replayed"])
        )
        result["submitted_at"] = int(status["submitted_at"])
        result["result_hash"] = status["result_hash"]
        return result

    def receive_task_hold(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(
            body, {"hold_id", "result_hash"}, name="task received"
        )
        hold_id = _bounded_text(request["hold_id"], "hold_id")
        result_hash = request["result_hash"]
        if (
            not isinstance(result_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", result_hash) is None
        ):
            raise LedgerValueError("result_hash must be 64 lowercase hex")
        status = self.store.receive_task_hold(hold_id, keyid, result_hash)
        result = self._task_hold_response(
            status, replayed=bool(status["replayed"])
        )
        result["received_at"] = int(status["received_at"])
        result["received_hash"] = status["received_hash"]
        return result

    def refund_task_hold(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(body, {"hold_id", "reason"}, name="task refund")
        hold_id = _bounded_text(request["hold_id"], "hold_id")
        reason = _bounded_text(request["reason"], "reason", maximum=64)
        status = self.store.refund_task_hold(hold_id, keyid, reason)
        return self._task_hold_response(status, replayed=bool(status["replayed"]))

    def dispute_task_hold(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        request = _strict_fields(
            body, {"hold_id", "reason", "note"}, name="task dispute"
        )
        hold_id = _bounded_text(request["hold_id"], "hold_id")
        reason = _bounded_text(request["reason"], "reason", maximum=64)
        note = _bounded_note(request["note"])
        status = self.store.dispute_task_hold(
            hold_id, keyid, reason, note
        )
        return self._task_hold_response(status, replayed=bool(status["replayed"]))

    def resolve_task_hold(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _operator, tier = _row_identity(keyid, roster)
        if tier != "self":
            raise PermissionError("only the ledger operator may resolve task disputes")
        request = _strict_fields(
            body, {"hold_id", "outcome", "reason"}, name="task resolve"
        )
        hold_id = _bounded_text(request["hold_id"], "hold_id")
        outcome = _bounded_text(request["outcome"], "outcome", maximum=6)
        reason = _bounded_text(request["reason"], "reason", maximum=64)
        status = self.store.resolve_task_hold(hold_id, outcome, reason)
        return self._task_hold_response(status, replayed=bool(status["replayed"]))

    def task_hold_status(
        self,
        hold_id: str,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        hold_id = _bounded_text(hold_id, "hold_id")
        status = self.store.task_hold_status_scoped(hold_id, keyid)
        return {
            "v": 1,
            "hold_id": status["hold_id"],
            "task_hash": status["task_hash"],
            "payer_account": status["payer_account"],
            "worker_keyid": status["worker_keyid"],
            "amount": int(status["amount"]),
            "deadline": int(status["deadline"]),
            "state": status["state"],
            "submitted_at": int(status["submitted_at"]),
            "result_hash": status["result_hash"],
            "received_at": int(status["received_at"]),
            "received_hash": status["received_hash"],
            "dispute_reason": status["dispute_reason"],
            "locked": bool(status["locked"]),
            "refund_after_submit": (
                status["state"] == "refunded" and int(status["submitted_at"]) > 0
            ),
            "server_time": self.store._now(),
        }

    @staticmethod
    def _starter_response(
        grant: Mapping[str, object], *, include_replayed: bool
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "v": 1,
            "invite_id": grant["invite_id"],
            "from_account": grant["src_account"],
            "to_account": grant["dst_account"],
            "to_keyid": grant["to_keyid"],
            "amount": int(grant["amount"]),
            "ts": int(grant["ts"]),
        }
        if include_replayed:
            result["replayed"] = bool(grant["replayed"])
        return result

    @staticmethod
    def _starter_row_identity(
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
        *,
        recipient: bool = False,
    ) -> tuple[str, str]:
        row = roster.get(keyid)
        if recipient and not isinstance(row, Mapping):
            raise LookupError("recipient not in roster")
        if isinstance(row, Mapping) and is_reserved(row.get("operator")):
            raise LedgerValueError("starter grant account is reserved")
        return _row_identity(keyid, roster)

    def grant_starter(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        request = _strict_fields(
            body, {"invite_id", "to_keyid", "amount"}, name="starter grant"
        )
        src, src_tier = self._starter_row_identity(keyid, roster)
        invite_id = request["invite_id"]
        if (
            not isinstance(invite_id, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", invite_id) is None
        ):
            raise LedgerValueError(
                "invite_id must be 1..64 characters from A-Za-z0-9_-"
            )
        to_keyid = request["to_keyid"]
        if (
            not isinstance(to_keyid, str)
            or re.fullmatch(r"[0-9a-f]{64}", to_keyid) is None
        ):
            raise LedgerValueError("to_keyid must be 64 lowercase hex")
        dst, dst_tier = self._starter_row_identity(
            to_keyid, roster, recipient=True
        )
        amount = _bounded_integer(
            request["amount"], "amount", low=1, high=STARTER_MAX
        )
        grant = self.store.grant_starter(
            invite_id,
            src,
            dst,
            to_keyid,
            amount,
            src_tier,
            dst_tier,
        )
        return self._starter_response(grant, include_replayed=True)

    def starter_status(
        self,
        invite_id: str,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        src, _src_tier = self._starter_row_identity(keyid, roster)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", invite_id) is None:
            raise LedgerValueError(
                "invite_id must be 1..64 characters from A-Za-z0-9_-"
            )
        grant = self.store.starter_grant(src, invite_id)
        if grant is None:
            raise LookupError("starter grant not found")
        return self._starter_response(grant, include_replayed=False)

    def spend_status(
        self,
        hold_id: str,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        hold_id = _bounded_text(hold_id, "hold_id")
        status = self.store.refresh_spend_status_scoped(hold_id, keyid)
        return self._status_response(status)

    def spend_ready(
        self,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        _row_identity(keyid, roster)
        with self.store._lock:
            self.store._db.execute("SELECT 1").fetchone()
        return {
            "v": 1,
            "ready": self._sweep_error is None,
            "capability": SPEND_CAPABILITY,
            "server_time": self.store._now(),
        }

    def settle(
        self,
        body: object,
        keyid: str,
        roster: Mapping[str, Mapping[str, object]],
    ) -> dict[str, object]:
        if (
            not isinstance(body, dict)
            or set(body) != {"receipt"}
            or not isinstance(body.get("receipt"), dict)
        ):
            raise ReceiptError("legacy settle body must contain exactly receipt")
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
            spend_endpoint = target.path in _SPEND_PATHS
            if spend_endpoint and (
                not _spend_routes_enabled() or not _loopback_client(self.client_address)
            ):
                self._send(404, {"error": "not found"})
                return
            spend_path = target.path in _SPEND_GET_PATHS
            if target.path not in (
                "/balance", "/history", "/can_consume", "/wallet", "/wallet/status",
                *_SPEND_GET_PATHS,
            ):
                self._send(404, {"error": "not found"})
                return
            body_bytes = b""
            if spend_path:
                raw_body = self._raw_body()
                if raw_body is None:
                    return
                body_bytes = raw_body
            authenticated = self._authenticate("GET", body_bytes)
            if authenticated is None:
                return
            keyid, roster = authenticated
            if spend_path and body_bytes:
                self._send(400, {"error": "spend GET routes require an empty body"})
                return
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
                elif target.path == "/wallet/status":
                    result = svc.wallet_status(keyid, roster)
                elif target.path == "/spend/status":
                    query = _exact_query(target, {"hold_id"})
                    result = svc.spend_status(query["hold_id"], keyid, roster)
                elif target.path == "/spend/task/status":
                    query = _exact_query(target, {"hold_id"})
                    result = svc.task_hold_status(query["hold_id"], keyid, roster)
                elif target.path == "/spend/starter/status":
                    query = _exact_query(target, {"invite_id"})
                    result = svc.starter_status(query["invite_id"], keyid, roster)
                elif target.path == "/spend/ready":
                    _exact_query(target, set())
                    result = svc.spend_ready(keyid, roster)
                else:
                    self._send(404, {"error": "not found"})
                    return
                self._send(200, result)
            except PermissionError as exc:
                self._send(403, {"error": str(exc)})
            except SpendConflict as exc:
                self._send(409, {"error": str(exc)})
            except SpendExpired as exc:
                self._send(410, {"error": str(exc), "code": "spend_expired"})
            except SpendNotFound:
                self._send(404, {"error": "spend hold not found"})
            except SpendStateError as exc:
                code = 404 if "does not exist" in str(exc) else 409
                self._send(code, {"error": str(exc)})
            except LookupError as exc:
                self._send(404, {"error": str(exc)})
            except LedgerValueError as exc:
                self._send(422, {"error": str(exc)})

        def do_POST(self) -> None:
            target = urlparse(self.path)
            funds_path = target.path in ("/wallet/bind", "/withdraw")
            if funds_path and not _funds_routes_enabled():
                self._send(404, {"error": "not found"})
                return
            spend_endpoint = target.path in _SPEND_PATHS
            if spend_endpoint and (
                not _spend_routes_enabled() or not _loopback_client(self.client_address)
            ):
                self._send(404, {"error": "not found"})
                return
            spend_path = target.path in _SPEND_POST_PATHS
            body_bytes = self._raw_body()
            if body_bytes is None:
                return
            authenticated = self._authenticate("POST", body_bytes)
            if authenticated is None:
                return
            keyid, roster = authenticated
            if target.path not in (
                "/settle", "/transfer", "/dispute", "/wallet/bind", "/withdraw",
                *_SPEND_POST_PATHS,
            ):
                self._send(404, {"error": "not found"})
                return
            try:
                body = (
                    _strict_json_object(body_bytes)
                    if spend_path
                    else json.loads(body_bytes or b"{}")
                )
            except (UnicodeDecodeError, json.JSONDecodeError, LedgerValueError):
                self._send(400, {"error": "body must be valid JSON"})
                return
            try:
                if spend_path and target.query:
                    raise LedgerValueError("spend POST routes do not accept a query")
                if target.path == "/settle":
                    result = svc.settle(body, keyid, roster)
                elif target.path == "/transfer":
                    result = svc.transfer(body, keyid, roster)
                elif target.path == "/dispute":
                    result = svc.dispute(body, keyid, roster)
                elif target.path == "/wallet/bind":
                    result = svc.bind_wallet(body, keyid, roster)
                elif target.path == "/withdraw":
                    result = svc.withdraw(body, keyid, roster)
                elif target.path == "/spend/authorize":
                    result = svc.authorize_spend(body, keyid, roster)
                elif target.path == "/spend/claim":
                    result = svc.claim_spend(body, keyid, roster)
                elif target.path == "/spend/settle":
                    result = svc.settle_spend(body, keyid, roster)
                elif target.path == "/spend/abandon":
                    result = svc.abandon_spend(body, keyid, roster)
                elif target.path == "/spend/release":
                    result = svc.release_spend(body, keyid, roster)
                elif target.path == "/spend/task/authorize":
                    result = svc.authorize_task_hold(body, keyid, roster)
                elif target.path == "/spend/task/submit":
                    result = svc.submit_task_hold(body, keyid, roster)
                elif target.path == "/spend/task/received":
                    result = svc.receive_task_hold(body, keyid, roster)
                elif target.path == "/spend/task/pay":
                    result = svc.pay_task_hold(body, keyid, roster)
                elif target.path == "/spend/task/refund":
                    result = svc.refund_task_hold(body, keyid, roster)
                elif target.path == "/spend/task/dispute":
                    result = svc.dispute_task_hold(body, keyid, roster)
                elif target.path == "/spend/task/resolve":
                    result = svc.resolve_task_hold(body, keyid, roster)
                elif target.path == "/spend/starter":
                    result = svc.grant_starter(body, keyid, roster)
                else:
                    self._send(404, {"error": "not found"})
                    return
                self._send(200, result)
            except CreditLimitError as exc:
                self._send(422 if target.path == "/withdraw" else 402,
                           {"error": str(exc)})
            except (PayoutAddressError, WithdrawalTierError) as exc:
                self._send(403, {"error": str(exc)})
            except WithdrawalRateLimitError as exc:
                self._send(429, {"error": str(exc)})
            except SpendConflict as exc:
                self._send(409, {"error": str(exc)})
            except SpendExpired as exc:
                expiry = (
                    "execution_expired"
                    if target.path in ("/spend/claim", "/spend/abandon")
                    else "settlement_expired"
                )
                self._send(410, {"error": str(exc), "code": expiry})
            except SpendNotFound:
                self._send(404, {"error": "spend hold not found"})
            except TaskSubmittedLocked as exc:
                self._send(409, {"error": str(exc), "code": exc.code})
            except SpendStateError as exc:
                code = 404 if "does not exist" in str(exc) else 409
                payload: dict[str, object] = {"error": str(exc)}
                if isinstance(exc, TaskHoldNotOpen):
                    payload["state"] = exc.state
                self._send(code, payload)
            except ReceiptStateError as exc:
                self._send(409, {"error": str(exc)})
            except PermissionError as exc:
                self._send(403, {"error": str(exc)})
            except LookupError as exc:
                self._send(404, {"error": str(exc)})
            except (ReceiptError, LedgerValueError, KeyError) as exc:
                self._send(422, {"error": str(exc)})

    return H


class _DualHTTPServer:
    """Serve one handler on the mesh address and a loopback address."""

    def __init__(
        self,
        host: str,
        port: int,
        loopback_port: int,
        handler: type[BaseHTTPRequestHandler],
    ):
        self.primary = ThreadingHTTPServer((host, port), handler)
        try:
            self.loopback = ThreadingHTTPServer(
                ("127.0.0.1", loopback_port), handler
            )
        except BaseException:
            self.primary.server_close()
            raise
        self._loopback_thread: threading.Thread | None = None

    def serve_forever(self) -> None:
        self._loopback_thread = threading.Thread(
            target=self.loopback.serve_forever,
            name="neuron-ledger-loopback-listener",
            daemon=True,
        )
        self._loopback_thread.start()
        try:
            self.primary.serve_forever()
        finally:
            self.loopback.shutdown()
            self._loopback_thread.join()
            self.server_close()

    def shutdown(self) -> None:
        """Stop both serving loops when called from another thread."""
        self.primary.shutdown()
        self.loopback.shutdown()

    def server_close(self) -> None:
        self.primary.server_close()
        self.loopback.server_close()


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8093)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument(
        "--loopback-port", type=int,
        help="also listen on 127.0.0.1:PORT using the same service instance",
    )
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
    if args.loopback_port is None:
        srv = ThreadingHTTPServer((args.host, args.port), handler)
        print(f"[ledger] serving on {args.host}:{args.port}  store={description}", flush=True)
        try:
            srv.serve_forever()
        finally:
            if isinstance(svc, V2LedgerService):
                svc.close()
        return

    servers = _DualHTTPServer(args.host, args.port, args.loopback_port, handler)
    print(f"[ledger] serving on {args.host}:{args.port}  store={description}", flush=True)
    print(
        f"[ledger] also serving on 127.0.0.1:{args.loopback_port}",
        flush=True,
    )
    try:
        servers.serve_forever()
    finally:
        servers.server_close()
        if isinstance(svc, V2LedgerService):
            svc.close()


if __name__ == "__main__":
    main()
