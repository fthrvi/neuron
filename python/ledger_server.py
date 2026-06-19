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
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qs, urlparse

import sys
sys.path.insert(0, os.path.dirname(__file__))
from core.credit_ledger import CreditLedger, CreditError  # noqa: E402

DEFAULT_PATH = os.path.expanduser("~/.neuron/credits/ledger.json")


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
    def settle(self, receipt: dict, requester: str) -> dict:
        d = self.led.settle(receipt, requester)   # raises CreditError on a bad receipt
        self._save()
        return {"run_id": d.run_id, "credited": d.credited, "requester": d.requester,
                "debited": d.debited, "total": d.total}

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
                        return self._send(200, {"delta": svc.settle(b["receipt"], b["requester"])})
                    except CreditError as e:
                        return self._send(422, {"error": str(e)})   # bad/forged receipt
                if u.path == "/dispute":
                    return self._send(200, svc.dispute(b["run_id"]))
                return self._send(404, {"error": "not found"})
            except Exception as e:
                return self._send(500, {"error": repr(e)})
    return H


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8093)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--path", default=DEFAULT_PATH)
    ap.add_argument("--grace", type=int, default=0, help="bootstrap consume allowance per account")
    args = ap.parse_args()
    svc = LedgerService(args.path, grace=args.grace)
    srv = ThreadingHTTPServer((args.host, args.port), _make_handler(svc))
    print(f"[ledger] serving on {args.host}:{args.port}  store={args.path}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
