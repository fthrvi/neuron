"""Protocol-shape tests for the dependency-free Solana JSON-RPC client."""
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import chain.solana_rpc as solana_rpc  # noqa: E402
from chain.solana_rpc import RPCError, SolanaRPC  # noqa: E402


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_requests_finalized_json_parsed_transactions(monkeypatch):
    seen = []

    def urlopen(request, timeout):
        seen.append((json.loads(request.data), timeout, dict(request.headers)))
        return _Response(
            json.dumps(
                {"jsonrpc": "2.0", "id": 1, "result": {"slot": 1, "meta": {}}}
            ).encode()
        )

    monkeypatch.setattr(solana_rpc.urllib.request, "urlopen", urlopen)
    client = SolanaRPC("http://127.0.0.1:8899", timeout=3)
    assert client.get_transaction("signature")["slot"] == 1
    payload, timeout, headers = seen[0]
    assert timeout == 3
    assert headers["Content-type"] == "application/json"
    assert payload == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            "signature",
            {
                "commitment": "finalized",
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0,
            },
        ],
    }


def test_rpc_error_is_not_returned_as_a_result(monkeypatch):
    def urlopen(_request, timeout):
        return _Response(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32000, "message": "node unhealthy"},
                }
            ).encode()
        )

    monkeypatch.setattr(solana_rpc.urllib.request, "urlopen", urlopen)
    with pytest.raises(RPCError, match="node unhealthy"):
        SolanaRPC("http://127.0.0.1:8899").call("getHealth", [])


def test_parses_token_account_raw_amount(monkeypatch):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "context": {"slot": 99},
            "value": {
                "data": {
                    "parsed": {
                        "type": "account",
                        "info": {
                            "mint": "mint",
                            "tokenAmount": {"amount": "1234567", "decimals": 6},
                        },
                    }
                }
            },
        },
    }
    monkeypatch.setattr(
        solana_rpc.urllib.request,
        "urlopen",
        lambda _request, timeout: _Response(json.dumps(payload).encode()),
    )
    assert SolanaRPC("http://127.0.0.1:8899").get_token_account("account") == {
        "mint": "mint",
        "amount": 1_234_567,
        "decimals": 6,
        "slot": 99,
    }
