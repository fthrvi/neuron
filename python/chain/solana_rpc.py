"""Small, dependency-free Solana JSON-RPC client.

Only the finalized, read-only calls needed by the deposit indexer live here.
The module deliberately contains no signing or key-loading code.
"""
from __future__ import annotations

import itertools
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class RPCError(RuntimeError):
    """A transport, protocol, or Solana JSON-RPC error."""


def decode_base58(value: str) -> bytes:
    """Decode an unpadded Bitcoin-base58 string without a third-party package."""
    if not isinstance(value, str) or not value:
        raise ValueError("base58 value must be a non-empty string")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    lookup = {char: index for index, char in enumerate(alphabet)}
    number = 0
    try:
        for char in value:
            number = number * 58 + lookup[char]
    except KeyError as exc:
        raise ValueError(f"invalid base58 character {exc.args[0]!r}") from None
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + body


def validate_pubkey(value: str, name: str = "public key") -> str:
    """Return *value* if it is the base58 encoding of exactly 32 bytes."""
    try:
        decoded = decode_base58(value)
    except ValueError as exc:
        raise ValueError(f"{name} is not valid base58: {exc}") from exc
    if len(decoded) != 32:
        raise ValueError(f"{name} must decode to 32 bytes, got {len(decoded)}")
    return value


class SolanaRPC:
    """Synchronous stdlib client for the indexer's finalized RPC reads."""

    def __init__(self, url: str, *, timeout: float = 25.0):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("RPC URL must be an http(s) URL")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("RPC URL must not contain credentials or a fragment")
        self.url = url
        self.timeout = timeout
        self._ids = itertools.count(1)

    def call(self, method: str, params: list[Any]) -> Any:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "nak-indexer/1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise RPCError(f"{method} transport failed: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            raise RPCError(f"{method} returned an invalid JSON-RPC response")
        if payload.get("error") is not None:
            error = payload["error"]
            if isinstance(error, dict):
                raise RPCError(
                    f"{method} failed ({error.get('code')}): {error.get('message')}"
                )
            raise RPCError(f"{method} failed: {error}")
        if "result" not in payload:
            raise RPCError(f"{method} response has no result")
        return payload["result"]

    def get_signatures_for_address(
        self,
        address: str,
        *,
        before: str | None = None,
        until: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        options: dict[str, Any] = {"commitment": "finalized", "limit": limit}
        if before:
            options["before"] = before
        if until:
            options["until"] = until
        result = self.call("getSignaturesForAddress", [address, options])
        if not isinstance(result, list):
            raise RPCError("getSignaturesForAddress result is not a list")
        return result

    def get_transaction(self, signature: str) -> dict[str, Any] | None:
        result = self.call(
            "getTransaction",
            [
                signature,
                {
                    "commitment": "finalized",
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )
        if result is not None and not isinstance(result, dict):
            raise RPCError("getTransaction result is neither an object nor null")
        return result

    def get_token_account(self, address: str) -> dict[str, Any]:
        result = self.call(
            "getAccountInfo", [address, {"commitment": "finalized", "encoding": "jsonParsed"}]
        )
        try:
            value = result["value"]
            parsed = value["data"]["parsed"]
            if parsed["type"] != "account":
                raise KeyError("type")
            info = parsed["info"]
            token_amount = info["tokenAmount"]
            return {
                "mint": info["mint"],
                "amount": int(token_amount["amount"]),
                "decimals": int(token_amount["decimals"]),
                "slot": int(result["context"]["slot"]),
            }
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise RPCError(f"{address} is not a parsed SPL token account") from exc
