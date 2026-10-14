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


MAINNET_BETA_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"


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
    """Synchronous stdlib client for the indexer's finalized RPC reads.

    ``urllib`` does not expose a durable connection contract, so a pinned
    client verifies ``getGenesisHash`` before every subsequent RPC request.
    That is deliberately stricter than merely checking after a detectable
    reconnect: every HTTP connection is treated as a possible reconnect.
    """

    def __init__(self, url: str, *, timeout: float = 25.0):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("RPC URL must be an http(s) URL")
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("RPC URL must not contain credentials or a fragment")
        self.url = url
        self.timeout = timeout
        self._ids = itertools.count(1)
        self._pinned_genesis: str | None = None

    def _request(self, method: str, params: list[Any]) -> Any:
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

    def _read_genesis_hash(self) -> str:
        result = self._request("getGenesisHash", [])
        if not isinstance(result, str) or not result:
            raise RPCError("getGenesisHash result is not a non-empty string")
        try:
            validate_pubkey(result, "genesis hash")
        except ValueError as exc:
            raise RPCError(str(exc)) from exc
        return result

    def pin_genesis(self, expected: str | None = None) -> str:
        """Pin this endpoint to its current genesis, optionally requiring one."""
        actual = self._read_genesis_hash()
        if expected is not None and actual != expected:
            raise RPCError(f"genesis hash {actual} does not match expected {expected}")
        self._pinned_genesis = actual
        return actual

    def get_genesis_hash(self) -> str:
        return self._read_genesis_hash()

    def call(self, method: str, params: list[Any]) -> Any:
        if method != "getGenesisHash" and self._pinned_genesis is not None:
            actual = self._read_genesis_hash()
            if actual == MAINNET_BETA_GENESIS_HASH:
                raise RPCError("RPC reconnected to explicitly refused mainnet-beta genesis")
            if actual != self._pinned_genesis:
                raise RPCError(
                    f"RPC genesis changed from {self._pinned_genesis} to {actual}"
                )
        return self._request(method, params)

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
            parsed_account = {
                "mint": info["mint"],
                "amount": int(token_amount["amount"]),
                "decimals": int(token_amount["decimals"]),
                "slot": int(result["context"]["slot"]),
            }
            if isinstance(info.get("owner"), str):
                parsed_account["owner"] = info["owner"]
            return parsed_account
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise RPCError(f"{address} is not a parsed SPL token account") from exc

    def get_token_accounts(self, addresses: list[str]) -> dict[str, Any]:
        """Read token accounts atomically at one finalized RPC context slot."""
        if not addresses:
            raise ValueError("at least one token account is required")
        if len(set(addresses)) != len(addresses):
            raise ValueError("token account addresses must be unique")
        result = self.call(
            "getMultipleAccounts",
            [addresses, {"commitment": "finalized", "encoding": "jsonParsed"}],
        )
        try:
            slot = int(result["context"]["slot"])
            values = result["value"]
            if slot < 0 or not isinstance(values, list) or len(values) != len(addresses):
                raise ValueError("invalid context or account count")
            accounts: list[dict[str, Any]] = []
            for address, value in zip(addresses, values, strict=True):
                parsed = value["data"]["parsed"]
                if parsed["type"] != "account":
                    raise KeyError("type")
                info = parsed["info"]
                token_amount = info["tokenAmount"]
                account = {
                    "token_account": address,
                    "mint": info["mint"],
                    "amount": int(token_amount["amount"]),
                    "decimals": int(token_amount["decimals"]),
                    "owner": info["owner"],
                }
                if account["amount"] < 0:
                    raise ValueError("negative token amount")
                accounts.append(account)
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise RPCError("getMultipleAccounts returned malformed token accounts") from exc
        return {"slot": slot, "accounts": accounts}

    def get_latest_blockhash(self) -> dict[str, Any]:
        result = self.call(
            "getLatestBlockhash", [{"commitment": "finalized"}]
        )
        try:
            value = result["value"]
            blockhash = validate_pubkey(value["blockhash"], "blockhash")
            last_valid = int(value["lastValidBlockHeight"])
            if last_valid < 0:
                raise ValueError("negative height")
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise RPCError("getLatestBlockhash returned malformed data") from exc
        return {"blockhash": blockhash, "last_valid_block_height": last_valid}

    def get_block_height(self) -> int:
        result = self.call("getBlockHeight", [{"commitment": "finalized"}])
        if isinstance(result, bool) or not isinstance(result, int) or result < 0:
            raise RPCError("getBlockHeight result is not a non-negative integer")
        return result

    def get_minimum_balance_for_rent_exemption(self, size: int) -> int:
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ValueError("account size must be a positive integer")
        result = self.call(
            "getMinimumBalanceForRentExemption",
            [size, {"commitment": "finalized"}],
        )
        if isinstance(result, bool) or not isinstance(result, int) or result < 0:
            raise RPCError(
                "getMinimumBalanceForRentExemption result is not a non-negative integer"
            )
        return result

    def get_signature_status(self, signature: str) -> dict[str, Any] | None:
        result = self.call(
            "getSignatureStatuses",
            [[signature], {"searchTransactionHistory": True}],
        )
        try:
            values = result["value"]
            status = values[0]
        except (KeyError, IndexError, TypeError) as exc:
            raise RPCError("getSignatureStatuses returned malformed data") from exc
        if status is not None and not isinstance(status, dict):
            raise RPCError("signature status is neither an object nor null")
        return status

    def get_signature_statuses(
        self, signatures: list[str]
    ) -> dict[str, dict[str, Any] | None]:
        """Read all requested statuses in one RPC call."""
        if len(set(signatures)) != len(signatures):
            raise ValueError("signatures must be unique")
        if not signatures:
            return {}
        result = self.call(
            "getSignatureStatuses",
            [signatures, {"searchTransactionHistory": True}],
        )
        try:
            values = result["value"]
            if not isinstance(values, list) or len(values) != len(signatures):
                raise TypeError("invalid status count")
            statuses = dict(zip(signatures, values, strict=True))
        except (KeyError, TypeError, ValueError) as exc:
            raise RPCError("getSignatureStatuses returned malformed data") from exc
        if any(value is not None and not isinstance(value, dict) for value in values):
            raise RPCError("signature status is neither an object nor null")
        return statuses

    def send_transaction(self, transaction_b64: str) -> str:
        result = self.call(
            "sendTransaction",
            [
                transaction_b64,
                {
                    "encoding": "base64",
                    "preflightCommitment": "finalized",
                    "skipPreflight": False,
                    "maxRetries": 0,
                },
            ],
        )
        if not isinstance(result, str) or not result:
            raise RPCError("sendTransaction result is not a signature")
        return result

    def account_exists(self, address: str) -> bool:
        result = self.call(
            "getAccountInfo", [address, {"commitment": "finalized", "encoding": "base64"}]
        )
        try:
            value = result["value"]
        except (KeyError, TypeError) as exc:
            raise RPCError("getAccountInfo returned malformed data") from exc
        if value is not None and not isinstance(value, dict):
            raise RPCError("getAccountInfo value is neither an object nor null")
        return value is not None
