"""
NRN Fee System — Per-inference token pricing.

Users pay NRN for every inference. GPU operators earn NRN for work.
5% of every fee is burned, making NRN deflationary.

All balances live ON-CHAIN. This module only calculates fees,
executes on-chain transfers, and records history.
No off-chain ledger — your wallet IS your balance, like Bitcoin.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# Base price: NRN per token (completion tokens)
# Prompt tokens charged at 25% of this rate
BASE_NRN_PER_TOKEN = 0.000010  # 0.00001 NRN per completion token
PROMPT_DISCOUNT = 0.25         # prompt tokens cost 25% of completion tokens
BURN_RATE = 0.05               # 5% of every fee is burned

# Model difficulty multipliers
MODEL_FEE_MULTIPLIER = {
    "qwen3:8b": 0.5,
    "llama3:8b": 0.5,
    "llama3.1:8b": 0.6,
    "qwen3:14b": 1.0,
    "llama3:70b": 3.0,
    "qwen3:72b": 3.0,
}


@dataclass
class FeeRecord:
    """A single inference fee record."""
    timestamp: float
    api_key: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    fee_nrn: float
    burn_nrn: float
    operator_nrn: float
    from_address: str = ""
    to_address: str = ""
    tx_hash: str = ""


class FeeEngine:
    """
    Calculates NRN fees and executes on-chain transfers.

    No off-chain balance — everything is on the blockchain.
    """

    def __init__(self, data_dir: Path | None = None):
        self._history: list[FeeRecord] = []
        self._data_dir = data_dir or Path.home() / ".neuron" / "fees"
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._load()

    def calculate_fee(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        model: str = "",
        utilization_mult: float = 1.0,
    ) -> tuple[float, float, float]:
        """
        Calculate NRN fee for an inference request.

        Returns: (total_fee, burn_amount, operator_amount)
        """
        difficulty = MODEL_FEE_MULTIPLIER.get(model, 1.0)

        prompt_cost = prompt_tokens * BASE_NRN_PER_TOKEN * PROMPT_DISCOUNT
        completion_cost = completion_tokens * BASE_NRN_PER_TOKEN
        raw_fee = (prompt_cost + completion_cost) * difficulty * utilization_mult

        total_fee = round(raw_fee, 8)
        burn = round(total_fee * BURN_RATE, 8)
        operator = round(total_fee - burn, 8)

        return total_fee, burn, operator

    def charge(
        self,
        api_key: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        utilization_mult: float = 1.0,
    ) -> FeeRecord | None:
        """
        Charge a user for inference via on-chain transfer.

        Looks up the user's wallet, transfers fee to the GPU operator,
        and burns 5%. If the user has no wallet or insufficient balance,
        the inference still completes but the fee is recorded as unpaid.
        """
        total_fee, burn, operator_pay = self.calculate_fee(
            prompt_tokens, completion_tokens, model, utilization_mult,
        )

        if total_fee <= 0:
            return None

        # Try on-chain transfer
        from_address = ""
        to_address = ""
        tx_hash = ""

        try:
            from core.wallet import get_wallet_manager
            wm = get_wallet_manager()

            # Get user's wallet
            user_address = wm.get_address(api_key) if api_key else ""
            from_address = user_address

            if user_address:
                # Check on-chain balance
                balance = wm.query_balance(user_address)
                if balance >= total_fee:
                    # Get the operator's address (validator who runs the GPU)
                    # For now, the operator is the node running this gateway
                    operator_address = self._get_operator_address()
                    to_address = operator_address

                    if operator_address and operator_address != user_address:
                        # Transfer operator's share on-chain
                        result = wm.send(api_key, operator_address, operator_pay)
                        if result.get("status") == "sent":
                            tx_hash = result.get("tx_hash", "")

                        # Burn 5% on-chain
                        dead_address = "5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM"
                        wm.send(api_key, dead_address, burn)

                        # Record fee on-chain via Fees pallet
                        try:
                            keypair = wm._keypairs.get(api_key)
                            if keypair:
                                from substrateinterface import SubstrateInterface
                                sub = SubstrateInterface(url="ws://127.0.0.1:9944")
                                model_bytes = model.encode()[:8]
                                model_hash = list(model_bytes) + [0] * (8 - len(model_bytes))
                                call = sub.compose_call(
                                    call_module="Fees",
                                    call_function="record_fee",
                                    call_params={
                                        "operator": operator_address,
                                        "total_fee": int(total_fee * 1_000_000_000_000),
                                        "burned": int(burn * 1_000_000_000_000),
                                        "tokens": prompt_tokens + completion_tokens,
                                        "model_hash": model_hash,
                                    },
                                )
                                extrinsic = sub.create_signed_extrinsic(call=call, keypair=keypair)
                                sub.submit_extrinsic(extrinsic)
                                log.info("Fee: recorded on-chain via Fees pallet")
                        except Exception as e:
                            log.debug(f"Fee: on-chain record skipped: {e}")
                else:
                    log.warning(
                        f"Fee: {api_key[:8]}... insufficient on-chain balance "
                        f"({balance:.6f} < {total_fee:.6f} NRN)"
                    )
        except Exception as e:
            log.debug(f"Fee: on-chain transfer skipped: {e}")

        record = FeeRecord(
            timestamp=time.time(),
            api_key=api_key or "anonymous",
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            fee_nrn=total_fee,
            burn_nrn=burn,
            operator_nrn=operator_pay,
            from_address=from_address,
            to_address=to_address,
            tx_hash=tx_hash,
        )
        self._history.append(record)

        log.info(
            f"Fee: {total_fee:.6f} NRN "
            f"({prompt_tokens}p+{completion_tokens}c tokens, model={model}) "
            f"→ operator={operator_pay:.6f}, burn={burn:.6f}"
            f"{' [on-chain]' if tx_hash else ' [recorded]'}"
        )

        self._save()
        return record

    def _get_operator_address(self) -> str:
        """Get the GPU operator's on-chain address (this node's validator)."""
        # Validator 1 (PC — the GPU node)
        return "5FF9StVD76DiNQnHriYL427taHX1mxrdhRtRk158Mkjhtx1i"

    def get_stats(self) -> dict:
        """Network-wide fee stats (public — like a block explorer)."""
        total_fees = sum(r.fee_nrn for r in self._history)
        total_burned = sum(r.burn_nrn for r in self._history)
        total_operator = sum(r.operator_nrn for r in self._history)
        on_chain = sum(1 for r in self._history if r.tx_hash)
        return {
            "total_inferences": len(self._history),
            "total_fees_nrn": round(total_fees, 6),
            "total_burned_nrn": round(total_burned, 6),
            "total_operator_nrn": round(total_operator, 6),
            "on_chain_payments": on_chain,
            "burn_rate": BURN_RATE,
            "base_price_per_token": BASE_NRN_PER_TOKEN,
        }

    def recent_fees(self, limit: int = 20) -> list[dict]:
        """Recent fee records (public)."""
        return [
            {
                "time": r.timestamp,
                "model": r.model,
                "tokens": r.prompt_tokens + r.completion_tokens,
                "fee_nrn": round(r.fee_nrn, 6),
                "burn_nrn": round(r.burn_nrn, 6),
                "on_chain": bool(r.tx_hash),
            }
            for r in self._history[-limit:]
        ]

    # --- Persistence ---

    def _save(self):
        try:
            history = [
                {
                    "t": r.timestamp, "k": r.api_key, "m": r.model,
                    "pt": r.prompt_tokens, "ct": r.completion_tokens,
                    "f": r.fee_nrn, "b": r.burn_nrn, "o": r.operator_nrn,
                    "fa": r.from_address, "ta": r.to_address, "tx": r.tx_hash,
                }
                for r in self._history[-1000:]
            ]
            (self._data_dir / "history.json").write_text(json.dumps(history))
        except Exception as e:
            log.debug(f"Fee save failed: {e}")

    def _load(self):
        try:
            hist_file = self._data_dir / "history.json"
            if hist_file.exists():
                data = json.loads(hist_file.read_text())
                for r in data:
                    self._history.append(FeeRecord(
                        timestamp=r["t"], api_key=r["k"], model=r["m"],
                        prompt_tokens=r["pt"], completion_tokens=r["ct"],
                        fee_nrn=r["f"], burn_nrn=r["b"], operator_nrn=r["o"],
                        from_address=r.get("fa", ""), to_address=r.get("ta", ""),
                        tx_hash=r.get("tx", ""),
                    ))
                log.info(f"Fee: loaded {len(self._history)} records")
        except Exception as e:
            log.debug(f"Fee load failed: {e}")


# Singleton
_fee_engine: FeeEngine | None = None


def get_fee_engine() -> FeeEngine:
    global _fee_engine
    if _fee_engine is None:
        _fee_engine = FeeEngine()
    return _fee_engine
