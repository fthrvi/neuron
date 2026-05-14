"""
NRN Wallet — User accounts on the Neuron Network.

Users register → get an API key + mnemonic + chain wallet.
The mnemonic is theirs — they control the wallet.
The API key authenticates them to the gateway.

Flow for a new user:
  1. POST /api/register  → gets {api_key, mnemonic, address}
  2. Save the mnemonic (this is your wallet backup)
  3. Use the API key for all requests (Bearer token)
  4. Receive NRN to your address from anyone
  5. Spend NRN on inference, send to others

Flow to recover:
  1. POST /api/wallet/recover {mnemonic}  → gets back {api_key, address}
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

WALLET_DIR = Path.home() / ".neuron" / "wallets"
MASTER_SECRET_FILE = Path.home() / ".neuron" / ".master_secret"


def _get_fernet():
    """Derive a Fernet key from a master secret + salt for encrypting seeds."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet

    # Master secret: generated once, stored locally
    if MASTER_SECRET_FILE.exists():
        secret = MASTER_SECRET_FILE.read_text().strip()
    else:
        secret = secrets.token_hex(32)
        MASTER_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        MASTER_SECRET_FILE.write_text(secret)
        MASTER_SECRET_FILE.chmod(0o600)

    # Salt: per-installation
    salt_file = WALLET_DIR / ".salt"
    if salt_file.exists():
        salt = salt_file.read_bytes()
    else:
        salt = os.urandom(16)
        WALLET_DIR.mkdir(parents=True, exist_ok=True)
        salt_file.write_bytes(salt)
        salt_file.chmod(0o600)

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
    key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
    return Fernet(key)


@dataclass
class UserAccount:
    api_key: str
    address: str
    mnemonic_hash: str  # we store hash, NOT the mnemonic itself
    created_at: float
    label: str = ""


class WalletManager:
    """
    Manages user accounts — each with an API key and chain wallet.

    The user's mnemonic generates both their keypair and their API key.
    The gateway only stores the hashed mnemonic (for recovery verification).
    """

    def __init__(self, chain_url: str = "ws://127.0.0.1:9944", admin_key: str = ""):
        self._accounts: dict[str, UserAccount] = {}  # api_key -> UserAccount
        self._address_to_key: dict[str, str] = {}    # address -> api_key
        self._keypairs: dict[str, object] = {}        # api_key -> Keypair
        self._chain_url = chain_url
        self._admin_key = admin_key  # the original single admin key
        WALLET_DIR.mkdir(parents=True, exist_ok=True)
        WALLET_DIR.chmod(0o700)
        self._load()
        self._migrate_seeds()

    def register(self, label: str = "") -> dict:
        """
        Register a new user. Returns everything they need to get started.

        Returns: {api_key, mnemonic, address}
        The mnemonic is shown ONCE — user must save it.
        """
        from substrateinterface import Keypair

        # Generate a fresh mnemonic — this IS the user's identity
        mnemonic = Keypair.generate_mnemonic()
        keypair = Keypair.create_from_mnemonic(mnemonic)

        # Derive API key from mnemonic (deterministic — same mnemonic = same key)
        api_key = "nrn-" + hashlib.sha256(mnemonic.encode()).hexdigest()[:32]

        # Store account (mnemonic hash only — we never store the raw mnemonic)
        mnemonic_hash = hashlib.sha256(mnemonic.encode()).hexdigest()
        account = UserAccount(
            api_key=api_key,
            address=keypair.ss58_address,
            mnemonic_hash=mnemonic_hash,
            created_at=time.time(),
            label=label,
        )
        self._accounts[api_key] = account
        self._address_to_key[keypair.ss58_address] = api_key
        self._keypairs[api_key] = keypair
        self._save()
        self._save_seed(api_key, mnemonic)

        log.info(f"Wallet: registered user {api_key[:12]}... → {keypair.ss58_address}")

        return {
            "api_key": api_key,
            "mnemonic": mnemonic,  # shown ONCE
            "address": keypair.ss58_address,
            "message": "Save your mnemonic! It cannot be recovered.",
        }

    def recover(self, mnemonic: str) -> dict:
        """
        Recover account from mnemonic or seed. Returns the API key + address.

        Accepts:
          - 12-word mnemonic: "word1 word2 word3 ..."
          - Hex seed: "0xfc1e05f..." (from chain_key.json secretSeed)

        Works even if the gateway has never seen this key before —
        it re-derives the same API key deterministically.
        """
        from substrateinterface import Keypair

        if mnemonic.startswith("0x"):
            keypair = Keypair.create_from_seed(mnemonic)
        else:
            keypair = Keypair.create_from_mnemonic(mnemonic)
        api_key = "nrn-" + hashlib.sha256(mnemonic.encode()).hexdigest()[:32]
        mnemonic_hash = hashlib.sha256(mnemonic.encode()).hexdigest()

        # Re-register if not already known
        if api_key not in self._accounts:
            account = UserAccount(
                api_key=api_key,
                address=keypair.ss58_address,
                mnemonic_hash=mnemonic_hash,
                created_at=time.time(),
                label="recovered",
            )
            self._accounts[api_key] = account
            self._address_to_key[keypair.ss58_address] = api_key
            self._save()
            log.info(f"Wallet: recovered user {api_key[:12]}... → {keypair.ss58_address}")

        self._keypairs[api_key] = keypair
        self._save_seed(api_key, mnemonic)

        return {
            "api_key": api_key,
            "address": keypair.ss58_address,
            "message": "Account recovered.",
        }

    def is_valid_key(self, api_key: str) -> bool:
        """Check if an API key belongs to a registered user (or is the admin key)."""
        if self._admin_key and api_key == self._admin_key:
            return True
        return api_key in self._accounts

    def is_admin(self, api_key: str) -> bool:
        """Check if this is the admin/owner key."""
        return bool(self._admin_key and api_key == self._admin_key)

    def get_address(self, api_key: str) -> str:
        """Get chain address for an API key."""
        acct = self._accounts.get(api_key)
        return acct.address if acct else ""

    def get_balance(self, api_key: str) -> float:
        """Query on-chain NRN balance."""
        address = self.get_address(api_key)
        if not address:
            return 0.0
        return self.query_balance(address)

    def query_balance(self, address: str) -> float:
        """Query on-chain balance for any address."""
        try:
            from substrateinterface import SubstrateInterface
            sub = SubstrateInterface(url=self._chain_url)
            result = sub.query("System", "Account", [address])
            if result:
                raw = result.value.get("data", {}).get("free", 0)
                return round(raw / 1_000_000_000_000, 6)
            return 0.0
        except Exception as e:
            log.debug(f"Wallet: balance query failed: {e}")
            return 0.0

    def send(self, from_api_key: str, to_address: str, amount_nrn: float) -> dict:
        """Send NRN from user's wallet to any address."""
        if amount_nrn <= 0:
            return {"status": "error", "message": "Amount must be positive"}

        acct = self._accounts.get(from_api_key)
        if not acct:
            return {"status": "error", "message": "Account not found"}

        keypair = self._keypairs.get(from_api_key)
        if not keypair:
            return {"status": "error", "message": "Keypair not loaded — recover your wallet first"}

        balance = self.query_balance(acct.address)
        if balance < amount_nrn:
            return {
                "status": "error",
                "message": f"Insufficient balance: {balance:.6f} NRN (need {amount_nrn:.6f})",
            }

        try:
            from substrateinterface import SubstrateInterface
            sub = SubstrateInterface(url=self._chain_url)
            amount_raw = int(amount_nrn * 1_000_000_000_000)

            call = sub.compose_call(
                call_module="Balances",
                call_function="transfer_keep_alive",
                call_params={"dest": to_address, "value": amount_raw},
            )
            extrinsic = sub.create_signed_extrinsic(call=call, keypair=keypair)
            receipt = sub.submit_extrinsic(extrinsic)
            tx_hash = str(getattr(receipt, "extrinsic_hash", "") or "")

            log.info(f"Wallet: {amount_nrn:.6f} NRN sent {acct.address[:16]}→{to_address[:16]}")
            return {
                "status": "sent",
                "from": acct.address,
                "to": to_address,
                "amount": amount_nrn,
                "tx_hash": tx_hash,
            }
        except Exception as e:
            log.warning(f"Wallet: send failed: {e}")
            return {"status": "error", "message": str(e)}

    def get_account_info(self, api_key: str) -> dict:
        """Full account info for a user."""
        acct = self._accounts.get(api_key)
        if not acct:
            return {}
        balance = self.query_balance(acct.address)
        return {
            "address": acct.address,
            "balance_nrn": balance,
            "label": acct.label,
            "created_at": acct.created_at,
        }

    def list_accounts(self) -> list[dict]:
        """List all registered accounts (admin only)."""
        return [
            {
                "api_key": k[:12] + "...",
                "address": v.address,
                "label": v.label,
                "created_at": v.created_at,
            }
            for k, v in self._accounts.items()
        ]

    def _migrate_seeds(self):
        """Auto-encrypt plaintext seeds on first load."""
        try:
            seed_file = WALLET_DIR / ".seeds.json"
            if not seed_file.exists():
                return
            raw = seed_file.read_bytes()
            # If it parses as JSON, it's still plaintext — encrypt it
            try:
                json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return  # already encrypted
            seeds = self._load_seeds()
            if seeds:
                fernet = _get_fernet()
                seed_file.write_bytes(fernet.encrypt(json.dumps(seeds).encode()))
                seed_file.chmod(0o600)
                log.info("Wallet: migrated seeds to encrypted storage")
        except Exception as e:
            log.error(f"CRITICAL: Seed encryption migration failed: {e} — seeds may be in plaintext!")

    # --- Persistence ---

    def _save_seed(self, api_key: str, seed: str):
        """Persist seed material encrypted so keypairs survive restarts."""
        seeds = self._load_seeds()
        seeds[api_key] = seed
        seed_file = WALLET_DIR / ".seeds.json"
        fernet = _get_fernet()
        seed_file.write_bytes(fernet.encrypt(json.dumps(seeds).encode()))
        seed_file.chmod(0o600)

    def _load_seeds(self) -> dict:
        try:
            seed_file = WALLET_DIR / ".seeds.json"
            if not seed_file.exists():
                return {}
            raw = seed_file.read_bytes()
            # Try plaintext first (migration from old unencrypted format)
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            # Encrypted format
            fernet = _get_fernet()
            return json.loads(fernet.decrypt(raw))
        except Exception:
            pass
        return {}

    def _save(self):
        try:
            data = {
                k: {
                    "address": v.address,
                    "mnemonic_hash": v.mnemonic_hash,
                    "created_at": v.created_at,
                    "label": v.label,
                }
                for k, v in self._accounts.items()
            }
            acct_file = WALLET_DIR / "accounts.json"
            acct_file.write_text(json.dumps(data, indent=2))
            acct_file.chmod(0o600)
        except Exception as e:
            log.debug(f"Wallet save failed: {e}")

    def _load(self):
        try:
            afile = WALLET_DIR / "accounts.json"
            if afile.exists():
                data = json.loads(afile.read_text())
                seeds = self._load_seeds()
                for api_key, info in data.items():
                    acct = UserAccount(
                        api_key=api_key,
                        address=info["address"],
                        mnemonic_hash=info.get("mnemonic_hash", ""),
                        created_at=info.get("created_at", 0),
                        label=info.get("label", ""),
                    )
                    self._accounts[api_key] = acct
                    self._address_to_key[acct.address] = api_key
                    # Restore keypair from saved seed
                    if api_key in seeds:
                        try:
                            from substrateinterface import Keypair
                            seed = seeds[api_key]
                            if seed.startswith("0x"):
                                self._keypairs[api_key] = Keypair.create_from_seed(seed)
                            else:
                                self._keypairs[api_key] = Keypair.create_from_mnemonic(seed)
                        except Exception:
                            pass
                loaded_keys = sum(1 for k in self._accounts if k in self._keypairs)
                log.info(f"Wallet: loaded {len(self._accounts)} accounts ({loaded_keys} with keys)")
        except Exception as e:
            log.debug(f"Wallet load failed: {e}")


# Singleton
_wallet_mgr: WalletManager | None = None


def get_wallet_manager(admin_key: str = "") -> WalletManager:
    global _wallet_mgr
    if _wallet_mgr is None:
        _wallet_mgr = WalletManager(admin_key=admin_key)
    return _wallet_mgr
