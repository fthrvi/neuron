"""Offline end-to-end payout against a throwaway solana-test-validator."""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chain.indexer import DepositIndexer, IndexerConfig  # noqa: E402
from chain.payout import PayoutConfig, PayoutEngine, SoldersTreasuryBackend  # noqa: E402
from chain.solana_rpc import RPCError, SolanaRPC  # noqa: E402
from core.ledger_store import RATE, LedgerStore  # noqa: E402


def _tool(name):
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is not installed")
    return path


def _run(command, env, *, timeout=45, skip_missing_token_program=False):
    try:
        return subprocess.run(
            command,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as exc:
        if skip_missing_token_program and (
            "Program is not deployed" in exc.stderr
            or "Unsupported program id" in exc.stderr
        ):
            pytest.skip(
                "local validator has no SPL programs; set NAK_SPL_PROGRAM_DIR: "
                + exc.stderr.strip()[:500]
            )
        pytest.fail(
            f"command failed ({exc.returncode}): {' '.join(command)}\n"
            f"stdout: {exc.stdout}\nstderr: {exc.stderr}"
        )


def _json_value(output, wanted):
    payload = json.loads(output)

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in wanted and isinstance(child, str):
                    return child
            for child in value.values():
                found = walk(child)
                if found:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = walk(child)
                if found:
                    return found
        return None

    result = walk(payload)
    assert result, f"none of {wanted!r} found in {payload!r}"
    return result


def _port_block():
    for _ in range(100):
        try:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                base = probe.getsockname()[1]
        except OSError as exc:
            pytest.skip(f"sandbox does not permit local validator sockets: {exc}")
        if 12000 <= base <= 64000 - 80:
            return base
    pytest.skip("could not reserve a local validator port range")


def _wait_for_validator(rpc, process, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate(timeout=1)
            pytest.skip(f"local validator could not start: {stderr[-1000:]}")
        try:
            if rpc.call("getHealth", []) == "ok" and rpc.call("getSlot", []) >= 2:
                return
        except RPCError:
            pass
        time.sleep(0.2)
    pytest.skip("local validator did not become healthy in the sandbox")


def test_real_deposit_hold_send_finalize_is_zero_sum(tmp_path):
    validator = _tool("solana-test-validator")
    keygen = _tool("solana-keygen")
    solana = _tool("solana")
    spl_token = _tool("spl-token")

    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    for name in ("SOLANA_URL", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(name, None)

    treasury = tmp_path / "treasury.json"
    recipient = tmp_path / "recipient.json"
    for keypair in (treasury, recipient):
        _run(
            [keygen, "new", "--no-bip39-passphrase", "--silent", "--force", "-o", str(keypair)],
            env,
        )
        assert (keypair.stat().st_mode & 0o777) == 0o600
    treasury_address = _run([solana, "address", "-k", str(treasury)], env).stdout.strip()
    recipient_address = _run([solana, "address", "-k", str(recipient)], env).stdout.strip()

    port = _port_block()
    rpc_url = f"http://127.0.0.1:{port}"
    preload = []
    program_dir = os.environ.get(
        "NAK_SPL_PROGRAM_DIR", "/home/prithvi/.cache/nak-solana"
    )
    for program_id, filename in (
        ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "spl_token.so"),
        ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "spl_ata.so"),
    ):
        path = os.path.join(program_dir, filename)
        if os.path.isfile(path):
            preload += ["--bpf-program", program_id, path]
    process = subprocess.Popen(
        [
            validator,
            *preload,
            "--ledger",
            str(tmp_path / "validator-ledger"),
            "--reset",
            "--quiet",
            "--rpc-port",
            str(port),
            "--faucet-port",
            str(port + 2),
            "--gossip-port",
            str(port + 3),
            "--dynamic-port-range",
            f"{port + 10}-{port + 70}",
            "--mint",
            treasury_address,
        ],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        rpc = SolanaRPC(rpc_url, timeout=2)
        _wait_for_validator(rpc, process)
        common = [
            spl_token,
            "--url",
            rpc_url,
            "--fee-payer",
            str(treasury),
            "--output",
            "json",
        ]
        mint_result = _run(
            common + ["create-token", "--decimals", "6", "--mint-authority", treasury_address],
            env,
            skip_missing_token_program=True,
        )
        mint = _json_value(mint_result.stdout, {"address", "mint"})

        def token_account(name):
            keypair = tmp_path / f"{name}.json"
            _run(
                [keygen, "new", "--no-bip39-passphrase", "--silent", "--force", "-o", str(keypair)],
                env,
            )
            _run(
                common
                + ["create-account", mint, str(keypair), "--owner", treasury_address],
                env,
            )
            return _run([solana, "address", "-k", str(keypair)], env).stdout.strip()

        vault_account = token_account("vault-token")
        source_account = token_account("deposit-source")
        _run(
            common
            + ["mint", mint, "1", source_account, "--mint-authority", str(treasury)],
            env,
        )
        # The payout RPC intentionally preflights at finalized commitment.
        # Wait for CLI-created fixtures to reach that bank before exercising it.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if rpc.account_exists(mint) and rpc.account_exists(vault_account):
                break
            time.sleep(0.2)
        else:
            pytest.fail("mint and vault account did not finalize")

        config = PayoutConfig(
            cluster="localnet",
            mint=mint,
            rpc_url=rpc_url,
            vault_account=vault_account,
            enabled=True,
            kill_file=tmp_path / "payout.off",
            roster_path=tmp_path / "roster.tsv",
        )
        config.roster_path.write_text("", encoding="utf-8")
        secret = treasury.read_text()
        backend = SoldersTreasuryBackend(
            rpc,
            mint,
            vault_account,
            secret_loader=lambda name: secret if name == "nak-treasury-secret" else "",
        )

        with LedgerStore(tmp_path / "ledger.sqlite") as store:
            engine = PayoutEngine(
                store,
                rpc,
                config,
                backend=backend,
                presence=lambda *_args: pytest.fail("auto-cap payout requested presence"),
            )
            assert store.queue_deposit_account("validator-user") is True
            assert engine.poll_once() == 1
            deposit_account = store._db.execute(
                "SELECT token_account FROM deposit_accounts "
                "WHERE operator='validator-user'"
            ).fetchone()[0]
            created_account = rpc.get_token_account(deposit_account)
            assert created_account["mint"] == mint
            assert created_account["owner"] == treasury_address

            transfer = _run(
                common
                + [
                    "transfer",
                    mint,
                    "1",
                    deposit_account,
                    "--from",
                    source_account,
                    "--owner",
                    str(treasury),
                    "--allow-non-system-account-recipient",
                ],
                env,
            )
            deposit_signature = _json_value(
                transfer.stdout, {"signature", "transactionSignature"}
            )
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if any(
                    item["signature"] == deposit_signature
                    for item in rpc.get_signatures_for_address(deposit_account)
                ):
                    break
                time.sleep(0.2)
            else:
                pytest.fail("deposit transfer did not finalize")

            indexer = DepositIndexer(
                store,
                rpc,
                IndexerConfig(cluster="localnet", mint=mint, rpc_url=rpc_url),
            )
            assert indexer.poll_once() == 1
            amount = 1_000_000 * RATE
            assert store.balance("validator-user") == amount

            # Consolidate the fully indexed deposit before paying from the vault.
            assert engine.poll_once() == 1
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                engine.poll_once()
                sweep_state = store._db.execute(
                    "SELECT state FROM chain_sweeps"
                ).fetchone()[0]
                if sweep_state == "finalized":
                    break
                time.sleep(0.2)
            else:
                pytest.fail(f"sweep did not finalize; state={sweep_state}")
            assert rpc.get_token_account(deposit_account)["amount"] == 0
            assert rpc.get_token_account(vault_account)["amount"] == 1_000_000

            store.withdraw_hold(
                "validator-user", amount, recipient_address, "validator-withdrawal"
            )
            engine.poll_once()
            assert store._db.execute(
                "SELECT state FROM withdrawals WHERE id='validator-withdrawal'"
            ).fetchone()[0] == "sent"

            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                engine.poll_once()
                state = store._db.execute(
                    "SELECT state FROM withdrawals WHERE id='validator-withdrawal'"
                ).fetchone()[0]
                if state == "finalized":
                    break
                time.sleep(0.2)
            else:
                pytest.fail(f"payout did not finalize; state={state}")

            recipient_ata = backend.recipient_ata(recipient_address)
            assert rpc.get_token_account(recipient_ata)["amount"] == 1_000_000
            assert rpc.get_token_account(vault_account)["amount"] == 0
            assert store.balance("validator-user") == 0
            assert store._balance_in(store._db, "treasury") == 0
            assert store._db.execute(
                "SELECT COALESCE(SUM(balance), 0) FROM accounts"
            ).fetchone()[0] == 0
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
