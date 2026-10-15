"""S6 reconciliation against a real throwaway solana-test-validator."""
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from chain.indexer import DepositIndexer, IndexerConfig  # noqa: E402
from chain.payout import PayoutConfig, PayoutEngine, SoldersTreasuryBackend  # noqa: E402
from chain.reconcile import ReconcileConfig, Reconciler, verify_report  # noqa: E402
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


def _wait_finalized(rpc, signature, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = rpc.get_signature_status(signature)
        if (
            isinstance(status, dict)
            and status.get("confirmationStatus") == "finalized"
        ):
            assert status.get("err") is None
            return
        time.sleep(0.2)
    pytest.fail(f"transaction {signature} did not finalize")


def _write_signing_key(path):
    private = ed25519.Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)
    path.chmod(0o600)
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _no_buzz(_helper, _message):
    return {"attempted": False, "delivered": False, "detail": "test injection"}


def test_real_validator_signed_report_kill_and_sent_adjustment(tmp_path):
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
                common + ["create-account", mint, str(keypair), "--owner", treasury_address],
                env,
            )
            return _run([solana, "address", "-k", str(keypair)], env).stdout.strip()

        vault_account = token_account("vault-token")
        source_account = token_account("source-token")
        _run(
            common + ["mint", mint, "1", source_account, "--mint-authority", str(treasury)],
            env,
        )
        transfer = _run(
            common
            + [
                "transfer",
                mint,
                "1",
                vault_account,
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
        _wait_finalized(rpc, deposit_signature)

        signing_key = home / ".nakshatra" / "keys" / "worker.ed25519"
        signing_public_key = _write_signing_key(signing_key)
        ledger_path = tmp_path / "ledger.sqlite"
        with LedgerStore(ledger_path) as store:
            store._db.execute(
                "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
                "VALUES ('validator-user', ?, 1)",
                (vault_account,),
            )
            indexer = DepositIndexer(
                store,
                rpc,
                IndexerConfig(cluster="localnet", mint=mint, rpc_url=rpc_url),
            )
            assert indexer.poll_once() == 1
            amount = 1_000_000 * RATE
            assert store.balance("validator-user") == amount

            def reconcile_config(name, kill_name="payout.off"):
                return ReconcileConfig(
                    cluster="localnet",
                    mint=mint,
                    rpc_url=rpc_url,
                    vault_account=vault_account,
                    report_dir=tmp_path / name,
                    kill_file=tmp_path / kill_name,
                    signing_key=signing_key,
                    buzz_helper=None,
                )

            envelope, report_path = Reconciler(
                ledger_path,
                rpc,
                reconcile_config("reports-ok"),
                notify=_no_buzz,
            ).run()
            assert envelope["report"]["ok"] is True
            assert verify_report(envelope, signing_public_key) is True
            assert verify_report(envelope, None) is False
            assert verify_report(json.loads(report_path.read_text()), signing_public_key) is True
            assert envelope["report"]["finalized_withdrawal_verification"] == "all"
            assert not (tmp_path / "payout.off").exists()

            # SQLite backup gives the test a transactionally consistent temp copy;
            # inject only the bogus append-only journal row into that copy.
            bogus_path = tmp_path / "bogus-ledger.sqlite"
            destination = sqlite3.connect(str(bogus_path))
            try:
                store._db.backup(destination)
            finally:
                destination.close()
            with LedgerStore(bogus_path) as bogus:
                bogus._db.execute(
                    "INSERT INTO journal(ts, kind, account, amount, detail) "
                    "VALUES (1, 'deposit', 'validator-user', ?, '{}')",
                    (RATE,),
                )
                mismatch_envelope, mismatch_path = Reconciler(
                    bogus_path,
                    rpc,
                    reconcile_config("reports-mismatch", "mismatch-payout.off"),
                    notify=_no_buzz,
                ).run()
            mismatch = mismatch_envelope["report"]
            assert mismatch["ok"] is False
            assert next(
                check
                for check in mismatch["checks"]
                if check["id"] == "deposit_provenance"
            )["ok"] is False
            assert (tmp_path / "mismatch-payout.off").is_file()
            assert mismatch["alerts"][0]["event"] == "nak_reconcile_mismatch"
            assert verify_report(
                json.loads(mismatch_path.read_text()), signing_public_key
            ) is True

            payout_config = PayoutConfig(
                cluster="localnet",
                mint=mint,
                rpc_url=rpc_url,
                vault_account=vault_account,
                enabled=True,
                kill_file=tmp_path / "sent-payout.off",
            )
            backend = SoldersTreasuryBackend(
                rpc,
                mint,
                vault_account,
                secret_loader=lambda name: (
                    treasury.read_text() if name == "nak-treasury-secret" else ""
                ),
            )
            store.withdraw_hold(
                "validator-user", amount, recipient_address, "sent-withdrawal"
            )
            engine = PayoutEngine(
                store,
                rpc,
                payout_config,
                backend=backend,
                presence=lambda *_args: pytest.fail("auto-cap requested presence"),
            )
            # One state transition approves the hold and one durably sends it.
            assert engine.poll_once() == 2
            sent = store._db.execute(
                "SELECT tx_sig, state FROM withdrawals WHERE id='sent-withdrawal'"
            ).fetchone()
            assert sent["state"] == "sent"
            _wait_finalized(rpc, sent["tx_sig"])

            sent_envelope, _ = Reconciler(
                ledger_path,
                rpc,
                reconcile_config("reports-sent", "sent-payout.off"),
                notify=_no_buzz,
            ).run()
            sent_report = sent_envelope["report"]
            assert sent_report["ok"] is True
            assert sent_report["totals"]["chain_micro_usdc"] == 0
            assert sent_report["totals"]["sent_signed_hold_adjustment_credits"] == -amount
            assert sent_report["totals"]["backing_right_credits"] == amount
            assert sent_report["sent_withdrawals"][0]["chain_state"] == "finalized_pending_ledger"
            assert not (tmp_path / "sent-payout.off").exists()

            store.withdraw_finalize("sent-withdrawal")
            final_envelope, _ = Reconciler(
                ledger_path,
                rpc,
                reconcile_config("reports-final", "final-payout.off"),
                notify=_no_buzz,
            ).run()
            final_report = final_envelope["report"]
            assert final_report["ok"] is True
            assert next(
                check for check in final_report["checks"]
                if check["id"] == "finalized_withdrawals"
            ) == {
                "id": "finalized_withdrawals",
                "ok": True,
                "verification": "all",
                "checked": 1,
                "failed": 0,
            }
            assert final_report["finalized_withdrawals"][0]["ok"] is True
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
