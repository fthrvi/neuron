"""Offline integration test against a throwaway solana-test-validator."""
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
from chain.solana_rpc import RPCError, SolanaRPC  # noqa: E402
from core.ledger_store import RATE, LedgerStore  # noqa: E402


def _tool(name):
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is not installed")
    return path


def _run(command, env, *, timeout=30, skip_missing_token_program=False):
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
                "local validator has no SPL Token program (set NAK_SPL_PROGRAM_DIR to a dir "
                f"holding spl_token.so/spl_ata.so): {exc.stderr.strip()[:600]}"
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
    # The validator needs RPC, websocket, faucet, gossip, and a dynamic range.
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
            # Healthy is not enough: programs preloaded with --bpf-program only become
            # invocable after the first slots ("Program is not deployed" at slot 0).
            if rpc.call("getHealth", []) == "ok" and rpc.call("getSlot", []) >= 2:
                return
        except RPCError:
            pass
        time.sleep(0.2)
    pytest.skip("local validator did not become healthy in the sandbox")


def test_indexes_real_finalized_spl_transfer(tmp_path):
    validator = _tool("solana-test-validator")
    keygen = _tool("solana-keygen")
    solana = _tool("solana")
    spl_token = _tool("spl-token")

    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    env.pop("SOLANA_URL", None)
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)

    payer = tmp_path / "payer.json"
    _run(
        [keygen, "new", "--no-bip39-passphrase", "--silent", "--force", "-o", str(payer)],
        env,
    )
    payer_address = _run([solana, "address", "-k", str(payer)], env).stdout.strip()

    port = _port_block()
    rpc_url = f"http://127.0.0.1:{port}"
    # Solana 4.x's local validator ships without the SPL programs. NAK_SPL_PROGRAM_DIR points at
    # spl_token.so / spl_ata.so dumped once from devnet (`solana program dump -u devnet <id> <file>`),
    # loaded at their real program ids so spl-token works offline.
    preload = []
    program_dir = os.environ.get("NAK_SPL_PROGRAM_DIR", "")
    for program_id, filename in (
        ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "spl_token.so"),
        ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "spl_ata.so"),
    ):
        path = os.path.join(program_dir, filename) if program_dir else ""
        if path and os.path.isfile(path):
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
            payer_address,
        ],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        rpc = SolanaRPC(rpc_url, timeout=1)
        _wait_for_validator(rpc, process)

        common = [spl_token, "--url", rpc_url, "--fee-payer", str(payer), "--output", "json"]
        mint_result = _run(
            common
            + ["create-token", "--decimals", "6", "--mint-authority", payer_address],
            env,
            skip_missing_token_program=True,
        )
        mint = _json_value(mint_result.stdout, {"address", "mint"})

        # spl-token's JSON for create-account carries only the signature, so both token
        # accounts are made from explicit keypairs whose addresses we already know.
        source_keypair = tmp_path / "source-token.json"
        _run(
            [keygen, "new", "--no-bip39-passphrase", "--silent", "--force", "-o", str(source_keypair)],
            env,
        )
        _run(
            common + ["create-account", mint, str(source_keypair), "--owner", payer_address], env
        )
        source = _run([solana, "address", "-k", str(source_keypair)], env).stdout.strip()

        deposit_keypair = tmp_path / "deposit-token.json"
        _run(
            [
                keygen,
                "new",
                "--no-bip39-passphrase",
                "--silent",
                "--force",
                "-o",
                str(deposit_keypair),
            ],
            env,
        )
        _run(
            common
            + ["create-account", mint, str(deposit_keypair), "--owner", payer_address],
            env,
        )
        deposit = _run([solana, "address", "-k", str(deposit_keypair)], env).stdout.strip()

        _run(
            common
            + ["mint", mint, "1", source, "--mint-authority", str(payer)],
            env,
        )
        transfer_result = _run(
            common
            + [
                "transfer",
                mint,
                "1",
                deposit,
                "--from",
                source,
                "--owner",
                str(payer),
                "--allow-non-system-account-recipient",
            ],
            env,
        )
        signature = _json_value(transfer_result.stdout, {"signature", "transactionSignature"})

        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            records = rpc.get_signatures_for_address(deposit)
            if any(record["signature"] == signature for record in records):
                break
            time.sleep(0.2)
        else:
            pytest.fail("SPL transfer did not reach finalized commitment")

        with LedgerStore(tmp_path / "ledger.sqlite") as store:
            store._db.execute(
                "INSERT INTO deposit_accounts(operator, token_account, created_ts) "
                "VALUES ('validator-user', ?, 1)",
                (deposit,),
            )
            config = IndexerConfig(cluster="localnet", mint=mint, rpc_url=rpc_url)
            indexer = DepositIndexer(store, rpc, config)
            assert indexer.poll_once() == 1
            assert store.balance("validator-user") == 1_000_000 * RATE
            assert store._balance_in(store._db, "treasury") == -(1_000_000 * RATE)
            assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 1
            assert indexer.poll_once() == 0
            assert store._db.execute("SELECT COUNT(*) FROM chain_refs").fetchone()[0] == 1
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
