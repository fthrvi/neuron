"""Real-validator end-to-end test for the Python nakshatra_pay client."""
from __future__ import annotations

import base64
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

solders = pytest.importorskip("solders")
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import (
    CreateAccountParams,
    TransferParams,
    create_account,
    transfer,
)
from solders.transaction import Transaction

from python.chain import program_client as pay
from python.chain.solana_rpc import RPCError, SolanaRPC


RENT_SYSVAR_ID = Pubkey.from_string("SysvarRent111111111111111111111111111111111")
MINT_SIZE = 82
TOKEN_ACCOUNT_SIZE = 165


def _port_block() -> int:
    for _ in range(100):
        try:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                base = probe.getsockname()[1]
        except OSError as exc:
            pytest.skip(f"sandbox does not permit local validator sockets: {exc}")
        if 12_000 <= base <= 64_000 - 90 and not 8_800 <= base <= 8_999:
            return base
    pytest.skip("could not reserve a validator port range outside 8800-8999")


def _wait_for_validator(
    rpc: SolanaRPC, process: subprocess.Popen[str], log_path: Path
) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = log_path.read_text(encoding="utf-8", errors="replace")
            pytest.skip(f"local validator could not start: {output[-2000:]}")
        try:
            if rpc.call("getHealth", []) == "ok" and rpc.call("getSlot", []) >= 2:
                return
        except RPCError:
            pass
        time.sleep(0.2)
    pytest.skip("local validator did not become healthy")


def _wait_finalized(rpc: SolanaRPC, signature: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = rpc.get_signature_status(signature)
        if last is not None:
            if last.get("err") is not None:
                pytest.fail(f"transaction {signature} failed: {last['err']!r}")
            if last.get("confirmationStatus") == "finalized":
                return
        time.sleep(0.15)
    pytest.fail(f"transaction {signature} did not finalize; last status={last!r}")


def _wait_confirmed(rpc: SolanaRPC, signature: str, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = rpc.get_signature_status(signature)
        if last is not None:
            if last.get("err") is not None:
                pytest.fail(f"transaction {signature} failed: {last['err']!r}")
            if last.get("confirmationStatus") in {"confirmed", "finalized"}:
                return
        time.sleep(0.1)
    pytest.fail(f"transaction {signature} did not confirm; last status={last!r}")


def _send(
    rpc: SolanaRPC,
    instructions: list[Instruction],
    payer: Keypair,
    signers: list[Keypair] | None = None,
) -> str:
    latest = rpc.get_latest_blockhash()
    blockhash = Hash.from_string(latest["blockhash"])
    message = Message.new_with_blockhash(instructions, payer.pubkey(), blockhash)
    ordered = [payer]
    for signer in signers or []:
        if signer.pubkey() != payer.pubkey() and signer.pubkey() not in {
            item.pubkey() for item in ordered
        }:
            ordered.append(signer)
    transaction = Transaction(ordered, message, blockhash)
    assert transaction.verify_with_results() == [True] * len(ordered)
    signature = str(transaction.signatures[0])
    returned = rpc.call(
        "sendTransaction",
        [
            base64.b64encode(bytes(transaction)).decode("ascii"),
            {
                "encoding": "base64",
                "preflightCommitment": "confirmed",
                "skipPreflight": False,
                "maxRetries": 0,
            },
        ],
    )
    assert returned == signature
    _wait_confirmed(rpc, signature)
    return signature


def _create_mint(rpc: SolanaRPC, payer: Keypair, mint: Keypair) -> None:
    rent = rpc.get_minimum_balance_for_rent_exemption(MINT_SIZE)
    create = create_account(
        CreateAccountParams(
            from_pubkey=payer.pubkey(),
            to_pubkey=mint.pubkey(),
            lamports=rent,
            space=MINT_SIZE,
            owner=pay.TOKEN_PROGRAM_ID,
        )
    )
    # Classic SPL Token InitializeMint: tag, decimals, authority, COption<freeze authority>.
    initialize = Instruction(
        pay.TOKEN_PROGRAM_ID,
        b"\x00\x06" + bytes(payer.pubkey()) + struct_pack_u32(0),
        [
            AccountMeta(mint.pubkey(), False, True),
            AccountMeta(RENT_SYSVAR_ID, False, False),
        ],
    )
    _send(rpc, [create, initialize], payer, [mint])


def struct_pack_u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _create_token_account(
    rpc: SolanaRPC, payer: Keypair, account: Keypair, mint: Pubkey, owner: Pubkey
) -> None:
    rent = rpc.get_minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_SIZE)
    create = create_account(
        CreateAccountParams(
            from_pubkey=payer.pubkey(),
            to_pubkey=account.pubkey(),
            lamports=rent,
            space=TOKEN_ACCOUNT_SIZE,
            owner=pay.TOKEN_PROGRAM_ID,
        )
    )
    initialize = Instruction(
        pay.TOKEN_PROGRAM_ID,
        b"\x01",  # Classic SPL Token InitializeAccount.
        [
            AccountMeta(account.pubkey(), False, True),
            AccountMeta(mint, False, False),
            AccountMeta(owner, False, False),
            AccountMeta(RENT_SYSVAR_ID, False, False),
        ],
    )
    _send(rpc, [create, initialize], payer, [account])


def _mint_to(
    rpc: SolanaRPC,
    payer: Keypair,
    mint: Pubkey,
    destination: Pubkey,
    amount: int,
) -> None:
    instruction = Instruction(
        pay.TOKEN_PROGRAM_ID,
        b"\x07" + amount.to_bytes(8, "little"),
        [
            AccountMeta(mint, False, True),
            AccountMeta(destination, False, True),
            AccountMeta(payer.pubkey(), True, False),
        ],
    )
    _send(rpc, [instruction], payer)


def _program_accounts(**values: Pubkey | None) -> dict[str, Pubkey | None]:
    return values


def test_pay_program_real_validator_end_to_end(tmp_path: Path) -> None:
    validator = shutil.which("solana-test-validator")
    if validator is None:
        pytest.skip("solana-test-validator is not installed")
    root = Path(__file__).resolve().parents[2]
    program_so = root / "programs/nakshatra_pay/target/deploy/nakshatra_pay.so"
    if not program_so.is_file():
        pytest.skip(f"built program is missing: {program_so}")
    spl_token_so = Path("/home/prithvi/.cache/nak-solana/spl_token.so")
    if not spl_token_so.is_file():
        pytest.skip("cached classic SPL Token program is missing")

    authority = Keypair()
    owner = Keypair()
    delegate_key = Keypair()
    worker = Keypair()
    verifier = Keypair()
    mint = Keypair()
    source = Keypair()
    owner_destination = Keypair()
    worker_token = Keypair()
    fee_wallet = Keypair()

    port = _port_block()
    rpc_url = f"http://127.0.0.1:{port}"
    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env["HOME"] = str(home)
    for name in ("SOLANA_URL", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env.pop(name, None)
    validator_log_path = tmp_path / "validator.log"
    validator_log = validator_log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            validator,
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
            f"{port + 10}-{port + 80}",
            "--mint",
            str(authority.pubkey()),
            "--bpf-program",
            str(pay.TOKEN_PROGRAM_ID),
            str(spl_token_so),
            "--upgradeable-program",
            str(pay.PROGRAM_ID),
            str(program_so),
            str(authority.pubkey()),
        ],
        env=env,
        text=True,
        stdout=validator_log,
        stderr=subprocess.STDOUT,
    )
    try:
        rpc = SolanaRPC(rpc_url, timeout=3)
        _wait_for_validator(rpc, process, validator_log_path)

        # Owner and delegate pay rent for the accounts they create, per the program rules.
        _send(
            rpc,
            [
                transfer(
                    TransferParams(
                        from_pubkey=authority.pubkey(),
                        to_pubkey=owner.pubkey(),
                        lamports=100_000_000,
                    )
                ),
                transfer(
                    TransferParams(
                        from_pubkey=authority.pubkey(),
                        to_pubkey=delegate_key.pubkey(),
                        lamports=100_000_000,
                    )
                ),
            ],
            authority,
        )
        _create_mint(rpc, authority, mint)
        _create_token_account(rpc, authority, source, mint.pubkey(), owner.pubkey())
        _create_token_account(
            rpc, authority, owner_destination, mint.pubkey(), owner.pubkey()
        )
        _create_token_account(rpc, authority, worker_token, mint.pubkey(), worker.pubkey())
        _create_token_account(
            rpc, authority, fee_wallet, mint.pubkey(), authority.pubkey()
        )
        _mint_to(rpc, authority, mint.pubkey(), source.pubkey(), 10_000)

        config = pay.config_pda()[0]
        fee_vault = pay.fee_vault_pda(config)[0]
        escrow = pay.escrow_pda(owner.pubkey(), config)[0]
        owner_state = pay.owner_state_pda(owner.pubkey(), config)[0]
        vault = pay.vault_pda(escrow)[0]
        delegate = pay.delegate_pda(escrow, delegate_key.pubkey())[0]
        event_authority = pay.event_authority_pda()[0]

        _send(
            rpc,
            [
                pay.config_init(
                    _program_accounts(
                        authority=authority.pubkey(),
                        config=config,
                        program_data=pay.program_data_pda()[0],
                        mint=mint.pubkey(),
                        fee_wallet=fee_wallet.pubkey(),
                        fee_vault=fee_vault,
                        token_program=pay.TOKEN_PROGRAM_ID,
                        system_program=pay.SYSTEM_PROGRAM_ID,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    ),
                    300,
                )
            ],
            authority,
        )
        _send(
            rpc,
            [
                pay.escrow_init(
                    _program_accounts(
                        owner=owner.pubkey(),
                        config=config,
                        owner_state=owner_state,
                        mint=mint.pubkey(),
                        escrow=escrow,
                        vault=vault,
                        token_program=pay.TOKEN_PROGRAM_ID,
                        system_program=pay.SYSTEM_PROGRAM_ID,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    )
                )
            ],
            owner,
        )
        _send(
            rpc,
            [
                pay.escrow_deposit(
                    _program_accounts(
                        owner=owner.pubkey(),
                        config=config,
                        mint=mint.pubkey(),
                        escrow=escrow,
                        source=source.pubkey(),
                        vault=vault,
                        token_program=pay.TOKEN_PROGRAM_ID,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    ),
                    2_000,
                )
            ],
            authority,
            [owner],
        )
        _send(
            rpc,
            [
                pay.delegate_set(
                    _program_accounts(
                        owner=owner.pubkey(),
                        config=config,
                        escrow=escrow,
                        delegate=delegate,
                        system_program=pay.SYSTEM_PROGRAM_ID,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    ),
                    delegate_key.pubkey(),
                    1_000,
                    int(time.time()) + 3_600,
                    pay.DELEGATE_FLAGS_ALL,
                )
            ],
            owner,
        )
        channel = pay.channel_pda(escrow, 0, 0)[0]
        _send(
            rpc,
            [
                pay.channel_open(
                    _program_accounts(
                        signer=delegate_key.pubkey(),
                        config=config,
                        escrow=escrow,
                        vault=vault,
                        delegate=delegate,
                        channel=channel,
                        system_program=pay.SYSTEM_PROGRAM_ID,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    ),
                    worker.pubkey(),
                    500,
                )
            ],
            delegate_key,
        )

        # Three cumulative vouchers are signed and persisted; only the latter two land.
        with pay.VoucherBook(tmp_path / "payer-vouchers.sqlite") as vouchers:
            signed = []
            for total in (101, 201, 333):
                signature = pay.sign_voucher(delegate_key, pay.PROGRAM_ID, channel, total)
                vouchers.store(
                    channel,
                    total,
                    signature,
                    signer=delegate_key.pubkey(),
                    program=pay.PROGRAM_ID,
                )
                signed.append((total, signature))
            assert vouchers.latest(channel).total == 333

        redeem_accounts = _program_accounts(
            by=worker.pubkey(),
            config=config,
            mint=mint.pubkey(),
            escrow=escrow,
            channel=channel,
            vault=vault,
            worker_token=worker_token.pubkey(),
            fee_vault=fee_vault,
            instructions_sysvar=pay.INSTRUCTIONS_SYSVAR_ID,
            token_program=pay.TOKEN_PROGRAM_ID,
            event_authority=event_authority,
            program=pay.PROGRAM_ID,
        )
        redeem_signature = ""
        for total, signature in signed[1:]:
            redeem_signature = _send(
                rpc,
                [
                    pay.voucher_ed25519_instruction(
                        delegate_key.pubkey(), signature, pay.PROGRAM_ID, channel, total
                    ),
                    pay.channel_redeem(redeem_accounts, total),
                ],
                authority,
                [worker],
            )
        _wait_finalized(rpc, redeem_signature)
        assert pay.decode_config(pay._read_account(rpc, config)).fee_bps == 300
        assert pay.decode_owner_state(
            pay._read_account(rpc, owner_state)
        ).next_generation == 1
        delegate_state = pay.decode_delegate(pay._read_account(rpc, delegate))
        assert delegate_state.key == delegate_key.pubkey()
        assert delegate_state.cap_total == 1_000
        assert rpc.get_token_account(str(worker_token.pubkey()))["amount"] == 324
        assert rpc.get_token_account(str(fee_vault))["amount"] == 9
        assert pay.get_channel_state(rpc, channel).redeemed == 333

        _send(
            rpc,
            [
                pay.channel_close_request(
                    _program_accounts(
                        signer=owner.pubkey(),
                        config=config,
                        escrow=escrow,
                        channel=channel,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    )
                )
            ],
            authority,
            [owner],
        )
        # A worker signature permits cooperative close without clock warping.
        close_signature = _send(
            rpc,
            [
                pay.channel_close_finalize(
                    _program_accounts(
                        executor=worker.pubkey(),
                        config=config,
                        escrow=escrow,
                        delegate=delegate,
                        rent_payer=delegate_key.pubkey(),
                        channel=channel,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    )
                )
            ],
            authority,
            [worker],
        )
        _wait_finalized(rpc, close_signature)
        assert not rpc.account_exists(str(channel))

        def settle_task(task_seq: int, amount: int, verdict: str) -> Pubkey:
            task = pay.task_pda(escrow, 0, task_seq)[0]
            task_hash = bytes([task_seq + 1]) * 32
            result_hash = bytes([task_seq + 11]) * 32
            open_signature = _send(
                rpc,
                [
                    pay.task_open(
                        _program_accounts(
                            signer=owner.pubkey(),
                            config=config,
                            escrow=escrow,
                            vault=vault,
                            delegate=None,
                            task=task,
                            system_program=pay.SYSTEM_PROGRAM_ID,
                            event_authority=event_authority,
                            program=pay.PROGRAM_ID,
                        ),
                        worker.pubkey(),
                        verifier.pubkey(),
                        amount,
                        int(time.time()) + 600,
                        task_hash,
                    )
                ],
                owner,
            )
            _wait_finalized(rpc, open_signature)
            assert pay.get_task_state(rpc, task).status == "Open"
            _send(
                rpc,
                [
                    pay.task_submit(
                        _program_accounts(
                            worker=worker.pubkey(),
                            config=config,
                            escrow=escrow,
                            task=task,
                            event_authority=event_authority,
                            program=pay.PROGRAM_ID,
                        ),
                        result_hash,
                    )
                ],
                authority,
                [worker],
            )
            verdict_signature = pay.sign_verdict(
                verifier, pay.PROGRAM_ID, task, worker.pubkey(), amount, result_hash, verdict
            )
            settle_accounts = _program_accounts(
                executor=authority.pubkey(),
                config=config,
                mint=mint.pubkey(),
                escrow=escrow,
                delegate=None,
                rent_payer=owner.pubkey(),
                task=task,
                vault=vault,
                worker_token=worker_token.pubkey(),
                fee_vault=fee_vault,
                instructions_sysvar=pay.INSTRUCTIONS_SYSVAR_ID,
                token_program=pay.TOKEN_PROGRAM_ID,
                event_authority=event_authority,
                program=pay.PROGRAM_ID,
            )
            verify_signature = _send(
                rpc,
                [
                    pay.verdict_ed25519_instruction(
                        verifier.pubkey(),
                        verdict_signature,
                        pay.PROGRAM_ID,
                        task,
                        worker.pubkey(),
                        amount,
                        result_hash,
                        verdict,
                    ),
                    pay.task_verify(settle_accounts, verdict),
                ],
                authority,
            )
            _wait_finalized(rpc, verify_signature)
            assert not rpc.account_exists(str(task))
            return task

        settle_task(0, 100, "pass")
        assert rpc.get_token_account(str(worker_token.pubkey()))["amount"] == 421
        assert rpc.get_token_account(str(fee_vault))["amount"] == 12
        settle_task(1, 100, "fail")
        assert rpc.get_token_account(str(worker_token.pubkey()))["amount"] == 421
        assert rpc.get_token_account(str(fee_vault))["amount"] == 12

        withdraw_signature = _send(
            rpc,
            [
                pay.escrow_withdraw_request(
                    _program_accounts(
                        owner=owner.pubkey(),
                        config=config,
                        escrow=escrow,
                        vault=vault,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    ),
                    100,
                )
            ],
            authority,
            [owner],
        )
        _wait_finalized(rpc, withdraw_signature)
        status = pay.get_escrow_status(rpc, escrow)
        assert status.vault_balance == 1_567
        assert status.committed == 0
        assert status.available == 1_567
        assert status.pending_withdraw is not None
        assert status.pending_withdraw.amount == 100
        with pytest.raises(RPCError):
            _send(
                rpc,
                [
                    pay.escrow_withdraw_execute(
                        _program_accounts(
                            owner=owner.pubkey(),
                            config=config,
                            mint=mint.pubkey(),
                            escrow=escrow,
                            vault=vault,
                            destination=owner_destination.pubkey(),
                            token_program=pay.TOKEN_PROGRAM_ID,
                            event_authority=event_authority,
                            program=pay.PROGRAM_ID,
                        )
                    )
                ],
                authority,
                [owner],
            )
        assert pay.get_escrow_status(rpc, escrow).pending_withdraw.amount == 100

        fee_signature = _send(
            rpc,
            [
                pay.fee_withdraw(
                    _program_accounts(
                        authority=authority.pubkey(),
                        config=config,
                        mint=mint.pubkey(),
                        fee_vault=fee_vault,
                        fee_wallet=fee_wallet.pubkey(),
                        token_program=pay.TOKEN_PROGRAM_ID,
                        event_authority=event_authority,
                        program=pay.PROGRAM_ID,
                    ),
                    12,
                )
            ],
            authority,
        )
        _wait_finalized(rpc, fee_signature)
        assert rpc.get_token_account(str(fee_vault))["amount"] == 0
        assert rpc.get_token_account(str(fee_wallet.pubkey()))["amount"] == 12
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        validator_log.close()
