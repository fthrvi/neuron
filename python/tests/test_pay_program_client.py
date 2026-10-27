from __future__ import annotations

import json
import os
import stat
import struct
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from solders.pubkey import Pubkey
except ModuleNotFoundError:
    Pubkey = None  # type: ignore[assignment,misc]

from python.chain import program_client as client


requires_solders = pytest.mark.skipif(Pubkey is None, reason="solders is not installed")


@requires_solders
def test_pda_derivations_match_rust_vectors() -> None:
    # These values were generated with solana_sdk::pubkey::Pubkey::find_program_address
    # using the same seed expressions as the program's m0_m1.rs/m2.rs fixtures.
    owner = Pubkey.from_string("11111111111111111111111111111111")
    escrow = client.escrow_pda(owner)[0]
    vectors = {
        "config": (*client.config_pda(), "8Q1BNKohnutkCsWhPSKVydM5LBNbzVom8Zss5hNsa7r8", 253),
        "fee_vault": (*client.fee_vault_pda(), "7DkBUyoStBewnue8UtaCYkw8ei2Nor1T8ku8aNobKH2F", 254),
        "owner_state": (*client.owner_state_pda(owner), "AUwPoA474V3PCetuYr2pFVCydUqnVPVzaUDtjWSRfeLD", 253),
        "escrow": (*client.escrow_pda(owner), "3uFjhTtEaGMKjcozPfGQTrKfGPB15uhxK6TBPCZ77Yfu", 255),
        "vault": (*client.vault_pda(escrow), "DZdnJ98PrSTxbzwtm9uGvD6g4REqqngYPksgf7EN5cgU", 254),
        "delegate": (*client.delegate_pda(escrow, owner), "CUYmpWdtopFuvFHjVYALZievYAgJdtBJyRKfdsgGczcb", 254),
        "channel": (*client.channel_pda(escrow, 7, 11), "Gyqo3gEY8yZFR5QCN4hH2H8WhTcUUEaxB2L3pQG3yRvf", 254),
        "task": (*client.task_pda(escrow, 7, 13), "Dh2njy7da1p7HioPYbLYuhYipnx7yofnQEd5GEPV8sAA", 254),
        "event": (*client.event_authority_pda(), "H1orCw5goBsLUNn5JxPvQWgZvP7jNbx6pgxVWRFLKWXP", 255),
        "program_data": (*client.program_data_pda(), "97gxB89oiTezhWHdyhovCei33k9Bkn9ZqppamVKenF1d", 253),
    }
    for address, bump, expected_address, expected_bump in vectors.values():
        assert str(address) == expected_address
        assert bump == expected_bump


def _sample_arg(kind: str):
    return {
        "u8": 3,
        "u16": 300,
        "u64": 123,
        "i64": 1_900_000_000,
        "pubkey": Pubkey.new_unique(),
        "bytes32": bytes(range(32)),
        "verdict": "pass",
    }[kind]


@requires_solders
def test_every_builder_agrees_with_committed_idl() -> None:
    idl = json.loads(client.IDL_PATH.read_text(encoding="utf-8"))
    assert set(client._ARG_LAYOUTS) == {item["name"] for item in idl["instructions"]}
    for spec in idl["instructions"]:
        accounts = {
            account["name"]: None if account.get("optional") else Pubkey.new_unique()
            for account in spec["accounts"]
        }
        args = [_sample_arg(kind) for _, kind in client._ARG_LAYOUTS[spec["name"]]]
        ix = client.build_instruction(spec["name"], accounts, *args)
        assert ix.data[:8] == bytes(spec["discriminator"])
        assert len(ix.accounts) == len(spec["accounts"])
        for meta, account in zip(ix.accounts, spec["accounts"], strict=True):
            assert meta.is_signer is bool(account.get("signer", False))
            assert meta.is_writable is bool(account.get("writable", False))
        assert len(ix.data) == 8 + sum(
            {"u8": 1, "u16": 2, "u64": 8, "i64": 8, "pubkey": 32, "bytes32": 32, "verdict": 1}[kind]
            for _, kind in client._ARG_LAYOUTS[spec["name"]]
        )


@requires_solders
def test_instruction_argument_encoding_and_ed25519_self_offsets() -> None:
    key = Pubkey.new_unique()
    ix = client.build_instruction(
        "delegate_set",
        {
            "owner": key,
            "config": key,
            "escrow": key,
            "delegate": key,
            "event_authority": key,
            "program": client.PROGRAM_ID,
        },
        key,
        0x0102030405060708,
        -42,
        3,
    )
    assert ix.data[8:40] == bytes(key)
    assert ix.data[40:48] == struct.pack("<Q", 0x0102030405060708)
    assert ix.data[48:56] == struct.pack("<q", -42)
    assert ix.data[56:] == b"\x03"

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    message = b"message"
    signature = private.sign(message)
    ed = client.ed25519_instruction(public, signature, message)
    assert ed.program_id == client.ED25519_PROGRAM_ID
    assert ed.accounts == []
    assert ed.data[:2] == b"\x01\x00"
    assert struct.unpack("<7H", ed.data[2:16]) == (
        48,
        0xFFFF,
        16,
        0xFFFF,
        112,
        len(message),
        0xFFFF,
    )
    assert ed.data[16:48] == public
    assert ed.data[48:112] == signature
    assert ed.data[112:] == message


def test_voucher_sign_verify_round_trip_and_tamper_rejection() -> None:
    key = Ed25519PrivateKey.generate()
    channel = "11111111111111111111111111111111"
    signature = client.sign_voucher(key, client.PROGRAM_ID, channel, 987_654)
    public = key.public_key().public_bytes_raw()
    assert client.verify_voucher(public, signature, client.PROGRAM_ID, channel, 987_654)
    assert not client.verify_voucher(public, signature, client.PROGRAM_ID, channel, 987_655)
    assert not client.verify_voucher(public, signature, client.PROGRAM_ID, client.IDL["address"], 987_654)
    altered = bytearray(signature)
    altered[-1] ^= 1
    assert not client.verify_voucher(public, altered, client.PROGRAM_ID, channel, 987_654)


def test_voucher_book_is_monotonic_and_supports_full_u64(tmp_path, monkeypatch) -> None:
    channel = client.IDL["address"]
    program = client.PROGRAM_ID
    signer = Ed25519PrivateKey.generate()
    signer_public = signer.public_key().public_bytes_raw()
    other_signer = Ed25519PrivateKey.generate()
    other_public = other_signer.public_key().public_bytes_raw()
    wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    wrong_address = "11111111111111111111111111111111"
    database = tmp_path / "vouchers.sqlite"
    first_total = 2**64 - 2
    first = client.sign_voucher(signer, program, channel, first_total)
    second = client.sign_voucher(signer, program, channel, 2**64 - 1)

    with client.VoucherBook(database) as book:
        assert book.latest(channel) is None

        rejected = (
            (channel, first_total, bytes(64), signer_public, program),
            (channel, first_total, first, wrong_key, program),
            (wrong_address, first_total, first, signer_public, program),
            (channel, first_total, first, signer_public, wrong_address),
            (channel, 2**64 - 1, bytes(64), signer_public, program),
        )
        for target_channel, total, signature, public, target_program in rejected:
            with pytest.raises(ValueError, match="invalid voucher signature"):
                book.store(
                    target_channel,
                    total,
                    signature,
                    signer=public,
                    program=target_program,
                )
        assert book.latest(channel) is None

        assert book.store(
            channel, first_total, first, signer=signer_public, program=program
        ).total == first_total
        # Exact replay is idempotent.
        assert book.store(
            channel, first_total, first, signer=signer_public, program=program
        ).signature == first

        different_signer_signature = client.sign_voucher(
            other_signer, program, channel, 2**64 - 1
        )
        with pytest.raises(ValueError, match="pinned"):
            book.store(
                channel,
                2**64 - 1,
                different_signer_signature,
                signer=other_public,
                program=program,
            )
        different_program_signature = client.sign_voucher(
            signer, wrong_address, channel, 2**64 - 1
        )
        with pytest.raises(ValueError, match="pinned"):
            book.store(
                channel,
                2**64 - 1,
                different_program_signature,
                signer=signer_public,
                program=wrong_address,
            )
        lower = client.sign_voucher(signer, program, channel, first_total - 1)
        with pytest.raises(ValueError, match="below stored total"):
            book.store(
                channel,
                first_total - 1,
                lower,
                signer=signer_public,
                program=program,
            )
        altered = bytearray(first)
        altered[0] ^= 1
        with monkeypatch.context() as patch:
            # Ed25519 has a unique valid signature for this key/message.  Bypass
            # only cryptographic verification to exercise the equal-total guard.
            patch.setattr(client, "verify_voucher", lambda *args: True)
            with pytest.raises(ValueError, match="different signature"):
                book.store(
                    channel,
                    first_total,
                    altered,
                    signer=signer_public,
                    program=program,
                )
        assert book.store(
            channel, 2**64 - 1, second, signer=signer_public, program=program
        ).signature == second
        assert book.latest(channel) == client.VoucherRecord(
            channel, 2**64 - 1, second
        )
        for suffix in ("", "-wal", "-shm"):
            path = type(database)(f"{database}{suffix}")
            assert path.is_file()
            assert stat.S_IMODE(path.stat().st_mode) == 0o600


def _mutate_instruction_arg(idl: dict) -> None:
    instruction = next(item for item in idl["instructions"] if item["name"] == "config_init")
    instruction["args"][0]["type"] = "u32"


def _mutate_account_flag(idl: dict) -> None:
    instruction = next(item for item in idl["instructions"] if item["name"] == "config_init")
    instruction["accounts"][0]["signer"] = not instruction["accounts"][0].get(
        "signer", False
    )


def _mutate_enum_order(idl: dict) -> None:
    enum = next(item for item in idl["types"] if item["name"] == "Verdict")
    enum["type"]["variants"].reverse()


@pytest.mark.parametrize(
    "mutate", [_mutate_instruction_arg, _mutate_account_flag, _mutate_enum_order]
)
def test_import_rejects_idl_wire_format_drift(tmp_path, mutate) -> None:
    idl = json.loads(client.IDL_PATH.read_text(encoding="utf-8"))
    mutate(idl)
    changed = tmp_path / "changed-idl.json"
    changed.write_text(json.dumps(idl), encoding="utf-8")
    env = os.environ.copy()
    env["NAKSHATRA_PAY_IDL_PATH"] = str(changed)
    result = subprocess.run(
        [sys.executable, "-c", "import python.chain.program_client"],
        cwd=client.IDL_PATH.parents[3],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "nakshatra_pay IDL" in result.stderr


def test_program_id_can_be_overridden_by_environment(tmp_path) -> None:
    copied_idl = tmp_path / "nakshatra_pay.json"
    copied_idl.write_text(client.IDL_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    override = "11111111111111111111111111111111"
    env = os.environ.copy()
    env["NAKSHATRA_PAY_IDL_PATH"] = str(copied_idl)
    env["NAKSHATRA_PAY_PROGRAM_ID"] = override
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from python.chain.program_client import IDL_PATH, PROGRAM_ID; "
            "print(IDL_PATH); print(PROGRAM_ID)",
        ],
        cwd=client.IDL_PATH.parents[3],
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.splitlines() == [str(copied_idl), override]


@requires_solders
def test_pubkey_rejects_integers() -> None:
    with pytest.raises(ValueError, match="cannot be an integer"):
        client._pubkey(32)


@requires_solders
def test_account_decoders_reject_wrong_discriminator_and_trailing_data() -> None:
    data = bytes(client._ACCOUNT_DISCRIMINATORS["OwnerState"]) + struct.pack("<QB", 7, 255)
    assert client.decode_owner_state(data) == client.OwnerState(7, 255)
    with pytest.raises(ValueError, match="not a OwnerState"):
        client.decode_owner_state(b"12345678" + struct.pack("<QB", 7, 255))
    with pytest.raises(ValueError, match="trailing"):
        client.decode_owner_state(data + b"\x01")
