from __future__ import annotations

import json
import struct

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


def test_voucher_book_is_monotonic_and_supports_full_u64(tmp_path) -> None:
    channel = client.IDL["address"]
    first = bytes(range(64))
    second = bytes(reversed(range(64)))
    with client.VoucherBook(tmp_path / "vouchers.sqlite") as book:
        assert book.latest(channel) is None
        assert book.store(channel, 2**64 - 2, first).total == 2**64 - 2
        assert book.store(channel, 2**64 - 1, second).signature == second
        with pytest.raises(ValueError, match="below stored total"):
            book.store(channel, 2**64 - 2, first)
        assert book.latest(channel) == client.VoucherRecord(
            channel, 2**64 - 1, second
        )


@requires_solders
def test_account_decoders_reject_wrong_discriminator_and_trailing_data() -> None:
    data = bytes(client._ACCOUNT_DISCRIMINATORS["OwnerState"]) + struct.pack("<QB", 7, 255)
    assert client.decode_owner_state(data) == client.OwnerState(7, 255)
    with pytest.raises(ValueError, match="not a OwnerState"):
        client.decode_owner_state(b"12345678" + struct.pack("<QB", 7, 255))
    with pytest.raises(ValueError, match="trailing"):
        client.decode_owner_state(data + b"\x01")
