#!/usr/bin/env python3
import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "devnet_deploy.py"
SPEC = importlib.util.spec_from_file_location("nak_pay_devnet_deploy", SCRIPT)
deploy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = deploy
SPEC.loader.exec_module(deploy)


class FakeRpc:
    def __init__(self, genesis="local-test-genesis", url="http://127.0.0.1:19999"):
        self.genesis = genesis
        self.url = url

    def call(self, method, params=None):
        if method == "getGenesisHash":
            return self.genesis
        raise AssertionError(method)


class CodecTests(unittest.TestCase):
    def test_rfc8032_empty_message_vector(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertEqual(deploy._public_from_seed(seed), public)
        self.assertEqual(deploy._sign(seed, public, b""), signature)

    def test_base58_round_trip_with_leading_zeroes(self):
        value = b"\0\0" + bytes(range(1, 33))
        self.assertEqual(deploy.b58decode(deploy.b58encode(value)), value)

    def test_known_program_pdas(self):
        self.assertEqual(
            deploy.b58encode(deploy.config_pda()),
            "8Q1BNKohnutkCsWhPSKVydM5LBNbzVom8Zss5hNsa7r8",
        )
        self.assertEqual(
            deploy.b58encode(deploy.squads_program_config_pda()),
            "BSTq9w3kZwNwpBXJEvTZz2G9ZTNyKBvoSeXMvwb4cNZr",
        )

    def test_shortvec_boundaries(self):
        self.assertEqual(deploy.shortvec(0), b"\0")
        self.assertEqual(deploy.shortvec(127), b"\x7f")
        self.assertEqual(deploy.shortvec(128), b"\x80\x01")
        self.assertEqual(deploy.shortvec(16384), b"\x80\x80\x01")

    def test_wrapped_accept_message_has_compact_squads_layout(self):
        vault = bytes(range(32))
        message, accounts = deploy.build_config_accept_message(vault)
        self.assertEqual(message[:4], b"\x01\x01\x01\x04")
        self.assertEqual(message[-1], 0)  # no address table lookups
        self.assertEqual(len(accounts), 4)
        self.assertTrue(accounts[0].writable)
        self.assertFalse(accounts[0].signer)


class SafetyTests(unittest.TestCase):
    def test_devnet_genesis_is_accepted(self):
        rpc = FakeRpc(genesis=deploy.DEVNET_GENESIS, url=deploy.DEVNET_RPC)
        self.assertEqual(deploy.cluster_guard(rpc, False), deploy.DEVNET_GENESIS)

    def test_non_devnet_genesis_is_refused(self):
        with self.assertRaisesRegex(deploy.DeployError, "not devnet"):
            deploy.cluster_guard(FakeRpc(url="http://127.0.0.2:19999"), False)

    def test_rehearsal_requires_literal_loopback(self):
        with self.assertRaisesRegex(deploy.DeployError, "not devnet"):
            deploy.cluster_guard(FakeRpc(url="http://localhost:19999"), True)
        self.assertEqual(deploy.cluster_guard(FakeRpc(), True), "local-test-genesis")

    def test_wrong_binary_hash_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            so = root / "program.so"
            so.write_bytes(b"not the reviewed binary")
            state = deploy.State(root / "state")
            args = argparse.Namespace(so=so, expect_sha256="0" * 64)
            with self.assertRaisesRegex(deploy.DeployError, "sha256 mismatch"):
                deploy.cmd_build_check(args, state)

    def test_solana_buffer_recovery_phrase_is_redacted(self):
        stderr = (
            "Recover the intermediate account's ephemeral keypair file with\n"
            "the following 12-word seed phrase:\nsecret words must never escape here\n"
            "To resume a deploy, pass the recovered keypair"
        )
        completed = SimpleNamespace(returncode=1, stderr=stderr, stdout="")
        with patch.object(deploy.subprocess, "run", return_value=completed):
            with self.assertRaises(deploy.DeployError) as raised:
                deploy.run_cli(["solana", "program", "deploy"])
        self.assertNotIn("secret words", str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))

    def test_multisig_threshold_duplicate_and_lock_validation(self):
        base = dict(
            rehearsal=True,
            member=[deploy.SYSTEM_PROGRAM_ID, deploy.TOKEN_PROGRAM_ID, deploy.PROGRAM_ID],
            threshold=2,
            time_lock=5,
            payer=Path("unused"),
        )
        with tempfile.TemporaryDirectory() as directory:
            state = deploy.State(Path(directory))
            with self.assertRaisesRegex(deploy.DeployError, "threshold"):
                deploy.cmd_multisig_create(argparse.Namespace(**{**base, "threshold": 1}), state, FakeRpc())
            duplicate = [deploy.PROGRAM_ID, deploy.PROGRAM_ID, deploy.TOKEN_PROGRAM_ID]
            with self.assertRaisesRegex(deploy.DeployError, "distinct"):
                deploy.cmd_multisig_create(argparse.Namespace(**{**base, "member": duplicate}), state, FakeRpc())
            with self.assertRaisesRegex(deploy.DeployError, "time-lock"):
                deploy.cmd_multisig_create(
                    argparse.Namespace(**{**base, "rehearsal": False, "time_lock": 6}),
                    state,
                    FakeRpc(genesis=deploy.DEVNET_GENESIS, url=deploy.DEVNET_RPC),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
