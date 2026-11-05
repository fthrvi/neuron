#!/usr/bin/env python3
import argparse
import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
import os
import struct
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(os.environ.get("NAK_PAY_DEPLOY_TOOL", Path(__file__).resolve().parents[1] / "scripts" / "devnet_deploy.py"))
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


class AccountRpc(FakeRpc):
    def __init__(self, accounts):
        super().__init__(genesis=deploy.DEVNET_GENESIS, url=deploy.DEVNET_RPC)
        self.accounts = accounts

    def account(self, address):
        return self.accounts.get(address)


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass


class RedirectHandler(QuietHandler):
    target = ""

    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()


class GenesisHandler(QuietHandler):
    requests = 0

    def do_GET(self):
        type(self).requests += 1
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "redirected-non-devnet"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def redirecting_rpc():
    GenesisHandler.requests = 0
    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GenesisHandler)
    RedirectHandler.target = f"http://localhost:{target.server_port}/"
    source = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (target, source)]
    for thread in threads:
        thread.start()
    try:
        yield f"http://127.0.0.1:{source.server_port}"
    finally:
        for server in (source, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()


@contextlib.contextmanager
def stateful_307_rpc():
    counts = {"source": 0, "target": 0}

    class Target(QuietHandler):
        def do_POST(self):
            counts["target"] += 1
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)

    class Source(QuietHandler):
        def do_POST(self):
            counts["source"] += 1
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            if request.get("method") == "getGenesisHash":
                body = json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": "local-test-genesis"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}")
            self.send_header("Content-Length", "0")
            self.end_headers()

    source = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Source)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (target, source)]
    for thread in threads:
        thread.start()
    try:
        yield f"http://127.0.0.1:{source.server_port}", counts
    finally:
        for server in (source, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()


def redirect_following_cli(args):
    """Model the installed Rust CLI's POST-preserving 307 behavior."""
    command = [str(arg) for arg in args]
    url = command[command.index("--url") + 1]
    body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "getLatestBlockhash", "params": []}).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        if exc.code != 307:
            raise deploy.DeployError(f"simulated CLI RPC failed: HTTP {exc.code}") from exc
        redirected = urllib.request.Request(
            exc.headers["Location"], data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(redirected, timeout=2) as response:
            response.read()
    return json.dumps({"signature": "simulated", "transactionSignature": "simulated"})


def program_accounts(code, authority=deploy.SYSTEM_PROGRAM_ID):
    program_data = deploy.b58encode(deploy.program_data_pda())
    program = {
        "owner": deploy.UPGRADEABLE_LOADER_ID,
        "executable": True,
        "data_raw": struct.pack("<I", 2) + deploy.pubkey(program_data),
    }
    data = struct.pack("<IQB", 3, 7, 1) + deploy.pubkey(authority) + code
    return {
        deploy.PROGRAM_ID: program,
        program_data: {"owner": deploy.UPGRADEABLE_LOADER_ID, "data_raw": data},
    }


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
    def _assert_url_parse_refused(self, url, rehearsal=False):
        argv = ["--url", url]
        if rehearsal:
            argv.append("--rehearsal")
        argv += ["build-check", "--so", "/tmp/not-read-during-parse.so", "--expect-sha256", "0" * 64]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            deploy.parser().parse_args(argv)
        self.assertEqual(raised.exception.code, 2)

    def _assert_cli_path_redirect_fenced(self, path):
        payer = deploy.pubkey(deploy.SYSTEM_PROGRAM_ID)
        program_key = deploy.pubkey(deploy.PROGRAM_ID)
        with tempfile.TemporaryDirectory() as directory, stateful_307_rpc() as (url, counts):
            root = Path(directory)
            state = deploy.State(root / "state")
            rpc = deploy.Rpc(url)

            def fake_load(key_path):
                public = program_key if Path(key_path).name == "program.json" else payer
                return b"\0" * 32, public

            common_patches = (
                patch.object(deploy, "load_keypair", side_effect=fake_load),
                patch.object(deploy, "run_cli", side_effect=redirect_following_cli),
            )
            with common_patches[0], common_patches[1]:
                try:
                    if path == "deploy":
                        so = root / "program.so"
                        so.write_bytes(b"reviewed program")
                        state.data = {
                            "expected_sha256": hashlib.sha256(so.read_bytes()).hexdigest(),
                            "so_size": so.stat().st_size,
                        }
                        args = argparse.Namespace(
                            url=url, rehearsal=True, so=so, program_keypair=root / "program.json",
                            payer=root / "payer.json",
                        )
                        with patch.object(deploy, "inspect_program", return_value=None), \
                                patch.object(deploy, "create_keypair", return_value=b"\1" * 32):
                            deploy.cmd_deploy(args, state, rpc)
                    elif path == "fee-wallet":
                        mint = deploy.TOKEN_PROGRAM_ID
                        payer_text = deploy.b58encode(payer)
                        ata = deploy.b58encode(
                            deploy.find_pda(
                                [payer, deploy.pubkey(deploy.TOKEN_PROGRAM_ID), deploy.pubkey(mint)],
                                deploy.ASSOCIATED_TOKEN_PROGRAM_ID,
                            )[0]
                        )
                        ata_reads = 0

                        def fake_account(address):
                            nonlocal ata_reads
                            if address == mint:
                                return {"owner": deploy.TOKEN_PROGRAM_ID, "data_raw": b"mint"}
                            if address == ata:
                                ata_reads += 1
                                if ata_reads == 1:
                                    return None
                                return {
                                    "owner": deploy.TOKEN_PROGRAM_ID,
                                    "data_raw": deploy.pubkey(mint) + payer + b"\0" * 101,
                                }
                            return None

                        state.data = {
                            "expected_sha256": "ab" * 32, "so_size": 16, "deployer": payer_text,
                        }
                        config = {
                            "authority": payer_text, "pending_authority": None, "mint": mint,
                            "fee_bps": 300, "fee_wallet": ata,
                        }
                        args = argparse.Namespace(
                            url=url, rehearsal=True, fee_bps=300, payer=root / "payer.json",
                            mint=mint, fee_wallet=None,
                        )
                        with patch.object(rpc, "account", side_effect=fake_account), \
                                patch.object(deploy, "read_config", side_effect=[None, config]), \
                                patch.object(deploy, "send_instructions", return_value="config-signature"):
                            deploy.cmd_config_init(args, state, rpc)
                    elif path == "set-upgrade-authority":
                        payer_text = deploy.b58encode(payer)
                        vault = deploy.TOKEN_PROGRAM_ID
                        state.data = {
                            "deployer": payer_text, "vault": vault, "so_size": 16,
                            "expected_sha256": "ab" * 32,
                        }
                        config = {"authority": payer_text, "pending_authority": vault}
                        before = {
                            "upgrade_authority": payer_text, "program_data": deploy.SYSTEM_PROGRAM_ID,
                            "code_sha256": "ab" * 32, "code_length": 16,
                        }
                        after = {**before, "upgrade_authority": vault}
                        args = argparse.Namespace(url=url, rehearsal=True, payer=root / "payer.json")
                        with patch.object(deploy, "read_config", return_value=config), \
                                patch.object(deploy, "inspect_program", side_effect=[before, after]):
                            deploy.cmd_handover(args, state, rpc)
                    else:
                        raise AssertionError(path)
                except deploy.DeployError:
                    pass
            self.assertEqual(counts["source"], 3, "command guard, proxy guard and CLI request must all run")
            self.assertEqual(counts["target"], 0, f"redirect target received a {path} CLI request")

    def test_devnet_genesis_is_accepted(self):
        rpc = FakeRpc(genesis=deploy.DEVNET_GENESIS, url=deploy.DEVNET_RPC)
        self.assertEqual(deploy.cluster_guard(rpc, False), deploy.DEVNET_GENESIS)

    def test_production_url_with_userinfo_is_refused_at_parse(self):
        self._assert_url_parse_refused("https://operator@api.devnet.solana.com")

    def test_production_url_with_another_port_is_refused_at_parse(self):
        self._assert_url_parse_refused("https://api.devnet.solana.com:443")

    def test_production_url_with_trailing_path_is_refused_at_parse(self):
        self._assert_url_parse_refused("https://api.devnet.solana.com/rpc")

    def test_rehearsal_url_must_be_exact_literal_loopback_at_parse(self):
        self._assert_url_parse_refused("http://localhost:8899", rehearsal=True)
        self._assert_url_parse_refused("http://127.0.0.1:8899/", rehearsal=True)

    def test_cli_deploy_redirect_target_receives_zero_requests(self):
        self._assert_cli_path_redirect_fenced("deploy")

    def test_cli_fee_wallet_redirect_target_receives_zero_requests(self):
        self._assert_cli_path_redirect_fenced("fee-wallet")

    def test_cli_set_authority_redirect_target_receives_zero_requests(self):
        self._assert_cli_path_redirect_fenced("set-upgrade-authority")

    def test_non_devnet_genesis_is_refused(self):
        with self.assertRaisesRegex(deploy.DeployError, "not devnet"):
            deploy.cluster_guard(FakeRpc(url="http://127.0.0.2:19999"), False)

    def test_rehearsal_requires_literal_loopback(self):
        with self.assertRaisesRegex(deploy.DeployError, "not devnet"):
            deploy.cluster_guard(FakeRpc(url="http://localhost:19999"), True)
        self.assertEqual(deploy.cluster_guard(FakeRpc(), True), "local-test-genesis")

    def test_rpc_redirect_is_refused_on_every_subcommand_path(self):
        with tempfile.TemporaryDirectory() as directory, redirecting_rpc() as url:
            root = Path(directory)
            so = root / "program.so"
            so.write_bytes(b"reviewed program")
            digest = hashlib.sha256(so.read_bytes()).hexdigest()
            commands = {
                "build-check": ["build-check", "--so", str(so), "--expect-sha256", digest],
                "deploy": ["deploy", "--so", str(so), "--program-keypair", str(root / "program.json"), "--payer", str(root / "payer.json")],
                "config-init": ["config-init", "--fee-bps", "300", "--payer", str(root / "payer.json")],
                "multisig-create": [
                    "multisig-create", "--member", deploy.SYSTEM_PROGRAM_ID, "--member", deploy.TOKEN_PROGRAM_ID,
                    "--member", deploy.PROGRAM_ID, "--threshold", "2", "--time-lock", "5", "--payer", str(root / "payer.json"),
                ],
                "handover": ["handover", "--payer", str(root / "payer.json")],
                "accept-config-authority": ["accept-config-authority", "propose", "--member-key", str(root / "member.json")],
                "verify": ["verify"],
            }
            for name, command in commands.items():
                with self.subTest(command=name):
                    output = io.StringIO()
                    argv = ["--url", url, "--rehearsal", "--state-dir", str(root / name), *command]
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(deploy.main(argv), 1)
                    self.assertIn("redirect refused", output.getvalue())
            self.assertEqual(GenesisHandler.requests, 0, "redirect target must never receive an RPC request")

    def test_wrong_binary_hash_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            so = root / "program.so"
            so.write_bytes(b"not the reviewed binary")
            state = deploy.State(root / "state")
            args = argparse.Namespace(so=so, expect_sha256="0" * 64)
            with self.assertRaisesRegex(deploy.DeployError, "sha256 mismatch"):
                deploy.cmd_build_check(args, state)

    def test_state_file_must_be_a_json_object(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state.json").write_text("[]\n")
            with self.assertRaisesRegex(deploy.DeployError, "JSON object"):
                deploy.State(root)

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

    def test_program_data_trailing_bytes_are_refused(self):
        reviewed = b"reviewed program bytes"
        rpc = AccountRpc(program_accounts(reviewed + b"trailing bytes"))
        with self.assertRaisesRegex(deploy.DeployError, "length"):
            deploy.inspect_program(rpc, len(reviewed))

    def test_program_report_includes_complete_code_length(self):
        reviewed = b"reviewed program bytes"
        report = deploy.inspect_program(AccountRpc(program_accounts(reviewed)), len(reviewed))
        self.assertEqual(report["code_length"], len(reviewed))
        self.assertEqual(report["code_sha256"], hashlib.sha256(reviewed).hexdigest())

    def test_same_length_program_difference_is_refused_by_verify(self):
        reviewed = b"reviewed program bytes"
        changed = reviewed[:-1] + bytes([reviewed[-1] ^ 1])
        multisig_address = deploy.ASSOCIATED_TOKEN_PROGRAM_ID
        vault = deploy.b58encode(deploy.squads_vault_pda(deploy.pubkey(multisig_address)))
        members = [deploy.SYSTEM_PROGRAM_ID, deploy.TOKEN_PROGRAM_ID, deploy.PROGRAM_ID]
        with tempfile.TemporaryDirectory() as directory:
            state = deploy.State(Path(directory))
            state.data = {
                "expected_sha256": hashlib.sha256(reviewed).hexdigest(), "so_size": len(reviewed),
                "multisig": multisig_address, "members": members, "vault": vault,
                "mint": deploy.DEVNET_USDC_MINT, "time_lock": 172800,
            }
            config = {"mint": deploy.DEVNET_USDC_MINT, "fee_bps": 300, "authority": vault, "pending_authority": None}
            multisig = {"threshold": 2, "time_lock": 172800, "members": [{"key": key, "permissions": 7} for key in members]}
            with patch.object(deploy, "read_config", return_value=config), patch.object(deploy, "read_multisig", return_value=multisig):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    deploy.cmd_verify(
                        argparse.Namespace(url=deploy.DEVNET_RPC, rehearsal=False), state,
                        AccountRpc(program_accounts(changed, vault)),
                    )

    def _verify_with(self, state_values, program_authority, config, multisig, rehearsal=False):
        with tempfile.TemporaryDirectory() as directory:
            state = deploy.State(Path(directory))
            state.data = {
                "expected_sha256": "ab" * 32, "so_size": 10,
                "multisig": deploy.ASSOCIATED_TOKEN_PROGRAM_ID,
                "members": [deploy.SYSTEM_PROGRAM_ID, deploy.TOKEN_PROGRAM_ID, deploy.PROGRAM_ID],
                **state_values,
            }
            program = {
                "program": deploy.PROGRAM_ID, "program_data": deploy.SYSTEM_PROGRAM_ID, "executable": True,
                "slot": 7, "upgrade_authority": program_authority, "code_sha256": "ab" * 32, "code_length": 10,
            }
            printed = []
            with patch.object(deploy, "inspect_program", return_value=program), patch.object(deploy, "read_config", return_value=config), \
                    patch.object(deploy, "read_multisig", return_value=multisig), patch.object(deploy, "json_print", side_effect=printed.append):
                try:
                    report = deploy.cmd_verify(
                        argparse.Namespace(url=deploy.DEVNET_RPC, rehearsal=rehearsal), state,
                        FakeRpc(genesis=deploy.DEVNET_GENESIS, url=deploy.DEVNET_RPC),
                    )
                except SystemExit:
                    report = printed[-1]
            return report

    def _valid_verify_values(self):
        multisig_address = deploy.ASSOCIATED_TOKEN_PROGRAM_ID
        vault = deploy.b58encode(deploy.squads_vault_pda(deploy.pubkey(multisig_address)))
        members = [deploy.SYSTEM_PROGRAM_ID, deploy.TOKEN_PROGRAM_ID, deploy.PROGRAM_ID]
        config = {"mint": deploy.DEVNET_USDC_MINT, "fee_bps": 300, "authority": vault, "pending_authority": None}
        multisig = {"threshold": 2, "time_lock": 172800, "members": [{"key": key, "permissions": 7} for key in members]}
        return vault, config, multisig

    def test_production_verify_does_not_require_state_policy_fields(self):
        vault, config, multisig = self._valid_verify_values()
        report = self._verify_with({}, vault, config, multisig)
        self.assertTrue(report["ok"], report)

    def test_production_verify_refuses_state_substituted_mint(self):
        vault, config, multisig = self._valid_verify_values()
        config = {**config, "mint": deploy.TOKEN_PROGRAM_ID}
        report = self._verify_with(
            {"vault": vault, "mint": deploy.TOKEN_PROGRAM_ID, "time_lock": 172800}, vault, config, multisig,
        )
        self.assertFalse(report["ok"], report)
        self.assertIn("config_mint", report["mismatches"])

    def test_production_verify_refuses_state_substituted_time_lock(self):
        vault, config, multisig = self._valid_verify_values()
        multisig = {**multisig, "time_lock": 5}
        report = self._verify_with(
            {"vault": vault, "mint": deploy.DEVNET_USDC_MINT, "time_lock": 5}, vault, config, multisig,
        )
        self.assertFalse(report["ok"], report)
        self.assertIn("multisig_time_lock", report["mismatches"])

    def test_production_verify_refuses_state_substituted_vault(self):
        canonical_vault, config, multisig = self._valid_verify_values()
        unrelated = deploy.TOKEN_PROGRAM_ID
        config = {**config, "authority": unrelated}
        report = self._verify_with(
            {"vault": unrelated, "mint": deploy.DEVNET_USDC_MINT, "time_lock": 172800}, unrelated, config, multisig,
        )
        self.assertFalse(report["ok"], report)
        self.assertIn("upgrade_authority", report["mismatches"])
        self.assertIn("config_authority", report["mismatches"])
        self.assertNotEqual(canonical_vault, unrelated)

    def test_verify_reports_canonical_config_authority_as_pending(self):
        vault, config, multisig = self._valid_verify_values()
        config = {**config, "authority": deploy.SYSTEM_PROGRAM_ID, "pending_authority": vault}
        report = self._verify_with({}, vault, config, multisig)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["config"]["authority_status"], "pending")

    def test_rehearsal_script_checks_specific_upgrade_authority_error(self):
        rehearsal = SCRIPT.with_name("rehearse_devnet_deploy.sh").read_text()
        self.assertIn(
            'expect_failure_output_contains deployer-upgrade "does not match authority provided"',
            rehearsal,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
