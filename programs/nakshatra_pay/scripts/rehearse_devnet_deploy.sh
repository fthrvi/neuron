#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
deploy_tool="$workspace_dir/scripts/devnet_deploy.py"
solana_bin=/home/prithvi/.local/share/solana/install/active_release/bin
solana="$solana_bin/solana"
solana_keygen="$solana_bin/solana-keygen"
validator="$solana_bin/solana-test-validator"
spl_token="$solana_bin/spl-token"
program_keypair=/home/prithvi/wt/neu-pay/programs/nakshatra_pay/target/deploy/nakshatra_pay-keypair.json
program_id=GLWqQsSqUsDkPvkc8rxcoQUyro7ZQd5denht21NtdTTo
squads_program=SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf
token_program=TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
ata_program=ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
squads_config=BSTq9w3kZwNwpBXJEvTZz2G9ZTNyKBvoSeXMvwb4cNZr

rehearsal_tmp="$(mktemp -d)"
validator_pid=""
fake_rpc_pid=""
devnet_rpc_pid=""
cleanup() {
    local status=$?
    if [[ -n "$devnet_rpc_pid" ]]; then kill "$devnet_rpc_pid" 2>/dev/null || true; fi
    if [[ -n "$fake_rpc_pid" ]]; then kill "$fake_rpc_pid" 2>/dev/null || true; fi
    if [[ -n "$validator_pid" ]]; then kill "$validator_pid" 2>/dev/null || true; fi
    if [[ $status -ne 0 ]]; then
        echo "rehearsal failed (status=$status)" >&2
        if [[ -f "$rehearsal_tmp/validator.log" ]]; then
            tail -n 200 "$rehearsal_tmp/validator.log" >&2
        fi
        for result in "$rehearsal_tmp"/results/*.json; do
            if [[ -f "$result" ]]; then
                echo "result: $(basename "$result")" >&2
                sed -n '1,80p' "$result" >&2
            fi
        done
    fi
    rm -rf -- "$rehearsal_tmp"
    return "$status"
}
trap cleanup EXIT

export HOME="$rehearsal_tmp/home"
export CARGO_HOME=/home/prithvi/.cargo
export RUSTUP_HOME=/home/prithvi/.rustup
mkdir -p "$HOME" "$rehearsal_tmp/cache" "$rehearsal_tmp/results"

new_key() {
    "$solana_keygen" -C "$rehearsal_tmp/solana.yml" new --silent --no-bip39-passphrase --outfile "$1"
}
pubkey_of() {
    "$solana_keygen" -C "$rehearsal_tmp/solana.yml" pubkey "$1"
}
expect_failure() {
    local name="$1"
    shift
    if "$@" >"$rehearsal_tmp/results/$name.json" 2>&1; then
        echo "expected failure: $name" >&2
        return 1
    fi
}
expect_failure_contains() {
    local name="$1"
    local needle="$2"
    shift 2
    expect_failure "$name" "$@"
    python3 - "$rehearsal_tmp/results/$name.json" "$needle" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
assert value.get("ok") is False and sys.argv[2] in value.get("error", ""), value
PY
}
expect_failure_output_contains() {
    local name="$1"
    local needle="$2"
    shift 2
    expect_failure "$name" "$@"
    if ! grep -Fq -- "$needle" "$rehearsal_tmp/results/$name.json"; then
        echo "failure for $name did not contain the required error: $needle" >&2
        return 1
    fi
}
run_step() {
    local name="$1"
    shift
    "$@" >"$rehearsal_tmp/results/$name.json"
    python3 - "$rehearsal_tmp/results/$name.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
if value.get("ok") is not True:
    raise SystemExit(f"step failed: {value}")
PY
}

new_key "$rehearsal_tmp/payer.json"
new_key "$rehearsal_tmp/member1.json"
new_key "$rehearsal_tmp/member2.json"
new_key "$rehearsal_tmp/member3.json"
new_key "$rehearsal_tmp/mint.json"
new_key "$rehearsal_tmp/upgrade-buffer.json"
payer_pub="$(pubkey_of "$rehearsal_tmp/payer.json")"
member1_pub="$(pubkey_of "$rehearsal_tmp/member1.json")"
member2_pub="$(pubkey_of "$rehearsal_tmp/member2.json")"
member3_pub="$(pubkey_of "$rehearsal_tmp/member3.json")"
mint_pub="$(pubkey_of "$rehearsal_tmp/mint.json")"

# Cache exact devnet binaries and the real Squads program-config account only in
# this throwaway directory.  No faucet is contacted.
"$solana" --url devnet program dump "$squads_program" "$rehearsal_tmp/cache/squads-v4.so" >/dev/null
"$solana" --url devnet program dump "$token_program" "$rehearsal_tmp/cache/spl-token.so" >/dev/null
"$solana" --url devnet program dump "$ata_program" "$rehearsal_tmp/cache/spl-associated-token.so" >/dev/null
"$solana" --url devnet --output json account "$squads_config" >"$rehearsal_tmp/cache/squads-program-config.json"

rpc=http://127.0.0.1:18899
"$validator" \
    --ledger "$rehearsal_tmp/ledger" --reset --quiet \
    --bind-address 127.0.0.1 --rpc-port 18899 --dynamic-port-range 19000-19999 \
    --url devnet --clone-feature-set \
    --mint "$payer_pub" \
    --upgradeable-program "$squads_program" "$rehearsal_tmp/cache/squads-v4.so" none \
    --clone-upgradeable-program "$token_program" \
    --clone "$ata_program" \
    --account "$squads_config" "$rehearsal_tmp/cache/squads-program-config.json" \
    >"$rehearsal_tmp/validator.log" 2>&1 &
validator_pid=$!
for _ in $(seq 1 60); do
    if "$solana" --url "$rpc" cluster-version >/dev/null 2>&1; then break; fi
    if ! kill -0 "$validator_pid" 2>/dev/null; then
        echo "validator exited during startup" >&2
        sed -n '1,160p' "$rehearsal_tmp/validator.log" >&2
        exit 1
    fi
    sleep 1
done
"$solana" --url "$rpc" cluster-version >/dev/null
"$solana" --url "$rpc" --keypair "$rehearsal_tmp/payer.json" --output json program show "$token_program" >"$rehearsal_tmp/results/token-program.json" 2>&1 || true
"$solana" --url "$rpc" --keypair "$rehearsal_tmp/payer.json" --output json program show "$squads_program" >"$rehearsal_tmp/results/squads-program.json" 2>&1 || true
for member_pub in "$member1_pub" "$member2_pub" "$member3_pub"; do
    "$solana" --url "$rpc" --keypair "$rehearsal_tmp/payer.json" --output json \
        transfer "$member_pub" 5 --allow-unfunded-recipient --fee-payer "$rehearsal_tmp/payer.json" \
        >/dev/null
done

"$spl_token" --url "$rpc" --output json --fee-payer "$rehearsal_tmp/payer.json" \
    create-token --decimals 6 --mint-authority "$payer_pub" "$rehearsal_tmp/mint.json" \
    >"$rehearsal_tmp/results/create-mint.json"

so_path="${NAK_PAY_SO:-$workspace_dir/target/deploy/nakshatra_pay.so}"
if [[ ! -f "$so_path" ]]; then
    (cd "$workspace_dir" && anchor build --arch v0 --tools-version v1.57)
fi
so_sha="$(sha256sum "$so_path" | awk '{print $1}')"
common=(python3 "$deploy_tool" --url "$rpc" --rehearsal --state-dir "$rehearsal_tmp/state")

run_step build-check "${common[@]}" build-check --so "$so_path" --expect-sha256 "$so_sha"
run_step deploy "${common[@]}" deploy --so "$so_path" --program-keypair "$program_keypair" --payer "$rehearsal_tmp/payer.json"
run_step config-init "${common[@]}" config-init --fee-bps 300 --payer "$rehearsal_tmp/payer.json" --mint "$mint_pub"
run_step multisig-create "${common[@]}" multisig-create \
    --member "$member1_pub" --member "$member2_pub" --member "$member3_pub" \
    --threshold 2 --time-lock 5 --payer "$rehearsal_tmp/payer.json"
run_step handover "${common[@]}" handover --payer "$rehearsal_tmp/payer.json"
run_step accept-propose "${common[@]}" accept-config-authority propose --member-key "$rehearsal_tmp/member1.json"
multisig_pub="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["multisig"])' "$rehearsal_tmp/results/multisig-create.json")"
accept_index="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["transaction_index"])' "$rehearsal_tmp/results/accept-propose.json")"
run_step accept-approve-1 "${common[@]}" accept-config-authority approve \
    --multisig "$multisig_pub" --transaction-index "$accept_index" --member-key "$rehearsal_tmp/member1.json"
member2_common=(python3 "$deploy_tool" --url "$rpc" --rehearsal --state-dir "$rehearsal_tmp/member2-state")
run_step accept-approve-2 "${member2_common[@]}" accept-config-authority approve \
    --multisig "$multisig_pub" --transaction-index "$accept_index" --member-key "$rehearsal_tmp/member2.json"
executor_common=(python3 "$deploy_tool" --url "$rpc" --rehearsal --state-dir "$rehearsal_tmp/executor-state")
expect_failure_contains execute-early time-lock "${executor_common[@]}" accept-config-authority execute \
    --multisig "$multisig_pub" --transaction-index "$accept_index" --member-key "$rehearsal_tmp/member3.json"
sleep 6
run_step accept-execute "${executor_common[@]}" accept-config-authority execute \
    --multisig "$multisig_pub" --transaction-index "$accept_index" --member-key "$rehearsal_tmp/member3.json"
run_step verify "${common[@]}" verify

# Every subcommand is safe to rerun after the completed handover.
run_step idempotent-build-check "${common[@]}" build-check --so "$so_path" --expect-sha256 "$so_sha"
run_step idempotent-deploy "${common[@]}" deploy --so "$so_path" --program-keypair "$program_keypair" --payer "$rehearsal_tmp/payer.json"
run_step idempotent-config-init "${common[@]}" config-init --fee-bps 300 --payer "$rehearsal_tmp/payer.json" --mint "$mint_pub"
run_step idempotent-multisig-create "${common[@]}" multisig-create \
    --member "$member1_pub" --member "$member2_pub" --member "$member3_pub" \
    --threshold 2 --time-lock 5 --payer "$rehearsal_tmp/payer.json"
run_step idempotent-handover "${common[@]}" handover --payer "$rehearsal_tmp/payer.json"
run_step idempotent-propose "${common[@]}" accept-config-authority propose --member-key "$rehearsal_tmp/member1.json"
run_step idempotent-approve "${common[@]}" accept-config-authority approve --member-key "$rehearsal_tmp/member1.json"
run_step idempotent-execute "${common[@]}" accept-config-authority execute --member-key "$rehearsal_tmp/member1.json"
run_step idempotent-verify "${common[@]}" verify

# Required negative cases.
expect_failure_contains wrong-hash "sha256 mismatch" python3 "$deploy_tool" --state-dir "$rehearsal_tmp/wrong-hash" \
    build-check --so "$so_path" --expect-sha256 "$(printf '0%.0s' {1..64})"
expect_failure_contains threshold-1 threshold "${common[@]}" multisig-create \
    --member "$member1_pub" --member "$member2_pub" --member "$member3_pub" \
    --threshold 1 --time-lock 5 --payer "$rehearsal_tmp/payer.json"
expect_failure_contains duplicate-members distinct "${common[@]}" multisig-create \
    --member "$member1_pub" --member "$member1_pub" --member "$member3_pub" \
    --threshold 2 --time-lock 5 --payer "$rehearsal_tmp/payer.json"
python3 "$workspace_dir/tests/fake_genesis_rpc.py" --port 18897 --genesis EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG \
    >"$rehearsal_tmp/fake-devnet-rpc.log" 2>&1 &
devnet_rpc_pid=$!
sleep 1
expect_failure_contains production-short-lock time-lock python3 "$deploy_tool" --url http://127.0.0.1:18897 --state-dir "$rehearsal_tmp/state" multisig-create \
    --member "$member1_pub" --member "$member2_pub" --member "$member3_pub" \
    --threshold 2 --time-lock 6 --payer "$rehearsal_tmp/payer.json"

python3 "$workspace_dir/tests/fake_genesis_rpc.py" --port 18898 >"$rehearsal_tmp/fake-rpc.log" 2>&1 &
fake_rpc_pid=$!
sleep 1
expect_failure_contains wrong-genesis "not devnet" python3 "$deploy_tool" --url http://127.0.0.1:18898 --state-dir "$rehearsal_tmp/state" \
    deploy --so "$so_path" --program-keypair "$program_keypair" --payer "$rehearsal_tmp/payer.json"

expect_failure_output_contains deployer-upgrade "does not match authority provided" "$solana" --url "$rpc" --keypair "$rehearsal_tmp/payer.json" --output json program deploy "$so_path" \
    --program-id "$program_id" --upgrade-authority "$rehearsal_tmp/payer.json" \
    --fee-payer "$rehearsal_tmp/payer.json" --buffer "$rehearsal_tmp/upgrade-buffer.json" \
    --max-len "$(stat -c %s "$so_path")" \
    --max-sign-attempts 1 --use-rpc

python3 - "$rehearsal_tmp/results/verify.json" "$so_sha" <<'PY'
import json, sys
verify = json.load(open(sys.argv[1]))
summary = {
    "ok": True,
    "rehearsal": "PASS",
    "flow_steps": 11,
    "idempotency_checks": 9,
    "negative_tests": 7,
    "total_assertions": 27,
    "program": verify["program"]["program"],
    "program_data": verify["program"]["program_data"],
    "code_sha256": sys.argv[2],
    "multisig": verify["multisig"]["address"],
    "vault": verify["multisig"]["vault"],
}
print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
PY
