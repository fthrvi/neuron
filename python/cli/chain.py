"""
Query the Neuron Network checkpoint chain.

Usage:
  python3 cli/chain.py                     # show recent checkpoints
  python3 cli/chain.py --verify            # verify the full hash-chain
  python3 cli/chain.py --checkpoint ID     # show specific checkpoint details
  python3 cli/chain.py --latest            # show latest checkpoint
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.checkpoint import CheckpointChain, CHECKPOINT_DIR


def fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def main():
    parser = argparse.ArgumentParser(description="Query Neuron Network checkpoint chain")
    parser.add_argument("--verify", action="store_true", help="Verify the full hash-chain")
    parser.add_argument("--checkpoint", type=int, help="Show specific checkpoint by ID")
    parser.add_argument("--latest", action="store_true", help="Show latest checkpoint")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--count", type=int, default=10, help="Number of checkpoints to show")
    args = parser.parse_args()

    if not CHECKPOINT_DIR.exists() or not list(CHECKPOINT_DIR.glob("*.json")):
        print("No checkpoints found. Start a node first.")
        sys.exit(1)

    chain = CheckpointChain(node_id="cli-readonly")

    if args.verify:
        valid = chain.verify_chain()
        if args.json:
            print(json.dumps({"valid": valid, "height": chain.height}))
        else:
            print()
            if valid:
                print(f"  Chain VALID — {chain.height} checkpoints, all hashes verified.")
            else:
                print(f"  Chain BROKEN — hash-chain verification failed!")
            print()
        sys.exit(0 if valid else 1)

    if args.checkpoint is not None:
        cp = chain.get_checkpoint(args.checkpoint)
        if not cp:
            print(f"Checkpoint #{args.checkpoint} not found.")
            sys.exit(1)
        if args.json:
            print(json.dumps(cp.to_dict(), indent=2))
        else:
            print()
            print("=" * 60)
            print(f"  Checkpoint #{cp.checkpoint_id}")
            print("=" * 60)
            print(f"  Hash:     {cp.hash}")
            print(f"  Prev:     {cp.prev_hash}")
            print(f"  Time:     {fmt_time(cp.timestamp)}")
            print(f"  Valid:    {cp.is_valid} ({cp.signature_ratio} signed)")
            print(f"  Events:   {len(cp.event_hashes)}")
            ns = cp.network_state
            print(f"  Nodes:    {ns.get('total_nodes', '?')}")
            print(f"  VRAM:     {ns.get('total_vram_gb', '?')} GB")
            if cp.credit_balances:
                print(f"  Credits:")
                for nid, bal in sorted(cp.credit_balances.items()):
                    print(f"    {nid[:14]}..  {bal:.4f}")
            print("=" * 60)
            print()
        return

    if args.latest:
        cp = chain.latest
        if not cp:
            print("No checkpoints yet.")
            sys.exit(1)
        if args.json:
            print(json.dumps(cp.to_dict(), indent=2))
        else:
            print(f"\n  Latest: #{cp.checkpoint_id} | {cp.hash[:16]}... | {fmt_time(cp.timestamp)}\n")
        return

    # List recent checkpoints
    history = chain.history(args.count)
    if args.json:
        print(json.dumps(history, indent=2))
        return

    print()
    print(f"  Checkpoint Chain (height: {chain.height})")
    print("  " + "-" * 72)
    print(f"  {'#':>5}  {'HASH':>18}  {'PREV':>18}  {'TIME':>20}  {'SIG':>6}  {'EVT':>4}")
    print("  " + "-" * 72)

    for h in history:
        t = fmt_time(h["time"])
        valid = "ok" if h["valid"] else "!!"
        print(
            f"  {h['id']:>5}  {h['hash']:>18}  {h['prev']:>18}  "
            f"{t:>20}  {h['signed']:>6}  {h['events']:>4}"
        )

    print("  " + "-" * 72)
    if chain.chain:
        print(f"  Genesis: {chain.chain[0].hash[:32]}...")
        print(f"  Latest:  {chain.latest.hash[:32]}...")
    print()


if __name__ == "__main__":
    main()
