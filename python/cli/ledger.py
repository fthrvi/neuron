"""
Query the Neuron Network credit ledger.

Usage:
  python3 cli/ledger.py                     # show all balances
  python3 cli/ledger.py --node NODE_ID      # specific node balance
  python3 cli/ledger.py --economy           # network economy stats
  python3 cli/ledger.py --history           # recent transactions
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.ledger import CreditLedger, LEDGER_FILE


def main():
    parser = argparse.ArgumentParser(description="Query Neuron Network credit ledger")
    parser.add_argument("--node", type=str, help="Show balance for a specific node ID (prefix match)")
    parser.add_argument("--economy", action="store_true", help="Show network economy stats")
    parser.add_argument("--history", action="store_true", help="Show recent transactions")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if not LEDGER_FILE.exists():
        print("No ledger found. Start a node first.")
        sys.exit(1)

    ledger = CreditLedger()

    if args.economy:
        econ = ledger.network_economy()
        if args.json:
            print(json.dumps(econ, indent=2))
        else:
            print()
            print("=" * 50)
            print("  NEURON NETWORK — Credit Economy")
            print("=" * 50)
            print(f"  Total supply:     {econ['total_supply']:.4f}")
            print(f"  Total earned:     {econ['total_earned']:.4f}")
            print(f"  Total spent:      {econ['total_spent']:.4f}")
            print(f"  Total frozen:     {econ['total_frozen']:.4f}")
            print(f"  Nodes w/balance:  {econ['nodes_with_balance']}")
            print(f"  Transactions:     {econ['transactions']}")
            print("=" * 50)
            print()
        return

    if args.history:
        txs = ledger.recent_transactions(20)
        if args.json:
            print(json.dumps(txs, indent=2))
        else:
            print()
            print(f"  Recent Transactions ({len(txs)})")
            print("  " + "-" * 70)
            for tx in txs:
                fr = tx["from_node"][:10] + ".." if tx["from_node"] else "MINTED"
                to = tx["to_node"][:10] + ".."
                print(
                    f"  {tx['tx_id']:>10}  {fr:>14} → {to:<14}  "
                    f"{tx['amount']:>10.4f}  {tx['reason']}"
                )
            print("  " + "-" * 70)
            print()
        return

    if args.node:
        matches = [
            nid for nid in ledger.balances
            if nid.startswith(args.node)
        ]
        if not matches:
            print(f"No node found matching '{args.node}'")
            sys.exit(1)
        for nid in matches:
            s = ledger.node_summary(nid)
            if args.json:
                print(json.dumps(s, indent=2))
            else:
                print()
                print(f"  Node: {nid}")
                print(f"  Balance:       {s['balance']:.4f}")
                print(f"  Available:     {s['available']:.4f}")
                print(f"  Frozen:        {s['frozen']:.4f}")
                print(f"  Total earned:  {s['total_earned']:.4f}")
                print(f"  Total spent:   {s['total_spent']:.4f}")
                print(f"  Compute score: {s['compute_score']}")
                print()
        return

    # List all balances
    if args.json:
        print(json.dumps(ledger.all_balances(), indent=2))
        return

    print()
    print(f"  Credit Balances ({len(ledger.balances)} nodes)")
    print("  " + "-" * 55)
    print(f"  {'NODE':>14}  {'BALANCE':>10}  {'EARNED':>10}  {'SPENT':>10}  {'SCORE':>6}")
    print("  " + "-" * 55)
    for nid, bal in sorted(ledger.balances.items(), key=lambda x: x[1].balance, reverse=True):
        print(
            f"  {nid[:12] + '..':>14}  {bal.balance:>10.4f}  "
            f"{bal.total_earned:>10.4f}  {bal.total_spent:>10.4f}  "
            f"{bal.compute_score:>6.1f}"
        )
    print("  " + "-" * 55)
    print()


if __name__ == "__main__":
    main()
