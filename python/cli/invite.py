"""
Manage Neuron Network invite codes.

Usage:
  python3 cli/invite.py create                    # create a new invite
  python3 cli/invite.py create --expiry 48        # expires in 48 hours
  python3 cli/invite.py list                      # list active invites
  python3 cli/invite.py list --all                # include used invites
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.invite import InviteManager, INVITES_FILE
from core.identity import get_or_create_identity


def main():
    parser = argparse.ArgumentParser(description="Manage Neuron Network invites")
    sub = parser.add_subparsers(dest="command")

    create_p = sub.add_parser("create", help="Create a new invite")
    create_p.add_argument("--expiry", type=float, default=24, help="Expiry in hours (default: 24)")
    create_p.add_argument("--host", type=str, default="", help="Override host IP")
    create_p.add_argument("--port", type=int, default=9900, help="Override port")

    list_p = sub.add_parser("list", help="List invites")
    list_p.add_argument("--all", action="store_true", help="Include used invites")
    list_p.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    identity = get_or_create_identity()
    mgr = InviteManager(
        node_id=identity.node_id,
        sign_fn=identity.sign,
    )

    if args.command == "create":
        inv = mgr.create_invite(expiry_s=args.expiry * 3600)

        # Auto-detect host if not provided
        host = args.host
        if not host:
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                host = s.getsockname()[0]
                s.close()
            except Exception:
                host = "127.0.0.1"

        uri = inv.to_uri(host, args.port)
        print()
        print("  Share this invite with a friend:")
        print()
        print(f"  {uri}")
        print()
        print(f"  Expires in {args.expiry:.0f} hours. Single use.")
        print(f"  Active invites: {mgr.active_count()}")
        print()

    elif args.command == "list":
        invites = mgr.list_invites(include_used=args.all)
        if args.json:
            print(json.dumps(invites, indent=2))
            return

        if not invites:
            print("No invites." + (" Use 'create' to make one." if not args.all else ""))
            return

        print()
        print(f"  Invites ({len(invites)})")
        print("  " + "-" * 60)
        for inv in invites:
            status = "USED" if inv["used"] else ("VALID" if inv["valid"] else "EXPIRED")
            by = f" by {inv['used_by']}" if inv["used_by"] else ""
            print(f"  {inv['code']}  [{status}]  {inv['expires_in']}{by}")
        print("  " + "-" * 60)
        print()


if __name__ == "__main__":
    main()
