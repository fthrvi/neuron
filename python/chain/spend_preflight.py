#!/usr/bin/env python3
"""Read-only preflight for legacy spend-hold namespace collisions."""
from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


SPEND_HOLD_STEM = "__spend_hold__"


class SpendPreflightError(RuntimeError):
    """The target could not be checked safely as an existing ledger."""


@dataclass(frozen=True)
class SpendNamespaceCollision:
    account: str
    balance: int


def find_spend_namespace_collisions(
    database: str | Path,
) -> tuple[SpendNamespaceCollision, ...]:
    """Return unbacked reserved spend accounts without modifying the database."""
    path = Path(database).expanduser().resolve(strict=True)
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro",
        uri=True,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            )
        }
        if "accounts" not in tables:
            raise SpendPreflightError("database has no accounts table")
        if "spend_holds" in tables:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(spend_holds)")
            }
        else:
            columns = set()
        if "escrow_account" in columns:
            rows = connection.execute(
                "SELECT a.id, a.balance FROM accounts AS a "
                "LEFT JOIN spend_holds AS h ON h.escrow_account=a.id "
                "WHERE substr(a.id, 1, ?)=? AND h.hold_id IS NULL "
                "ORDER BY a.id",
                (len(SPEND_HOLD_STEM), SPEND_HOLD_STEM),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT id, balance FROM accounts "
                "WHERE substr(id, 1, ?)=? ORDER BY id",
                (len(SPEND_HOLD_STEM), SPEND_HOLD_STEM),
            ).fetchall()
        connection.execute("COMMIT")
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return tuple(
        SpendNamespaceCollision(account=str(row["id"]), balance=int(row["balance"]))
        for row in rows
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "report unbacked __spend_hold__ reserved-account collisions "
            "without opening the ledger for writes or migrations"
        )
    )
    parser.add_argument("database", help="path to an existing SQLite ledger")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        path = Path(args.database).expanduser().resolve(strict=True)
        collisions = find_spend_namespace_collisions(path)
    except (OSError, sqlite3.Error, SpendPreflightError) as exc:
        print(f"ERROR: {exc}")
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "database": str(path),
                    "status": "collision" if collisions else "clear",
                    "collision_count": len(collisions),
                    "collisions": [asdict(collision) for collision in collisions],
                },
                sort_keys=True,
            )
        )
    elif collisions:
        print(f"COLLISION: {len(collisions)} reserved account(s) in {path}")
        for collision in collisions:
            print(f"{collision.account}\tbalance={collision.balance}")
    else:
        print(f"CLEAR: no reserved spend-account collisions in {path}")
    return 1 if collisions else 0


if __name__ == "__main__":
    raise SystemExit(main())
