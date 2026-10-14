"""One-shot, offline migration from a v1 JSON ledger to the v2 SQLite store."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from core.ledger_store import LedgerStore, import_legacy_snapshot


def _snapshot(path: Path) -> dict[str, Any]:
    decoded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("legacy ledger must contain a JSON object")
    return decoded


def _expected(snapshot: dict[str, Any]) -> tuple[dict[str, int], set[str]]:
    balances = snapshot.get("balances", {})
    settled = snapshot.get("settled", {})
    if not isinstance(balances, dict) or not isinstance(settled, dict):
        raise ValueError("legacy balances and settled fields must be objects")
    # The store importer performs the authoritative strict validation.  This
    # conversion is only for detecting an identical, already-migrated target.
    return dict(balances), set(settled)


def _matches_existing(
    target: Path, balances: dict[str, int], receipt_ids: set[str]
) -> bool:
    try:
        uri = f"file:{target.resolve()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            actual = {
                str(account): value
                for account, value in db.execute("SELECT id, balance FROM accounts")
            }
            receipts = {
                str(receipt_id)
                for (receipt_id,) in db.execute(
                    "SELECT receipt_id FROM receipts WHERE state='legacy_unsigned'"
                )
            }
            nonlegacy = db.execute(
                "SELECT 1 FROM receipts WHERE state!='legacy_unsigned' LIMIT 1"
            ).fetchone()
            unexpected_journal = db.execute(
                "SELECT 1 FROM journal WHERE kind!='legacy_import' LIMIT 1"
            ).fetchone()
            journal_count = db.execute("SELECT COUNT(*) FROM journal").fetchone()[0]
            nonce_count = db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0]
            return (
                actual == balances
                and receipts == receipt_ids
                and nonlegacy is None
                and unexpected_journal is None
                and journal_count == sum(value != 0 for value in balances.values())
                and nonce_count == 0
            )
    except (OSError, sqlite3.DatabaseError):
        return False


def _print_counts(balances: dict[str, int], receipt_ids: set[str], *, reused: bool) -> None:
    suffix = " (already migrated)" if reused else ""
    print(
        f"accounts={len(balances)} receipts={len(receipt_ids)} "
        f"balance_total={sum(balances.values())}{suffix}"
    )


def migrate(source: str | Path, target: str | Path, *, force: bool = False) -> None:
    source_path = Path(source)
    target_path = Path(target)
    snapshot = _snapshot(source_path)
    balances, receipt_ids = _expected(snapshot)

    if target_path.exists() and target_path.stat().st_size:
        if _matches_existing(target_path, balances, receipt_ids):
            _print_counts(balances, receipt_ids, reused=True)
            return
        if not force:
            raise FileExistsError(
                f"refusing to overwrite non-empty target {target_path}; pass --force"
            )

    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target_path.name}.", suffix=".tmp", dir=target_path.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with LedgerStore(temporary) as store:
            import_legacy_snapshot(snapshot, store)
            imported = {account: store.balance(account) for account in balances}
            assert imported == balances
            assert sum(imported.values()) == sum(balances.values())
        os.replace(temporary, target_path)
    finally:
        temporary.unlink(missing_ok=True)
        Path(f"{temporary}-wal").unlink(missing_ok=True)
        Path(f"{temporary}-shm").unlink(missing_ok=True)

    _print_counts(balances, receipt_ids, reused=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="source", required=True, help="v1 ledger JSON")
    parser.add_argument("--to", dest="target", required=True, help="v2 SQLite ledger")
    parser.add_argument("--force", action="store_true", help="replace a non-empty target")
    args = parser.parse_args()
    try:
        migrate(args.source, args.target, force=args.force)
    except (FileExistsError, OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
