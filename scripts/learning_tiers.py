#!/usr/bin/env python3
"""Learning loop operator CLI (learning-loop design 2026-10-27, P0 and P1).

    uv run python scripts/learning_tiers.py backfill   [--dsn DSN]
    uv run python scripts/learning_tiers.py stats      [--dsn DSN]
    uv run python scripts/learning_tiers.py recompute  --version 2026.11.03-1 [--previous V] [--diff PATH] [--dsn DSN]
    uv run python scripts/learning_tiers.py import-judge --file verdicts.json [--dsn DSN]
    uv run python scripts/learning_tiers.py activate   --version V --actor NAME [--dsn DSN]
    uv run python scripts/learning_tiers.py rollback   --actor NAME [--version V] [--dsn DSN]

`recompute` writes a new immutable `contract/learning/rule_tiers/<version>.yaml` and a markdown
diff for the pull request; it never changes what production shows. `activate` and `rollback`
set the `learning.rule_tiers` flag (logged in admin_audit) and take effect on the next
review_leads call. The DSN defaults to SOKEN_DATABASE_URL and is never taken from argv in a
service unit.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import psycopg

from soken_review.learning import generate, ledger


async def _main(args: argparse.Namespace) -> int:
    async with await psycopg.AsyncConnection.connect(args.dsn, autocommit=True) as conn:
        if args.cmd == "backfill":
            print(json.dumps(await ledger.backfill(conn)))
        elif args.cmd == "stats":
            for row in await generate.rule_stats(conn):
                print(json.dumps(row, default=str))
        elif args.cmd == "recompute":
            out = await generate.recompute(conn, args.version, args.previous,
                                           diff_path=Path(args.diff) if args.diff else None)
            print(out["diff"] if not args.diff else json.dumps({k: v for k, v in out.items() if k != "diff"}))
        elif args.cmd == "import-judge":
            rows = json.loads(Path(args.file).read_text(encoding="utf-8"))
            print(json.dumps({"imported": await generate.import_judge(conn, rows)}))
        elif args.cmd == "activate":
            await generate.activate(conn, args.version, args.actor)
            print(json.dumps({"active": args.version}))
        elif args.cmd == "rollback":
            await generate.rollback(conn, args.actor, args.version)
            print(json.dumps({"active": args.version or "baseline"}))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dsn", default=os.environ.get("SOKEN_DATABASE_URL", ""))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backfill")
    sub.add_parser("stats")
    p = sub.add_parser("recompute")
    p.add_argument("--version", required=True)
    p.add_argument("--previous", default=None)
    p.add_argument("--diff", default=None)
    p = sub.add_parser("import-judge")
    p.add_argument("--file", required=True)
    p = sub.add_parser("activate")
    p.add_argument("--version", required=True)
    p.add_argument("--actor", required=True)
    p = sub.add_parser("rollback")
    p.add_argument("--actor", required=True)
    p.add_argument("--version", default=None)
    args = ap.parse_args(argv)
    if not args.dsn:
        ap.error("--dsn or SOKEN_DATABASE_URL required")
    return asyncio.run(_main(args))


if __name__ == "__main__":
    sys.exit(main())
