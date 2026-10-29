"""Edit one audit row by hand, for the live demo.

    python -m demo.tamper --db leash.db --seq 3

Flips a BLOCKED decision to ALLOWED in the raw database, bypassing the gateway.
Then press "Verify audit log" on the dashboard (or GET /audit/verify): it flags
exactly that entry. Only run this against your own demo database.
"""

import argparse
import sqlite3


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--seq", type=int, required=True, help="audit entry number to edit")
    args = ap.parse_args()
    conn = sqlite3.connect(args.db)
    cur = conn.execute(
        "UPDATE audit SET data = replace(data, '\"allowed\":false', '\"allowed\":true') WHERE seq = ?",
        (args.seq,),
    )
    conn.commit()
    print(f"edited entry #{args.seq}" if cur.rowcount else f"no entry #{args.seq}")


if __name__ == "__main__":
    main()
