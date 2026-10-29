"""The two-minute Leash demo: a scripted grocery agent hits every control.

    python -m demo.run_demo                      # self-contained, in-process
    python -m demo.run_demo --url http://127.0.0.1:8000 --admin-key KEY [--db leash.db]

Everything here is MOCK: no real payment system is contacted. The agent is a
scripted stand-in (no LLM); it only ever holds a narrow, expiring token.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from leash.policy_file import load_policy
from leash.sdk import LeashClient

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "policies" / "grocery_agent.yaml"


def rs(paise: int) -> str:
    return f"Rs {paise / 100:,.2f}"


def run(
    http: httpx.Client,
    admin_key: str,
    db_path: Optional[str],
    out: Callable[[str], None] = print,
    expiry_s: int = 2,
    sleep: Callable[[float], None] = time.sleep,
) -> List[Dict[str, Any]]:
    admin = {"X-Admin-Key": admin_key}
    results: List[Dict[str, Any]] = []

    def create(ttl_s: Optional[int] = None) -> Dict[str, Any]:
        body = load_policy(POLICY)
        if ttl_s is not None:
            body["ttl_s"] = ttl_s
        r = http.post("/grants", json=body, headers=admin)
        r.raise_for_status()
        return r.json()

    def attempt(step: str, label: str, client: LeashClient, payee: str, amount: Any, expect_ok: bool) -> None:
        res = client.pay(payee, amount)
        shown = rs(amount) if isinstance(amount, int) and not isinstance(amount, bool) else repr(amount)
        verdict = "ALLOWED" if res["ok"] else f"BLOCKED ({res['reason']})"
        mark = "ok " if res["ok"] == expect_ok else "!! "
        out(f"  {mark}[{verdict}] {payee} {shown}" + (f"  -> {res['txn_id']}" if res["ok"] else ""))
        results.append({"step": step, "label": label, "expected_ok": expect_ok, **res})

    out("Leash demo (MOCK payments: no real money moves)\n")
    main_grant = create()
    agent = LeashClient(main_grant["token"], http=http)
    g = main_grant["grant"]
    out(f"Human grants 'grocery-agent' a token: max {rs(g['per_txn_cap_paise'])} per payment, "
        f"{rs(g['total_cap_paise'])} total, {len(g['payees'])} payees, expires in 30 min.\n")

    out("1. The agent buys groceries within its limits")
    attempt("1", "within limits", agent, "bigbasket@okaxis", 45_000, True)
    attempt("1", "within limits", agent, "Blinkit@okhdfcbank", 89_950, True)

    out("2. It tries to pay a merchant that is not on the list")
    attempt("2", "unlisted merchant", agent, "totally-legit-shop@okaxis", 10_000, False)

    out("3. It tries an amount over its per-payment cap")
    attempt("3", "over cap", agent, "bigbasket@okaxis", 200_000, False)

    out(f"4. It reuses an expired token (second grant with a {expiry_s}s lifetime)")
    short = create(ttl_s=expiry_s)
    short_agent = LeashClient(short["token"], http=http)
    attempt("4", "before expiry", short_agent, "zepto@okicici", 5_000, True)
    sleep(expiry_s + 0.3)
    attempt("4", "expired token", short_agent, "zepto@okicici", 5_000, False)

    out("5. Someone edits a row in the audit log by hand")
    if db_path:
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT seq FROM audit WHERE event='payment_decision' AND data LIKE '%PAYEE_NOT_ALLOWED%' "
            "ORDER BY seq LIMIT 1"
        ).fetchone()
        before = http.get("/audit/verify").json()
        conn.execute("UPDATE audit SET data = replace(data, '\"allowed\":false', '\"allowed\":true') WHERE seq = ?", (row[0],))
        conn.commit()
        conn.close()
        after = http.get("/audit/verify").json()
        out(f"  verify before edit: ok={before['ok']}")
        out(f"  edited entry #{row[0]} (flipped a BLOCKED decision to ALLOWED)")
        out(f"  verify after edit:  ok={after['ok']}, bad entry = #{after['bad_seq']}  ({after['reason']})")
        results.append({"step": "5", "label": "tamper", "tampered_seq": row[0], "before_ok": before["ok"],
                        "after_ok": after["ok"], "flagged_seq": after["bad_seq"]})
    else:
        out("  skipped: pass --db with the gateway's database path to tamper with it")

    out("6. The grant is revoked mid-run")
    attempt("6", "before revoke", agent, "zepto@okicici", 10_000, True)
    http.post(f"/grants/{g['id']}/revoke", headers=admin).raise_for_status()
    out("  human clicks Revoke")
    attempt("6", "after revoke", agent, "zepto@okicici", 10_000, False)

    mism = [r for r in results if "expected_ok" in r and r["ok"] != r["expected_ok"]]
    out("\nAll steps behaved as expected." if not mism else f"\nUNEXPECTED RESULTS: {mism}")
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", help="use a running gateway instead of an in-process one")
    ap.add_argument("--admin-key", default="demo-admin-key")
    ap.add_argument("--db", help="gateway database path (needed for the tamper step)")
    args = ap.parse_args()

    if args.url:
        http = httpx.Client(base_url=args.url, timeout=10)
        results = run(http, args.admin_key, args.db)
    else:
        from fastapi.testclient import TestClient

        from leash.gateway import create_app

        db = Path("demo_leash.db")
        for suffix in ("", "-wal", "-shm"):
            Path(str(db) + suffix).unlink(missing_ok=True)
        app = create_app(db, secret="demo-secret-demo-secret-0000", admin_key=args.admin_key)
        results = run(TestClient(app), args.admin_key, str(db))
    bad = [r for r in results if "expected_ok" in r and r["ok"] != r["expected_ok"]]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
