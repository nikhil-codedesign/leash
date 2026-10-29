"""Hash-chained audit log.

Each entry stores the hash of the previous entry, so editing, removing,
inserting or reordering any past entry breaks the chain and `verify` reports
the entry where it broke.

This is TAMPER-EVIDENT, not tamper-proof. Someone with full write access to
the database could rewrite the whole chain consistently, and could truncate
the tail. Anchoring the latest head (`head()`) somewhere external and passing
it back to `verify(anchor=...)` closes that gap; this repo does not do the
external anchoring for you.

All functions take an open sqlite3 connection so that callers can write an
audit entry in the same transaction as the decision it records.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64


def canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(
    seq: int, prev_hash: str, ts_us: int, event: str, grant_id: Optional[str], data_json: str
) -> str:
    # A JSON list is an unambiguous encoding, so no field can bleed into another.
    blob = json.dumps([seq, prev_hash, ts_us, event, grant_id, data_json], ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def append(
    conn: sqlite3.Connection,
    event: str,
    grant_id: Optional[str],
    data: Dict[str, Any],
    now: float,
) -> int:
    """Append an entry. The caller must hold the write lock (BEGIN IMMEDIATE)."""
    last = conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    seq = 1 if last is None else last["seq"] + 1
    prev = GENESIS if last is None else last["hash"]
    ts_us = int(now * 1_000_000)
    data_json = canonical(data)
    digest = compute_hash(seq, prev, ts_us, event, grant_id, data_json)
    conn.execute(
        "INSERT INTO audit(seq, ts_us, event, grant_id, data, prev_hash, hash) "
        "VALUES (?,?,?,?,?,?,?)",
        (seq, ts_us, event, grant_id, data_json, prev, digest),
    )
    return seq


def read(
    conn: sqlite3.Connection, limit: int = 100, after_seq: int = 0
) -> List[Dict[str, Any]]:
    """Return up to `limit` entries with seq > after_seq, oldest first.

    With after_seq=0 this returns the most recent `limit` entries.
    """
    limit = max(1, min(int(limit), 1000))
    if after_seq > 0:
        rows = conn.execute(
            "SELECT * FROM audit WHERE seq > ? ORDER BY seq ASC LIMIT ?", (after_seq, limit)
        ).fetchall()
    else:
        rows = list(
            reversed(conn.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)).fetchall())
        )
    return [_row(r) for r in rows]


def _row(r: sqlite3.Row) -> Dict[str, Any]:
    try:
        data = json.loads(r["data"])
    except Exception:
        data = {"_unparseable": True}
    return {
        "seq": r["seq"],
        "ts": r["ts_us"] / 1_000_000,
        "event": r["event"],
        "grant_id": r["grant_id"],
        "data": data,
        "prev_hash": r["prev_hash"],
        "hash": r["hash"],
    }


def head(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    last = conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    return None if last is None else {"seq": last["seq"], "hash": last["hash"]}


def verify(conn: sqlite3.Connection, anchor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Walk the whole chain. Returns a dict with ok, entries, bad_seq, reason, head.

    `anchor` is an earlier `head()` value kept somewhere the database owner
    cannot rewrite. If given, the entry at anchor["seq"] must still exist with
    the same hash, which also catches truncation and wholesale rewrites.
    """
    expected_seq = 1
    prev = GENESIS
    count = 0
    anchored_hash: Optional[str] = None
    last_hash: Optional[str] = None

    def fail(bad_seq: int, reason: str) -> Dict[str, Any]:
        return {"ok": False, "entries": count, "bad_seq": bad_seq, "reason": reason, "head": None}

    for r in conn.execute("SELECT * FROM audit ORDER BY seq ASC"):
        if r["seq"] != expected_seq:
            return fail(expected_seq, f"entry {expected_seq} is missing from the log")
        recomputed = compute_hash(
            r["seq"], r["prev_hash"], r["ts_us"], r["event"], r["grant_id"], r["data"]
        )
        if recomputed != r["hash"]:
            return fail(r["seq"], "entry contents do not match their stored hash (edited)")
        if r["prev_hash"] != prev:
            if r["seq"] == 1:
                return fail(1, "first entry does not start from the genesis hash")
            return fail(
                r["seq"] - 1,
                f"entry {r['seq'] - 1} was rewritten: its hash no longer matches "
                f"the link stored in entry {r['seq']}",
            )
        if anchor is not None and r["seq"] == anchor.get("seq"):
            anchored_hash = r["hash"]
        prev = r["hash"]
        last_hash = r["hash"]
        expected_seq += 1
        count += 1

    if anchor is not None:
        if anchored_hash is None:
            return fail(int(anchor.get("seq", 0)), "anchored entry is missing (log truncated)")
        if anchored_hash != anchor.get("hash"):
            return fail(int(anchor["seq"]), "anchored entry does not match the anchor (log rewritten)")

    return {
        "ok": True,
        "entries": count,
        "bad_seq": None,
        "reason": None,
        "head": None if last_hash is None else {"seq": count, "hash": last_hash},
    }
