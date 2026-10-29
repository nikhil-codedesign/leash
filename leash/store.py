"""SQLite storage: grants, an attempt ledger, and the audit log.

`decide_and_record` runs the policy check AND writes the attempt + audit entry
inside one `BEGIN IMMEDIATE` transaction. SQLite allows a single writer, so
concurrent requests are serialised and cannot jointly overspend a cap.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from . import audit
from .policy import (
    GRANT_NOT_FOUND,
    MAX_AMOUNT_PAISE,
    Decision,
    GrantPolicy,
    decide,
    normalize_payee,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS grants(
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    payees TEXT NOT NULL,
    per_txn_cap_paise INTEGER NOT NULL,
    total_cap_paise INTEGER NOT NULL,
    rate_limit INTEGER NOT NULL,
    rate_window_s INTEGER NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked_at REAL
);
CREATE TABLE IF NOT EXISTS attempts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id TEXT NOT NULL,
    ts REAL NOT NULL,
    payee TEXT,
    amount_paise INTEGER,
    allowed INTEGER NOT NULL,
    reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_grant_ts ON attempts(grant_id, ts);
CREATE TABLE IF NOT EXISTS audit(
    seq INTEGER PRIMARY KEY,
    ts_us INTEGER NOT NULL,
    event TEXT NOT NULL,
    grant_id TEXT,
    data TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""

MAX_TTL_S = 30 * 24 * 3600
MAX_RATE_LIMIT = 10_000
_LOG_TRUNC = 128


@dataclass(frozen=True)
class Outcome:
    decision: Decision
    audit_seq: int
    attempt_id: Optional[int]


def _pos_int(name: str, value: Any, maximum: int) -> int:
    if type(value) is not int or not (0 < value <= maximum):
        raise ValueError(f"{name} must be an integer between 1 and {maximum}")
    return value


def _loggable(value: Any) -> Any:
    """Make untrusted request values safe and bounded for the log."""
    if type(value) is int and abs(value) <= MAX_AMOUNT_PAISE:
        return value
    return repr(value)[:_LOG_TRUNC]


class Store:
    def __init__(self, path: Union[str, Path]):
        self.path = str(path)
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
        finally:
            conn.close()

    # -- plumbing ------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _tx(self):
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
        finally:
            conn.close()

    @contextmanager
    def _read(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    # -- grants --------------------------------------------------------
    def create_grant(
        self,
        agent: str,
        payees: Iterable[str],
        per_txn_cap_paise: int,
        total_cap_paise: int,
        rate_limit: int = 10,
        rate_window_s: int = 60,
        ttl_s: int = 900,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        now = time.time() if now is None else now
        if not isinstance(agent, str) or not agent.strip() or len(agent) > 128:
            raise ValueError("agent must be a non-empty string of at most 128 characters")
        per_txn = _pos_int("per_txn_cap_paise", per_txn_cap_paise, MAX_AMOUNT_PAISE)
        total = _pos_int("total_cap_paise", total_cap_paise, MAX_AMOUNT_PAISE)
        limit = _pos_int("rate_limit", rate_limit, MAX_RATE_LIMIT)
        window = _pos_int("rate_window_s", rate_window_s, MAX_TTL_S)
        ttl = _pos_int("ttl_s", ttl_s, MAX_TTL_S)

        norm: List[str] = []
        for p in payees:
            key = normalize_payee(p)
            if key is None:
                raise ValueError(f"invalid payee {_loggable(p)!r}: must be non-empty ASCII text")
            if key not in norm:
                norm.append(key)
        if not norm:
            raise ValueError("at least one payee is required")

        gid = uuid.uuid4().hex
        expires_at = now + ttl
        with self._tx() as c:
            c.execute(
                "INSERT INTO grants(id, agent, payees, per_txn_cap_paise, total_cap_paise, "
                "rate_limit, rate_window_s, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (gid, agent, json.dumps(norm), per_txn, total, limit, window, now, expires_at),
            )
            audit.append(
                c,
                "grant_created",
                gid,
                {
                    "agent": agent,
                    "payees": norm,
                    "per_txn_cap_paise": per_txn,
                    "total_cap_paise": total,
                    "rate_limit": limit,
                    "rate_window_s": window,
                    "expires_at": expires_at,
                },
                now,
            )
        return self.get_grant(gid, now=now)  # type: ignore[return-value]

    def get_grant(self, grant_id: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        now = time.time() if now is None else now
        with self._read() as c:
            row = c.execute(self._GRANT_SELECT + " WHERE g.id = ?", (str(grant_id),)).fetchone()
        return None if row is None else self._grant_dict(row, now)

    def list_grants(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        now = time.time() if now is None else now
        with self._read() as c:
            rows = c.execute(self._GRANT_SELECT + " ORDER BY g.created_at DESC").fetchall()
        return [self._grant_dict(r, now) for r in rows]

    _GRANT_SELECT = (
        "SELECT g.*, "
        "COALESCE((SELECT SUM(amount_paise) FROM attempts a WHERE a.grant_id=g.id AND a.allowed=1),0) "
        "AS spent_paise, "
        "(SELECT COUNT(*) FROM attempts a WHERE a.grant_id=g.id) AS attempts "
        "FROM grants g"
    )

    @staticmethod
    def _grant_dict(row: sqlite3.Row, now: float) -> Dict[str, Any]:
        if row["revoked_at"] is not None:
            status = "revoked"
        elif now >= row["expires_at"]:
            status = "expired"
        else:
            status = "active"
        return {
            "id": row["id"],
            "agent": row["agent"],
            "payees": json.loads(row["payees"]),
            "per_txn_cap_paise": row["per_txn_cap_paise"],
            "total_cap_paise": row["total_cap_paise"],
            "rate_limit": row["rate_limit"],
            "rate_window_s": row["rate_window_s"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "revoked_at": row["revoked_at"],
            "status": status,
            "spent_paise": row["spent_paise"],
            "attempts": row["attempts"],
        }

    def revoke_grant(self, grant_id: str, now: Optional[float] = None) -> Dict[str, Any]:
        """Revoke a grant immediately. Idempotent. Raises KeyError if unknown."""
        now = time.time() if now is None else now
        with self._tx() as c:
            row = c.execute("SELECT revoked_at FROM grants WHERE id=?", (str(grant_id),)).fetchone()
            if row is None:
                raise KeyError(grant_id)
            if row["revoked_at"] is None:
                c.execute("UPDATE grants SET revoked_at=? WHERE id=?", (now, grant_id))
                audit.append(c, "grant_revoked", grant_id, {}, now)
        return self.get_grant(grant_id, now=now)  # type: ignore[return-value]

    # -- decisions -----------------------------------------------------
    def decide_and_record(
        self,
        grant_id: Any,
        payee: Any,
        amount_paise: Any,
        now: Optional[float] = None,
        token_exp: Optional[float] = None,
    ) -> Outcome:
        """Decide a payment request and record the result atomically.

        `token_exp`, if given, is the expiry carried by the signed token; the
        effective expiry is the earlier of it and the grant's own expiry.
        """
        now = time.time() if now is None else now
        gid = str(grant_id)
        with self._tx() as c:
            row = c.execute("SELECT * FROM grants WHERE id=?", (gid,)).fetchone()
            attempt_id: Optional[int] = None
            if row is None:
                decision = Decision(False, GRANT_NOT_FOUND)
            else:
                spent = c.execute(
                    "SELECT COALESCE(SUM(amount_paise),0) FROM attempts WHERE grant_id=? AND allowed=1",
                    (gid,),
                ).fetchone()[0]
                recent = c.execute(
                    "SELECT COUNT(*) FROM attempts WHERE grant_id=? AND ts > ?",
                    (gid, now - row["rate_window_s"]),
                ).fetchone()[0]
                expires_at = row["expires_at"]
                if token_exp is not None:
                    expires_at = min(expires_at, token_exp)
                policy = GrantPolicy(
                    payees=frozenset(json.loads(row["payees"])),
                    per_txn_cap_paise=row["per_txn_cap_paise"],
                    total_cap_paise=row["total_cap_paise"],
                    rate_limit=row["rate_limit"],
                    rate_window_s=row["rate_window_s"],
                    expires_at=expires_at,
                    revoked=row["revoked_at"] is not None,
                )
                decision = decide(policy, payee, amount_paise, now, spent, recent)
                valid_amount = type(amount_paise) is int and abs(amount_paise) <= MAX_AMOUNT_PAISE
                cur = c.execute(
                    "INSERT INTO attempts(grant_id, ts, payee, amount_paise, allowed, reason) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        gid,
                        now,
                        payee[:_LOG_TRUNC] if isinstance(payee, str) else repr(payee)[:_LOG_TRUNC],
                        amount_paise if valid_amount else None,
                        1 if decision.allowed else 0,
                        decision.reason,
                    ),
                )
                attempt_id = cur.lastrowid
            seq = audit.append(
                c,
                "payment_decision",
                gid[:_LOG_TRUNC],
                {
                    "payee": payee[:_LOG_TRUNC] if isinstance(payee, str) else repr(payee)[:_LOG_TRUNC],
                    "amount_paise": _loggable(amount_paise),
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                },
                now,
            )
        return Outcome(decision, seq, attempt_id)

    def record_event(
        self, event: str, grant_id: Optional[str], data: Dict[str, Any], now: Optional[float] = None
    ) -> int:
        now = time.time() if now is None else now
        with self._tx() as c:
            return audit.append(c, event, grant_id, data, now)

    # -- audit ---------------------------------------------------------
    def audit_entries(self, limit: int = 100, after_seq: int = 0) -> List[Dict[str, Any]]:
        with self._read() as c:
            return audit.read(c, limit=limit, after_seq=after_seq)

    def audit_head(self) -> Optional[Dict[str, Any]]:
        with self._read() as c:
            return audit.head(c)

    def verify_audit(self, anchor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        with self._read() as c:
            return audit.verify(c, anchor=anchor)
