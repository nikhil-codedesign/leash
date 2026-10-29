"""Pure policy engine.

No I/O, no clock, no database: everything the decision depends on is passed in,
so every rule is trivially testable and the result is deterministic.

Checks run in a fixed order and the FIRST failing check decides the reason
code. Anything unexpected is denied (fail closed).

Money is always an integer number of paise (1 INR = 100 paise); floats are
never accepted, so limits never depend on floating-point arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, FrozenSet, Optional

# Reason codes -----------------------------------------------------------
ALLOWED = "ALLOWED"
REVOKED = "REVOKED"
EXPIRED = "EXPIRED"
INVALID_AMOUNT = "INVALID_AMOUNT"
PAYEE_NOT_ALLOWED = "PAYEE_NOT_ALLOWED"
OVER_TXN_CAP = "OVER_TXN_CAP"
OVER_TOTAL_CAP = "OVER_TOTAL_CAP"
RATE_LIMITED = "RATE_LIMITED"
GRANT_NOT_FOUND = "GRANT_NOT_FOUND"
INTERNAL_ERROR = "INTERNAL_ERROR"

# Sanity ceiling (INR 10 trillion in paise). Keeps values inside SQLite's
# 64-bit integers and rejects absurd requests outright.
MAX_AMOUNT_PAISE = 10**15


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class GrantPolicy:
    """The narrow permission a single agent run holds.

    `payees` must already be normalised with `normalize_payee`.
    `expires_at` and `now` are epoch seconds.
    """

    payees: FrozenSet[str]
    per_txn_cap_paise: int
    total_cap_paise: int
    rate_limit: int  # max attempts (allowed OR blocked) per window
    rate_window_s: int
    expires_at: float
    revoked: bool = False


def normalize_payee(payee: Any) -> Optional[str]:
    """Exact-match key for a payee, or None if it can never match.

    Matching is case-insensitive but otherwise exact: no trimming, no
    wildcards. Non-ASCII payees are rejected outright, because Unicode case
    folding creates lookalikes (e.g. KELVIN SIGN lowercases to "k") and UPI
    IDs are ASCII anyway.
    """
    if not isinstance(payee, str) or not payee or not payee.isascii():
        return None
    return payee.lower()


def is_valid_amount(amount: Any) -> bool:
    # `type(...) is int` deliberately excludes bool (True == 1 in Python).
    return type(amount) is int and 0 < amount <= MAX_AMOUNT_PAISE


def decide(
    policy: GrantPolicy,
    payee: Any,
    amount_paise: Any,
    now: float,
    spent_paise: int,
    recent_attempts: int,
) -> Decision:
    """Decide one payment request.

    spent_paise      total of previously ALLOWED payments under this grant
    recent_attempts  attempts (allowed or blocked) inside the rate window,
                     not counting this one
    """
    try:
        if policy.revoked:
            return Decision(False, REVOKED)
        if now >= policy.expires_at:
            return Decision(False, EXPIRED)
        if not is_valid_amount(amount_paise):
            return Decision(False, INVALID_AMOUNT)
        key = normalize_payee(payee)
        if key is None or key not in policy.payees:
            return Decision(False, PAYEE_NOT_ALLOWED)
        if amount_paise > policy.per_txn_cap_paise:
            return Decision(False, OVER_TXN_CAP)
        if spent_paise + amount_paise > policy.total_cap_paise:
            return Decision(False, OVER_TOTAL_CAP)
        if recent_attempts >= policy.rate_limit:
            return Decision(False, RATE_LIMITED)
        return Decision(True, ALLOWED)
    except Exception:  # fail closed
        return Decision(False, INTERNAL_ERROR)
