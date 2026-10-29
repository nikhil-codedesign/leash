import dataclasses

import pytest

from leash import policy as P
from leash.policy import Decision, GrantPolicy, decide, normalize_payee

NOW = 1_800_000_000.0


def pol(**over):
    base = dict(
        payees=frozenset({"bigbasket@okaxis", "blinkit@okhdfcbank"}),
        per_txn_cap_paise=10_000,
        total_cap_paise=30_000,
        rate_limit=5,
        rate_window_s=60,
        expires_at=NOW + 600,
        revoked=False,
    )
    base.update(over)
    return GrantPolicy(**base)


def run(p=None, payee="bigbasket@okaxis", amount=5_000, now=NOW, spent=0, recent=0):
    return decide(p or pol(), payee, amount, now, spent, recent)


def test_allowed_when_every_check_passes():
    assert run() == Decision(True, P.ALLOWED)


def test_revoked():
    assert run(pol(revoked=True)).reason == P.REVOKED


def test_expired_at_and_after_expiry():
    p = pol(expires_at=NOW)
    assert run(p, now=NOW).reason == P.EXPIRED  # exactly at expiry is expired
    assert run(p, now=NOW + 1).reason == P.EXPIRED
    assert run(p, now=NOW - 0.001).allowed


@pytest.mark.parametrize(
    "bad",
    [0, -1, -5_000, 1.5, 100.0, 5_000.0, "5000", None, True, False, [5000], P.MAX_AMOUNT_PAISE + 1, 10**30],
)
def test_invalid_amounts(bad):
    r = run(amount=bad)
    assert (r.allowed, r.reason) == (False, P.INVALID_AMOUNT)


def test_float_that_equals_an_integer_is_still_rejected():
    assert run(amount=10_000.0).reason == P.INVALID_AMOUNT


def test_payee_not_on_allowlist():
    assert run(payee="evil@okaxis").reason == P.PAYEE_NOT_ALLOWED


def test_payee_match_is_case_insensitive():
    assert run(payee="BigBasket@OKAXIS").allowed


@pytest.mark.parametrize(
    "lookalike",
    [
        "bigbasket@okaxls",  # l instead of i
        "bigbasket@okaxis ",  # trailing space
        " bigbasket@okaxis",  # leading space
        "bigbasket@okaxis\n",
        "bigbasket@okaxis.evil",
        "bigbasket@@okaxis",
        "bigbаsket@okaxis",  # Cyrillic a
        "bigbasKet@okaxis".replace("K", "K"),  # KELVIN SIGN lowercases to "k"
        "",
        "*",
        "*@okaxis",
        "bigbasket@*",
        "bigbasket",
    ],
)
def test_lookalike_and_wildcard_payees_are_blocked(lookalike):
    assert run(payee=lookalike).reason == P.PAYEE_NOT_ALLOWED


def test_wildcard_in_allowlist_is_not_special():
    p = pol(payees=frozenset({"*@okaxis"}))
    assert run(p, payee="anything@okaxis").reason == P.PAYEE_NOT_ALLOWED
    assert run(p, payee="*@okaxis").allowed  # literal match only


@pytest.mark.parametrize("bad", [None, 123, ["bigbasket@okaxis"], b"bigbasket@okaxis", {"a": 1}])
def test_non_string_payee_blocked(bad):
    assert run(payee=bad).reason == P.PAYEE_NOT_ALLOWED


def test_per_transaction_cap_boundary():
    assert run(amount=10_000).allowed  # exactly at cap
    assert run(amount=10_001).reason == P.OVER_TXN_CAP


def test_total_cap_boundary():
    assert run(amount=10_000, spent=20_000).allowed  # lands exactly on the cap
    assert run(amount=10_000, spent=20_001).reason == P.OVER_TOTAL_CAP
    assert run(amount=1, spent=30_000).reason == P.OVER_TOTAL_CAP


def test_rate_limit_boundary():
    assert run(recent=4).allowed
    assert run(recent=5).reason == P.RATE_LIMITED
    assert run(recent=50).reason == P.RATE_LIMITED


# First failing check decides the reason code ----------------------------
ORDER_CASES = [
    ("revoked beats expired", dict(p=pol(revoked=True, expires_at=NOW - 1)), P.REVOKED),
    ("expired beats invalid amount", dict(p=pol(expires_at=NOW - 1), amount=-1), P.EXPIRED),
    ("invalid amount beats bad payee", dict(amount=0, payee="evil@x"), P.INVALID_AMOUNT),
    ("bad payee beats over txn cap", dict(payee="evil@x", amount=99_999), P.PAYEE_NOT_ALLOWED),
    ("txn cap beats total cap", dict(amount=10_001, spent=29_000), P.OVER_TXN_CAP),
    ("total cap beats rate limit", dict(amount=5_000, spent=29_000, recent=99), P.OVER_TOTAL_CAP),
]


@pytest.mark.parametrize("name,kwargs,expected", ORDER_CASES, ids=[c[0] for c in ORDER_CASES])
def test_check_order(name, kwargs, expected):
    assert run(**kwargs).reason == expected


def test_fails_closed_on_unexpected_error():
    broken = pol(payees=None)  # `in None` raises TypeError
    assert run(broken) == Decision(False, P.INTERNAL_ERROR)


def test_deterministic_and_pure():
    p = pol()
    args = (p, "bigbasket@okaxis", 5_000, NOW, 0, 0)
    assert decide(*args) == decide(*args)
    assert dataclasses.is_dataclass(p) and p.__dataclass_params__.frozen


def test_normalize_payee():
    assert normalize_payee("A@B") == "a@b"
    assert normalize_payee("") is None
    assert normalize_payee("é@b") is None
    assert normalize_payee(5) is None
