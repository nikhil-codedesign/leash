import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from leash import policy as P
from leash.store import Store

NOW = 1_800_000_000.0


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "s.db")


def grant(store, **over):
    kw = dict(
        agent="a",
        payees=["Shop@UPI"],
        per_txn_cap_paise=1_000,
        total_cap_paise=3_000,
        rate_limit=100,
        rate_window_s=60,
        ttl_s=600,
        now=NOW,
    )
    kw.update(over)
    return store.create_grant(**kw)


def pay(store, g, payee="shop@upi", amount=1_000, now=NOW, **kw):
    return store.decide_and_record(g["id"], payee, amount, now=now, **kw)


def test_create_and_get_grant(store):
    g = grant(store)
    assert g["payees"] == ["shop@upi"]  # normalised
    assert g["status"] == "active" and g["spent_paise"] == 0
    assert store.get_grant(g["id"], now=NOW)["agent"] == "a"
    assert store.get_grant("nope") is None


def test_status_changes_with_time_and_revocation(store):
    g = grant(store)
    assert store.get_grant(g["id"], now=NOW + 599)["status"] == "active"
    assert store.get_grant(g["id"], now=NOW + 600)["status"] == "expired"
    store.revoke_grant(g["id"], now=NOW + 1)
    assert store.get_grant(g["id"], now=NOW + 2)["status"] == "revoked"


@pytest.mark.parametrize(
    "over",
    [
        dict(payees=[]),
        dict(payees=["bad payee é"]),
        dict(payees=[""]),
        dict(payees=[5]),
        dict(per_txn_cap_paise=0),
        dict(total_cap_paise=-1),
        dict(per_txn_cap_paise=True),
        dict(per_txn_cap_paise=10.5),
        dict(ttl_s=0),
        dict(ttl_s=10**9),
        dict(rate_limit=0),
        dict(agent=""),
        dict(agent=None),
    ],
)
def test_create_grant_validation(store, over):
    with pytest.raises(ValueError):
        grant(store, **over)


def test_allowed_then_spent_accumulates(store):
    g = grant(store)
    assert pay(store, g).decision.allowed
    assert pay(store, g).decision.allowed
    assert store.get_grant(g["id"], now=NOW)["spent_paise"] == 2_000


def test_blocked_requests_do_not_spend(store):
    g = grant(store)
    assert pay(store, g, payee="evil@upi").decision.reason == P.PAYEE_NOT_ALLOWED
    assert pay(store, g, amount=9_999).decision.reason == P.OVER_TXN_CAP
    assert store.get_grant(g["id"], now=NOW)["spent_paise"] == 0


def test_total_cap_enforced_across_requests(store):
    g = grant(store)
    for _ in range(3):
        assert pay(store, g).decision.allowed
    assert pay(store, g, amount=1).decision.reason == P.OVER_TOTAL_CAP


def test_revocation_cuts_off_immediately(store):
    g = grant(store)
    assert pay(store, g).decision.allowed
    store.revoke_grant(g["id"], now=NOW)
    assert pay(store, g).decision.reason == P.REVOKED


def test_revoke_is_idempotent_and_unknown_raises(store):
    g = grant(store)
    store.revoke_grant(g["id"], now=NOW)
    before = len(store.audit_entries(limit=1000))
    store.revoke_grant(g["id"], now=NOW + 5)
    assert len(store.audit_entries(limit=1000)) == before  # no duplicate entry
    with pytest.raises(KeyError):
        store.revoke_grant("missing")


def test_grant_expiry(store):
    g = grant(store)
    assert pay(store, g, now=NOW + 599).decision.allowed
    assert pay(store, g, now=NOW + 600).decision.reason == P.EXPIRED


def test_token_expiry_can_shorten_but_not_extend(store):
    g = grant(store)
    assert pay(store, g, now=NOW + 10, token_exp=NOW + 5).decision.reason == P.EXPIRED
    # a token claiming a later expiry doesn't outlive the grant
    assert pay(store, g, now=NOW + 700, token_exp=NOW + 10_000).decision.reason == P.EXPIRED


def test_unknown_grant_denied_and_logged(store):
    out = store.decide_and_record("nope", "shop@upi", 100, now=NOW)
    assert out.decision.reason == P.GRANT_NOT_FOUND and out.attempt_id is None
    entry = store.audit_entries(limit=1)[0]
    assert entry["data"]["reason"] == P.GRANT_NOT_FOUND


def test_blocked_attempts_count_toward_rate_limit(store):
    g = grant(store, rate_limit=3)
    for _ in range(3):
        assert pay(store, g, payee="evil@upi").decision.reason == P.PAYEE_NOT_ALLOWED
    # A request that would otherwise be fine is now rate limited.
    assert pay(store, g).decision.reason == P.RATE_LIMITED


def test_rate_window_slides(store):
    g = grant(store, rate_limit=2, rate_window_s=60)
    pay(store, g, now=NOW)
    pay(store, g, now=NOW + 1)
    assert pay(store, g, now=NOW + 2).decision.reason == P.RATE_LIMITED
    assert pay(store, g, now=NOW + 62).decision.allowed  # earlier attempts fell out of the window


def test_every_decision_is_audited_in_the_same_transaction(store):
    g = grant(store)
    pay(store, g)
    pay(store, g, payee="evil@upi")
    events = store.audit_entries(limit=100)
    assert [e["event"] for e in events] == ["grant_created", "payment_decision", "payment_decision"]
    assert [e["data"]["allowed"] for e in events[1:]] == [True, False]
    assert store.verify_audit()["ok"]


def test_hostile_inputs_are_logged_safely(store):
    g = grant(store)
    for payee, amount in [
        ("x" * 100_000, 10**40),
        (None, "1000"),
        (b"bytes", 1.5),
        ({"a": 1}, [1]),
        ("é", True),
    ]:
        out = pay(store, g, payee=payee, amount=amount)
        assert not out.decision.allowed
    assert store.get_grant(g["id"], now=NOW)["spent_paise"] == 0
    assert store.verify_audit()["ok"]
    for e in store.audit_entries(limit=100):
        assert len(str(e["data"])) < 1_000  # bounded


def test_transaction_rolls_back_on_failure(store, monkeypatch):
    g = grant(store)
    from leash import audit

    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(audit, "append", boom)
    with pytest.raises(RuntimeError):
        pay(store, g)
    monkeypatch.undo()
    # nothing was recorded: no phantom spend, no orphan attempt
    assert store.get_grant(g["id"], now=NOW)["attempts"] == 0
    assert store.verify_audit()["ok"]


def test_race_20_simultaneous_requests_cannot_overspend(store):
    # cap allows exactly five 1,000-paise payments
    g = grant(store, per_txn_cap_paise=1_000, total_cap_paise=5_000, rate_limit=1_000)
    barrier = threading.Barrier(20)

    def attempt(_):
        barrier.wait()
        return store.decide_and_record(g["id"], "shop@upi", 1_000, now=NOW)

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(attempt, range(20)))

    allowed = [r for r in results if r.decision.allowed]
    blocked = [r for r in results if not r.decision.allowed]
    assert len(allowed) == 5
    assert len(blocked) == 15
    assert {r.decision.reason for r in blocked} == {P.OVER_TOTAL_CAP}
    assert store.get_grant(g["id"], now=NOW)["spent_paise"] == 5_000
    assert len({r.audit_seq for r in results}) == 20  # unique, gap-free sequence numbers
    assert store.verify_audit()["ok"]
