import base64
import json
import sqlite3

import pytest

from leash import tokens
from tests.conftest import ADMIN, SECRET, pay


# -- basics ---------------------------------------------------------------
def test_health_labels_payments_as_mock(http):
    body = http.get("/health").json()
    assert body["ok"] and body["mock_payments"] is True and body["provider"] == "mock"


def test_dashboard_served_with_csp(http):
    r = http.get("/")
    assert r.status_code == 200 and "Leash" in r.text and "MOCK" in r.text
    assert "default-src 'none'" in r.headers["content-security-policy"]


# -- admin auth -----------------------------------------------------------
@pytest.mark.parametrize(
    "method,path",
    [("get", "/grants"), ("get", "/audit"), ("get", "/mock/payments"), ("post", "/grants/x/revoke")],
)
def test_admin_endpoints_require_key(http, method, path):
    assert getattr(http, method)(path).status_code == 401
    assert getattr(http, method)(path, headers={"X-Admin-Key": "wrong"}).status_code == 401


def test_create_grant_requires_key(http):
    body = dict(agent="a", payees=["x@upi"], per_txn_cap_paise=1, total_cap_paise=1, ttl_s=60)
    assert http.post("/grants", json=body).status_code == 401
    assert http.post("/grants", json=body, headers={"X-Admin-Key": "nope"}).status_code == 401


def test_non_ascii_admin_key_does_not_crash(http):
    assert http.get("/grants", headers={"X-Admin-Key": "kéy".encode("latin-1")}).status_code == 401


@pytest.mark.parametrize(
    "over",
    [
        dict(payees=[]),
        dict(payees=["é@upi"]),
        dict(per_txn_cap_paise=0),
        dict(per_txn_cap_paise=1.5),
        dict(per_txn_cap_paise="100"),
        dict(ttl_s=-5),
        dict(agent=""),
    ],
)
def test_create_grant_validation_errors(http, make_grant, over):
    body = dict(agent="a", payees=["x@upi"], per_txn_cap_paise=100, total_cap_paise=100, ttl_s=60)
    body.update(over)
    assert http.post("/grants", json=body, headers=ADMIN).status_code == 422


# -- the happy path and each way to be blocked ------------------------------
def test_allowed_payment_is_forwarded_to_mock_provider(http, make_grant, provider):
    g = make_grant()
    r = pay(http, g["token"], payee="SHOP@upi", amount=5_000)
    body = r.json()
    assert r.status_code == 200
    assert body["allowed"] and body["paid"] and body["provider"] == "mock"
    assert body["txn_id"].startswith("mock_txn_")
    assert len(provider.payments()) == 1 and provider.payments()[0]["amount_paise"] == 5_000


@pytest.mark.parametrize(
    "payee,amount,reason,status",
    [
        ("unlisted@upi", 100, "PAYEE_NOT_ALLOWED", 403),
        ("shop@upi", 10_001, "OVER_TXN_CAP", 403),
        ("shop@upi", 0, "INVALID_AMOUNT", 403),
        ("shop@upi", -100, "INVALID_AMOUNT", 403),
        ("shop@upi", 100.5, "INVALID_AMOUNT", 403),
        ("shop@upi", 100.0, "INVALID_AMOUNT", 403),
        ("shop@upi", True, "INVALID_AMOUNT", 403),
        ("shop@upi", "100", "INVALID_AMOUNT", 403),
        ("shop@upi", None, "INVALID_AMOUNT", 403),
        ("shop@upi ", 100, "PAYEE_NOT_ALLOWED", 403),
        ("shop@upl", 100, "PAYEE_NOT_ALLOWED", 403),
        (None, 100, "PAYEE_NOT_ALLOWED", 403),
        (["shop@upi"], 100, "PAYEE_NOT_ALLOWED", 403),
    ],
)
def test_blocked_requests_return_reason_and_never_reach_provider(http, make_grant, provider, payee, amount, reason, status):
    g = make_grant()
    r = pay(http, g["token"], payee=payee, amount=amount)
    assert r.status_code == status
    body = r.json()
    assert body["allowed"] is False and body["paid"] is False and body["reason"] == reason
    assert provider.payments() == []


def test_total_cap_enforced(http, make_grant):
    g = make_grant()
    for _ in range(3):
        assert pay(http, g["token"], amount=10_000).status_code == 200
    r = pay(http, g["token"], amount=1)
    assert r.status_code == 403 and r.json()["reason"] == "OVER_TOTAL_CAP"


def test_rate_limit_returns_429_and_counts_blocked_attempts(http, make_grant):
    g = make_grant(rate_limit=3)
    for _ in range(3):
        assert pay(http, g["token"], payee="evil@upi").json()["reason"] == "PAYEE_NOT_ALLOWED"
    r = pay(http, g["token"])
    assert r.status_code == 429 and r.json()["reason"] == "RATE_LIMITED"


def test_expired_token_is_blocked_and_logged(http, make_grant, clock):
    g = make_grant(ttl_s=60)
    assert pay(http, g["token"]).status_code == 200
    clock.advance(61)
    r = pay(http, g["token"])
    assert r.status_code == 403 and r.json()["reason"] == "EXPIRED"
    last = http.get("/audit?limit=1", headers=ADMIN).json()["entries"][0]
    assert last["data"]["reason"] == "EXPIRED"


def test_revocation_cuts_agent_off_immediately(http, make_grant):
    g = make_grant()
    assert pay(http, g["token"]).status_code == 200
    assert http.post(f"/grants/{g['grant']['id']}/revoke", headers=ADMIN).json()["grant"]["status"] == "revoked"
    r = pay(http, g["token"])
    assert r.status_code == 403 and r.json()["reason"] == "REVOKED"


def test_revoke_unknown_grant_404(http):
    assert http.post("/grants/nope/revoke", headers=ADMIN).status_code == 404


def test_tokens_are_not_interchangeable_between_grants(http, make_grant):
    a, b = make_grant(payees=["a@upi"]), make_grant(payees=["b@upi"])
    assert pay(http, a["token"], payee="b@upi").json()["reason"] == "PAYEE_NOT_ALLOWED"
    assert pay(http, b["token"], payee="b@upi").status_code == 200


# -- authentication of the token itself --------------------------------------
@pytest.mark.parametrize("header", [None, "", "Bearer", "Bearer ", "Basic abc", "Bearer a.b", "Bearer not-a-token", "token xyz"])
def test_bad_or_missing_token_is_401(http, header):
    headers = {} if header is None else {"Authorization": header}
    r = http.post("/pay", json={"payee": "shop@upi", "amount_paise": 1}, headers=headers)
    assert r.status_code == 401 and r.json()["reason"] == "BAD_TOKEN"


def test_token_signed_with_another_secret_rejected(http, make_grant):
    g = make_grant()
    forged = tokens.issue(g["grant"]["id"], 2_000_000_000, "some-other-secret-0123456789")
    assert pay(http, forged).status_code == 401


def test_token_with_extended_expiry_rejected(http, make_grant):
    g = make_grant(ttl_s=60)
    payload, sig = g["token"].split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["exp"] += 100_000
    forged_payload = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
    assert pay(http, f"{forged_payload}.{sig}").status_code == 401


def test_validly_signed_token_for_unknown_grant_is_denied_and_logged(http):
    token = tokens.issue("ghost-grant", 2_000_000_000, SECRET)
    r = pay(http, token)
    assert r.status_code == 403 and r.json()["reason"] == "GRANT_NOT_FOUND"


def test_unauthenticated_requests_do_not_flood_the_audit_log(http, make_grant):
    make_grant()
    before = len(http.get("/audit?limit=1000", headers=ADMIN).json()["entries"])
    for _ in range(25):
        http.post("/pay", json={"payee": "x", "amount_paise": 1}, headers={"Authorization": "Bearer junk.junk"})
    assert len(http.get("/audit?limit=1000", headers=ADMIN).json()["entries"]) == before


def test_malformed_json_body_is_rejected_not_allowed(http, make_grant):
    g = make_grant()
    r = http.post("/pay", content=b"{not json", headers={"Authorization": f"Bearer {g['token']}", "Content-Type": "application/json"})
    assert r.status_code == 422
    r = http.post("/pay", json={"payee": "shop@upi"}, headers={"Authorization": f"Bearer {g['token']}"})
    assert r.status_code == 422


# -- fail closed ---------------------------------------------------------------
def test_internal_error_in_store_denies_and_does_not_forward(app, http, make_grant, provider, monkeypatch):
    g = make_grant()

    def boom(*a, **k):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(app.state.store, "decide_and_record", boom)
    r = pay(http, g["token"])
    assert r.status_code == 500 and r.json()["allowed"] is False and r.json()["reason"] == "INTERNAL_ERROR"
    assert provider.payments() == []


def test_provider_failure_returns_502_is_logged_and_still_counts(app, http, make_grant, monkeypatch):
    g = make_grant()

    def broken(*a, **k):
        raise ConnectionError("provider down")

    monkeypatch.setattr(app.state.provider, "pay", broken)
    r = pay(http, g["token"], amount=10_000)
    assert r.status_code == 502
    body = r.json()
    assert body["allowed"] is True and body["paid"] is False and body["reason"] == "PROVIDER_ERROR"
    events = [e["event"] for e in http.get("/audit?limit=100", headers=ADMIN).json()["entries"]]
    assert "provider_error" in events
    spent = http.get("/grants", headers=ADMIN).json()["grants"][0]["spent_paise"]
    assert spent == 10_000  # conservative: counted even though not paid


# -- audit, verify, tamper -----------------------------------------------------
def test_audit_log_records_everything_and_verifies(http, make_grant):
    g = make_grant()
    pay(http, g["token"])
    pay(http, g["token"], payee="evil@upi")
    http.post(f"/grants/{g['grant']['id']}/revoke", headers=ADMIN)
    entries = http.get("/audit", headers=ADMIN).json()["entries"]
    assert [e["event"] for e in entries] == ["grant_created", "payment_decision", "payment_decision", "grant_revoked"]
    v = http.get("/audit/verify").json()
    assert v["ok"] and v["entries"] == 4


def test_hand_edited_audit_row_is_flagged_at_the_exact_entry(app, http, make_grant):
    g = make_grant()
    pay(http, g["token"])
    pay(http, g["token"], payee="evil@upi")  # entry 3 (blocked)
    pay(http, g["token"])
    conn = sqlite3.connect(app.state.store.path)
    conn.execute("UPDATE audit SET data = replace(data, '\"allowed\":false', '\"allowed\":true') WHERE seq = 3")
    conn.commit()
    v = http.get("/audit/verify").json()
    assert v["ok"] is False and v["bad_seq"] == 3


def test_verify_with_anchor(http, make_grant):
    g = make_grant()
    pay(http, g["token"])
    head = http.get("/audit/head").json()["head"]
    pay(http, g["token"])
    ok = http.get("/audit/verify", params={"anchor_seq": head["seq"], "anchor_hash": head["hash"]}).json()
    assert ok["ok"]
    bad = http.get("/audit/verify", params={"anchor_seq": head["seq"], "anchor_hash": "0" * 64}).json()
    assert bad["ok"] is False
    assert http.get("/audit/verify", params={"anchor_seq": 1}).status_code == 422


def test_audit_limit_validation(http):
    assert http.get("/audit?limit=0", headers=ADMIN).status_code == 422
    assert http.get("/audit?limit=100000", headers=ADMIN).status_code == 422


def test_grants_list_reports_spend(http, make_grant):
    g = make_grant()
    pay(http, g["token"], amount=4_000)
    pay(http, g["token"], payee="evil@upi")
    row = http.get("/grants", headers=ADMIN).json()["grants"][0]
    assert row["spent_paise"] == 4_000 and row["attempts"] == 2 and row["status"] == "active"


def test_mock_payments_endpoint(http, make_grant):
    g = make_grant()
    pay(http, g["token"])
    body = http.get("/mock/payments", headers=ADMIN).json()
    assert body["mock"] is True and len(body["payments"]) == 1
