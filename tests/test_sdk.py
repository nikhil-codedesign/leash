import httpx
import pytest

from leash.sdk import LeashClient, LeashDenied
from tests.conftest import ADMIN


@pytest.fixture
def client(http, make_grant):
    g = make_grant()
    return LeashClient(token=g["token"], http=http), g


def test_pay_allowed(client):
    c, _ = client
    r = c.pay("shop@upi", 5_000)
    assert r["ok"] is True and r["reason"] == "ALLOWED" and r["txn_id"].startswith("mock_txn_")


def test_pay_denied_returns_structured_result_by_default(client):
    c, _ = client
    r = c.pay("evil@upi", 5_000)
    assert r["ok"] is False and r["reason"] == "PAYEE_NOT_ALLOWED" and r["status"] == 403


def test_guard_decorator_replaces_body_and_keeps_signature(client, provider):
    c, _ = client
    ran = []

    @c.guard
    def pay_merchant(payee: str, amount_paise: int):
        """Pay a merchant."""
        ran.append(True)  # must never run: the gateway does the paying

    assert pay_merchant.__name__ == "pay_merchant" and pay_merchant.__doc__ == "Pay a merchant."
    assert pay_merchant("shop@upi", 1_000)["ok"] is True
    assert pay_merchant(payee="evil@upi", amount_paise=1_000)["ok"] is False
    assert pay_merchant("shop@upi", amount_paise=2_000)["ok"] is True
    assert ran == []
    assert len(provider.payments()) == 2


def test_guard_with_raise_on_deny(client):
    c, _ = client

    @c.guard(raise_on_deny=True)
    def pay(payee, amount_paise): ...

    assert pay("shop@upi", 100)["ok"]
    with pytest.raises(LeashDenied) as exc:
        pay("evil@upi", 100)
    assert exc.value.reason == "PAYEE_NOT_ALLOWED"


def test_client_level_raise_on_deny(http, make_grant):
    c = LeashClient(token=make_grant()["token"], http=http, raise_on_deny=True)

    @c.guard
    def pay(payee, amount_paise): ...

    with pytest.raises(LeashDenied):
        pay("evil@upi", 1)
    # pay() itself always returns a result dict; raise_on_deny applies to guarded tools
    assert c.pay("evil@upi", 1)["ok"] is False


def test_guard_rejects_functions_without_expected_parameters(client):
    c, _ = client
    with pytest.raises(TypeError):
        c.guard(lambda to, cents: None)


def test_unreachable_gateway_fails_closed():
    def refuse(request):
        raise httpx.ConnectError("no route")

    c = LeashClient(token="t", http=httpx.Client(transport=httpx.MockTransport(refuse), base_url="http://x"))
    r = c.pay("shop@upi", 100)
    assert r["ok"] is False and r["reason"] == "GATEWAY_UNREACHABLE"


def test_garbage_response_fails_closed():
    c = LeashClient(
        token="t",
        http=httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, text="<html>")), base_url="http://x"),
    )
    assert c.pay("shop@upi", 100)["reason"] == "BAD_RESPONSE"


def test_allowed_without_paid_is_not_ok():
    body = {"allowed": True, "paid": False, "reason": "PROVIDER_ERROR"}
    c = LeashClient(
        token="t",
        http=httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(502, json=body)), base_url="http://x"),
    )
    r = c.pay("shop@upi", 100)
    assert r["ok"] is False and r["reason"] == "PROVIDER_ERROR"


def test_unserialisable_arguments_fail_closed(client):
    c, _ = client
    assert c.pay(object(), 100)["ok"] is False


def test_revoked_mid_run_through_sdk(client, http):
    c, g = client
    assert c.pay("shop@upi", 100)["ok"]
    http.post(f"/grants/{g['grant']['id']}/revoke", headers=ADMIN)
    assert c.pay("shop@upi", 100)["reason"] == "REVOKED"
