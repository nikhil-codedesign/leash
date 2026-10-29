import pytest
from fastapi.testclient import TestClient

from leash.gateway import create_app
from leash.mock_provider import MockProvider

SECRET = "gateway-test-secret-0123456789"
ADMIN_KEY = "admin-key-for-tests"
ADMIN = {"X-Admin-Key": ADMIN_KEY}


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def provider():
    return MockProvider()


@pytest.fixture
def app(tmp_path, clock, provider):
    return create_app(
        db_path=tmp_path / "gw.db", secret=SECRET, admin_key=ADMIN_KEY, provider=provider, clock=clock
    )


@pytest.fixture
def http(app):
    return TestClient(app)


@pytest.fixture
def make_grant(http):
    def _make(**over):
        body = dict(
            agent="test-agent",
            payees=["shop@upi", "Other@UPI"],
            per_txn_cap_paise=10_000,
            total_cap_paise=30_000,
            rate_limit=100,
            rate_window_s=60,
            ttl_s=600,
        )
        body.update(over)
        r = http.post("/grants", json=body, headers=ADMIN)
        assert r.status_code == 201, r.text
        return r.json()

    return _make


def pay(http, token, payee="shop@upi", amount=5_000):
    return http.post(
        "/pay",
        json={"payee": payee, "amount_paise": amount},
        headers={"Authorization": f"Bearer {token}"},
    )
