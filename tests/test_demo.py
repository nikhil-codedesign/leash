"""Runs the full seven-step demo as a test, so the demo can't silently rot."""

from fastapi.testclient import TestClient

from demo.run_demo import run
from leash.gateway import create_app


def test_demo_script_behaves_exactly_as_documented(tmp_path):
    db = tmp_path / "demo.db"
    app = create_app(db, secret="demo-secret-demo-secret-0000", admin_key="k" * 16)
    lines = []
    results = run(TestClient(app), "k" * 16, str(db), out=lines.append, expiry_s=1)

    attempts = [r for r in results if "expected_ok" in r]
    assert attempts and all(r["ok"] == r["expected_ok"] for r in attempts)

    by_label = {r["label"]: r for r in attempts}
    assert by_label["unlisted merchant"]["reason"] == "PAYEE_NOT_ALLOWED"
    assert by_label["over cap"]["reason"] == "OVER_TXN_CAP"
    assert by_label["expired token"]["reason"] == "EXPIRED"
    assert by_label["after revoke"]["reason"] == "REVOKED"

    tamper = next(r for r in results if r["label"] == "tamper")
    assert tamper["before_ok"] is True and tamper["after_ok"] is False
    assert tamper["flagged_seq"] == tamper["tampered_seq"]  # the exact edited entry
    assert any("All steps behaved as expected" in line for line in lines)
