"""Real-browser test of the dashboard (skipped unless Playwright + Chromium are installed).

    pip install playwright && playwright install chromium && pytest tests/test_dashboard_browser.py

Exists because a rendering bug (numbers passed to the table-cell helper) once made
the grants table silently stay empty, which no API-level test could catch.
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api")
from playwright.sync_api import sync_playwright  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
KEY = "e2e-admin-key-123456"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    port, db = _free_port(), tmp_path / "e2e.db"
    env = dict(os.environ, LEASH_ADMIN_KEY=KEY, LEASH_SECRET="e2e-secret-e2e-secret-0123456")
    proc = subprocess.Popen(
        [sys.executable, "-m", "leash", "--db", str(db), "--port", str(port)],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(url + "/health", timeout=1)
                break
            except Exception:
                time.sleep(0.25)
        else:
            pytest.fail("gateway did not start")
        yield url, str(db), proc
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
def page():
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception:
            pytest.skip("Chromium is not installed (playwright install chromium)")
        # bypass_csp only so the test harness can poll with evaluated expressions;
        # the page renders every value with textContent, which is what the XSS check proves.
        pg = browser.new_page(viewport={"width": 1280, "height": 800}, bypass_csp=True)
        pg.js_errors = []
        pg.on("pageerror", lambda e: pg.js_errors.append(str(e)))
        yield pg
        browser.close()


def _status(page):
    return page.inner_text("#status")


def test_connection_states(server, page):
    url, _, _ = server
    page.goto(url + "/")
    assert "Not connected" in _status(page)
    assert not page.is_visible("#grants-empty")  # don't claim "no grants" when not connected

    page.fill("#key", "definitely-wrong")
    page.click("#save")
    page.wait_for_selector("#status.bad")
    assert "Wrong admin key" in _status(page)

    page.fill("#key", KEY)
    page.click("#save")
    page.wait_for_selector("#status.ok")
    assert page.is_visible("#grants-empty")


def test_demo_renders_tamper_and_escapes_hostile_input(server, page):
    url, db, proc = server
    page.goto(url + "/")
    page.fill("#key", KEY)
    page.click("#save")
    page.wait_for_selector("#status.ok")

    demo = subprocess.run(
        [sys.executable, "-m", "demo.run_demo", "--url", url, "--admin-key", KEY, "--db", db],
        cwd=ROOT, capture_output=True, text=True, timeout=90,
    )
    assert demo.returncode == 0, demo.stdout[-400:] + demo.stderr[-400:]

    page.wait_for_selector("#grants .pill.bad", timeout=10_000)  # the revoked grant
    page.wait_for_function("document.getElementById('feed').textContent.includes('BLOCKED: REVOKED')", timeout=10_000)
    assert page.locator("#grants tr").count() == 2
    feed = page.inner_text("#feed")
    for reason in ("OVER_TXN_CAP", "EXPIRED", "REVOKED"):
        assert f"BLOCKED: {reason}" in feed
    assert page.locator("#feed tr.blocked").count() == 3  # the 4th was forged to look allowed

    page.click("#verify")
    page.wait_for_selector("#banner.bad")
    assert "TAMPERING DETECTED at entry #" in page.inner_text("#banner")
    page.wait_for_selector("#feed tr.tampered")

    # A hostile payee must show as literal text and never run.
    grant = json.load(urllib.request.urlopen(urllib.request.Request(
        url + "/grants",
        data=json.dumps(dict(agent="x", payees=["a@b"], per_txn_cap_paise=100, total_cap_paise=100, ttl_s=60)).encode(),
        headers={"X-Admin-Key": KEY, "Content-Type": "application/json"},
    )))
    payload = "<img src=x onerror=window.__xss=1>"
    try:
        urllib.request.urlopen(urllib.request.Request(
            url + "/pay",
            data=json.dumps(dict(payee=payload, amount_paise=1)).encode(),
            headers={"Authorization": f"Bearer {grant['token']}", "Content-Type": "application/json"},
        ))
    except Exception:
        pass  # 403 expected; the attempt is logged
    page.wait_for_function("document.getElementById('feed').textContent.includes('onerror')", timeout=10_000)
    assert page.evaluate("window.__xss") is None
    assert payload in page.inner_text("#feed")
    assert page.js_errors == []


def test_gateway_down_is_reported(server, page):
    url, _, proc = server
    page.goto(url + "/")
    page.fill("#key", KEY)
    page.click("#save")
    page.wait_for_selector("#status.ok")
    proc.terminate()
    proc.wait(timeout=10)
    page.wait_for_function("document.getElementById('status').textContent.includes('Cannot reach')", timeout=10_000)
