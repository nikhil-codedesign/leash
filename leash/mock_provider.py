"""MOCK payment provider.

This is NOT a real UPI or bank integration. It records UPI-style payments
(`name@bank`, amounts in paise) in memory so the gateway has something to
forward allowed requests to. Every response is labelled as mock.
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List


class MockProvider:
    name = "mock"

    def __init__(self) -> None:
        self._payments: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def pay(self, payee: str, amount_paise: int) -> Dict[str, Any]:
        record = {
            "txn_id": f"mock_txn_{uuid.uuid4().hex[:12]}",
            "payee": payee,
            "amount_paise": amount_paise,
            "currency": "INR",
            "ts": time.time(),
            "provider": self.name,
            "mock": True,
        }
        with self._lock:
            self._payments.append(record)
        return dict(record)

    def payments(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(p) for p in self._payments]
