"""Python SDK: wrap an agent's payment tool in a few lines.

    from leash.sdk import LeashClient

    leash = LeashClient(token=os.environ["LEASH_TOKEN"], base_url="http://127.0.0.1:8000")

    @leash.guard
    def pay(payee: str, amount_paise: int):
        \"\"\"Pay a merchant. Amount is in paise (1 INR = 100 paise).\"\"\"

The decorated function's body is never run. The gateway executes the payment,
so the agent never holds a payment credential. The function name, signature
and docstring are kept so LLM tool-calling frameworks can still read them.
Every failure, including an unreachable gateway, comes back as a denial.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, Optional

import httpx


class LeashDenied(Exception):
    def __init__(self, reason: str, result: Dict[str, Any]):
        super().__init__(reason)
        self.reason = reason
        self.result = result


class LeashClient:
    def __init__(
        self,
        token: str,
        base_url: str = "http://127.0.0.1:8000",
        http: Optional[httpx.Client] = None,
        raise_on_deny: bool = False,
        timeout: float = 10.0,
    ):
        self.token = token
        self.raise_on_deny = raise_on_deny
        self._http = http if http is not None else httpx.Client(base_url=base_url, timeout=timeout)

    def pay(self, payee: str, amount_paise: int) -> Dict[str, Any]:
        """Request a payment. Returns {"ok", "reason", "txn_id", "audit_seq", "status"}."""
        try:
            resp = self._http.post(
                "/pay",
                json={"payee": payee, "amount_paise": amount_paise},
                headers={"Authorization": f"Bearer {self.token}"},
            )
        except httpx.HTTPError:
            return self._result(False, "GATEWAY_UNREACHABLE", None, {})
        except (TypeError, ValueError):
            return self._result(False, "BAD_REQUEST", None, {})
        try:
            body = resp.json()
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._result(False, "BAD_RESPONSE", resp.status_code, {})
        ok = body.get("allowed") is True and body.get("paid") is True
        return self._result(ok, str(body.get("reason", "UNKNOWN")), resp.status_code, body)

    @staticmethod
    def _result(ok: bool, reason: str, status: Optional[int], body: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ok": ok,
            "reason": reason,
            "txn_id": body.get("txn_id"),
            "audit_seq": body.get("audit_seq"),
            "status": status,
        }

    def guard(self, fn: Optional[Callable] = None, *, raise_on_deny: Optional[bool] = None):
        """Decorator for a tool function that takes `payee` and `amount_paise`.

        By default a denial is returned as a result dict so an LLM agent can read
        the reason. With raise_on_deny (here or on the client) it raises
        LeashDenied instead. `LeashClient.pay` itself always returns a dict.
        """

        def decorate(f: Callable):
            sig = inspect.signature(f)
            for needed in ("payee", "amount_paise"):
                if needed not in sig.parameters:
                    raise TypeError(f"guarded function must accept a '{needed}' parameter")

            @functools.wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                result = self.pay(bound.arguments["payee"], bound.arguments["amount_paise"])
                raising = self.raise_on_deny if raise_on_deny is None else raise_on_deny
                if raising and not result["ok"]:
                    raise LeashDenied(result["reason"], result)
                return result

            return wrapper

        return decorate(fn) if fn is not None else decorate
