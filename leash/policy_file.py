"""Load a human-readable YAML policy (written in rupees) into grant parameters.

Rupee amounts are converted with Decimal, never float, and must have at most
two decimal places.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, Union

import yaml


class PolicyFileError(ValueError):
    pass


def inr_to_paise(value: Any, field: str = "amount") -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise PolicyFileError(f"{field}: expected a rupee amount")
    try:
        dec = Decimal(str(value))
    except InvalidOperation as exc:
        raise PolicyFileError(f"{field}: {value!r} is not a number") from exc
    paise = dec * 100
    if paise != paise.to_integral_value():
        raise PolicyFileError(f"{field}: {value!r} has more than two decimal places")
    if paise <= 0:
        raise PolicyFileError(f"{field}: must be positive")
    return int(paise)


def _require(mapping: Any, key: str, where: str) -> Any:
    if not isinstance(mapping, dict) or key not in mapping:
        raise PolicyFileError(f"missing required field '{key}' in {where}")
    return mapping[key]


def parse_policy(doc: Any) -> Dict[str, Any]:
    """Turn a parsed YAML document into keyword arguments for a new grant."""
    agent = _require(doc, "agent", "policy")
    payees = _require(doc, "payees", "policy")
    limits = _require(doc, "limits", "policy")
    if not isinstance(payees, list) or not payees or not all(isinstance(p, str) for p in payees):
        raise PolicyFileError("payees must be a non-empty list of strings")

    rate = limits.get("rate_limit", {}) if isinstance(limits, dict) else {}
    max_requests = rate.get("max_requests", 10)
    per_seconds = rate.get("per_seconds", 60)
    minutes = _require(doc, "expires_in_minutes", "policy")
    for name, v in (("max_requests", max_requests), ("per_seconds", per_seconds), ("expires_in_minutes", minutes)):
        if type(v) is not int or v <= 0:
            raise PolicyFileError(f"{name} must be a positive integer")

    return {
        "agent": agent,
        "payees": payees,
        "per_txn_cap_paise": inr_to_paise(_require(limits, "per_payment_inr", "limits"), "per_payment_inr"),
        "total_cap_paise": inr_to_paise(_require(limits, "total_inr", "limits"), "total_inr"),
        "rate_limit": max_requests,
        "rate_window_s": per_seconds,
        "ttl_s": minutes * 60,
    }


def load_policy(path: Union[str, Path]) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_policy(yaml.safe_load(fh))
