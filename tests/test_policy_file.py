from pathlib import Path

import pytest

from leash.policy_file import PolicyFileError, inr_to_paise, load_policy, parse_policy

ROOT = Path(__file__).resolve().parent.parent


def test_example_policy_loads_in_paise():
    p = load_policy(ROOT / "policies" / "grocery_agent.yaml")
    assert p["agent"] == "grocery-agent"
    assert p["per_txn_cap_paise"] == 150_000
    assert p["total_cap_paise"] == 400_000
    assert p["rate_limit"] == 10 and p["rate_window_s"] == 60
    assert p["ttl_s"] == 30 * 60
    assert "bigbasket@okaxis" in p["payees"]


@pytest.mark.parametrize(
    "value,paise",
    [(1, 100), (1500, 150_000), ("12.50", 1_250), (0.1, 10), (99.99, 9_999), (19.9, 1_990)],
)
def test_inr_to_paise_is_exact(value, paise):
    assert inr_to_paise(value) == paise


@pytest.mark.parametrize("bad", [0, -5, 1.005, "abc", True, None, [1], "0.001"])
def test_inr_to_paise_rejects_bad_values(bad):
    with pytest.raises(PolicyFileError):
        inr_to_paise(bad)


def base():
    return {
        "agent": "a",
        "payees": ["x@upi"],
        "limits": {"per_payment_inr": 10, "total_inr": 50},
        "expires_in_minutes": 5,
    }


def test_defaults_for_rate_limit():
    p = parse_policy(base())
    assert (p["rate_limit"], p["rate_window_s"], p["ttl_s"]) == (10, 60, 300)


@pytest.mark.parametrize("missing", ["agent", "payees", "limits", "expires_in_minutes"])
def test_missing_top_level_field(missing):
    doc = base()
    del doc[missing]
    with pytest.raises(PolicyFileError):
        parse_policy(doc)


def test_missing_limit_field():
    doc = base()
    del doc["limits"]["total_inr"]
    with pytest.raises(PolicyFileError):
        parse_policy(doc)


@pytest.mark.parametrize("payees", [[], "x@upi", [1], None])
def test_bad_payees(payees):
    doc = base()
    doc["payees"] = payees
    with pytest.raises(PolicyFileError):
        parse_policy(doc)


def test_non_mapping_document():
    with pytest.raises(PolicyFileError):
        parse_policy(["not", "a", "mapping"])
