import sqlite3

import pytest

from leash import audit
from leash.store import Store

NOW = 1_800_000_000.0


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "a.db")
    g = s.create_grant("a", ["shop@upi"], 1_000, 5_000, now=NOW)
    for i in range(5):
        s.decide_and_record(g["id"], "shop@upi" if i % 2 == 0 else "evil@upi", 500, now=NOW + i)
    return s  # entries: 1 grant_created + 5 decisions


def raw(store):
    conn = sqlite3.connect(store.path)
    conn.row_factory = sqlite3.Row
    return conn


def test_empty_log_verifies(tmp_path):
    result = Store(tmp_path / "e.db").verify_audit()
    assert result["ok"] and result["entries"] == 0 and result["head"] is None


def test_intact_chain_verifies(store):
    result = store.verify_audit()
    assert result["ok"] and result["entries"] == 6
    assert result["head"]["seq"] == 6 and result["bad_seq"] is None


def test_entries_are_linked(store):
    entries = store.audit_entries(limit=100)
    assert entries[0]["prev_hash"] == audit.GENESIS
    for a, b in zip(entries, entries[1:]):
        assert b["prev_hash"] == a["hash"]


def test_edit_flags_the_exact_entry(store):
    c = raw(store)
    c.execute(
        "UPDATE audit SET data = replace(data, '\"allowed\":false', '\"allowed\":true') WHERE seq = 3"
    )
    c.commit()
    result = store.verify_audit()
    assert not result["ok"] and result["bad_seq"] == 3
    assert "edited" in result["reason"]


@pytest.mark.parametrize("column,value", [("event", "grant_revoked"), ("grant_id", "other"), ("ts_us", 1)])
def test_editing_any_field_is_detected(store, column, value):
    c = raw(store)
    c.execute(f"UPDATE audit SET {column} = ? WHERE seq = 4", (value,))
    c.commit()
    result = store.verify_audit()
    assert not result["ok"] and result["bad_seq"] == 4


def test_deleted_middle_entry_is_detected(store):
    c = raw(store)
    c.execute("DELETE FROM audit WHERE seq = 3")
    c.commit()
    result = store.verify_audit()
    assert not result["ok"] and result["bad_seq"] == 3 and "missing" in result["reason"]


def test_deleted_first_entry_is_detected(store):
    c = raw(store)
    c.execute("DELETE FROM audit WHERE seq = 1")
    c.commit()
    result = store.verify_audit()
    assert not result["ok"] and result["bad_seq"] == 1


def test_inserted_fake_entry_is_detected(store):
    c = raw(store)
    c.execute(
        "INSERT INTO audit(seq, ts_us, event, grant_id, data, prev_hash, hash) VALUES (99,0,'x',NULL,'{}','a','b')"
    )
    c.commit()
    assert not store.verify_audit()["ok"]


def test_rewriting_an_entry_with_a_fresh_hash_is_still_caught(store):
    # A smarter attacker edits entry 3 AND recomputes its hash. The link stored
    # in entry 4 no longer matches, so the break is still found at entry 3.
    c = raw(store)
    row = c.execute("SELECT * FROM audit WHERE seq = 3").fetchone()
    new_data = row["data"].replace('"allowed":false', '"allowed":true')
    new_hash = audit.compute_hash(3, row["prev_hash"], row["ts_us"], row["event"], row["grant_id"], new_data)
    c.execute("UPDATE audit SET data=?, hash=? WHERE seq=3", (new_data, new_hash))
    c.commit()
    result = store.verify_audit()
    assert not result["ok"] and result["bad_seq"] == 3


def test_reordered_entries_are_detected(store):
    c = raw(store)
    c.execute("UPDATE audit SET seq = 100 WHERE seq = 2")
    c.execute("UPDATE audit SET seq = 2 WHERE seq = 3")
    c.execute("UPDATE audit SET seq = 3 WHERE seq = 100")
    c.commit()
    assert not store.verify_audit()["ok"]


def test_limitation_tail_truncation_is_not_detected_without_an_anchor(store):
    # Documented limit: a hash chain alone cannot see entries removed from the end.
    c = raw(store)
    c.execute("DELETE FROM audit WHERE seq > 4")
    c.commit()
    assert store.verify_audit()["ok"]


def test_anchor_catches_tail_truncation(store):
    anchor = store.audit_head()
    c = raw(store)
    c.execute("DELETE FROM audit WHERE seq > 4")
    c.commit()
    result = store.verify_audit(anchor=anchor)
    assert not result["ok"] and "truncated" in result["reason"]


def test_anchor_catches_wholesale_rewrite(store):
    anchor = store.audit_head()
    c = raw(store)
    rows = c.execute("SELECT * FROM audit ORDER BY seq").fetchall()
    c.execute("DELETE FROM audit")
    prev = audit.GENESIS
    for r in rows:
        data = r["data"].replace('"allowed":false', '"allowed":true')
        h = audit.compute_hash(r["seq"], prev, r["ts_us"], r["event"], r["grant_id"], data)
        c.execute(
            "INSERT INTO audit VALUES (?,?,?,?,?,?,?)",
            (r["seq"], r["ts_us"], r["event"], r["grant_id"], data, prev, h),
        )
        prev = h
    c.commit()
    assert store.verify_audit()["ok"]  # internally consistent, so the plain check passes
    assert not store.verify_audit(anchor=anchor)["ok"]  # but it no longer matches the anchor


def test_valid_anchor_passes(store):
    anchor = store.audit_head()
    store.record_event("note", None, {"x": 1}, now=NOW + 99)
    assert store.verify_audit(anchor=anchor)["ok"]


def test_read_pagination(store):
    assert [e["seq"] for e in store.audit_entries(limit=2)] == [5, 6]
    assert [e["seq"] for e in store.audit_entries(limit=100, after_seq=4)] == [5, 6]
