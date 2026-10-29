# Leash

**A permission and audit layer for AI agents that handle money.**

Instead of giving an agent a powerful, long-lived key, a human gives each agent *run* a narrow, expiring grant: which payees it may pay, how much per payment, how much in total, and how fast. Everything else is blocked by default, and every decision lands in a hash-chained log that shows if anyone edits it.

> **Prototype. Payments are MOCKED.** There is no real UPI or bank integration; the "provider" is an in-memory fake with UPI-style payees and INR amounts, labelled `mock` in every response. The demo agent is scripted, not an LLM.

```
Agent ──token──> Leash gateway ──(only if allowed)──> Payment API (MOCK)
                    │
          policy engine + audit log
```

## Try it in 30 seconds

```bash
pip install -e ".[dev]"
python -m demo.run_demo        # scripted agent hits every control, self-contained
pytest                         # full test suite
```

The demo walks through: a purchase within limits (allowed) → an unlisted merchant (blocked) → an over-cap amount (blocked) → an expired token (blocked) → a hand-edited audit row (flagged at the exact entry) → a mid-run revoke (agent cut off immediately).

### Run the gateway and dashboard

```bash
LEASH_ADMIN_KEY=choose-a-long-random-key \
LEASH_SECRET=choose-another-long-random-secret \
python -m leash --db leash.db --port 8000
# open http://127.0.0.1:8000/ and paste the admin key
```

If you don't set those two variables, random ones are generated and printed at startup (tokens then won't survive a restart).

Run the demo against it (and tamper with its database for real):

```bash
python -m demo.run_demo --url http://127.0.0.1:8000 --admin-key choose-a-long-random-key --db leash.db
```

The dashboard shows grants, a live action feed with blocked actions highlighted, a **Verify audit log** button and a **Revoke** button.

## Using it from an agent

```python
from leash.sdk import LeashClient

leash = LeashClient(token=os.environ["LEASH_TOKEN"], base_url="http://127.0.0.1:8000")

@leash.guard
def pay(payee: str, amount_paise: int):
    """Pay a merchant. Amount is in paise (1 INR = 100 paise)."""

pay("bigbasket@okaxis", 45_000)   # {"ok": True, "reason": "ALLOWED", "txn_id": "mock_txn_…", …}
pay("unknown@upi", 100)           # {"ok": False, "reason": "PAYEE_NOT_ALLOWED", …}
```

The decorated function's body never runs: the gateway makes the payment, so the agent never holds a payment credential. Denials come back as a result dict an LLM can read (or raise `LeashDenied` with `raise_on_deny=True`). An unreachable gateway is a denial too.

Grants are written in rupees in a readable YAML file ([`policies/grocery_agent.yaml`](policies/grocery_agent.yaml)) and loaded with `leash.policy_file.load_policy`, which converts to paise exactly (no floats).

## How a request is decided

1. **Grant**: a human creates a grant (`POST /grants`, admin key) and gets back a signed token.
2. **Request**: the agent sends each payment to `POST /pay` with `Authorization: Bearer <token>`.
3. **Checks**, in this fixed order; the first failure decides the reason code:

   | # | Check | Reason code |
   |---|-------|-------------|
   | 1 | Grant revoked? | `REVOKED` |
   | 2 | Grant (or token) expired? | `EXPIRED` |
   | 3 | Amount a positive integer number of paise? | `INVALID_AMOUNT` |
   | 4 | Payee on the allowlist? (exact, case-insensitive, no wildcards) | `PAYEE_NOT_ALLOWED` |
   | 5 | At or under the per-payment cap? | `OVER_TXN_CAP` |
   | 6 | Would the total stay at or under the cumulative cap? | `OVER_TOTAL_CAP` |
   | 7 | Under the rate limit? (blocked attempts count too) | `RATE_LIMITED` |

   Other codes: `GRANT_NOT_FOUND`, `INTERNAL_ERROR` (anything unexpected is denied: fail closed).
4. **Decision**: allowed requests are forwarded to the provider; blocked ones get a reason code. Both are logged.
5. **Audit**: each entry includes the hash of the previous one. `GET /audit/verify` walks the chain and reports the first bad entry.

### API

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /pay` | grant token | Request a payment |
| `POST /grants` | admin key | Create a grant, returns the token |
| `GET /grants` | admin key | List grants with spend and status |
| `POST /grants/{id}/revoke` | admin key | Revoke immediately |
| `GET /audit` | admin key | Read audit entries |
| `GET /audit/verify` | none | Verify the chain (optionally against an anchor) |
| `GET /audit/head` | none | Latest `{seq, hash}`, for external anchoring |
| `GET /mock/payments` | admin key | What the mock provider received |
| `GET /` | none | Dashboard |

## Design decisions

- **Default deny.** A request is allowed only if every check passes.
- **Integer paise.** Limits never depend on floating-point arithmetic; floats, strings and booleans are rejected as amounts.
- **Pure policy engine** (`leash/policy.py`): no I/O, no clock, so every rule is trivially testable.
- **Atomic decide-and-record.** The check, the spend ledger and the audit entry are written in one `BEGIN IMMEDIATE` transaction, so simultaneous requests cannot overspend a cap. A test fires 20 concurrent requests at a cap that allows exactly five and asserts exactly five succeed.
- **Exact payee matching.** Lookalikes (`okaxls`, trailing spaces, Cyrillic letters, the Kelvin sign) are blocked. Non-ASCII payees are rejected outright.
- **Signed tokens** (HMAC-SHA256) carry a grant id and expiry. Forged signatures, extended expiries and malformed tokens are rejected before any parsing of the payload.
- **Bad requests are logged too.** Wrong amounts and payees reach the policy engine so they get a reason code and an audit entry, with untrusted values truncated.

## Honest limits

- **Tamper-evident, not tamper-proof.** A hash chain shows edits, deletions, insertions and reordering. Someone with full database access could rewrite the *entire* chain consistently, or truncate the tail, and a plain `verify` would pass. Keep the latest `GET /audit/head` somewhere external (a different system, a printed line, a signed message) and pass it to `verify` as `anchor_seq`/`anchor_hash`: that catches both. **Automatic external anchoring is not built yet.**
- **Payments are mocked.** No real UPI, bank or payment-provider integration.
- **If the provider call fails after an allow**, the gateway returns 502 and the spend still counts against the grant (conservative). There is no reconciliation or retry logic.
- **Unauthenticated requests are not logged** (bad or missing tokens), so anyone who can reach the gateway can't flood the audit log. The cost: forged-token attempts leave no trace in it.
- **Admin auth is one shared key**, compared in constant time. No login system, users or multi-tenancy.
- **Single node, SQLite.** The spend ledger (`attempts` table) is not itself hash-chained; the audit log is.
- **The demo agent is scripted**, not LLM-driven.
- Only test against systems you own or have written permission to test.

## Layout

```
leash/policy.py       pure decision logic and reason codes
leash/tokens.py       HMAC-signed grant tokens
leash/store.py        SQLite grants, attempt ledger, atomic decide-and-record
leash/audit.py        hash-chained log, verify, anchoring
leash/gateway.py      FastAPI service
leash/mock_provider.py  fake UPI-style provider (MOCK)
leash/sdk.py          @leash.guard decorator
leash/policy_file.py  rupee YAML -> grant parameters
leash/static/dashboard.html
policies/             example policy
demo/                 run_demo.py (the 2-minute demo), tamper.py
tests/                pytest suite
```

## Roadmap

Human approval step above a threshold · automatic external anchoring of the audit head · an LLM-driven demo agent · test-mode integration with a real payment provider · reconciliation of provider results against grants.

## License

MIT, see [LICENSE](LICENSE).
