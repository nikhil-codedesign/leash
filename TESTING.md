# Testing Leash

Thanks for trying this. It takes about 10 minutes, and honest feedback ("this was confusing", "I'd never use this because…") is exactly what I'm after.

**What Leash is:** a permission and audit layer for AI agents that handle money. Instead of giving an agent a long-lived key, a human gives each run a narrow, expiring grant (which payees, how much per payment, how much total, how fast). Anything outside it is blocked, and every decision goes into a hash-chained log that shows if anyone edits it.

**Important:** payments are **mocked**. No real UPI, bank or payment system is involved, and no real money moves. The demo agent is a script, not an LLM.

You need Python 3.10 or newer.

## 1. Install (2 minutes)

```bash
git clone https://github.com/nikhil-codedesign/leash.git
cd leash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Optional sanity check: `pytest` (a browser test is skipped unless Playwright is installed; that's fine).

## 2. Watch the demo (1 minute)

```bash
python -m demo.run_demo
```

A scripted grocery agent works through six situations: a purchase within its limits (allowed), an unlisted merchant (blocked), an over-limit amount (blocked), an expired token (blocked), someone hand-editing the audit log (caught at the exact entry), and the grant being revoked mid-run (agent cut off immediately).

## 3. See it in the dashboard (3 minutes)

Terminal 1 (leave running):

```bash
python -m leash --db leash.db --port 8000
```

It prints an **admin key**. Open http://127.0.0.1:8000/, paste the key, click **Connect**.

Terminal 2 (same folder, venv active), replacing `<KEY>`:

```bash
python -m demo.run_demo --url http://127.0.0.1:8000 --admin-key <KEY> --db leash.db
```

Watch the grants and action feed fill in (blocked actions are red). Then click **Verify audit log**: the demo edited one row behind the gateway's back, and Leash points at exactly that entry.

## 4. Optional but most valuable: try it on your own agent

With the gateway from step 3 running, create a grant (this prints a token):

```python
import httpx
r = httpx.post(
    "http://127.0.0.1:8000/grants",
    headers={"X-Admin-Key": "<KEY>"},
    json={
        "agent": "my-agent",
        "payees": ["shop@upi"],        # exact match only, no wildcards
        "per_txn_cap_paise": 50_000,   # Rs 500.00 per payment (1 INR = 100 paise)
        "total_cap_paise": 200_000,    # Rs 2,000.00 total
        "ttl_s": 1800,                 # expires in 30 minutes
    },
)
print(r.json()["token"])
```

Then give your agent's payment tool a guard:

```python
from leash.sdk import LeashClient

leash = LeashClient(token="<TOKEN>", base_url="http://127.0.0.1:8000")

@leash.guard
def pay(payee: str, amount_paise: int):
    """Pay a merchant. Amount is in paise (1 INR = 100 paise)."""

pay("shop@upi", 10_000)      # allowed (mock)
pay("someone@upi", 10_000)   # blocked: PAYEE_NOT_ALLOWED
```

The function body never runs; the gateway makes the (mock) payment. Denials come back as a result an agent can read, with a reason code.

## Things worth trying to break

- Pay a payee that *looks* like an allowed one (`shop@upl`, a trailing space, different capitalisation).
- Send a negative amount, `0`, `1.5`, or a string.
- Fire many requests quickly (rate limit), or hit the total cap.
- Revoke a grant in the dashboard, then try to pay with its token.
- Edit a row in `leash.db` yourself (`sqlite3 leash.db`) and press **Verify audit log**.

## Feedback

Please [open a "Tester feedback" issue](https://github.com/nikhil-codedesign/leash/issues/new?template=tester-feedback.yml), or reply to whoever sent you this. Useful things to tell me:

1. Where did you get stuck or confused? (Install, the demo, the dashboard, the words I use.)
2. Does this match a problem you actually have with agents and money or API access? How do you handle it today?
3. Would you use something like this? What would have to be true first?
4. What's missing, and what feels pointless?

You can be blunt. Quotes are more useful to me than polite summaries; tell me if you'd rather I don't quote you.

## Known limits (so you don't have to discover them)

- Payments are mocked; there is no real payment-provider integration.
- The audit log is **tamper-evident, not tamper-proof**: someone with full database access could rewrite the whole chain consistently unless you keep the latest head (`GET /audit/head`) somewhere external and verify against it. Automatic external anchoring isn't built yet.
- Single node, SQLite, one shared admin key. No users or login.
- The demo agent is scripted, not LLM-driven.
