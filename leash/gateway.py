"""FastAPI gateway.

Agents call POST /pay with a signed grant token. Humans (admin key) create and
revoke grants and read the audit log. Payments are forwarded to a MOCK
provider only after the policy engine allows them.
"""

from __future__ import annotations

import logging
import math
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Optional, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, StrictInt

from . import policy, tokens
from .mock_provider import MockProvider
from .store import Store

log = logging.getLogger("leash")
STATIC = Path(__file__).parent / "static"

_CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'"
)


class GrantBody(BaseModel):
    agent: str = Field(min_length=1, max_length=128)
    payees: list[str] = Field(min_length=1, max_length=500)
    per_txn_cap_paise: StrictInt
    total_cap_paise: StrictInt
    rate_limit: StrictInt = 10
    rate_window_s: StrictInt = 60
    ttl_s: StrictInt = 900


class PayBody(BaseModel):
    # Deliberately `Any`: the policy engine, not the JSON parser, decides what
    # is a valid payee/amount, so bad values are blocked AND logged with a
    # reason code instead of being rejected before they reach the audit log.
    payee: Any
    amount_paise: Any


def create_app(
    db_path: Union[str, Path] = "leash.db",
    secret: Optional[str] = None,
    admin_key: Optional[str] = None,
    provider: Optional[Any] = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    secret = secret or os.environ.get("LEASH_SECRET")
    if not secret:
        secret = secrets.token_hex(32)
        log.warning("LEASH_SECRET not set: using a random one; issued tokens die on restart")
    admin_key = admin_key or os.environ.get("LEASH_ADMIN_KEY")
    if not admin_key:
        admin_key = secrets.token_urlsafe(24)
        log.warning("LEASH_ADMIN_KEY not set: generated one for this process: %s", admin_key)

    store = Store(db_path)
    provider = provider if provider is not None else MockProvider()

    app = FastAPI(title="Leash", version="0.1.0", description="Permission and audit layer for AI agents that handle money. MOCK payments only.")
    app.state.store = store
    app.state.provider = provider
    app.state.admin_key = admin_key

    def require_admin(x_admin_key: Optional[str] = Header(default=None)) -> None:
        if x_admin_key is None or not secrets.compare_digest(
            x_admin_key.encode("utf-8"), admin_key.encode("utf-8")
        ):
            raise HTTPException(status_code=401, detail="admin key required (X-Admin-Key header)")

    def deny(status: int, reason: str, **extra: Any) -> JSONResponse:
        return JSONResponse(status_code=status, content={"allowed": False, "paid": False, "reason": reason, **extra})

    # -- agent-facing ----------------------------------------------------
    @app.post("/pay")
    def pay(body: PayBody, authorization: Optional[str] = Header(default=None)):
        parts = (authorization or "").split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return deny(401, "BAD_TOKEN")
        try:
            claims = tokens.verify(parts[1].strip(), secret)
        except tokens.TokenError:
            # Unauthenticated noise is rejected without being written, so
            # anyone who can reach the gateway cannot flood the audit log.
            return deny(401, "BAD_TOKEN")

        try:
            outcome = store.decide_and_record(
                claims["gid"], body.payee, body.amount_paise, now=clock(), token_exp=claims["exp"]
            )
        except Exception:
            log.exception("decide_and_record failed; denying (fail closed)")
            return deny(500, policy.INTERNAL_ERROR)

        decision = outcome.decision
        if not decision.allowed:
            status = 429 if decision.reason == policy.RATE_LIMITED else 403
            return deny(status, decision.reason, audit_seq=outcome.audit_seq)

        try:
            result = provider.pay(body.payee, body.amount_paise)
        except Exception:
            log.exception("payment provider failed")
            try:
                store.record_event(
                    "provider_error",
                    claims["gid"],
                    {"amount_paise": body.amount_paise, "decision_seq": outcome.audit_seq},
                    now=clock(),
                )
            except Exception:
                log.exception("could not record provider_error")
            # The spend still counts against the grant (conservative).
            return JSONResponse(
                status_code=502,
                content={"allowed": True, "paid": False, "reason": "PROVIDER_ERROR", "audit_seq": outcome.audit_seq},
            )
        return {
            "allowed": True,
            "paid": True,
            "reason": policy.ALLOWED,
            "txn_id": result["txn_id"],
            "provider": getattr(provider, "name", "unknown"),
            "audit_seq": outcome.audit_seq,
        }

    # -- human/admin-facing ----------------------------------------------
    @app.post("/grants", status_code=201, dependencies=[Depends(require_admin)])
    def create_grant(body: GrantBody):
        try:
            grant = store.create_grant(
                agent=body.agent,
                payees=body.payees,
                per_txn_cap_paise=body.per_txn_cap_paise,
                total_cap_paise=body.total_cap_paise,
                rate_limit=body.rate_limit,
                rate_window_s=body.rate_window_s,
                ttl_s=body.ttl_s,
                now=clock(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        token = tokens.issue(grant["id"], math.ceil(grant["expires_at"]), secret)
        return {"grant": grant, "token": token}

    @app.get("/grants", dependencies=[Depends(require_admin)])
    def list_grants():
        return {"grants": store.list_grants(now=clock())}

    @app.post("/grants/{grant_id}/revoke", dependencies=[Depends(require_admin)])
    def revoke(grant_id: str):
        try:
            return {"grant": store.revoke_grant(grant_id, now=clock())}
        except KeyError:
            raise HTTPException(status_code=404, detail="grant not found")

    @app.get("/audit", dependencies=[Depends(require_admin)])
    def audit_log(limit: int = Query(100, ge=1, le=1000), after_seq: int = Query(0, ge=0)):
        return {"entries": store.audit_entries(limit=limit, after_seq=after_seq)}

    @app.get("/audit/head")
    def audit_head():
        return {"head": store.audit_head()}

    @app.get("/audit/verify")
    def audit_verify(
        anchor_seq: Optional[int] = Query(None, ge=1),
        anchor_hash: Optional[str] = Query(None, min_length=64, max_length=64),
    ):
        if (anchor_seq is None) != (anchor_hash is None):
            raise HTTPException(status_code=422, detail="give both anchor_seq and anchor_hash, or neither")
        anchor = None if anchor_seq is None else {"seq": anchor_seq, "hash": anchor_hash}
        return store.verify_audit(anchor=anchor)

    @app.get("/mock/payments", dependencies=[Depends(require_admin)])
    def mock_payments():
        if not hasattr(provider, "payments"):
            raise HTTPException(status_code=404, detail="provider does not expose payments")
        return {"mock": True, "payments": provider.payments()}

    @app.get("/health")
    def health():
        return {"ok": True, "provider": getattr(provider, "name", "unknown"), "mock_payments": True}

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard():
        html = (STATIC / "dashboard.html").read_text(encoding="utf-8")
        return HTMLResponse(html, headers={"Content-Security-Policy": _CSP, "X-Content-Type-Options": "nosniff"})

    return app
