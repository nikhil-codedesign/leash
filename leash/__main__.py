"""Run the gateway: python -m leash --db leash.db --port 8000"""

from __future__ import annotations

import argparse
import logging
import os
import secrets

import uvicorn

from .gateway import create_app


def main() -> None:
    ap = argparse.ArgumentParser(prog="leash", description="Leash gateway (MOCK payments only)")
    ap.add_argument("--db", default="leash.db")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO)
    if not os.environ.get("LEASH_ADMIN_KEY"):
        key = secrets.token_urlsafe(24)
        os.environ["LEASH_ADMIN_KEY"] = key
        print(f"\nLEASH_ADMIN_KEY not set. Generated for this run:\n  {key}\n")
    if not os.environ.get("LEASH_SECRET"):
        os.environ["LEASH_SECRET"] = secrets.token_hex(32)
        print("LEASH_SECRET not set. Using a random one; tokens will not survive a restart.\n")

    print(f"Dashboard: http://{args.host}:{args.port}/   (payments are MOCK)\n")
    uvicorn.run(create_app(args.db), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
