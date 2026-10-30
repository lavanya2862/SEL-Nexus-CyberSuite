"""`python -m dashboard serve [--port 8800] [--reload]` — start the portal API (+ built web app)."""
from __future__ import annotations

import argparse

import uvicorn

from dashboard.config import load_settings
from dashboard.services import start_watcher


def main() -> None:
    parser = argparse.ArgumentParser(prog="dashboard", description="Unified Cyber Portal")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="start the portal on 127.0.0.1")
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true", help="restart on code changes (development)")
    args = parser.parse_args()

    settings = load_settings()
    if args.command == "serve":
        start_watcher(settings)   # keeps the fixing and alert-triage services running (PORTAL_AUTOSTART=0 to switch off)
        uvicorn.run("dashboard.app:create_app", factory=True, host=settings.host, port=args.port or settings.port,
                    reload=args.reload, log_level="info")


if __name__ == "__main__":
    main()
