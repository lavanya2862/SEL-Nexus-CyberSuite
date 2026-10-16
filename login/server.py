"""SEL Nexus CyberSuite sign-in page: one login in front of the suite's modules.

    .venv\\Scripts\\python.exe server.py            # http://127.0.0.1:8000

After sign-in the page shows one button per module (config/login.env). The session cookie it sets is the one every
module on 127.0.0.1 checks (see accounts.py), so people sign in once.

API (all JSON):
  GET  /api/health          is the page up
  GET  /api/config          modules, sign-up on or off, password rule (nothing secret)
  GET  /api/me              who is signed in (null if nobody)
  POST /api/login           {email, password}            -> sets the cookie
  POST /api/signup          {name, email, password}      -> creates the account and sets the cookie
  POST /api/logout                                       -> clears the cookie (signs out of every module)
The POSTs need the header X-CyberSuite: auth, which a form on another website cannot send.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Header, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from accounts import COOKIE, PASSWORD_RULE, Accounts, AuthError

HERE = Path(__file__).resolve().parent


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.split(" #", 1)[0].strip().strip('"')
    return values


def _on(value: str | None, default: bool) -> bool:
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def load_settings() -> dict:
    env = {**_load_env_file(HERE / "config" / "login.env"), **os.environ}
    return {
        "port": int(env.get("LOGIN_PORT", 8000)),
        "session_hours": int(env.get("LOGIN_SESSION_HOURS", 12)),
        "signup_open": _on(env.get("LOGIN_SIGNUP"), True),
        "cookie_secure": _on(env.get("LOGIN_COOKIE_SECURE"), False),
        "allowed_email_domains": tuple(d.strip().lower().lstrip("@") for d in env.get("LOGIN_ALLOWED_EMAIL_DOMAINS", "").split(",")
                                       if d.strip()),
        "modules": [
            {"id": "defender_infra", "name": "Defender & Infrastructure",
             "description": "Threat intelligence, vulnerabilities, fixes and alert triage from Microsoft Defender.",
             "url": env.get("DEFENDER_INFRA_URL", "http://127.0.0.1:8800").rstrip("/")},
            {"id": "code_vulnerabilities", "name": "Code Vulnerabilities",
             "description": "Security flaws found in our application source code, and how to fix them.",
             "url": env.get("CODE_VULN_URL", "").rstrip("/")},
        ],
    }


def create_app(settings: dict | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="SEL Nexus CyberSuite sign-in", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])
    accounts = Accounts(HERE / "data" / "auth", settings["session_hours"], settings["signup_open"],
                        settings["allowed_email_domains"])

    def signed_in(user: dict) -> JSONResponse:
        token = accounts.sessions.issue(user["email"], user["name"])
        out = JSONResponse({"user": accounts.sessions.read(token)})
        out.set_cookie(COOKIE, token, max_age=settings["session_hours"] * 3600, httponly=True, samesite="lax",
                       secure=settings["cookie_secure"], path="/")
        return out

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True}

    @app.get("/api/config")
    def config() -> dict:
        return {"signup_open": settings["signup_open"], "password_rule": PASSWORD_RULE,
                "allowed_email_domains": list(settings["allowed_email_domains"]), "modules": settings["modules"]}

    @app.get("/api/me")
    def me(request: Request) -> dict:
        return {"user": accounts.sessions.read(request.cookies.get(COOKIE))}

    @app.post("/api/{action}")
    async def action(action: str, request: Request, x_cybersuite: str | None = Header(default=None)):
        ip = request.client.host if request.client else None
        if x_cybersuite != "auth":
            return JSONResponse({"error": "Missing X-CyberSuite header."}, status_code=400)
        if action == "logout":
            user = accounts.sessions.read(request.cookies.get(COOKIE))
            if user:
                accounts.log("logout", user["email"], True, ip)
            out = JSONResponse({"user": None})
            out.delete_cookie(COOKIE, path="/", httponly=True, samesite="lax", secure=settings["cookie_secure"])
            return out
        handlers = {"login": accounts.login, "signup": accounts.signup}
        if action not in handlers:
            return JSONResponse({"error": "Unknown action."}, status_code=404)
        try:
            body = await request.json()
            if not isinstance(body, dict):
                raise AuthError("Send a JSON object.")
            user = handlers[action](body)
        except AuthError as exc:
            accounts.log(action, str(body.get("email") or "")[:254].lower() if isinstance(body, dict) else "", False, ip, str(exc))
            return JSONResponse({"error": str(exc)}, status_code=exc.status)
        except ValueError:
            return JSONResponse({"error": "Send a JSON object."}, status_code=400)
        accounts.log(action, user["email"], True, ip)
        return signed_in(user)

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.get("/", include_in_schema=False)
    def page() -> FileResponse:
        return FileResponse(HERE / "static" / "index.html", headers={"Cache-Control": "no-cache"})

    return app


def main() -> None:
    settings = load_settings()
    parser = argparse.ArgumentParser(description="SEL Nexus CyberSuite sign-in page")
    parser.add_argument("--port", type=int, default=settings["port"])
    args = parser.parse_args()
    uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
