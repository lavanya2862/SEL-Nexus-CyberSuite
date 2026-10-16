"""Portal API (FastAPI). Serves /api/* and, in production, the built React app from web/dist.

Security (same spirit as the UC1/UC3 sites): listens on 127.0.0.1 only and rejects any Host header that is not
this machine (blocks DNS-rebinding tricks). Data endpoints are read-only; POST /api/runs/{uc} starts a real
pipeline run and needs the X-Portal: run header. /api/fix* forwards the Fix Centre to UC1's own fix engine
(UC1's website API) and its POSTs need the X-Portal: fix header. /api/uc4/* reads UC4's triage exports; the
analyst's agree/disagree click is forwarded to UC4's own website API and needs the X-Portal: feedback header.
POST /api/help/ask (header X-Portal: help) answers the help chatbot's free questions from the portal's own read-only
data with Gemini; it never acts. The portal itself never isolates a device or closes an incident; POST /api/uc4/reopen (X-Portal: reopen) lets a
person undo an automatic close. (UC4 may close or escalate lab incidents by itself
when its own UC4_AUTO_RESOLVE setting is on; the portal shows what it did and links to UC4's Reopen.)

Sign-in (auth.py): every /api/* call except /api/health and /api/auth/* needs a valid portal_session cookie, or gets
401. The cookie comes from /api/auth/login or /signup (local accounts) or /api/auth/cognito (Amazon Cognito ID
token); their POSTs need the X-Portal: auth header. PORTAL_AUTH=off switches sign-in off (tests).
"""
from __future__ import annotations

import os
import re

from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from portal import devicenames, fixproxy, helpbot, helpready, notifications, services, uc4proxy
from portal.auth import COOKIE, Auth, AuthError
from portal.config import PORTAL_DIR, Settings, _load_env_file, load_settings
from portal.runs import RunManager
from portal.sources import UC1, UC3, UC4
from portal.summary import build_summary


UCS = ("uc1", "uc3", "uc4", "attack")     # attack = the Attack Detection Agent (UC1's attack-check run)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="Defender & Infrastructure API (SEL Nexus CyberSuite)", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])

    secrets_env = {**_load_env_file(PORTAL_DIR / "config" / "portal.secrets.env"), **os.environ}
    auth = Auth(settings, secrets_env.get("PORTAL_SESSION_SECRET") or None)
    app.state.auth = auth

    @app.middleware("http")
    async def require_sign_in(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and path != "/api/health" and not path.startswith("/api/auth/"):
            user = auth.current_user(request.cookies.get(COOKIE))
            if user is None:
                return JSONResponse({"error": "Please sign in", "signed_out": True}, status_code=401)
            request.state.user = user
        return await call_next(request)

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True}

    # ---- Sign-in (see auth.py)
    def _signed_in(user: dict, event: str, request: Request) -> JSONResponse:
        auth.log(event, user["email"], True, request.client.host if request.client else None)
        token = auth.issue(user)
        out = JSONResponse({"user": auth.current_user(token)})
        out.set_cookie(COOKIE, token, max_age=settings.session_hours * 3600, httponly=True, samesite="lax",
                       secure=settings.cookie_secure, path="/")
        return out

    async def _auth_body(request: Request, x_portal: str | None) -> dict:
        if x_portal != "auth":
            raise AuthError("missing header", 403)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        return body if isinstance(body, dict) else {}

    @app.get("/api/auth/config")
    def auth_config() -> dict:
        return auth.public_config()

    @app.get("/api/auth/me")
    def auth_me(request: Request) -> dict:
        return {"user": auth.current_user(request.cookies.get(COOKIE)), "mode": auth.mode}

    @app.post("/api/auth/{action}")
    async def auth_action(action: str, request: Request, x_portal: str | None = Header(default=None)):
        """login / signup (local accounts), cognito (exchange a Cognito ID token), logout."""
        ip = request.client.host if request.client else None
        if action == "logout":
            user = auth.current_user(request.cookies.get(COOKIE))
            if user and auth.mode != "off":
                auth.log("logout", user["email"], True, ip)
            out = JSONResponse({"user": None})
            out.delete_cookie(COOKIE, path="/", httponly=True, samesite="lax", secure=settings.cookie_secure)
            return out
        handlers = {"login": auth.login, "signup": auth.signup, "cognito": auth.cognito}
        if action not in handlers:
            return JSONResponse({"error": "not found"}, status_code=404)
        body: dict = {}
        try:
            body = await _auth_body(request, x_portal)
            user = handlers[action](body)
        except AuthError as exc:
            if str(exc) != "missing header":
                auth.log(action, str(body.get("email") or "")[:254].lower(), False, ip, str(exc))
            return JSONResponse({"error": str(exc)}, status_code=exc.status)
        return _signed_in(user, action, request)

    @app.get("/api/summary")
    def summary() -> dict:
        return build_summary(settings)

    @app.get("/api/device-names")
    def device_names() -> dict:
        """Friendly names shown instead of the real computer names (config/device_names.csv)."""
        return devicenames.load()

    @app.get("/api/uc3/dashboard")
    def uc3_dashboard():
        data = UC3(settings.uc3_dir).dashboard()
        if data is None:
            return JSONResponse({"error": "Vulnerability data is not built yet: run the vulnerability update"}, status_code=404)
        return data

    @app.get("/api/uc1/dashboard")
    def uc1_dashboard():
        data = UC1(settings.uc1_dir).dashboard()
        if data is None:
            return JSONResponse({"error": "Threat data is not built yet: run the threat check"}, status_code=404)
        return data

    @app.get("/api/uc1/clues")
    def uc1_clues():
        data = UC1(settings.uc1_dir).clues()
        if data is None:
            return JSONResponse({"error": "The clue list is not built yet: run the Threat Intel Agent"}, status_code=404)
        return data

    @app.get("/api/uc1/threats/{threat_id:path}")
    def uc1_threat(threat_id: str):
        data = UC1(settings.uc1_dir).threat(threat_id)
        if data is None:
            return JSONResponse({"error": "threat not found"}, status_code=404)
        return data

    # ---- Fix Centre: UC1's fix engine, reached through UC1's own website API (see fixproxy.py)
    @app.get("/api/fix")
    def fix_view():
        try:
            return fixproxy.get_fix(settings.uc1_site)
        except fixproxy.Uc1Unavailable as exc:
            return JSONResponse({"error": str(exc), "uc1_down": True}, status_code=503)

    @app.post("/api/fix/start-uc1")
    def fix_start_uc1(x_portal: str | None = Header(default=None)):
        if x_portal != "fix":
            return JSONResponse({"error": "missing header"}, status_code=403)
        try:
            ok = services.start_one(settings, "fixing")
        except fixproxy.Uc1Unavailable as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)
        return JSONResponse({"started": ok}, status_code=200 if ok else 504)

    @app.post("/api/fix/{action}")
    async def fix_action(action: str, request: Request, x_portal: str | None = Header(default=None)):
        """Approve / withdraw / run / check. Needs X-Portal: fix (a plain link or another website cannot press it)."""
        if x_portal != "fix":
            return JSONResponse({"error": "missing header"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        try:
            status, out = fixproxy.post_fix(settings.uc1_site, action, body if isinstance(body, dict) else {})
        except fixproxy.Uc1Unavailable as exc:
            return JSONResponse({"error": str(exc), "uc1_down": True}, status_code=503)
        return JSONResponse(out, status_code=status)

    # ---- Triage (UC4): read its exports; agree/disagree goes to UC4's own website API (see uc4proxy.py)
    @app.get("/api/uc4/queue")
    def uc4_queue():
        data = UC4(settings.uc4_dir).queue()
        if data is None:
            return JSONResponse({"error": "Nothing triaged yet: run the triage check"}, status_code=404)
        data["site_up"] = uc4proxy.site_up(settings.uc4_site)
        data["site_url"] = settings.uc4_site
        return data

    @app.get("/api/uc4/cases/{incident_id}")
    def uc4_case(incident_id: str):
        data = UC4(settings.uc4_dir).case(incident_id)
        if data is None:
            return JSONResponse({"error": "case not found"}, status_code=404)
        data["site_up"] = uc4proxy.site_up(settings.uc4_site)
        data["site_url"] = settings.uc4_site
        return data

    @app.get("/api/uc4/quality")
    def uc4_quality():
        uc4 = UC4(settings.uc4_dir)
        return {"metrics": uc4.metrics(), "backtest": uc4.backtest()}

    @app.post("/api/uc4/feedback")
    async def uc4_feedback(request: Request, x_portal: str | None = Header(default=None)):
        if x_portal != "feedback":
            return JSONResponse({"error": "missing header"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        try:
            status, out = uc4proxy.post_feedback(settings.uc4_site, body if isinstance(body, dict) else {})
        except uc4proxy.Uc4Unavailable as exc:
            return JSONResponse({"error": str(exc), "uc4_down": True}, status_code=503)
        return JSONResponse(out, status_code=status)

    @app.post("/api/uc4/ask")
    async def uc4_ask(request: Request, x_portal: str | None = Header(default=None)):
        if x_portal != "ask":
            return JSONResponse({"error": "missing header"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        try:
            status, out = uc4proxy.post_ask(settings.uc4_site, body if isinstance(body, dict) else {})
        except uc4proxy.Uc4Unavailable as exc:
            return JSONResponse({"error": str(exc), "uc4_down": True}, status_code=503)
        return JSONResponse(out, status_code=status)

    @app.post("/api/uc4/reopen")
    async def uc4_reopen(request: Request, x_portal: str | None = Header(default=None)):
        """Undo an automatic close (a person's click). Forwarded to the triage service, which reopens it in Defender."""
        if x_portal != "reopen":
            return JSONResponse({"error": "missing header"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        try:
            status, out = uc4proxy.post_reopen(settings.uc4_site, body if isinstance(body, dict) else {})
        except uc4proxy.Uc4Unavailable as exc:
            return JSONResponse({"error": str(exc), "uc4_down": True}, status_code=503)
        return JSONResponse(out, status_code=status)

    @app.post("/api/uc4/start-site")
    def uc4_start_site(x_portal: str | None = Header(default=None)):
        if x_portal != "feedback":
            return JSONResponse({"error": "missing header"}, status_code=403)
        try:
            ok = services.start_one(settings, "triage")
        except uc4proxy.Uc4Unavailable as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)
        return JSONResponse({"started": ok}, status_code=200 if ok else 504)

    @app.get("/api/reports")
    def report_files() -> dict:
        return {"uc1": UC1(settings.uc1_dir).reports(), "uc3": UC3(settings.uc3_dir).downloads()}

    @app.get("/api/files/{uc}/{name}")
    def download(uc: str, name: str):
        """Download one listed report file. Only names the listing returns are served (no paths)."""
        listed = {"uc1": UC1(settings.uc1_dir).reports, "uc3": UC3(settings.uc3_dir).downloads}.get(uc)
        if listed is None or name not in {f["name"] for f in listed()}:
            return JSONResponse({"error": "not found"}, status_code=404)
        folder = settings.uc1_dir / "data" / "reports" if uc == "uc1" else settings.uc3_dir / "data" / "reporting"
        return FileResponse(folder / name, filename=name)

    runs = RunManager({"uc1": settings.uc1_dir, "uc3": settings.uc3_dir, "uc4": settings.uc4_dir, "attack": settings.uc1_dir})
    app.state.runs = runs

    @app.get("/api/runs")
    def run_status() -> dict:
        return runs.snapshot()

    @app.get("/api/runs/history")
    def run_history() -> list[dict]:
        return runs.history()

    @app.get("/api/runs/{uc}/log")
    def run_log(uc: str, after: int = 0, run: str | None = None):
        if uc not in UCS or (run and not re.fullmatch(r"\d{8}_\d{6}_(uc[134]|attack)", run)):
            return JSONResponse({"error": "not found"}, status_code=404)
        return runs.log(uc, max(0, after), run)

    @app.post("/api/runs/{uc}")
    def start_run(uc: str, x_portal: str | None = Header(default=None)):
        """Start a real pipeline run. Needs the X-Portal: run header (a plain link or form cannot trigger it)."""
        if x_portal != "run":
            return JSONResponse({"error": "missing header"}, status_code=403)
        if uc not in UCS:
            return JSONResponse({"error": "unknown use case"}, status_code=404)
        started, state, message = runs.start(uc)
        body = {"started": started, "message": message, "run": state.to_dict() if state else None}
        return JSONResponse(body, status_code=202 if started else 409)

    # ---- Help chatbot (the "?" bubble on every screen): answers from the portal's own data, never acts
    @app.get("/api/notifications")
    def notification_list() -> dict:
        """The bell: newest alerts and automatic actions from all agents (read-only)."""
        return notifications.build(settings, build_summary(settings), runs.history())

    @app.get("/api/help/status")
    def help_status() -> dict:
        return helpbot.status()

    @app.get("/api/help/ready")
    def help_ready(screen: str = "home", path: str = "/") -> dict:
        """The chat's two ready questions for this screen, answered from today's data (no AI)."""
        return {"items": helpready.ready(settings, build_summary(settings), runs.snapshot(), screen[:20], path[:200])}

    @app.post("/api/help/ask")
    async def help_ask(request: Request, x_portal: str | None = Header(default=None)):
        if x_portal != "help":
            return JSONResponse({"error": "missing header"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        try:
            row = helpbot.ask(settings, build_summary(settings), runs.snapshot(), runs.history(),
                              body if isinstance(body, dict) else {})
        except helpbot.HelpError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return {"saved": row}

    dist = settings.web_dist

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        """Production: hand out the built React files; unknown paths get index.html (client-side routing)."""
        if path.startswith("api/"):
            return JSONResponse({"error": "not found"}, status_code=404)
        file = (dist / path).resolve()
        if path and file.is_file() and dist.resolve() in file.parents:
            return FileResponse(file)
        index = dist / "index.html"
        if index.is_file():
            # never cache the page itself: it names the hashed JS/CSS files, so a rebuild shows on the next refresh
            return FileResponse(index, headers={"Cache-Control": "no-cache"})
        return JSONResponse({"error": "web app not built yet: run `npm run build` in web/"}, status_code=404)

    return app
