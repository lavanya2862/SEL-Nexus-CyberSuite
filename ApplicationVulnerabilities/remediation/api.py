"""HTTP API + web UI. The only required input is a GitHub repository link."""
from __future__ import annotations

import hmac
import logging
import shutil
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from . import __version__, jobqueue
from .config import RUNTIME_KEYS, SECRET_KEYS, Settings, get_settings, load_runtime_overrides, save_runtime_overrides
from .db import Job, JobArtifact, JobEvent, as_aware, engine, session_scope
from .github import GitHubClient, RepoAccessError, RepoURLError, parse_repo_url
from .logging_setup import setup_logging
from .models import Finding, JobOptions, RemediationReport
from .sandbox import sandbox_available
from .scanners import capabilities
from .suite_auth import COOKIE as SUITE_COOKIE, SuiteSessions

log = logging.getLogger(__name__)
# The React web app (web/), built with `npm run build`. Same look as the suite's Defender & Infrastructure portal.
WEB_DIST = Path(__file__).resolve().parents[1] / "web" / "dist"
ARTIFACT_NAMES = {"report.json", "report.md", "findings.json", "findings.sarif", "fixes.patch", "fixes.mbox"}


class JobCreate(BaseModel):
    repo_url: str = Field(..., min_length=3, max_length=500, examples=["https://github.com/owner/repo"])
    options: JobOptions = Field(default_factory=JobOptions)
    priority: int = Field(default=0, ge=-10, le=10)


class _RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


rate_limiter = _RateLimiter()


def require_api_key(request: Request) -> str:
    keys = get_settings().api_key_set
    client = request.client.host if request.client else "unknown"
    if not keys:
        return f"anon:{client}"
    supplied = request.headers.get("x-api-key") or ""
    auth = request.headers.get("authorization", "")
    if not supplied and auth.lower().startswith("bearer "):
        supplied = auth[7:].strip()
    for key in keys:
        if supplied and hmac.compare_digest(supplied, key):
            return f"key:{key[:6]}"
    raise HTTPException(401, "Missing or invalid API key (X-API-Key header).")


def _iso(value) -> str | None:
    return as_aware(value).isoformat() if value else None


def _job_dict(job: Job, include_options: bool = True) -> dict:
    data = {"id": job.id, "repo_url": job.repo_url, "repo": job.repo_full_name, "ref": job.ref,
            "commit": job.commit_sha, "status": job.status, "stage": job.stage, "progress": job.progress,
            "error": job.error, "summary": job.summary, "attempts": job.attempts, "cached_from": job.cached_from,
            "cancel_requested": job.cancel_requested,
            "created_at": _iso(job.created_at), "started_at": _iso(job.started_at),
            "finished_at": _iso(job.finished_at)}
    if include_options:
        data["options"] = job.options
        data["stages"] = job.stages
    return data


_worker = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _worker
    setup_logging()
    s = get_settings()
    engine()
    if not s.api_key_set:
        log.warning("API_KEYS is empty: the API is unauthenticated. Only expose it on a trusted network.")
    if s.embedded_worker:
        from .worker import Worker
        _worker = Worker()
        _worker.start()
    yield
    if _worker is not None:
        _worker.stop(timeout=5)
        _worker = None


app = FastAPI(title="AI Vulnerability Remediation Pipeline", version=__version__, lifespan=lifespan,
              description="Submit a GitHub repository link; the service clones it, scans it with multiple "
                          "engines, proposes and validates fixes, and returns reports, a patch and optionally a PR.")

if get_settings().cors_origin_list:
    app.add_middleware(CORSMiddleware, allow_origins=get_settings().cors_origin_list, allow_methods=["*"],
                       allow_headers=["*"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/assets/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"  # file names change on every build
    return response


# --- SEL Nexus CyberSuite shared sign-in -------------------------------------------------------

@lru_cache(maxsize=4)
def _suite_sessions(auth_dir: Path) -> SuiteSessions:
    return SuiteSessions(auth_dir)


def _suite_user(request: Request) -> dict | None:
    s = get_settings()
    if not s.suite_login_url:
        return {"email": "local", "name": "Local user", "via": "off", "expires": None}
    return _suite_sessions(s.suite_auth_dir).read(request.cookies.get(SUITE_COOKIE))


_OPEN_PATHS = ("/health", "/ready", "/metrics", "/favicon.svg")


@app.middleware("http")
async def suite_sign_in(request: Request, call_next):
    """With SUITE_LOGIN_URL set, only people signed in on the suite's sign-in page get in. Pages send everyone else
    there (and they come straight back after signing in); API calls answer 401 so the web app can do the same."""
    login_url = get_settings().suite_login_url.rstrip("/")
    path = request.url.path
    if not login_url or path in _OPEN_PATHS or path.startswith(("/assets/", "/api/v1/auth/")):
        return await call_next(request)
    if _suite_user(request):
        return await call_next(request)
    if path.startswith("/api/") or path == "/openapi.json":
        return JSONResponse({"detail": "Sign in on the SEL Nexus CyberSuite sign-in page first."}, status_code=401)
    return RedirectResponse(f"{login_url}/?next={quote(str(request.url), safe='')}", status_code=303)


@app.get("/api/v1/auth/me")
def auth_me(request: Request):
    """Who is signed in, and where the suite's sign-in page (the module chooser) is."""
    s = get_settings()
    return {"user": _suite_user(request), "login_url": s.suite_login_url.rstrip("/") or None}


@app.post("/api/v1/auth/logout")
def auth_logout(x_cybersuite: str | None = Header(default=None)):
    """Signs out of the whole suite: the cookie is shared by every module on this host, so clearing it here clears it
    everywhere. The header is one a form on another website cannot send."""
    if x_cybersuite != "auth":
        raise HTTPException(400, "Missing X-CyberSuite header.")
    out = JSONResponse({"user": None})
    out.delete_cookie(SUITE_COOKIE, path="/", httponly=True, samesite="lax")
    return out


# --- Health / meta ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "ai-remediation-pipeline", "version": __version__}


@app.get("/ready")
def ready():
    try:
        with session_scope() as db:
            db.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"status": "unavailable", "error": str(exc)[:200]}, status_code=503)
    return {"status": "ready"}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    counts = jobqueue.stats()
    lines = ["# HELP remediation_jobs Jobs by status", "# TYPE remediation_jobs gauge"]
    for status in ("queued", "running", "completed", "failed", "cancelled"):
        lines.append(f'remediation_jobs{{status="{status}"}} {counts.get(status, 0)}')
    lines.append(f"remediation_embedded_worker_active {len(_worker.active) if _worker else 0}")
    return "\n".join(lines) + "\n"


@app.get("/api/v1/capabilities")
def get_capabilities(_: str = Depends(require_api_key)):
    s = get_settings()
    sandbox_ok, sandbox_reason = sandbox_available()
    return {"version": __version__, "scanners": capabilities(),
            "llm": {"enabled": s.llm_enabled, "provider": s.resolved_llm_provider, "model": s.llm_model or None},
            "github_token_configured": bool(s.github_token), "sandbox": {"available": sandbox_ok, "mode": sandbox_reason},
            "git": bool(shutil.which("git")), "auth_required": bool(s.api_key_set),
            "allowed_hosts": sorted(s.allowed_hosts), "defaults": JobOptions().model_dump()}


# --- Jobs ------------------------------------------------------------------------------------

@app.post("/api/v1/jobs", status_code=202)
def create_job(body: JobCreate, response: Response, principal: str = Depends(require_api_key)):
    s = get_settings()
    if not rate_limiter.allow(principal, s.rate_limit_per_minute):
        raise HTTPException(429, "Rate limit exceeded; slow down.")
    try:
        repo = parse_repo_url(body.repo_url, body.options.ref)
    except RepoURLError as exc:
        raise HTTPException(422, str(exc))
    options = body.options.model_copy(update={"ref": repo.ref})
    if options.create_pr and not s.github_token:
        raise HTTPException(422, "create_pr requires GITHUB_TOKEN to be configured on the server.")
    try:
        job, deduped = jobqueue.enqueue(repo.html_url, repo.full_name, options, principal, body.priority)
    except jobqueue.QueueFull as exc:
        raise HTTPException(503, str(exc), headers={"Retry-After": "60"})
    if deduped:
        response.status_code = 200
    response.headers["Location"] = f"/api/v1/jobs/{job.id}"
    return {"job": _job_dict(job), "deduplicated": deduped}


@app.get("/api/v1/jobs")
def list_jobs(status: str | None = Query(None, pattern="^(queued|running|completed|failed|cancelled)$"),
              repo: str | None = Query(None, max_length=200), limit: int = Query(25, ge=1, le=200),
              offset: int = Query(0, ge=0), _: str = Depends(require_api_key)):
    with session_scope() as db:
        stmt = select(Job)
        count = select(func.count()).select_from(Job)
        if status:
            stmt, count = stmt.where(Job.status == status), count.where(Job.status == status)
        if repo:
            stmt, count = stmt.where(Job.repo_full_name.ilike(f"%{repo}%")), count.where(Job.repo_full_name.ilike(f"%{repo}%"))
        jobs = db.scalars(stmt.order_by(Job.created_at.desc()).limit(limit).offset(offset)).all()
        total = db.scalar(count)
        return {"total": total, "items": [_job_dict(j, include_options=False) for j in jobs]}


def _get_job(job_id: str) -> Job:
    if not job_id.isalnum() or len(job_id) > 64:
        raise HTTPException(400, "Invalid job id.")
    with session_scope() as db:
        job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(404, "Job not found.")
    return job


@app.get("/api/v1/jobs/{job_id}")
def get_job(job_id: str, _: str = Depends(require_api_key)):
    job = _get_job(job_id)
    data = _job_dict(job)
    with session_scope() as db:
        data["artifacts"] = [{"name": n, "size": sz, "url": f"/api/v1/jobs/{job_id}/artifacts/{n}"}
                             for n, sz in db.execute(select(JobArtifact.name, JobArtifact.size)
                                                     .where(JobArtifact.job_id == job_id)).all()]
    return data


@app.get("/api/v1/jobs/{job_id}/events")
def get_events(job_id: str, after: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=2000),
               _: str = Depends(require_api_key)):
    _get_job(job_id)
    with session_scope() as db:
        rows = db.scalars(select(JobEvent).where(JobEvent.job_id == job_id, JobEvent.id > after)
                          .order_by(JobEvent.id).limit(limit)).all()
        return {"items": [{"id": e.id, "ts": _iso(e.ts), "level": e.level, "message": e.message} for e in rows]}


def _artifact(job_id: str, name: str) -> JobArtifact:
    with session_scope() as db:
        art = db.get(JobArtifact, {"job_id": job_id, "name": name})
    if art is None:
        raise HTTPException(404, "Artifact not available (job may still be running).")
    return art


@app.get("/api/v1/jobs/{job_id}/report")
def get_report(job_id: str, _: str = Depends(require_api_key)):
    _get_job(job_id)
    import json
    return json.loads(_artifact(job_id, "report.json").content)


@app.get("/api/v1/jobs/{job_id}/findings")
def get_findings(job_id: str, severity: str | None = None, scanner: str | None = None,
                 _: str = Depends(require_api_key)):
    _get_job(job_id)
    import json
    items = json.loads(_artifact(job_id, "findings.json").content)
    if severity:
        wanted = {s.strip().lower() for s in severity.split(",")}
        items = [f for f in items if f.get("severity") in wanted]
    if scanner:
        items = [f for f in items if scanner.lower() in [f.get("scanner", "").lower(),
                                                         *[x.lower() for x in f.get("also_reported_by", [])]]]
    return {"count": len(items), "items": items}


@app.get("/api/v1/jobs/{job_id}/artifacts/{name}")
def download_artifact(job_id: str, name: str, download: bool = False, _: str = Depends(require_api_key)):
    if name not in ARTIFACT_NAMES:
        raise HTTPException(404, "Unknown artifact.")
    _get_job(job_id)
    art = _artifact(job_id, name)
    headers = {"Content-Disposition": f'attachment; filename="{job_id[:12]}-{name}"'} if download else {}
    return Response(art.content, media_type=art.content_type, headers=headers)


@app.post("/api/v1/jobs/{job_id}/cancel")
def cancel_job(job_id: str, _: str = Depends(require_api_key)):
    _get_job(job_id)
    job = jobqueue.request_cancel(job_id)
    return {"job": _job_dict(job)}


@app.post("/api/v1/jobs/{job_id}/retry")
def retry(job_id: str, _: str = Depends(require_api_key)):
    job = _get_job(job_id)
    if job.status not in jobqueue.TERMINAL:
        raise HTTPException(409, f"Job is {job.status}; only finished jobs can be retried.")
    return {"job": _job_dict(jobqueue.retry_job(job_id))}


# --- Dashboard -------------------------------------------------------------------------------

@app.get("/api/v1/dashboard")
def dashboard(_: str = Depends(require_api_key)):
    with session_scope() as db:
        jobs = db.scalars(select(Job).order_by(Job.created_at.desc()).limit(500)).all()
        data = [_job_dict(j, include_options=False) for j in jobs]
    by_status: dict[str, int] = {}
    for j in data:
        by_status[j["status"]] = by_status.get(j["status"], 0) + 1
    completed = [j for j in data if j["status"] == "completed" and j["summary"]]
    latest_per_repo: dict[str, dict] = {}
    for j in completed:  # newest first
        latest_per_repo.setdefault(j["repo"], j)
    severity: dict[str, int] = {}
    for j in latest_per_repo.values():
        for sev, n in (j["summary"].get("severity_counts") or {}).items():
            severity[sev] = severity.get(sev, 0) + n
    verdicts: dict[str, int] = {}
    for j in completed:
        v = j["summary"].get("validation_status") or "not_run"
        verdicts[v] = verdicts.get(v, 0) + 1
    validated = verdicts.get("passed", 0) + verdicts.get("flagged", 0)
    return {
        "runs": len(data), "by_status": by_status, "repositories": len(latest_per_repo),
        "open_findings": sum(j["summary"].get("findings", 0) for j in latest_per_repo.values()),
        "severity": severity,
        "fixes_applied": sum(j["summary"].get("fixes_applied", 0) for j in completed),
        "ai_fixes": sum(j["summary"].get("ai_fixes", 0) or 0 for j in completed),
        "verified_fixed": sum(j["summary"].get("verified_fixed", 0) for j in completed),
        "pull_requests": sum(1 for j in completed if j["summary"].get("pull_request_url")),
        "validation": verdicts,
        "validation_pass_rate": round(100 * verdicts.get("passed", 0) / validated) if validated else None,
        "recent": data[:8],
    }


# --- Human approval: push the branch and open the PR ----------------------------------------

_publishing: set[str] = set()
_publish_lock = threading.Lock()


def _publish_job(job_id: str, repo_url: str) -> None:
    import json as _json

    from .publish import publish_from_artifacts
    from .report import build_artifacts

    def log_fn(msg: str) -> None:
        jobqueue.add_event(job_id, msg)
    try:
        report = RemediationReport.model_validate_json(_artifact(job_id, "report.json").content)
        mbox = _artifact(job_id, "fixes.mbox").content
        url, draft = publish_from_artifacts(repo_url, report, mbox, log_fn)
        report.pull_request_url, report.pull_request_draft, report.approval_status = url, draft, "pr_opened"
        for st in report.stages:
            if st.id == "approval":
                st.status = "warning" if draft else "completed"
                st.summary = ("Draft PR opened (flagged for investigation)" if draft else
                              "Approved by reviewer — PR opened")
                st.metrics["pull_request"] = url
        findings = [Finding.model_validate(f) for f in _json.loads(_artifact(job_id, "findings.json").content)]
        arts = build_artifacts(report, findings, "")
        for name in ("report.json", "report.md"):
            jobqueue.replace_artifact(job_id, name, *arts[name])
        jobqueue.set_stages(job_id, [st.model_dump() for st in report.stages])
        jobqueue.update_summary(job_id, pull_request_url=url, pull_request_draft=draft, approval_status="pr_opened")
    except Exception as exc:  # noqa: BLE001
        log.exception("publish failed for %s", job_id)
        jobqueue.add_event(job_id, f"Publishing failed: {exc}", "error")
        jobqueue.update_summary(job_id, approval_status="failed", publish_error=str(exc)[:500])
    finally:
        with _publish_lock:
            _publishing.discard(job_id)


@app.post("/api/v1/jobs/{job_id}/publish", status_code=202)
def publish(job_id: str, _: str = Depends(require_api_key)):
    """Reviewer approval: replay the fix commits onto a fresh clone, push the branch and open a PR."""
    job = _get_job(job_id)
    if job.status != "completed":
        raise HTTPException(409, "Only completed runs can be published.")
    summary = job.summary or {}
    if summary.get("pull_request_url"):
        return {"status": "exists", "pull_request_url": summary["pull_request_url"]}
    if not summary.get("fixes_applied"):
        raise HTTPException(409, "This run has no fixes to publish.")
    if not get_settings().github_token:
        raise HTTPException(422, "No GitHub token configured. Add one under Settings → GitHub, then approve again.")
    with _publish_lock:
        if job_id in _publishing:
            return {"status": "publishing"}
        _publishing.add(job_id)
    jobqueue.update_summary(job_id, approval_status="publishing", publish_error=None)
    jobqueue.add_event(job_id, "Reviewer approved the fixes — pushing branch and opening pull request")
    threading.Thread(target=_publish_job, args=(job_id, job.repo_url), name=f"publish-{job_id[:8]}",
                     daemon=True).start()
    return {"status": "publishing"}


# --- Runtime settings (LLM + GitHub) ---------------------------------------------------------

class SettingsUpdate(BaseModel):
    llm_provider: str | None = Field(default=None, pattern="^(auto|openai|anthropic|gemini|none)$")
    llm_base_url: str | None = Field(default=None, max_length=300)
    llm_model: str | None = Field(default=None, max_length=200)
    llm_api_key: str | None = Field(default=None, max_length=500)
    github_token: str | None = Field(default=None, max_length=500)
    max_findings_per_run: int | None = Field(default=None, ge=1, le=500)
    llm_fix_attempts: int | None = Field(default=None, ge=1, le=5)


def _require_settings_access(request: Request, principal: str = Depends(require_api_key)) -> str:
    """Secrets may only be managed from this machine, or by an authenticated client."""
    host = request.client.host if request.client else ""
    if not get_settings().api_key_set and host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(403, "Settings can only be changed from localhost unless API_KEYS is configured.")
    return principal


def _mask(value: str) -> str:
    return ("•" * 8 + value[-4:]) if len(value) > 8 else "•" * len(value)


def _settings_view() -> dict:
    s = get_settings()
    runtime = load_runtime_overrides()
    out = {}
    for key in sorted(RUNTIME_KEYS):
        value = getattr(s, key)
        default = Settings.model_fields[key].default
        source = ("ui" if key in runtime else "unset" if value in ("", None)
                  else "default" if value == default else "env")
        out[key] = {"value": _mask(value) if key in SECRET_KEYS and value else value,
                    "configured": value not in ("", None), "source": source, "secret": key in SECRET_KEYS}
    return {"settings": out, "llm_enabled": s.llm_enabled, "llm_provider": s.resolved_llm_provider,
            "llm_endpoint": s.effective_llm_base_url}


@app.get("/api/v1/settings")
def read_settings(_: str = Depends(_require_settings_access)):
    return _settings_view()


@app.put("/api/v1/settings")
def write_settings(body: SettingsUpdate, _: str = Depends(_require_settings_access)):
    updates = body.model_dump(exclude_unset=True)
    for key in SECRET_KEYS:  # masked placeholders mean "unchanged"
        if isinstance(updates.get(key), str) and updates[key].startswith("•"):
            updates.pop(key)
    try:
        save_runtime_overrides(updates)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"Invalid settings: {exc}")
    return _settings_view()


@app.post("/api/v1/settings/test-llm")
def test_llm(_: str = Depends(_require_settings_access)):
    from .llm import LLMError, chat
    s = get_settings()
    if not s.llm_enabled:
        raise HTTPException(422, "LLM is not configured (provider, model and API key are required).")
    try:
        reply = chat("You are a connectivity check. Reply with the single word OK.",
                     [{"role": "user", "content": "ping"}])
    except LLMError as exc:
        raise HTTPException(502, str(exc)[:500])
    return {"ok": True, "provider": s.resolved_llm_provider, "model": s.llm_model, "reply": reply[:200]}


@app.post("/api/v1/settings/test-github")
def test_github(_: str = Depends(_require_settings_access)):
    if not get_settings().github_token:
        raise HTTPException(422, "No GitHub token configured.")
    try:
        with GitHubClient() as gh:
            return {"ok": True, **gh.whoami()}
    except RepoAccessError as exc:
        raise HTTPException(502, str(exc))


# --- Assistant (chatbot) ----------------------------------------------------------------------

class ChatMessage(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(max_length=8000)


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(min_length=1, max_length=40)
    job_id: str | None = Field(default=None, max_length=64)
    finding_id: str | None = Field(default=None, max_length=200)


@app.post("/api/v1/assistant/chat")
def assistant_chat(body: ChatRequest, principal: str = Depends(require_api_key)):
    from .assistant import ask
    from .llm import LLMError
    if not rate_limiter.allow("chat:" + principal, max(20, get_settings().rate_limit_per_minute * 2)):
        raise HTTPException(429, "Too many messages; slow down.")
    if not get_settings().llm_enabled:
        raise HTTPException(503, "The assistant needs an LLM. Configure a provider, model and API key in Settings.")
    if body.job_id:
        _get_job(body.job_id)
    try:
        reply = ask([m.model_dump() for m in body.messages], body.job_id, body.finding_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except LLMError as exc:
        raise HTTPException(502, f"LLM error: {str(exc)[:400]}")
    return {"reply": reply}


# --- Insights: agents, action center, portfolio ------------------------------------------------

def _json_artifact(job_id: str, name: str):
    import json as _json
    with session_scope() as db:
        art = db.get(JobArtifact, {"job_id": job_id, "name": name})
        content = art.content if art else None
    if not content:
        return None
    try:
        return _json.loads(content)
    except ValueError:
        return None


def _artifact_list(job_id: str) -> list[dict]:
    with session_scope() as db:
        return [{"name": n, "size": sz} for n, sz in db.execute(
            select(JobArtifact.name, JobArtifact.size).where(JobArtifact.job_id == job_id)).all()]


def _recent_jobs(limit: int = 300) -> list[dict]:
    with session_scope() as db:
        jobs = db.scalars(select(Job).order_by(Job.created_at.desc()).limit(limit)).all()
        return [_job_dict(j) for j in jobs]


def _latest_completed_per_repo(jobs: list[dict]) -> list[dict]:
    seen, out = set(), []
    for j in jobs:  # newest first
        if j["status"] == "completed" and j["repo"] not in seen:
            seen.add(j["repo"])
            out.append(j)
    return out


@app.get("/api/v1/jobs/{job_id}/agents")
def job_agents(job_id: str, _: str = Depends(require_api_key)):
    """What each agent received, produced and learned in this run, plus a plain-English story."""
    from .insights import agent_views, run_story
    job = _job_dict(_get_job(job_id))
    report = _json_artifact(job_id, "report.json") if job["status"] == "completed" else None
    findings = (_json_artifact(job_id, "findings.json") or []) if report else []
    return {"story": run_story(job, report, findings),
            "agents": agent_views(job, report, findings, _artifact_list(job_id))}


@app.get("/api/v1/agents/{agent_id}/history")
def agent_history(agent_id: str, limit: int = Query(10, ge=1, le=50), _: str = Depends(require_api_key)):
    """One agent's outputs and conclusions across recent runs."""
    from .insights import AGENTS, agent_views
    if agent_id not in AGENTS:
        raise HTTPException(404, "Unknown agent.")
    rows = []
    for job in _recent_jobs(limit * 3):
        if job["status"] != "completed" or len(rows) >= limit:
            continue
        report = _json_artifact(job["id"], "report.json")
        findings = _json_artifact(job["id"], "findings.json") or []
        view = agent_views(job, report, findings, _artifact_list(job["id"]))[agent_id]
        rows.append({"job_id": job["id"], "repo": job["repo"], "when": job["finished_at"] or job["created_at"],
                     "status": view["status"], "duration": view["duration"], "outputs": view["outputs"],
                     "learnings": view["learnings"][:3]})
    return {"agent": AGENTS[agent_id] | {"id": agent_id}, "runs": rows}


@app.get("/api/v1/attention")
def attention(_: str = Depends(require_api_key)):
    """The Action Center: approvals waiting, issues still needing a fix, and errors to resolve."""
    from .insights import fixes_needed, run_errors
    s = get_settings()
    jobs = _recent_jobs()
    latest = _latest_completed_per_repo(jobs)
    approvals, needed, errors = [], [], []
    for job in latest:
        summ = job["summary"] or {}
        findings = _json_artifact(job["id"], "findings.json") or []
        report = _json_artifact(job["id"], "report.json")
        if summ.get("fixes_applied") and not summ.get("pull_request_url"):
            failed = [c for c in (report or {}).get("validation_checks", []) if c["status"] == "failed"]
            approvals.append({**job, "failed_checks": [{"name": c["name"], "detail": c["detail"][:240]} for c in failed]})
        needed += fixes_needed(job, findings)
        errors += run_errors(job, report, findings)
    seen_failed = set()
    for job in jobs:
        if job["status"] == "failed" and job["repo"] not in seen_failed and not any(
                l["repo"] == job["repo"] and (l["created_at"] or "") > (job["created_at"] or "") for l in latest):
            seen_failed.add(job["repo"])
            errors += run_errors(job, None, [])
    config_errors = []
    if not s.llm_enabled:
        config_errors.append({"severity": "medium", "kind": "No AI model configured",
                              "message": "Code issues cannot be fixed automatically.",
                              "action": "Add an LLM provider, model and key in Settings.", "link": "/settings"})
    if not s.github_token:
        config_errors.append({"severity": "medium", "kind": "No GitHub token",
                              "message": "Fixes cannot be pushed and pull requests cannot be opened.",
                              "action": "Add a GitHub token in Settings.", "link": "/settings"})
    caps = capabilities()
    for name in ("codeql", "trivy"):
        if caps.get(name, {}).get("enabled") and not caps[name]["available"]:
            config_errors.append({"severity": "medium", "kind": f"{name.capitalize()} is not installed",
                                  "message": "A primary scanner is missing, so coverage is reduced.",
                                  "action": "Run scripts/install-codeql.ps1" if name == "codeql" else "Install Trivy.",
                                  "link": "/agents/analysis"})
    needed.sort(key=lambda x: -(x["score"] or 0))
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    errors.sort(key=lambda e: (sev_rank.get(e["severity"], 3), e.get("when") or ""))
    return {"counts": {"approvals": len(approvals), "fixes_needed": len(needed),
                       "errors": len(errors) + len(config_errors)},
            "approvals": approvals, "fixes_needed": needed[:800], "errors": errors, "config_errors": config_errors}


@app.get("/api/v1/vulnerabilities")
def vulnerabilities(_: str = Depends(require_api_key)):
    """Every finding from the latest completed run of each repository."""
    items = []
    for job in _latest_completed_per_repo(_recent_jobs()):
        for f in _json_artifact(job["id"], "findings.json") or []:
            f.pop("code_context", None)
            items.append({**f, "repo": job["repo"], "job_id": job["id"], "scanned_at": job["finished_at"]})
    items.sort(key=lambda f: -(f.get("priority_score") or 0))
    return {"count": len(items), "items": items[:3000]}


@app.get("/api/v1/repositories")
def repositories(_: str = Depends(require_api_key)):
    repos: dict[str, dict] = {}
    for job in _recent_jobs(500):
        entry = repos.setdefault(job["repo"], {"repo": job["repo"], "repo_url": job["repo_url"], "runs": 0,
                                               "latest": job, "latest_completed": None, "history": []})
        entry["runs"] += 1
        if job["status"] == "completed":
            if entry["latest_completed"] is None:
                entry["latest_completed"] = job
            s = job["summary"] or {}
            entry["history"].append({"when": job["finished_at"], "findings": s.get("findings", 0),
                                     "fixed": s.get("verified_fixed", 0)})
    for entry in repos.values():
        entry["history"].reverse()  # oldest → newest
        entry["history"] = entry["history"][-12:]
    return {"items": sorted(repos.values(), key=lambda e: e["latest"]["created_at"] or "", reverse=True)}


# --- Web UI ----------------------------------------------------------------------------------

if (WEB_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

_NOT_BUILT = """<!doctype html><meta charset="utf-8"><title>Application Vulnerabilities</title>
<body style="font-family:system-ui;background:#05070d;color:#eef2fb;padding:48px;line-height:1.5">
<h1>The web app is not built yet</h1>
<p>Run these once in the <code>web</code> folder, then reload: <code>npm ci</code> and <code>npm run build</code>.<br>
<code>Start_Application_Vulnerabilities.cmd</code> does this for you. The API itself is running (<a style="color:#6b97ff" href="/docs">/docs</a>).</p>"""


@app.get("/{path:path}", include_in_schema=False)
def web_app(path: str):
    """The React app: real files from web/dist, and index.html for every page address (the app routes itself)."""
    if path.startswith("api/"):
        raise HTTPException(404, "Not found.")
    if path:
        file = (WEB_DIST / path).resolve()
        if file.is_file() and WEB_DIST.resolve() in file.parents:
            return FileResponse(file)
    index = WEB_DIST / "index.html"
    if index.is_file():
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
    return HTMLResponse(_NOT_BUILT)

