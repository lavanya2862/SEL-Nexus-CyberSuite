"""HTTP API + web UI. The only required input is a GitHub repository link."""
from __future__ import annotations

import hmac
import logging
import shutil
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from . import __version__, activity, credentials, jobqueue, testloop
from .activity import LOCAL, Actor
from .config import (RUNTIME_KEYS, SECRET_KEYS, Settings, base_settings, current_user, get_settings,
                     load_runtime_overrides, save_runtime_overrides, user_scope)
from .db import Job, JobArtifact, JobEvent, as_aware, engine, session_scope
from .github import GitHubClient, RepoAccessError, RepoURLError, parse_repo_url
from .logging_setup import setup_logging
from .models import Finding, JobOptions, RemediationReport
from .pdf_reports import PDF_NAMES, render_pdf
from .scanners import capabilities
from .suite_auth import COOKIE as SUITE_COOKIE, DOMAIN as SUITE_DOMAIN, OLD_DOMAIN as SUITE_OLD_DOMAIN, SuiteSessions

log = logging.getLogger(__name__)
# The React web app (web/), built with `npm run build`. Same look as the suite's Infrastructure Security portal.
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


def _can_act(job: Job) -> bool:
    """Only the person who started a scan acts on it: approve its fixes, run or stop its tests, cancel, re-run, mark a
    draft reviewed. Everyone else can look at it and download its reports. Without the shared sign-in, the one local
    user can do everything."""
    if not base_settings().per_user:
        return True
    return job.owner is not None and job.owner == current_user()


def _require_starter(job: Job) -> None:
    if _can_act(job):
        return
    if job.owner:
        who = f"{job.owner_name} ({job.owner})" if job.owner_name and job.owner_name != job.owner else job.owner
        raise HTTPException(403, f"Only {who}, who started this scan, can do that. You can view it and download its "
                                 "reports, or start a scan of your own.")
    raise HTTPException(403, "This scan was made before sign-ins were recorded, so nobody can act on it. You can view "
                             "it and download its reports, or start a new scan of the repository.")


def _iso(value) -> str | None:
    return as_aware(value).isoformat() if value else None


def _job_dict(job: Job, include_options: bool = True) -> dict:
    data = {"id": job.id, "repo_url": job.repo_url, "repo": job.repo_full_name, "ref": job.ref,
            "commit": job.commit_sha, "status": job.status, "stage": job.stage, "progress": job.progress,
            "error": job.error, "summary": job.summary, "attempts": job.attempts, "cached_from": job.cached_from,
            "cancel_requested": job.cancel_requested,
            "created_at": _iso(job.created_at), "started_at": _iso(job.started_at),
            "finished_at": _iso(job.finished_at),
            "started_by": {"email": job.owner, "name": job.owner_name} if job.owner or job.owner_name else None,
            "can_act": _can_act(job)}
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
    testloop.recover_interrupted()
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


app = FastAPI(title="Application Security API (SEL Nexus CyberSuite)", version=__version__, lifespan=lifespan,
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
    user = _suite_sessions(s.suite_auth_dir).read(request.cookies.get(SUITE_COOKIE))
    # accounts made with a domain choice may only open the domains they picked (older accounts have no list: all)
    if user and isinstance(user.get("domains"), list) and not {SUITE_DOMAIN, SUITE_OLD_DOMAIN} & set(user["domains"]):
        return None
    return user


_OPEN_PATHS = ("/health", "/ready", "/metrics", "/favicon.svg")


@app.middleware("http")
async def suite_sign_in(request: Request, call_next):
    """With SUITE_LOGIN_URL set, only people signed in on the suite's sign-in page get in. Pages send everyone else
    there (and they come straight back after signing in); API calls answer 401 so the web app can do the same."""
    login_url = get_settings().suite_login_url.rstrip("/")
    path = request.url.path
    if not login_url or path in _OPEN_PATHS or path.startswith(("/assets/", "/api/v1/auth/")):
        return await call_next(request)
    user = _suite_user(request)
    if user and user.get("email"):
        # whose scans this request may see, and whose keys get_settings() returns while it runs
        request.state.owner = str(user["email"]).strip().lower()
        request.state.owner_name = str(user.get("name") or "").strip() or None
        with user_scope(request.state.owner):
            return await call_next(request)
    if path.startswith("/api/") or path == "/openapi.json":
        return JSONResponse({"detail": "Sign in on the SEL Nexus CyberSuite sign-in page first."}, status_code=401)
    return RedirectResponse(f"{login_url}/?next={quote(str(request.url), safe='')}", status_code=303)


def actor(request: Request) -> Actor:
    """Who is doing this: the signed-in person (their name and email go in the activity log, and their own keys do
    the work), or the one local user without the shared sign-in."""
    if not base_settings().per_user:
        return LOCAL
    email = getattr(request.state, "owner", None)
    if not email:
        raise HTTPException(401, "Sign in on the SEL Nexus CyberSuite sign-in page first.")
    return Actor(email, getattr(request.state, "owner_name", None) or email)


def owner(request: Request) -> str | None:
    """Whose scans this request may see: with RUNS_VISIBLE_TO=owner only the signed-in person's own, else (None)
    every scan."""
    s = base_settings()
    if not s.per_user or s.runs_visible_to == "everyone":
        return None
    return actor(request).email


def _keys_of(who: Actor) -> str | None:
    """The person whose own keys an action uses (None: the server's keys, without the shared sign-in)."""
    return who.email if base_settings().per_user else None


def _mine(stmt, me: str | None):
    return stmt if me is None else stmt.where(Job.owner == me)


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
    return {"version": __version__, "scanners": capabilities(),
            "llm": {"enabled": s.llm_enabled, "provider": s.resolved_llm_provider, "model": s.llm_model or None},
            "github_token_configured": bool(s.github_token),
            "git": bool(shutil.which("git")), "auth_required": bool(s.api_key_set),
            "allowed_hosts": sorted(s.allowed_hosts), "defaults": JobOptions().model_dump()}


# --- Jobs ------------------------------------------------------------------------------------

@app.post("/api/v1/jobs", status_code=202)
def create_job(body: JobCreate, response: Response, principal: str = Depends(require_api_key),
               who: Actor = Depends(actor)):
    s = get_settings()
    if not rate_limiter.allow(principal, s.rate_limit_per_minute):
        raise HTTPException(429, "Rate limit exceeded; slow down.")
    try:
        repo = parse_repo_url(body.repo_url, body.options.ref)
    except RepoURLError as exc:
        raise HTTPException(422, str(exc))
    options = body.options.model_copy(update={"ref": repo.ref})
    if options.create_pr and not s.github_token:
        raise HTTPException(422, "create_pr needs a GitHub token: add yours under Settings → GitHub."
                            if _keys_of(who) else "create_pr requires GITHUB_TOKEN to be configured on the server.")
    try:
        job, deduped = jobqueue.enqueue(repo.html_url, repo.full_name, options, principal, body.priority,
                                        owner=_keys_of(who), owner_name=who.name)
    except jobqueue.QueueFull as exc:
        raise HTTPException(503, str(exc), headers={"Retry-After": "60"})
    asked = [f"ref {options.ref}" if options.ref else "default branch"] + \
        (["open a pull request"] if options.create_pr else []) + (["run tests on GitHub"] if options.github_tests else [])
    if deduped:
        activity.record(who, "scan_started", job.id, repo.full_name,
                        "joined the identical scan already running \u00b7 " + ", ".join(asked))
    else:
        jobqueue.add_event(job.id, f"Started by {who.label()}")
        activity.record(who, "scan_started", job.id, repo.full_name, ", ".join(asked))
    if deduped:
        response.status_code = 200
    response.headers["Location"] = f"/api/v1/jobs/{job.id}"
    return {"job": _job_dict(job), "deduplicated": deduped}


@app.get("/api/v1/jobs")
def list_jobs(status: str | None = Query(None, pattern="^(queued|running|completed|failed|cancelled)$"),
              repo: str | None = Query(None, max_length=200), limit: int = Query(25, ge=1, le=200),
              offset: int = Query(0, ge=0), _: str = Depends(require_api_key), me: str | None = Depends(owner)):
    with session_scope() as db:
        stmt = _mine(select(Job), me)
        count = _mine(select(func.count()).select_from(Job), me)
        if status:
            stmt, count = stmt.where(Job.status == status), count.where(Job.status == status)
        if repo:
            stmt, count = stmt.where(Job.repo_full_name.ilike(f"%{repo}%")), count.where(Job.repo_full_name.ilike(f"%{repo}%"))
        jobs = db.scalars(stmt.order_by(Job.created_at.desc()).limit(limit).offset(offset)).all()
        total = db.scalar(count)
        return {"total": total, "items": [_job_dict(j, include_options=False) for j in jobs]}


def _get_job(job_id: str, me: str | None) -> Job:
    """The scan, if ``me`` may see it. Another person's scan answers exactly like one that does not exist."""
    if not job_id.isalnum() or len(job_id) > 64:
        raise HTTPException(400, "Invalid job id.")
    with session_scope() as db:
        job = db.get(Job, job_id)
    if job is None or (me is not None and job.owner != me):
        raise HTTPException(404, "Job not found.")
    return job


@app.get("/api/v1/jobs/{job_id}")
def get_job(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner)):
    job = _get_job(job_id, me)
    data = _job_dict(job)
    with session_scope() as db:
        data["artifacts"] = [{"name": n, "size": sz, "url": f"/api/v1/jobs/{job_id}/artifacts/{n}"}
                             for n, sz in db.execute(select(JobArtifact.name, JobArtifact.size)
                                                     .where(JobArtifact.job_id == job_id)).all()]
    return data


@app.get("/api/v1/jobs/{job_id}/events")
def get_events(job_id: str, after: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=2000),
               _: str = Depends(require_api_key), me: str | None = Depends(owner)):
    _get_job(job_id, me)
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
def get_report(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner)):
    _get_job(job_id, me)
    import json
    return json.loads(_artifact(job_id, "report.json").content)


@app.get("/api/v1/jobs/{job_id}/findings")
def get_findings(job_id: str, severity: str | None = None, scanner: str | None = None,
                 _: str = Depends(require_api_key), me: str | None = Depends(owner)):
    _get_job(job_id, me)
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
def download_artifact(job_id: str, name: str, download: bool = False, _: str = Depends(require_api_key),
                      me: str | None = Depends(owner)):
    if name not in ARTIFACT_NAMES and name not in PDF_NAMES:
        raise HTTPException(404, "Unknown artifact.")
    _get_job(job_id, me)
    if name in PDF_NAMES:
        # PDFs for people are built on request from the run's report and findings, so older runs get them too.
        import json
        report = RemediationReport.model_validate_json(_artifact(job_id, "report.json").content)
        findings = [Finding.model_validate(f) for f in json.loads(_artifact(job_id, "findings.json").content)]
        disposition = "attachment" if download else "inline"
        headers = {"Content-Disposition": f'{disposition}; filename="{job_id[:12]}-{name}"'}
        return Response(render_pdf(name, report, findings), media_type="application/pdf", headers=headers)
    art = _artifact(job_id, name)
    headers = {"Content-Disposition": f'attachment; filename="{job_id[:12]}-{name}"'} if download else {}
    return Response(art.content, media_type=art.content_type, headers=headers)


@app.post("/api/v1/jobs/{job_id}/cancel")
def cancel_job(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner),
               who: Actor = Depends(actor)):
    before = _get_job(job_id, me)
    _require_starter(before)
    job = jobqueue.request_cancel(job_id)
    if before.status in jobqueue.ACTIVE:
        jobqueue.add_event(job_id, f"Cancelled by {who.label()}", "warning")
        activity.record(who, "scan_cancelled", job_id, job.repo_full_name)
    return {"job": _job_dict(job)}


@app.post("/api/v1/jobs/{job_id}/retry")
def retry(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner),
          who: Actor = Depends(actor)):
    job = _get_job(job_id, me)
    _require_starter(job)
    if job.status not in jobqueue.TERMINAL:
        raise HTTPException(409, f"Job is {job.status}; only finished jobs can be retried.")
    # the re-run is the re-runner's own scan: it runs with their keys
    again = jobqueue.retry_job(job_id, _keys_of(who), who.name, by=who.label())
    activity.record(who, "scan_rerun", job_id, job.repo_full_name,
                    f"first started by {Actor(job.owner, job.owner_name).label()}" if job.owner_name else "")
    return {"job": _job_dict(again)}


# --- Dashboard -------------------------------------------------------------------------------

@app.get("/api/v1/dashboard")
def dashboard(_: str = Depends(require_api_key), me: str | None = Depends(owner)):
    with session_scope() as db:
        jobs = db.scalars(_mine(select(Job), me).order_by(Job.created_at.desc()).limit(500)).all()
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


def _publish_job(job_id: str, repo_url: str, who: Actor) -> None:
    # a new thread has no person: push and open the PR with the keys of the person who approved
    with user_scope(_keys_of(who)):
        _publish_as(job_id, repo_url, who)


def _publish_as(job_id: str, repo_url: str, who: Actor) -> None:
    import json as _json

    from .publish import publish_from_artifacts, publish_tested_branch
    from .report import build_artifacts

    def log_fn(msg: str) -> None:
        jobqueue.add_event(job_id, msg)
    try:
        report = RemediationReport.model_validate_json(_artifact(job_id, "report.json").content)
        tests = (_get_job(job_id, None).summary or {}).get("tests") or {}
        if tests.get("branch_pushed") and tests.get("branch"):
            # the Test & Fix loop already pushed (and tested) the fix branch: open the PR from it as it is
            url, draft = publish_tested_branch(repo_url, report, tests, log_fn)
        else:
            mbox = _artifact(job_id, "fixes.mbox").content
            url, draft = publish_from_artifacts(repo_url, report, mbox, log_fn)
        report.pull_request_url, report.pull_request_draft, report.approval_status = url, draft, "pr_opened"
        for st in report.stages:
            if st.id == "approval":
                st.status = "warning" if draft else "completed"
                st.summary = (f"Approved by {who.label()} \u2014 draft PR opened (needs review)" if draft else
                              f"Approved by {who.label()} \u2014 PR opened")
                st.metrics["pull_request"] = url
        findings = [Finding.model_validate(f) for f in _json.loads(_artifact(job_id, "findings.json").content)]
        arts = build_artifacts(report, findings, "")
        for name in ("report.json", "report.md"):
            jobqueue.replace_artifact(job_id, name, *arts[name])
        jobqueue.set_stages(job_id, [st.model_dump() for st in report.stages])
        jobqueue.update_summary(job_id, pull_request_url=url, pull_request_draft=draft, approval_status="pr_opened")
        activity.record(who, "pr_opened", job_id, report.repo, f"{url}{' (draft)' if draft else ''}")
    except Exception as exc:  # noqa: BLE001
        log.exception("publish failed for %s", job_id)
        jobqueue.add_event(job_id, f"Publishing failed: {exc}", "error")
        jobqueue.update_summary(job_id, approval_status="failed", publish_error=str(exc)[:500])
        activity.record(who, "pr_failed", job_id, _get_job(job_id, None).repo_full_name, str(exc)[:500])
    finally:
        with _publish_lock:
            _publishing.discard(job_id)


@app.post("/api/v1/jobs/{job_id}/publish", status_code=202)
def publish(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner),
            who: Actor = Depends(actor)):
    """Reviewer approval: replay the fix commits onto a fresh clone, push the branch and open a PR with the approver's
    own GitHub token, so the pull request is theirs."""
    job = _get_job(job_id, me)
    _require_starter(job)
    if job.status != "completed":
        raise HTTPException(409, "Only completed runs can be published.")
    summary = job.summary or {}
    if summary.get("pull_request_url"):
        return {"status": "exists", "pull_request_url": summary["pull_request_url"]}
    tests = summary.get("tests") or {}
    if tests.get("status") in testloop.ACTIVE:
        raise HTTPException(409, "The tests are still running on the fix branch. Approve when they have finished.")
    if not summary.get("fixes_applied") and not _test_fixes(summary):
        raise HTTPException(409, "This scan has no fixes to publish.")
    if not get_settings().github_token:
        raise HTTPException(422, "No GitHub token configured. Add one under Settings → GitHub, then approve again.")
    with _publish_lock:
        if job_id in _publishing:
            return {"status": "publishing"}
        _publishing.add(job_id)
    approved = {**who.as_dict(), "at": datetime.now(timezone.utc).isoformat()}
    jobqueue.update_summary(job_id, approval_status="publishing", publish_error=None, approved_by=approved)
    jobqueue.add_event(job_id, f"{who.label()} approved the fixes \u2014 pushing branch and opening pull request")
    activity.record(who, "fixes_approved", job_id, job.repo_full_name,
                    f"{summary.get('fixes_applied') or 0} fix commit(s) \u00b7 validation {summary.get('validation_status') or 'not run'}")
    threading.Thread(target=_publish_job, args=(job_id, job.repo_url, who), name=f"publish-{job_id[:8]}",
                     daemon=True).start()
    return {"status": "publishing"}


# --- Test & Fix loop: the repository's tests on GitHub Actions, failures fixed by the Remediation Agent (testloop.py) ----------

def _test_fixes(summary: dict) -> int:
    return sum(1 for r in ((summary.get("tests") or {}).get("runs") or []) if r.get("fix"))


@app.post("/api/v1/jobs/{job_id}/tests", status_code=202)
def start_tests(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner),
                who: Actor = Depends(actor)):
    """Push the run's fix branch with a test workflow; GitHub Actions runs every test, the Remediation Agent fixes failures and
    pushes again, up to TEST_FIX_ATTEMPTS times."""
    job = _get_job(job_id, me)
    _require_starter(job)
    if job.status != "completed":
        raise HTTPException(409, "Only completed runs can be tested.")
    summary = job.summary or {}
    if summary.get("pull_request_url") and not (summary.get("tests") or {}).get("branch_pushed"):
        jobqueue.add_event(job_id, "Tests: the pull request is already open; testing its branch")
    if not get_settings().github_token:
        raise HTTPException(422, "No GitHub token configured. Add one under Settings → GitHub: it pushes the fix "
                                 "branch so GitHub Actions can test it.")
    if summary.get("approval_status") == "publishing":
        raise HTTPException(409, "The pull request is being opened right now. Try again in a moment.")
    if not testloop.start(job_id, who):  # pushes and fixes with the keys of whoever asked
        return {"status": "running"}
    jobqueue.add_event(job_id, f"Tests: started by {who.label()}")
    activity.record(who, "tests_started", job_id, job.repo_full_name)
    return {"status": "started"}


@app.post("/api/v1/jobs/{job_id}/tests/cancel")
def cancel_tests(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner),
                 who: Actor = Depends(actor)):
    job = _get_job(job_id, me)
    _require_starter(job)
    if testloop.is_running(job_id):
        jobqueue.add_event(job_id, f"Tests: stop requested by {who.label()}", "warning")
        activity.record(who, "tests_cancelled", job_id, job.repo_full_name)
    testloop.cancel(job_id)
    return {"status": "cancelling" if testloop.is_running(job_id) else "idle"}


# --- Runtime settings (LLM + GitHub) ---------------------------------------------------------

class SettingsUpdate(BaseModel):
    llm_provider: str | None = Field(default=None, pattern="^(auto|openai|anthropic|gemini|none)$")
    llm_base_url: str | None = Field(default=None, max_length=300)
    llm_model: str | None = Field(default=None, max_length=200)
    llm_api_key: str | None = Field(default=None, max_length=500)
    github_token: str | None = Field(default=None, max_length=500)
    max_findings_per_run: int | None = Field(default=None, ge=1, le=500)
    llm_fix_attempts: int | None = Field(default=None, ge=1, le=5)


def _settings_owner(request: Request, _: str = Depends(require_api_key), who: Actor = Depends(actor),
                    x_cybersuite: str | None = Header(default=None)) -> str | None:
    """Whose settings these are. With the shared sign-in, every signed-in person manages their own keys, from any
    computer; changes need the X-CyberSuite header, which a form on another website cannot send. Without it, the
    server's keys may only be managed from this machine, or by a client with an API key."""
    me = _keys_of(who)
    if me is not None:
        if request.method != "GET" and x_cybersuite != "settings":
            raise HTTPException(400, "Missing X-CyberSuite header.")
        return me
    host = request.client.host if request.client else ""
    if not get_settings().api_key_set and host not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(403, "Settings can only be changed from localhost unless API_KEYS is configured.")
    return None


def _mask(value: str) -> str:
    return ("•" * 8 + value[-4:]) if len(value) > 8 else "•" * len(value)


def _settings_view(me: str | None) -> dict:
    s = get_settings()
    runtime = credentials.load(me) if me else load_runtime_overrides()
    out = {}
    for key in sorted(RUNTIME_KEYS):
        value = getattr(s, key)
        default = Settings.model_fields[key].default
        source = ("ui" if key in runtime else "unset" if value in ("", None)
                  else "default" if value == default else "env")
        out[key] = {"value": _mask(value) if key in SECRET_KEYS and value else value,
                    "configured": value not in ("", None), "source": source, "secret": key in SECRET_KEYS}
    return {"settings": out, "llm_enabled": s.llm_enabled, "llm_provider": s.resolved_llm_provider,
            "llm_endpoint": s.effective_llm_base_url, "per_user": me is not None, "user": me}


@app.get("/api/v1/settings")
def read_settings(me: str | None = Depends(_settings_owner)):
    return _settings_view(me)


_SETTING_NAMES = {"github_token": "GitHub token", "llm_api_key": "AI key", "llm_model": "AI model",
                  "llm_provider": "AI provider", "llm_base_url": "AI address",
                  "max_findings_per_run": "max code fixes per scan", "llm_fix_attempts": "attempts per finding"}


@app.put("/api/v1/settings")
def write_settings(body: SettingsUpdate, me: str | None = Depends(_settings_owner), who: Actor = Depends(actor)):
    updates = body.model_dump(exclude_unset=True)
    for key in SECRET_KEYS:  # masked placeholders mean "unchanged"
        if isinstance(updates.get(key), str) and updates[key].startswith("•"):
            updates.pop(key)
    try:
        if me:
            credentials.save(me, updates)
        else:
            save_runtime_overrides(updates)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"Invalid settings: {exc}")
    saved = [_SETTING_NAMES[k] for k, v in updates.items() if v not in (None, "")]
    removed = [_SETTING_NAMES[k] for k, v in updates.items() if v in (None, "")]
    if saved or removed:  # which settings, never their values
        activity.record(who, "settings_changed", detail=" \u00b7 ".join(
            ([f"saved {', '.join(saved)}"] if saved else []) + ([f"removed {', '.join(removed)}"] if removed else [])))
    return _settings_view(me)


@app.post("/api/v1/settings/test-llm")
def test_llm(_: str | None = Depends(_settings_owner)):
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
def test_github(_: str | None = Depends(_settings_owner)):
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
def assistant_chat(body: ChatRequest, principal: str = Depends(require_api_key), me: str | None = Depends(owner)):
    from .assistant import ask
    from .llm import LLMError
    if not rate_limiter.allow("chat:" + principal, max(20, get_settings().rate_limit_per_minute * 2)):
        raise HTTPException(429, "Too many messages; slow down.")
    if not get_settings().llm_enabled:
        raise HTTPException(503, "The assistant needs an LLM. Configure a provider, model and API key in Settings.")
    if body.job_id:
        _get_job(body.job_id, me)
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


def _recent_jobs(me: str | None, limit: int = 300) -> list[dict]:
    with session_scope() as db:
        jobs = db.scalars(_mine(select(Job), me).order_by(Job.created_at.desc()).limit(limit)).all()
        return [_job_dict(j) for j in jobs]


def _latest_completed_per_repo(jobs: list[dict]) -> list[dict]:
    seen, out = set(), []
    for j in jobs:  # newest first
        if j["status"] == "completed" and j["repo"] not in seen:
            seen.add(j["repo"])
            out.append(j)
    return out


@app.get("/api/v1/jobs/{job_id}/agents")
def job_agents(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner)):
    """What each agent received, produced and learned in this run, plus a plain-English story."""
    from .insights import agent_views, run_story
    job = _job_dict(_get_job(job_id, me))
    report = _json_artifact(job_id, "report.json") if job["status"] == "completed" else None
    findings = (_json_artifact(job_id, "findings.json") or []) if report else []
    return {"story": run_story(job, report, findings),
            "agents": agent_views(job, report, findings, _artifact_list(job_id))}


@app.get("/api/v1/agents/{agent_id}/history")
def agent_history(agent_id: str, limit: int = Query(10, ge=1, le=50), _: str = Depends(require_api_key),
                  me: str | None = Depends(owner)):
    """One agent's outputs and conclusions across recent runs."""
    from .insights import AGENTS, agent_views
    if agent_id not in AGENTS:
        raise HTTPException(404, "Unknown agent.")
    rows = []
    for job in _recent_jobs(me, limit * 3):
        if job["status"] != "completed" or len(rows) >= limit:
            continue
        report = _json_artifact(job["id"], "report.json")
        findings = _json_artifact(job["id"], "findings.json") or []
        view = agent_views(job, report, findings, _artifact_list(job["id"]))[agent_id]
        rows.append({"job_id": job["id"], "repo": job["repo"], "when": job["finished_at"] or job["created_at"],
                     "status": view["status"], "duration": view["duration"], "outputs": view["outputs"],
                     "learnings": view["learnings"][:3]})
    return {"agent": AGENTS[agent_id] | {"id": agent_id}, "runs": rows}


def _unreviewed_draft(job: dict) -> bool:
    """A draft PR the pipeline opened on its own for a flagged run, not yet marked as reviewed."""
    summ = job["summary"] or {}
    return bool(summ.get("pull_request_url") and summ.get("pull_request_draft")
                and summ.get("validation_status") == "flagged" and (job.get("options") or {}).get("create_pr")
                and not summ.get("draft_reviewed_at"))


@app.post("/api/v1/jobs/{job_id}/draft-reviewed")
def mark_draft_reviewed(job_id: str, _: str = Depends(require_api_key), me: str | None = Depends(owner),
                        who: Actor = Depends(actor)):
    """Take an automatically opened draft PR off the Approvals list once a person has looked at it."""
    row = _get_job(job_id, me)
    _require_starter(row)
    job = _job_dict(row)
    if not _unreviewed_draft(job):
        raise HTTPException(409, "This scan has no unreviewed draft pull request.")
    jobqueue.update_summary(job_id, draft_reviewed_at=datetime.now(timezone.utc).isoformat(),
                            draft_reviewed_by=who.as_dict())
    activity.record(who, "draft_reviewed", job_id, job["repo"], (job["summary"] or {}).get("pull_request_url") or "")
    return {"status": "reviewed"}


@app.get("/api/v1/attention")
def attention(_: str = Depends(require_api_key), me: str | None = Depends(owner)):
    """The Action Center: approvals waiting, issues still needing a fix, and errors to resolve."""
    from .insights import fixes_needed, run_errors
    s = get_settings()
    jobs = _recent_jobs(me)
    latest = _latest_completed_per_repo(jobs)
    approvals, needed, errors = [], [], []
    for job in latest:
        summ = job["summary"] or {}
        findings = _json_artifact(job["id"], "findings.json") or []
        report = _json_artifact(job["id"], "report.json")
        failed = [{"name": c["name"], "detail": c["detail"][:240]}
                  for c in (report or {}).get("validation_checks", []) if c["status"] == "failed"]
        if not job["can_act"]:
            pass  # someone else's scan: only the person who started it decides
        elif (summ.get("fixes_applied") or _test_fixes(summ)) and not summ.get("pull_request_url"):
            approvals.append({**job, "failed_checks": failed})
        elif _unreviewed_draft(job):
            # Opened automatically while validation flagged it: nobody has looked at it yet.
            approvals.append({**job, "failed_checks": failed, "draft_review": True})
        needed += fixes_needed(job, findings)
        errors += run_errors(job, report, findings)
        tests = summ.get("tests") or {}
        if tests.get("status") in ("failed", "error"):
            errors.append({"job_id": job["id"], "repo": job["repo"], "when": tests.get("finished_at"),
                           "severity": "high" if tests["status"] == "failed" else "medium",
                           "kind": "Tests fail on GitHub Actions" if tests["status"] == "failed" else "Test run could not finish",
                           "message": tests.get("message") or "",
                           "action": "Open the run's GitHub tests tab, look at the last run on GitHub, fix what the Remediation Agent "
                                     "could not, then run the tests again.",
                           "link": f"/runs/{job['id']}/tests"})
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


@app.get("/api/v1/activity")
def activity_log(action: str | None = Query(None, max_length=40), q: str | None = Query(None, max_length=200),
                 limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                 _: str = Depends(require_api_key), me: str | None = Depends(owner)):
    """Who did what and when, newest first. With RUNS_VISIBLE_TO=owner, only the signed-in person's own actions."""
    return activity.listing(limit, offset, action or None, (q or "").strip() or None, only=me)


@app.get("/api/v1/vulnerabilities")
def vulnerabilities(_: str = Depends(require_api_key), me: str | None = Depends(owner)):
    """Every finding from the latest completed run of each repository."""
    items = []
    for job in _latest_completed_per_repo(_recent_jobs(me)):
        for f in _json_artifact(job["id"], "findings.json") or []:
            f.pop("code_context", None)
            items.append({**f, "repo": job["repo"], "job_id": job["id"], "scanned_at": job["finished_at"]})
    items.sort(key=lambda f: -(f.get("priority_score") or 0))
    return {"count": len(items), "items": items[:3000]}


@app.get("/api/v1/repositories")
def repositories(_: str = Depends(require_api_key), me: str | None = Depends(owner)):
    repos: dict[str, dict] = {}
    for job in _recent_jobs(me, 500):
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

_NOT_BUILT = """<!doctype html><meta charset="utf-8"><title>Application Security</title>
<body style="font-family:system-ui;background:#05070d;color:#eef2fb;padding:48px;line-height:1.5">
<h1>The web app is not built yet</h1>
<p>Run these once in the <code>web</code> folder, then reload: <code>npm ci</code> and <code>npm run build</code>.<br>
<code>Start_Application_Security.cmd</code> does this for you. The API itself is running (<a style="color:#6b97ff" href="/docs">/docs</a>).</p>"""


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

