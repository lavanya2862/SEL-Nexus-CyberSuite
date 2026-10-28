"""Database-backed job queue.

Any number of worker processes (on any number of hosts) can share one PostgreSQL database:
jobs are claimed atomically (``FOR UPDATE SKIP LOCKED`` on PostgreSQL, a guarded UPDATE on
SQLite), held with a renewable lease, and re-queued automatically if a worker dies.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select, update

from .config import get_settings
from .db import Job, JobArtifact, JobEvent, as_aware, engine, session_scope, utcnow
from .models import JobOptions

ACTIVE = ("queued", "running")
TERMINAL = ("completed", "failed", "cancelled")


class QueueFull(RuntimeError):
    pass


def cache_key(repo_full_name: str, ref: str | None, options: JobOptions, owner: str | None = None) -> str:
    """Identical scans share results, but only within one person's scans: another person's results would show them
    code (and AI fixes) from a repository their own token may not reach."""
    material = {"repo": repo_full_name.lower(), "ref": ref, "opts": options.cache_key_material()}
    if owner:
        material["owner"] = owner
    material = json.dumps(material, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()[:40]


def enqueue(repo_url: str, repo_full_name: str, options: JobOptions, requested_by: str | None = None,
            priority: int = 0, dedupe: bool = True, owner: str | None = None) -> tuple[Job, bool]:
    """Create a job. Returns (job, deduplicated) — an identical active job of the same owner is reused."""
    s = get_settings()
    key = cache_key(repo_full_name, options.ref, options, owner)
    with session_scope() as db:
        if dedupe and not options.create_pr:
            existing = db.scalars(select(Job).where(Job.cache_key == key, Job.status.in_(ACTIVE), _same_owner(owner))
                                  .order_by(Job.created_at.desc()).limit(1)).first()
            if existing:
                return existing, True
        queued = db.scalar(select(func.count()).select_from(Job).where(Job.status == "queued"))
        if queued >= s.max_queued_jobs:
            raise QueueFull(f"Queue is full ({queued} jobs waiting). Try again later.")
        job = Job(id=uuid.uuid4().hex, repo_url=repo_url, repo_full_name=repo_full_name, ref=options.ref,
                  options=options.model_dump(), status="queued", stage="queued", priority=priority,
                  cache_key=key, requested_by=requested_by, owner=owner)
        db.add(job)
        db.add(JobEvent(job_id=job.id, message=f"Job queued for {repo_url}"))
        return job, False


def _same_owner(owner: str | None):
    return Job.owner.is_(None) if owner is None else Job.owner == owner


def claim_next(worker_id: str) -> Job | None:
    """Atomically move the oldest highest-priority queued job to running."""
    s = get_settings()
    is_pg = engine().dialect.name == "postgresql"
    for _ in range(5):
        with session_scope() as db:
            stmt = (select(Job.id).where(Job.status == "queued", Job.cancel_requested.is_(False))
                    .order_by(Job.priority.desc(), Job.created_at.asc()).limit(1))
            if is_pg:
                stmt = stmt.with_for_update(skip_locked=True)
            job_id = db.scalar(stmt)
            if job_id is None:
                return None
            now = utcnow()
            res = db.execute(update(Job).where(Job.id == job_id, Job.status == "queued")
                             .values(status="running", stage="starting", worker_id=worker_id, started_at=now,
                                     lease_until=now + timedelta(seconds=s.lease_seconds), attempts=Job.attempts + 1))
            if res.rowcount == 1:
                db.add(JobEvent(job_id=job_id, message=f"Claimed by worker {worker_id}"))
                db.flush()
                return db.get(Job, job_id)
        # lost the race to another worker; try the next job
    return None


def heartbeat(job_id: str, worker_id: str) -> bool:
    """Extend the lease. Returns False if this worker no longer owns the job."""
    s = get_settings()
    with session_scope() as db:
        res = db.execute(update(Job).where(Job.id == job_id, Job.worker_id == worker_id, Job.status == "running")
                         .values(lease_until=utcnow() + timedelta(seconds=s.lease_seconds)))
        return res.rowcount == 1


def is_cancel_requested(job_id: str) -> bool:
    with session_scope() as db:
        return bool(db.scalar(select(Job.cancel_requested).where(Job.id == job_id)))


def set_progress(job_id: str, stage: str, progress: int) -> None:
    with session_scope() as db:
        db.execute(update(Job).where(Job.id == job_id).values(stage=stage, progress=max(0, min(100, progress))))


def set_stages(job_id: str, stages: list[dict]) -> None:
    with session_scope() as db:
        db.execute(update(Job).where(Job.id == job_id).values(stages=stages))


def update_summary(job_id: str, **changes) -> None:
    with session_scope() as db:
        job = db.get(Job, job_id)
        if job is not None:
            job.summary = {**(job.summary or {}), **changes}


def replace_artifact(job_id: str, name: str, content: str, content_type: str) -> None:
    with session_scope() as db:
        art = db.get(JobArtifact, {"job_id": job_id, "name": name})
        if art is None:
            db.add(JobArtifact(job_id=job_id, name=name, content_type=content_type, content=content,
                               size=len(content.encode("utf-8"))))
        else:
            art.content, art.content_type, art.size = content, content_type, len(content.encode("utf-8"))


def add_event(job_id: str, message: str, level: str = "info") -> None:
    with session_scope() as db:
        db.add(JobEvent(job_id=job_id, level=level, message=message[:4000]))


def complete(job_id: str, worker_id: str | None, summary: dict, artifacts: dict[str, tuple[str, str]],
             commit_sha: str | None, cached_from: str | None = None) -> None:
    with session_scope() as db:
        db.execute(delete(JobArtifact).where(JobArtifact.job_id == job_id))
        for name, (content, ctype) in artifacts.items():
            db.add(JobArtifact(job_id=job_id, name=name, content_type=ctype, content=content,
                               size=len(content.encode("utf-8"))))
        cond = [Job.id == job_id] + ([Job.worker_id == worker_id] if worker_id else [])
        db.execute(update(Job).where(*cond).values(
            status="completed", stage="done", progress=100, summary=summary, commit_sha=commit_sha,
            finished_at=utcnow(), lease_until=None, error=None, cached_from=cached_from))
        db.add(JobEvent(job_id=job_id, message="Job completed" + (f" (reused results of {cached_from})" if cached_from else "")))


def fail(job_id: str, worker_id: str | None, error: str, status: str = "failed", retry: bool = False) -> None:
    s = get_settings()
    with session_scope() as db:
        job = db.get(Job, job_id)
        if job is None or (worker_id and job.worker_id != worker_id):
            return
        if retry and job.attempts < s.max_job_attempts and status == "failed":
            job.status, job.stage, job.worker_id, job.lease_until = "queued", "queued", None, None
            db.add(JobEvent(job_id=job_id, level="warning", message=f"Attempt {job.attempts} failed, re-queued: {error[:500]}"))
            return
        job.status, job.error, job.finished_at, job.lease_until = status, error[:4000], utcnow(), None
        db.add(JobEvent(job_id=job_id, level="error" if status == "failed" else "warning", message=error[:4000]))


def request_cancel(job_id: str) -> Job | None:
    with session_scope() as db:
        job = db.get(Job, job_id)
        if job is None:
            return None
        if job.status == "queued":
            job.status, job.stage, job.finished_at, job.cancel_requested = "cancelled", "cancelled", utcnow(), True
            db.add(JobEvent(job_id=job_id, level="warning", message="Cancelled before start"))
        elif job.status == "running":
            job.cancel_requested = True
            db.add(JobEvent(job_id=job_id, level="warning", message="Cancellation requested"))
        return job


def retry_job(job_id: str) -> Job | None:
    with session_scope() as db:
        job = db.get(Job, job_id)
        if job is None or job.status not in TERMINAL:
            return job
        job.status, job.stage, job.progress, job.error, job.stages = "queued", "queued", 0, None, None
        job.cancel_requested, job.worker_id, job.attempts, job.finished_at = False, None, 0, None
        db.add(JobEvent(job_id=job_id, message="Re-queued by user"))
        return job


def recover_stale(now=None) -> int:
    """Re-queue (or fail) running jobs whose lease expired, e.g. after a worker crash."""
    s = get_settings()
    now = now or utcnow()
    recovered = 0
    with session_scope() as db:
        stale = db.scalars(select(Job).where(Job.status == "running", Job.lease_until.is_not(None))).all()
        for job in stale:
            if as_aware(job.lease_until) >= now:
                continue
            recovered += 1
            if job.cancel_requested:
                job.status, job.finished_at = "cancelled", now
            elif job.attempts >= s.max_job_attempts:
                job.status, job.error, job.finished_at = "failed", "Worker lost (lease expired) too many times.", now
            else:
                job.status, job.stage, job.worker_id = "queued", "queued", None
            job.lease_until = None
            db.add(JobEvent(job_id=job.id, level="warning", message=f"Lease expired on worker {job.worker_id}; "
                                                                    f"job is now {job.status}"))
    return recovered


def find_cached_result(job: Job, commit_sha: str) -> Job | None:
    s = get_settings()
    cutoff = utcnow() - timedelta(hours=s.result_cache_ttl_hours)
    with session_scope() as db:
        return db.scalars(select(Job).where(Job.cache_key == job.cache_key, _same_owner(job.owner),
                                            Job.commit_sha == commit_sha,
                                            Job.status == "completed", Job.id != job.id, Job.cached_from.is_(None),
                                            Job.finished_at >= cutoff)
                          .order_by(Job.finished_at.desc()).limit(1)).first()


def copy_artifacts(source_id: str) -> dict[str, tuple[str, str]]:
    with session_scope() as db:
        rows = db.scalars(select(JobArtifact).where(JobArtifact.job_id == source_id)).all()
        return {r.name: (r.content, r.content_type) for r in rows}


def stats() -> dict:
    with session_scope() as db:
        rows = db.execute(select(Job.status, func.count()).group_by(Job.status)).all()
        return {status: count for status, count in rows}
