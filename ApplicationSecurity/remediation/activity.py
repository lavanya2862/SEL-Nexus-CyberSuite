"""The activity log: who started, re-ran or cancelled a scan, approved its fixes, opened a pull request, ran the tests on
GitHub or changed their own settings, with their name, email and the time. Shown on the Activity log page.

Recording never fails the action it records; values of keys are never written here, only which ones changed.
"""
from __future__ import annotations

import logging
from typing import NamedTuple

from sqlalchemy import func, or_, select

from .db import Activity, session_scope

log = logging.getLogger(__name__)

ACTIONS = ("scan_started", "scan_rerun", "scan_cancelled", "fixes_approved", "pr_opened", "pr_failed", "tests_started",
           "tests_cancelled", "draft_reviewed", "settings_changed")


class Actor(NamedTuple):
    email: str | None
    name: str | None

    def label(self) -> str:
        if self.name and self.email and self.name != self.email:
            return f"{self.name} ({self.email})"
        return self.name or self.email or "someone"

    def as_dict(self) -> dict:
        return {"email": self.email, "name": self.name}


LOCAL = Actor(None, "Local user")  # without the shared sign-in there is one, unnamed, person


def record(who: Actor, action: str, job_id: str | None = None, repo: str | None = None, detail: str = "") -> None:
    try:
        with session_scope() as db:
            db.add(Activity(email=who.email, name=who.name, action=action, job_id=job_id, repo=repo,
                            detail=detail[:2000]))
    except Exception:  # noqa: BLE001 - the audit trail must never break the action itself
        log.exception("could not record activity %s by %s", action, who.label())


def listing(limit: int = 100, offset: int = 0, action: str | None = None, q: str | None = None,
            only: str | None = None) -> dict:
    """Newest first. ``q`` matches a name, email or repository; ``only`` limits it to one person's actions."""
    stmt = select(Activity)
    if action:
        stmt = stmt.where(Activity.action == action)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Activity.name.ilike(like), Activity.email.ilike(like), Activity.repo.ilike(like)))
    if only is not None:
        stmt = stmt.where(Activity.email == only)
    with session_scope() as db:
        total = db.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = db.scalars(stmt.order_by(Activity.ts.desc(), Activity.id.desc()).limit(limit).offset(offset)).all()
        items = [{"id": r.id, "ts": _iso(r.ts), "email": r.email, "name": r.name, "action": r.action,
                  "job_id": r.job_id, "repo": r.repo, "detail": r.detail} for r in rows]
    return {"total": total, "items": items}


def _iso(value) -> str | None:
    from .db import as_aware
    return as_aware(value).isoformat() if value else None
