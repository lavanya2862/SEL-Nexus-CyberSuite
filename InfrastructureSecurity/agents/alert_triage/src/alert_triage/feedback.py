"""Analyst feedback and actions written by the website. The website only appends to JSON-lines files (it never
opens the database, so it can't block a scheduled run); each run imports them into DuckDB.

  data/feedback/feedback.jsonl  {"feedback_id", "incident_id", "agree", "analyst_verdict", "reason", "minutes",
                                 "mode": "assisted"|"manual", "created_at"}
  data/feedback/actions.jsonl   {"action_id", "incident_id", "action", "target", "status", "detail",
                                 "requested_at", "done_at"}
"""

from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path

from alert_triage.config import Settings
from alert_triage.schemas import VERDICTS
from alert_triage.store import Store, to_utc, utcnow

_lock = threading.Lock()


def _append(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock, path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def add_feedback(settings: Settings, incident_id: str, agree: bool, analyst_verdict: str | None, reason: str,
                 minutes: float | None, mode: str = "assisted") -> dict:
    if analyst_verdict and analyst_verdict not in VERDICTS:
        raise ValueError("unknown verdict")
    if mode not in ("assisted", "manual"):
        raise ValueError("mode must be assisted or manual")
    if minutes is not None and not (0 <= float(minutes) <= 600):
        raise ValueError("minutes must be between 0 and 600")
    row = {"feedback_id": uuid.uuid4().hex[:12], "incident_id": str(incident_id)[:80], "agree": bool(agree),
           "analyst_verdict": analyst_verdict or None, "reason": (reason or "")[:500],
           "minutes": float(minutes) if minutes not in (None, "") else None, "mode": mode,
           "created_at": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}
    _append(settings.feedback_dir / "feedback.jsonl", row)
    return row


def add_action(settings: Settings, incident_id: str, action: str, target: str, status: str, detail: str = "",
               done: bool = False) -> dict:
    now = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    row = {"action_id": uuid.uuid4().hex[:12], "incident_id": str(incident_id)[:80], "action": action,
           "target": target, "status": status, "detail": detail[:500], "requested_at": now,
           "done_at": now if done else None}
    _append(settings.feedback_dir / "actions.jsonl", row)
    return row


def import_all(store: Store, settings: Settings) -> dict:
    fb = read_jsonl(settings.feedback_dir / "feedback.jsonl")
    store.upsert("feedback", [{**r, "created_at": to_utc(r.get("created_at"))} for r in fb if r.get("feedback_id")])
    acts = read_jsonl(settings.feedback_dir / "actions.jsonl")
    store.upsert("actions", [{**r, "requested_at": to_utc(r.get("requested_at")), "done_at": to_utc(r.get("done_at"))}
                             for r in acts if r.get("action_id")])
    return {"feedback": len(fb), "actions": len(acts)}


def latest_by_incident(settings: Settings) -> dict[str, dict]:
    """For the website: the newest feedback per incident, straight from the file (no database)."""
    out: dict[str, dict] = {}
    for r in read_jsonl(settings.feedback_dir / "feedback.jsonl"):
        out[r.get("incident_id")] = r
    return out
