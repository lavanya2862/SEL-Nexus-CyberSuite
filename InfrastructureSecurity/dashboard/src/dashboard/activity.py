"""Activity log: who ran which agent pipeline and who acted on its results, and when (GET /api/activity).

Since the activity trail (audit.py) began, every run start, Remediation action and triage decision is recorded there
with the signed-in person's name and email. Anything older is rebuilt from what the agents kept themselves, so the
log does not start empty: the portal's run folders (data/runs/*/meta.json, result.json) and the Remediation state
of the Threat Intel Agent (Threat Intel data/fix/state.json: who approved each fix, when it ran and how it ended).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from dashboard.audit import ACTIONS
from dashboard.fixproxy import is_account
from dashboard.runs import AGENT_NAMES, agent_key

KINDS = ("run", "fix", "triage")
NOT_RECORDED = "Not recorded"
METHODS = {"runcommand": "Azure Run Command", "liveresponse": "Defender Live Response"}


def _utc(value) -> str | None:
    """ISO time in UTC; times without a zone (Threat Intel's fix state) are taken as UTC."""
    if not value:
        return None
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat(timespec="seconds")


def _person(by) -> tuple[str, str]:
    """(name, email) from a run's "by" ({email, name}) or a fix's approver. A computer account (Threat Intel wrote the Windows
    login before the portal passed the person's name) or "portal" = not recorded."""
    if isinstance(by, dict):
        return str(by.get("name") or by.get("email") or NOT_RECORDED), str(by.get("email") or "")
    by = str(by or "").strip()
    return (by, "") if by and not is_account(by) else (NOT_RECORDED, "")


def _entry(key: str, at, action: str, who, *, agent: str = "", target: str = "", outcome: str = "success",
           detail: str = "", run: str | None = None) -> dict | None:
    ts = _utc(at)
    if not ts:
        return None
    name, email = _person(who)
    return {"id": key, "ts": ts, "email": email, "name": name, "action": action, "label": ACTIONS.get(action, action),
            "agent": agent, "target": target, "outcome": outcome, "detail": detail, "run": run, "source": "history"}


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def earlier_runs(runs_dir: Path) -> list[dict]:
    out = []
    for d in sorted(runs_dir.glob("*_*")) if runs_dir.is_dir() else []:
        meta = _read_json(d / "meta.json")
        if not meta:
            continue
        uc = agent_key(str(meta.get("uc") or d.name.rsplit("_", 1)[-1]))
        agent = AGENT_NAMES.get(uc, uc)
        out.append(_entry(f"run:{d.name}", meta.get("started_at"), "run.start", meta.get("by"), agent=agent,
                          target=d.name, run=d.name))
        result = _read_json(d / "result.json")
        if result.get("finished_at"):
            code = result.get("exit_code")
            out.append(_entry(f"run-end:{d.name}", result["finished_at"], "run.finish", meta.get("by"), agent=agent,
                              target=d.name, run=d.name, outcome="success" if code == 0 else "failed",
                              detail="Finished normally" if code == 0 else f"Ended with exit code {code}"))
    return [e for e in out if e]


def earlier_fixes(threat_intel_dir: Path) -> list[dict]:
    fixes = _read_json(threat_intel_dir / "data" / "fix" / "state.json").get("fixes") or {}
    out = []
    for fix_id, f in fixes.items() if isinstance(fixes, dict) else []:
        if not isinstance(f, dict):
            continue
        item = f.get("item") or {}
        target = f"{item.get('app') or item.get('software_name') or fix_id} on {item.get('device_name') or '?'}"
        method = METHODS.get(f.get("method"), f.get("method") or "")
        who = f.get("approved_by")
        agent = AGENT_NAMES["threat_intel"]
        if f.get("status") == "saved":
            out.append(_entry(f"fix-save:{fix_id}", f.get("saved_at"), "fix.save", f.get("saved_by"), agent=agent, target=target))
            continue
        out.append(_entry(f"fix-approve:{fix_id}", f.get("approved_at"), "fix.approve", who, agent=agent, target=target,
                          detail=method and f"Method: {method}"))
        if f.get("finished_at"):
            status = str(f.get("status") or "")
            ok = status in ("verified", "done")
            out.append(_entry(f"fix-run:{fix_id}", f["finished_at"], "fix.run", who, agent=agent, target=target,
                              outcome="success" if ok else "failed", detail=str(f.get("message") or status)[:500]))
    return [e for e in out if e]


def listing(audit_rows: list[dict], runs_dir: Path, threat_intel_dir: Path, *, action: str = "", q: str = "",
            limit: int = 300, offset: int = 0) -> dict:
    rows = [{"id": f"audit:{r.get('seq')}", "ts": _utc(r.get("at")) or r.get("at"), "email": r.get("user_email") if r.get("user_email") != "unknown" else "",
             "name": r.get("user_name"), "action": r.get("action"), "label": ACTIONS.get(r.get("action", ""), r.get("action", "")),
             "agent": AGENT_NAMES.get(r.get("agent"), r.get("agent") or ""), "target": r.get("target") or "",
             "outcome": r.get("outcome") or "success", "detail": r.get("detail") or "", "run": r.get("ref"), "source": "audit"}
            for r in audit_rows if "_broken" not in r and str(r.get("action", "")).split(".")[0] in KINDS]
    # older events only from before the trail began, so nothing shows twice
    began = min((r["ts"] for r in rows if r["ts"]), default=None)
    rows += [e for e in earlier_runs(runs_dir) + earlier_fixes(threat_intel_dir) if not began or e["ts"] < began]
    if action:
        rows = [r for r in rows if r["action"] == action or r["action"].startswith(action + ".")]
    needle = q.strip().lower()[:200]
    if needle:
        rows = [r for r in rows if any(needle in str(r.get(k) or "").lower() for k in ("name", "email", "agent", "target", "detail", "run"))]
    rows.sort(key=lambda r: (r["ts"] or "", str(r["id"])), reverse=True)
    limit, offset = max(1, min(limit, 1000)), max(0, offset)
    return {"items": rows[offset:offset + limit], "total": len(rows)}
