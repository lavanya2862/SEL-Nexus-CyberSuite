"""The bell: one newest-first list of what the assistant raised or did, from data it already keeps (read-only).

- threat alerts the Threat Intel Agent raised (UC1 dashboard `alerts`)
- holes the news named for an app version we have that Defender doesn't list yet (UC1 `explorer`, match "early")
- incidents the Alert Triage Agent rated, and the automatic actions it took (UC4 export + actions.jsonl)
- agent runs that finished or failed (portal run history)
- automatic-fixing events (UC1's fix view; only when the fixing service is answering, so the bell never waits)
- data-quality checks that failed (UC3)

Every item has a stable id, so the web app can tell what is new since the user last opened the bell.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from urllib.parse import quote

from portal import fixproxy, services
from portal.audit import AuditLog
from portal.sources import UC1, UC4, _jsonl

AGENTS = {"uc1": "Threat Intel Agent", "uc3": "Vulnerability Agent", "uc4": "Alert Triage Agent", "attack": "Attack Detection Agent"}
VERDICT_WORDS = {"likely_true_positive": "true positive", "likely_false_positive": "false positive",
                 "benign_positive": "false positive", "needs_investigation": "needs review"}
ACTION_WORDS = {"auto_resolve": "Closed", "auto_escalate": "Escalated",
                "auto_tag": "Marked for review", "av_scan": "Antivirus scan started", "stop_quarantine": "File stopped and quarantined",
                "isolate_device": "Device isolated", "release_device": "Device released", "reopen": "Reopened",
                "close_incident": "Closed by a person", "escalate_incident": "Escalated by a person", "comment": "Note added in Defender",
                "remove_inbox_rule": "Inbox rule removed"}
LEVEL = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info"}
MAX_ITEMS = 40


def iso(value) -> str | None:
    """Any of our time formats → ISO UTC with Z. Times without a zone are UTC (the agents store UTC)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).strip().replace(" ", "T").replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def item(id_: str, at, kind: str, level: str, title: str, detail: str = "", link: str | None = None) -> dict | None:
    at = iso(at)
    if not at:
        return None
    return {"id": id_, "at": at, "kind": kind, "level": level, "title": title[:160], "detail": detail[:240], "link": link}


def _threats(settings) -> list[dict]:
    out = []
    for a in (UC1(settings.uc1_dir).dashboard() or {}).get("alerts") or []:
        lines = [l for l in str(a.get("message") or "").splitlines()[1:] if l.strip()]
        affected = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("Affected:")), "")
        detail = (f"On {affected}" if affected else "") + (" · lab test" if a.get("is_test") else "")
        out.append(item(f"threat:{a.get('alert_id')}", a.get("created_at"), "threat",
                        LEVEL.get(str(a.get("rating")).lower(), "medium"), str(a.get("title") or "Threat alert"), detail,
                        f"/uc1/threat/{quote(str(a.get('threat_id') or ''), safe='')}" if a.get("threat_id") else "/uc1"))
    return out


def _not_in_defender(settings) -> list[dict]:
    """A hole the news named for an app version we have, that Defender doesn't list yet (UC1 exposure 'early')."""
    out = []
    for t in (UC1(settings.uc1_dir).dashboard() or {}).get("explorer") or []:
        if t.get("match") != "early" or t.get("test"):
            continue
        early = [x for x in t.get("on_us") or [] if x.get("match") == "early"]
        first = early[0] if early else {}
        devices = ", ".join(dict.fromkeys(x.get("device", "") for x in early))
        out.append(item(f"early:{t.get('id')}", first.get("known") or t.get("first_seen"), "threat", "high",
                        f"Not in Defender yet: {first.get('cve', '')} in {first.get('app', '')} {first.get('version', '')}".strip(),
                        f"On {devices} · the installed version is affected; Defender hasn't listed it yet",
                        "/uc1/affects?show=early"))
    return out


def _incidents(settings) -> list[dict]:
    uc4 = UC4(settings.uc4_dir)
    out = []
    for q in (uc4.queue() or {}).get("queue") or []:
        verdict = VERDICT_WORDS.get(q.get("verdict"), "not rated yet")
        detail = f"Rated {verdict}" + (f", {q['confidence']} confidence" if q.get("confidence") else "") + \
                 (" · escalated" if q.get("escalate") else "")
        out.append(item(f"incident:{q.get('incident_id')}:{q.get('verdict')}", q.get("triaged_at") or q.get("created_at"),
                        "incident", LEVEL.get(str(q.get("severity")).lower(), "medium"),
                        f"Incident #{q.get('incident_id')}: {q.get('title')}", detail, f"/respond/{quote(str(q.get('incident_id')))}"))
    for a in _jsonl(settings.uc4_dir / "data" / "feedback" / "actions.jsonl")[-60:]:
        if a.get("status") not in ("done", "failed"):
            continue
        words = ACTION_WORDS.get(a.get("action"), str(a.get("action") or "Action").replace("_", " ").capitalize())
        failed = a.get("status") == "failed"
        out.append(item(f"action:{a.get('action_id')}", a.get("done_at") or a.get("requested_at"), "action",
                        "high" if failed else "info", f"{words}{' (failed)' if failed else ''}: incident #{a.get('incident_id')}"
                        + (f" on {a['target']}" if a.get("target") and str(a["target"]) != str(a.get("incident_id")) else ""),
                        _plain(a.get("detail")), f"/respond/{quote(str(a.get('incident_id')))}"))
    return out


def _plain(detail) -> str:
    """Drop Defender's internal action ids from a detail line."""
    text = str(detail or "").split(" -> ")[0]
    return re.sub(r"\s*\(action [0-9a-f-]{20,}, status (\w+)\)", r" (\1)", text).strip()


def _runs(history: list[dict]) -> list[dict]:
    out = []
    for r in history[:12]:
        if r.get("status") == "running" or not r.get("finished_at"):
            continue
        ok = r.get("status") == "ok"
        name = AGENTS.get(r.get("uc"), r.get("uc"))
        out.append(item(f"run:{r.get('run_id')}", r.get("finished_at"), "agent", "info" if ok else "high",
                        f"{name} {'finished' if ok else 'stopped'}", "" if ok else str(r.get("message") or ""),
                        f"/runs/{r.get('uc')}"))
    return out


def _fixes(settings) -> list[dict]:
    if not services.listening(settings.uc1_site, timeout=0.3):
        return []
    try:
        events = fixproxy.named(fixproxy.get_fix(settings.uc1_site), AuditLog(settings.audit_dir).entries).get("events") or []
    except fixproxy.Uc1Unavailable:
        return []
    out = []
    for e in events[:12]:
        text = str(e.get("text") or "")
        bad = any(w in text.lower() for w in ("failed", "still there", "error"))
        out.append(item(f"fix:{e.get('at')}:{hashlib.md5(text.encode()).hexdigest()[:8]}", e.get("at"), "fix", "high" if bad else "info",
                        text.split(": ", 1)[0] if ": " in text and len(text) > 90 else text,
                        text.split(": ", 1)[1] if ": " in text and len(text) > 90 else "",
                        "/fixes/progress"))
    return out


def _quality(summary: dict) -> list[dict]:
    h = next((h for h in summary.get("health") or [] if h.get("key") == "uc3"), {})
    bad = [q for q in (summary.get("uc3") or {}).get("quality") or [] if str(q.get("status")).upper() in ("FAIL", "ERROR")]
    if not bad:
        return []
    names = ", ".join(q.get("check_name", "") for q in bad[:4])
    return [item(f"quality:{h.get('data_as_of')}", h.get("data_as_of"), "quality", "high",
                 f"{len(bad)} data check{'s' if len(bad) != 1 else ''} failed", names, "/uc3/quality")]


def build(settings, summary: dict, run_history: list[dict]) -> dict:
    items = [i for part in (_threats(settings), _not_in_defender(settings), _incidents(settings), _runs(run_history),
                            _fixes(settings), _quality(summary))
             for i in part if i]
    items.sort(key=lambda i: i["at"], reverse=True)
    return {"items": items[:MAX_ITEMS], "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
