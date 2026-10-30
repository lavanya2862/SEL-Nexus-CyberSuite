"""Write the data the website and the Unified Portal read (read-only): the triage queue and per-incident details.
The server never opens DuckDB, so a run and the website never block each other (same design as Threat Intel/Vulnerability).
"""

from __future__ import annotations

import json

from alert_triage.config import Settings
from alert_triage.store import Store, utcnow

SLA_HOURS = {"high": 1, "medium": 4, "low": 24, "informational": 72}


def queue(store: Store) -> list[dict]:
    rows = store.query("""
        SELECT i.incident_id, i.title, i.severity, i.status, i.classification, i.determination, i.sources, i.is_lab,
               i.web_url, i.created_at, i.updated_at,
               i.devices, i.accounts, v.verdict, v.confidence, v.recommended_severity, v.escalate, v.guardrails,
               v.summary, v.ai_status, v.triaged_at, v.queries_run, v.ti_lookups, v.seconds
        FROM incidents i JOIN verdicts v USING (incident_id)
        ORDER BY v.triaged_at DESC""")
    for r in rows:
        for key in ("devices", "accounts", "guardrails"):
            r[key] = _j(r.get(key))
        fb = store.query("SELECT agree, analyst_verdict FROM feedback WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
                         [r["incident_id"]])
        r["feedback"] = fb[0] if fb else None
        act = store.query("""SELECT action, status, done_at FROM actions WHERE incident_id = ? AND status = 'done'
                             AND action IN ('auto_resolve', 'auto_escalate', 'close_incident', 'escalate_incident',
                                            'reopen', 'isolate_device', 'release_device', 'av_scan',
                                            'quarantine_file')
                             ORDER BY COALESCE(done_at, requested_at) DESC LIMIT 1""", [r["incident_id"]])
        r["last_action"] = act[0] if act else None
    return rows


def export_all(store: Store, settings: Settings) -> None:
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    q = queue(store)
    counts = {}
    for r in q:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    payload = {
        "generated_at": utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
        "last_run": store.get_state("last_run"),
        "totals": {"incidents": len(q), "escalate": sum(1 for r in q if r["escalate"]),
                   "lab": sum(1 for r in q if r["is_lab"]),
                   "auto_resolved": sum(1 for r in q if (r["last_action"] or {}).get("action") == "auto_resolve"),
                   "resolved": sum(1 for r in q if (r.get("status") or "").lower() == "resolved")},
        "by_verdict": counts,
        "queue": q,
    }
    (settings.export_dir / "triage_data.json").write_text(json.dumps(payload, default=str, ensure_ascii=False),
                                                          encoding="utf-8")


def _j(v):
    if isinstance(v, (list, dict)):
        return v
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []
