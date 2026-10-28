"""Alerts for high-risk threats that affect us: rating Critical/High AND (exposed OR hunt hit).

Each alert is raised once per threat and rating. Delivery: data/alerts.jsonl + the dashboard banner, and a
Microsoft Teams message only if TEAMS_WEBHOOK_URL is set in .env (needs your organisation's approval).
"""

from __future__ import annotations

import hashlib
import json
import logging

import requests

from uc1.config import Settings
from uc1.store import NEW_IDS_SHOWN, Store, utcnow

log = logging.getLogger("uc1.alerts")


def candidates(store: Store) -> list[dict]:
    return store.query("""
        SELECT t.threat_id, t.title, t.is_test, s.rating, s.score, s.why,
               a.actions, a.summary, (SELECT max(e.recommended_update) FROM exposure e WHERE e.threat_id = t.threat_id AND e.recommended_update <> '') AS fix,
               (SELECT string_agg(DISTINCT f.device_name, ', ') FROM findings f WHERE f.threat_id = t.threat_id) AS devices
        FROM threats t JOIN scores s ON s.threat_id = t.threat_id LEFT JOIN analysis a ON a.threat_id = t.threat_id
        WHERE s.rating IN ('Critical', 'High')
          AND t.threat_id IN (SELECT threat_id FROM findings)
        ORDER BY s.score DESC""")


def run(store: Store, settings: Settings) -> dict:
    new = []
    for c in candidates(store):
        alert_id = hashlib.sha256(f"{c['threat_id']}|{c['rating']}".encode()).hexdigest()[:16]
        if store.scalar("SELECT 1 FROM alerts WHERE alert_id = ?", [alert_id]):
            continue
        actions = json.loads(c["actions"] or "[]") if isinstance(c["actions"], str) else (c["actions"] or [])
        actions = ([c["fix"]] if c["fix"] else []) + actions
        prefix = "[TEST] " if c["is_test"] else ""
        message = (f"{prefix}{c['rating']} risk: {c['title']}\nAffected: {c['devices'] or 'n/a'}\nWhy: {c['why']}\n"
                   f"First action: {actions[0] if actions else 'see report'}")
        new.append({"alert_id": alert_id, "threat_id": c["threat_id"], "rating": c["rating"], "title": prefix + c["title"],
                    "message": message, "is_test": c["is_test"], "created_at": utcnow(), "delivered": "dashboard"})
    if not new:
        return {"new_alerts": 0}
    if settings.teams_webhook_url:
        for a in new:
            try:
                requests.post(settings.teams_webhook_url, json={"text": a["message"].replace("\n", "<br>")}, timeout=20)
                a["delivered"] = "dashboard+teams"
            except requests.RequestException as exc:
                log.warning("Teams delivery failed: %s", exc)
    store.upsert("alerts", new)
    path = settings.data_dir / "alerts.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        for a in new:
            fh.write(json.dumps(a, default=str, ensure_ascii=False) + "\n")
    for a in new:
        log.warning("ALERT %s", a["message"].replace("\n", " | "))
    return {"new_alerts": len(new), "new_alert_ids": [a["alert_id"] for a in new][:NEW_IDS_SHOWN]}
