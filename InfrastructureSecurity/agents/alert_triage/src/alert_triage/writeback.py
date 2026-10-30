"""Pilot write-back (OFF by default; TRIAGE_WRITEBACK=1 turns it on): post one 'AI-triage' comment on each triaged
lab incident through Graph. It never changes the incident's status, classification or assignment.
Needs the extra Graph permission SecurityIncident.ReadWrite.All.
"""

from __future__ import annotations

import logging

from alert_triage.config import Settings
from alert_triage.store import Store

log = logging.getLogger("alert_triage.writeback")


def comment_text(v: dict) -> str:
    sev = v.get("recommended_severity") or "?"
    esc = "yes" if v.get("escalate") else "no"
    guard = ", ".join(_list(v.get("guardrails"))) or "none"
    from alert_triage.labels import label
    return (f"AI-triage [shadow, recommend-only]: {label(v['verdict'])} "
            f"(confidence {v.get('confidence')}, severity {sev}, escalate {esc}; guardrails: {guard}). "
            f"{(v.get('summary') or '')[:600]} An analyst decides; see Security Assistant (Alert response).")


def post_pending(graph, store: Store, settings: Settings) -> int:
    if not settings.writeback:
        return 0
    rows = store.query("""SELECT v.*, i.is_lab, i.status AS inc_status FROM verdicts v JOIN incidents i USING (incident_id)""")
    posted = 0
    for v in rows:
        if not v["is_lab"]:
            continue                                   # PoC rule: only lab incidents get comments
        key = f"commented:{v['incident_id']}:{v['fingerprint']}"
        auto = store.get_state(f"auto:{v['incident_id']}:{v['fingerprint']}")
        if store.get_state(key) or auto in ("resolve", "escalate") or (v["inc_status"] or "").lower() == "resolved":
            continue                                   # automatic handling already wrote its own explaining comment
        try:
            graph.add_comment(v["incident_id"], comment_text(v))
        except Exception as exc:  # noqa: BLE001
            log.warning("Comment on %s failed: %s", v["incident_id"], str(exc).splitlines()[0][:200])
            continue
        store.set_state(key, "1")
        posted += 1
    return posted


def _list(value):
    import json
    if isinstance(value, list):
        return value
    try:
        return json.loads(value) if value else []
    except (ValueError, TypeError):
        return []
