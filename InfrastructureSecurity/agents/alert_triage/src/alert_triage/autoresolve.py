"""Automatic handling (UC4_AUTO_RESOLVE=1), policy in config/auto_resolve.yaml:

  harmless / false alarm, high confidence, no safety rule, not high severity -> RESOLVED in Defender (incident and
      its alerts) with a comment explaining why
  real attack                                                               -> ESCALATED: in progress, true positive,
      tagged; never closed automatically
  anything else                                                             -> left open, tagged "needs human"

Each incident version is handled once (state key per fingerprint). Every action is logged in
data/feedback/actions.jsonl and can be undone with the website's Reopen button (reopen()).
"""

from __future__ import annotations

import json
import logging

from alert_triage.config import Settings, read_yaml
from alert_triage.feedback import add_action
from alert_triage.labels import label
from alert_triage.store import Store

log = logging.getLogger("alert_triage.autoresolve")
SEV_ORDER = ["informational", "low", "medium", "high"]
CONF_ORDER = ["low", "medium", "high"]


def _list(v):
    if isinstance(v, list):
        return v
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []


def decide(v: dict, incident: dict, policy: dict) -> tuple[str, str]:
    """('resolve' | 'escalate' | 'needs_human', reason). Pure function: easy to test and to explain."""
    res, esc = policy.get("resolve", {}), policy.get("escalate", {})
    verdict, conf = v.get("verdict"), (v.get("confidence") or "low").lower()
    guards = _list(v.get("guardrails"))
    if policy.get("only_lab_incidents", True) and not incident.get("is_lab"):
        return "needs_human", "not a lab incident (PoC rule)"
    if v.get("ai_status") != "ai":
        return "needs_human", "the AI was not used for this verdict"
    if verdict in esc.get("verdicts", []) and CONF_ORDER.index(conf) >= CONF_ORDER.index(esc.get("min_confidence", "medium")):
        return "escalate", f"true positive ({conf} confidence)"
    if verdict in res.get("verdicts", []):
        if CONF_ORDER.index(conf) < CONF_ORDER.index(res.get("min_confidence", "high")):
            return "needs_human", f"confidence {conf} is below {res.get('min_confidence', 'high')}"
        limit = SEV_ORDER.index(res.get("max_severity", "medium"))
        for sev in (incident.get("severity"), v.get("recommended_severity")):
            if sev in SEV_ORDER and SEV_ORDER.index(sev) > limit:
                return "needs_human", f"severity {sev} is too high to close automatically"
        if res.get("block_if_any_guardrail", True) and guards:
            return "needs_human", f"safety rule fired: {', '.join(guards)}"
        if v.get("playbook") in res.get("block_playbooks", []):
            return "needs_human", f"playbook {v.get('playbook')} is never closed automatically"
        return "resolve", f"{label(verdict)} with high confidence and no safety rule"
    return "needs_human", f"verdict: {label(verdict)}"


def changes_for(action: str, verdict: str, policy: dict) -> dict | None:
    if action == "resolve":
        det = (policy.get("resolve", {}).get("determination") or {}).get(verdict, "notMalicious")
        cls = "informationalExpectedActivity" if verdict == "benign_positive" else "falsePositive"
        return {"status": "resolved", "classification": cls, "determination": det,
                "customTags": ["AI-triage: auto-resolved"]}
    if action == "escalate":
        return {"status": "inProgress", "classification": "truePositive", "determination": "other",
                "customTags": ["AI-triage: escalated"]}
    tag = (policy.get("needs_human") or {}).get("tag", "AI-triage: needs human")
    return {"customTags": [tag]}


def run(graph, store: Store, settings: Settings, policy: dict | None = None) -> dict:
    if not settings.auto_resolve:
        return {"switched": "off"}
    policy = policy or read_yaml("auto_resolve.yaml")
    rows = store.query("""SELECT v.*, i.severity AS inc_severity, i.status AS inc_status, i.is_lab
                          FROM verdicts v JOIN incidents i USING (incident_id)""")
    counts = {"resolve": 0, "escalate": 0, "needs_human": 0, "failed": 0}
    # a person's decision always wins: never act again on incidents a person reopened or closed on the website
    human = {r["incident_id"] for r in store.query(
        "SELECT DISTINCT incident_id FROM actions WHERE action IN ('reopen', 'close_incident', 'escalate_incident') "
        "AND status = 'done'")}
    for v in rows:
        key = f"auto:{v['incident_id']}:{v['fingerprint']}"
        last = f"auto_last:{v['incident_id']}"
        if (v["inc_status"] or "").lower() == "resolved" or v["incident_id"] in human:
            continue
        action, reason = decide(v, {"is_lab": v["is_lab"], "severity": v["inc_severity"]}, policy)
        # done already: for these alerts, or as the incident's last action (a new alert that doesn't change the
        # decision must not post the same escalation again). A re-triage that changes the action acts again.
        if action in (store.get_state(key), store.get_state(last)):
            continue
        changes = changes_for(action, v["verdict"], policy)
        try:
            graph.update_incident(v["incident_id"], changes)
            if action != "needs_human":
                graph.add_comment(v["incident_id"], _comment(action, reason, v))
        except Exception as exc:  # noqa: BLE001
            counts["failed"] += 1
            add_action(settings, v["incident_id"], f"auto_{action}", v["incident_id"], "failed",
                       str(exc).splitlines()[0][:300])
            log.warning("Automatic %s of %s failed: %s", action, v["incident_id"], str(exc).splitlines()[0][:200])
            continue
        store.set_state(key, action)
        store.set_state(last, action)
        if action == "resolve":
            store.execute("UPDATE incidents SET status = 'resolved' WHERE incident_id = ?", [v["incident_id"]])
        add_action(settings, v["incident_id"], f"auto_{action}", v["incident_id"], "done",
                   f"{reason} -> {json.dumps(changes)}", done=True)
        counts[action] += 1
        log.info("Automatic %s for incident %s: %s", action, v["incident_id"], reason)
    return counts


def _comment(action: str, reason: str, v: dict) -> str:
    head = {"resolve": "Resolved automatically by Security Assistant", "escalate": "Escalated automatically by Security Assistant"}[action]
    return (f"{head}: {reason}. AI verdict: {label(v['verdict'])} (confidence {v['confidence']}, "
            f"severity {v['recommended_severity']}). {(v.get('summary') or '')[:500]} "
            "If this is wrong, use Reopen in Security Assistant (Alert response) or reopen the incident here.")


def reopen(settings: Settings, graph, incident_id: str, reason: str = "") -> dict:
    """Undo: set the incident back to active (human click on the website)."""
    import getpass
    who = getpass.getuser()
    graph.update_incident(incident_id, {"status": "active", "classification": "unknown", "determination": "unknown",
                                        "customTags": ["AI-triage: reopened by analyst"]})
    graph.add_comment(incident_id, f"Reopened by {who} in Security Assistant (Alert response). {reason[:300]}".strip())
    return add_action(settings, incident_id, "reopen", incident_id, "done", f"reopened by {who}: {reason[:200]}",
                      done=True)
