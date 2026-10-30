"""'Agree & close in Defender' (TRIAGE_CLOSE=1): after a PERSON decides on the website, Alert Triage writes that decision into the
Defender incident through Graph, so the analyst doesn't have to do it again in the portal.

  harmless (benign positive) -> status resolved, classification "informational, expected activity"
  false alarm                -> status resolved, classification "false positive"
  real attack                -> NOT closed: status "in progress", classification "true positive", tag "AI-triage:
                                escalated" (a real attack is handed on, never closed with one click)
  needs investigation        -> nothing written (pick a final verdict first)

Every write also adds a comment saying who decided and why, and is logged in data/feedback/actions.jsonl.
The AI and the schedule never call this; only the website's button after a confirmation.
"""

from __future__ import annotations

import getpass
import json
import logging

from alert_triage.config import Settings
from alert_triage.feedback import add_action, add_feedback
from alert_triage.labels import label

log = logging.getLogger("alert_triage.close")

# analyst's choice of "why" -> Graph determination value
DETERMINATIONS = {
    "benign_positive": {"securityTesting": "Security test", "confirmedUserActivity": "Approved user / admin activity",
                        "lineOfBusinessApplication": "Business application"},
    "likely_false_positive": {"notMalicious": "Not malicious", "notEnoughDataToValidate": "Not enough data to validate"},
    "likely_true_positive": {"malware": "Malware", "compromisedAccount": "Compromised account",
                             "maliciousUserActivity": "Malicious user activity", "other": "Other"},
}
CLASSIFICATION = {"benign_positive": "informationalExpectedActivity", "likely_false_positive": "falsePositive",
                  "likely_true_positive": "truePositive"}
LABEL = {"benign_positive": "Informational, expected activity", "likely_false_positive": "False positive",
         "likely_true_positive": "True positive"}


class CloseError(ValueError):
    pass


def _saved(settings: Settings, incident_id: str) -> dict:
    from alert_triage.triage import _safe
    path = settings.verdicts_dir / f"{_safe(incident_id)}.json"
    if not path.is_file():
        raise CloseError("unknown incident")
    return json.loads(path.read_text(encoding="utf-8"))


def plan(verdict: str, determination: str | None) -> dict:
    """The exact change written to Defender for a final verdict (pure function, tested)."""
    if verdict not in CLASSIFICATION:
        raise CloseError("Pick a final verdict (true positive, false positive or informational/expected activity) "
                         "before writing to Defender.")
    options = DETERMINATIONS[verdict]
    det = determination if determination in options else next(iter(options))
    if verdict == "likely_true_positive":
        return {"status": "inProgress", "classification": "truePositive", "determination": det,
                "customTags": ["AI-triage: escalated"]}
    return {"status": "resolved", "classification": CLASSIFICATION[verdict], "determination": det,
            "customTags": ["AI-triage: closed after review"]}


def act(settings: Settings, graph, incident_id: str, verdict: str, determination: str | None, reason: str,
        minutes: float | None = None, by: str | None = None) -> dict:
    if not settings.close:
        raise CloseError("Closing in Defender is switched off in the settings.")
    saved = _saved(settings, incident_id)
    ai_verdict = saved["verdict"].get("verdict")
    changes = plan(verdict, determination)
    who = (by or "").strip()[:80] or getpass.getuser()       # the portal passes the signed-in person's name
    try:
        graph.update_incident(incident_id, changes)
    except Exception as exc:  # noqa: BLE001
        add_action(settings, incident_id, "close_incident", incident_id, "failed", str(exc).splitlines()[0][:300])
        raise CloseError(f"Defender refused: {str(exc).splitlines()[0][:200]}") from exc
    note = (f"Decided by {who} in SEL Nexus CyberSuite: {LABEL[verdict]}"
            f" ({DETERMINATIONS[verdict][changes['determination']]}). "
            f"The assistant's AI had said: {label(ai_verdict)}. "
            + (f"Reason: {reason[:300]}" if reason else ""))
    try:
        graph.add_comment(incident_id, note)
    except Exception as exc:  # noqa: BLE001 - the decision is already written; the comment is a nice-to-have
        log.warning("Comment after closing %s failed: %s", incident_id, exc)
    action = "close_incident" if changes["status"] == "resolved" else "escalate_incident"
    row = add_action(settings, incident_id, action, incident_id, "done",
                     f"{changes['status']} / {changes['classification']} / {changes['determination']} by {who}",
                     done=True)
    add_feedback(settings, incident_id, agree=(verdict == ai_verdict), analyst_verdict=verdict, reason=reason,
                 minutes=minutes, mode="assisted")
    log.info("Incident %s: %s by %s", incident_id, action, who)
    return {"action": row, "changes": changes}
