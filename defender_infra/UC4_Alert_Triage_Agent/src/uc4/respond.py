"""Response playbook (UC4_RESPOND=1).

After triage, every incident is put in one situation, and Defender's OWN built-in actions are requested when needed:

  false positive / expected activity -> nothing on the computer (autoresolve.py closes the incident)
  true positive, already blocked     -> ask Defender for an antivirus scan of each lab device on the incident
  true positive, still active        -> antivirus scan + stop-and-quarantine of the file(s) involved (high confidence);
                                        isolate only if UC4_AUTO_ISOLATE=1 and it's high severity + high confidence
  needs review                       -> nothing on the computer (a person decides)

Defender's automated investigation ("Full" automation level in the device group) does its own clean-up in parallel.
Rules: lab devices only; each action once per incident and device (max 3 tries on failure); every request is
logged (data/feedback/actions.jsonl) and explained in a Defender comment. `collect_view()` saves what Defender did
(investigation state, clean-up status per file/process, scans and other device actions) for the website.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta

from uc4.config import Settings
from uc4.feedback import add_action
from uc4.labels import label
from uc4.store import Store, to_utc, utcnow

log = logging.getLogger("uc4.respond")

SITUATION_LABEL = {
    "false_positive": "False positive",
    "expected_activity": "Informational, expected activity",
    "tp_blocked": "True positive, already blocked",
    "tp_active": "True positive, still active",
    "needs_review": "Needs review",
}
STOPPED = {"prevented", "blocked", "remediated"}
MAX_TRIES = 3


def _list(v):
    if isinstance(v, list):
        return v
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []


def _evidence(packet: dict) -> list[dict]:
    ent = packet["entities"]
    return [e for e in ent.get("files", []) + ent.get("processes", []) if e.get("sha1") or e.get("detection")]


def situation(verdict: dict, packet: dict) -> str:
    v = verdict.get("verdict")
    if v == "likely_false_positive":
        return "false_positive"
    if v == "benign_positive":
        return "expected_activity"
    if v != "likely_true_positive":
        return "needs_review"
    ev = _evidence(packet)
    statuses = [(e.get("remediation") or e.get("detection") or "").lower() for e in ev]
    return "tp_blocked" if statuses and all(s in STOPPED for s in statuses) else "tp_active"


def _lab_devices(packet: dict, settings: Settings) -> list[dict]:
    lab = {d.split(".")[0] for d in settings.lab_devices}
    return [d for d in packet["entities"]["devices"] if d.get("id") and (d.get("name") or "").split(".")[0] in lab]


def plan(verdict: dict, packet: dict, settings: Settings) -> list[dict]:
    """The Defender actions for this incident (pure: easy to test and to show)."""
    sit = situation(verdict, packet)
    if sit not in ("tp_blocked", "tp_active"):
        return []
    devices = _lab_devices(packet, settings)
    actions = [{"action": "av_scan", "device_id": d["id"], "device": d["name"],
                "why": f"{SITUATION_LABEL[sit]}: make sure nothing else is left on the computer"} for d in devices]
    if sit == "tp_active" and (verdict.get("confidence") or "") == "high":
        by_id = {d["id"]: d for d in devices}
        seen = set()
        for e in _evidence(packet):
            sha1, dev = e.get("sha1"), e.get("device_id") or (devices[0]["id"] if len(devices) == 1 else "")
            status = (e.get("remediation") or e.get("detection") or "").lower()
            if sha1 and dev in by_id and status not in STOPPED and (sha1, dev) not in seen:
                seen.add((sha1, dev))
                actions.append({"action": "quarantine_file", "device_id": dev, "device": by_id[dev]["name"],
                                "sha1": sha1, "file": e.get("name") or e.get("file") or "",
                                "why": "the file involved is not blocked yet"})
        if settings.auto_isolate and (verdict.get("recommended_severity") or "") == "high":
            actions += [{"action": "isolate_device", "device_id": d["id"], "device": d["name"],
                         "why": "sure, high-severity true positive (automatic isolation is switched on)"}
                        for d in devices]
    return actions


def _packet(settings: Settings, incident_id: str) -> dict | None:
    from uc4.triage import _safe
    path = settings.verdicts_dir / f"{_safe(incident_id)}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def run(defender, graph, store: Store, settings: Settings) -> dict:
    if not settings.respond:
        return {"switched": "off"}
    counts = {"requested": 0, "already_running": 0, "failed": 0}
    human = {r["incident_id"] for r in store.query(
        "SELECT DISTINCT incident_id FROM actions WHERE action IN ('reopen', 'close_incident') AND status = 'done'")}
    rows = store.query("SELECT v.*, i.status AS inc_status FROM verdicts v JOIN incidents i USING (incident_id) "
                       "WHERE v.verdict = 'likely_true_positive'")
    for v in rows:
        if v["incident_id"] in human or (v["inc_status"] or "").lower() == "resolved":
            continue
        saved = _packet(settings, v["incident_id"])
        if not saved:
            continue
        done_now = []
        for a in plan(v, saved["packet"], settings):
            key = f"respond:{v['incident_id']}:{a['action']}:{a['device_id']}:{a.get('sha1', '')}"
            tries = store.get_state(key + ":tries")
            if store.get_state(key) or (tries and int(tries) >= MAX_TRIES):
                continue
            comment = f"Security Assistant playbook for incident {v['incident_id']}: {a['why']}"
            try:
                if a["action"] == "av_scan":
                    result = defender.antivirus_scan(a["device_id"], comment, settings.scan_type)
                elif a["action"] == "quarantine_file":
                    result = defender.stop_and_quarantine(a["device_id"], a["sha1"], comment)
                else:
                    result = defender.isolate(a["device_id"], comment)
            except Exception as exc:  # noqa: BLE001
                text = str(exc)
                if "ActiveRequestAlreadyExists" in text or "already" in text.lower():
                    store.set_state(key, "already-running")
                    add_action(settings, v["incident_id"], a["action"], a["device"], "done",
                               f"Defender was already doing this ({a['why']})", done=True)
                    counts["already_running"] += 1
                    continue
                store.set_state(key + ":tries", str(int(tries or 0) + 1))
                add_action(settings, v["incident_id"], a["action"], a["device"], "failed", text.splitlines()[0][:300])
                counts["failed"] += 1
                log.warning("Playbook %s on %s failed: %s", a["action"], a["device"], text.splitlines()[0][:200])
                continue
            store.set_state(key, result.get("id") or "requested")
            add_action(settings, v["incident_id"], a["action"], a["device"], "done",
                       f"requested from Defender (action {result.get('id', '?')}, status {result.get('status', '?')}): "
                       f"{a['why']}", done=True)
            done_now.append(a)
            counts["requested"] += 1
        if done_now and graph is not None:
            what = "; ".join(f"{_words(a)} on {a['device']}" for a in done_now)
            try:
                graph.add_comment(v["incident_id"], f"Security Assistant response playbook ({SITUATION_LABEL[situation(v, saved['packet'])]}): "
                                                    f"asked Defender for: {what}. Results: Action center in Defender, "
                                                    f"or the alert page in Security Assistant.")
            except Exception as exc:  # noqa: BLE001
                log.warning("Playbook comment on %s failed: %s", v["incident_id"], exc)
    return counts


def _words(a: dict) -> str:
    return {"av_scan": "an antivirus scan", "quarantine_file": f"stop and quarantine {a.get('file') or 'the file'}",
            "isolate_device": "isolate the computer"}.get(a["action"], a["action"])


def collect_view(graph, defender, store: Store, settings: Settings, days: int = 7) -> int:
    """'What Defender did' per recent incident -> data/verdicts/<id>.defender.json (read by the website)."""
    from uc4.triage import _safe
    since = utcnow() - timedelta(days=days)
    rows = store.query("SELECT v.*, i.created_at FROM verdicts v JOIN incidents i USING (incident_id) "
                       "WHERE COALESCE(i.updated_at, v.triaged_at) >= ?", [since])
    written = 0
    for v in rows:
        saved = _packet(settings, v["incident_id"])
        if not saved:
            continue
        try:
            inc = graph.incident(v["incident_id"])
        except Exception as exc:  # noqa: BLE001
            log.info("Defender view for %s skipped: %s", v["incident_id"], exc)
            continue
        alerts, items = [], []
        for a in inc.get("alerts") or []:
            alerts.append({"title": a.get("title"), "status": a.get("status"),
                           "investigation": a.get("investigationState") or "", "created": a.get("createdDateTime")})
            for e in a.get("evidence") or []:
                kind = (e.get("@odata.type") or "").rsplit(".", 1)[-1].replace("Evidence", "")
                if kind not in ("file", "process"):
                    continue
                name = ((e.get("fileDetails") or {}).get("fileName") or (e.get("imageFile") or {}).get("fileName") or "")
                items.append({"kind": kind, "name": name, "detection": e.get("detectionStatus") or "",
                              "remediation": e.get("remediationStatus") or "", "verdict": e.get("verdict") or ""})
        created = to_utc(v["created_at"]) or since
        machine_actions = []
        for d in _lab_devices(saved["packet"], settings):
            try:
                for m in defender.machine_actions(d["id"]):
                    when = to_utc(m.get("creationDateTimeUtc"))
                    if when and when >= created - timedelta(hours=1):
                        machine_actions.append({"device": d["name"], "type": m.get("type"), "status": m.get("status"),
                                                "requestor": m.get("requestor"), "comment": (m.get("requestorComment") or "")[:200],
                                                "created": str(when), "updated": str(to_utc(m.get("lastUpdateDateTimeUtc")) or "")})
            except Exception as exc:  # noqa: BLE001
                log.info("Device actions for %s skipped: %s", d["name"], exc)
        sit = situation(v, saved["packet"])
        scans = [m for m in machine_actions if (m["type"] or "").lower() == "runantivirusscan"]
        view = {"collected_at": str(utcnow()), "situation": sit, "situation_label": SITUATION_LABEL[sit],
                "planned": plan(v, saved["packet"], settings), "incident_status": inc.get("status"),
                "alerts": alerts, "items": items, "machine_actions": sorted(machine_actions, key=lambda m: m["created"]),
                "ready_to_close": sit in ("tp_blocked", "tp_active") and bool(scans)
                and all((m["status"] or "") == "Succeeded" for m in scans),
                "verdict_label": label(v["verdict"])}
        (settings.verdicts_dir / f"{_safe(v['incident_id'])}.defender.json").write_text(
            json.dumps(view, default=str, ensure_ascii=False), encoding="utf-8")
        written += 1
    return written
