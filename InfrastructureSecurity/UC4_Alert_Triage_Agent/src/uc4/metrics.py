"""The client's UC4 metrics, measured on our lab incidents and labelled honestly:
  MEASURED    = computed from real timestamps / your timed triages in this lab
  ASSUMPTION  = a number from config/metrics_assumptions.csv (to confirm with your manager)

  - Time to verdict (agent part of MTTR): incident created -> AI verdict ready
  - Time to decision (MTTR in shadow mode): incident created -> analyst agree/disagree
  - Time to containment advice (MTTC): incident created -> verdict that recommends containment
    (+ time to containment done, if a human-approved isolate was performed)
  - Closure SLA: decided within config/sla_policy.csv hours
  - Triage effort: minutes per incident, manual vs AI-assisted (from the feedback form) -> reduction %
  - Coverage: incidents with an AI verdict / all triaged incidents
  - Automatic look-ups per incident (proxy for analyst fatigue)
"""

from __future__ import annotations

import json
import statistics

from uc4.config import Settings, read_csv
from uc4.store import Store, utcnow


def _minutes(a, b) -> float | None:
    if not a or not b:
        return None
    return round((b - a).total_seconds() / 60, 1)


def _stats(values: list[float]) -> dict:
    values = [v for v in values if v is not None and v >= 0]
    if not values:
        return {"n": 0, "median": None, "mean": None}
    return {"n": len(values), "median": round(statistics.median(values), 1),
            "mean": round(statistics.fmean(values), 1)}


def compute(store: Store, settings: Settings) -> dict:
    sla = {r["severity"]: float(r["hours"]) for r in read_csv("sla_policy.csv")}
    assume = {r["key"]: r for r in read_csv("metrics_assumptions.csv")}
    rows = store.query("""
        SELECT i.incident_id, i.severity, i.created_at, i.is_lab, v.verdict, v.triaged_at, v.containment,
               v.ai_status, v.queries_run, v.ti_lookups, v.seconds, v.recommended_severity,
               (SELECT MIN(created_at) FROM feedback f WHERE f.incident_id = i.incident_id) AS decided_at,
               (SELECT MIN(done_at) FROM actions a WHERE a.incident_id = i.incident_id
                       AND a.action = 'isolate_device' AND a.status = 'done') AS contained_at,
               (SELECT MIN(done_at) FROM actions a WHERE a.incident_id = i.incident_id
                       AND a.action IN ('auto_resolve', 'close_incident') AND a.status = 'done') AS closed_at,
               (SELECT COUNT(*) FROM actions a WHERE a.incident_id = i.incident_id
                       AND a.action = 'auto_resolve' AND a.status = 'done') AS auto_closed
        FROM incidents i JOIN verdicts v USING (incident_id)""")
    to_verdict, to_decision, to_advice, to_contained, sla_hits, sla_total = [], [], [], [], 0, 0
    to_closed = [_minutes(r["created_at"], r["closed_at"]) for r in rows if r["closed_at"]]
    auto_closed = sum(1 for r in rows if r["auto_closed"])
    for r in rows:
        to_verdict.append(_minutes(r["created_at"], r["triaged_at"]))
        decided = r["decided_at"]
        if decided:
            to_decision.append(_minutes(r["created_at"], decided))
        cont = json.loads(r["containment"]) if isinstance(r["containment"], str) else (r["containment"] or [])
        if cont:
            to_advice.append(_minutes(r["created_at"], r["triaged_at"]))
        if r["contained_at"]:
            to_contained.append(_minutes(r["created_at"], r["contained_at"]))
        sev = (r["recommended_severity"] or r["severity"] or "medium").lower()
        limit_h = sla.get(sev, 24)
        end = decided or r["triaged_at"]
        if r["created_at"] and end:
            sla_total += 1
            sla_hits += (end - r["created_at"]).total_seconds() <= limit_h * 3600

    fb = store.query("SELECT mode, minutes FROM feedback WHERE minutes IS NOT NULL")
    manual = [f["minutes"] for f in fb if f["mode"] == "manual"]
    assisted = [f["minutes"] for f in fb if f["mode"] == "assisted"]
    m_manual, m_assisted = _stats(manual), _stats(assisted)
    reduction = None
    if m_manual["mean"] and m_assisted["mean"] is not None:
        reduction = round(100 * (1 - m_assisted["mean"] / m_manual["mean"]), 1)

    agree = store.query("SELECT agree, COUNT(*) AS n FROM feedback GROUP BY agree")
    agree_n = sum(a["n"] for a in agree if a["agree"])
    fb_total = sum(a["n"] for a in agree)
    total = len(rows)
    ai_rows = sum(1 for r in rows if r["ai_status"] == "ai")

    client_manual = float(assume.get("manual_triage_minutes", {}).get("value") or 25)
    per_day = float(assume.get("incidents_per_day", {}).get("value") or 120)
    est_saved_h = round(per_day * client_manual * (reduction or 0) / 100 / 60, 1) if reduction is not None else None

    return {
        "generated_at": utcnow().strftime("%Y-%m-%d %H:%M:%SZ"),
        "incidents": total,
        "metrics": [
            {"name": "Time to AI verdict (minutes)", "value": _stats(to_verdict), "label": "MEASURED",
             "note": "Incident created in Defender -> verdict ready. Includes waiting for the next 5-minute run."},
            {"name": "Time to analyst decision (MTTR, minutes)", "value": _stats(to_decision), "label": "MEASURED",
             "note": "Incident created -> your agree/disagree click (shadow mode)."},
            {"name": "Time to containment advice (MTTC, minutes)", "value": _stats(to_advice), "label": "MEASURED",
             "note": "Incident created -> verdict recommending containment."},
            {"name": "Time to containment done (minutes)", "value": _stats(to_contained), "label": "MEASURED",
             "note": "Only when a human-approved isolate was performed (optional stretch)."},
            {"name": "Time to closure in Defender (minutes)", "value": _stats(to_closed), "label": "MEASURED",
             "note": "Incident created -> resolved in Defender by the assistant (automatic) or by you (Agree & close)."},
            {"name": "Resolved automatically (%)",
             "value": round(100 * auto_closed / total, 1) if total else None, "label": "MEASURED",
             "note": f"{auto_closed} incident(s) closed by the assistant itself (config/auto_resolve.yaml: high confidence only)."},
            {"name": "Decided within SLA (%)",
             "value": round(100 * sla_hits / sla_total, 1) if sla_total else None, "label": "MEASURED",
             "note": "Against config/sla_policy.csv (lab assumption for the SLA hours)."},
            {"name": "Triage minutes - manual", "value": m_manual, "label": "MEASURED",
             "note": "Your stopwatch-timed triages without the AI packet."},
            {"name": "Triage minutes - AI-assisted", "value": m_assisted, "label": "MEASURED",
             "note": "Your timed triages with the AI packet."},
            {"name": "Triage effort reduction (%)", "value": reduction, "label": "MEASURED",
             "note": "Client target: 50-70%. Small lab sample."},
            {"name": "Analyst agreement with the agent (%)",
             "value": round(100 * agree_n / fb_total, 1) if fb_total else None, "label": "MEASURED",
             "note": f"{fb_total} feedback click(s)."},
            {"name": "Coverage: incidents with an AI verdict (%)",
             "value": round(100 * ai_rows / total, 1) if total else None, "label": "MEASURED",
             "note": "Others got the rules-only packet (AI unavailable or answer rejected)."},
            {"name": "Automatic look-ups per incident",
             "value": round(statistics.fmean([(r["queries_run"] or 0) + (r["ti_lookups"] or 0) for r in rows]), 1)
             if rows else None, "label": "MEASURED",
             "note": "Searches + threat-intel checks an analyst would otherwise do by hand."},
            {"name": "Client analyst hours saved per day (estimate)", "value": est_saved_h, "label": "ASSUMPTION",
             "note": f"{per_day:g} incidents/day x {client_manual:g} min x measured reduction "
                     "(config/metrics_assumptions.csv)."},
        ],
    }


def write(store: Store, settings: Settings) -> dict:
    data = compute(store, settings)
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    (settings.export_dir / "metrics.json").write_text(json.dumps(data, default=str, indent=1), encoding="utf-8")
    return data
