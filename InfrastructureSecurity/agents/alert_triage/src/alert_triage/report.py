"""Alert Triage Report for one run (Word + PDF): every incident the AI checked in this run, its verdict, evidence,
recommended actions and what was done. When a run checked nothing new, the report says so and lists the open queue.
Built from the database and the saved verdict files only; nothing here asks the AI again."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime

from alert_triage import docstyle as ds
from alert_triage.config import Settings
from alert_triage.store import Store, utcnow

VERDICT_WORDS = {"likely_true_positive": "Real threat", "likely_false_positive": "False alarm",
                 "benign_positive": "Harmless (expected)", "needs_investigation": "Needs a person"}
VERDICT_COLOURS = {"Real threat": ds.BAD, "Needs a person": ds.SERIOUS, "False alarm": ds.GOOD,
                   "Harmless (expected)": "16A34A"}
SEVERITY = {"high": ds.BAD, "medium": ds.SERIOUS, "low": ds.WARN, "informational": "98A2B3"}
SLA_HOURS = {"high": 1, "medium": 4, "low": 24, "informational": 72}


def _j(value):
    if value in (None, ""):
        return []
    return json.loads(value) if isinstance(value, str) else value


def _file(settings: Settings, incident_id: str) -> dict:
    try:
        return json.loads((settings.verdicts_dir / f"{incident_id}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def build(store: Store, settings: Settings, run_id: str | None = None, started: datetime | None = None) -> dict:
    finished = utcnow()
    if started is None:                            # built by hand: the latest finished run
        last = store.query("SELECT * FROM runs WHERE finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 1")
        if last:
            run_id, started, finished = last[0]["run_id"], last[0]["started_at"], last[0]["finished_at"]
        else:
            started = finished
    rows = store.query("""SELECT v.*, i.title, i.severity, i.status, i.created_at, i.web_url, i.devices, i.accounts,
                                 i.sources, i.is_lab, i.alert_count
                          FROM verdicts v JOIN incidents i USING (incident_id) ORDER BY v.triaged_at DESC""")
    this_run = [r for r in rows if r["triaged_at"] and r["triaged_at"] >= started]
    actions = store.query("SELECT * FROM actions WHERE requested_at >= ? ORDER BY requested_at", [started])
    shown = this_run or [r for r in rows if r["status"] != "resolved"]
    words = Counter(VERDICT_WORDS.get(r["verdict"], r["verdict"]) for r in this_run)
    escalated = sum(1 for r in this_run if r["escalate"])
    closed = sum(1 for a in actions if a["action"] == "auto_resolve" and a["status"] == "done")

    rep = ds.Report("Alert Triage Report", "Alert Triage Agent", [
        f"Run of {started:%d %b %Y, %H:%M} UTC · took {int((finished - started).total_seconds())} s",
        f"Incidents from Microsoft Defender and Sentinel · {len(rows)} in the queue",
        f"Created {finished:%d %b %Y, %H:%M} UTC · this report shows this run only"])
    rep.h1("1. Summary")
    rep.tiles([(f"{len(this_run)}", "Incidents triaged", "new or changed in this run", ds.BLUE),
               (f"{words.get('Real threat', 0)}", "Real threats", "act on these first", ds.BAD),
               (f"{words.get('Needs a person', 0)}", "Need a person", "the AI was not sure enough", ds.SERIOUS),
               (f"{words.get('False alarm', 0) + words.get('Harmless (expected)', 0)}", "False alarms", "safe to close",
                ds.GOOD),
               (f"{escalated}", "Escalated", "sent to the security team", ds.BAD if escalated else ds.INK_3),
               (f"{closed}", "Closed automatically", "high-confidence false alarms", ds.GOOD)])
    if this_run:
        rep.para(f"This run checked {len(this_run)} new or changed incidents: " +
                 ", ".join(f"{n} {w.lower()}" for w, n in words.most_common()) + f". {escalated} were escalated and "
                 f"{closed} closed automatically.")
        rep.image(ds.donut(list(words), list(words.values()), [VERDICT_COLOURS.get(w, ds.BLUE) for w in words],
                           str(len(this_run)), "triaged"), 9)
    else:
        rep.para("No new or changed incidents arrived in this run, so nothing needed a verdict. The incidents still open "
                 "in the queue are listed below for reference.")

    rep.h1("2. Incidents at a glance" if this_run else "2. Open incidents in the queue")
    rep.table(["#", "Incident", "Severity", "Verdict", "Confidence", "Escalated", "Respond within"],
              [[r["incident_id"], r["title"][:90], r["severity"], VERDICT_WORDS.get(r["verdict"], r["verdict"]),
                r["confidence"], "Yes" if r["escalate"] else "", f"{SLA_HOURS.get(r['severity'], 24)} h"] for r in shown],
              [1, 7, 2, 2.8, 2, 1.8, 2], colour_cols={2: SEVERITY, 3: VERDICT_COLOURS, 5: {"Yes": ds.BAD}})

    rep.h1("3. Each incident in detail")
    for r in shown:
        f = _file(settings, r["incident_id"])
        v = f.get("verdict") or {}
        word = VERDICT_WORDS.get(r["verdict"], r["verdict"])
        evidence = [f"{e.get('source', '')}: {e.get('finding', '')}" for e in v.get("evidence", [])[:10]]
        queries = [f"{q.get('id', '')}: {q.get('status', '')}, {q.get('row_count', 0)} rows" for q in f.get("queries", [])[:10]]
        mine = [f"{a['action']} on {a['target']}: {a['status']}" for a in actions if a["incident_id"] == r["incident_id"]]
        guard = v.get("guardrail_triggered") or "; ".join(_j(r["guardrails"]))
        rep.card(f"#{r['incident_id']} {r['title']}",
                 f"Severity {r['severity']} · created {r['created_at']:%d %b %Y %H:%M} · computers {', '.join(_j(r['devices'])) or 'n/a'}"
                 f" · accounts {', '.join(_j(r['accounts'])) or 'n/a'}" + (" · lab test" if r["is_lab"] else ""),
                 [("What the AI found", r["summary"]),
                  ("Verdict", f"{word} (confidence {r['confidence']}, suggested severity {r['recommended_severity']})"),
                  ("Safety rule", guard), ("Evidence", evidence), ("What it would change its mind on", v.get("would_change_verdict_if")),
                  ("Recommended actions", v.get("recommended_actions") or []),
                  ("Containment options", ", ".join(_j(r["containment"])).replace("_", " ")),
                  ("Actions taken in this run", mine), ("Searches run", queries),
                  ("Attack techniques", ", ".join(v.get("mitre_techniques", []))),
                  ("Source", f"Verdict by AI ({r['ai_model'] or 'AI'}), checked by the safety rules · {r['seconds']:.0f} s"
                   if r["ai_status"] == "ai" else "Verdict by rules (AI not available)")],
                 VERDICT_COLOURS.get(word, ds.BLUE), word.upper())

    if actions:
        rep.h1("4. Actions taken in this run")
        rep.table(["Incident", "Action", "Target", "Result", "When"],
                  [[a["incident_id"], a["action"].replace("_", " "), a["target"], a["status"],
                    f"{a['requested_at']:%d %b %H:%M}"] for a in actions], [2, 4, 3, 2, 3])

    rep.h1("Appendix: how the verdicts are made")
    rep.bullets([
        "Each incident's alerts, computers and accounts are read from Microsoft Defender and Sentinel, and the agent runs "
        "fixed searches for more evidence.",
        "The AI decides: real threat, false alarm, or needs a person, with a confidence. Safety rules always escalate "
        "high-risk kinds (for example credential theft), whatever the AI says.",
        "Only false alarms with high confidence and no safety rule are closed automatically.",
        f"Respond-within times by severity: high {SLA_HOURS['high']} h, medium {SLA_HOURS['medium']} h, "
        f"low {SLA_HOURS['low']} h, informational {SLA_HOURS['informational']} h.",
    ])
    out_dir = settings.data_dir / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    return rep.save(out_dir / f"Alert_Triage_Report_{started:%Y%m%d_%H%M}.docx")
