"""What the Alert Triage Agent publishes: data/export/*.json, data/verdicts/<incident>.json, data/feedback/*.jsonl,
last_run.json and its reports, plus how an incident's outcome is worded.

Rules: never write into an agent's folder, never open its live DuckDB database (that would block its runs).
Every reader returns None (or empty) when a file is missing, so one broken agent never breaks the dashboard.
"""

from __future__ import annotations

from pathlib import Path

from dashboard.agents.common import _jsonl, _read_json, mtime_iso


def alert_triage_safe_id(incident_id: str) -> str:
    """Same file-name rule as Alert Triage (alert_triage.triage._safe): letters, digits, '-' and '_' only."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in str(incident_id))[:80]


# Defender's classification of an incident -> the triage outcome (informational, expected activity is harmless)
TRIAGE_DEFENDER_OUTCOME = {"truePositive": "likely_true_positive", "falsePositive": "likely_false_positive",
                        "informationalExpectedActivity": "likely_false_positive"}
TRIAGE_PERSON_ACTIONS = ("close_incident", "escalate_incident", "reopen")


def _stamp(t) -> str:
    """'2026-10-29 06:47:42Z' and '2026-10-29T06:47:42Z' compare as text once written the same way."""
    return str(t or "").replace(" ", "T")


def alert_triage_person_action(actions: list[dict]) -> dict | None:
    """The newest decision a person wrote into Defender through CyberSuite (Alert Triage close.act or reopen)."""
    for a in reversed(actions):
        if a.get("status") == "done" and a.get("action") in TRIAGE_PERSON_ACTIONS:
            return a
    return None


def alert_triage_decision(state: dict, action: dict | None, synced_at) -> dict | None:
    """The final classification once one is made, and whether Defender has the incident open or closed.

    An analyst's decision made in CyberSuite (written into Defender by Alert Triage: false positive -> resolved, true positive
    -> in progress) wins while Defender still holds it, or while it is newer than the last check of Defender.
    Otherwise Defender's own classification counts (set by an analyst there, or by the agent's automatic
    close / escalate). None while nobody has classified the incident."""
    status, classification = state.get("status"), state.get("classification")
    if action:
        fresh = _stamp(action.get("done_at")) > _stamp(synced_at)
        if action["action"] == "reopen":
            if fresh:
                return None
        else:
            head, _, who = str(action.get("detail") or "").partition(" by ")
            parts = [x.strip() for x in head.split(" / ")]
            a_status = parts[0] if len(parts) == 3 else ("resolved" if action["action"] == "close_incident" else "inProgress")
            a_class = parts[1] if len(parts) == 3 else ("falsePositive" if action["action"] == "close_incident" else "truePositive")
            if fresh or classification == a_class:
                return {"outcome": TRIAGE_DEFENDER_OUTCOME.get(a_class, "likely_true_positive"), "by": "analyst",
                        "who": who.strip(), "at": action.get("done_at"), "classification": a_class,
                        "determination": parts[2] if len(parts) == 3 else None,
                        "status": a_status if fresh else status}
    if classification in TRIAGE_DEFENDER_OUTCOME:
        return {"outcome": TRIAGE_DEFENDER_OUTCOME[classification], "by": "defender", "classification": classification,
                "determination": state.get("determination"), "status": status}
    return None


def alert_triage_outcome(verdict: str | None, decision: dict | None) -> str | None:
    """What the queue shows: the decision when there is one, else the agent's verdict (older benign = false positive)."""
    if decision:
        return decision["outcome"]
    return "likely_false_positive" if verdict == "benign_positive" else verdict


class AlertTriageSource:
    MAX_ROWS = 50          # rows kept per evidence search on the case page

    def __init__(self, root: Path):
        self.root = root
        self.data = root / "data"

    def reports(self) -> list[dict]:
        folder = self.data / "reports"
        files = sorted(folder.glob("Alert_Triage_Report_*.*"), key=lambda p: p.stat().st_mtime, reverse=True)             if folder.is_dir() else []
        return [{"name": p.name, "size": p.stat().st_size, "modified": mtime_iso(p)}
                for p in files if p.suffix.lower() in (".docx", ".pdf")]

    def last_run(self) -> dict | None:
        return _read_json(self.data / "last_run.json")

    def _feedback(self) -> list[dict]:
        return _jsonl(self.data / "feedback" / "feedback.jsonl")

    def queue(self) -> dict | None:
        """The triage queue, with the newest agree/disagree click per incident applied straight away (as Alert Triage's site),
        and each incident's final outcome and Defender status: an analyst's decision (made here or in Defender) wins
        over the agent's verdict."""
        data = _read_json(self.data / "export" / "triage_data.json")
        if not isinstance(data, dict):
            return None
        latest = {r.get("incident_id"): r for r in self._feedback()}
        acts: dict[str, list[dict]] = {}
        for a in _jsonl(self.data / "feedback" / "actions.jsonl"):
            acts.setdefault(a.get("incident_id"), []).append(a)
        by_outcome: dict[str, int] = {}
        for row in data.get("queue", []):
            f = latest.get(row.get("incident_id"))
            if f:
                row["feedback"] = {"agree": f.get("agree"), "analyst_verdict": f.get("analyst_verdict")}
            row["decision"] = alert_triage_decision(row, alert_triage_person_action(acts.get(row.get("incident_id"), [])),
                                           data.get("generated_at"))
            if row["decision"] and row["decision"].get("status"):
                row["status"] = row["decision"]["status"]       # a decision just written: Defender has it already
            row["outcome"] = alert_triage_outcome(row.get("verdict"), row["decision"])
            by_outcome[row["outcome"]] = by_outcome.get(row["outcome"], 0) + 1
        data["by_outcome"] = by_outcome
        last = self.last_run() or {}
        data["last_run_detail"] = last
        data["automation"] = self.automation(last)
        return data

    @staticmethod
    def automation(last: dict | None) -> dict:
        """What Alert Triage is switched to do by itself, read from the steps its last run performed (Alert Triage's .env is never read)."""
        steps = (last or {}).get("steps") or {}
        return {"auto_resolve": "auto_resolve" in steps, "writeback": "writeback" in steps, "known": bool(steps)}

    def case(self, incident_id: str) -> dict | None:
        data = _read_json(self.data / "verdicts" / f"{alert_triage_safe_id(incident_id)}.json")
        if not isinstance(data, dict) or "packet" not in data:
            return None
        real_id = data["packet"].get("incident_id")
        for q in data.get("queries") or []:
            rows = q.get("rows") or []
            q["rows_total"] = len(rows)
            q["rows"] = rows[: self.MAX_ROWS]
        data["feedback"] = [r for r in self._feedback() if r.get("incident_id") == real_id]
        data["actions"] = [r for r in _jsonl(self.data / "feedback" / "actions.jsonl") if r.get("incident_id") == real_id]
        data["questions"] = [r for r in _jsonl(self.data / "feedback" / "ask.jsonl") if r.get("incident_id") == real_id]
        data["automation"] = self.automation(self.last_run())
        # Defender's current status and classification (the saved packet holds them as they were at triage time)
        export = _read_json(self.data / "export" / "triage_data.json")
        row = next((r for r in (export or {}).get("queue", []) if r.get("incident_id") == real_id), {}) \
            if isinstance(export, dict) else {}
        data["defender_state"] = {k: row.get(k) or data["packet"].get(k)
                                  for k in ("status", "classification", "determination", "updated_at")}
        verdict = (data.get("verdict") or {}).get("verdict")
        data["decision"] = alert_triage_decision(data["defender_state"], alert_triage_person_action(data["actions"]),
                                        export.get("generated_at") if isinstance(export, dict) else None)
        if data["decision"] and data["decision"].get("status"):
            data["defender_state"]["status"] = data["decision"]["status"]
        data["outcome"] = alert_triage_outcome(verdict, data["decision"])
        return data

    def metrics(self) -> dict | None:
        return _read_json(self.data / "export" / "metrics.json")

    def backtest(self) -> dict | None:
        return _read_json(self.data / "export" / "backtest.json")
