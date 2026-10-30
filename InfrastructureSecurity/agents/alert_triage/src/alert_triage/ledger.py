"""The lab ledger: the answer key for incidents we caused on purpose in the lab.

Each lab test script prints one line per test:
    UC4LAB {"run_id": "w1-eicar-a", "wave": "1", "name": "EICAR test file", "technique": "T1204",
            "device": "opca-wks-01", "account": "labadmin", "start": "2026-10-08T09:00:00Z",
            "end": "2026-10-08T09:01:00Z", "expected": "benign_positive", "must_escalate": "no",
            "match": "eicar|malware"}
You save the Run command output into data/inbox/ledger/*.txt; `alert_triage ledger` loads every UC4LAB line and links each lab
incident to the test that caused it (same device, alert inside the test's time window, a match word in the alert).

`expected` may list several acceptable verdicts separated by "|". The agent NEVER sees the ledger: it is only used to
grade the agent afterwards.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import timedelta
from pathlib import Path

from alert_triage.config import Settings
from alert_triage.store import Store, to_utc

log = logging.getLogger("alert_triage.ledger")
LINE = re.compile(r"UC4LAB\s+(\{.*\})")
BEFORE = timedelta(minutes=10)
AFTER = timedelta(hours=3)            # Defender can take a while to raise an alert, custom rules run hourly


def parse_text(text: str, source_file: str = "") -> list[dict]:
    rows = []
    for m in LINE.finditer(text or ""):
        try:
            d = json.loads(m.group(1))
        except ValueError:
            log.warning("Skipping unreadable UC4LAB line in %s", source_file)
            continue
        if not d.get("run_id") or not d.get("device"):
            continue
        rows.append({
            "run_id": str(d["run_id"])[:80], "wave": str(d.get("wave", "")), "device": str(d["device"]).lower(),
            "account": str(d.get("account", "")).lower(), "technique": str(d.get("technique", "")).upper(),
            "name": str(d.get("name", ""))[:200], "match_terms": str(d.get("match", "")).lower(),
            "expected": str(d.get("expected", "needs_investigation")),
            "must_escalate": str(d.get("must_escalate", "any")).lower(),
            "started_at": to_utc(d.get("start")), "ended_at": to_utc(d.get("end")) or to_utc(d.get("start")),
            "source_file": source_file,
        })
    return rows


CSV_COLUMNS = ["run_id", "wave", "name", "technique", "device", "account", "start", "end", "expected",
               "must_escalate", "match"]


def parse_csv(path: Path) -> list[dict]:
    """The hand-filled sheet (data/inbox/ledger/*.csv, columns CSV_COLUMNS): one row per lab test you did."""
    import csv
    with path.open(encoding="utf-8-sig", newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if (r.get("run_id") or "").strip() and not r["run_id"].startswith("#")]
    text = "\n".join("UC4LAB " + json.dumps({k: (r.get(k) or "").strip() for k in CSV_COLUMNS}) for r in rows)
    return parse_text(text, path.name)


def load_inbox(store: Store, settings: Settings) -> int:
    folder = settings.inbox_dir / "ledger"
    rows = []
    for path in sorted(folder.glob("*.txt")) + sorted(folder.glob("*.log")):
        rows.extend(parse_text(path.read_text(encoding="utf-8", errors="replace"), path.name))
    for path in sorted(folder.glob("*.csv")):
        if path.name.startswith("_"):        # _template.csv and other notes are skipped
            continue
        rows.extend(parse_csv(path))
    return store.upsert("ledger", rows)


def _packet(settings: Settings, incident_id: str) -> dict | None:
    from alert_triage.triage import _safe
    path = settings.verdicts_dir / f"{_safe(incident_id)}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8")).get("packet")


def match_incidents(store: Store, settings: Settings) -> int:
    """Link lab incidents to ledger runs. Returns how many incidents were matched."""
    runs = store.query("SELECT * FROM ledger WHERE started_at IS NOT NULL")
    if not runs:
        return 0
    matched = []
    for inc in store.query("SELECT incident_id FROM incidents"):
        packet = _packet(settings, inc["incident_id"])
        if not packet:
            continue
        best = match_one(packet, runs)
        if best:
            matched.append({"incident_id": inc["incident_id"], "run_id": best[0], "how": best[1]})
    store.execute("DELETE FROM ledger_matches")
    return store.upsert("ledger_matches", matched)


def match_one(packet: dict, runs: list[dict]) -> tuple[str, str] | None:
    devices = {d["name"].split(".")[0] for d in packet["entities"]["devices"] if d.get("name")}
    times = [t for t in (to_utc(a["first_activity"] or a["created"]) for a in packet["alerts"]) if t]
    if not times:
        return None
    candidates = []
    for r in runs:
        if r["device"].split(".")[0] not in devices:
            continue
        terms = [t for t in (r["match_terms"] or "").split("|") if t]
        tech = (r["technique"] or "").lower()
        # Defender can add a new alert to an older incident: any alert inside the test's window counts
        for a in packet["alerts"]:
            when = to_utc(a["first_activity"] or a["created"])
            if not when or not (r["started_at"] - BEFORE <= when <= (r["ended_at"] or r["started_at"]) + AFTER):
                continue
            text = (a["title"] + " " + a["category"] + " " + " ".join(a["techniques"])).lower()
            hit = next((t for t in terms if t in text), None) or (tech if tech and tech in text else None)
            if hit:
                candidates.append((abs((when - r["started_at"]).total_seconds()), r["run_id"], f"device+time+'{hit}'"))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][1], candidates[0][2]


def lab_results(store: Store) -> list[dict]:
    """One row per matched lab incident: truth from the ledger vs the agent's verdict."""
    return store.query("""
        SELECT m.incident_id, l.run_id, l.name, l.wave, l.expected, l.must_escalate, v.verdict, v.confidence,
               v.escalate, v.recommended_severity, v.guardrails, v.ai_status, i.title
        FROM ledger_matches m JOIN ledger l USING (run_id) JOIN verdicts v USING (incident_id)
        JOIN incidents i USING (incident_id) ORDER BY l.wave, l.run_id""")


def grade(row: dict) -> dict:
    """Is the agent's verdict acceptable? Missed = the truth is a real attack but the agent said close it."""
    acceptable = {v.strip() for v in (row["expected"] or "").split("|") if v.strip()}
    if "benign_positive" in acceptable:          # three outcomes only: harmless is filed as a false positive
        acceptable.add("likely_false_positive")
    verdict_ok = row["verdict"] in acceptable
    esc = row["must_escalate"]
    escalate_ok = esc == "any" or (esc == "yes") == bool(row["escalate"])
    real_attack = "likely_true_positive" in acceptable and not acceptable & {"benign_positive", "likely_false_positive"}
    missed = real_attack and row["verdict"] in ("benign_positive", "likely_false_positive")
    return {"verdict_ok": verdict_ok, "escalate_ok": escalate_ok, "correct": verdict_ok and escalate_ok,
            "missed_true_positive": missed}
