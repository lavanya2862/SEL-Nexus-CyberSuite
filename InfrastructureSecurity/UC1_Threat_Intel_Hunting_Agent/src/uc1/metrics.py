"""Phase 9: the client's key metrics, measured from stored timestamps.

Manual-effort figures are ASSUMPTIONS from config/metrics_assumptions.csv (to be confirmed by the team);
everything else is measured.
"""

from __future__ import annotations

import json
import statistics
from datetime import timedelta

from uc1.config import Settings, read_policy
from uc1.store import Store, utcnow

DEFAULT_ASSUMPTIONS = {"manual_minutes_per_threat": 120, "manual_minutes_per_hunt": 45, "manual_minutes_per_report": 240}


def _minutes(delta) -> float | None:
    return round(delta.total_seconds() / 60, 1) if delta is not None else None


def compute(store: Store, settings: Settings | None = None, days: int = 30) -> dict:
    a = {**DEFAULT_ASSUMPTIONS, **read_policy("metrics_assumptions.csv")}
    since = utcnow() - timedelta(days=days)
    threats = store.query("""
        SELECT t.threat_id, t.first_seen_at, t.is_test, COALESCE(a.first_assessed_at, a.analysed_at) AS analysed_at, a.ai_status
        FROM threats t LEFT JOIN analysis a ON a.threat_id = t.threat_id
        WHERE t.first_seen_at >= ? AND NOT t.is_test AND t.kind <> 'ioc'""", [since])   # IOC bundles are clues, not threats
    assessed = [t for t in threats if t["analysed_at"] and t["ai_status"] in ("done", "skipped")]
    to_assess = [_minutes(t["analysed_at"] - t["first_seen_at"]) for t in assessed if t["analysed_at"] >= t["first_seen_at"]]
    reports = store.query("SELECT created_at FROM reports WHERE created_at >= ? ORDER BY created_at", [since])
    to_report = []
    for t in assessed:
        after = next((r["created_at"] for r in reports if r["created_at"] >= t["first_seen_at"]), None)
        if after:
            to_report.append(_minutes(after - t["first_seen_at"]))
    hunts = store.scalar("SELECT COUNT(*) FROM hunts WHERE status = 'ok' AND started_at >= ?", [since]) or 0
    last_run = store.scalar("SELECT run_id FROM hunts ORDER BY started_at DESC LIMIT 1")
    per_run = store.scalar("SELECT COUNT(*) FROM hunts WHERE run_id = ? AND status = 'ok'", [last_run]) or 0
    proactive = store.scalar("""SELECT COUNT(DISTINCT f.threat_id) FROM findings f JOIN threats t ON t.threat_id = f.threat_id
                                WHERE NOT f.is_test""") or 0
    ai = store.query("SELECT COALESCE(SUM(calls),0) calls, COALESCE(SUM(failures),0) failures FROM ai_usage")[0]
    dropped = store.scalar("""SELECT COUNT(*) FROM analysis WHERE ai_status = 'done'
                              AND dropped IS NOT NULL AND dropped::VARCHAR NOT IN ('{}', 'null')""") or 0
    ai_done = store.scalar("SELECT COUNT(*) FROM analysis WHERE ai_status = 'done'") or 0
    agent_minutes = sum(to_assess) / max(1, len(to_assess)) if to_assess else None
    from uc1.spotcheck import latest_result
    spot = latest_result(settings) if settings else None
    manual_hours = (len(assessed) * a["manual_minutes_per_threat"] + hunts * a["manual_minutes_per_hunt"]
                    + len(reports) * a["manual_minutes_per_report"]) / 60
    return {
        "window_days": days,
        "new_threats": len(threats),
        "threats_assessed": len(assessed),
        "pct_assessed": round(100 * len(assessed) / len(threats), 1) if threats else None,
        "median_minutes_to_assess": statistics.median(to_assess) if to_assess else None,
        "median_minutes_to_report": statistics.median(to_report) if to_report else None,
        "hunts_completed": hunts,
        "hunts_per_run": per_run,
        "hunts_per_month_projected": per_run * 6 * 30,     # schedule: every 4 hours
        "proactive_threats_identified": proactive,
        "reports_published": len(reports),
        "manual_hours_equivalent (assumption)": round(manual_hours, 1),
        "mean_minutes_to_assess": round(agent_minutes, 1) if agent_minutes is not None else None,
        "ai_calls": int(ai["calls"]), "ai_failures": int(ai["failures"]),
        "ai_items_corrected_by_guard": f"{dropped} of {ai_done}",
        "ai_accuracy_spotcheck_pct": (spot or {}).get("overall_pct_correct"),
        "assumptions": a,
    }


def write(store: Store, settings: Settings) -> dict:
    m = compute(store, settings)
    (settings.data_dir / "metrics.json").write_text(json.dumps(m, indent=2, default=str), encoding="utf-8")
    return m
