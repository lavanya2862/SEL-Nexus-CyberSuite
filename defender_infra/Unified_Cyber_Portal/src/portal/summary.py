"""The combined Home page data: one JSON built from UC1 + UC3 + UC4 outputs (read-only)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from portal.config import Settings
from portal.sources import UC1, UC3, UC4

STALE_HOURS = 24          # older data than this shows amber on the Home page


def _parse_time(value: Any) -> datetime | None:
    """UC1 writes naive UTC times; UC3 writes ISO times with an offset."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _age_hours(dt: datetime | None, now: datetime) -> float | None:
    return round((now - dt).total_seconds() / 3600, 1) if dt else None


def _health(key: str, name: str, ok: bool, last_run_at: datetime | None, data_as_of: datetime | None,
            message: str, now: datetime, extra: dict | None = None) -> dict:
    age = _age_hours(data_as_of, now)
    if data_as_of is None:
        status = "missing"
    elif not ok:
        status = "error"
    elif age is not None and age > STALE_HOURS:
        status = "stale"
    else:
        status = "ok"
    return {"key": key, "name": name, "status": status, "message": message,
            "last_run_at": last_run_at.isoformat() if last_run_at else None,
            "data_as_of": data_as_of.isoformat() if data_as_of else None, "age_hours": age, **(extra or {})}


def _uc3_part(uc3: UC3, now: datetime) -> dict:
    status = uc3.status() or {}
    runs = uc3.query("select * from {run_history} order by run_date desc limit 1", "run_history")
    run = runs[0] if runs else {}
    run_at = _parse_time(status.get("run_at") or run.get("started_at"))
    health = _health("uc3", "Vulnerabilities", str(status.get("status", "")).upper() in ("OK", "WARN"),
                     run_at, run_at, status.get("message") or "No run recorded yet", now,
                     {"quality": run.get("quality"), "coverage": run.get("coverage"),
                      "rows": run.get("vulnerability_rows"), "defender_count": run.get("defender_count")})

    latest = "(select max(snapshot_date) from {fact_daily_summary})"
    totals = uc3.query(f"""select sum(vulnerabilities) total,
            sum(vulnerabilities) filter (where priority = 'P1') p1,
            sum(vulnerabilities) filter (where severity = 'Critical') critical,
            sum(exploitable) exploitable, sum(sla_breaches) sla_breaches
        from {{fact_daily_summary}} where snapshot_date = {latest}""", "fact_daily_summary")
    cves = uc3.query("""select count(*) cves, count(*) filter (where in_cisa_kev) kev,
            count(*) filter (where in_cisa_kev and kev_ransomware) ransomware from {dim_cve}""", "dim_cve")
    trend = uc3.query("""select snapshot_date::varchar date, sum(vulnerabilities) total,
            sum(vulnerabilities) filter (where priority = 'P1') p1, sum(exploitable) exploitable
        from {fact_daily_summary} group by 1 order by 1""", "fact_daily_summary")
    priority = uc3.query(f"""select priority, sum(vulnerabilities) count from {{fact_daily_summary}}
        where snapshot_date = {latest} group by 1 order by 1""", "fact_daily_summary")
    opco = uc3.query(f"""select opco, severity, sum(vulnerabilities) count from {{fact_daily_summary}}
        where snapshot_date = {latest} group by all order by 1""", "fact_daily_summary")
    devices = uc3.query("""select device_name, opco, findings, critical, p1, exposure_level,
            last_seen::varchar last_seen, is_stale from {dim_device} order by findings desc""", "dim_device")
    fixes = uc3.query("""select rank, app, installed_versions, urgency, urgency_level, fix_by::varchar fix_by,
            cves, p1, kev_cves, devices, opcos, fix_action, command, why_now, source
        from {ai_fix_plan} order by rank limit 8""", "ai_fix_plan")
    latest_v = "(select max(snapshot_date) from {fact_vulnerability})"
    opco_totals = uc3.query(f"""select opco, count(*) findings, count(*) filter (where priority = 'P1') p1,
            count(*) filter (where severity = 'Critical') critical,
            count(distinct cve_id) filter (where in_cisa_kev) kev, count(distinct device_id) devices
        from {{fact_vulnerability}} where snapshot_date = {latest_v} group by 1 order by 1""", "fact_vulnerability")
    ransom = uc3.query(f"""select v.opco, count(distinct v.cve_id) ransomware
        from {{fact_vulnerability}} v join {{dim_cve}} c using (cve_id)
        where v.snapshot_date = (select max(snapshot_date) from {{fact_vulnerability}}) and c.kev_ransomware
        group by 1""", "fact_vulnerability", "dim_cve")
    for row in opco_totals:
        row["ransomware"] = next((r["ransomware"] for r in ransom if r["opco"] == row["opco"]), 0)
    names = uc3.app_names()
    apps = uc3.query(f"""select software_vendor || ':' || software_name as app_key, software_name, opco, count(*) findings,
            count(*) filter (where priority = 'P1') p1, count(distinct cve_id) filter (where in_cisa_kev) kev
        from {{fact_vulnerability}} where snapshot_date = {latest_v} group by all order by findings desc""",
                     "fact_vulnerability")
    for row in apps:
        row["app"] = names.get(row.pop("app_key"), row["software_name"].replace("_", " ").title())
    trend_opco = uc3.query("""select snapshot_date::varchar date, opco, sum(vulnerabilities) total
        from {fact_daily_summary} group by all order by 1, 2""", "fact_daily_summary")
    quality = uc3.query("""select check_name, status, message from {dq_status}
        where run_date = (select max(run_date) from {dq_status}) order by status desc, check_name""", "dq_status")
    changes = uc3.query("select status, count(*) count from {fact_change_event} group by 1", "fact_change_event")
    remediated = uc3.query("select count(*) count from {fact_remediation}", "fact_remediation")
    return {
        "health": health,
        "totals": {**(totals[0] if totals else {}), **(cves[0] if cves else {}),
                   "devices": len(devices), "remediated": remediated[0]["count"] if remediated else 0,
                   "changes": {c["status"]: c["count"] for c in changes}},
        "trend": trend, "trend_opco": trend_opco, "priority": priority, "opco": opco, "opco_totals": opco_totals,
        "apps": apps, "quality": quality, "devices": devices,
        "fixes": fixes, "ai_fixes": uc3.ai_fixes_meta(),
    }


def _uc1_part(uc1: UC1, now: datetime) -> dict:
    data = uc1.dashboard() or {}
    last = uc1.last_run() or {}
    generated = _parse_time(data.get("generated"))
    finished = _parse_time(last.get("finished_at") or last.get("started_at"))
    failed = (last.get("failed_steps") or []) + (last.get("failed_feeds") or [])
    ok = last.get("status") in ("ok", None) and not last.get("failed_steps")
    message = "Run completed" if ok and not failed else f"Problems: {', '.join(map(str, failed))}" if failed \
        else f"Last run: {last.get('status', 'unknown')}"
    health = _health("uc1", "Threat news and attack hunting", ok, finished, generated, message, now,
                     {"run_id": last.get("run_id"), "model": data.get("model")})

    metrics = data.get("metrics") or {}
    feeds = data.get("feeds") or []
    hunts = data.get("hunts") or []
    hits = data.get("hits") or []
    top = [{k: t.get(k) for k in ("id", "title", "source", "kind", "rating", "score", "why", "chips", "action",
                                    "summary", "devices", "url", "published")}
           for t in (data.get("top") or []) if not t.get("test")][:6]
    return {
        "health": health,
        "posture": data.get("posture") or {},
        "totals": {
            "new_threats": metrics.get("new_threats"),
            "pct_assessed": metrics.get("pct_assessed"),
            "affecting": (data.get("posture") or {}).get("affecting"),
            "kev_on_devices": (data.get("posture") or {}).get("kev"),
            "urgent": (data.get("posture") or {}).get("urgent"),
            "hunts_per_run": metrics.get("hunts_per_run"),
            "hunts_ok": sum(1 for h in hunts if h.get("status") == "ok"),
            "hunts_total": len(hunts),
            "real_hits": sum(1 for h in hits if not h.get("is_test")),
            "test_hits": sum(1 for h in hits if h.get("is_test")),
            "alerts": len(data.get("alerts") or []),
            "median_minutes_to_assess": metrics.get("median_minutes_to_assess"),
            "manual_hours_saved": metrics.get("manual_hours_equivalent (assumption)"),
        },
        "funnel": data.get("funnel") or [],
        "threat_trend": {"days": data.get("days") or [], "series": data.get("series") or {}},
        "top_threats": top,
        "devices": data.get("devices") or [],
        "feeds": {"ok": sum(1 for f in feeds if f.get("last_status") == "ok"), "total": len(feeds),
                  "failing": [f.get("feed") for f in feeds if f.get("last_status") == "error"]},
    }


def _uc4_needs_person(r: dict, auto: bool) -> bool:
    """Same rule as the website's needsPerson() and UC4's autoresolve: the AI's verdict is final; a person decides
    only "needs review", a verdict made without the AI, a non-lab incident, or one a person reopened."""
    return (not auto or not r.get("is_lab") or r.get("ai_status") != "ai" or r.get("verdict") == "needs_investigation"
            or (r.get("last_action") or {}).get("action") == "reopen")


def _uc4_part(uc4: UC4, now: datetime) -> dict:
    data = uc4.queue() or {}
    last = uc4.last_run() or {}
    finished = _parse_time(last.get("finished_at"))
    failed = [k for k, v in (last.get("steps") or {}).items() if str(v).startswith("FAILED")]
    ok = last.get("status") in ("ok", None) and not failed
    message = ("Run completed" if ok else f"Problems: {', '.join(failed)}" if failed
               else f"Last run: {last.get('status', 'unknown')}") if last else "No run recorded yet"
    # an alert queue is fresh as of its last run (a quiet day with no incidents is still up to date)
    health = _health("uc4", "Alert triage", ok, finished, finished, message, now)
    queue = data.get("queue") or []
    auto = UC4.automation(last)["auto_resolve"]
    agent = [r for r in queue if not _uc4_needs_person(r, auto)]
    open_rows = [r for r in queue if _uc4_needs_person(r, auto) and not r.get("feedback")]
    escalated = sum(1 for r in agent if r.get("verdict") == "likely_true_positive")
    return {
        "health": health,
        "totals": {"incidents": len(queue), "escalate": escalated, "closed": len(agent) - escalated,
                   "awaiting_review": len(open_rows), "lab": sum(1 for r in queue if r.get("is_lab")),
                   "by_verdict": data.get("by_verdict") or {}},
        "latest": [{k: r.get(k) for k in ("incident_id", "title", "verdict", "confidence", "escalate", "is_lab",
                                          "triaged_at", "devices")} for r in queue[:3]],
    }


def build_summary(settings: Settings) -> dict:
    now = datetime.now(timezone.utc)
    uc1 = _uc1_part(UC1(settings.uc1_dir), now)
    uc3 = _uc3_part(UC3(settings.uc3_dir), now)
    uc4 = _uc4_part(UC4(settings.uc4_dir), now)

    # one device list for the Home page: UC3 counts + UC1 threat exposure / hunt hits
    by_name: dict[str, dict] = {}
    for d in uc3["devices"]:
        by_name[d["device_name"]] = {"name": d["device_name"], "opco": d["opco"], "findings": d["findings"],
                                     "critical": d["critical"], "p1": d["p1"], "last_seen": d["last_seen"]}
    for d in uc1["devices"]:
        row = by_name.setdefault(d["device_name"], {"name": d["device_name"], "opco": d.get("opco")})
        row.update({"threats_exposed": d.get("exposed"), "hunt_hits": d.get("hits"), "test_hits": d.get("test_hits")})

    reports = {"uc1": len(UC1(settings.uc1_dir).reports()), "uc3": len(UC3(settings.uc3_dir).downloads())}
    return {"generated_at": now.isoformat(), "stale_hours": STALE_HOURS, "reports": reports,
            "health": [uc1.pop("health"), uc3.pop("health"), uc4.pop("health")],
            "devices": sorted(by_name.values(), key=lambda r: -(r.get("findings") or 0)),
            "uc1": uc1, "uc3": uc3, "uc4": uc4}
