"""Publish step: write the Power-BI-ready reporting tables to data/reporting/*.parquet.

Every dashboard (the HTML Command Centre, the Excel summary, Power BI later) reads ONLY these files.
Also refreshes the CISA "Known Exploited
Vulnerabilities" list (cached for 24 h; a failed download falls back to the cached copy and never breaks a run).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyarrow as pa
import requests

from uc3.config import Settings
from uc3.posture import publish_posture
from uc3.transform import connect

log = logging.getLogger("uc3.publish")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_AGE = timedelta(hours=24)

REPORTING_SQL = {
    "fact_vulnerability": """
        SELECT v.snapshot_date, v.device_id, v.device_name, v.opco, v.software_vendor, v.software_name,
               v.software_version, v.cve_id, v.severity, v.cvss_score, v.exploitability, v.priority,
               v.first_seen, v.age_days, v.age_bucket, v.sla_days, v.sla_breached, v.recommended_update,
               v.security_update_available, v.device_is_stale, (k.cve_id IS NOT NULL) AS in_cisa_kev
        FROM vuln_current v LEFT JOIN ref_cisa_kev k ON k.cve_id = v.cve_id
        WHERE v.cve_id IS NOT NULL""",
    "fact_daily_summary": "SELECT * FROM vuln_daily_summary",
    "fact_change_event": """
        SELECT CAST(c.event_time AS DATE) AS event_date, c.event_time, c.status, c.device_id, c.device_name,
               coalesce(d.opco, 'UNMAPPED') AS opco, c.software_name, c.software_version, c.cve_id, c.severity
        FROM changes_dedup c LEFT JOIN device_current d USING (device_id)""",
    "fact_remediation": """
        SELECT CAST(r.event_time AS DATE) AS fixed_date, r.event_time, r.device_id, r.device_name,
               coalesce(d.opco, 'UNMAPPED') AS opco, r.software_name, r.software_version, r.cve_id,
               r.severity, r.first_seen, r.days_to_fix
        FROM remediation_events r LEFT JOIN device_current d USING (device_id)""",
    "dim_device": """
        SELECT d.device_id, d.device_name, d.opco, d.os_platform, d.os_version, d.os_build, d.health_status,
               d.exposure_level, d.risk_score, d.device_value, d.machine_tags, d.rbac_group_name, d.first_seen,
               d.last_seen, d.is_stale, d.snapshot_date, coalesce(f.findings, 0) AS findings,
               coalesce(f.critical, 0) AS critical, coalesce(f.p1, 0) AS p1
        FROM device_current d LEFT JOIN (
            SELECT device_id, count(*) AS findings, count(*) FILTER (WHERE severity = 'Critical') AS critical,
                   count(*) FILTER (WHERE priority = 'P1') AS p1
            FROM vuln_current WHERE cve_id IS NOT NULL GROUP BY device_id) f USING (device_id)""",
    "dim_cve": """
        SELECT c.*, (k.cve_id IS NOT NULL) AS in_cisa_kev, k.vulnerability_name AS kev_name,
               k.date_added AS kev_date_added, k.due_date AS kev_due_date,
               coalesce(k.ransomware_use = 'Known', false) AS kev_ransomware
        FROM cve_summary c LEFT JOIN ref_cisa_kev k ON k.cve_id = c.cve_id""",
    "dim_software": "SELECT * FROM software_summary",
    "dim_opco": """
        SELECT opco, count(*) AS devices, count(*) FILTER (WHERE is_stale) AS stale_devices
        FROM device_current GROUP BY opco""",
    "dim_date": """
        SELECT CAST(d AS DATE) AS date, year(d) AS year, month(d) AS month, strftime(d, '%Y-%m') AS year_month,
               isodow(d) AS weekday, strftime(d, '%a %d %b') AS label
        FROM range((SELECT min(snapshot_date) FROM lake_vulnerabilities),
                   (SELECT max(snapshot_date) FROM lake_vulnerabilities) + INTERVAL 1 DAY, INTERVAL 1 DAY) t(d)""",
    "dq_status": "SELECT * FROM dq_results",
    "run_history": "SELECT * FROM run_history",
}


def refresh_kev(settings: Settings, session=requests) -> dict:
    """Download the CISA KEV list at most once a day; fall back to the cached copy on any failure."""
    path = settings.data_dir / "reference" / "cisa_kev.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) if path.is_file() else None
    status = "cached"
    if age is None or age > KEV_MAX_AGE:
        try:
            response = session.get(KEV_URL, timeout=60)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data.get("vulnerabilities"), list):
                raise ValueError("unexpected format")
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(path)
            status = "downloaded"
        except Exception as exc:   # network, HTTP or format problem: keep going with the cache
            log.warning("CISA KEV download failed (%s); using cached copy if any", exc)
            status = "cached (download failed)" if path.is_file() else "unavailable"
    if not path.is_file():
        return {"status": status, "entries": 0, "catalog_version": None, "path": None}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {"status": status, "entries": len(data["vulnerabilities"]), "catalog_version": data.get("catalogVersion"),
            "path": path}


def _kev_table(kev: dict) -> pa.Table:
    records = json.loads(kev["path"].read_text(encoding="utf-8"))["vulnerabilities"] if kev["path"] else []
    return pa.table({
        "cve_id": [r.get("cveID") for r in records],
        "vulnerability_name": [r.get("vulnerabilityName") for r in records],
        "date_added": [r.get("dateAdded") for r in records],
        "due_date": [r.get("dueDate") for r in records],
        "ransomware_use": [r.get("knownRansomwareCampaignUse") for r in records],
    }, schema=pa.schema([(n, pa.string()) for n in
                         ("cve_id", "vulnerability_name", "date_added", "due_date", "ransomware_use")]))


def _run_history_table(settings: Settings) -> pa.Table:
    rows = []
    for manifest_path in sorted(settings.raw_dir.glob("????-??-??/manifest.json")):
        m = json.loads(manifest_path.read_text())
        quality_path = manifest_path.with_name("quality.json")
        quality = json.loads(quality_path.read_text())["overall"] if quality_path.is_file() else None
        rows_exported, source = m["counts"]["vulnerability_rows"], m.get("source_count")
        rows.append({
            "run_date": m["run_date"], "started_at": m.get("started_at"), "duration_seconds": m.get("duration_seconds"),
            "export_generated_time": m.get("export_generated_time"), "machines": m["counts"]["machines"],
            "vulnerability_rows": rows_exported, "defender_count": source,
            "coverage": (rows_exported / source) if source else None, "change_rows": m["counts"]["change_rows"],
            "retries": m.get("retries"), "export_attempts": m.get("export_attempts"), "quality": quality,
        })
    schema = pa.schema([("run_date", pa.string()), ("started_at", pa.string()), ("duration_seconds", pa.float64()),
                        ("export_generated_time", pa.string()), ("machines", pa.int64()),
                        ("vulnerability_rows", pa.int64()), ("defender_count", pa.int64()), ("coverage", pa.float64()),
                        ("change_rows", pa.int64()), ("retries", pa.int64()), ("export_attempts", pa.int64()),
                        ("quality", pa.string())])
    return pa.Table.from_pylist(rows, schema=schema)


def run_publish(settings: Settings, kev_session=requests) -> dict:
    settings.ensure_dirs()
    kev = refresh_kev(settings, kev_session)
    out: dict[str, int] = {}
    with connect(settings) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS dq_results (run_date DATE, check_name VARCHAR, status VARCHAR,
                       value VARCHAR, expected VARCHAR, message VARCHAR, checked_at TIMESTAMP)""")
        kev_arrow, history_arrow = _kev_table(kev), _run_history_table(settings)
        con.register("kev_arrow", kev_arrow)
        con.execute("CREATE OR REPLACE TABLE ref_cisa_kev AS SELECT * FROM kev_arrow")
        con.register("history_arrow", history_arrow)
        con.execute("CREATE OR REPLACE TABLE run_history AS SELECT * FROM history_arrow")
        for name, sql in REPORTING_SQL.items():
            target = settings.reporting_dir / f"{name}.parquet"
            tmp = target.with_suffix(".tmp")
            con.execute(f"COPY ({sql}) TO '{tmp.as_posix()}' (FORMAT PARQUET, COMPRESSION ZSTD)")
            tmp.replace(target)
            out[name] = con.execute(f"SELECT count(*) FROM read_parquet('{target.as_posix()}')").fetchone()[0]
        try:
            out.update(publish_posture(settings, con).get("tables", {}))
        except Exception:   # settings / end-of-support tables are extra: never block the main reporting tables
            log.exception("Security-settings tables not published")
    return {"tables": out, "kev": {k: (str(v) if isinstance(v, Path) else v) for k, v in kev.items()}}
