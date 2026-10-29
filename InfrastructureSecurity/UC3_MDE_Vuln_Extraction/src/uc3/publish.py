"""Publish step: write the Power-BI-ready reporting tables to data/reporting/*.parquet.

Every dashboard (the HTML Command Centre, the Excel summary, Power BI later) reads ONLY these files.
"""

from __future__ import annotations

import json
import logging

import pyarrow as pa

from uc3.config import Settings
from uc3.posture import publish_posture
from uc3.transform import connect

log = logging.getLogger("uc3.publish")

REPORTING_SQL = {
    "fact_vulnerability": """
        SELECT v.snapshot_date, v.device_id, v.device_name, v.opco, v.software_vendor, v.software_name,
               v.software_version, v.cve_id, v.severity, v.cvss_score, v.exploitability, v.priority,
               v.first_seen, v.age_days, v.age_bucket, v.sla_days, v.sla_breached, v.recommended_update,
               v.security_update_available, v.device_is_stale
        FROM vuln_current v
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
    "dim_cve": "SELECT * FROM cve_summary",
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


def _run_history_table(settings: Settings) -> pa.Table:
    rows = []
    for manifest_path in sorted(settings.raw_dir.glob("????-??-??/manifest.json")):
        m = json.loads(manifest_path.read_text())
        quality_path = manifest_path.with_name("quality.json")
        quality = json.loads(quality_path.read_text())["overall"] if quality_path.is_file() else None
        rows_exported, source = m["counts"]["vulnerability_rows"], m.get("source_count")
        # Defender lists some findings twice; the load step keeps one copy (no load.json = before that step existed)
        load_path = manifest_path.with_name("load.json")
        repeats = json.loads(load_path.read_text()).get("duplicates_dropped", 0) if load_path.is_file() else 0
        rows.append({
            "run_date": m["run_date"], "started_at": m.get("started_at"), "duration_seconds": m.get("duration_seconds"),
            "export_generated_time": m.get("export_generated_time"), "machines": m["counts"]["machines"],
            "vulnerability_rows": rows_exported, "repeats": repeats, "vulnerabilities": rows_exported - repeats,
            "defender_count": source,
            "coverage": (rows_exported / source) if source else None, "change_rows": m["counts"]["change_rows"],
            "retries": m.get("retries"), "export_attempts": m.get("export_attempts"), "quality": quality,
        })
    schema = pa.schema([("run_date", pa.string()), ("started_at", pa.string()), ("duration_seconds", pa.float64()),
                        ("export_generated_time", pa.string()), ("machines", pa.int64()),
                        ("vulnerability_rows", pa.int64()), ("repeats", pa.int64()), ("vulnerabilities", pa.int64()),
                        ("defender_count", pa.int64()), ("coverage", pa.float64()),
                        ("change_rows", pa.int64()), ("retries", pa.int64()), ("export_attempts", pa.int64()),
                        ("quality", pa.string())])
    return pa.Table.from_pylist(rows, schema=schema)


def run_publish(settings: Settings) -> dict:
    settings.ensure_dirs()
    out: dict[str, int] = {}
    with connect(settings) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS dq_results (run_date DATE, check_name VARCHAR, status VARCHAR,
                       value VARCHAR, expected VARCHAR, message VARCHAR, checked_at TIMESTAMP)""")
        history_arrow = _run_history_table(settings)
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
    return {"tables": out}
