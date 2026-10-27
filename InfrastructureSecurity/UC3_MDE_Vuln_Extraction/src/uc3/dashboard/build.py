"""The data behind the portal's Vulnerabilities pages: data/dashboard/dashboard_data.json.

The agent makes no web pages of its own: the Unified Cyber Portal reads this file (read-only) and draws it.
Like every other report it reads ONLY data/reporting/*.parquet.
"""

from __future__ import annotations

import csv
import json
from datetime import date, datetime, timezone
from pathlib import Path

import duckdb

from uc3.config import CONFIG_DIR, Settings
from uc3.status import read_status

FINDING_COLUMNS = ["d", "sw", "ver", "cve", "sev", "cvss", "ex", "pr", "age", "bk", "br", "kev", "upd", "fs", "ua"]
FIXED_COLUMNS = ["d", "sw", "ver", "cve", "sev", "fixed", "fs", "days"]


def _rows(con, sql: str) -> list[tuple]:
    return con.execute(sql).fetchall()


def _dicts(con, sql: str) -> list[dict]:
    result = con.execute(sql)
    names = [d[0] for d in result.description]
    return [dict(zip(names, row)) for row in result.fetchall()]


def _json_default(value):
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"not JSON serialisable: {type(value)}")


def build_payload(settings: Settings) -> dict:
    rep = settings.reporting_dir
    con = duckdb.connect()
    for name in ("fact_vulnerability", "fact_daily_summary", "fact_change_event", "fact_remediation", "dim_device",
                 "dim_cve", "dq_status", "run_history"):
        path = rep / f"{name}.parquet"
        if not path.is_file():
            raise FileNotFoundError(f"{path} missing. Run: python -m uc3 publish")
        con.execute(f"CREATE VIEW {name} AS SELECT * FROM read_parquet('{path.as_posix()}')")

    devices = _dicts(con, """
        SELECT device_id AS id, device_name AS name, opco, os_platform AS os, os_version AS osv, machine_tags AS tags,
               strftime(last_seen, '%Y-%m-%d %H:%M') AS last_seen, health_status AS health, exposure_level AS exposure,
               is_stale AS stale, rbac_group_name, findings, critical, p1
        FROM dim_device ORDER BY device_name""")
    index = {d["id"]: i for i, d in enumerate(devices)}
    findings = []
    for row in _dicts(con, """
            SELECT device_id, device_name, opco, software_name AS sw, software_version AS ver, cve_id AS cve,
                   severity AS sev, cvss_score AS cvss, exploitability AS ex, priority AS pr, age_days AS age,
                   age_bucket AS bk, sla_breached AS br, in_cisa_kev AS kev, recommended_update AS upd,
                   strftime(first_seen, '%Y-%m-%d') AS fs, security_update_available AS ua
            FROM fact_vulnerability ORDER BY device_id, sw, cve"""):
        if row["device_id"] not in index:   # vulnerability for a device missing from the device list
            index[row["device_id"]] = len(devices)
            devices.append({"id": row["device_id"], "name": row["device_name"], "opco": row["opco"], "os": None,
                            "osv": None, "tags": [], "last_seen": None, "health": "Unknown", "exposure": None,
                            "stale": False, "findings": 0, "critical": 0, "p1": 0})
        row["d"] = index[row["device_id"]]
        row["br"], row["kev"] = int(bool(row["br"])), int(bool(row["kev"]))
        row["ua"] = int(row["ua"] is not False)   # 0 = Defender says the vendor has no security update yet
        findings.append([row[c] for c in FINDING_COLUMNS])

    # Vulnerabilities Defender reported as fixed (delta feed), minus any that are open again today
    fixed = []
    for row in _dicts(con, """
            SELECT r.device_id, r.device_name, r.opco, r.software_name AS sw, r.software_version AS ver, r.cve_id AS cve,
                   r.severity AS sev, strftime(r.fixed_date, '%Y-%m-%d') AS fixed, strftime(r.first_seen, '%Y-%m-%d') AS fs,
                   r.days_to_fix AS days
            FROM fact_remediation r
            WHERE r.cve_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM fact_vulnerability v WHERE v.device_id = r.device_id AND v.cve_id = r.cve_id
                  AND v.software_name = r.software_name AND v.software_version = r.software_version)
            QUALIFY row_number() OVER (PARTITION BY r.device_id, r.cve_id, r.software_name, r.software_version
                                       ORDER BY r.event_time DESC) = 1
            ORDER BY r.fixed_date DESC, r.device_name, sw, cve"""):
        if row["device_id"] not in index:
            index[row["device_id"]] = len(devices)
            devices.append({"id": row["device_id"], "name": row["device_name"], "opco": row["opco"], "os": None,
                            "osv": None, "tags": [], "last_seen": None, "health": "Unknown", "exposure": None,
                            "stale": False, "findings": 0, "critical": 0, "p1": 0})
        row["d"] = index[row["device_id"]]
        fixed.append([row[c] for c in FIXED_COLUMNS])

    runs = _dicts(con, "SELECT * FROM run_history ORDER BY run_date")
    latest_dq = _dicts(con, """SELECT check_name AS name, status, value, expected, message, run_date
                               FROM dq_status WHERE run_date = (SELECT max(run_date) FROM dq_status)""")
    kql_path = settings.data_dir / "reference" / "kql_limit.json"
    kev_path = settings.data_dir / "reference" / "cisa_kev.json"
    kev_meta = {"entries": 0, "version": None}
    if kev_path.is_file():
        catalog = json.loads(kev_path.read_text(encoding="utf-8"))
        kev_meta = {"entries": len(catalog.get("vulnerabilities", [])), "version": catalog.get("catalogVersion")}
    with (CONFIG_DIR / "sla_policy.csv").open(encoding="utf-8") as fh:
        sla = {r["severity"].strip(): int(r["days_to_fix"]) for r in csv.DictReader(fh)}

    snapshot = _rows(con, "SELECT max(snapshot_date) FROM dim_device")[0][0]
    fixes_path = rep / "ai_fixes.json"   # AI Fix Guide (uc3.ai.fixes); optional
    fixes = json.loads(fixes_path.read_text(encoding="utf-8")) if fixes_path.is_file() else None
    if fixes and str(fixes.get("snapshot")) != str(snapshot):
        fixes["stale"] = True
    return {
        "meta": {"snapshot": snapshot, "built_at": datetime.now(timezone.utc).isoformat(timespec="minutes"),
                 "source": "Microsoft Defender for Endpoint (lab tenant)", "kev": kev_meta, "sla": sla},
        "run": runs[-1] if runs else None,
        "runs": runs,
        "kql": json.loads(kql_path.read_text()) if kql_path.is_file() else None,
        "devices": devices,
        "f": {"cols": FINDING_COLUMNS, "rows": findings},
        "fixed": {"cols": FIXED_COLUMNS, "rows": fixed},
        "kev": _dicts(con, """SELECT cve_id AS cve, kev_name AS name, kev_date_added AS added, kev_ransomware AS rw
                             FROM dim_cve WHERE in_cisa_kev"""),
        "daily": _rows(con, """SELECT snapshot_date, opco, severity, priority, vulnerabilities, exploitable, sla_breaches
                              FROM fact_daily_summary ORDER BY 1"""),
        "changes": _rows(con, """SELECT event_date, opco, status, coalesce(severity, 'None'), count(*)
                                FROM fact_change_event GROUP BY ALL ORDER BY 1"""),
        "remed": _rows(con, "SELECT fixed_date, opco, severity, days_to_fix FROM fact_remediation ORDER BY 1"),
        "dq": latest_dq,
        "status": read_status(settings),
        "fixes": fixes,
        "posture": _posture_meta(settings, con, rep),
        "download": _last_download(settings),
    }


def _last_download(settings: Settings) -> dict | None:
    """The latest run's download from Defender: the full list, plus what Defender itself changed since the run before."""
    manifests = sorted(settings.raw_dir.glob("????-??-??/manifest.json"))
    if not manifests:
        return None
    m = json.loads(manifests[-1].read_text())
    counts = m.get("counts") or {}
    changes = manifests[-1].parent / "changes.json.gz"
    if "new" not in counts and changes.is_file():     # downloads from before the counts were kept
        from uc3.extract import _count_changes
        counts = {**counts, **_count_changes(changes)}
    return {k: m.get(k) for k in ("run_date", "started_at", "export_generated_time", "previous_export_time", "changes_since")} \
        | {"counts": counts}


def _posture_meta(settings: Settings, con, rep: Path) -> dict | None:
    """What the latest settings/end-of-support download did (manifest) + today's pass rate (fact_config_assessment)."""
    manifests = sorted(settings.raw_dir.glob("????-??-??/manifest.json"))
    posture = json.loads(manifests[-1].read_text()).get("posture") if manifests else None
    if not posture:
        return None
    meta = {"run_date": manifests[-1].parent.name, **posture, "compliance": None, "failing": 0}
    path = rep / "fact_config_assessment.parquet"
    if path.is_file():
        total, ok = con.execute(f"SELECT count(*), count(*) FILTER (WHERE is_compliant) FROM read_parquet('{path.as_posix()}')").fetchone()
        meta.update(compliance=(ok / total) if total else None, failing=total - ok)
    return meta


def build_dashboard(settings: Settings) -> Path:
    """Write data/dashboard/dashboard_data.json: what the portal's Vulnerabilities and Fix pages are drawn from."""
    payload = build_payload(settings)
    out_dir = settings.data_dir / "dashboard"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "dashboard_data.json"
    path.write_text(json.dumps(payload, default=_json_default, separators=(",", ":")), encoding="utf-8")
    return path
