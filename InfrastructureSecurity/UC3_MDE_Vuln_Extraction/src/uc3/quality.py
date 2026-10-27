"""Quality step: automatic data checks for one run, saved to data/raw/<date>/quality.json and the dq_results table.

Levels: FAIL = the data can't be trusted (later steps should not publish it), WARN = publish but flag it,
PASS = fine, INFO = for information only.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone

from uc3.config import Settings
from uc3.load import latest_run_date
from uc3.transform import connect

VOLUME_SWING = 0.20          # warn when rows change by more than 20% from the previous snapshot
MAX_EXPORT_AGE = timedelta(hours=24)


@dataclass
class Check:
    name: str
    status: str          # PASS / WARN / FAIL / INFO
    value: str
    expected: str
    message: str


def _parse(text: str | None) -> datetime | None:
    return datetime.fromisoformat(text.replace("Z", "+00:00")) if text else None


def run_checks(settings: Settings, run_date: date | None = None) -> dict:
    run_date = run_date or latest_run_date(settings)
    raw = settings.raw_dir / run_date.isoformat()
    manifest = json.loads((raw / "manifest.json").read_text())
    load_file = raw / "load.json"
    dropped = json.loads(load_file.read_text()).get("duplicates_dropped", 0) if load_file.is_file() else 0
    day = f"DATE '{run_date.isoformat()}'"
    checks: list[Check] = []
    add = lambda *args: checks.append(Check(*args))

    with connect(settings) as con:
        one = lambda sql: con.execute(sql).fetchone()
        rows, with_cve, devices_in_vulns = one(
            f"SELECT count(*), count(cve_id), count(DISTINCT device_id) FROM lake_vulnerabilities WHERE snapshot_date = {day}")
        device_rows = one(f"SELECT count(*) FROM lake_devices WHERE snapshot_date = {day}")[0]

        # 1. Everything downloaded made it into the lake (less the repeated copies the load step dropped)
        expected = manifest["counts"]["vulnerability_rows"] - dropped
        add("completeness", "PASS" if rows == expected else "FAIL", f"{rows:,} rows loaded",
            f"{expected:,} rows downloaded" + (f" less {dropped:,} repeats" if dropped else ""),
            "Rows in the data lake match the downloaded export files."
            if rows == expected else "Rows were lost or duplicated between download and data lake.")

        # 2. Coverage against Defender's own count (a KQL count is never capped at 100,000)
        source = manifest.get("source_count")
        if source is None:
            add("coverage_vs_defender", "WARN", f"{with_cve:,} rows", "Defender's own count",
                "Defender's count wasn't available (" + manifest.get("source_count_error", "unknown reason") + ").")
        else:
            with_cve += dropped     # Defender's count includes the repeated copies
            coverage = with_cve / source if source else 1.0
            add("coverage_vs_defender", "PASS" if with_cve == source else "WARN", f"{coverage:.1%} ({with_cve:,} rows)",
                f"100% ({source:,} rows in Defender)",
                "Every vulnerability row Defender holds was extracted." if with_cve == source else
                "Counts differ. Defender refreshes the export every 6 hours while its count is live, so a "
                "difference right after new scans is normal; if it persists, investigate.")

        # 3. Something arrived at all
        ok = rows > 0 and device_rows > 0
        add("not_empty", "PASS" if ok else "FAIL", f"{rows:,} rows, {device_rows:,} devices", "> 0",
            "Data received." if ok else "The export or device list was empty.")

        # 4. The export is recent
        generated, started = _parse(manifest.get("export_generated_time")), _parse(manifest.get("started_at"))
        if generated and started:
            age = started - generated
            fresh = age <= MAX_EXPORT_AGE
            add("freshness", "PASS" if fresh else "FAIL", f"export {age.total_seconds() / 3600:.1f} h old",
                f"<= {MAX_EXPORT_AGE.total_seconds() / 3600:.0f} h", "Export is recent." if fresh else
                "Defender's export is older than a day; its data may be stale.")
        else:
            add("freshness", "WARN", "unknown", "<= 24 h", "The export didn't say when it was generated.")

        # 5. No duplicate records
        duplicates = one(f"""SELECT count(*) FROM (
              SELECT 1 FROM lake_vulnerabilities WHERE snapshot_date = {day}
              GROUP BY device_id, software_vendor, software_name, software_version, cve_id HAVING count(*) > 1)""")[0]
        add("no_duplicates", "PASS" if duplicates == 0 else "FAIL", f"{duplicates:,} duplicated keys", "0",
            "Each device/software/version/CVE appears once." if duplicates == 0 else "Some records appear more than once.")
        if dropped:
            add("defender_repeats", "INFO", f"{dropped:,} repeated rows dropped", "info",
                "Defender's export listed some findings twice (an older copy next to the current one); "
                "only the newest copy was kept.")

        # 6. Mandatory fields are filled
        missing = one(f"""SELECT count(*) FROM lake_vulnerabilities WHERE snapshot_date = {day}
              AND (device_id IS NULL OR software_name IS NULL)""")[0]
        add("mandatory_fields", "PASS" if missing == 0 else "FAIL", f"{missing:,} incomplete rows", "0",
            "Device and software are always filled." if missing == 0 else "Some rows lack a device or software name.")

        # 6b. Brand-new CVEs not yet rated by Microsoft - information only, shown as 'Unrated'
        unrated = one(f"""SELECT count(*), count(DISTINCT cve_id) FROM lake_vulnerabilities WHERE snapshot_date = {day}
              AND cve_id IS NOT NULL AND severity IS NULL""")
        add("unrated_cves", "INFO", f"{unrated[0]:,} rows ({unrated[1]:,} CVEs) without a severity yet", "info",
            "Very new CVEs arrive before Microsoft rates them; they show as 'Unrated' (treated as P3) until rated.")

        # 7. Volume didn't jump unexpectedly
        previous = one(f"""SELECT snapshot_date, count(*) FROM lake_vulnerabilities WHERE snapshot_date < {day}
              GROUP BY 1 ORDER BY 1 DESC LIMIT 1""")
        if previous:
            change = (rows - previous[1]) / previous[1] if previous[1] else 1.0
            add("volume_change", "PASS" if abs(change) <= VOLUME_SWING else "WARN",
                f"{change:+.0%} vs {previous[0]}", f"within ±{VOLUME_SWING:.0%}",
                "Normal day-to-day change." if abs(change) <= VOLUME_SWING else
                "Large change - expected after onboarding or mass patching, otherwise investigate.")
        else:
            add("volume_change", "INFO", "first snapshot", "a previous day", "Nothing to compare with yet.")

        # 8. Every device in the vulnerability data is in the device list
        orphans = one(f"""SELECT count(DISTINCT v.device_id) FROM lake_vulnerabilities v
              LEFT JOIN lake_devices d ON d.device_id = v.device_id AND d.snapshot_date = v.snapshot_date
              WHERE v.snapshot_date = {day} AND d.device_id IS NULL""")[0]
        add("devices_known", "PASS" if orphans == 0 else "WARN", f"{orphans:,} unknown devices", "0",
            "All devices are in the device list." if orphans == 0 else "Some devices have vulnerabilities but no device record.")

        # 9. Every device is mapped to an OpCo
        unmapped = one(f"""SELECT count(*), string_agg(device_name, ', ') FROM device_snapshot
              WHERE snapshot_date = {day} AND opco = 'UNMAPPED'""")
        add("opco_mapping", "PASS" if unmapped[0] == 0 else "WARN", f"{unmapped[0]:,} unmapped devices", "0",
            "Every device belongs to an OpCo." if unmapped[0] == 0 else
            f"Add a tag or a rule in config/opco_mapping.csv for: {unmapped[1]}")

        # 10. Stale devices (not seen for 30+ days) - information only
        stale = one(f"SELECT count(*) FROM device_snapshot WHERE snapshot_date = {day} AND is_stale")[0]
        add("stale_devices", "INFO", f"{stale:,} stale devices", "info",
            "Devices not seen for over 30 days are shown separately in reports.")

        overall = "FAIL" if any(c.status == "FAIL" for c in checks) else (
            "WARN" if any(c.status == "WARN" for c in checks) else "PASS")
        checked_at = datetime.now(timezone.utc).replace(microsecond=0)
        con.execute("""CREATE TABLE IF NOT EXISTS dq_results (run_date DATE, check_name VARCHAR, status VARCHAR,
                       value VARCHAR, expected VARCHAR, message VARCHAR, checked_at TIMESTAMP)""")
        con.execute(f"DELETE FROM dq_results WHERE run_date = {day}")
        con.executemany("INSERT INTO dq_results VALUES (?, ?, ?, ?, ?, ?, ?)",
                        [(run_date, c.name, c.status, c.value, c.expected, c.message, checked_at.replace(tzinfo=None))
                         for c in checks])

    report = {"run_date": run_date.isoformat(), "overall": overall, "checked_at": checked_at.isoformat(),
              "checks": [asdict(c) for c in checks]}
    (raw / "quality.json").write_text(json.dumps(report, indent=2))
    return report


def format_report(report: dict) -> str:
    lines = [f"Data quality for {report['run_date']}: {report['overall']}", ""]
    width = max(len(c["name"]) for c in report["checks"])
    for c in report["checks"]:
        lines.append(f"  [{c['status']:<4}] {c['name']:<{width}}  {c['value']}  (expected {c['expected']})")
        if c["status"] in ("WARN", "FAIL"):
            lines.append(f"         {'':<{width}}  -> {c['message']}")
    return "\n".join(lines)
