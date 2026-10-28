"""Security posture beyond software CVEs: wrong security SETTINGS and END-OF-SUPPORT software.

Extract (part of `uc3 extract` / `run`, never stops a run if it fails) -> data/raw/<date>/posture/:
- config/part-*.json.gz  Defender "secure configuration assessment": one row per device x setting.
                         Uses the export API (no row limit); falls back to advanced hunting (lab scale) if the app
                         registration lacks the permission.
- config_kb.json         Microsoft's description, risk and remediation text for every setting (advanced hunting).
- eos.json.gz            installed software that is past / near end of support. Export API needs Software.Read.All;
                         without it, a filtered advanced-hunting query (only end-of-support rows) is used.

Publish (part of `uc3 publish`) -> data/reporting/:
  fact_config_assessment, dim_config, fact_eos_software, fact_posture_daily.
"""

from __future__ import annotations

import gzip
import html
import json
import logging
import re
import shutil
from pathlib import Path

import pyarrow as pa

from uc3.api_client import ApiError, DefenderClient, EmptyDownload, LinkExpired

log = logging.getLogger("uc3.posture")

EXPORT_ATTEMPTS = 3
CONFIG_EXPORT = "/api/machines/SecureConfigurationsAssessmentExport"
SOFTWARE_EXPORT = "/api/machines/SoftwareInventoryExport"
HUNTING = "/api/advancedqueries/run"
KQL_ROW_LIMIT = 100_000
CONFIG_QUERY = """DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| project DeviceId, DeviceName, ConfigurationId, ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact,
          IsApplicable, IsCompliant, IsExpectedUserImpact, Context, Timestamp"""
KB_QUERY = "DeviceTvmSecureConfigurationAssessmentKB"
EOS_QUERY = """DeviceTvmSoftwareInventory
| where isnotempty(EndOfSupportStatus)
| project DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate"""
NO_PERMISSION = (401, 403, 404)


# ---------- extract ----------
def _write_gz(path: Path, records) -> int:
    rows = 0
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
            rows += 1
    return rows


def _hunting(client: DefenderClient, query: str) -> list[dict]:
    rows = client.post_json(HUNTING, {"Query": query}).get("Results", [])
    if len(rows) >= KQL_ROW_LIMIT:
        log.warning("Advanced hunting returned %d rows = the KQL limit; data is incomplete. Grant the export "
                    "permission so UC3 can use the export API instead", len(rows))
    return rows


def _export(client: DefenderClient, path: str, folder: Path) -> dict:
    """Request an export and download its files. Defender sometimes hands back an empty file or links that have
    already expired: then a fresh export is requested, like the vulnerability export does."""
    for attempt in range(1, EXPORT_ATTEMPTS + 1):
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
        files = []
        try:
            export = client.get_json(path, {"sasValidHours": 1})
            for i, url in enumerate(export.get("exportFiles", [])):
                size, rows = client.download(url, folder / f"part-{i:05d}.json.gz")
                files.append({"name": f"part-{i:05d}.json.gz", "bytes": size, "rows": rows})
        except (LinkExpired, EmptyDownload) as exc:
            if attempt == EXPORT_ATTEMPTS:
                shutil.rmtree(folder, ignore_errors=True)
                raise
            log.info("%s; requesting a fresh export",
                     "Download links expired" if isinstance(exc, LinkExpired) else "A downloaded file was empty")
            continue
        except Exception:
            shutil.rmtree(folder, ignore_errors=True)
            raise
        return {"generated_time": export.get("generatedTime"), "rows": sum(f["rows"] for f in files),
                "files": len(files), "attempts": attempt}
    raise AssertionError("unreachable")


def extract_posture(client: DefenderClient, work_dir: Path) -> dict:
    """Download settings, their descriptions and end-of-support software. Each part fails on its own."""
    out_dir = work_dir / "posture"
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {"errors": []}

    try:
        try:
            result["config"] = {"method": "export API", **_export(client, CONFIG_EXPORT, out_dir / "config")}
        except ApiError as exc:
            if exc.status not in NO_PERMISSION:
                raise
            log.info("Settings export not allowed (%s); using advanced hunting instead", exc.status)
            rows = _hunting(client, CONFIG_QUERY)
            (out_dir / "config").mkdir(exist_ok=True)
            _write_gz(out_dir / "config" / "part-00000.json.gz", rows)
            result["config"] = {"method": "advanced hunting", "rows": len(rows), "files": 1,
                                "truncated": len(rows) >= KQL_ROW_LIMIT}
    except Exception as exc:   # posture is extra information: log it and carry on
        # No config folder for this day, so publish keeps showing the last day that has settings data
        shutil.rmtree(out_dir / "config", ignore_errors=True)
        log.warning("Could not download security settings (the last good download is kept): %s",
                    str(exc).splitlines()[0])
        result["errors"].append(f"settings: {str(exc).splitlines()[0]}")

    try:
        kb = _hunting(client, KB_QUERY)
        (out_dir / "config_kb.json").write_text(json.dumps(kb), encoding="utf-8")
        result["config_kb"] = {"rows": len(kb)}
    except Exception as exc:
        log.warning("Could not download setting descriptions: %s", exc)
        result["errors"].append(f"setting descriptions: {str(exc).splitlines()[0]}")

    try:
        try:
            tmp = out_dir / "software_export"
            meta = _export(client, SOFTWARE_EXPORT, tmp)
            eos = [r for part in sorted(tmp.glob("*.json.gz")) for r in _read_gz(part) if _lower(r).get("endofsupportstatus")]
            for part in tmp.glob("*.json.gz"):   # full inventory is not kept, only end-of-support rows
                part.unlink()
            tmp.rmdir()
            method = "export API"
        except ApiError as exc:
            if exc.status not in NO_PERMISSION:
                raise
            log.info("Software inventory export not allowed (%s); using advanced hunting instead", exc.status)
            eos, method = _hunting(client, EOS_QUERY), "advanced hunting"
        result["eos"] = {"method": method, "rows": _write_gz(out_dir / "eos.json.gz", eos)}
    except Exception as exc:
        shutil.rmtree(out_dir / "software_export", ignore_errors=True)
        log.warning("Could not download end-of-support software: %s", str(exc).splitlines()[0])
        result["errors"].append(f"end-of-support: {str(exc).splitlines()[0]}")
    return result


# ---------- read raw ----------
def _read_gz(path: Path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def _lower(record: dict) -> dict:
    return {k.lower(): v for k, v in record.items()}


def _ts(value) -> str:
    return str(value or "").replace("T", " ").rstrip("Z")[:19]


def latest_config_rows(day_dir: Path) -> list[dict]:
    """One row per device x setting: the newest reading (the export can contain older readings too)."""
    best: dict[tuple, dict] = {}
    for part in sorted((day_dir / "posture" / "config").glob("*.json.gz")):
        for raw in _read_gz(part):
            r = _lower(raw)
            if not r.get("isapplicable"):
                continue
            key = (r.get("deviceid"), r.get("configurationid"))
            if key not in best or _ts(r.get("timestamp")) >= _ts(best[key].get("timestamp")):
                best[key] = r
    return list(best.values())


def html_to_text(value: str | None) -> str:
    text = re.sub(r"<\s*(br|/p|/li|li)[^>]*>", "\n", value or "", flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", "", text))
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n", text)).strip()


def html_links(value: str | None) -> list[str]:
    return sorted({u.strip() for u in re.findall(r"href=['\"](https://[^'\"]+)['\"]", value or "")})


def _context_text(context) -> str:
    """Defender's context (e.g. which services have an unquoted path), user folders masked."""
    if not context:
        return ""
    text = json.dumps(context, ensure_ascii=False)
    return re.sub(r"(?i)(c:\\\\users\\\\)[^\\\\\"]+", r"\1<user>", text)[:2000]


# ---------- publish ----------
SCHEMAS = {
    "fact_config_assessment": pa.schema([
        ("snapshot_date", pa.string()), ("device_id", pa.string()), ("device_name", pa.string()),
        ("config_id", pa.string()), ("is_compliant", pa.bool_()), ("user_impact", pa.bool_()),
        ("context", pa.string()), ("assessed_at", pa.string())]),
    "dim_config": pa.schema([
        ("config_id", pa.string()), ("config_name", pa.string()), ("category", pa.string()),
        ("subcategory", pa.string()), ("impact", pa.float64()), ("description", pa.string()), ("risk", pa.string()),
        ("remediation", pa.string()), ("remediation_links", pa.string()), ("benchmarks", pa.string()),
        ("tags", pa.string())]),
    "fact_eos_software": pa.schema([
        ("snapshot_date", pa.string()), ("device_id", pa.string()), ("device_name", pa.string()),
        ("software_vendor", pa.string()), ("software_name", pa.string()), ("software_version", pa.string()),
        ("eos_status", pa.string()), ("eos_date", pa.string())]),
}


def _config_table(day: str, rows: list[dict]) -> pa.Table:
    return pa.Table.from_pylist([{
        "snapshot_date": day, "device_id": r.get("deviceid"), "device_name": r.get("devicename"),
        "config_id": r.get("configurationid"), "is_compliant": bool(r.get("iscompliant")),
        "user_impact": bool(r.get("isexpecteduserimpact")), "context": _context_text(r.get("context")),
        "assessed_at": _ts(r.get("timestamp")),
    } for r in rows], schema=SCHEMAS["fact_config_assessment"])


def _dim_config(day_dir: Path, config_rows: list[dict]) -> pa.Table:
    kb_path = day_dir / "posture" / "config_kb.json"
    kb = ({r["ConfigurationId"]: r for r in json.loads(kb_path.read_text(encoding="utf-8")) if r.get("ConfigurationId")}
          if kb_path.is_file() else {})
    names = {r.get("configurationid"): r for r in config_rows}   # export rows carry names even without the KB
    out = []
    for cid in sorted(set(kb) | set(names)):
        k, n = kb.get(cid, {}), names.get(cid, {})
        out.append({
            "config_id": cid, "config_name": k.get("ConfigurationName") or n.get("configurationname") or cid,
            "category": k.get("ConfigurationCategory") or n.get("configurationcategory"),
            "subcategory": k.get("ConfigurationSubcategory") or n.get("configurationsubcategory"),
            "impact": float(k.get("ConfigurationImpact") or n.get("configurationimpact") or 0),
            "description": html_to_text(k.get("ConfigurationDescription")), "risk": html_to_text(k.get("RiskDescription")),
            "remediation": html_to_text(k.get("RemediationOptions")),
            "remediation_links": json.dumps(html_links(k.get("RemediationOptions")) + html_links(k.get("ConfigurationDescription"))),
            "benchmarks": ", ".join(k.get("ConfigurationBenchmarks") or []), "tags": ", ".join(k.get("Tags") or []),
        })
    return pa.Table.from_pylist(out, schema=SCHEMAS["dim_config"])


def _eos_table(day: str, day_dir: Path) -> pa.Table:
    path = day_dir / "posture" / "eos.json.gz"
    rows = [_lower(r) for r in _read_gz(path)] if path.is_file() else []
    seen, out = set(), []
    for r in rows:
        key = (r.get("deviceid"), r.get("softwarename"), r.get("softwareversion"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"snapshot_date": day, "device_id": r.get("deviceid"), "device_name": r.get("devicename"),
                    "software_vendor": r.get("softwarevendor"), "software_name": r.get("softwarename"),
                    "software_version": r.get("softwareversion"), "eos_status": r.get("endofsupportstatus"),
                    "eos_date": str(r.get("endofsupportdate") or "")[:10] or None})
    return pa.Table.from_pylist(out, schema=SCHEMAS["fact_eos_software"])


def publish_posture(settings, con) -> dict:
    """Write the posture reporting tables from the newest downloaded day that has posture data."""
    # Only days whose settings download worked: an empty folder would show zero weak settings
    days = sorted(p.parent.parent for p in settings.raw_dir.glob("????-??-??/posture/config") if any(p.glob("*.json.gz")))
    rep = settings.reporting_dir
    if not days:
        log.info("No security-settings data downloaded yet (runs before 2026-10-05); posture tables skipped")
        for name in ("fact_config_assessment", "dim_config", "fact_eos_software", "fact_posture_daily"):
            (rep / f"{name}.parquet").unlink(missing_ok=True)
        return {}
    latest = days[-1]
    config_rows = latest_config_rows(latest)
    tables = {"fact_config_assessment": _config_table(latest.name, config_rows),
              "dim_config": _dim_config(latest, config_rows),
              "fact_eos_software": _eos_table(latest.name, latest)}
    history = pa.concat_tables([_config_table(d.name, latest_config_rows(d)) for d in days])
    for name, table in {**tables, "history": history}.items():
        con.register(f"posture_{name}", table)
    # OpCo comes from the device list (same mapping as the vulnerability tables)
    statements = {
        "fact_config_assessment": """
            SELECT a.snapshot_date, a.device_id, a.device_name, coalesce(d.opco, 'UNMAPPED') AS opco, a.config_id,
                   c.config_name, c.category, c.subcategory, c.impact, a.is_compliant, a.user_impact, a.context, a.assessed_at
            FROM posture_fact_config_assessment a LEFT JOIN device_current d USING (device_id)
            LEFT JOIN posture_dim_config c USING (config_id)""",
        "dim_config": "SELECT * FROM posture_dim_config",
        "fact_eos_software": """
            SELECT e.*, coalesce(d.opco, 'UNMAPPED') AS opco
            FROM posture_fact_eos_software e LEFT JOIN device_current d USING (device_id)""",
        "fact_posture_daily": """
            SELECT CAST(h.snapshot_date AS DATE) AS snapshot_date, coalesce(d.opco, 'UNMAPPED') AS opco,
                   count(*) AS applicable, count(*) FILTER (WHERE h.is_compliant) AS compliant,
                   count(*) FILTER (WHERE NOT h.is_compliant) AS failing, count(DISTINCT h.device_id) AS devices
            FROM posture_history h LEFT JOIN device_current d USING (device_id) GROUP BY ALL ORDER BY 1, 2""",
    }
    counts = {}
    for name, sql in statements.items():
        target = rep / f"{name}.parquet"
        tmp = target.with_suffix(".tmp")
        con.execute(f"COPY ({sql}) TO '{tmp.as_posix()}' (FORMAT PARQUET, COMPRESSION ZSTD)")
        tmp.replace(target)
        counts[name] = con.execute(f"SELECT count(*) FROM read_parquet('{target.as_posix()}')").fetchone()[0]
    for name in (*tables, "history"):
        con.unregister(f"posture_{name}")
    return {"snapshot": latest.name, "tables": counts}
