"""Load step: turn one day's raw downloads (data/raw/<date>/) into typed Parquet files in the data lake.

  data/lake/vulnerabilities/snapshot_date=<date>/part-0.parquet   full snapshot of that day
  data/lake/devices/snapshot_date=<date>/part-0.parquet           device list of that day
  data/lake/changes/snapshot_date=<date>/part-0.parquet           change events collected that day

Field names are matched case-insensitively (Defender's export files use `DeviceId`, its JSON answers use
`deviceId`), unknown fields are ignored and missing ones become empty. Re-loading a day replaces it. A finding the
export lists twice is kept once (the newest copy); the count dropped goes to data/raw/<date>/load.json.
"""

from __future__ import annotations

import gzip
import json
import re
from collections.abc import Iterable, Iterator
from datetime import date, datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from uc3.config import Settings

# (column, source field lower-cased, arrow type)
VULNERABILITY_FIELDS = [
    ("record_id", "id", pa.string()),
    ("device_id", "deviceid", pa.string()),
    ("device_name", "devicename", pa.string()),
    ("os_platform", "osplatform", pa.string()),
    ("os_version", "osversion", pa.string()),
    ("os_architecture", "osarchitecture", pa.string()),
    ("software_vendor", "softwarevendor", pa.string()),
    ("software_name", "softwarename", pa.string()),
    ("software_version", "softwareversion", pa.string()),
    ("cve_id", "cveid", pa.string()),
    ("cvss_score", "cvssscore", pa.float64()),
    ("severity", "vulnerabilityseveritylevel", pa.string()),
    ("exploitability", "exploitabilitylevel", pa.string()),
    ("first_seen", "firstseentimestamp", pa.timestamp("us")),
    ("last_seen", "lastseentimestamp", pa.timestamp("us")),
    ("recommendation_reference", "recommendationreference", pa.string()),
    ("recommended_update", "recommendedsecurityupdate", pa.string()),
    ("recommended_update_id", "recommendedsecurityupdateid", pa.string()),
    ("security_update_available", "securityupdateavailable", pa.bool_()),
    ("rbac_group_name", "rbacgroupname", pa.string()),
    ("rbac_group_id", "rbacgroupid", pa.string()),
]
CHANGE_FIELDS = VULNERABILITY_FIELDS + [
    ("status", "status", pa.string()),
    ("event_time", "eventtimestamp", pa.timestamp("us")),
]
DEVICE_FIELDS = [
    ("device_id", "id", pa.string()),
    ("device_name", "computerdnsname", pa.string()),
    ("os_platform", "osplatform", pa.string()),
    ("os_version", "version", pa.string()),
    ("os_build", "osbuild", pa.int64()),
    ("health_status", "healthstatus", pa.string()),
    ("onboarding_status", "onboardingstatus", pa.string()),
    ("rbac_group_name", "rbacgroupname", pa.string()),
    ("rbac_group_id", "rbacgroupid", pa.string()),
    ("risk_score", "riskscore", pa.string()),
    ("exposure_level", "exposurelevel", pa.string()),
    ("device_value", "devicevalue", pa.string()),
    ("machine_tags", "machinetags", pa.list_(pa.string())),
    ("first_seen", "firstseen", pa.timestamp("us")),
    ("last_seen", "lastseen", pa.timestamp("us")),
    ("last_ip", "lastipaddress", pa.string()),
    ("aad_device_id", "aaddeviceid", pa.string()),
]
UNASSIGNED = "Unassigned"   # what Defender's export shows for devices in no device group
_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?)(?:\.(\d+))?([+-]\d{2}:\d{2})?")


def parse_timestamp(value) -> datetime | None:
    """Accept Defender's styles: '2026-09-29 18:53:59', '...T23:56:29.760014Z', 7-digit fractions, offsets."""
    if value in (None, ""):
        return None
    text = str(value).strip().replace("T", " ").replace("Z", "+00:00")
    match = _TIMESTAMP.fullmatch(text)
    if not match:
        raise ValueError(f"Unrecognised timestamp: {value!r}")
    base, fraction, offset = match.groups()
    fraction = f".{fraction[:6].ljust(6, '0')}" if fraction else ""
    parsed = datetime.fromisoformat(f"{base}{fraction}{offset or ''}")
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _convert(value, arrow_type: pa.DataType):
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if pa.types.is_timestamp(arrow_type):
        return parse_timestamp(value)
    if pa.types.is_string(arrow_type):
        return str(value).strip()
    if pa.types.is_floating(arrow_type):
        return float(value)
    if pa.types.is_integer(arrow_type):
        return int(value)
    if pa.types.is_boolean(arrow_type):
        return value if isinstance(value, bool) else str(value).lower() == "true"
    if pa.types.is_list(arrow_type):
        return [str(v) for v in value] if isinstance(value, list) else [str(value)]
    return value


def normalise(records: Iterable[dict], fields: list) -> dict[str, list]:
    columns: dict[str, list] = {name: [] for name, _, _ in fields}
    for record in records:
        lowered = {k.lower(): v for k, v in record.items()}
        for name, source, arrow_type in fields:
            columns[name].append(_convert(lowered.get(source), arrow_type))
    return columns


def keep_newest(columns: dict[str, list]) -> tuple[dict[str, list], int]:
    """One row per record_id: the copy Defender saw last. Its export can list a finding twice, an older copy next to
    the current one (seen when software is removed and detected again), differing only in first/last seen.
    Returns the columns and how many copies were dropped."""
    seen, newest = columns["last_seen"], {}
    for i, record_id in enumerate(columns["record_id"]):
        key = record_id if record_id is not None else ("row", i)
        j = newest.get(key)
        if j is None or (seen[i] or datetime.min) >= (seen[j] or datetime.min):
            newest[key] = i
    dropped = len(columns["record_id"]) - len(newest)
    if not dropped:
        return columns, 0
    keep = sorted(newest.values())
    return {name: [values[i] for i in keep] for name, values in columns.items()}, dropped


def _read_jsonl_gz(paths: Iterable[Path]) -> Iterator[dict]:
    for path in paths:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)


def _write_partition(lake: Path, table_name: str, run_date: date, columns: dict, fields: list) -> int:
    schema = pa.schema([(name, arrow_type) for name, _, arrow_type in fields])
    table = pa.table(columns, schema=schema)
    folder = lake / table_name / f"snapshot_date={run_date.isoformat()}"
    folder.mkdir(parents=True, exist_ok=True)
    tmp = folder / "part-0.parquet.tmp"
    pq.write_table(table, tmp, compression="zstd")
    tmp.replace(folder / "part-0.parquet")
    return table.num_rows


def latest_run_date(settings: Settings) -> date:
    days = sorted(p.name for p in settings.raw_dir.glob("????-??-??") if (p / "manifest.json").is_file())
    if not days:
        raise FileNotFoundError(f"No downloaded runs in {settings.raw_dir}. Run: python -m uc3 extract")
    return date.fromisoformat(days[-1])


def run_load(settings: Settings, run_date: date | None = None) -> dict:
    run_date = run_date or latest_run_date(settings)
    raw = settings.raw_dir / run_date.isoformat()
    if not (raw / "manifest.json").is_file():
        raise FileNotFoundError(f"No completed download for {run_date} in {raw}")
    settings.ensure_dirs()

    vulns = normalise(_read_jsonl_gz(sorted((raw / "vulnerabilities").glob("*.json.gz"))), VULNERABILITY_FIELDS)
    vulns, duplicates_dropped = keep_newest(vulns)
    (raw / "load.json").write_text(json.dumps({"duplicates_dropped": duplicates_dropped}, indent=2))
    devices = normalise(_read_jsonl_gz([raw / "machines.json.gz"]), DEVICE_FIELDS)
    devices["rbac_group_name"] = [g or UNASSIGNED for g in devices["rbac_group_name"]]
    changes_file = raw / "changes.json.gz"
    changes = normalise(_read_jsonl_gz([changes_file] if changes_file.is_file() else []), CHANGE_FIELDS)

    counts = {
        "vulnerability_rows": _write_partition(settings.lake_dir, "vulnerabilities", run_date, vulns, VULNERABILITY_FIELDS),
        "devices": _write_partition(settings.lake_dir, "devices", run_date, devices, DEVICE_FIELDS),
        "change_rows": _write_partition(settings.lake_dir, "changes", run_date, changes, CHANGE_FIELDS),
        "duplicates_dropped": duplicates_dropped,
    }
    return {"run_date": run_date.isoformat(), "counts": counts}
