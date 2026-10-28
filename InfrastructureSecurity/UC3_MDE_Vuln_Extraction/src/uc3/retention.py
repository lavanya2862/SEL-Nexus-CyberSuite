"""Retention: remove old files so the disk doesn't fill up. Runs at the end of every successful daily run.

  data/raw/<date>/                     kept 90 days (the original downloads)
  data/lake/vulnerabilities|devices    daily snapshots kept 90 days, after that only Sundays (weekly history)
  data/lake/changes                    kept 365 days (small)
  data/reporting/*_<date>.xlsx         kept 30 days
  logs/uc3_<date>.log                  kept 90 days
"""

from __future__ import annotations

import re
import shutil
from datetime import date, datetime, timezone
from pathlib import Path

from uc3.config import Settings

RAW_KEEP_DAYS = 90
SNAPSHOT_DAILY_DAYS = 90
CHANGES_KEEP_DAYS = 365
REPORT_FILE_KEEP_DAYS = 30
LOG_KEEP_DAYS = 90
_DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _age(name: str, today: date) -> tuple[int, date] | None:
    match = _DATE.search(name)
    if not match:
        return None
    day = date.fromisoformat(match[1])
    return (today - day).days, day


def _remove(path: Path) -> None:
    shutil.rmtree(path) if path.is_dir() else path.unlink()


def apply_retention(settings: Settings, today: date | None = None) -> dict:
    today = today or datetime.now(timezone.utc).date()
    removed = {"raw_days": 0, "snapshots": 0, "change_partitions": 0, "report_files": 0, "logs": 0}

    def sweep(paths, key, keep_if):
        for path in paths:
            info = _age(path.name, today)
            if info and not keep_if(*info):
                _remove(path)
                removed[key] += 1

    sweep(settings.raw_dir.glob("????-??-??"), "raw_days", lambda age, day: age <= RAW_KEEP_DAYS)
    for table in ("vulnerabilities", "devices"):
        sweep((settings.lake_dir / table).glob("snapshot_date=*"), "snapshots",
              lambda age, day: age <= SNAPSHOT_DAILY_DAYS or day.weekday() == 6)
    sweep((settings.lake_dir / "changes").glob("snapshot_date=*"), "change_partitions",
          lambda age, day: age <= CHANGES_KEEP_DAYS)
    sweep(settings.reporting_dir.glob("*_????-??-??.xlsx"),
          "report_files", lambda age, day: age <= REPORT_FILE_KEEP_DAYS)
    sweep(settings.log_dir.glob("uc3_????-??-??.log"), "logs", lambda age, day: age <= LOG_KEEP_DAYS)
    return removed
