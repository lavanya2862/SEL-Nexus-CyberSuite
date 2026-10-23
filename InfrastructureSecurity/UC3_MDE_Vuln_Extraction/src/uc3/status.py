"""Status of the latest run (data/status/last_run.json), shown as an alert on the dashboard when a run failed.

status: OK (all checks passed) · WARN (published with warnings) · FAIL (a quality check failed, nothing
published) · ERROR (the run stopped, e.g. Defender unreachable or login expired).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from uc3.config import Settings


def status_path(settings: Settings):
    return settings.data_dir / "status" / "last_run.json"


def write_status(settings: Settings, status: str, message: str, run_date: str | None = None) -> dict:
    record = {"status": status, "message": message, "run_date": run_date,
              "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    path = status_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2))
    return record


def read_status(settings: Settings) -> dict | None:
    path = status_path(settings)
    return json.loads(path.read_text()) if path.is_file() else None
