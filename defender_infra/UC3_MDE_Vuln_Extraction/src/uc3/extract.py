"""Extract step: download devices, the full vulnerability export and recent changes into data/raw/<date>/.

A run writes into a temporary folder and only replaces data/raw/<date>/ when everything succeeded, so a
failed run never leaves half a day behind. manifest.json records what was downloaded (files, sizes, row
counts, export time, retries) plus Defender's own row count, which the quality checks compare against.
Security settings and end-of-support software go to posture/ (see posture.py); a problem there never stops the run.
"""

from __future__ import annotations

import gzip
import json
import logging
import shutil
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from uc3.api_client import ApiError, DefenderClient, LinkExpired
from uc3.auth import EntraTokenProvider
from uc3.config import Settings
from uc3.posture import extract_posture

log = logging.getLogger("uc3.extract")

MACHINES = "/api/machines"
EXPORT = "/api/machines/SoftwareVulnerabilitiesExport"
CHANGES = "/api/machines/SoftwareVulnerabilityChangesByMachine"
HUNTING = "/api/advancedqueries/run"
SOURCE_COUNT_QUERY = "DeviceTvmSoftwareVulnerabilities | count"
DELTA_MAX_DAYS = 14
PAGE_SIZE = 200_000
EXPORT_ATTEMPTS = 2           # request a fresh export once if download links expire mid-way


def make_client(settings: Settings, **kwargs) -> DefenderClient:
    return DefenderClient(settings.api_base, EntraTokenProvider(settings), **kwargs)


def _parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def _write_jsonl_gz(path: Path, pages) -> int:
    rows = 0
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for page in pages:
            for record in page:
                fh.write(json.dumps(record) + "\n")
                rows += 1
    return rows


def _state_path(settings: Settings) -> Path:
    return settings.raw_dir / "state.json"


def _load_state(settings: Settings) -> dict:
    path = _state_path(settings)
    return json.loads(path.read_text()) if path.is_file() else {}


def _download_export(client: DefenderClient, folder: Path) -> dict:
    """Request the full export and download every part; retry once with fresh links if they expire."""
    for attempt in range(1, EXPORT_ATTEMPTS + 1):
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
        export = client.get_json(EXPORT, {"sasValidHours": 1})
        files = []
        try:
            for i, url in enumerate(export.get("exportFiles", [])):
                name = f"part-{i:05d}.json.gz"
                size, rows = client.download(url, folder / name)
                files.append({"name": name, "bytes": size, "rows": rows})
        except LinkExpired:
            if attempt == EXPORT_ATTEMPTS:
                raise
            log.warning("Download links expired; requesting a fresh export")
            continue
        return {"generated_time": export.get("generatedTime"), "files": files, "attempts": attempt}
    raise AssertionError("unreachable")


def _source_count(client: DefenderClient) -> dict:
    """Defender's own total of vulnerability rows (a KQL count returns 1 row, so it's never capped)."""
    try:
        results = client.post_json(HUNTING, {"Query": SOURCE_COUNT_QUERY}).get("Results", [])
        return {"source_count": int(results[0]["Count"]) if results else 0,
                "source_counted_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    except (ApiError, KeyError, ValueError) as exc:
        log.warning("Could not get Defender's own row count: %s", exc)
        return {"source_count": None, "source_count_error": str(exc).splitlines()[0]}


def run_extract(settings: Settings, run_date: date | None = None, client: DefenderClient | None = None) -> dict:
    run_date = run_date or datetime.now(timezone.utc).date()
    client = client or make_client(settings)
    settings.ensure_dirs()
    final_dir = settings.raw_dir / run_date.isoformat()
    work_dir = settings.raw_dir / f".{run_date.isoformat()}.inprogress"
    shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True)
    started = time.perf_counter()
    started_at = datetime.now(timezone.utc)

    log.info("Downloading device list")
    machines = _write_jsonl_gz(work_dir / "machines.json.gz", client.iter_pages(MACHINES))

    log.info("Requesting the full vulnerability export")
    export = _download_export(client, work_dir / "vulnerabilities")
    generated = _parse_time(export["generated_time"]) if export["generated_time"] else started_at

    log.info("Asking Defender for its own row count")
    source = _source_count(client)

    log.info("Downloading security settings and end-of-support software")
    posture = extract_posture(client, work_dir)

    state = _load_state(settings)
    since = _parse_time(state["last_generated_time"]) if state.get("last_generated_time") else generated - timedelta(days=1)
    since = max(since, generated - timedelta(days=DELTA_MAX_DAYS) + timedelta(minutes=5))
    log.info("Downloading changes since %s", since.isoformat())
    changes = _write_jsonl_gz(work_dir / "changes.json.gz", client.iter_pages(
        CHANGES, {"sinceTime": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "pageSize": PAGE_SIZE}))

    manifest = {
        "run_date": run_date.isoformat(),
        "api_host": settings.api_base.split("://")[-1].split("/")[0],
        "started_at": started_at.isoformat(timespec="seconds"),
        "duration_seconds": round(time.perf_counter() - started, 1),
        "export_generated_time": export["generated_time"],
        "export_attempts": export["attempts"],
        "retries": client.retries,
        "changes_since": since.isoformat(timespec="seconds"),
        "counts": {
            "machines": machines,
            "vulnerability_rows": sum(f["rows"] for f in export["files"]),
            "change_rows": changes,
        },
        **source,
        "posture": posture,
        "files": export["files"],
    }
    (work_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    shutil.rmtree(final_dir, ignore_errors=True)
    work_dir.rename(final_dir)
    if export["generated_time"]:
        state["last_generated_time"] = export["generated_time"]
        _state_path(settings).write_text(json.dumps(state, indent=2))
    log.info("Extract finished: %s", manifest["counts"])
    return manifest
