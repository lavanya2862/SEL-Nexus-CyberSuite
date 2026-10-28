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

from uc3.api_client import ApiError, DefenderClient, EmptyDownload, LinkExpired
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
EXPORT_ATTEMPTS = 2           # request a fresh export once if download links expire or a file comes back empty


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


def _count_changes(path: Path) -> dict:
    """Defender's change list by kind: {"new": n, "fixed": n, "updated": n} (its statuses New / Fixed / Updated)."""
    counts = {"new": 0, "fixed": 0, "updated": 0}
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            status = str(json.loads(line).get("status") or "").lower()
            if status in counts:
                counts[status] += 1
    return counts


def _last_rows(settings: Settings) -> int | None:
    """Rows in the last finished download (its manifest), for state files written before we kept the number."""
    manifests = sorted(settings.raw_dir.glob("????-??-??/manifest.json"))
    return json.loads(manifests[-1].read_text())["counts"].get("vulnerability_rows") if manifests else None


def _state_path(settings: Settings) -> Path:
    return settings.raw_dir / "state.json"


def _load_state(settings: Settings) -> dict:
    path = _state_path(settings)
    return json.loads(path.read_text()) if path.is_file() else {}


def _previous_export(settings: Settings, generated_time: str | None) -> tuple[Path, list] | None:
    """The newest finished download of this same Defender export (same generatedTime) with all its files on disk.

    Empty (0-byte) files are never reused, so one bad download can't be copied into every later run.
    """
    if not generated_time:
        return None
    for manifest_path in sorted(settings.raw_dir.glob("????-??-??/manifest.json"), reverse=True):
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, ValueError):
            continue
        if manifest.get("export_generated_time") != generated_time:
            continue
        folder = manifest_path.parent / "vulnerabilities"
        files = manifest.get("files") or []
        if files and all(f["bytes"] > 0 and (folder / f["name"]).is_file()
                         and (folder / f["name"]).stat().st_size == f["bytes"] for f in files):
            return folder, files
    return None


def _download_export(client: DefenderClient, folder: Path, settings: Settings) -> dict:
    """Request the full export and download every part; retry once with fresh links if they expire.

    Defender rebuilds the export only a few times a day. When it hands back the same export (same generatedTime) as
    a finished earlier run, that run's files are copied instead of downloaded again.
    """
    for attempt in range(1, EXPORT_ATTEMPTS + 1):
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
        export = client.get_json(EXPORT, {"sasValidHours": 1})
        previous = _previous_export(settings, export.get("generatedTime"))
        if previous:
            source, files = previous
            for f in files:
                shutil.copy2(source / f["name"], folder / f["name"])
            log.info("Defender has not made a new export since %s; reusing the files from %s",
                     export["generatedTime"], source.parent.name)
            return {"generated_time": export["generatedTime"], "files": files, "attempts": attempt,
                    "reused_from": source.parent.name}
        files = []
        try:
            for i, url in enumerate(export.get("exportFiles", [])):
                name = f"part-{i:05d}.json.gz"
                size, rows = client.download(url, folder / name)
                files.append({"name": name, "bytes": size, "rows": rows})
        except (LinkExpired, EmptyDownload) as exc:
            if attempt == EXPORT_ATTEMPTS:
                raise
            log.warning("%s; requesting a fresh export",
                        "Download links expired" if isinstance(exc, LinkExpired) else "A downloaded file was empty")
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
    export = _download_export(client, work_dir / "vulnerabilities", settings)
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
    # What Defender itself changed since the last run (its own change list), and whether it made a new full export
    # at all: Defender rebuilds the export a few times a day, so a run soon after the last one gets the same data.
    by_kind = _count_changes(work_dir / "changes.json.gz")
    rows = sum(f["rows"] for f in export["files"])
    refreshed = not export["generated_time"] or export["generated_time"] != state.get("last_generated_time")
    log.info("Defender changes since the last run: %d new, %d fixed, %d updated%s", by_kind["new"], by_kind["fixed"],
             by_kind["updated"], "" if refreshed else " (Defender has not made a new export since the last run)")

    manifest = {
        "run_date": run_date.isoformat(),
        "api_host": settings.api_base.split("://")[-1].split("/")[0],
        "started_at": started_at.isoformat(timespec="seconds"),
        "duration_seconds": round(time.perf_counter() - started, 1),
        "export_generated_time": export["generated_time"],
        "export_attempts": export["attempts"],
        "export_reused_from": export.get("reused_from"),        # earlier run whose files were copied, if any
        "retries": client.retries,
        "changes_since": since.isoformat(timespec="seconds"),
        "counts": {
            "machines": machines,
            "vulnerability_rows": rows,
            "change_rows": changes,
            **by_kind,                                                   # new / fixed / updated, as Defender reports them
            "previous_rows": state.get("last_vulnerability_rows") or _last_rows(settings),   # the last run's full download
            "defender_refreshed": refreshed,
            "export_reused": bool(export.get("reused_from")),          # files copied from an earlier run, not downloaded
        },
        "previous_export_time": state.get("last_generated_time"),
        **source,
        "posture": posture,
        "files": export["files"],
    }
    (work_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    shutil.rmtree(final_dir, ignore_errors=True)
    work_dir.rename(final_dir)
    if export["generated_time"]:
        state["last_generated_time"] = export["generated_time"]
        state["last_vulnerability_rows"] = rows
        _state_path(settings).write_text(json.dumps(state, indent=2))
    log.info("Extract finished: %s", manifest["counts"])
    return manifest
