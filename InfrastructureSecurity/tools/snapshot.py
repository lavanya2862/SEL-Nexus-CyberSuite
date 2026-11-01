r"""Share the agents' data between team members: one person exports a snapshot, the others import it.

    python tools\snapshot.py export                  snapshots\infra_<time>_<user>.zip
    python tools\snapshot.py export --logs           ... with each agent's logs
    python tools\snapshot.py import <file.zip>       replaces this computer's data (the old data is kept aside)
    python tools\snapshot.py show <file.zip>         what a snapshot holds, without importing it

Run it from the InfrastructureSecurity folder with any Python 3.11+ (only the standard library is used), with
Infrastructure Security STOPPED (Stop_Infrastructure_Security.cmd): the databases must not be open while copying.

A snapshot holds every agent's data folder and the dashboard's run history. It never holds secrets (.env, sign-in
accounts and session keys stay out) or what each computer rebuilds by itself (feed caches, lock files). The GUIDE
backtest database (about 400 MB, rebuilt from Kaggle) is left out unless --with-guide is given.

Snapshots contain device names, accounts, IP addresses and Defender evidence from the tenant: share them only
through the team's private storage (Teams/SharePoint, OneDrive), never through git (snapshots/ is ignored).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]                  # InfrastructureSecurity/
PARTS = {                                                   # snapshot name -> folder (relative to ROOT)
    "threat_intel": "agents/threat_intel",
    "vulnerability": "agents/vulnerability",
    "attack_detection": "agents/attack_detection",
    "alert_triage": "agents/alert_triage",
    "dashboard": "dashboard",
}
PORTS = (8800, 8700, 8900, 8000)                            # dashboard, fix engine, alert triage, sign-in
SKIP_DIRS = {"cache", "auth", "__pycache__"}                # rebuilt per computer, or secrets
SKIP_SUFFIXES = (".lock", ".tmp", ".key", ".wal")
SKIP_NAMES = {"guide.duckdb"}                               # unless --with-guide
FORMAT = 1


def running() -> list[int]:
    busy = []
    for port in PORTS:
        with socket.socket() as s:
            s.settimeout(0.3)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                busy.append(port)
    return busy


def refuse_if_running() -> None:
    busy = running()
    if busy:
        sys.exit(f"Infrastructure Security is running (ports {', '.join(map(str, busy))}). "
                 "Stop it first with Stop_Infrastructure_Security.cmd, then try again.")


def wanted(path: Path, with_guide: bool) -> bool:
    if any(part in SKIP_DIRS for part in path.parts) or path.suffix.lower() in SKIP_SUFFIXES:
        return False
    return with_guide or path.name not in SKIP_NAMES


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              timeout=10).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def export(logs: bool, with_guide: bool, out: Path | None) -> Path:
    refuse_if_running()
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    user = getpass.getuser().replace(" ", "_")
    target = out or ROOT / "snapshots" / f"infra_{stamp}_{user}.zip"
    target.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"format": FORMAT, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "created_by": user, "computer": platform.node(), "git_commit": git_commit(), "logs": logs,
                "guide": with_guide, "parts": {}}
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name, folder in PARTS.items():
            files = 0
            for sub in ("data", "logs") if logs else ("data",):
                base = ROOT / folder / sub
                if not base.is_dir():
                    continue
                for f in sorted(p for p in base.rglob("*") if p.is_file()):
                    rel = f.relative_to(base)
                    if wanted(rel, with_guide):
                        z.write(f, f"{name}/{sub}/{rel.as_posix()}")
                        files += 1
            last = next((x for x in (ROOT / folder / "data" / "last_run.json", ROOT / folder / "data" / "status" / "last_run.json")
                         if x.is_file()), ROOT / folder / "data" / "last_run.json")
            manifest["parts"][name] = {"files": files,
                                       "last_run": json.loads(last.read_text(encoding="utf-8")).get("finished_at")
                                       if last.is_file() else None}
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
    print(f"Snapshot written: {target} ({target.stat().st_size / 1e6:.1f} MB)")
    for name, info in manifest["parts"].items():
        print(f"  {name:17s} {info['files']:5d} files   last run {info['last_run'] or '-'}")
    print("Share it through the team's private storage only (it holds tenant data), never through git.")
    return target


def read_manifest(z: zipfile.ZipFile) -> dict:
    try:
        manifest = json.loads(z.read("manifest.json"))
    except KeyError:
        sys.exit("Not an Infrastructure Security snapshot (no manifest.json).")
    if manifest.get("format") != FORMAT:
        sys.exit(f"Snapshot format {manifest.get('format')} is not supported by this version (expected {FORMAT}).")
    return manifest


def show(path: Path) -> None:
    with zipfile.ZipFile(path) as z:
        m = read_manifest(z)
    print(f"Snapshot {path.name}: made {m['created_at']} by {m['created_by']} on {m['computer']} (code {m['git_commit']})")
    for name, info in m["parts"].items():
        print(f"  {name:17s} {info['files']:5d} files   last run {info['last_run'] or '-'}")
    if m["git_commit"] not in ("unknown", git_commit()):
        print(f"Note: your code is at {git_commit()}; run git pull first if the snapshot is newer.")


def import_(path: Path) -> None:
    refuse_if_running()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with zipfile.ZipFile(path) as z:
        m = read_manifest(z)
        names = [n for n in z.namelist() if n != "manifest.json"]
        for n in names:                                           # no absolute paths or ".." in a snapshot
            parts = Path(n).parts
            if Path(n).is_absolute() or ".." in parts or parts[0] not in PARTS or parts[1] not in ("data", "logs"):
                sys.exit(f"Refusing a snapshot with an unexpected path: {n}")
        show(path)
        for name, folder in PARTS.items():
            for sub in ("data", "logs"):
                members = [n for n in names if n.startswith(f"{name}/{sub}/")]
                if not members:
                    continue
                dest = ROOT / folder / sub
                if dest.exists():                                  # kept aside, never deleted
                    aside = dest.with_name(f"{sub}.before-import-{stamp}")
                    dest.rename(aside)
                    for keep in SKIP_DIRS - {"__pycache__"}:       # this computer's caches and sign-in data stay
                        if (aside / keep).is_dir():
                            shutil.copytree(aside / keep, dest / keep)
                dest.mkdir(parents=True, exist_ok=True)
                for n in members:
                    target = dest / Path(n).relative_to(f"{name}/{sub}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(n) as src, open(target, "wb") as out:
                        shutil.copyfileobj(src, out)
    print(f"Imported. The previous data is kept next to each folder as data.before-import-{stamp} (delete it when "
          "you no longer need it). Start Infrastructure Security again.")


def main() -> int:
    parser = argparse.ArgumentParser(prog="python tools\\snapshot.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    e = sub.add_parser("export", help="write a snapshot of this computer's data")
    e.add_argument("--logs", action="store_true", help="include each agent's logs")
    e.add_argument("--with-guide", action="store_true", help="include the GUIDE backtest database (about 400 MB)")
    e.add_argument("--out", type=Path, help="where to write the .zip (default: snapshots\\)")
    for name in ("import", "show"):
        sub.add_parser(name).add_argument("file", type=Path)
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.command == "export":
        export(args.logs, args.with_guide, args.out)
    elif args.command == "show":
        show(args.file)
    else:
        import_(args.file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
