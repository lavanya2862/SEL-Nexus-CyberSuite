"""Where each part of Infrastructure Security lives, and how to rebuild its dashboard data offline.

The restructure (docs/ARCHITECTURE.md, phases 1 to 3) moves folders and renames packages. Only this table changes
when that happens; the tests that use it stay the same, so they prove the move changed nothing.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]           # InfrastructureSecurity/

# part -> folder, Python package, and the venv that runs it
PARTS = {
    "threat_intel": {"dir": "agents/threat_intel", "package": "threat_intel"},
    "vulnerability": {"dir": "agents/vulnerability", "package": "vulnerability"},
    "alert_triage": {"dir": "agents/alert_triage", "package": "alert_triage"},
    "dashboard": {"dir": "dashboard", "package": "dashboard"},
}

# How each agent rebuilds the data the dashboard shows, from a COPY of its database (never the live one).
# copy: files or folders under the agent's data/ copied into a temporary data folder
# env: points the agent at that temporary folder; run: arguments after `python`; outputs: files it must write there
REBUILDS = {
    "threat_intel": {
        "copy": ["threat_intel.duckdb"],
        "env": {"THREAT_INTEL_DATA_DIR": "{data}"},
        "run": ["-m", "threat_intel", "dashboard"],
        "outputs": ["dashboard/dashboard_data.json", "dashboard/site_data.json", "dashboard/clues.json",
                    "dashboard/threat_matches.json"],
    },
    "vulnerability": {
        "copy": ["reporting", "status", "reference", "ai", "raw"],
        "env": {"VULN_DATA_DIR": "{data}"},
        "run": ["-c", "from vulnerability.config import load_settings; from vulnerability.dashboard.build import build_dashboard; "
                      "build_dashboard(load_settings(require_credentials=False))"],
        "outputs": ["dashboard/dashboard_data.json"],
    },
    "alert_triage": {
        "copy": ["alert_triage.duckdb"],
        "env": {"TRIAGE_DATA_DIR": "{data}"},
        "run": ["-c", "from alert_triage.config import load_settings; from alert_triage.store import Store; "
                      "from alert_triage.export import export_all; "
                      "s = load_settings(); export_all(Store(s.db_path), s)"],
        "outputs": ["export/triage_data.json"],
    },
}

# The dashboard's read-only API: a stable name per endpoint -> its path. {threat}, {software} and {incident} are filled
# in from the first item of an earlier answer.
API = {
    "summary": "/api/summary",
    "device_names": "/api/device-names",
    "vulnerability.dashboard": "/api/vulnerability/dashboard",
    "threat_intel.dashboard": "/api/threat-intel/dashboard",
    "threat_intel.clues": "/api/threat-intel/clues",
    "threat_intel.matches": "/api/threat-intel/matches",
    "threat_intel.matches_one": "/api/threat-intel/matches/{software}",
    "threat_intel.threat": "/api/threat-intel/threats/{threat}",
    "alert_triage.queue": "/api/alert-triage/queue",
    "alert_triage.case": "/api/alert-triage/cases/{incident}",
    "alert_triage.quality": "/api/alert-triage/quality",
    "reports": "/api/reports",
    "runs": "/api/runs",
    "runs.history": "/api/runs/history",
    "activity": "/api/activity",
    "notifications": "/api/notifications",
    "help.ready": "/api/help/ready?screen=home&path=/",
}


def part_dir(part: str) -> Path:
    return ROOT / PARTS[part]["dir"]


def python(part: str) -> Path:
    return part_dir(part) / ".venv" / "Scripts" / "python.exe"
