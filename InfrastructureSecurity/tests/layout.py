"""Where each part of Infrastructure Security lives, and how to rebuild its dashboard data offline.

The restructure (docs/ARCHITECTURE.md, phases 1 to 3) moves folders and renames packages. Only this table changes
when that happens; the tests that use it stay the same, so they prove the move changed nothing.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]           # InfrastructureSecurity/

# part -> folder, Python package, and the venv that runs it
PARTS = {
    "threat_intel": {"dir": "UC1_Threat_Intel_Hunting_Agent", "package": "uc1"},
    "vulnerability": {"dir": "UC3_MDE_Vuln_Extraction", "package": "uc3"},
    "alert_triage": {"dir": "UC4_Alert_Triage_Agent", "package": "uc4"},
    "dashboard": {"dir": "Unified_Cyber_Portal", "package": "portal"},
}

# How each agent rebuilds the data the dashboard shows, from a COPY of its database (never the live one).
# copy: files or folders under the agent's data/ copied into a temporary data folder
# env: points the agent at that temporary folder; run: arguments after `python`; outputs: files it must write there
REBUILDS = {
    "threat_intel": {
        "copy": ["uc1.duckdb"],
        "env": {"UC1_DATA_DIR": "{data}"},
        "run": ["-m", "uc1", "dashboard"],
        "outputs": ["dashboard/dashboard_data.json", "dashboard/site_data.json", "dashboard/clues.json",
                    "dashboard/threat_matches.json"],
    },
    "vulnerability": {
        "copy": ["reporting", "status", "reference", "ai", "raw"],
        "env": {"UC3_DATA_DIR": "{data}"},
        "run": ["-c", "from uc3.config import load_settings; from uc3.dashboard.build import build_dashboard; "
                      "build_dashboard(load_settings(require_credentials=False))"],
        "outputs": ["dashboard/dashboard_data.json"],
    },
    "alert_triage": {
        "copy": ["uc4.duckdb"],
        "env": {"UC4_DATA_DIR": "{data}"},
        "run": ["-c", "from uc4.config import load_settings; from uc4.store import Store; from uc4.export import export_all; "
                      "s = load_settings(); export_all(Store(s.db_path), s)"],
        "outputs": ["export/triage_data.json"],
    },
}

# The dashboard's read-only API: a stable name per endpoint -> its path. {threat}, {software} and {incident} are filled
# in from the first item of an earlier answer.
API = {
    "summary": "/api/summary",
    "device_names": "/api/device-names",
    "vulnerability.dashboard": "/api/uc3/dashboard",
    "threat_intel.dashboard": "/api/uc1/dashboard",
    "threat_intel.clues": "/api/uc1/clues",
    "threat_intel.matches": "/api/uc1/matches",
    "threat_intel.matches_one": "/api/uc1/matches/{software}",
    "threat_intel.threat": "/api/uc1/threats/{threat}",
    "alert_triage.queue": "/api/uc4/queue",
    "alert_triage.case": "/api/uc4/cases/{incident}",
    "alert_triage.quality": "/api/uc4/quality",
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
