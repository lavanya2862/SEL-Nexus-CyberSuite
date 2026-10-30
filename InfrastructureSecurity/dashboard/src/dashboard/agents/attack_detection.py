"""What the Attack Detection Agent publishes for people: its reports and its last run.

Its signs of attack reach the dashboard through the Threat Intel Agent, which imports them after every Attack
Detection run (they appear in threat_intel/data/dashboard/*.json with the threats they belong to).

Rules: never write into an agent's folder, never open its live DuckDB database (that would block its runs).
Every reader returns None (or empty) when a file is missing, so one broken agent never breaks the dashboard.
"""

from __future__ import annotations

from pathlib import Path

from dashboard.agents.common import _read_json, mtime_iso


class AttackDetectionSource:
    def __init__(self, root: Path):
        self.root = root
        self.data = root / "data"

    def reports(self) -> list[dict]:
        folder = self.data / "reports"
        files = sorted(folder.glob("Attack_Detection_Report_*.*"), key=lambda p: p.stat().st_mtime, reverse=True) \
            if folder.is_dir() else []
        return [{"name": p.name, "size": p.stat().st_size, "modified": mtime_iso(p)}
                for p in files if p.suffix.lower() in (".docx", ".pdf")]

    def last_run(self) -> dict | None:
        return _read_json(self.data / "last_run.json")
