"""Read-only access to what UC1, UC3 and UC4 already export.

Rules: never write into a use-case folder, never open their live DuckDB databases (that would block their runs).
UC1 → data/dashboard/dashboard_data.json, site_data.json, clues.json (+ last_run.json); UC3 → data/reporting/*.parquet, ai_fixes, status JSON;
UC4 → data/export/*.json, data/verdicts/<incident>.json, data/feedback/*.jsonl (+ last_run.json).
Every reader returns None (or empty) when a file is missing, so one broken use case never breaks the portal.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def mtime_iso(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    except OSError:
        return None


class UC1:
    def __init__(self, root: Path):
        self.root = root
        self.dashboard_dir = root / "data" / "dashboard"

    def dashboard(self) -> dict | None:
        data = _read_json(self.dashboard_dir / "dashboard_data.json")
        return data if isinstance(data, dict) else None

    def last_run(self) -> dict | None:
        return _read_json(self.root / "data" / "last_run.json")

    def clues(self) -> list | None:
        """Every clue (IP, domain, web link, file hash) UC1 collected, from its clues.json (the page filters by period)."""
        data = _read_json(self.dashboard_dir / "clues.json")
        return data if isinstance(data, list) else None

    _site_cache: tuple[float, dict] | None = None

    def threat(self, threat_id: str) -> dict | None:
        """One threat's full detail from UC1's site_data.json (1-2 MB, so it is cached until the file changes)."""
        path = self.dashboard_dir / "site_data.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        cache = UC1._site_cache
        if cache is None or cache[0] != mtime:
            data = _read_json(path)
            if not isinstance(data, dict):
                return None
            UC1._site_cache = cache = (mtime, data)
        return cache[1].get(threat_id)

    def reports(self) -> list[dict]:
        folder = self.root / "data" / "reports"
        files = sorted(folder.glob("*.*"), key=lambda p: p.stat().st_mtime, reverse=True) if folder.is_dir() else []
        return [{"name": p.name, "size": p.stat().st_size, "modified": mtime_iso(p)}
                for p in files if p.suffix.lower() in (".docx", ".pdf", ".xlsx")
                and not p.name.startswith("UC1_Threat_Hunting_Report")]    # replaced by Threat_Intel / Attack_Detection


class UC3:
    def __init__(self, root: Path):
        self.root = root
        self.reporting = root / "data" / "reporting"

    def table(self, name: str) -> Path:
        return self.reporting / f"{name}.parquet"

    def query(self, sql: str, *tables: str) -> list[dict]:
        """Run SQL over UC3's exported Parquet files with an in-memory DuckDB (never UC3's own database).

        Use {name} placeholders in the SQL for each table; returns [] if any file is missing.
        """
        paths = {t: self.table(t) for t in tables}
        if not all(p.is_file() for p in paths.values()):
            return []
        sql = sql.format(**{t: "read_parquet('" + p.as_posix().replace("'", "''") + "')" for t, p in paths.items()})
        con = duckdb.connect(":memory:")
        try:
            cur = con.execute(sql)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            con.close()

    def status(self) -> dict | None:
        return _read_json(self.root / "data" / "status" / "last_run.json")

    def dashboard(self) -> dict | None:
        """UC3's exported data bundle (data/dashboard/dashboard_data.json), unchanged."""
        data = _read_json(self.root / "data" / "dashboard" / "dashboard_data.json")
        return data if isinstance(data, dict) else None

    def ai_fixes_meta(self) -> dict | None:
        data = _read_json(self.reporting / "ai_fixes.json")
        if not isinstance(data, dict):
            return None
        return {k: data.get(k) for k in ("snapshot", "built_at", "ai_enabled", "model", "counts")}

    def app_names(self) -> dict[str, str]:
        """Friendly app names from UC3's AI Fix Guide ("mozilla:firefox" → "Mozilla Firefox"); {} when absent."""
        data = _read_json(self.reporting / "ai_fixes.json")
        apps = data.get("apps") if isinstance(data, dict) else None
        return {a["key"]: a["app"] for a in apps or [] if isinstance(a, dict) and a.get("key") and a.get("app")}

    def downloads(self) -> list[dict]:
        files = sorted([*self.reporting.glob("UC3_*.*"), *self.reporting.glob("Vulnerability_Report_*.*")], key=lambda p: p.stat().st_mtime, reverse=True) \
            if self.reporting.is_dir() else []
        return [{"name": p.name, "size": p.stat().st_size, "modified": mtime_iso(p)}
                for p in files if p.suffix.lower() in (".xlsx", ".docx", ".pdf", ".md")
                and not p.name.startswith("UC3_Vulnerability_Summary")]    # replaced by Vulnerability_Report_*


def _jsonl(path: Path) -> list[dict]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def uc4_safe_id(incident_id: str) -> str:
    """Same file-name rule as UC4 (uc4.triage._safe): letters, digits, '-' and '_' only."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in str(incident_id))[:80]


class UC4:
    MAX_ROWS = 50          # rows kept per evidence search on the case page

    def __init__(self, root: Path):
        self.root = root
        self.data = root / "data"

    def reports(self) -> list[dict]:
        folder = self.data / "reports"
        files = sorted(folder.glob("Alert_Triage_Report_*.*"), key=lambda p: p.stat().st_mtime, reverse=True)             if folder.is_dir() else []
        return [{"name": p.name, "size": p.stat().st_size, "modified": mtime_iso(p)}
                for p in files if p.suffix.lower() in (".docx", ".pdf")]

    def last_run(self) -> dict | None:
        return _read_json(self.data / "last_run.json")

    def _feedback(self) -> list[dict]:
        return _jsonl(self.data / "feedback" / "feedback.jsonl")

    def queue(self) -> dict | None:
        """The triage queue, with the newest agree/disagree click per incident applied straight away (as UC4's site)."""
        data = _read_json(self.data / "export" / "triage_data.json")
        if not isinstance(data, dict):
            return None
        latest = {r.get("incident_id"): r for r in self._feedback()}
        for row in data.get("queue", []):
            f = latest.get(row.get("incident_id"))
            if f:
                row["feedback"] = {"agree": f.get("agree"), "analyst_verdict": f.get("analyst_verdict")}
        last = self.last_run() or {}
        data["last_run_detail"] = last
        data["automation"] = self.automation(last)
        return data

    @staticmethod
    def automation(last: dict | None) -> dict:
        """What UC4 is switched to do by itself, read from the steps its last run performed (UC4's .env is never read)."""
        steps = (last or {}).get("steps") or {}
        return {"auto_resolve": "auto_resolve" in steps, "writeback": "writeback" in steps, "known": bool(steps)}

    def case(self, incident_id: str) -> dict | None:
        data = _read_json(self.data / "verdicts" / f"{uc4_safe_id(incident_id)}.json")
        if not isinstance(data, dict) or "packet" not in data:
            return None
        real_id = data["packet"].get("incident_id")
        for q in data.get("queries") or []:
            rows = q.get("rows") or []
            q["rows_total"] = len(rows)
            q["rows"] = rows[: self.MAX_ROWS]
        data["feedback"] = [r for r in self._feedback() if r.get("incident_id") == real_id]
        data["actions"] = [r for r in _jsonl(self.data / "feedback" / "actions.jsonl") if r.get("incident_id") == real_id]
        data["questions"] = [r for r in _jsonl(self.data / "feedback" / "ask.jsonl") if r.get("incident_id") == real_id]
        data["automation"] = self.automation(self.last_run())
        return data

    def metrics(self) -> dict | None:
        return _read_json(self.data / "export" / "metrics.json")

    def backtest(self) -> dict | None:
        return _read_json(self.data / "export" / "backtest.json")
