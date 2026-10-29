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

    _matches_cache: tuple[float, dict] | None = None

    def _matches(self) -> dict | None:
        """UC1's threat_matches.json, cached until the file changes."""
        path = self.dashboard_dir / "threat_matches.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        cache = UC1._matches_cache
        if cache is None or cache[0] != mtime:
            data = _read_json(path)
            if not isinstance(data, dict) or not isinstance(data.get("rows"), list):
                return None
            UC1._matches_cache = cache = (mtime, data)
        return cache[1]

    def _early_rows(self, data: dict, first_found: dict[tuple[str, str], str]) -> list:
        """The matches where Threat Intel found the threat no later than the Vulnerability Agent found that CVE on that
        computer (first_found: UC3.first_found()). A later one only repeats Defender's list, so it is not reported."""
        threats = data.get("threats", {})
        def early(r: list) -> bool:
            found, vuln_found = (threats.get(r[4]) or [None, None])[1], first_found.get((r[0], r[3]))
            return not (found and vuln_found and found > vuln_found)
        return [r for r in data["rows"] if early(r)]

    def threat_match_counts(self, first_found: dict[tuple[str, str], str], list_rows: dict[tuple[str, str, str], tuple[int, int]]) -> dict | None:
        """Per app (Defender's software name): how many rows of its vulnerability list (UC3.list_rows: one per computer,
        version and CVE) a threat in the news names, so the card and the list show the same number;
        split: {app: [still open, fixed]}; vm_cves: {"computer|app|version" (lower case): [CVE, …]} for the Remediation
        page's per-computer cards (it keeps the ones still open)."""
        data = self._matches()
        if data is None:
            return None
        pairs: dict[str, set] = {}
        vm_cves: dict[str, set] = {}
        for r in self._early_rows(data, first_found):
            pairs.setdefault(r[1], set()).add((r[0], r[3]))
            vm_cves.setdefault(f"{r[0]}|{r[1]}|{r[2]}".lower(), set()).add(r[3])
        split: dict[str, list[int]] = {}
        for sw, p in pairs.items():
            o = f = 0
            for k in p:
                ro, rf = list_rows.get((sw, *k), (0, 0)) if list_rows else (1, 0)
                o, f = o + ro, f + rf
            if o + f:
                split[sw] = [o, f]
        return {"built_at": data.get("built_at"), "counts": {sw: o + f for sw, (o, f) in split.items()}, "split": split,
                "vm_cves": {k: sorted(v) for k, v in vm_cves.items()}}

    def threat_matches(self, software: str, first_found: dict[tuple[str, str], str]) -> dict | None:
        """One app's vulnerabilities that a threat in the news names:
        {built_at, rows: [{device, version, cve, threat}], threats: {id: {title, found, published, score}}}."""
        data = self._matches()
        if data is None:
            return None
        rows = [{"device": r[0], "version": r[2], "cve": r[3], "threat": r[4]} for r in self._early_rows(data, first_found) if r[1] == software]
        threats = {}
        for r in rows:
            t = data.get("threats", {}).get(r["threat"]) or [r["threat"], None, None, 0]
            threats[r["threat"]] = {"title": t[0], "found": t[1], "published": t[2], "score": t[3]}
        return {"built_at": data.get("built_at"), "rows": rows, "threats": threats}

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

    _index_cache: tuple[float, dict] | None = None

    def _index(self) -> dict:
        """first: {(computer, CVE): 'YYYY-MM-DD'} the earliest Defender first-seen date of its open and fixed findings;
        rows: {(app, computer, CVE): (open, fixed)} the rows the portal's vulnerability list shows for it: one per open
        version, else one fixed row (open 0, fixed 1). Cached until the file changes; empty when absent."""
        path = self.root / "data" / "dashboard" / "dashboard_data.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return {"first": {}, "rows": {}}
        cache = UC3._index_cache
        if cache is None or cache[0] != mtime:
            data = self.dashboard() or {}
            names = [(d.get("name") or "").split(".")[0].lower() for d in data.get("devices") or []]
            first: dict[tuple[str, str], str] = {}
            rows: dict[tuple[str, str, str], tuple[int, int]] = {}
            for key in ("f", "fixed"):
                t = data.get(key) or {}
                cols = t.get("cols") or []
                if not {"d", "sw", "cve", "fs"} <= set(cols):
                    continue
                d, sw, cve, fs = (cols.index(c) for c in ("d", "sw", "cve", "fs"))
                for r in t.get("rows") or []:
                    if not (isinstance(r[d], int) and r[d] < len(names)):
                        continue
                    k = (names[r[d]], r[cve])
                    day = str(r[fs] or "")[:10]
                    if day and (k not in first or day < first[k]):
                        first[k] = day
                    rk = (r[sw], *k)
                    if key == "f":
                        rows[rk] = (rows.get(rk, (0, 0))[0] + 1, 0)
                    else:
                        rows.setdefault(rk, (0, 1))  # fixed everywhere: one row (f comes first, so open rows win)
            UC3._index_cache = cache = (mtime, {"first": first, "rows": rows})
        return cache[1]

    def first_found(self) -> dict[tuple[str, str], str]:
        """When the Vulnerability Agent first found each CVE on each computer: {(computer, CVE): 'YYYY-MM-DD'}."""
        return self._index()["first"]

    def list_rows(self) -> dict[tuple[str, str, str], tuple[int, int]]:
        """The vulnerability list's rows per (app, computer, CVE): (open rows, fixed rows)."""
        return self._index()["rows"]

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
                for p in files if p.suffix.lower() in (".xlsx", ".docx", ".pdf")
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


# Defender's classification of an incident -> the triage outcome (informational, expected activity is harmless)
UC4_DEFENDER_OUTCOME = {"truePositive": "likely_true_positive", "falsePositive": "likely_false_positive",
                        "informationalExpectedActivity": "likely_false_positive"}
UC4_PERSON_ACTIONS = ("close_incident", "escalate_incident", "reopen")


def _stamp(t) -> str:
    """'2026-10-29 06:47:42Z' and '2026-10-29T06:47:42Z' compare as text once written the same way."""
    return str(t or "").replace(" ", "T")


def uc4_person_action(actions: list[dict]) -> dict | None:
    """The newest decision a person wrote into Defender through CyberSuite (UC4 close.act or reopen)."""
    for a in reversed(actions):
        if a.get("status") == "done" and a.get("action") in UC4_PERSON_ACTIONS:
            return a
    return None


def uc4_decision(state: dict, action: dict | None, synced_at) -> dict | None:
    """The final classification once one is made, and whether Defender has the incident open or closed.

    An analyst's decision made in CyberSuite (written into Defender by UC4: false positive -> resolved, true positive
    -> in progress) wins while Defender still holds it, or while it is newer than the last check of Defender.
    Otherwise Defender's own classification counts (set by an analyst there, or by the agent's automatic
    close / escalate). None while nobody has classified the incident."""
    status, classification = state.get("status"), state.get("classification")
    if action:
        fresh = _stamp(action.get("done_at")) > _stamp(synced_at)
        if action["action"] == "reopen":
            if fresh:
                return None
        else:
            head, _, who = str(action.get("detail") or "").partition(" by ")
            parts = [x.strip() for x in head.split(" / ")]
            a_status = parts[0] if len(parts) == 3 else ("resolved" if action["action"] == "close_incident" else "inProgress")
            a_class = parts[1] if len(parts) == 3 else ("falsePositive" if action["action"] == "close_incident" else "truePositive")
            if fresh or classification == a_class:
                return {"outcome": UC4_DEFENDER_OUTCOME.get(a_class, "likely_true_positive"), "by": "analyst",
                        "who": who.strip(), "at": action.get("done_at"), "classification": a_class,
                        "determination": parts[2] if len(parts) == 3 else None,
                        "status": a_status if fresh else status}
    if classification in UC4_DEFENDER_OUTCOME:
        return {"outcome": UC4_DEFENDER_OUTCOME[classification], "by": "defender", "classification": classification,
                "determination": state.get("determination"), "status": status}
    return None


def uc4_outcome(verdict: str | None, decision: dict | None) -> str | None:
    """What the queue shows: the decision when there is one, else the agent's verdict (older benign = false positive)."""
    if decision:
        return decision["outcome"]
    return "likely_false_positive" if verdict == "benign_positive" else verdict


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
        """The triage queue, with the newest agree/disagree click per incident applied straight away (as UC4's site),
        and each incident's final outcome and Defender status: an analyst's decision (made here or in Defender) wins
        over the agent's verdict."""
        data = _read_json(self.data / "export" / "triage_data.json")
        if not isinstance(data, dict):
            return None
        latest = {r.get("incident_id"): r for r in self._feedback()}
        acts: dict[str, list[dict]] = {}
        for a in _jsonl(self.data / "feedback" / "actions.jsonl"):
            acts.setdefault(a.get("incident_id"), []).append(a)
        by_outcome: dict[str, int] = {}
        for row in data.get("queue", []):
            f = latest.get(row.get("incident_id"))
            if f:
                row["feedback"] = {"agree": f.get("agree"), "analyst_verdict": f.get("analyst_verdict")}
            row["decision"] = uc4_decision(row, uc4_person_action(acts.get(row.get("incident_id"), [])),
                                           data.get("generated_at"))
            if row["decision"] and row["decision"].get("status"):
                row["status"] = row["decision"]["status"]       # a decision just written: Defender has it already
            row["outcome"] = uc4_outcome(row.get("verdict"), row["decision"])
            by_outcome[row["outcome"]] = by_outcome.get(row["outcome"], 0) + 1
        data["by_outcome"] = by_outcome
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
        # Defender's current status and classification (the saved packet holds them as they were at triage time)
        export = _read_json(self.data / "export" / "triage_data.json")
        row = next((r for r in (export or {}).get("queue", []) if r.get("incident_id") == real_id), {}) \
            if isinstance(export, dict) else {}
        data["defender_state"] = {k: row.get(k) or data["packet"].get(k) for k in ("status", "classification", "determination")}
        verdict = (data.get("verdict") or {}).get("verdict")
        data["decision"] = uc4_decision(data["defender_state"], uc4_person_action(data["actions"]),
                                        export.get("generated_at") if isinstance(export, dict) else None)
        if data["decision"] and data["decision"].get("status"):
            data["defender_state"]["status"] = data["decision"]["status"]
        data["outcome"] = uc4_outcome(verdict, data["decision"])
        return data

    def metrics(self) -> dict | None:
        return _read_json(self.data / "export" / "metrics.json")

    def backtest(self) -> dict | None:
        return _read_json(self.data / "export" / "backtest.json")
