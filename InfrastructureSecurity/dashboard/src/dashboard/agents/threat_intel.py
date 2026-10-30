"""What the Threat Intel Agent publishes: data/dashboard/dashboard_data.json, site_data.json, clues.json,
threat_matches.json, last_run.json and its reports.

Rules: never write into an agent's folder, never open its live DuckDB database (that would block its runs).
Every reader returns None (or empty) when a file is missing, so one broken agent never breaks the dashboard.
"""

from __future__ import annotations

from pathlib import Path

from dashboard.agents.common import _read_json, mtime_iso


class ThreatIntelSource:
    def __init__(self, root: Path):
        self.root = root
        self.dashboard_dir = root / "data" / "dashboard"

    def dashboard(self) -> dict | None:
        data = _read_json(self.dashboard_dir / "dashboard_data.json")
        return data if isinstance(data, dict) else None

    def last_run(self) -> dict | None:
        return _read_json(self.root / "data" / "last_run.json")

    def clues(self) -> list | None:
        """Every clue (IP, domain, web link, file hash) Threat Intel collected, from its clues.json (the page filters by period)."""
        data = _read_json(self.dashboard_dir / "clues.json")
        return data if isinstance(data, list) else None

    _site_cache: tuple[float, dict] | None = None

    def threat(self, threat_id: str) -> dict | None:
        """One threat's full detail from Threat Intel's site_data.json (1-2 MB, so it is cached until the file changes)."""
        path = self.dashboard_dir / "site_data.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        cache = ThreatIntelSource._site_cache
        if cache is None or cache[0] != mtime:
            data = _read_json(path)
            if not isinstance(data, dict):
                return None
            ThreatIntelSource._site_cache = cache = (mtime, data)
        return cache[1].get(threat_id)

    _matches_cache: tuple[float, dict] | None = None

    def _matches(self) -> dict | None:
        """Threat Intel's threat_matches.json, cached until the file changes."""
        path = self.dashboard_dir / "threat_matches.json"
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        cache = ThreatIntelSource._matches_cache
        if cache is None or cache[0] != mtime:
            data = _read_json(path)
            if not isinstance(data, dict) or not isinstance(data.get("rows"), list):
                return None
            ThreatIntelSource._matches_cache = cache = (mtime, data)
        return cache[1]

    def _early_rows(self, data: dict, first_found: dict[tuple[str, str], str]) -> list:
        """The matches where Threat Intel found the threat no later than the Vulnerability Agent found that CVE on that
        computer (first_found: VulnerabilitySource.first_found()). A later one only repeats Defender's list, so it is not reported."""
        threats = data.get("threats", {})
        def early(r: list) -> bool:
            found, vuln_found = (threats.get(r[4]) or [None, None])[1], first_found.get((r[0], r[3]))
            return not (found and vuln_found and found > vuln_found)
        return [r for r in data["rows"] if early(r)]

    def threat_match_counts(self, first_found: dict[tuple[str, str], str], list_rows: dict[tuple[str, str, str], tuple[int, int]]) -> dict | None:
        """Per app (Defender's software name): how many rows of its vulnerability list (VulnerabilitySource.list_rows: one per computer,
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
