"""What the Attack Detection Agent publishes for people: its reports and its last run.

Its findings, hunts and devices come from its own data/out/findings.json; nothing goes through the Threat Intel Agent.

Rules: never write into an agent's folder, never open its live DuckDB database (that would block its runs).
Every reader returns None (or empty) when a file is missing, so one broken agent never breaks the dashboard.
"""

from __future__ import annotations

import json
from pathlib import Path

from dashboard.agents.common import _read_json, mtime_iso


def _json(value) -> list:
    """findings.json keeps users, alerts, timeline and steps as JSON text or as lists."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return value if isinstance(value, list) else []


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

    def page(self) -> dict | None:
        """The Attack detection page: every finding (with its resolution and trimmed users/alerts/timeline), the
        latest run's hunts and the devices Defender listed."""
        out = _read_json(self.data / "out" / "findings.json")
        if not out or out.get("schema_version") != 1:
            return None
        res = {r["finding_id"]: r for r in out.get("resolutions") or []}
        titles = {t["threat_id"]: t.get("title") or "" for t in out.get("threats") or []}
        hits = []
        for f in out.get("findings") or []:
            r = res.get(f["finding_id"])
            hits.append({**f, "title": titles.get(f.get("threat_id"), ""),
                         "sign_ins": [u for u in _json(f.get("users")) if u.get("account")][:5],
                         "users": list(dict.fromkeys(u.get("account") for u in _json(f.get("users")) if u.get("account")))[:3],
                         "alerts": [a.get("title") for a in _json(f.get("alerts"))][:2],
                         "timeline": _json(f.get("timeline"))[:6],
                         "resolution": {"what_happened": r["what_happened"], "steps": _json(r.get("steps")), "done_when": r["done_when"],
                                        "source": r["source"], "model": r.get("model")} if r else None})
        hits.sort(key=lambda h: str(h.get("first_hit") or ""), reverse=True)
        return {"generated": out.get("generated_at"), "run_id": out.get("run_id"), "hits": hits,
                "hunts": out.get("hunts") or [], "devices": out.get("devices") or [], "attacks": out.get("attacks") or []}

    def last_run(self) -> dict | None:
        return _read_json(self.data / "last_run.json")


def remediation_status(fix_dir: Path, finding_ids: set[str]) -> dict[str, dict]:
    """finding_id -> {fix_id, status} of its scan-and-clean response, from the fix engine's plan and state files."""
    plan = _read_json(fix_dir / "plan.json") or {}
    state = (_read_json(fix_dir / "state.json") or {}).get("fixes") or {}
    out = {}
    for item in plan.get("items") or []:
        fid = item.get("finding_id")
        if item.get("kind") == "response" and fid in finding_ids:
            out[fid] = {"fix_id": item["fix_id"], "status": (state.get(item["fix_id"]) or {}).get("status") or "proposed"}
    return out
