"""Run a playbook's related-log searches. KQL templates live in config/kql/; placeholders are filled with values
taken from the incident packet, each one escaped (never raw string concatenation), and every finished query is
checked read-only before it is sent to Microsoft Graph.

Placeholders:
  {{START}} {{END}}      ISO datetimes of the +- window around the alerts (quoted inside datetime(...))
  {{DEVICE_IDS}}         comma list of quoted Defender device IDs on the incident
  {{DEVICE_NAMES}}       comma list of quoted device names
  {{HOSTS}}              comma list of quoted short computer names (no domain), for Windows security event tables
  {{ACCOUNTS}}           comma list of quoted account names
  {{UPNS}}               comma list of quoted sign-in names (user@domain), for Sentinel sign-in / Office tables
  {{IPS}}                comma list of quoted IP addresses on the incident
  {{HASHES}}             comma list of quoted SHA256 values gathered for this incident
  {{DOMAINS}}            comma list of quoted domains
  {{LIMIT}}              row cap (int)
"""

from __future__ import annotations

import logging
import re
from datetime import timedelta
from pathlib import Path

from uc4.config import CONFIG_DIR, Settings
from uc4.store import to_utc, utcnow
from uc4.validator import validate

log = logging.getLogger("uc4.logs")
_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _kql_str(value: str) -> str:
    """A KQL string literal: only safe characters kept, wrapped in double quotes. Blocks injection via entity text."""
    cleaned = re.sub(r'[^A-Za-z0-9_.\-:@\\/ ]', "", str(value or ""))[:200]
    return '"' + cleaned.replace('"', "") + '"'


def _list(values, limit: int = 50) -> str:
    seen, out = set(), []
    for v in values:
        v = (v or "").strip()
        if v and v.lower() not in seen:
            seen.add(v.lower())
            out.append(_kql_str(v))
        if len(out) >= limit:
            break
    return ", ".join(out) if out else '""'


def _collect_hashes(packet: dict) -> list[str]:
    out = []
    for f in packet["entities"]["files"]:
        if f.get("sha256") and re.fullmatch(r"[0-9a-f]{64}", f["sha256"]):
            out.append(f["sha256"])
    for p in packet["entities"]["processes"]:
        if p.get("sha256") and re.fullmatch(r"[0-9a-f]{64}", p["sha256"]):
            out.append(p["sha256"])
    return out


def build_params(packet: dict, settings: Settings) -> dict[str, str]:
    ent = packet["entities"]
    center = to_utc(packet["last_activity"]) or to_utc(packet["created_at"]) or utcnow()
    start = center - timedelta(hours=settings.window_hours)
    end = center + timedelta(hours=settings.window_hours)
    return {
        "START": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "END": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DEVICE_IDS": _list([d.get("id") for d in ent["devices"]]),
        "DEVICE_NAMES": _list([d.get("name") for d in ent["devices"]]),
        "HOSTS": _list([(d.get("name") or "").split(".")[0] for d in ent["devices"]]),
        "ACCOUNTS": _list([a.get("name") for a in ent["accounts"]]),
        "UPNS": _list([a.get("upn") or (a.get("name") if "@" in (a.get("name") or "") else "") for a in ent["accounts"]]
                      + [m.get("address") for m in ent["mailboxes"]]),
        "IPS": _list([i.get("value") for i in ent["ips"]]),
        "HASHES": _list(_collect_hashes(packet)),
        "DOMAINS": _list([d.get("value") for d in ent["domains"]]),
        "LIMIT": str(settings.max_rows),
    }


def render(template: str, params: dict[str, str]) -> str:
    out = template
    for key, value in params.items():
        out = out.replace("{{" + key + "}}", value)
    return out


class LogTools:
    def __init__(self, graph, settings: Settings, kql_dir: Path | None = None):
        self.graph = graph
        self.settings = settings
        self.kql_dir = kql_dir or (CONFIG_DIR / "kql")

    def available(self) -> set[str]:
        return {p.stem for p in self.kql_dir.glob("Q*.kql")}

    def run(self, query_ids: list[str], packet: dict) -> list[dict]:
        """Return one result block per query: {id, rows (capped for AI), row_count, status, query, error}."""
        params = build_params(packet, self.settings)
        results = []
        for qid in query_ids[: self.settings.max_queries]:
            path = self.kql_dir / f"{qid}.kql"
            if not path.is_file():
                results.append({"id": qid, "status": "missing", "rows": [], "row_count": 0, "error": "template not found"})
                continue
            kql = render(path.read_text(encoding="utf-8"), params)
            problems = validate(kql, require_time=False, require_limit=True)  # some templates summarise, not time-filter
            if problems:
                results.append({"id": qid, "status": "blocked", "rows": [], "row_count": 0,
                                "error": "; ".join(problems), "query": kql})
                continue
            try:
                rows = self.graph.hunt(kql)
            except Exception as exc:  # noqa: BLE001 - one failed query must not stop the triage
                log.info("Query %s failed: %s", qid, exc)
                results.append({"id": qid, "status": "error", "rows": [], "row_count": 0,
                                "error": str(exc).splitlines()[0][:200], "query": kql})
                continue
            results.append({"id": qid, "status": "ok", "row_count": len(rows),
                            "rows": rows[: self.settings.ai_rows], "query": kql})
        return results
