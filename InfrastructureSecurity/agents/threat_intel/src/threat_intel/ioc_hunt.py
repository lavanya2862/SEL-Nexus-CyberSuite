"""Search for clues: sweep Defender's device events for the indicators (IOCs) the feeds collected, and turn each hit
into a sign of attack with its device, users, Defender alerts and timeline.

All IOCs of recent threats (and TEST indicators) are batched per type (config/kql_templates/ioc_*.kql), so a few
queries cover hundreds of indicators. Hits are mapped back to the IOC value and so to the threat(s). Signs of attack
are kept from run to run. Searching for attacker behaviour (no indicator needed) is the Attack Detection Agent's job.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from threat_intel.api_client import ApiError, DefenderClient
from threat_intel.config import CONFIG_DIR
from threat_intel.correlate import _alerts, _fid, _users, kql_string
from threat_intel.feeds.iocs import allowlisted
from threat_intel.store import NEW_IDS_SHOWN, Store, to_utc, utcnow

log = logging.getLogger("threat_intel.ioc_hunt")

TEMPLATE_DIR = CONFIG_DIR / "kql_templates"
BATCH = 400
ACCOUNT_FIELDS = ("AccountName", "InitiatingProcessAccountName")
SUMMARY_FIELDS = ("ActionType", "FileName", "RemoteUrl", "RemoteIP", "Url", "SHA256", "InitiatingProcessFileName")


@dataclass(frozen=True)
class Template:
    """One ioc_*.kql file. Header comments carry // name, // ioc_type (comma-separated) and // technique.
    Placeholders: {{LOOKBACK}} (days) and {{VALUES}} (a comma-separated list of KQL string literals)."""
    key: str
    name: str
    ioc_types: tuple[str, ...]
    technique: str
    body: str

    def render(self, lookback_days: int, values: list[str]) -> str:
        values_kql = ", ".join(kql_string(v) for v in values) or '@"__none__"'
        return self.body.replace("{{LOOKBACK}}", str(int(lookback_days))).replace("{{VALUES}}", values_kql)


def parse(path: Path) -> Template:
    meta, body = {}, []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("//") and ":" in stripped and not body:
            key, _, value = stripped[2:].partition(":")
            meta[key.strip()] = value.strip()
        elif stripped or body:
            body.append(line)
    return Template(key=path.stem, name=meta.get("name", path.stem),
                    ioc_types=tuple(t.strip() for t in meta.get("ioc_type", "").split(",") if t.strip()),
                    technique=meta.get("technique", ""), body="\n".join(body).strip())


def load(directory: Path = TEMPLATE_DIR) -> list[Template]:
    return [parse(p) for p in sorted(directory.glob("ioc_*.kql"))]


def _summary(row: dict) -> str:
    return "; ".join(f"{k}={str(row[k])[:160]}" for k in SUMMARY_FIELDS if row.get(k))[:600]


def _matched(ioc_type: str, row: dict, values: set[str]) -> list[str]:
    if ioc_type == "ip":
        return [row["RemoteIP"]] if row.get("RemoteIP") in values else []
    if ioc_type == "domain":
        text = f"{row.get('Host', '')} {row.get('RemoteUrl', '')}".lower()
        return [v for v in values if v in text]
    if ioc_type == "url":
        url = (row.get("Url") or "").lower()
        return [v for v in values if v.lower() == url]
    hashes = {str(row.get(k) or "").lower() for k in ("SHA256", "SHA1", "MD5")}
    return [v for v in values if v in hashes]


def ioc_values(store: Store, recent_days: int) -> dict[str, set[str]]:
    since = utcnow() - timedelta(days=recent_days)
    rows = store.query("""
        SELECT l.value FROM threat_links l JOIN threats t ON t.threat_id = l.threat_id
        WHERE l.link_type = 'ioc' AND (t.first_seen_at >= ? OR t.is_test)""", [since])
    by_type: dict[str, set[str]] = {}
    for r in rows:
        ioc_type, _, value = r["value"].partition("|")
        if ioc_type == "domain" and allowlisted(value):
            continue                      # stored before the allowlist existed, or added by the AI
        by_type.setdefault(ioc_type, set()).add(value)
    return by_type


def sweep(store: Store, client: DefenderClient, run_id: str, lookback_days: int, recent_days: int) -> list[tuple]:
    """Run the sweeps; returns (hunt, row, matched values, ioc type) for every hit."""
    by_type = ioc_values(store, recent_days)
    hits, stats = [], {"hunts": 0, "errors": 0, "ioc_values": 0}
    for t in load():
        for ioc_type in t.ioc_types:
            values = sorted(by_type.get(ioc_type, set()))
            stats["ioc_values"] += len(values)
            for b in range(0, len(values), BATCH):
                batch, n = values[b:b + BATCH], b // BATCH + 1
                hunt = {"hunt_id": f"{run_id}:{t.key}:{ioc_type}:{n}", "run_id": run_id, "threat_id": None,
                        "name": f"{t.name} ({ioc_type}, {len(batch)} values, batch {n})", "template": t.key,
                        "origin": "template", "technique": t.technique, "query": t.render(lookback_days, batch),
                        "started_at": utcnow()}
                started = time.monotonic()
                stats["hunts"] += 1
                try:
                    rows = client.run_query(hunt["query"])
                except ApiError as exc:
                    stats["errors"] += 1
                    log.warning("IOC sweep %s failed: %s", hunt["name"], exc.detail[:200])
                    store.upsert("hunts", [{**hunt, "status": "error", "row_count": 0, "error": exc.detail[:1000],
                                            "duration_s": round(time.monotonic() - started, 2)}])
                    continue
                store.upsert("hunts", [{**hunt, "status": "ok", "row_count": len(rows), "error": None,
                                        "duration_s": round(time.monotonic() - started, 2)}])
                results = []
                for i, row in enumerate(rows):
                    matched = _matched(ioc_type, row, set(batch))
                    results.append({"hunt_id": hunt["hunt_id"], "row_no": i, "device_id": row.get("DeviceId"),
                                    "device_name": (row.get("DeviceName") or "").split(".")[0].lower(),
                                    "event_time": to_utc(row.get("Timestamp")),
                                    "account": next((row[k] for k in ACCOUNT_FIELDS if row.get(k)), None),
                                    "summary": _summary(row), "row_json": {**row, "_matched": matched,
                                                                            "_ioc_type": ioc_type}})
                    hits.append((hunt, results[-1], matched, ioc_type))
                store.upsert("hunt_results", results)
    log.info("IOC sweeps: %s", stats)
    return hits


def run(store: Store, client: DefenderClient, run_id: str, lookback_days: int, recent_days: int = 7) -> dict:
    hits = sweep(store, client, run_id, lookback_days, recent_days)
    now = utcnow()
    devices = {d["device_id"]: d for d in store.query("SELECT * FROM devices")}
    ioc_threats: dict[str, set[str]] = {}
    for l in store.query("SELECT threat_id, value FROM threat_links WHERE link_type = 'ioc'"):
        ioc_threats.setdefault(l["value"], set()).add(l["threat_id"])
    test_threats = {r["threat_id"] for r in store.query("SELECT threat_id FROM threats WHERE is_test")}

    groups: dict[tuple, dict] = {}
    for hunt, r, matched, ioc_type in hits:
        for value in matched:
            for tid in ioc_threats.get(f"{ioc_type}|{value}", ()):
                g = groups.setdefault((tid, r["device_id"], value), {"hunt": hunt, "rows": [],
                                                                     "detail": f"matched {ioc_type} {value}"})
                g["rows"].append(r)

    users = _users(client, sorted({k[1] for k in groups if k[1]}))
    alerts, alert_note = _alerts(client) if groups else ({}, None)
    # signs of attack are kept from run to run: a run adds the new ones and refreshes the ones it finds again
    known = {r["finding_id"]: r for r in store.query(
        "SELECT finding_id, first_hit, created_at FROM findings WHERE kind = 'ioc_hit'")}
    findings = []
    for (tid, dev, _), g in groups.items():
        times = sorted(r["event_time"] for r in g["rows"] if r["event_time"])
        first = times[0] if times else None
        name = g["hunt"]["name"].split(" (")[0]
        timeline = [{"time": str(r["event_time"]), "what": f"Hunt '{name}': {r['summary']}", "account": r["account"]}
                    for r in sorted(g["rows"], key=lambda x: x["event_time"] or now)[:25]]
        near = [a for a in alerts.get(dev, []) if first and abs((to_utc(a["time"]) - first).total_seconds()) <= 86400]
        timeline += [{"time": a["time"], "what": f"Defender alert: {a['title']} ({a['severity']}, {a['status']})",
                      "account": None} for a in near]
        timeline.sort(key=lambda x: x["time"])
        d = devices.get(dev, {})
        fid = _fid("ioc_hit", tid, dev, g["detail"])
        prev = (known.get(fid) or {}).get("first_hit")
        findings.append({"finding_id": fid, "threat_id": tid, "hunt_id": g["hunt"]["hunt_id"], "kind": "ioc_hit",
                         "device_id": dev, "device_name": d.get("device_name") or g["rows"][0]["device_name"],
                         "opco": d.get("opco", "Unassigned"), "detail": g["detail"], "users": users.get(dev, [])[:5],
                         "alerts": near[:10], "timeline": timeline, "is_test": tid in test_threats,
                         "first_hit": min(x for x in (prev, first) if x) if (prev or first) else None,
                         "created_at": (known.get(fid) or {}).get("created_at") or now})
    store.upsert("findings", findings)
    new = [f for f in findings if f["finding_id"] not in known]
    stats = {"ioc_rows": len(hits), "new_hits": len(new), "new_hit_ids": [f["finding_id"] for f in new][:NEW_IDS_SHOWN],
             "ioc_findings": store.scalar("SELECT COUNT(*) FROM findings WHERE kind = 'ioc_hit'") or 0,
             "test_hits": sum(f["is_test"] for f in new), "alerts_note": alert_note}
    log.info("IOC hits: %s", stats)
    return stats
