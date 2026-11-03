"""Publish: write data/out/findings.json, everything other parts may know about this agent's work
(contracts/attack_detection.findings.schema.json).

- findings: every sign of attack kept so far (signs are kept from run to run), with users, alerts and timeline
- resolutions: the steps written for each sign of attack
- threats, threat_links: the 'Proactive hunt' threats behaviour hits created, with their ATT&CK technique
- hunts: the hunts of the latest run (name, origin, technique, status, row count), not their raw rows
- devices: the devices Defender listed in this run
- attacks: the 12 attacks searched for (config/attacks.csv) with their searches (name, technique, needs)
- each finding also carries its search, attack number, attack name, severity and technique; findings on
  IGNORE_DEVICES are left out

The Attack detection page reads it, and the fix engine proposes a scan-and-clean for each finding. The file is written to a temporary name first, so a reader never sees half of it.
"""

from __future__ import annotations

import json
import os

from attack_detection.config import read_csv
from attack_detection.hunting import templates as tpl
from infra_core.settings import ignored_devices
from attack_detection.config import Settings
from attack_detection.store import Store, utcnow

SCHEMA_VERSION = 1
HUNT_FIELDS = "hunt_id, run_id, threat_id, name, template, origin, technique, status, row_count, error, started_at, duration_s"


def _rows(store: Store, sql: str, params=None) -> list[dict]:
    out = []
    for r in store.query(sql, params):
        out.append({k: (json.loads(v) if k in ("users", "alerts", "timeline", "steps", "dropped") and isinstance(v, str) else v)
                    for k, v in r.items()})
    return out


def catalogue() -> list[dict]:
    """The 12 attacks and the searches for each (the Attack coverage tab)."""
    searches: dict[int, list[dict]] = {}
    for t in tpl.load().values():
        if t.kind == "behaviour" and t.attack:
            searches.setdefault(t.attack, []).append({"key": t.key, "name": t.name, "technique": t.technique, "needs": t.needs,
                                                      "query": t.body})
    return [{**a, "attack": int(a["attack"]), "searches": sorted(searches.get(int(a["attack"]), []), key=lambda s: s["name"])}
            for a in read_csv("attacks.csv")]


HIDDEN_COLUMNS = {"DeviceId", "DeviceName", "ReportId", "Timestamp", "TenantId", "MachineGroup"}
MAX_EVENTS = 25


def _events(store: Store, findings: list[dict]) -> dict[str, dict]:
    """finding_id -> the hunt result rows behind it (every run, newest first, at most 25) with their columns, plus the
    total count and the last time seen: what the search actually found on that device."""
    out: dict[str, dict] = {}
    for f in findings:
        key = str(f.get("hunt_id") or "").split(":", 1)[-1]
        rows = store.query("""SELECT r.event_time, r.account, r.row_json FROM hunt_results r JOIN hunts h ON h.hunt_id = r.hunt_id
                              WHERE h.template = ? AND r.device_id = ? ORDER BY r.event_time DESC NULLS LAST""",
                           [key, f.get("device_id")])
        seen, events = set(), []
        for r in rows:
            row = json.loads(r["row_json"]) if isinstance(r["row_json"], str) else (r["row_json"] or {})
            cols = {k: v for k, v in row.items() if k not in HIDDEN_COLUMNS and v not in (None, "", [], [""])}
            sig = json.dumps(cols, sort_keys=True, default=str)
            if sig in seen:                       # the same row found again by a later run
                continue
            seen.add(sig)
            events.append({"time": str(r["event_time"] or ""), "account": r["account"], "columns": cols})
        out[f["finding_id"]] = {"events": events[:MAX_EVENTS], "event_count": len(events),
                                "last_hit": events[0]["time"] if events else None}
    return out


def _label(findings: list[dict], attacks: list[dict]) -> list[dict]:
    """Search, attack and severity on each finding (from its search's `// attack:` tag); ignored devices left out."""
    templates, by_no, skip = tpl.load(), {a["attack"]: a for a in attacks}, ignored_devices()
    out = []
    for f in findings:
        if (f.get("device_name") or "").lower() in skip:
            continue
        key = str(f.get("hunt_id") or "").split(":", 1)[-1]
        t = templates.get(key)
        a = by_no.get(t.attack if t else 0, {})
        out.append({**f, "search": key, "search_name": t.name if t else key, "technique": t.technique if t else "",
                    "attack": a.get("attack", 0), "attack_name": a.get("name", "Other"), "severity": a.get("severity", "Medium")})
    return out


def merge_key(f: dict) -> tuple:
    """One detection per attack per device: several searches that see the same activity (a new account found by
    'new local account' and 'created outside working hours') are one possible attack, not three."""
    return (f.get("attack") or f.get("search"), f.get("device_id") or f.get("device_name"), bool(f.get("is_test")))


def _merge(findings: list[dict], events: dict[str, dict]) -> list[dict]:
    """Keep one finding per merge_key (the first found), with every search that matched listed in `signals` and the
    events of all of them."""
    groups: dict[tuple, list[dict]] = {}
    for f in findings:
        groups.setdefault(merge_key(f), []).append(f)
    out = []
    for members in groups.values():
        members.sort(key=lambda f: (str(f.get("first_hit") or "9"), f["finding_id"]))
        main = members[0]
        seen, merged = set(), []
        for m in members:
            for e in (events.get(m["finding_id"]) or {}).get("events", []):
                sig = json.dumps([e["time"], e["columns"]], sort_keys=True, default=str)
                if sig not in seen:
                    seen.add(sig)
                    merged.append(e)
        merged.sort(key=lambda e: e["time"], reverse=True)
        main = {**main, "signals": [{"search": m["search"], "search_name": m["search_name"], "technique": m["technique"]} for m in members],
                "first_hit": min((str(m["first_hit"]) for m in members if m.get("first_hit")), default=main.get("first_hit"))}
        events[main["finding_id"]] = {"events": merged[:MAX_EVENTS], "event_count": len(merged),
                                      "last_hit": merged[0]["time"] if merged else None}
        out.append(main)
    return out


def write(store: Store, settings: Settings, run_id: str | None) -> dict:
    latest = run_id or store.scalar("SELECT run_id FROM hunts ORDER BY started_at DESC LIMIT 1")
    attacks = catalogue()
    findings = _label(_rows(store, "SELECT * FROM findings WHERE kind <> 'exposure' ORDER BY created_at DESC"), attacks)
    events = _events(store, findings)
    findings = _merge(findings, events)
    data = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utcnow().isoformat(),
        "run_id": latest,
        "findings": [{**f, **events.get(f["finding_id"], {})} for f in findings],
        "attacks": attacks,
        "resolutions": _rows(store, "SELECT * FROM resolutions"),
        "threats": _rows(store, "SELECT * FROM threats WHERE kind = 'hunt'"),
        "threat_links": _rows(store, """SELECT * FROM threat_links
                                        WHERE threat_id IN (SELECT threat_id FROM threats WHERE kind = 'hunt')"""),
        "hunts": _rows(store, f"SELECT {HUNT_FIELDS} FROM hunts WHERE run_id = ?", [latest]) if latest else [],
        "devices": _rows(store, "SELECT device_id, device_name, opco, os_platform, last_seen FROM devices ORDER BY device_name"),
    }
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    path = settings.out_dir / "findings.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, default=str, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return {"findings": len(data["findings"]), "resolutions": len(data["resolutions"]), "hunts": len(data["hunts"]),
            "path": str(path)}
