"""Publish: write data/out/findings.json, everything other parts may know about this agent's work
(contracts/attack_detection.findings.schema.json).

- findings: every sign of attack kept so far (signs are kept from run to run), with users, alerts and timeline
- resolutions: the steps written for each sign of attack
- threats, threat_links: the 'Proactive hunt' threats behaviour hits created, with their ATT&CK technique
- hunts: the hunts of the latest run (name, origin, technique, status, row count), not their raw rows

The Threat Intel Agent imports it (`python -m threat_intel attack-import`) for scoring, alerts, its report, the
dashboard and the fix plan. The file is written to a temporary name first, so a reader never sees half of it.
"""

from __future__ import annotations

import json
import os

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


def write(store: Store, settings: Settings, run_id: str | None) -> dict:
    latest = run_id or store.scalar("SELECT run_id FROM hunts ORDER BY started_at DESC LIMIT 1")
    data = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utcnow().isoformat(),
        "run_id": latest,
        "findings": _rows(store, "SELECT * FROM findings WHERE kind <> 'exposure' ORDER BY created_at DESC"),
        "resolutions": _rows(store, "SELECT * FROM resolutions"),
        "threats": _rows(store, "SELECT * FROM threats WHERE kind = 'hunt'"),
        "threat_links": _rows(store, """SELECT * FROM threat_links
                                        WHERE threat_id IN (SELECT threat_id FROM threats WHERE kind = 'hunt')"""),
        "hunts": _rows(store, f"SELECT {HUNT_FIELDS} FROM hunts WHERE run_id = ?", [latest]) if latest else [],
    }
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    path = settings.out_dir / "findings.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, default=str, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return {"findings": len(data["findings"]), "resolutions": len(data["resolutions"]), "hunts": len(data["hunts"]),
            "path": str(path)}
