"""Import what the Attack Detection Agent publishes (its data/out/findings.json) into this database.

Its signs of attack, their resolution steps, the 'Proactive hunt' threats behaviour hits created and the latest run's
hunts become this agent's copies, so scoring, alerts, the report, the dashboard data and the fix plan work on them as
before. The file is the whole current state, so earlier copies are replaced.
"""

from __future__ import annotations

import json
import logging

from threat_intel.config import Settings
from threat_intel.store import Store

log = logging.getLogger("threat_intel.attack_import")

SCHEMA_VERSION = 1


def run(store: Store, settings: Settings) -> dict:
    path = settings.attack_agent_dir / "data" / "out" / "findings.json" if settings.attack_agent_dir else None
    if not path or not path.is_file():
        return {"imported": False, "note": f"nothing published by the Attack Detection Agent yet ({path})"}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"{path.name} has schema_version {data.get('schema_version')}, expected {SCHEMA_VERSION}")
    store.add_threats(data.get("threats") or [])
    for link in data.get("threat_links") or []:
        store.link(link["threat_id"], link["link_type"], [link["value"]], link.get("origin") or "source")
    store.execute("DELETE FROM findings WHERE kind <> 'exposure'")
    findings = store.upsert("findings", data.get("findings") or [])
    store.execute("DELETE FROM resolutions")
    resolutions = store.upsert("resolutions", data.get("resolutions") or [])
    hunts = store.upsert("hunts", data.get("hunts") or [])
    result = {"imported": True, "run_id": data.get("run_id"), "findings": findings, "resolutions": resolutions,
              "hunts": hunts}
    log.info("Imported the Attack Detection Agent's findings: %s", result)
    return result
