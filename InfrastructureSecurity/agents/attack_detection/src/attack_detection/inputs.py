"""Search devices, step 0: load what the Threat Intel Agent publishes for the hunts (its data/out/hunt_inputs.json).

The file holds the threats (with their indicators and ATT&CK techniques), their scores, the ATT&CK catalogue and the
device inventory. They replace this agent's copies of those tables on every run; the agent never opens the Threat
Intel database. Threats this agent created itself (kind 'hunt', for behaviour hits) are kept. A missing or older file
means "no new input": the hunts then run on what the last run loaded.
"""

from __future__ import annotations

import json
import logging

from attack_detection.config import Settings
from attack_detection.store import Store

log = logging.getLogger("attack_detection.inputs")

SCHEMA_VERSION = 1
TABLES = ("threats", "threat_links", "scores", "attack_techniques", "devices")


def load(store: Store, settings: Settings) -> dict:
    path = (settings.threat_intel_dir / "data" / "out" / "hunt_inputs.json") if settings.threat_intel_dir else None
    if not path or not path.is_file():
        return {"loaded": False, "note": f"no input from the Threat Intel Agent yet ({path}); using the last one"}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != SCHEMA_VERSION:
        return {"loaded": False, "note": f"input has schema_version {data.get('schema_version')}, expected {SCHEMA_VERSION}"}
    own = {r["threat_id"] for r in store.query("SELECT threat_id FROM threats WHERE kind = 'hunt'")}
    counts = {}
    for table in TABLES:
        rows = data.get(table) or []
        if table in ("threats", "threat_links", "scores"):
            store.execute(f"DELETE FROM {table} WHERE threat_id NOT IN (SELECT threat_id FROM threats WHERE kind = 'hunt')"
                          if table != "threats" else "DELETE FROM threats WHERE kind <> 'hunt'")
            rows = [r for r in rows if r.get("threat_id") not in own]
        else:
            store.execute(f"DELETE FROM {table}")
        counts[table] = store.upsert(table, rows)
    log.info("Loaded the Threat Intel Agent's input of %s: %s", data.get("generated_at"), counts)
    return {"loaded": True, "generated_at": data.get("generated_at"), **counts}
