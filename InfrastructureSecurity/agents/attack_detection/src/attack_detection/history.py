"""Once, after the split: copy the hunts and signs of attack from before it out of the Threat Intel database.

Before the split, the Threat Intel Agent ran the hunts and kept them in its own database. This copies them here
(read-only on that file, which must not be in use), so signs of attack keep their first-seen dates and resolution
steps. After this, the agent never opens that database again.
"""

from __future__ import annotations

import duckdb

from attack_detection.config import Settings
from attack_detection.store import Store

COPY = {
    "hunts": "SELECT * FROM ti.hunts",
    "hunt_results": "SELECT * FROM ti.hunt_results",
    "findings": "SELECT * FROM ti.findings WHERE kind <> 'exposure'",
    "resolutions": "SELECT * FROM ti.resolutions",
    "threats": "SELECT * FROM ti.threats WHERE kind = 'hunt'",
    "threat_links": "SELECT * FROM ti.threat_links WHERE threat_id IN (SELECT threat_id FROM ti.threats WHERE kind = 'hunt')",
}


def copy_from_threat_intel(store: Store, settings: Settings) -> dict:
    if store.scalar("SELECT COUNT(*) FROM findings"):
        return {"copied": False, "note": "this agent already has signs of attack; nothing copied"}
    source = settings.threat_intel_dir / "data" / "threat_intel.duckdb" if settings.threat_intel_dir else None
    if not source or not source.is_file():
        return {"copied": False, "note": f"no Threat Intel database at {source}"}
    counts = {}
    with store.lock:
        store.con.execute(f"ATTACH '{source.as_posix()}' AS ti (READ_ONLY)")
        try:
            for table, sql in COPY.items():
                store.con.execute(f"INSERT OR REPLACE INTO {table} {sql}")
                counts[table] = store.con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except duckdb.Error as exc:
            return {"copied": False, "note": f"copy failed: {exc}"}
        finally:
            store.con.execute("DETACH ti")
    return {"copied": True, **counts}
