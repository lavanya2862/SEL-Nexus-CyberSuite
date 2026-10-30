"""Publish what the Attack Detection Agent hunts for: data/out/hunt_inputs.json
(contracts/threat_intel.hunt_inputs.schema.json).

threats, their indicator / ATT&CK technique / CVE links, scores, the ATT&CK catalogue and the device inventory. The
Attack Detection Agent loads it at the start of every run instead of opening this database. Written to a temporary
name first, so a reader never sees half of it.
"""

from __future__ import annotations

import json
import os

from threat_intel.config import Settings
from threat_intel.store import Store, utcnow

SCHEMA_VERSION = 1


def write(store: Store, settings: Settings) -> dict:
    data = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utcnow().isoformat(),
        "threats": store.query("SELECT * FROM threats"),
        "threat_links": store.query("SELECT * FROM threat_links WHERE link_type IN ('ioc', 'technique', 'cve')"),
        "scores": store.query("SELECT * FROM scores"),
        "attack_techniques": store.query("SELECT * FROM attack_techniques"),
        "devices": store.query("SELECT * FROM devices"),
    }
    for s in data["scores"]:
        if isinstance(s.get("factors"), str):
            s["factors"] = json.loads(s["factors"])
    settings.out_dir.mkdir(parents=True, exist_ok=True)
    path = settings.out_dir / "hunt_inputs.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, default=str, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return {k: len(v) for k, v in data.items() if isinstance(v, list)}
