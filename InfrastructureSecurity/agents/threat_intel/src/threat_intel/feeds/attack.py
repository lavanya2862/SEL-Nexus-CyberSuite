"""MITRE ATT&CK (Enterprise): the catalogue of attacker techniques, refreshed weekly."""

from __future__ import annotations

import json
from datetime import timedelta

from threat_intel.feeds.common import FeedContext, http
from threat_intel.store import to_utc, utcnow

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
REFRESH = timedelta(days=7)


def parse(bundle: dict) -> list[dict]:
    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref:
            continue
        rows.append({"technique_id": ref["external_id"], "name": obj.get("name", ""),
                     "tactics": ", ".join(p["phase_name"] for p in obj.get("kill_chain_phases", [])),
                     "platforms": ", ".join(obj.get("x_mitre_platforms", [])), "url": ref.get("url", "")})
    return rows


def collect(ctx: FeedContext, force: bool = False) -> int:
    state = ctx.store.feed_state("attack")
    last = to_utc(state.get("last_success_at"))
    have = ctx.store.scalar("SELECT COUNT(*) FROM attack_techniques")
    if not force and have and last and utcnow() - last < REFRESH:
        return 0
    cache = ctx.settings.cache_dir / "enterprise-attack.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    response = http(ctx, "GET", URL, timeout=300)
    cache.write_bytes(response.content)
    rows = parse(json.loads(response.content))
    ctx.store.execute("DELETE FROM attack_techniques")
    ctx.store.upsert("attack_techniques", rows)
    ctx.store.save_feed_state("attack", "ok", len(rows))
    return len(rows)
