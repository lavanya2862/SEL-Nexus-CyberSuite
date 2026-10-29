"""Fetch incidents from Microsoft Graph that are new or changed since the last run, turn each into a packet, and
decide which ones need (re-)triaging. A watermark (last update time seen) is kept in the store.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta

from uc4.config import Settings
from uc4.packet import build
from uc4.store import Store, to_utc, utcnow

log = logging.getLogger("uc4.ingest")


def _watermark(store: Store, settings: Settings):
    saved = store.get_state("incident_watermark")
    if saved:
        return to_utc(saved)
    return utcnow() - timedelta(days=settings.lookback_days)


def fetch(graph, store: Store, settings: Settings) -> list[dict]:
    """Return packets for incidents that are new or whose alerts changed since we last triaged them."""
    since = _watermark(store, settings)
    raw = graph.incidents(since)
    settings.raw_dir.mkdir(parents=True, exist_ok=True)
    (settings.raw_dir / f"incidents_{utcnow().strftime('%Y%m%d_%H%M%S')}.json").write_text(
        json.dumps(raw, default=str), encoding="utf-8")

    known = {r["incident_id"]: r["fingerprint"]
             for r in store.query("SELECT incident_id, fingerprint FROM verdicts")}
    seen = {r["incident_id"]: (r["status"], r["classification"], r["determination"])
            for r in store.query("SELECT incident_id, status, classification, determination FROM incidents")}
    packets, newest = [], since
    new = reclassified = 0
    for incident in raw:
        packet = build(incident, settings.lab_devices, lab_titles=settings.lab_alert_titles)
        updated = to_utc(packet["updated_at"]) or utcnow()
        newest = max(newest, updated) if newest else updated
        iid = packet["incident_id"]
        if iid not in known:
            new += 1
        elif seen.get(iid) != (packet["status"], packet["classification"], packet["determination"]):
            reclassified += 1       # closed, reopened or classified in Defender since we last looked
        if iid in known:
            # keep Defender's current status visible in the queue (closed in the portal, by UC4, reopened...)
            store.execute("UPDATE incidents SET status = ?, classification = ?, determination = ?, updated_at = ? "
                          "WHERE incident_id = ?", [packet["status"], packet["classification"],
                                                    packet["determination"], updated, iid])
            if packet["status"].lower() == "resolved":
                continue            # closed: closing changes alert statuses, which must not trigger a re-triage
        if known.get(iid) != packet["fingerprint"]:
            packets.append(packet)
    if newest:
        store.set_state("incident_watermark", newest.strftime("%Y-%m-%dT%H:%M:%SZ"))
    # Defender returns every incident whose last-update time moved, which includes touches that change nothing
    # (a comment, a tag, alert housekeeping): count what really changed. The portal reads this line.
    log.info("Ingest: %d incident(s) returned, %d need triage, %d new, %d status or classification change(s)",
             len(raw), len(packets), new, reclassified)
    return packets
