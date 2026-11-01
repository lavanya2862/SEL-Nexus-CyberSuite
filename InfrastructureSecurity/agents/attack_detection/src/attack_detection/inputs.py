"""Search devices, step 0: this agent's own device list, straight from Defender's Machines API.

The agent takes nothing from the Threat Intel Agent: its searches are the 12 attacks' `bh_*.kql`, and the attack 12
CVE list comes from Defender too (see `hunting/runner.py:hot_cves`). Without Defender the hunts run on the devices
the last run loaded.
"""

from __future__ import annotations

import fnmatch
import logging

from attack_detection.api_client import DefenderClient
from attack_detection.config import Settings, read_csv
from attack_detection.store import Store, to_utc, utcnow
from infra_core.settings import ignored_devices

log = logging.getLogger("attack_detection.inputs")


def opco_for(device: dict, rules: list[dict]) -> str:
    """RBAC device group, then tag, then name pattern (config/opco_mapping.csv, same rules as the other agents)."""
    name = (device.get("device_name") or "").lower()
    tags = [t.strip() for t in (device.get("tags") or "").split(",") if t.strip()]
    group = device.get("rbac_group") or ""
    for match_type in ("rbac_group", "tag", "name_pattern"):
        for r in rules:
            if r["match_type"] != match_type:
                continue
            if match_type == "rbac_group" and group and fnmatch.fnmatch(group, r["pattern"]):
                return r["opco"]
            if match_type == "tag" and r["pattern"] in tags:
                return r["opco"]
            if match_type == "name_pattern" and fnmatch.fnmatch(name, r["pattern"].lower()):
                return r["opco"]
    return "Unassigned"


def load(store: Store, settings: Settings, client: DefenderClient | None) -> dict:
    if client is None:
        return {"loaded": False, "note": "Defender not configured; using the last device list"}
    now, rules, skip = utcnow(), read_csv("opco_mapping.csv"), ignored_devices()
    devices = []
    for m in client.get_all("/api/machines"):
        name = (m.get("computerDnsName") or "").split(".")[0].lower()
        if not name or name in skip:
            continue
        d = {"device_id": m.get("id"), "device_name": name, "os_platform": m.get("osPlatform"), "os_version": m.get("version"),
             "rbac_group": m.get("rbacGroupName"), "tags": ",".join(m.get("machineTags") or []),
             "health": m.get("healthStatus"), "last_seen": to_utc(m.get("lastSeen")), "snapshot_at": now}
        d["opco"] = opco_for(d, rules)
        devices.append(d)
    store.execute("DELETE FROM devices")
    n = store.upsert("devices", devices)
    log.info("Loaded %s devices from Defender", n)
    return {"loaded": True, "devices": n}
