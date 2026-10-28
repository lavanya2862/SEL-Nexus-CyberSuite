"""Context for an incident: device details (from Defender), OpCo mapping, and watchlist hits (VIPs, service
accounts, approved admin tools/paths, approved scanners). Watchlists turn "suspicious" into "expected" - the key to
telling a benign admin action from a real attack.
"""

from __future__ import annotations

import fnmatch
import logging

from uc4.config import CONFIG_DIR, Settings, read_csv

log = logging.getLogger("uc4.context")


def _watchlists() -> dict[str, list[dict]]:
    base = CONFIG_DIR / "watchlists"
    return {name: read_csv(f"watchlists/{name}.csv")
            for name in ("approved_admin_tools", "service_accounts", "vip_users", "approved_scanners")}


def _under(path: str, folder: str) -> bool:
    """Is `path` the folder itself or inside it? Case-insensitive, trailing slashes ignored."""
    p = (path or "").replace("/", "\\").rstrip("\\").lower()
    f = (folder or "").replace("/", "\\").rstrip("\\").lower()
    return bool(p and f) and (p == f or p.startswith(f + "\\"))


def opco_for(device_name: str, tags: list[str] | None = None) -> str:
    rules = read_csv("opco_mapping.csv")
    name = (device_name or "").lower()
    for r in rules:
        if r["match_type"] == "tag" and r["pattern"] in (tags or []):
            return r["opco"]
    for r in rules:
        if r["match_type"] == "name_pattern" and fnmatch.fnmatch(name, r["pattern"].lower()):
            return r["opco"]
    return "Unassigned"


def gather(packet: dict, settings: Settings, defender=None) -> dict:
    wl = _watchlists()
    ent = packet["entities"]
    accounts = [a["name"].lower() for a in ent["accounts"] if a.get("name")]
    paths = [p.get("path", "") for p in ent["processes"]] + [f.get("path", "") for f in ent["files"]]
    ips = [i.get("value") for i in ent["ips"]]

    hits = {"vip": [], "service_account": [], "approved_admin": [], "approved_scanner": [], "privileged": []}
    for row in wl["vip_users"]:
        if row.get("account", "").lower() in accounts:
            hits["vip"].append(row["account"])
    for row in wl["service_accounts"]:
        if row.get("account", "").lower() in accounts:
            hits["service_account"].append(row["account"])
    for row in wl["approved_admin_tools"]:
        acc_ok = not row.get("account") or row["account"].lower() in accounts
        path_ok = not row.get("path") or any(_under(p, row["path"]) for p in paths)
        if acc_ok and path_ok and (row.get("account") or row.get("path")):
            hits["approved_admin"].append(row.get("account") or row.get("path"))
    for row in wl["approved_scanners"]:
        if row.get("ip") and row["ip"] in ips:
            hits["approved_scanner"].append(row["ip"])

    # device details from Defender (best effort)
    devices = []
    for d in ent["devices"]:
        info = {"name": d.get("name"), "os": d.get("os"), "risk": d.get("risk")}
        if defender is not None and d.get("id"):
            try:
                m = defender.machine(d["id"])
                info.update({"os": m.get("osPlatform") or info["os"], "risk": m.get("riskScore") or info["risk"],
                             "exposure": m.get("exposureLevel"), "health": m.get("healthStatus"),
                             "tags": m.get("machineTags") or []})
            except Exception as exc:  # noqa: BLE001
                log.debug("device info for %s failed: %s", d.get("name"), exc)
        info["opco"] = opco_for(info["name"], info.get("tags"))
        info["is_lab"] = (info["name"] or "").lower() in settings.lab_devices
        info["admin_account"] = any(a.get("name", "").lower() in ("administrator", "labadmin")
                                    or "admin" in a.get("name", "").lower() for a in ent["accounts"])
        devices.append(info)

    from uc4.uc1link import fixes_for
    uc1 = fixes_for(settings.uc1_dir, [d["name"] for d in devices])
    return {
        "devices": devices,
        "uc1": {"available": uc1["available"], "open": uc1.get("open", 0),
                "exploited_open": uc1.get("exploited_open", 0),
                "apps": [f"{f['app']} {f['version']} on {f['device']}"
                         + (" (on the CISA KEV list)" if f["actively_exploited"] else "")
                         for f in uc1["fixes"] if f["open"]][:6]},
        "watchlist_hits": {k: v for k, v in hits.items() if v},
        "account_is_admin": any(d.get("admin_account") for d in devices)
                            or any("admin" in a.lower() for a in accounts),
        "is_lab": packet["is_lab"] or any(d["is_lab"] for d in devices),
    }
