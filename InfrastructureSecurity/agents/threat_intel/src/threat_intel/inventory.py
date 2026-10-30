"""Phase 3: our environment from Defender: devices, installed software, vulnerabilities.

Devices come from the Machines API (tags, RBAC group). Software and vulnerabilities come from Advanced
Hunting, which is fine for a lab (far below the 100k-row limit). For a large estate, switch the
vulnerability pull to the export API used in Vulnerability (see README).
"""

from __future__ import annotations

import fnmatch
import logging

from threat_intel.api_client import MAX_HUNT_ROWS, DefenderClient
from threat_intel.config import read_csv
from threat_intel.store import Store, to_utc, utcnow

log = logging.getLogger("threat_intel.inventory")

SOFTWARE_QUERY = """DeviceTvmSoftwareInventory
| project DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion"""

VULN_QUERY = """DeviceTvmSoftwareVulnerabilities
| project DeviceId, DeviceName, CveId, SoftwareVendor, SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable) on CveId
| project-away CveId1"""

VULN_COUNT_QUERY = "DeviceTvmSoftwareVulnerabilities | count"

# Security settings Defender says are wrong on each computer (secure configuration assessment), for the fix loop
SETTINGS_QUERY = """DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1 and IsCompliant == 0
| join kind=leftouter (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName) on ConfigurationId
| project DeviceId, DeviceName, ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory,
          ConfigurationImpact"""


def opco_for(device: dict, rules: list[dict] | None = None) -> str:
    """Same rule order as Vulnerability: RBAC device group, then tag, then name pattern."""
    rules = rules if rules is not None else read_csv("opco_mapping.csv")
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


def pull_devices(client: DefenderClient) -> list[dict]:
    now = utcnow()
    rules = read_csv("opco_mapping.csv")
    devices = []
    for m in client.get_all("/api/machines"):
        d = {"device_id": m.get("id"), "device_name": (m.get("computerDnsName") or "").split(".")[0].lower(),
             "os_platform": m.get("osPlatform"), "os_version": m.get("version"),
             "rbac_group": m.get("rbacGroupName"), "tags": ",".join(m.get("machineTags") or []),
             "health": m.get("healthStatus"), "last_seen": to_utc(m.get("lastSeen")), "snapshot_at": now}
        d["opco"] = opco_for(d, rules)
        devices.append(d)
    return devices


def pull(store: Store, client: DefenderClient) -> dict:
    now = utcnow()
    devices = pull_devices(client)
    names = {d["device_id"]: d["device_name"] for d in devices}

    software = [{"device_id": r["DeviceId"], "device_name": names.get(r["DeviceId"], (r.get("DeviceName") or "").split(".")[0]),
                 "vendor": r.get("SoftwareVendor") or "", "name": r.get("SoftwareName") or "",
                 "version": r.get("SoftwareVersion") or "", "snapshot_at": now}
                for r in client.run_query(SOFTWARE_QUERY)]

    vuln_rows = client.run_query(VULN_QUERY)
    vulns = [{"device_id": r["DeviceId"], "device_name": names.get(r["DeviceId"], (r.get("DeviceName") or "").split(".")[0]),
              "cve_id": (r.get("CveId") or "").upper(), "vendor": r.get("SoftwareVendor") or "",
              "name": r.get("SoftwareName") or "", "version": r.get("SoftwareVersion") or "",
              "severity": r.get("VulnerabilitySeverityLevel"), "cvss": r.get("CvssScore"),
              "exploit_available": bool(r.get("IsExploitAvailable")),
              "recommended_update": r.get("RecommendedSecurityUpdate") or "", "snapshot_at": now}
             for r in vuln_rows if r.get("CveId")]
    vulns = list({(v["device_id"], v["cve_id"], v["vendor"], v["name"], v["version"]): v for v in vulns}.values())

    defender_count = (client.run_query(VULN_COUNT_QUERY) or [{}])[0].get("Count")
    if len(vuln_rows) >= MAX_HUNT_ROWS:
        log.warning("Vulnerability query hit the 100k limit: use the Vulnerability Agent's export method for this estate size")

    # replace the snapshot (current state only; history is not needed for Threat Intel)
    for table, rows in (("devices", devices), ("software", software), ("device_vulns", vulns)):
        store.execute(f"DELETE FROM {table}")
        store.upsert(table, rows)
    # when our runs first saw Defender list each CVE on each computer (kept across runs, unlike the snapshot)
    store.execute("""INSERT OR IGNORE INTO defender_seen SELECT DISTINCT device_name, cve_id, ? FROM device_vulns""", [now])
    result = {"devices": len(devices), "software": len(software), "vulnerabilities": len(vulns),
              "defender_count": defender_count,
              "coverage_ok": defender_count is None or defender_count == len(vuln_rows)}

    # extra for the fix loop: a failure here keeps the old settings snapshot (never "all fixed" by accident)
    try:
        settings_rows = [{"device_id": r["DeviceId"], "device_name": names.get(r["DeviceId"], (r.get("DeviceName") or "").split(".")[0]),
                          "config_id": (r.get("ConfigurationId") or "").lower(), "name": r.get("ConfigurationName") or "",
                          "category": r.get("ConfigurationCategory") or "", "subcategory": r.get("ConfigurationSubcategory") or "",
                          "impact": r.get("ConfigurationImpact"), "snapshot_at": now}
                         for r in client.run_query(SETTINGS_QUERY) if r.get("ConfigurationId")]
        store.execute("DELETE FROM device_settings")
        store.upsert("device_settings", settings_rows)
        result["wrong_settings"] = len(settings_rows)
    except Exception as exc:  # noqa: BLE001 - settings are extra; the vulnerability inventory above is complete
        log.warning("Could not read Defender's security-setting checks: %s", exc)
        result["wrong_settings"] = None
    log.info("Inventory: %s", result)
    return result
