"""Search devices: run the searches for the 12 attacks in Defender Advanced Hunting.

Every behaviour template runs each time. They look for what attackers do (ATT&CK techniques), so they need no
indicator; sweeping for the indicators (IOCs) the feeds collect is the Threat Intel Agent's job.
"""

from __future__ import annotations

import logging
import time

from attack_detection.api_client import ApiError, DefenderClient
from attack_detection.hunting import templates as tpl
from attack_detection.store import Store, to_utc, utcnow
from infra_core.settings import ignored_devices

HOT_CVE_QUERY = """DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ("Critical", "High")
| join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | where IsExploitAvailable == 1 | project CveId) on CveId
| distinct CveId"""

log = logging.getLogger("attack_detection.hunt")

ACCOUNT_FIELDS = ("AccountName", "InitiatingProcessAccountName")
SUMMARY_FIELDS = ("ActionType", "FileName", "ProcessCommandLine", "RemoteUrl", "RemoteIP", "Url", "SHA256",
                  "InitiatingProcessFileName", "Commands", "CVEs", "PipeName", "RegistryKey", "RegistryValueData")
# Hunts marked "needs: domain" only run when at least one device is joined to an Active Directory domain
DOMAIN_QUERY = """DeviceInfo
| where Timestamp > ago(7d)
| where JoinType in~ ("Domain Joined", "Hybrid Azure AD Join", "Hybrid Azure AD Joined") or DeviceType =~ "DomainController"
| take 1"""


def _row_summary(row: dict) -> str:
    parts = [f"{k}={str(row[k])[:160]}" for k in SUMMARY_FIELDS if row.get(k)]
    return "; ".join(parts)[:600]


class HuntRunner:
    def __init__(self, store: Store, client: DefenderClient, run_id: str, lookback_days: int):
        self.store, self.client, self.run_id, self.lookback = store, client, run_id, lookback_days
        self.templates = tpl.load()
        self.stats = {"hunts": 0, "ok": 0, "errors": 0, "skipped": 0, "rows": 0}

    # ---------- one hunt ----------
    def execute(self, key: str, name: str, query: str, *, origin: str = "template", technique: str = "",
                threat_id: str | None = None) -> dict:
        hunt_id = f"{self.run_id}:{key}"
        started = time.monotonic()
        record = {"hunt_id": hunt_id, "run_id": self.run_id, "threat_id": threat_id, "name": name,
                  "template": key.split(":")[0], "origin": origin, "technique": technique, "query": query,
                  "started_at": utcnow()}
        self.stats["hunts"] += 1
        try:
            rows = self.client.run_query(query)
        except ApiError as exc:
            record.update(status="error", row_count=0, error=exc.detail[:1000],
                          duration_s=round(time.monotonic() - started, 2))
            self.store.upsert("hunts", [record])
            self.stats["errors"] += 1
            log.warning("Hunt %s failed: %s", name, exc.detail[:200])
            return record
        skip = ignored_devices()           # IGNORE_DEVICES in .env: devices every agent leaves out
        rows = [r for r in rows if (r.get("DeviceName") or "").split(".")[0].lower() not in skip]
        results = []
        for i, row in enumerate(rows):
            results.append({"hunt_id": hunt_id, "row_no": i, "device_id": row.get("DeviceId"),
                            "device_name": (row.get("DeviceName") or "").split(".")[0].lower(),
                            "event_time": to_utc(row.get("Timestamp")),
                            "account": next((row[k] for k in ACCOUNT_FIELDS if row.get(k)), None),
                            "summary": _row_summary(row), "row_json": row})
        record.update(status="ok", row_count=len(rows), error=None, duration_s=round(time.monotonic() - started, 2))
        self.store.upsert("hunts", [record])
        self.store.upsert("hunt_results", results)
        self.stats["ok"] += 1
        self.stats["rows"] += len(rows)
        return record

    # ---------- the searches ----------
    def behaviour_hunts(self) -> None:
        hot_cves = self.hot_cves()
        has_domain = None
        for t in (t for t in self.templates.values() if t.kind == "behaviour"):
            if t.needs == "domain":
                has_domain = self.has_domain() if has_domain is None else has_domain
                if not has_domain:
                    self._skip(t, "needs a domain: no device in Defender is joined to an Active Directory domain")
                    continue
            self.execute(t.key, t.name, t.render(self.lookback, hot_cves=hot_cves), technique=t.technique)

    def hot_cves(self) -> list[str]:
        """For the attack 12 hunts: the Critical/High CVEs with a public exploit that Defender lists on our devices."""
        try:
            rows = self.client.run_query(HOT_CVE_QUERY)
        except ApiError as exc:
            log.warning("Hot CVE list failed, the attack 12 hunts run without it: %s", exc.detail[:200])
            return []
        return [r["CveId"] for r in rows if r.get("CveId")][:5000]

    def has_domain(self) -> bool:
        try:
            rows = self.client.run_query(DOMAIN_QUERY)
        except ApiError as exc:
            log.warning("Domain check failed, running the domain hunts anyway: %s", exc.detail[:200])
            return True
        return bool(rows)

    def _skip(self, t: tpl.Template, reason: str) -> None:
        self.stats["skipped"] += 1
        self.store.upsert("hunts", [{"hunt_id": f"{self.run_id}:{t.key}", "run_id": self.run_id, "threat_id": None,
                                     "name": t.name, "template": t.key, "origin": "template", "technique": t.technique,
                                     "query": t.render(self.lookback), "status": "skipped", "row_count": 0,
                                     "error": reason, "started_at": utcnow(), "duration_s": 0}])

    def run_all(self) -> dict:
        self.behaviour_hunts()
        log.info("Hunts: %s", self.stats)
        return self.stats

