"""Exposure findings: one finding per threat and device it affects, connected to the device's OpCo, the users who
logged on and related Defender alerts.

Signs of attack (hunt hits) are the Attack Detection Agent's findings; they arrive through `attack_import` and this
step leaves them alone.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import timedelta

from threat_intel.api_client import ApiError, DefenderClient
from threat_intel.store import Store, to_utc, utcnow

log = logging.getLogger("threat_intel.correlate")

SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon"}

USERS_QUERY = """DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceId in ({ids})
| where ActionType == "LogonSuccess"
| summarize LastLogon = max(Timestamp), Logons = count() by DeviceId, AccountDomain, AccountName, LogonType
| take 1000"""


def kql_string(value: str) -> str:
    """Verbatim KQL string literal: @"..." with embedded quotes doubled (backslashes stay literal)."""
    return '@"' + value.replace('"', '""') + '"'


def _fid(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:20]


def _users(client: DefenderClient | None, device_ids: list[str]) -> dict[str, list[dict]]:
    if not client or not device_ids:
        return {}
    ids = ", ".join(kql_string(d) for d in device_ids)
    try:
        rows = client.run_query(USERS_QUERY.format(ids=ids))
    except ApiError as exc:
        log.warning("User lookup failed: %s", exc.detail[:200])
        return {}
    users: dict[str, dict[str, dict]] = {}
    for r in rows:
        name = (r.get("AccountName") or "").lower()
        if not name or name in SYSTEM_ACCOUNTS or name.startswith(("dwm-", "umfd-")) or name.endswith("$"):
            continue
        account = f"{r.get('AccountDomain') or ''}\\{r.get('AccountName')}".lstrip("\\")
        # one entry per account, even when it logged on in several ways (console, remote, network...)
        u = users.setdefault(r["DeviceId"], {}).setdefault(
            account.lower(), {"account": account, "logon_types": [], "last_logon": "", "logons": 0})
        if r.get("LogonType") and r["LogonType"] not in u["logon_types"]:
            u["logon_types"].append(r["LogonType"])
        u["last_logon"] = max(u["last_logon"], str(to_utc(r.get("LastLogon"))))
        u["logons"] += int(r.get("Logons") or 0)
    return {dev: sorted(v.values(), key=lambda u: u["last_logon"], reverse=True) for dev, v in users.items()}


def _alerts(client: DefenderClient | None, days: int = 30) -> tuple[dict[str, list[dict]], str | None]:
    if not client:
        return {}, "Defender not configured"
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        rows = client.get_all("/api/alerts", {"$filter": f"alertCreationTime ge {since}", "$top": 1000})
    except ApiError as exc:
        return {}, f"alerts not available: {exc.detail[:150]}"
    by_device: dict[str, list[dict]] = {}
    for a in rows:
        by_device.setdefault(a.get("machineId"), []).append({
            "id": a.get("id"), "title": a.get("title"), "severity": a.get("severity"), "status": a.get("status"),
            "category": a.get("category"), "time": str(to_utc(a.get("alertCreationTime"))),
            "techniques": a.get("mitreTechniques") or []})
    return by_device, None


def run(store: Store, client: DefenderClient | None, run_id: str) -> dict:
    now = utcnow()
    devices = {d["device_id"]: d for d in store.query("SELECT * FROM devices")}
    exposure = store.query("SELECT * FROM exposure WHERE match_type = 'cve'")
    users = _users(client, sorted({e["device_id"] for e in exposure}))
    alerts, alert_note = _alerts(client)

    store.execute("DELETE FROM findings WHERE kind = 'exposure'")
    findings = []
    by_threat_device: dict[tuple, list[str]] = {}
    for e in exposure:
        by_threat_device.setdefault((e["threat_id"], e["device_id"]), []).append(e["detail"])
    for (tid, dev), details in by_threat_device.items():
        d = devices.get(dev, {})
        findings.append({"finding_id": _fid("exposure", tid, dev), "threat_id": tid, "hunt_id": None, "kind": "exposure",
                         "device_id": dev, "device_name": d.get("device_name"), "opco": d.get("opco"),
                         "detail": "; ".join(sorted(details))[:1000], "users": users.get(dev, [])[:5],
                         "alerts": alerts.get(dev, [])[:5], "timeline": [], "is_test": False,
                         "first_hit": None, "created_at": now})
    store.upsert("findings", findings)
    stats = {"exposure_findings": len(findings),
             "hit_findings": store.scalar("SELECT COUNT(*) FROM findings WHERE kind <> 'exposure'") or 0,  # from Attack Detection
             "alerts_note": alert_note}
    log.info("Correlation: %s", stats)
    return stats
