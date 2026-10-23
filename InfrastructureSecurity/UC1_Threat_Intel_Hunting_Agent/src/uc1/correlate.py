"""Phase 6: turn exposure and hunt hits into findings, and connect the dots:
finding -> device -> OpCo -> users who logged on -> related Defender alerts -> timeline.

Lab tests are recognised automatically (EICAR hash, the 'UC1 lab test' marker in a decoded PowerShell
command, TEST indicators) and marked is_test so reports never present them as real attacks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
from datetime import timedelta

from uc1.api_client import ApiError, DefenderClient
from uc1.feeds.common import content_hash
from uc1.hunting import templates as tpl
from uc1.store import Store, to_utc, utcnow

log = logging.getLogger("uc1.correlate")

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
LAB_MARKER = "uc1 lab test"
ENC_ARG = re.compile(r"(?i)\s[-/]e[a-z]*\s+([A-Za-z0-9+/=]{16,})")
SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon"}

USERS_QUERY = """DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceId in ({ids})
| where ActionType == "LogonSuccess"
| summarize LastLogon = max(Timestamp), Logons = count() by DeviceId, AccountDomain, AccountName, LogonType
| take 1000"""


def decode_powershell(command: str | None) -> str | None:
    """Decode the base64 (UTF-16LE) payload of 'powershell -EncodedCommand ...' for the analyst."""
    m = ENC_ARG.search(command or "")
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le", errors="replace")[:500]
    except (binascii.Error, ValueError):
        return None


def is_lab_test(row: dict) -> bool:
    text = json.dumps(row, default=str).lower()
    decoded = (decode_powershell(row.get("ProcessCommandLine")) or "").lower()
    return EICAR_SHA256 in text or "eicar" in text or LAB_MARKER in decoded


def _fid(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:20]


def _users(client: DefenderClient | None, device_ids: list[str]) -> dict[str, list[dict]]:
    if not client or not device_ids:
        return {}
    ids = ", ".join(tpl.kql_string(d) for d in device_ids)
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


def _hunt_threat(store: Store, hunt: dict, is_test: bool) -> str:
    """Behaviour hits become their own threat item ('Proactive hunt: ...') so they flow into scoring and reports."""
    tid = f"hunt:{hunt['template'] if hunt['origin'] != 'ai' else 'ai-' + (hunt['technique'] or '')}" + (":test" if is_test else "")
    name = hunt["name"].split(" (")[0]
    text = (f"Proactive behaviour hunt '{name}' (ATT&CK {hunt['technique'] or 'n/a'}) found matching activity on our "
            f"devices in Microsoft Defender." + (" LAB TEST: this activity was created on purpose with a harmless "
                                                   "test script." if is_test else ""))
    store.add_threats([{"threat_id": tid, "source": "Proactive hunt", "kind": "hunt",
                        "title": ("TEST: " if is_test else "") + f"Hunt hit: {name}", "text": text, "url": "",
                        "published_at": utcnow(), "content_hash": content_hash(text), "is_test": is_test}])
    if hunt["technique"]:
        store.link(tid, "technique", [hunt["technique"]])
    return tid


def run(store: Store, client: DefenderClient | None, run_id: str) -> dict:
    now = utcnow()
    devices = {d["device_id"]: d for d in store.query("SELECT * FROM devices")}
    hunts = {h["hunt_id"]: h for h in store.query("SELECT * FROM hunts WHERE run_id = ? AND status = 'ok'", [run_id])}
    results = store.query("""SELECT r.* FROM hunt_results r JOIN hunts h ON h.hunt_id = r.hunt_id
                             WHERE h.run_id = ? AND h.status = 'ok'""", [run_id])
    ioc_threats: dict[str, set[str]] = {}
    for l in store.query("SELECT threat_id, value FROM threat_links WHERE link_type = 'ioc'"):
        ioc_threats.setdefault(l["value"], set()).add(l["threat_id"])
    test_threats = {r["threat_id"] for r in store.query("SELECT threat_id FROM threats WHERE is_test")}

    # ---- group hits
    groups: dict[tuple, dict] = {}
    for r in results:
        row = json.loads(r["row_json"]) if isinstance(r["row_json"], str) else r["row_json"]
        hunt = hunts[r["hunt_id"]]
        if "_matched" in row:                                   # IOC sweep
            for value in row["_matched"]:
                for tid in ioc_threats.get(f"{row['_ioc_type']}|{value}", ()):
                    key = ("ioc_hit", tid, r["device_id"], value)
                    g = groups.setdefault(key, {"threat_id": tid, "hunt": hunt, "rows": [], "detail": f"matched {row['_ioc_type']} {value}",
                                                "is_test": tid in test_threats})
                    g["rows"].append((r, row))
        else:                                                   # behaviour / AI hunt
            test = is_lab_test(row)
            key = ("behaviour_hit", hunt["template"] + (hunt["technique"] or ""), r["device_id"], test)
            g = groups.setdefault(key, {"threat_id": None, "hunt": hunt, "rows": [], "detail": hunt["name"].split(" (")[0],
                                        "is_test": test})
            g["rows"].append((r, row))

    # ---- exposure findings (current state)
    exposure = store.query("SELECT * FROM exposure WHERE match_type = 'cve'")
    involved = sorted({k[2] for k in groups if k[2]} | {e["device_id"] for e in exposure})
    users = _users(client, involved)
    alerts, alert_note = _alerts(client)

    store.execute("DELETE FROM findings WHERE kind = 'exposure'")
    # Signs of attack are kept from run to run: a run adds the new ones and refreshes the ones it finds again
    known = {r["finding_id"]: r for r in store.query("SELECT finding_id, first_hit, created_at FROM findings WHERE kind <> 'exposure'")}
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

    for key, g in groups.items():
        kind, _, dev, _ = key
        hunt = g["hunt"]
        tid = g["threat_id"] or _hunt_threat(store, hunt, g["is_test"])
        times = sorted(r["event_time"] for r, _ in g["rows"] if r["event_time"])
        first = times[0] if times else None
        timeline = []
        for r, row in sorted(g["rows"], key=lambda x: x[0]["event_time"] or now)[:25]:
            decoded = decode_powershell(row.get("ProcessCommandLine"))
            timeline.append({"time": str(r["event_time"]), "what": f"Hunt '{hunt['name'].split(' (')[0]}': {r['summary']}"
                             + (f" | decoded command: {decoded}" if decoded else ""), "account": r["account"]})
        near = [a for a in alerts.get(dev, []) if first and abs((to_utc(a["time"]) - first).total_seconds()) <= 86400]
        timeline += [{"time": a["time"], "what": f"Defender alert: {a['title']} ({a['severity']}, {a['status']})",
                      "account": None} for a in near]
        timeline.sort(key=lambda x: x["time"])
        d = devices.get(dev, {})
        fid = _fid(kind, tid, dev, g["detail"])
        prev = (known.get(fid) or {}).get("first_hit")
        findings.append({"finding_id": fid, "threat_id": tid, "hunt_id": hunt["hunt_id"], "kind": kind,
                         "device_id": dev, "device_name": d.get("device_name") or g["rows"][0][0]["device_name"],
                         "opco": d.get("opco", "Unassigned"), "detail": g["detail"], "users": users.get(dev, [])[:5],
                         "alerts": near[:10], "timeline": timeline, "is_test": g["is_test"],
                         "first_hit": min(x for x in (prev, first) if x) if (prev or first) else None,
                         "created_at": (known.get(fid) or {}).get("created_at") or now})   # when this run first found it
    store.upsert("findings", findings)
    new = [f for f in findings if f["kind"] != "exposure" and f["finding_id"] not in known]
    stats = {"exposure_findings": sum(f["kind"] == "exposure" for f in findings),
             "new_hits": len(new),                                  # found for the first time in this run
             "hit_findings": store.scalar("SELECT COUNT(*) FROM findings WHERE kind <> 'exposure'") or 0,   # all kept
             "test_hits": sum(f["is_test"] for f in new),
             "alerts_note": alert_note}
    log.info("Correlation: %s", stats)
    return stats
