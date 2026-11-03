"""Connect evidence: turn hunt hits into findings and connect the dots:
finding -> device -> OpCo -> users who logged on -> related Defender alerts -> timeline.

In the PoC, lab tests count as real findings (MARK_LAB_TESTS is off): the 12 lab tests use realistic names, so the
demo looks like a real attack. With MARK_LAB_TESTS on, the EICAR test file and the AMSI test sample are marked
is_test so reports never present them as real attacks. Which devices a threat affects (exposure) is the Threat
Intel Agent's job, not this one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
from datetime import timedelta

from attack_detection.api_client import ApiError, DefenderClient
from attack_detection.hunting import templates as tpl
from attack_detection.indicators import content_hash
from attack_detection.store import NEW_IDS_SHOWN, Store, to_utc, utcnow

log = logging.getLogger("attack_detection.correlate")

MARK_LAB_TESTS = False            # PoC: lab test results are counted and reported as real findings
EICAR_SHA256 ="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
AMSI_TEST = "7e72c3ce-861b-4339-8740-0ac1484f1386"        # Microsoft's harmless AMSI test sample
ENC_ARG = re.compile(r"(?i)\s[-/]e[a-z]*\s+([A-Za-z0-9+/=]{16,})")
SYSTEM_ACCOUNTS = {"system", "local service", "network service", "anonymous logon"}
OPEN_DOOR_DAYS = 14               # attack 12: a sign of attacks 1-11 this recent on a machine with a high-rated weakness

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
    if not MARK_LAB_TESTS:
        return False
    text = json.dumps(row, default=str).lower()
    return EICAR_SHA256 in text or "eicar" in text or AMSI_TEST in text or "amsi_test" in text


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
    tid = f"hunt:{hunt['template']}" + (":test" if is_test else "")
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


def _blocked_only(finding: dict) -> bool:
    """Every Defender alert on it is Informational (e.g. a test file Defender prevented): not a sign of an attack in use."""
    try:
        alerts = json.loads(finding.get("alerts") or "[]") if isinstance(finding.get("alerts"), str) else finding.get("alerts") or []
    except ValueError:
        return False
    return bool(alerts) and all(str(a.get("severity", "")).lower() == "informational" for a in alerts)


def _open_doors(store: Store, known: dict, now) -> list[dict]:
    """Attack 12, search 4: a machine with a Critical or High exploitable vulnerability (an attack 12 hit) that also
    shows a sign of attacks 1 to 11 within OPEN_DOOR_DAYS becomes one 'open door in use now' finding."""
    attack_of = {key: t.attack for key, t in tpl.load().items()}
    rows = store.query("""SELECT f.*, h.template FROM findings f JOIN hunts h ON h.hunt_id = f.hunt_id
                          WHERE f.kind IN ('behaviour_hit', 'exposure') AND NOT f.is_test""")
    doors = []
    for door in (r for r in rows if r["template"] == "bh_exposure_hot_cve"):
        since = now - timedelta(days=OPEN_DOOR_DAYS)
        clues = [r for r in rows if r["device_id"] == door["device_id"] and 1 <= attack_of.get(r["template"], 0) <= 11
                 and r["first_hit"] and to_utc(r["first_hit"]) >= since and not _blocked_only(r)]
        if not clues:
            continue
        hunt = {"template": "open_door", "origin": "template", "technique": "T1190",
                "name": "Open door in use now (a high-rated weakness and a sign of attack on the same machine)"}
        tid = _hunt_threat(store, hunt, False)
        detail = hunt["name"].split(" (")[0]
        fid = _fid("behaviour_hit", tid, door["device_id"], detail)
        timeline = [{"time": str(c["first_hit"]), "what": f"Sign of attack {attack_of[c['template']]}: {c['detail']}",
                     "account": None} for c in sorted(clues, key=lambda c: str(c["first_hit"]))]
        timeline.insert(0, {"time": str(door["first_hit"]), "what": f"Weakness: {door['detail']}", "account": None})
        doors.append({"finding_id": fid, "threat_id": tid, "hunt_id": door["hunt_id"], "kind": "behaviour_hit",
                      "device_id": door["device_id"], "device_name": door["device_name"], "opco": door["opco"],
                      "detail": detail, "users": door["users"], "alerts": door["alerts"], "timeline": timeline,
                      "is_test": False, "first_hit": min(to_utc(c["first_hit"]) for c in clues),
                      "created_at": (known.get(fid) or {}).get("created_at") or now})
    return doors


def run(store: Store, client: DefenderClient | None, run_id: str) -> dict:
    now = utcnow()
    devices = {d["device_id"]: d for d in store.query("SELECT * FROM devices")}
    hunts = {h["hunt_id"]: h for h in store.query("SELECT * FROM hunts WHERE run_id = ? AND status = 'ok'", [run_id])}
    results = store.query("""SELECT r.* FROM hunt_results r JOIN hunts h ON h.hunt_id = r.hunt_id
                             WHERE h.run_id = ? AND h.status = 'ok'""", [run_id])

    # ---- group hits
    groups: dict[tuple, dict] = {}
    for r in results:
        row = json.loads(r["row_json"]) if isinstance(r["row_json"], str) else r["row_json"]
        hunt = hunts[r["hunt_id"]]
        test = is_lab_test(row)
        # a weakness alone (exploitable vulnerability) is exposure, not an attack: it only shows as an "open door"
        # when a sign of attack is on the same machine (_open_doors)
        kind = "exposure" if hunt["template"] == "bh_exposure_hot_cve" else "behaviour_hit"
        key = (kind, hunt["template"] + (hunt["technique"] or ""), r["device_id"], test)
        g = groups.setdefault(key, {"hunt": hunt, "rows": [], "detail": hunt["name"].split(" (")[0], "is_test": test})
        g["rows"].append((r, row))

    involved = sorted({k[2] for k in groups if k[2]})
    users = _users(client, involved)
    alerts, alert_note = _alerts(client)

    # Signs of attack are kept from run to run: a run adds the new ones and refreshes the ones it finds again
    known = {r["finding_id"]: r for r in store.query("SELECT finding_id, first_hit, created_at FROM findings WHERE kind <> 'exposure'")}
    findings = []
    for key, g in groups.items():
        kind, _, dev, _ = key
        hunt = g["hunt"]
        tid = _hunt_threat(store, hunt, g["is_test"])
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
    doors = _open_doors(store, known, now)
    store.upsert("findings", doors)
    findings += doors
    new = [f for f in findings if f["finding_id"] not in known]
    stats = {"new_hits": len(new),                                  # found for the first time in this run
             "new_hit_ids": [f["finding_id"] for f in new][:NEW_IDS_SHOWN],   # the dashboard's run page names them
             "hit_findings": store.scalar("SELECT COUNT(*) FROM findings WHERE kind <> 'exposure'") or 0,   # all kept
             "test_hits": sum(f["is_test"] for f in new),
             "alerts_note": alert_note}
    log.info("Correlation: %s", stats)
    return stats
