"""The fix plan: one row per computer x app version that Defender says is vulnerable, with what to do about it,
plus one row per computer x security setting that Defender says is wrong.

What to do comes ONLY from config/fix_catalog.csv (app -> update / remove / replace, winget + Chocolatey IDs,
the uninstall name pattern) and config/setting_fix_catalog.csv (setting -> attack-protection rule, Defender
Antivirus option or registry value, and the value it must have). The AI is not involved. The plan is rebuilt after
every inventory, and the same step verifies earlier fixes: a fix is "verified" when Defender no longer lists that
app version (or that wrong setting) on that computer.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import re
from datetime import datetime, timedelta

from uc1.config import Settings, read_csv
from uc1.fix.state import FixState, event
from uc1.store import Store, utcnow

STAGES = {1: "Urgent", 2: "End-of-life", 3: "Other updates", 4: "No action needed"}
ACTIONS = {"upgrade", "remove", "replace", "none"}
PACKAGE_ID = re.compile(r"^[A-Za-z0-9.+_-]{1,80}$")
PATTERN = re.compile(r"^[A-Za-z0-9 .+_()*{}-]{1,60}$")
PROCESS = re.compile(r"^[A-Za-z0-9 .+_-]{1,40}$")
STILL_THERE_AFTER = timedelta(hours=24)       # Defender normally notices a change within 2-6 hours
OPEN = ("approved", "queued", "running")


def load_catalog() -> dict[str, dict]:
    """The allow-list. Rows with odd characters are refused, so a bad edit can't inject a command."""
    catalog = {}
    for row in read_csv("fix_catalog.csv"):
        name = row.get("software_name", "").lower()
        action = row.get("action", "").lower()
        if not name or action not in ACTIONS:
            continue
        for key in ("winget_id", "choco_id"):
            if row.get(key) and not PACKAGE_ID.match(row[key]):
                raise ValueError(f"fix_catalog.csv: bad {key} for {name}")
        if row.get("match") and not PATTERN.match(row["match"]):
            raise ValueError(f"fix_catalog.csv: bad match pattern for {name}")
        procs = [p for p in row.get("processes", "").split(";") if p]
        if any(not PROCESS.match(p) for p in procs):
            raise ValueError(f"fix_catalog.csv: bad process name for {name}")
        catalog[name] = {**row, "software_name": name, "action": action, "processes": procs,
                         "stage": int(row.get("stage") or 3)}
    return catalog


SETTING_KINDS = {"asr", "defender", "registry"}
CONFIG_ID = re.compile(r"^scid-\d{1,6}$")
ASR_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
# the Defender Antivirus options UC1 may change (Set-MpPreference), nothing else
DEFENDER_OPTIONS = {"DisableEmailScanning", "PUAProtection", "DisableRemovableDriveScanning", "EnableNetworkProtection",
                    "EnableControlledFolderAccess"}
REG_PATH = re.compile(r"^HKLM:\\(SOFTWARE|SYSTEM)\\[A-Za-z0-9 _.\\-]{1,200}$")
REG_NAME = re.compile(r"^[A-Za-z0-9_]{1,60}$")
SETTING_STAGE = 3


def load_setting_catalog() -> dict[str, dict]:
    """The settings allow-list: config_id -> {name, kind, target, value, note}. Odd rows are refused, so a bad edit
    can't inject a command: the script on the computer only knows these three kinds of change."""
    catalog = {}
    for row in read_csv("setting_fix_catalog.csv"):
        cid, kind, target = row.get("config_id", "").lower(), row.get("kind", "").lower(), row.get("target", "")
        if not cid:
            continue
        if not CONFIG_ID.match(cid) or kind not in SETTING_KINDS:
            raise ValueError(f"setting_fix_catalog.csv: bad config_id or kind for {cid}")
        try:
            value = int(row.get("value", ""))
        except ValueError:
            raise ValueError(f"setting_fix_catalog.csv: value must be a whole number for {cid}") from None
        if kind == "asr" and not ASR_ID.match(target.lower()):
            raise ValueError(f"setting_fix_catalog.csv: bad attack-protection rule id for {cid}")
        if kind == "defender" and target not in DEFENDER_OPTIONS:
            raise ValueError(f"setting_fix_catalog.csv: {target} is not an allowed Defender option ({cid})")
        if kind == "registry":
            path, _, name = target.rpartition("|")
            if not REG_PATH.match(path) or not REG_NAME.match(name) or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError(f"setting_fix_catalog.csv: bad registry path, name or value for {cid}")
        catalog[cid] = {"config_id": cid, "name": row.get("name") or cid, "kind": kind,
                        "target": target.lower() if kind == "asr" else target, "value": value, "note": row.get("note", "")}
    return catalog


def fix_id(device_name: str, software: str, version: str) -> str:
    return "fx_" + hashlib.sha1(f"{device_name}|{software}|{version}".lower().encode()).hexdigest()[:12]


def ver2(version: str) -> str:
    return ".".join((version or "").split(".")[:2])


def build_spec(item: dict, allow_choco: bool = True) -> dict:
    """What the script on the VM gets (base64 JSON). Built from the catalogue row only."""
    action = item["action"]
    if action == "respond":
        return {"id": item["fix_id"], "action": "respond", "kind": "scan_clean", "check": [], "remove": [], "procs": [],
                "allow_choco": False}
    if action == "setting":
        return {"id": item["fix_id"], "action": "setting", "kind": item["setting_kind"], "target": item["setting_target"],
                "value": item["setting_value"], "check": [], "remove": [], "procs": [], "allow_choco": False}
    match = (item.get("match") or "").replace("{ver2}", ver2(item["version"]))
    check = [match] if action != "replace" else [match.split()[0] + "*"]
    return {"id": item["fix_id"], "action": action, "winget": item.get("winget_id") or "",
            "choco": item.get("choco_id") or "", "check": check,
            "remove": [match] if action in ("remove", "replace") else [],
            "procs": item.get("processes") or [], "allow_choco": allow_choco}


def probe_spec(catalog: dict[str, dict]) -> dict:
    patterns = sorted({(c["match"].replace("{ver2}", "*") if c.get("match") else "") for c in catalog.values()} - {""})
    return {"id": "probe", "action": "probe", "check": patterns, "procs": [], "remove": []}


def setting_items(store: Store, settings: Settings, catalog: dict[str, dict] | None = None,
                  limit_devices: bool = True) -> list[dict]:
    """One row per computer x wrong security setting. Not a vulnerability: findings/CVEs stay 0, so the
    vulnerability numbers are not mixed with settings."""
    catalog = catalog if catalog is not None else load_setting_catalog()
    rows = store.query("""
        SELECT s.device_id, s.device_name, COALESCE(d.opco, 'Unassigned') AS opco, s.config_id, s.name, s.category,
               s.subcategory, COALESCE(s.impact, 0) AS impact, s.snapshot_at
        FROM device_settings s LEFT JOIN devices d ON d.device_id = s.device_id""")
    items = []
    for r in rows:
        if limit_devices and settings.fix_devices and r["device_name"].lower() not in settings.fix_devices:
            continue
        cat = catalog.get(r["config_id"])
        item = {"device_id": r["device_id"], "device_name": r["device_name"], "opco": r["opco"], "kind": "setting",
                "software_name": f"setting:{r['config_id']}", "config_id": r["config_id"], "vendor": "", "version": "",
                "app": (cat or {}).get("name") or r["name"] or r["config_id"], "category": r["category"],
                "subcategory": r["subcategory"], "impact": r["impact"],
                "fix_id": fix_id(r["device_name"], f"setting:{r['config_id']}", ""),
                "findings": 0, "cves": 0, "kev": 0, "ransomware": 0, "max_epss": 0, "max_cvss": 0, "kev_cves": [],
                "winget_id": "", "choco_id": "", "match": "", "processes": [], "stage": SETTING_STAGE,
                "snapshot_at": r["snapshot_at"].isoformat() if isinstance(r["snapshot_at"], datetime) else r["snapshot_at"]}
        if cat:
            item.update(action="setting", setting_kind=cat["kind"], setting_target=cat["target"],
                        setting_value=cat["value"], note=cat["note"])
        else:
            # not in config/setting_fix_catalog.csv (add a row there to make it fixable)
            item.update(action="none", stage=4, note="Needs an IT person: changing it on one computer could lock "
                                                     "people out, so the portal leaves it alone")
        items.append(item)
    return items


RESPONSE_STAGE = 1
_EVIDENCE = re.compile(r"^Hunt '[^']*': ")


def response_items(store: Store, settings: Settings, limit_devices: bool = True) -> list[dict]:
    """One row per sign of attack (attack check finding): scan that computer with Defender and remove what it finds.
    The only response the fix engine can do with its permissions (Machine.LiveResponse / Azure Run Command);
    isolating a computer needs Machine.Isolate and stays a job for a person in Defender. Not a vulnerability:
    findings/CVEs stay 0. Findings are kept from run to run, so these rows never turn "verified"."""
    rows = store.query("""
        SELECT f.finding_id, f.kind, f.device_id, f.device_name, COALESCE(f.opco, d.opco, 'Unassigned') AS opco,
               f.detail, f.timeline, f.is_test, f.created_at
        FROM findings f LEFT JOIN devices d ON d.device_id = f.device_id
        WHERE f.kind <> 'exposure' AND f.device_name IS NOT NULL""")
    items = []
    for r in rows:
        if limit_devices and settings.fix_devices and r["device_name"].lower() not in settings.fix_devices:
            continue
        timeline = json.loads(r["timeline"]) if isinstance(r["timeline"], str) else (r["timeline"] or [])
        evidence = _EVIDENCE.sub("", str((timeline[-1] if timeline else {}).get("what") or ""))[:200]
        sign = "Warning sign found" if r["kind"] == "ioc_hit" else "Suspicious behaviour"
        items.append({
            "device_id": r["device_id"], "device_name": r["device_name"], "opco": r["opco"], "kind": "response",
            "software_name": f"response:{r['finding_id']}", "finding_id": r["finding_id"], "vendor": "", "version": "",
            "app": r["detail"] or sign, "fix_id": fix_id(r["device_name"], f"response:{r['finding_id']}", ""),
            "findings": 0, "cves": 0, "kev": 0, "ransomware": 0, "max_epss": 0, "max_cvss": 0, "kev_cves": [],
            "winget_id": "", "choco_id": "", "match": "", "processes": [], "stage": RESPONSE_STAGE, "action": "respond",
            "category": sign + (" (test)" if r["is_test"] else ""), "note": evidence,
            "snapshot_at": r["created_at"].isoformat() if isinstance(r["created_at"], datetime) else r["created_at"]})
    return items


def threats_by_fix(store: Store) -> dict[tuple, list[dict]]:
    """(device_id, software, version) -> the news threats that target it on that computer (exact CVE exposure:
    the threat names a CVE that Defender lists for this app version there). Most urgent first, at most 3."""
    rows = store.query("""
        SELECT DISTINCT v.device_id, v.name, v.version, e.threat_id, t.title, COALESCE(s.score, 0) AS score
        FROM device_vulns v
        JOIN exposure e ON e.device_id = v.device_id AND e.match_type = 'cve' AND e.detail LIKE v.cve_id || ' via %'
        LEFT JOIN threats t ON t.threat_id = e.threat_id LEFT JOIN scores s ON s.threat_id = e.threat_id""")
    out: dict[tuple, list[dict]] = {}
    for r in sorted(rows, key=lambda r: -r["score"]):
        found = out.setdefault((r["device_id"], r["name"], r["version"]), [])
        if len(found) < 3 and all(f["id"] != r["threat_id"] for f in found):
            found.append({"id": r["threat_id"], "title": (r["title"] or r["threat_id"])[:140]})
    return out


def compute(store: Store, settings: Settings, catalog: dict[str, dict] | None = None, limit_devices: bool = True,
            setting_catalog: dict[str, dict] | None = None) -> list[dict]:
    """The plan rows. limit_devices=False ignores FIX_DEVICES (verification needs every computer Defender lists)."""
    catalog = catalog if catalog is not None else load_catalog()
    rows = store.query("""
        SELECT v.device_id, v.device_name, COALESCE(d.opco, 'Unassigned') AS opco, v.name AS software_name,
               v.vendor, v.version, COUNT(*) AS findings, COUNT(DISTINCT v.cve_id) AS cves,
               COUNT(DISTINCT CASE WHEN c.kev_added IS NOT NULL THEN v.cve_id END) AS kev,
               COUNT(DISTINCT CASE WHEN c.kev_ransomware = 'Known' THEN v.cve_id END) AS ransomware,
               MAX(COALESCE(c.epss, 0)) AS max_epss, MAX(COALESCE(v.cvss, c.cvss, 0)) AS max_cvss,
               LIST(DISTINCT CASE WHEN c.kev_added IS NOT NULL THEN v.cve_id END) AS kev_cves,
               MAX(v.snapshot_at) AS snapshot_at
        FROM device_vulns v LEFT JOIN cves c ON c.cve_id = v.cve_id LEFT JOIN devices d ON d.device_id = v.device_id
        GROUP BY ALL""")
    items = []
    for r in rows:
        if limit_devices and settings.fix_devices and r["device_name"].lower() not in settings.fix_devices:
            continue
        cat = catalog.get(r["software_name"].lower())
        item = {**r, "fix_id": fix_id(r["device_name"], r["software_name"], r["version"]),
                "kev_cves": sorted(c for c in (r["kev_cves"] or []) if c), "max_epss": round(r["max_epss"] or 0, 3),
                "snapshot_at": r["snapshot_at"].isoformat() if isinstance(r["snapshot_at"], datetime) else r["snapshot_at"]}
        if cat:
            item.update(app=cat.get("app") or r["software_name"], action=cat["action"], winget_id=cat.get("winget_id", ""),
                        choco_id=cat.get("choco_id", ""), match=cat.get("match", ""), processes=cat["processes"],
                        stage=cat["stage"], note=cat.get("note", ""))
        else:
            item.update(app=r["software_name"], action="none", winget_id="", choco_id="", match="", processes=[],
                        stage=4, note="Not in config/fix_catalog.csv yet: add a row to make it fixable")
        if item["action"] != "none" and item["kev"] and item["stage"] > 1:
            item["stage"] = 1                                     # anything on the CISA KEV list is urgent
        items.append(item)
    threats = threats_by_fix(store)
    for item in items:
        item["threats"] = threats.get((item["device_id"], item["software_name"], item["version"]), [])
    items += setting_items(store, settings, setting_catalog, limit_devices)
    items += response_items(store, settings, limit_devices)
    items.sort(key=lambda i: (i["stage"], -i["ransomware"], -i["kev"], -i["findings"], i["device_name"]))
    return items


def verify(state: FixState, current_ids: set[str], inventory_at: datetime | None, now: datetime | None = None,
           devices: dict[str, datetime | None] | None = None,
           installed: dict[tuple[str, str], set[str]] | None = None) -> dict:
    """Mark fixes verified when Defender no longer lists them. Only inventories taken AFTER the fix count.

    devices = {computer name (lower case): Defender's last-seen time} for every computer in this inventory.
    "Not listed any more" only means "fixed" for a computer that IS in this inventory and that Defender has seen
    since the fix. A computer that is switched off, filtered out (FIX_DEVICES) or missing from Defender's answer
    is left alone, so it can never look fixed by accident. (devices=None: no device check, for old callers.)

    installed = {(computer, Defender software name): versions in this inventory}. Defender's last-seen time lags
    (6 Oct: last seen 18:00, fixes done 18:03-18:05, yet the inventory already listed the new versions), so a
    computer whose inventory lists the fixed app at a DIFFERENT version than the one replaced also counts as
    scanned since the fix: that is direct proof of a post-fix scan.
    """
    now = now or utcnow()
    counts = {"verified": 0, "still_there": 0, "gone": 0}
    if not inventory_at:
        return counts

    def after(stamp: str | None) -> bool:
        return bool(stamp) and inventory_at > datetime.fromisoformat(stamp)

    def seen_since(f: dict, stamp: str | None) -> bool:
        if devices is None:
            return True
        name = str((f.get("item") or {}).get("device_name", "")).lower()
        if not stamp or name not in devices:
            return False
        last_seen = devices[name]
        if last_seen is None or last_seen > datetime.fromisoformat(stamp):
            return True
        item = f.get("item") or {}
        versions = (installed or {}).get((name, str(item.get("software_name", "")).lower()))
        return bool(versions) and str(item.get("version", "")) not in versions

    with state.edit() as data:
        for fid, f in data["fixes"].items():
            status = f.get("status")
            done_at, decided_at = f.get("finished_at"), f.get("approved_at") or f.get("saved_at")
            if fid not in current_ids and status in ("done", "failed", "still_there") and after(done_at) \
                    and seen_since(f, done_at):
                f.update(status="verified", verified_at=now.isoformat())
                event(data, f"Verified by Defender: {_label(f)} is no longer vulnerable", fid)
                counts["verified"] += 1
            elif fid not in current_ids and status in ("approved", "saved") and after(decided_at) and seen_since(f, decided_at):
                f.update(status="gone", verified_at=now.isoformat())
                event(data, f"{_label(f)} disappeared from Defender before UC1 fixed it", fid)
                counts["gone"] += 1
            elif fid in current_ids and status == "done" and (f.get("item") or {}).get("kind") != "response" \
                    and after(done_at) and seen_since(f, done_at) and \
                    now - datetime.fromisoformat(done_at) > STILL_THERE_AFTER:
                f["status"] = "still_there"
                event(data, f"Still listed by Defender 24 h after the fix: {_label(f)}", fid)
                counts["still_there"] += 1
    return counts


def _label(f: dict) -> str:
    return _what(f.get("item", {}))


def _what(item: dict) -> str:
    """"WinRAR 5.80 on opca-wks-01" or, for a setting (no version), "Block ... on opca-wks-01"."""
    app = " ".join(p for p in (str(item.get("app") or "?"), str(item.get("version") or "")) if p)
    return f"{app} on {item.get('device_name', '?')}"


# The agents whose runs end with this step, and the fixes each one is about. One fix is one card: an app fix that a
# news threat targets belongs to both the Vulnerability and the Threat Intel Agent, and one decision covers both.
DOMAINS = {
    "vulnerability": lambda i: i.get("kind") != "response",                          # Defender's vulnerabilities + settings
    "threat_intel": lambda i: i.get("kind") != "response" and bool(i.get("threats")),  # ... that a threat in the news targets
    "attack_detection": lambda i: i.get("kind") == "response",                        # responses to signs of attack
}
SOURCES = set(DOMAINS)


def refresh(store: Store, settings: Settings, source: str | None = None) -> dict:
    """Pipeline step: rebuild data/fix/plan.json and verify earlier fixes.

    Every row keeps found_by = {agent: when that agent's run first flagged it} (None = before this was recorded).
    New fixes for this run = fixable rows in the agent's domain (DOMAINS) that this agent had not flagged yet and
    nobody has decided on (plan["new_ids"]); the agent's Fix stage shows them as cards to fix or save for later.
    A manual `fix-plan` (no source) flags nothing.
    """
    settings.fix_dir.mkdir(parents=True, exist_ok=True)
    source = source if source in SOURCES else None
    previous = {i["fix_id"]: i for i in read_plan(settings).get("items", [])}
    # first plan with found_by: whatever the old plan had was found before recording started (no flood of "new")
    migrating = bool(previous) and not any("found_by" in i for i in previous.values())
    everything = compute(store, settings, limit_devices=False)      # verification looks at every computer
    items = [i for i in everything if not settings.fix_devices or i["device_name"].lower() in settings.fix_devices]
    inventory_at = store.scalar("SELECT MAX(snapshot_at) FROM devices")
    devices = {str(r["device_name"]).lower(): r["last_seen"]
               for r in store.query("SELECT device_name, last_seen FROM devices") if r["device_name"]}
    installed: dict[tuple[str, str], set[str]] = {}
    for r in store.query("SELECT device_name, name, version FROM software"):
        installed.setdefault((str(r["device_name"]).lower(), str(r["name"]).lower()), set()).add(str(r["version"]))
    state = FixState(settings.fix_dir / "state.json")
    checked = verify(state, {i["fix_id"] for i in everything}, inventory_at, devices=devices, installed=installed)
    decided = state.read()["fixes"]
    fixable = [i for i in items if i["action"] != "none"]
    now = utcnow().isoformat()
    for item in items:
        old = previous.get(item["fix_id"])
        found = dict((old or {}).get("found_by") or {})
        if (old or {}).get("proposed_by"):                           # plans from the day before found_by
            found.setdefault(old["proposed_by"], old.get("proposed_at"))
        if migrating and old is not None:
            for agent, belongs in DOMAINS.items():
                if belongs(item):
                    found.setdefault(agent, None)
        item["found_by"] = found
    new_ids = []
    if source:
        for item in fixable:
            if DOMAINS[source](item) and source not in item["found_by"]:
                item["found_by"][source] = now
                if item["fix_id"] not in decided:
                    new_ids.append(item["fix_id"])
    plan = {"generated_at": now, "inventory_at": inventory_at.isoformat() if inventory_at else None,
            "stages": STAGES, "items": items, "new_ids": new_ids}
    (settings.fix_dir / "plan.json").write_text(json.dumps(plan, default=str, ensure_ascii=False), encoding="utf-8")
    waiting = sum(1 for i in fixable if i["fix_id"] not in decided and i["fix_id"] not in new_ids)
    saved = sum(1 for f in decided.values() if f.get("status") == "saved")
    return {"items": len(items), "fixable": len(fixable), "urgent": sum(1 for i in fixable if i["stage"] == 1),
            "new": len(new_ids), "new_ids": new_ids[:200], "waiting": waiting, "saved": saved,
            # what kind of fixes are new, so the run page links to the right Fix & protect tab
            "new_settings": sum(1 for i in fixable if i["fix_id"] in new_ids and i.get("kind") == "setting"),
            "new_apps": sum(1 for i in fixable if i["fix_id"] in new_ids and not i.get("kind")), **checked}


def read_plan(settings: Settings) -> dict:
    path = settings.fix_dir / "plan.json"
    if not path.is_file():
        return {"items": [], "stages": STAGES, "generated_at": None}
    return json.loads(path.read_text(encoding="utf-8"))


def view(settings: Settings) -> dict:
    """Plan + state merged: what the Fix Centre shows. Fixes that left the plan (verified) stay visible."""
    plan = read_plan(settings)
    data = FixState(settings.fix_dir / "state.json").read()
    rows, seen = [], set()
    for item in plan.get("items", []):
        f = data["fixes"].get(item["fix_id"], {})
        rows.append(_row(item, f))
        seen.add(item["fix_id"])
    for fid, f in data["fixes"].items():
        if fid not in seen and f.get("item"):
            rows.append(_row(f["item"], f))
    total = {s: sum(1 for r in rows if r["status"] == s) for s in
             ("proposed", "saved", "approved", "queued", "running", "done", "failed", "verified", "still_there", "gone", "info")}
    fixed = [r for r in rows if r["status"] == "verified"]
    return {"generated_at": plan.get("generated_at"), "inventory_at": plan.get("inventory_at"), "stages": plan.get("stages", STAGES),
            "rows": rows, "totals": total, "events": data["events"][-60:][::-1], "probes": data.get("probes", {}),
            "default_method": settings.fix_method,
            "impact": {"findings_open": sum(r["findings"] for r in rows if r["status"] not in ("verified", "gone")),
                       "findings_cleared": sum(r["findings"] for r in fixed),
                       "kev_cleared": sum(r["kev"] for r in fixed),
                       "kev_open": sum(r["kev"] for r in rows if r["status"] not in ("verified", "gone"))}}


def _row(item: dict, f: dict) -> dict:
    status = f.get("status") or ("info" if item.get("action") == "none" else "proposed")
    return {**{k: item.get(k) for k in ("fix_id", "device_name", "opco", "app", "software_name", "version", "action",
                                        "winget_id", "stage", "findings", "cves", "kev", "ransomware", "max_epss",
                                        "kev_cves", "note", "kind", "config_id", "category", "subcategory", "impact",
                                        "found_by", "threats",
                                        "setting_kind", "setting_target", "setting_value")},
            "status": status, **{k: f.get(k) for k in ("method", "approved_by", "approved_at", "saved_by", "saved_at",
                                                      "started_at", "finished_at",
                                                      "verified_at", "message", "result")}}


def approve(settings: Settings, ids: list[str], method: str | None = None, who: str | None = None) -> dict:
    method = (method or settings.fix_method).lower()
    if method not in ("runcommand", "liveresponse"):
        raise ValueError("method must be runcommand or liveresponse")
    items = {i["fix_id"]: i for i in read_plan(settings).get("items", [])}
    who = who or _user()
    done, skipped = [], []
    with FixState(settings.fix_dir / "state.json").edit() as data:
        for fid in ids:
            item = items.get(fid)
            current = data["fixes"].get(fid, {}).get("status")
            if not item or item["action"] == "none" or current in OPEN + ("verified",):
                skipped.append(fid)
                continue
            spec = build_spec(item, settings.fix_allow_choco)
            data["fixes"][fid] = {"status": "approved", "method": method, "approved_by": who,
                                  "approved_at": utcnow().isoformat(), "item": item, "spec": spec}
            event(data, f"Approved by {who} ({_METHOD[method]}): {_what(item)}", fid)
            done.append(fid)
    return {"approved": done, "skipped": skipped}


def unapprove(settings: Settings, ids: list[str]) -> dict:
    removed = []
    with FixState(settings.fix_dir / "state.json").edit() as data:
        for fid in ids:
            if data["fixes"].get(fid, {}).get("status") in ("approved", "failed", "still_there"):
                f = data["fixes"].pop(fid)
                event(data, f"Approval withdrawn: {_label(f)}", fid)
                removed.append(fid)
    return {"withdrawn": removed}


def save(settings: Settings, ids: list[str], who: str | None = None) -> dict:
    """Save for later: reviewed, not fixed yet. It leaves the new-fix cards and waits in the Fix Centre."""
    items = {i["fix_id"]: i for i in read_plan(settings).get("items", [])}
    who = who or _user()
    saved = []
    with FixState(settings.fix_dir / "state.json").edit() as data:
        for fid in ids:
            item = items.get(fid)
            if not item or item["action"] == "none" or fid in data["fixes"]:
                continue
            data["fixes"][fid] = {"status": "saved", "saved_by": who, "saved_at": utcnow().isoformat(), "item": item}
            event(data, f"Saved for later by {who}: {_what(item)}", fid)
            saved.append(fid)
    return {"saved": saved}


def unsave(settings: Settings, ids: list[str]) -> dict:
    """Undo Save for later: the fix is proposed again."""
    removed = []
    with FixState(settings.fix_dir / "state.json").edit() as data:
        for fid in ids:
            if data["fixes"].get(fid, {}).get("status") == "saved":
                f = data["fixes"].pop(fid)
                event(data, f"No longer saved for later: {_label(f)}", fid)
                removed.append(fid)
    return {"unsaved": removed}


_METHOD = {"runcommand": "Azure Run Command", "liveresponse": "Defender Live Response"}


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"
