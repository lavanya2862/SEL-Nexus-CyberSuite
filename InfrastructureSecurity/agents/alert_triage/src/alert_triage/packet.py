"""Turn one Graph security incident (with its alerts and evidence) into an incident packet: a plain dict that every
later step uses. Text an attacker can influence (command lines, file names, URLs, alert descriptions, e-mail
subjects) is kept under `untrusted` keys so the AI prompt can fence it off.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from urllib.parse import urlsplit

from alert_triage.store import to_utc

MAX_TEXT = 600


def _short(value, n: int = MAX_TEXT) -> str:
    text = str(value or "").replace("\x00", "")
    return text if len(text) <= n else text[:n] + " …"


def _type(evidence: dict) -> str:
    return (evidence.get("@odata.type") or "").rsplit(".", 1)[-1].replace("Evidence", "").lower()


def _sentinel_rule(alert: dict) -> dict | None:
    """The Sentinel analytics rule that raised the alert (Sentinel puts it in additionalData)."""
    extra = alert.get("additionalData") or {}
    if not extra.get("Analytic Rule Name") and not extra.get("Analytic Rule Ids"):
        return None
    def as_list(value) -> list[str]:          # Sentinel sends lists as JSON text
        if isinstance(value, str) and value.startswith("["):
            try:
                value = json.loads(value)
            except ValueError:
                pass
        return [str(v) for v in value][:10] if isinstance(value, list) else ([str(value)] if value else [])
    return {"name": _short(extra.get("Analytic Rule Name"), 200), "ids": as_list(extra.get("Analytic Rule Ids")),
            "template_id": extra.get("AnalyticsTemplateId") or "",
            "data_sources": as_list(extra.get("Data Sources")),
            "results": extra.get("Search Query Results Overall Count") or "",
            "trigger": f"{extra.get('Trigger Operator', '')} {extra.get('Trigger Threshold', '')}".strip()}


_EVIDENCE_NAME = {"file": lambda e: (e.get("fileDetails") or {}).get("fileName"),
                  "process": lambda e: (e.get("imageFile") or {}).get("fileName"),
                  "device": lambda e: e.get("deviceDnsName") or e.get("hostName"),
                  "user": lambda e: (e.get("userAccount") or {}).get("userPrincipalName") or (e.get("userAccount") or {}).get("accountName"),
                  "ip": lambda e: e.get("ipAddress"), "mailbox": lambda e: e.get("primaryAddress"),
                  "registryvalue": lambda e: e.get("registryValueName"), "cloudapplication": lambda e: e.get("displayName")}


def _evidence_verdicts(alert: dict) -> list[dict]:
    """Defender's own verdict on each piece of evidence (malicious / suspicious / unknown) and what it did about it."""
    out = []
    for ev in alert.get("evidence") or []:
        kind = _type(ev)
        name = _EVIDENCE_NAME.get(kind, lambda e: "")(ev) or ""
        out.append({"kind": kind, "name": _short(name, 120), "verdict": ev.get("verdict") or "",
                    "remediation": ev.get("remediationStatus") or ""})
    return out[:12]


def _account(acc: dict | None) -> dict | None:
    # Sentinel rules often map only a full name (e.g. "adele@contoso.com"), which arrives as displayName
    if acc and not (acc.get("accountName") or acc.get("userPrincipalName")) and "@" in (acc.get("displayName") or ""):
        acc = {**acc, "userPrincipalName": acc["displayName"]}
    if not acc or not (acc.get("accountName") or acc.get("userPrincipalName")):
        return None
    return {"name": acc.get("accountName") or (acc.get("userPrincipalName") or "").split("@")[0],
            "domain": acc.get("domainName") or "", "sid": acc.get("userSid") or "",
            "upn": acc.get("userPrincipalName") or "", "aad_id": acc.get("azureAdUserId") or ""}


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).strip("[]"))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast)


def _add(bucket: list, item: dict, key: str) -> None:
    if item and item.get(key) and all(x.get(key) != item[key] for x in bucket):
        bucket.append(item)


def build(incident: dict, lab_devices: tuple[str, ...] = (), source: str | None = None,
          lab_titles: tuple[str, ...] = ()) -> dict:
    alerts_in = incident.get("alerts") or []
    entities: dict[str, list] = {k: [] for k in ("devices", "accounts", "ips", "urls", "domains", "files",
                                                  "processes", "registry", "mailboxes", "messages", "apps")}
    alerts, techniques, services, detections = [], set(), set(), set()
    for a in alerts_in:
        techs = [t.upper() for t in a.get("mitreTechniques") or [] if t]
        techniques.update(techs)
        services.add(a.get("serviceSource") or "")
        detections.add(a.get("detectionSource") or "")
        alerts.append({
            "id": a.get("id"), "title": a.get("title") or "", "severity": (a.get("severity") or "").lower(),
            "category": a.get("category") or "", "status": a.get("status") or "",
            "detection_source": a.get("detectionSource") or "", "service_source": a.get("serviceSource") or "",
            "detector_id": a.get("detectorId") or "", "techniques": techs,
            "created": str(to_utc(a.get("createdDateTime")) or ""),
            "first_activity": str(to_utc(a.get("firstActivityDateTime")) or ""),
            "last_activity": str(to_utc(a.get("lastActivityDateTime")) or ""),
            "investigation_state": a.get("investigationState") or "",
            "classification": a.get("classification") or "", "determination": a.get("determination") or "",
            "threat_family": a.get("threatFamilyName") or "",
            "threat_name": a.get("threatDisplayName") or "", "product": a.get("productName") or "",
            "recommended_actions": _short(a.get("recommendedActions"), 1500),
            "sentinel_rule": _sentinel_rule(a), "evidence_verdicts": _evidence_verdicts(a),
            "untrusted": {"description": _short(a.get("description"), 800)},
            "web_url": a.get("alertWebUrl") or "",
        })
        for ev in a.get("evidence") or []:
            kind, verdict, roles = _type(ev), ev.get("verdict") or "", ev.get("roles") or []
            if kind == "device":
                name = (ev.get("deviceDnsName") or ev.get("hostName") or "").lower()   # Sentinel hosts: hostName only
                _add(entities["devices"], {"id": ev.get("mdeDeviceId") or "", "name": name,
                                           "os": ev.get("osPlatform") or "", "risk": ev.get("riskScore") or "",
                                           "verdict": verdict, "roles": roles}, "name")
                for u in ev.get("loggedOnUsers") or []:
                    _add(entities["accounts"], {"name": u.get("accountName") or "", "domain": u.get("domainName") or "",
                                                "sid": "", "upn": "", "aad_id": "", "logged_on": True}, "name")
            elif kind == "user":
                acc = _account(ev.get("userAccount"))
                if acc:
                    _add(entities["accounts"], {**acc, "verdict": verdict, "roles": roles}, "name")
            elif kind == "ip":
                ip = ev.get("ipAddress") or ""
                _add(entities["ips"], {"value": ip, "public": is_public_ip(ip), "country": ev.get("countryLetterCode") or "",
                                       "verdict": verdict, "roles": roles}, "value")
            elif kind == "url":
                url = ev.get("url") or ""
                _add(entities["urls"], {"value": _short(url, 400), "verdict": verdict, "untrusted": True}, "value")
                host = (urlsplit(url).hostname or "").lower()
                if host and not is_public_ip(host):
                    _add(entities["domains"], {"value": host, "verdict": verdict}, "value")
            elif kind == "file":
                fd = ev.get("fileDetails") or {}
                _add(entities["files"], {"name": _short(fd.get("fileName"), 200), "path": _short(fd.get("filePath"), 300),
                                         "sha256": (fd.get("sha256") or "").lower(), "sha1": (fd.get("sha1") or "").lower(),
                                         "verdict": verdict, "detection": ev.get("detectionStatus") or "",
                                         "remediation": ev.get("remediationStatus") or "",
                                         "device_id": ev.get("mdeDeviceId") or "",
                                         "untrusted": True}, "sha256" if fd.get("sha256") else "name")
            elif kind == "process":
                img, parent = ev.get("imageFile") or {}, ev.get("parentProcessImageFile") or {}
                acc = _account(ev.get("userAccount"))
                if acc:
                    _add(entities["accounts"], {**acc, "roles": roles}, "name")
                entities["processes"].append({
                    "file": _short(img.get("fileName"), 200), "path": _short(img.get("filePath"), 300),
                    "sha256": (img.get("sha256") or "").lower(), "parent": _short(parent.get("fileName"), 200),
                    "account": (acc or {}).get("name", ""), "pid": ev.get("processId"),
                    "created": str(to_utc(ev.get("processCreationDateTime")) or ""), "verdict": verdict,
                    "detection": ev.get("detectionStatus") or "", "remediation": ev.get("remediationStatus") or "",
                    "device_id": ev.get("mdeDeviceId") or "", "sha1": (img.get("sha1") or "").lower(),
                    "untrusted": {"command_line": _short(ev.get("processCommandLine"), 1500)}})
                if img.get("sha256"):
                    _add(entities["files"], {"name": _short(img.get("fileName"), 200), "path": _short(img.get("filePath"), 300),
                                             "sha256": img["sha256"].lower(), "sha1": (img.get("sha1") or "").lower(),
                                             "verdict": verdict, "detection": "", "untrusted": True}, "sha256")
            elif kind in ("registrykey", "registryvalue"):
                entities["registry"].append({"key": _short(ev.get("registryKey"), 300),
                                             "value_name": _short(ev.get("registryValueName"), 200),
                                             "untrusted": {"value": _short(ev.get("registryValue"), 300)}})
            elif kind == "dns":
                host = (ev.get("domainName") or "").lower()
                if host and not is_public_ip(host):
                    _add(entities["domains"], {"value": _short(host, 255), "verdict": verdict}, "value")
            elif kind == "mailbox":
                _add(entities["mailboxes"], {"address": ev.get("primaryAddress") or ""}, "address")
            elif kind == "analyzedmessage":
                entities["messages"].append({"sender_ip": ev.get("senderIp") or "",
                                             "recipient": ev.get("recipientEmailAddress") or "",
                                             "untrusted": {"subject": _short(ev.get("subject"), 300)}})
            elif kind in ("cloudapplication", "oauthapplication"):
                _add(entities["apps"], {"name": ev.get("displayName") or ev.get("appId") or ""}, "name")

    first = min((a["first_activity"] or a["created"] for a in alerts if a["first_activity"] or a["created"]), default="")
    last = max((a["last_activity"] or a["created"] for a in alerts if a["last_activity"] or a["created"]), default="")
    devices = [d["name"].split(".")[0] for d in entities["devices"]]
    lab = {d.lower().split(".")[0] for d in lab_devices}
    if source is None:
        source = "sentinel" if "microsoftSentinel" in services else "defender"
    return {
        "incident_id": str(incident.get("id")),
        "title": _short(incident.get("displayName"), 300),
        "severity": (incident.get("severity") or "").lower(),
        "status": incident.get("status") or "",
        "classification": incident.get("classification") or "",
        "determination": incident.get("determination") or "",
        "created_at": str(to_utc(incident.get("createdDateTime")) or ""),
        "updated_at": str(to_utc(incident.get("lastUpdateDateTime")) or ""),
        "web_url": incident.get("incidentWebUrl") or "",
        "source": source,
        "services": sorted(s for s in services if s),
        "detection_sources": sorted(s for s in detections if s),
        "alerts": alerts,
        "entities": entities,
        "techniques": sorted(techniques),
        "first_activity": first, "last_activity": last,
        "is_lab": bool(lab & set(devices)) or any(a["title"].lower().startswith(("uc4 lab", "alert triage lab")) for a in alerts)   # lab alert titles from before the rename say "UC4 lab"
        or any(a["title"].strip().lower().startswith(t) for a in alerts for t in lab_titles if t),
        "fingerprint": fingerprint(alerts),
    }


def fingerprint(alerts: list[dict]) -> str:
    """Changes when an alert is added or is resolved / reopened: then the incident is triaged again. "new" and
    "inProgress" count as the same open state, so Alert Triage's own escalation (which sets the alerts to in progress)
    doesn't trigger a re-triage."""
    def state(status) -> str:
        return "open" if str(status or "").lower() in ("new", "inprogress", "unknown", "") else str(status).lower()
    key = "|".join(sorted(f"{a.get('id')}:{state(a.get('status'))}" for a in alerts))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def summary_row(p: dict, playbook: str) -> dict:
    """The `incidents` table row for a packet."""
    return {
        "incident_id": p["incident_id"], "title": p["title"], "severity": p["severity"], "status": p["status"],
        "classification": p["classification"], "determination": p["determination"],
        "created_at": to_utc(p["created_at"]), "updated_at": to_utc(p["updated_at"]), "web_url": p["web_url"],
        "alert_count": len(p["alerts"]), "sources": ",".join(p["services"]) or p["source"],
        "devices": [d["name"] for d in p["entities"]["devices"]],
        "accounts": [a["name"] for a in p["entities"]["accounts"]],
        "techniques": p["techniques"], "playbook": playbook, "fingerprint": p["fingerprint"],
        "is_lab": p["is_lab"], "origin": p.get("origin", "live"),
    }
