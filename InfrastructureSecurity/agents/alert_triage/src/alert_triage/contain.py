"""Containment stretch (OFF by default; UC4_CONTAIN=1 turns it on): a HUMAN clicks "Approve isolate" on the
website, confirms, and only then is a LAB device isolated in Defender (Selective isolation: it keeps its link to
Defender). "Release" undoes it. The AI and the schedule can never call this.

Allowed only for device names in UC4_LAB_DEVICES (default opca-wks-01, opcc-wks-01) and only for a device that
appears on the incident. Needs WindowsDefenderATP Machine.Isolate.
"""

from __future__ import annotations

import json
import logging

from alert_triage.config import Settings
from alert_triage.feedback import add_action

log = logging.getLogger("alert_triage.contain")


class ContainError(ValueError):
    pass


def _incident_device(settings: Settings, incident_id: str, device_name: str) -> dict:
    from alert_triage.triage import _safe
    path = settings.verdicts_dir / f"{_safe(incident_id)}.json"
    if not path.is_file():
        raise ContainError("unknown incident")
    packet = json.loads(path.read_text(encoding="utf-8"))["packet"]
    for d in packet["entities"]["devices"]:
        if (d.get("name") or "").lower() == device_name.lower():
            return d
    raise ContainError("that device is not on this incident")


def act(settings: Settings, defender, incident_id: str, device_name: str, action: str) -> dict:
    if not settings.contain:
        raise ContainError("Isolation is switched off in the settings (needs your manager’s OK).")
    if action not in ("isolate_device", "release_device"):
        raise ContainError("unknown action")
    name = (device_name or "").lower().strip()
    if name.split(".")[0] not in {d.split(".")[0] for d in settings.lab_devices}:
        raise ContainError("Only the lab devices can be isolated in this PoC.")
    device = _incident_device(settings, incident_id, name)
    if not device.get("id"):
        raise ContainError("Defender device ID missing on the incident")
    comment = f"Security Assistant: {action.replace('_', ' ')} approved in the triage website for incident {incident_id}"
    try:
        if action == "isolate_device":
            result = defender.isolate(device["id"], comment)
        else:
            result = defender.release(device["id"], comment)
    except Exception as exc:  # noqa: BLE001
        add_action(settings, incident_id, action, name, "failed", str(exc).splitlines()[0][:300])
        raise ContainError(f"Defender refused: {str(exc).splitlines()[0][:200]}") from exc
    row = add_action(settings, incident_id, action, name, "done",
                     f"Defender action {result.get('id', '?')} status {result.get('status', '?')}", done=True)
    log.info("%s on %s for incident %s (human-approved)", action, name, incident_id)
    return row
