"""'Fix it with Threat Intel': read Threat Intel's fix plan (Threat Intel/data/fix/plan.json + state.json), READ-ONLY, and list the software
fixes Threat Intel has for the devices on an incident. Alert Triage never runs fixes: the link opens Threat Intel's Fix Centre, where a person
approves them. Missing or unreadable Threat Intel files simply mean "no Threat Intel information".
"""

from __future__ import annotations

import json
from pathlib import Path

FIX_CENTRE_URL = "http://127.0.0.1:8700/fix"
STATUS_LABEL = {"done": "fixed", "approved": "approved, waiting to run", "running": "running now",
                "failed": "failed - see Threat Intel", "verified": "fixed and verified"}


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def fixes_for(threat_intel_dir: Path | None, device_names: list[str]) -> dict:
    if not threat_intel_dir:
        return {"available": False, "fixes": []}
    plan = _read(threat_intel_dir / "data" / "fix" / "plan.json")
    state = _read(threat_intel_dir / "data" / "fix" / "state.json").get("fixes", {})
    if not plan:
        return {"available": False, "fixes": []}
    names = {(d or "").lower().split(".")[0] for d in device_names if d}
    out = []
    for item in plan.get("items", []):
        if (item.get("device_name") or "").lower().split(".")[0] not in names:
            continue
        if (item.get("action") or "none") == "none":
            continue
        status = (state.get(item.get("fix_id"), {}) or {}).get("status") or "not approved yet"
        out.append({"device": item.get("device_name"), "app": item.get("app") or item.get("software_name"),
                    "version": item.get("version"), "action": item.get("action"),
                    "note": item.get("note") or "", "status": STATUS_LABEL.get(status, status),
                    "open": status not in ("done", "verified")})
    out.sort(key=lambda f: (not f["open"], f["app"] or ""))
    return {"available": True, "fixes": out, "open": sum(f["open"] for f in out),
            "fix_centre": FIX_CENTRE_URL, "plan_time": plan.get("generated_at")}
