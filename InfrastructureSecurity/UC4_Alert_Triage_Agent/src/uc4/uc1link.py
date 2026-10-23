"""'Fix it with UC1': read UC1's fix plan (UC1/data/fix/plan.json + state.json), READ-ONLY, and list the software
fixes UC1 has for the devices on an incident. UC4 never runs fixes: the link opens UC1's Fix Centre, where a person
approves them. Missing or unreadable UC1 files simply mean "no UC1 information".
"""

from __future__ import annotations

import json
from pathlib import Path

UC1_FIX_CENTRE = "http://127.0.0.1:8700/fix"
STATUS_LABEL = {"done": "fixed", "approved": "approved, waiting to run", "running": "running now",
                "failed": "failed - see UC1", "verified": "fixed and verified"}


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def fixes_for(uc1_dir: Path | None, device_names: list[str]) -> dict:
    if not uc1_dir:
        return {"available": False, "fixes": []}
    plan = _read(uc1_dir / "data" / "fix" / "plan.json")
    state = _read(uc1_dir / "data" / "fix" / "state.json").get("fixes", {})
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
                    "actively_exploited": int(item.get("kev") or 0), "ransomware": int(item.get("ransomware") or 0),
                    "note": item.get("note") or "", "status": STATUS_LABEL.get(status, status),
                    "open": status not in ("done", "verified")})
    out.sort(key=lambda f: (not f["open"], -f["actively_exploited"], -f["ransomware"], f["app"] or ""))
    return {"available": True, "fixes": out, "open": sum(f["open"] for f in out),
            "exploited_open": sum(1 for f in out if f["open"] and f["actively_exploited"]),
            "fix_centre": UC1_FIX_CENTRE, "plan_time": plan.get("generated_at")}
