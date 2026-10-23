"""Choose which playbook handles an incident, from its alert titles, detection sources and MITRE techniques.

Playbooks are YAML files in config/playbooks/. Each lists match rules; the first that matches wins (by file name
order). An incident that matches nothing gets the `generic` playbook. This is deterministic and testable; the AI is
never asked to pick the playbook.

Playbooks with `scope: sentinel` are only for Sentinel incidents (sign-ins, Office activity: no device to search) and
are tried first for them, so a device playbook never catches a Sentinel incident by a shared title word.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from uc4.config import CONFIG_DIR


def load_playbooks(base: Path | None = None) -> list[dict]:
    folder = (base or CONFIG_DIR) / "playbooks"
    books = []
    for path in sorted(folder.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        data["id"] = data.get("id") or path.stem
        data["_file"] = path.name
        books.append(data)
    return books


def _matches(match: dict, titles: list[str], techniques: set[str], detections: set[str], categories: set[str]) -> bool:
    """A playbook matches if ANY of its listed conditions is met (title substring, technique, detection, category).
    An empty `match` never matches, so only the explicit `generic` fallback catches leftovers."""
    if not match:
        return False
    if match.get("always"):
        return True
    any_title = [t.lower() for t in match.get("any_title", [])]
    if any_title and any(sub in title for title in titles for sub in any_title):
        return True
    any_tech = {t.upper() for t in match.get("any_technique", [])}
    tech_with_base = techniques | {t.split(".")[0] for t in techniques}
    if any_tech and (any_tech & tech_with_base):
        return True
    any_det = {d.lower() for d in match.get("any_detection_source", [])}
    if any_det and (any_det & detections):
        return True
    any_cat = {c.lower() for c in match.get("any_category", [])}
    if any_cat and (any_cat & categories):
        return True
    return False


def route(packet: dict, playbooks: list[dict]) -> dict:
    titles = [a["title"].lower() for a in packet["alerts"]]
    techniques = set(packet["techniques"])
    detections = {d.lower() for d in packet["detection_sources"]}
    categories = {a["category"].lower() for a in packet["alerts"] if a.get("category")}
    sentinel = packet.get("source") == "sentinel"
    # catch-all Sentinel playbooks (`always: true`) are tried after the specific ones
    scoped = sorted((b for b in playbooks if b.get("scope") == "sentinel"),
                    key=lambda b: bool((b.get("match") or {}).get("always")))
    for book in (scoped if sentinel else []) + [b for b in playbooks if b.get("scope") != "sentinel"]:
        if book["id"] == "generic":
            continue
        if _matches(book.get("match", {}), titles, techniques, detections, categories):
            return book
    return next((b for b in playbooks if b["id"] == "generic"), {"id": "generic", "queries": [], "guardrails": []})
