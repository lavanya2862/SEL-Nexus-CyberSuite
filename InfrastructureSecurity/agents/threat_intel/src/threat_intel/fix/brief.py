"""The Remediation Agent's brief for every remediation it cannot run itself (plan items with action none).

The AI writes, from the item's facts only: a one-line reason (the card), the cause and the manual steps (the
handover). Nothing explanatory is written by hand: when the AI is not available the brief says so, and the page shows
that instead. Briefs are cached by their facts, so an unchanged item is not asked again (a card shown once per computer
gets a brief written for one computer, shared by every computer with the same item).
"""

from __future__ import annotations

import hashlib
import json
import logging

from threat_intel.config import Settings
from threat_intel.store import utcnow

log = logging.getLogger("threat_intel.fix")
BRIEF_VERSION = 2


def _facts(item: dict) -> dict:
    """What the AI may see: no device or user names, the same for every computer with this item."""
    if item.get("kind") == "setting":
        return {"type": "security setting", "setting": item.get("app"), "category": item.get("category"),
                "subcategory": item.get("subcategory"), "microsoft_impact_score_0_to_10": item.get("impact"),
                "why_it_is_not_automated": item.get("note")}
    return {"type": "application", "application": item.get("app"), "version": item.get("version"),
            "vulnerabilities": item.get("findings"), "why_it_is_not_automated": item.get("note")}


def _key(facts: dict) -> str:
    """Written once per item: the key is what the item is (app and version, or setting), not its counts or note."""
    ident = {k: facts.get(k) for k in ("type", "application", "version", "setting")}
    return "id:" + hashlib.sha256(json.dumps([BRIEF_VERSION, ident], sort_keys=True).encode()).hexdigest()[:16]


def _old_key(facts: dict) -> str:   # before briefs were written once: reused so no brief is asked for again
    return hashlib.sha256(json.dumps([BRIEF_VERSION, facts], sort_keys=True).encode()).hexdigest()[:16]


def attach_briefs(settings: Settings, items: list[dict], client=None) -> dict:
    """Give every action-none item a brief: {reason, cause, steps, model} from the AI, or {unavailable} when there is
    no AI. Returns {"ai": "available" | "not available: ...", "asked": n, "reused": n} for the pipeline."""
    targets = [i for i in items if i.get("action") == "none"]
    path = settings.fix_dir / "brief_cache.json"
    cache = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    need, moved = {}, False
    for item in targets:
        facts = _facts(item)
        key = _key(facts)
        if key not in cache and _old_key(facts) in cache:
            cache[key], moved = cache[_old_key(facts)], True
        if key in cache:
            item["brief"] = cache[key]
        else:
            need.setdefault(key, (facts, []))[1].append(item)
    status = {"ai": "available", "asked": 0, "reused": len(targets) - sum(len(v[1]) for v in need.values())}
    if not need and not moved:
        return status
    from threat_intel.ai.gemini_client import AIUnavailable
    from threat_intel.ai.prompts import BRIEF_SYSTEM, brief_prompt
    from threat_intel.ai.schemas import ManualBrief
    if client is None and need:
        try:
            from threat_intel.ai.azure_client import make_client
            client = make_client(settings)
        except AIUnavailable as exc:
            client, status["ai"] = None, f"not available: {exc}"
        if client is None and status["ai"] == "available":
            status["ai"] = "not available: no AI model is configured (AI_PROVIDER)"
    for key, (facts, its) in need.items():
        brief = None
        if client is not None:
            try:
                b = client.json("brief", BRIEF_SYSTEM, brief_prompt(json.dumps(facts, ensure_ascii=False)), ManualBrief,
                                max_tokens=600)
                brief = {"reason": b.reason.strip(), "cause": b.cause.strip(),
                         "steps": [s.strip() for s in b.steps if s.strip()][:6],
                         "model": getattr(client, "model", lambda: "")(),
                         "at": utcnow().isoformat()}
                cache[key] = brief
                status["asked"] += 1
            except AIUnavailable as exc:
                client, status["ai"] = None, f"not available: {exc}"
            except Exception as exc:  # noqa: BLE001 - one bad answer must not stop the plan
                log.warning("Remediation brief not written for %s: %s", facts.get("application") or facts.get("setting"), exc)
        for item in its:
            item["brief"] = brief or {"unavailable": status["ai"] if status["ai"] != "available"
                                      else "not available: the AI answer could not be used"}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=1, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)
    return status
