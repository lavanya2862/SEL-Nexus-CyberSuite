"""Fix steps for every threat that affects our computers, written by Gemini and checked by code.

- Threats count when Defender lists one of their CVEs on our computers (exact match, as everywhere in UC1).
- Input: the threat (title, summary, CVEs, the source's own advice) and where Defender found it on our computers,
  with the update Defender recommends. The source text is untrusted and goes in a data block.
- Each threat is advised once and kept; it is advised again when the computers or versions it affects change, or
  when it only got standard steps because the AI was unavailable.
- Check: a step that names a CVE or a version number that is not in the data is dropped. If fewer than two steps
  survive, the threat gets standard steps built from Defender's recommended updates instead.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re

from uc1.ai.gemini_client import AIUnavailable, GeminiClient
from uc1.ai.prompts import FIX_SYSTEM, fix_prompt
from uc1.ai.schemas import FixAdvice
from uc1.config import Settings
from uc1.store import Store, dumps, utcnow

log = logging.getLogger("uc1.fix_advice")

MAX_AI_PER_RUN = 25
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")


def _j(value):
    if value is None:
        return []
    return json.loads(value) if isinstance(value, str) else value


def affected(store: Store) -> list[dict]:
    """Threats that affect our computers (real ones), most urgent first, with where and what Defender recommends."""
    threats = store.query("""
        SELECT t.threat_id, t.title, t.source, t.kind, t.text, t.content_hash, a.summary, a.actions, s.score, s.rating
        FROM threats t JOIN scores s USING (threat_id) LEFT JOIN analysis a USING (threat_id)
        WHERE NOT t.is_test AND t.threat_id IN (SELECT threat_id FROM exposure WHERE match_type = 'cve')
        ORDER BY s.score DESC, t.threat_id""")
    exposure: dict[str, list[dict]] = {}
    for e in store.query("""SELECT threat_id, device_name, detail, recommended_update FROM exposure
                            WHERE match_type = 'cve' ORDER BY device_name, detail"""):
        exposure.setdefault(e["threat_id"], []).append(e)
    cves: dict[str, list[dict]] = {}
    for c in store.query("""SELECT l.threat_id, c.cve_id, c.cvss, c.kev_added, c.kev_ransomware FROM threat_links l
                            JOIN cves c ON c.cve_id = l.value WHERE l.link_type = 'cve'"""):
        cves.setdefault(c["threat_id"], []).append(c)
    for t in threats:
        t["exposure"] = exposure.get(t["threat_id"], [])
        t["cves"] = cves.get(t["threat_id"], [])[:20]
        t["basis"] = hashlib.sha256(dumps([t["content_hash"], [(e["device_name"], e["detail"], e["recommended_update"])
                                                               for e in t["exposure"]]]).encode()).hexdigest()[:20]
    return threats


def evidence(t: dict) -> str:
    lines = [f"Threat: {t['title']}", f"Source: {t['source']}", f"Our risk rating: {t['rating']} ({t['score']}/100)",
             f"Summary: {t['summary'] or 'n/a'}"]
    if t["cves"]:
        lines.append("CVEs: " + "; ".join(f"{c['cve_id']} (CVSS {c['cvss'] or '?'}"
                                           + (", known exploited" if c["kev_added"] else "")
                                           + (", used by ransomware" if c["kev_ransomware"] == "Known" else "") + ")"
                                           for c in t["cves"]))
    lines.append("Where Microsoft Defender found it on our computers:")
    lines += [f"- {e['device_name']}: {e['detail']}" + (f" -> Defender recommends: {e['recommended_update']}"
                                                         if e["recommended_update"] else "") for e in t["exposure"][:30]]
    actions = _j(t["actions"])
    if actions:
        lines.append("What the source advises: " + "; ".join(actions[:5]))
    lines.append("Source text (untrusted):\n" + (t["text"] or "")[:2500])
    return "\n".join(lines)


def standard(t: dict) -> dict:
    """Defender's recommended update per computer, then the source's advice: used when the AI is unavailable."""
    steps = [f"On {e['device_name']}: {e['recommended_update']}." for e in t["exposure"] if e["recommended_update"]]
    steps = list(dict.fromkeys(steps))[:4]
    if not steps:
        devices = ", ".join(dict.fromkeys(e["device_name"] for e in t["exposure"]))
        steps = [f"Update or remove the affected software on {devices} (see the vulnerability list in Microsoft Defender)."]
    steps += [a for a in _j(t["actions"])[:2] if a not in steps]
    steps.append("After 24 hours, check in Microsoft Defender that the vulnerability no longer shows for these computers.")
    return {"steps": steps, "done_when": "Microsoft Defender no longer lists this threat's vulnerabilities on any of our computers.",
            "source": "standard", "model": None, "dropped": []}


def checked(answer: FixAdvice, text: str) -> tuple[list[str], list[str]]:
    """Keep the steps whose CVE IDs and version numbers all appear in the data."""
    known = text.lower()
    keep, dropped = [], []
    for step in answer.steps[:6]:
        names = CVE_RE.findall(step) + VERSION_RE.findall(step)
        (keep if all(n.lower() in known for n in names) else dropped).append(step[:400])
    return keep, dropped


def advise_one(t: dict, ai: GeminiClient) -> dict:
    text = evidence(t)
    answer = ai.json("fix_advice", FIX_SYSTEM, fix_prompt(text), FixAdvice, max_tokens=1200)
    steps, dropped = checked(answer, text)
    if len(steps) < 2:
        return {**standard(t), "dropped": dropped}
    return {"steps": steps, "done_when": answer.done_when[:300], "source": "ai", "model": ai.model(), "dropped": dropped}


def run(store: Store, settings: Settings, ai: GeminiClient | None) -> dict:
    have = {r["threat_id"]: r for r in store.query("SELECT threat_id, basis, source FROM threat_fixes")}
    todo = [t for t in affected(store)
            if t["threat_id"] not in have or have[t["threat_id"]]["basis"] != t["basis"] or have[t["threat_id"]]["source"] != "ai"]
    ai_note = None if ai else "AI not configured"
    done = {"ai": 0, "standard": 0}
    for i, t in enumerate(todo):
        res = None
        if ai and not ai_note and i < MAX_AI_PER_RUN:
            try:
                res = advise_one(t, ai)
            except AIUnavailable as exc:
                ai_note = str(exc)
                log.warning("AI fix steps unavailable: %s", exc)
        if res is None:
            old = have.get(t["threat_id"])
            if old and old["basis"] == t["basis"]:
                continue                      # unchanged, already has standard steps: retry the AI next run
            res = standard(t)
        done[res["source"]] += 1
        store.upsert("threat_fixes", [{"threat_id": t["threat_id"], "basis": t["basis"], "steps": dumps(res["steps"]),
                                       "done_when": res["done_when"], "source": res["source"], "model": res["model"],
                                       "dropped": dumps(res["dropped"]), "created_at": utcnow()}])
    total = len(affected(store))
    by_ai = store.scalar("""SELECT COUNT(*) FROM threat_fixes f WHERE f.source = 'ai'
                            AND f.threat_id IN (SELECT threat_id FROM exposure WHERE match_type = 'cve')""") or 0
    out = {"threats": total, "by_ai": by_ai, "new_ai": done["ai"], "new_standard": done["standard"]}
    if ai_note:
        out["ai_note"] = ai_note[:200]
    log.info("Fix steps: %s", out)
    return out


def for_threats(store: Store) -> dict[str, dict]:
    """threat_id -> fix steps, for the report and the detail pages."""
    return {r["threat_id"]: {"steps": _j(r["steps"]), "done_when": r["done_when"], "source": r["source"], "model": r["model"]}
            for r in store.query("SELECT * FROM threat_fixes")}
