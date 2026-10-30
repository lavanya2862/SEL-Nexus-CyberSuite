"""Checks on AI output: anything the AI claims must be backed by the source or a trusted catalogue.

- CVEs must appear in the source text (or already be linked by the feed).
- Technique IDs must exist in the MITRE ATT&CK catalogue (when it is loaded).
- Indicators must be valid AND appear in the source text.
Dropped items are recorded, so the report can show how often the AI was corrected.
"""

from __future__ import annotations

import re

from threat_intel.ai.schemas import ThreatAnalysis
from threat_intel.feeds.common import find_cves
from threat_intel.feeds.iocs import normalise_ioc

TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ALLOWED_TYPES = {"vulnerability", "malware", "phishing", "campaign", "indicator_list", "advisory", "other"}


def _refang(text: str) -> str:
    return (text or "").replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http").lower()


def check(analysis: ThreatAnalysis, source_text: str, known_cves: set[str], techniques: set[str]) -> tuple[dict, dict]:
    """Return (clean result, dropped items)."""
    dropped: dict[str, list[str]] = {"cves": [], "techniques": [], "indicators": []}
    source_cves = set(find_cves(source_text)) | known_cves
    cves = []
    for c in analysis.cves:
        c = c.strip().upper()
        (cves if c in source_cves else dropped["cves"]).append(c)

    techs = []
    for t in analysis.techniques[:6]:
        tid = t.id.strip().upper()
        if TECH_RE.match(tid) and (not techniques or tid in techniques):
            techs.append({"id": tid, "reason": t.reason[:200]})
        else:
            dropped["techniques"].append(tid)

    refanged = _refang(source_text)
    indicators = []
    for i in analysis.indicators[:50]:
        clean = normalise_ioc(i.type, i.value)
        if clean and clean[1].lower() in refanged:
            indicators.append({"type": clean[0], "value": clean[1]})
        else:
            dropped["indicators"].append(f"{i.type}:{i.value}")

    words = analysis.summary.split()
    summary = " ".join(words[:110]) + (" …" if len(words) > 110 else "")
    result = {
        "summary": summary,
        "threat_type": analysis.threat_type if analysis.threat_type in ALLOWED_TYPES else "other",
        "cves": list(dict.fromkeys(cves)),
        "products": [p.model_dump() for p in analysis.products[:10] if p.product.strip()],
        "techniques": techs,
        "indicators": indicators,
        "actions": [a[:300] for a in analysis.actions[:5]],
        "confidence": analysis.confidence if analysis.confidence in ("high", "medium", "low") else "medium",
    }
    return result, {k: v for k, v in dropped.items() if v}


NUM_RE = re.compile(r"\b\d+(?:[.,]\d+)?\b")


def numbers_supported(text: str, facts_json: str) -> bool:
    """Every number in an AI summary must appear in the facts it was given (tiny counts 0-5 excepted)."""
    facts_numbers = set(NUM_RE.findall(facts_json))
    return all(n in facts_numbers or (n.isdigit() and int(n) <= 5) for n in NUM_RE.findall(text))
