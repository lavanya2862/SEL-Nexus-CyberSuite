"""Check the AI's verdict before it is trusted:
  1. It matches the answer format (schemas.TriageVerdict; documented in config/verdict.schema.json).
  2. The verdict is one the playbook allows.
  3. Every evidence item names a source that was actually run/collected, and any device name, account, IP, hash or
     technique it quotes appears in that source (stops invented evidence).
  4. Containment options are only ones in the menu and the playbook allows.
Returns (ok, cleaned_verdict, notes). On failure the caller retries once, then falls back to rules_only.
"""

from __future__ import annotations

import json
import re

from pydantic import ValidationError

from alert_triage.config import read_yaml
from alert_triage.schemas import TriageVerdict

TOKEN = re.compile(r"[A-Za-z0-9._:\-]{3,}")


NON_QUERY_SOURCES = ("threat_intel", "history", "alert", "watchlist", "entity")


def _source_corpus(packet: dict, query_results: list[dict], ti_results: list[dict], history: dict,
                   context: dict | None) -> dict[str, str]:
    """Text available per source id, lower-cased, for the 'evidence must be grounded' check."""
    corpus: dict[str, str] = {}
    for q in query_results:
        corpus[q["id"].lower()] = json.dumps(q.get("rows", []), default=str).lower() if q["status"] == "ok" else ""
    corpus["threat_intel"] = json.dumps(ti_results, default=str).lower() if ti_results else ""
    corpus["history"] = (history.get("note", "") + json.dumps(history.get("prior_verdicts", {}))).lower()
    corpus["alert"] = json.dumps([{"t": a["title"], "c": a["category"], "tech": a["techniques"],
                                   "sev": a["severity"], "src": a["detection_source"]}
                                  for a in packet["alerts"]], default=str).lower()
    ctx = context or {}
    corpus["watchlist"] = json.dumps({"hits": ctx.get("watchlist_hits", {}), "admin": ctx.get("account_is_admin"),
                                      "devices": ctx.get("devices", [])}, default=str).lower()
    corpus["entity"] = json.dumps(packet["entities"], default=str).lower()
    return corpus


def _resolve(qid: str, source: str, corpus: dict[str, str]) -> str | None:
    """Map what the AI cited to a corpus key. 'Q01' -> 'q01_process_tree'; 'threat_intel' -> itself.
    Returns None when the citation names a query that doesn't exist."""
    qid = (qid or "").lower().split("#")[0].strip()
    if qid:
        if qid in corpus:
            return qid
        for key in corpus:
            if key.startswith(qid + "_"):
                return key
        for key in NON_QUERY_SOURCES:
            if key in qid:
                return key
        if re.fullmatch(r"q\d+.*", qid):
            return None
    source = (source or "").lower()
    for key in corpus:                                   # source written as a query name
        if key not in NON_QUERY_SOURCES and (source == key or source.startswith(key.split("_")[0] + "_")):
            return key
    for key in NON_QUERY_SOURCES:
        if key.replace("_", " ") in source.replace("_", " ") or (key == "threat_intel" and "intel" in source):
            return key
    return "entity"


def check(verdict: dict, packet: dict, playbook: dict, query_results: list[dict], ti_results: list[dict],
          history: dict, menu: dict | None = None, context: dict | None = None) -> tuple[bool, dict, list[str]]:
    notes: list[str] = []
    try:
        verdict = TriageVerdict.model_validate(verdict).model_dump()
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()))
        return False, verdict if isinstance(verdict, dict) else {}, [f"format: {where} {first.get('msg', '')}"[:200]]

    allowed = set(playbook.get("allowed_verdicts") or
                  ["likely_true_positive", "likely_false_positive", "benign_positive", "needs_investigation"])
    if verdict["verdict"] not in allowed:
        notes.append(f"verdict '{verdict['verdict']}' not allowed by playbook -> needs_investigation")
        verdict = dict(verdict, verdict="needs_investigation")

    corpus = _source_corpus(packet, query_results, ti_results, history, context)
    kql = {q["id"].lower(): (q.get("query") or "").lower() for q in query_results}   # what a search looked for
    known = corpus["entity"] + corpus["alert"]
    kept = []
    for item in verdict.get("evidence", []):
        key = _resolve(item.get("query_id", ""), item.get("source", ""), corpus)
        if key is None:
            notes.append(f"evidence cites unknown query '{item.get('query_id')}' - dropped")
            continue
        text = corpus.get(key, "")
        if not text and key != "entity":
            notes.append(f"evidence cites '{key}', which returned nothing - dropped")
            continue
        if not _grounded(item.get("finding", ""), text + kql.get(key, ""), known):
            notes.append(f"evidence not supported by {key} - dropped: {item.get('finding','')[:60]}")
            continue
        item = dict(item, query_id=key if key not in NON_QUERY_SOURCES else item.get("query_id", ""))
        kept.append(item)
    verdict = dict(verdict, evidence=kept)
    if not kept and verdict["verdict"] in ("likely_true_positive", "likely_false_positive", "benign_positive"):
        notes.append("no grounded evidence left for a firm verdict -> needs_investigation")
        verdict["verdict"] = "needs_investigation"

    # containment menu
    menu = menu or read_yaml("containment_menu.yaml")
    menu_ids = set((menu.get("options") or {}).keys())
    pb_allowed = set(playbook.get("containment_options") or menu_ids)
    cont = [c for c in verdict.get("containment_options", []) if c in menu_ids and c in pb_allowed]
    if len(cont) != len(verdict.get("containment_options", [])):
        notes.append("removed containment options not in the menu/playbook")
    verdict = dict(verdict, containment_options=cont)

    return True, verdict, notes


FILE_EXT = re.compile(r"\.(exe|dll|ps1|psm1|bat|cmd|vbs|js|hta|com|zip|rar|7z|iso|lnk|msi|scr|docm|xlsm)$")
QUERY_REF = re.compile(r"^q\d+(_[a-z0-9_]+)?$")


def _identifiers(finding: str) -> list[str]:
    """The facts an AI could invent: file names, IPs, hashes, domains, accounts/devices with digits, numbers.
    Plain words are not checked (the first dry run showed that judging prose drops true evidence)."""
    out = []
    for raw in TOKEN.findall(finding or ""):
        t = raw.strip(".:-").lower()
        if len(t) < 3 or QUERY_REF.match(t):
            continue
        if t.isdigit():
            if int(t) > 5:                       # tiny counts 0-5 excepted (as in Threat Intel/Vulnerability)
                out.append(t)
            continue
        if (any(c.isdigit() for c in t) or FILE_EXT.search(t) or "@" in t
                or re.search(r"[a-z0-9-]\.[a-z]{2,}", t)):
            out.append(t)
    return out


def _grounded(finding: str, source_text: str, entity_text: str) -> bool:
    """Every identifier in the finding must appear in the cited source or among the incident's own entities/alerts."""
    return all(t in source_text or t in entity_text for t in _identifiers(finding))
