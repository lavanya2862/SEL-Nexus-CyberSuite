"""Phase 4a: Gemini reads each new/changed threat and returns checked, structured facts.

- Only threats without a current analysis are sent (cached by content hash).
- IOC-list and TEST threats are described by code (the AI adds nothing there) to save quota.
- Calls run in parallel (GEMINI_WORKERS) under the RPM limit; results are written by the main thread.
- If Gemini is unavailable, items get a rules-only summary and ai_status 'pending' and are retried next run.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from uc1.ai.gemini_client import AIUnavailable, GeminiClient
from uc1.ai.guard import check
from uc1.ai.prompts import EXTRACT_SYSTEM, extract_prompt
from uc1.ai.schemas import ThreatAnalysis
from uc1.store import Store, utcnow

log = logging.getLogger("uc1.analyse")


def pending(store: Store, limit: int) -> list[dict]:
    """Threats needing analysis, most important first (exposed, actively exploited, newest)."""
    return store.query("""
        SELECT t.* FROM threats t LEFT JOIN analysis a ON a.threat_id = t.threat_id
        WHERE a.threat_id IS NULL OR a.content_hash IS DISTINCT FROM t.content_hash
              OR a.ai_status IN ('pending', 'failed')
        ORDER BY (t.threat_id IN (SELECT threat_id FROM exposure)) DESC, (t.kind = 'kev') DESC,
                 t.first_seen_at DESC, t.published_at DESC NULLS LAST
        LIMIT ?""", [limit])


def rules_only(threat: dict, status: str, error: str | None = None, model: str | None = None) -> dict:
    text = " ".join((threat.get("text") or "").split())
    return {"threat_id": threat["threat_id"], "summary": text[:400] + ("…" if len(text) > 400 else ""),
            "threat_type": "indicator_list" if threat["kind"] in ("ioc", "test") else "other",
            "products": [], "techniques": [], "actions": [], "confidence": "n/a", "ai_status": status,
            "ai_model": model, "dropped": {}, "error": error, "content_hash": threat.get("content_hash"),
            "analysed_at": utcnow()}


def _upsert(store: Store, row: dict, first: dict) -> None:
    """Save an analysis row, keeping the time the threat was FIRST assessed (for the 'time to assess' metric)."""
    assessed = row["ai_status"] in ("done", "skipped")
    row["first_assessed_at"] = first.get(row["threat_id"]) or (row["analysed_at"] if assessed else None)
    store.upsert("analysis", [row])


def backfill_first_assessed(store: Store) -> None:
    """Rows saved before 1 Oct 2026 have no first_assessed_at: use the end of the first run after the threat was
    first seen (analysis happens in the same run), else the last analysis time."""
    store.execute("""
        UPDATE analysis SET first_assessed_at = COALESCE(
            (SELECT MIN(r.finished_at) FROM runs r JOIN threats t ON t.threat_id = analysis.threat_id
             WHERE r.finished_at >= t.first_seen_at), analysed_at)
        WHERE first_assessed_at IS NULL AND ai_status IN ('done', 'skipped')""")


def _save(store: Store, threat: dict, result: dict, dropped: dict, model: str, first: dict) -> None:
    tid = threat["threat_id"]
    _upsert(store, {
        "threat_id": tid, "summary": result["summary"], "threat_type": result["threat_type"],
        "products": result["products"], "techniques": result["techniques"], "actions": result["actions"],
        "confidence": result["confidence"], "ai_status": "done", "ai_model": model, "dropped": dropped,
        "error": None, "content_hash": threat.get("content_hash"), "analysed_at": utcnow()}, first)
    store.link(tid, "cve", result["cves"], origin="ai")
    store.link(tid, "technique", [t["id"] for t in result["techniques"]], origin="ai")
    store.link(tid, "ioc", [f"{i['type']}|{i['value']}" for i in result["indicators"]], origin="ai")
    store.link(tid, "product", [f"{p['vendor']}|{p['product']}" for p in result["products"]], origin="ai")


def run(store: Store, ai: GeminiClient | None, limit: int = 2000, workers: int = 8) -> dict:
    todo = pending(store, limit)
    stats = {"candidates": len(todo), "ai_done": 0, "rules_only": 0, "failed": 0, "dropped_items": 0}
    techniques = {r["technique_id"] for r in store.query("SELECT technique_id FROM attack_techniques")}
    backfill_first_assessed(store)
    first = {r["threat_id"]: r["first_assessed_at"] for r in store.query(
        "SELECT threat_id, first_assessed_at FROM analysis WHERE first_assessed_at IS NOT NULL")}

    for_ai = []
    for t in todo:
        if t["kind"] in ("ioc", "test"):
            _upsert(store, rules_only(t, "skipped"), first)
            stats["rules_only"] += 1
        else:
            for_ai.append(t)

    if ai is None:
        for t in for_ai:
            _upsert(store, rules_only(t, "pending", "AI not configured"), first)
        stats["rules_only"] += len(for_ai)
        return stats

    known = {}
    for r in store.query("SELECT threat_id, value FROM threat_links WHERE link_type = 'cve' AND origin <> 'ai'"):
        known.setdefault(r["threat_id"], set()).add(r["value"])

    def work(threat):
        return ai.json("extract", EXTRACT_SYSTEM, extract_prompt(threat), ThreatAnalysis)

    try:
        model = ai.model()
    except AIUnavailable as exc:
        for t in for_ai:
            _upsert(store, rules_only(t, "pending", str(exc)), first)
        stats["rules_only"] += len(for_ai)
        stats["error"] = str(exc)
        return stats

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(work, t): t for t in for_ai}
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                analysis = fut.result()
            except AIUnavailable as exc:
                _upsert(store, rules_only(t, "pending", str(exc), model), first)
                stats["failed"] += 1
                continue
            except Exception as exc:  # noqa: BLE001
                _upsert(store, rules_only(t, "failed", str(exc)[:300], model), first)
                stats["failed"] += 1
                continue
            result, dropped = check(analysis, t.get("text") or "", known.get(t["threat_id"], set()), techniques)
            _save(store, t, result, dropped, model, first)
            stats["ai_done"] += 1
            stats["dropped_items"] += sum(len(v) for v in dropped.values())
    log.info("Analysis: %s", stats)
    return stats
