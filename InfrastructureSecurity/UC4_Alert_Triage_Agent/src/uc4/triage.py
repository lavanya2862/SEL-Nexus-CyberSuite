"""Triage one incident end to end: route -> collect related logs -> threat intel -> history -> context ->
pre-guardrails -> AI verdict (checked, one retry) -> post-guardrails -> store. The AI only reasons; code runs the
tools and enforces safety. Returns the stored verdict dict.
"""

from __future__ import annotations

import json
import logging
import time

from uc4 import guardrails as gr
from uc4 import verdict as vd
from uc4.checker import check
from uc4.config import Settings
from uc4.injection import scan_packet
from uc4.llm import LLM, AIUnavailable
from uc4.packet import summary_row
from uc4.router import route
from uc4.store import Store, to_utc, utcnow
from uc4.tools.context import gather as gather_context
from uc4.tools.history import for_incident
from uc4.tools.logs import LogTools
from uc4.tools.ti import ThreatIntel

log = logging.getLogger("uc4.triage")


class Triage:
    def __init__(self, settings: Settings, store: Store, graph=None, defender=None, llm: LLM | None = None,
                 playbooks=None):
        self.settings = settings
        self.store = store
        self.graph = graph
        self.defender = defender
        self.llm = llm
        self.playbooks = playbooks if playbooks is not None else _load_playbooks()
        self.logs = LogTools(graph, settings) if graph is not None else None
        self.ti = ThreatIntel(settings)
        self.rules_cfg = gr.load()
        self.enabled = {r["id"] for r in self.rules_cfg.get("rules", [])}

    def run_one(self, packet: dict) -> dict:
        started = time.monotonic()
        book = route(packet, self.playbooks)

        # enrichment
        query_results = self.logs.run(book.get("queries", []), packet) if self.logs is not None else []
        ti_results = self.ti.lookup_all(packet) if book.get("ti") else []
        context = gather_context(packet, self.settings, self.defender)
        history = for_incident(self.store, packet, book["id"],
                               int((book.get("history") or {}).get("days", 90)))
        injection_hits = scan_packet(packet)

        # pre-guardrails
        feats = gr.features(packet, query_results, ti_results, context, injection_hits)
        pre = gr.evaluate(self.rules_cfg, self.enabled, feats)

        approved_test = bool(context.get("watchlist_hits", {}).get("approved_admin"))

        # AI verdict, checked, one retry
        verdict, ai_status, notes = self._verdict(packet, book, query_results, ti_results, context, history,
                                                  injection_hits, pre)

        # post-guardrails
        verdict = gr.apply(self.rules_cfg, self.enabled, pre, verdict, feats, approved_test=approved_test)
        verdict["ai_status"] = ai_status
        verdict["checker_notes"] = notes
        verdict = three_outcomes(verdict)

        seconds = round(time.monotonic() - started, 2)
        extra = {"context": context, "history": history, "injection": injection_hits,
                 "playbook": {k: book.get(k) for k in ("id", "label", "description", "notes")}}
        self._store(packet, book, verdict, query_results, ti_results, seconds, extra)
        log.info("Triaged %s -> %s (%s) via %s in %.1fs", packet["incident_id"], verdict["verdict"],
                 verdict["confidence"], book["id"], seconds)
        return verdict

    def _verdict(self, packet, book, query_results, ti_results, context, history, injection_hits, pre):
        if self.llm is None or not getattr(self.llm, "available", False):
            return vd.rules_only(packet, book, pre, ti_results, injection_hits), "rules_only", ["AI not configured"]
        last_notes: list[str] = []
        for attempt in (1, 2):
            try:
                raw = vd.ask(self.llm, packet, book, query_results, ti_results, context, history, injection_hits, pre)
            except AIUnavailable as exc:
                return (vd.rules_only(packet, book, pre, ti_results, injection_hits), "rules_only",
                        [f"AI unavailable: {str(exc)[:150]}"])
            ok, cleaned, notes = check(raw, packet, book, query_results, ti_results, history, context=context)
            last_notes = notes
            if ok:
                return cleaned, "ai", notes
            log.info("Verdict check failed (attempt %d): %s", attempt, "; ".join(notes)[:200])
        return (vd.rules_only(packet, book, pre, ti_results, injection_hits), "rules_rejected",
                ["AI answer rejected by checker"] + last_notes)

    def _store(self, packet, book, verdict, query_results, ti_results, seconds, extra=None):
        self.store.upsert("incidents", [summary_row(packet, book["id"])])
        self.store.upsert("verdicts", [{
            "incident_id": packet["incident_id"], "fingerprint": packet["fingerprint"], "playbook": book["id"],
            "verdict": verdict["verdict"], "confidence": verdict.get("confidence", "low"),
            "recommended_severity": verdict.get("recommended_severity", ""), "escalate": bool(verdict.get("escalate")),
            "guardrails": verdict.get("guardrails", []), "containment": verdict.get("containment_options", []),
            "summary": verdict.get("summary", ""), "ai_status": verdict.get("ai_status", ""),
            "ai_model": getattr(self.llm, "_model", None) if self.llm else None,
            "checker_notes": verdict.get("checker_notes", []),
            "queries_run": sum(1 for q in query_results if q["status"] == "ok"),
            "ti_lookups": len(ti_results), "seconds": seconds, "triaged_at": utcnow(),
        }])
        # full packet + verdict + evidence to disk for the website (it never opens the database)
        self.settings.verdicts_dir.mkdir(parents=True, exist_ok=True)
        path = self.settings.verdicts_dir / f"{_safe(packet['incident_id'])}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"packet": packet, "verdict": verdict, "queries": query_results, "ti": ti_results,
                                   "triaged_at": str(utcnow()), "seconds": seconds, **(extra or {})},
                                  default=str, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)                       # atomic: the website never reads a half-written file


def three_outcomes(verdict: dict) -> dict:
    """Only three outcomes: true positive, false positive, needs review. A benign positive (it happened but is
    harmless, e.g. our own antivirus test) is filed as a false positive; what the AI first said is kept."""
    if verdict.get("verdict") == "benign_positive":
        verdict["ai_said"] = "benign_positive"
        verdict["verdict"] = "likely_false_positive"
    return verdict


def _safe(incident_id: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in str(incident_id))[:80]


def _load_playbooks():
    from uc4.router import load_playbooks
    return load_playbooks()
