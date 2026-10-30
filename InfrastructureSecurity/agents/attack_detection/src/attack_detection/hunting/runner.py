"""Phase 5: run hunts in Defender Advanced Hunting.

1. IOC sweeps: all IOCs of recent threats (and TEST indicators), batched per type, so a few queries cover
   hundreds of indicators. Hits are mapped back to the IOC value and so to the threat(s).
2. Behaviour hunts: every behaviour template, each run.
3. AI-drafted hunts: for ATT&CK techniques of High/Critical threats that no template covers. Gemini drafts,
   the validator checks, Defender runs; on a syntax error Gemini gets one chance to fix it. Working drafts are
   cached and reused.
"""

from __future__ import annotations

import logging
import time
from datetime import timedelta

from attack_detection.ai.gemini_client import AIUnavailable, GeminiClient
from attack_detection.ai.prompts import KQL_SYSTEM, kql_fix_prompt, kql_prompt
from attack_detection.ai.schemas import KqlDraft
from attack_detection.api_client import ApiError, DefenderClient
from attack_detection.indicators import allowlisted
from attack_detection.hunting import templates as tpl
from attack_detection.hunting.validator import ensure_limit, validate
from attack_detection.store import Store, to_utc, utcnow

log = logging.getLogger("attack_detection.hunt")

BATCH = 400
MAX_AI_HUNTS = 5
ACCOUNT_FIELDS = ("AccountName", "InitiatingProcessAccountName")
SUMMARY_FIELDS = ("ActionType", "FileName", "ProcessCommandLine", "RemoteUrl", "RemoteIP", "Url", "SHA256",
                  "InitiatingProcessFileName")


def _row_summary(row: dict) -> str:
    parts = [f"{k}={str(row[k])[:160]}" for k in SUMMARY_FIELDS if row.get(k)]
    return "; ".join(parts)[:600]


def _matched(ioc_type: str, row: dict, values: set[str]) -> list[str]:
    if ioc_type == "ip":
        return [row["RemoteIP"]] if row.get("RemoteIP") in values else []
    if ioc_type == "domain":
        text = f"{row.get('Host', '')} {row.get('RemoteUrl', '')}".lower()
        return [v for v in values if v in text]
    if ioc_type == "url":
        url = (row.get("Url") or "").lower()
        return [v for v in values if v.lower() == url]
    hashes = {str(row.get(k) or "").lower() for k in ("SHA256", "SHA1", "MD5")}
    return [v for v in values if v in hashes]


class HuntRunner:
    def __init__(self, store: Store, client: DefenderClient, run_id: str, lookback_days: int,
                 ai: GeminiClient | None = None):
        self.store, self.client, self.run_id, self.lookback = store, client, run_id, lookback_days
        self.ai = ai
        self.templates = tpl.load()
        self.stats = {"hunts": 0, "ok": 0, "errors": 0, "rows": 0, "ioc_values": 0, "ai_drafted": 0,
                      "ai_rejected": 0}

    # ---------- one hunt ----------
    def execute(self, key: str, name: str, query: str, *, origin: str = "template", technique: str = "",
                threat_id: str | None = None, ioc_type: str | None = None, values: set[str] | None = None) -> dict:
        hunt_id = f"{self.run_id}:{key}"
        started = time.monotonic()
        record = {"hunt_id": hunt_id, "run_id": self.run_id, "threat_id": threat_id, "name": name,
                  "template": key.split(":")[0], "origin": origin, "technique": technique, "query": query,
                  "started_at": utcnow()}
        self.stats["hunts"] += 1
        try:
            rows = self.client.run_query(query)
        except ApiError as exc:
            record.update(status="error", row_count=0, error=exc.detail[:1000],
                          duration_s=round(time.monotonic() - started, 2))
            self.store.upsert("hunts", [record])
            self.stats["errors"] += 1
            log.warning("Hunt %s failed: %s", name, exc.detail[:200])
            return record
        results = []
        for i, row in enumerate(rows):
            if values is not None:
                row = {**row, "_matched": _matched(ioc_type or "", row, values), "_ioc_type": ioc_type}
            results.append({"hunt_id": hunt_id, "row_no": i, "device_id": row.get("DeviceId"),
                            "device_name": (row.get("DeviceName") or "").split(".")[0].lower(),
                            "event_time": to_utc(row.get("Timestamp")),
                            "account": next((row[k] for k in ACCOUNT_FIELDS if row.get(k)), None),
                            "summary": _row_summary(row), "row_json": row})
        record.update(status="ok", row_count=len(rows), error=None, duration_s=round(time.monotonic() - started, 2))
        self.store.upsert("hunts", [record])
        self.store.upsert("hunt_results", results)
        self.stats["ok"] += 1
        self.stats["rows"] += len(rows)
        return record

    # ---------- 1. IOC sweeps ----------
    def ioc_values(self, recent_days: int) -> dict[str, set[str]]:
        since = utcnow() - timedelta(days=recent_days)
        rows = self.store.query("""
            SELECT l.value FROM threat_links l JOIN threats t ON t.threat_id = l.threat_id
            WHERE l.link_type = 'ioc' AND (t.first_seen_at >= ? OR t.is_test)""", [since])
        by_type: dict[str, set[str]] = {}
        for r in rows:
            ioc_type, _, value = r["value"].partition("|")
            if ioc_type == "domain" and allowlisted(value):
                continue                      # stored before the allowlist existed, or added by the AI
            by_type.setdefault(ioc_type, set()).add(value)
        return by_type

    def ioc_sweeps(self, recent_days: int = 7) -> None:
        by_type = self.ioc_values(recent_days)
        for t in (t for t in self.templates.values() if t.kind == "ioc"):
            for ioc_type in t.ioc_types:
                values = sorted(by_type.get(ioc_type, set()))
                self.stats["ioc_values"] += len(values)
                for b in range(0, len(values), BATCH):
                    batch = values[b:b + BATCH]
                    n = b // BATCH + 1
                    self.execute(f"{t.key}:{ioc_type}:{n}", f"{t.name} ({ioc_type}, {len(batch)} values, batch {n})",
                                 t.render(self.lookback, batch), technique=t.technique, ioc_type=ioc_type,
                                 values=set(batch))

    # ---------- 2. behaviour hunts ----------
    def behaviour_hunts(self) -> None:
        for t in (t for t in self.templates.values() if t.kind == "behaviour"):
            self.execute(t.key, t.name, t.render(self.lookback), technique=t.technique)

    # ---------- 3. AI-drafted hunts ----------
    def ai_hunts(self, max_hunts: int = MAX_AI_HUNTS) -> None:
        if self.ai is None:
            return
        covered = {t.technique for t in self.templates.values() if t.technique}
        rows = self.store.query("""
            SELECT l.value AS technique, MIN(s.threat_id) AS threat_id, MAX(s.score) AS score
            FROM threat_links l JOIN scores s ON s.threat_id = l.threat_id
            WHERE l.link_type = 'technique' AND s.rating IN ('Critical', 'High')
            GROUP BY l.value ORDER BY score DESC""")
        todo = [r for r in rows if r["technique"] not in covered][:max_hunts]
        catalogue = {r["technique_id"]: r for r in self.store.query("SELECT * FROM attack_techniques")}
        for r in todo:
            tech = r["technique"]
            info = catalogue.get(tech, {"name": tech, "tactics": ""})
            cached = self.store.query("""SELECT query FROM hunts WHERE origin = 'ai' AND technique = ? AND status = 'ok'
                                         ORDER BY started_at DESC LIMIT 1""", [tech])
            if cached:
                self.execute(f"ai:{tech}", f"AI-drafted: {tech} {info['name']}", cached[0]["query"], origin="ai",
                             technique=tech, threat_id=r["threat_id"])
                continue
            context = self.store.scalar("SELECT text FROM threats WHERE threat_id = ?", [r["threat_id"]]) or ""
            try:
                draft = self.ai.json("kql", KQL_SYSTEM, kql_prompt(tech, info["name"], info["tactics"], context,
                                                                    self.lookback), KqlDraft)
            except AIUnavailable as exc:
                log.info("AI hunt drafting skipped: %s", exc)
                return
            query = ensure_limit(draft.query)
            problems = validate(query)
            if problems:
                self._reject(tech, info, query, problems, r["threat_id"])
                continue
            self.stats["ai_drafted"] += 1
            record = self.execute(f"ai:{tech}", f"AI-drafted: {tech} {info['name']}", query, origin="ai",
                                  technique=tech, threat_id=r["threat_id"])
            if record["status"] == "error":
                try:
                    fixed = self.ai.json("kql", KQL_SYSTEM, kql_fix_prompt(query, record["error"] or ""), KqlDraft)
                except AIUnavailable:
                    continue
                query = ensure_limit(fixed.query)
                problems = validate(query)
                if problems:
                    self._reject(tech, info, query, problems, r["threat_id"])
                    continue
                self.execute(f"ai:{tech}:fix", f"AI-drafted (fixed): {tech} {info['name']}", query, origin="ai",
                             technique=tech, threat_id=r["threat_id"])

    def _reject(self, tech, info, query, problems, threat_id) -> None:
        self.stats["ai_rejected"] += 1
        self.store.upsert("hunts", [{"hunt_id": f"{self.run_id}:ai:{tech}:rejected", "run_id": self.run_id,
                                     "threat_id": threat_id, "name": f"AI-drafted (rejected): {tech} {info['name']}",
                                     "template": "ai", "origin": "ai", "technique": tech, "query": query,
                                     "status": "invalid", "row_count": 0, "error": "; ".join(problems),
                                     "started_at": utcnow(), "duration_s": 0}])

    def run_all(self, recent_days: int = 7) -> dict:
        self.ioc_sweeps(recent_days)
        self.behaviour_hunts()
        self.ai_hunts()
        log.info("Hunts: %s", self.stats)
        return self.stats

