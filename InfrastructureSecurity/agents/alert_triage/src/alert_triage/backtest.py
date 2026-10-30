"""Backtest: grade the agent on incidents whose right answer is known.

  GUIDE set  - real, analyst-graded Microsoft incidents (guide.py). Same guardrails + one AI call per incident.
               Compared with two no-AI baselines: "history only" and "always escalate".
  Lab set    - our own simulated incidents, graded against the lab ledger (ledger.py).

Outputs: rows in the `backtest` table, data/export/backtest.json (website), data/reports/UC4_Backtest_<date>.xlsx.
"""

from __future__ import annotations

import json
import logging
import time

import duckdb
from pydantic import ValidationError

from alert_triage import guide, ledger
from alert_triage.config import Settings
from alert_triage.llm import LLM, AIUnavailable
from alert_triage.schemas import TriageVerdict
from alert_triage.store import Store, utcnow

log = logging.getLogger("alert_triage.backtest")

TO_GRADE = {"likely_true_positive": "TP", "benign_positive": "FP", "likely_false_positive": "FP",
            "needs_investigation": "human"}

GUIDE_SYSTEM = """You are a SOC alert-triage assistant preparing a recommendation for a human analyst.
The incident below comes from an anonymised dataset: names are replaced by numbers and there are no raw logs.
Judge it from its structure: alert categories, MITRE techniques, evidence types and roles, Defender's own
suspicion levels and verdicts on the evidence, and how incidents from the same detectors were graded before in the
same organisation ("history_by_detector"). Use only the facts given. Output ONLY JSON."""

GUIDE_SCHEMA_HINT = """Return JSON: {"summary": str (max 3 sentences), "verdict":
"likely_true_positive|likely_false_positive|benign_positive|needs_investigation", "confidence": "low|medium|high",
"recommended_severity": "informational|low|medium|high", "evidence": [{"source": "guide", "query_id": "",
"finding": str}], "escalate": bool, "would_change_verdict_if": str}"""

ESCALATE_CATEGORIES = {"credentialaccess", "credentialstealing", "ransomware", "impact"}


def _dial() -> bool:
    from alert_triage import guardrails
    return bool(guardrails.load().get("close_requires_high_confidence"))


def guide_guardrails(p: dict) -> list[str]:
    """The same "never overrule Microsoft" rule as config/guardrails.yaml, from what a GUIDE incident carries."""
    fired = []
    if any(k.lower() == "malicious" for k in p["defender_last_verdicts"]):
        fired.append("microsoft_malicious_evidence")
    return fired


def guide_verdict(llm: LLM | None, p: dict) -> tuple[str, str, bool, str, str]:
    """Return (verdict, confidence, escalate, ai_status, severity) for one GUIDE packet."""
    fired = guide_guardrails(p)
    if llm is None or not getattr(llm, "available", False):
        base = guide.history_baseline(p)
        verdict = {"TP": "likely_true_positive", "BP": "benign_positive", "FP": "likely_false_positive"}.get(
            base, "needs_investigation")
        status, conf, sev = "rules_only", "low", "medium"
    else:
        prompt = json.dumps(p, default=str) + "\n\n" + GUIDE_SCHEMA_HINT
        try:
            raw = llm.json("backtest", GUIDE_SYSTEM, prompt, max_tokens=600)
            v = TriageVerdict.model_validate(raw)
            verdict, conf, sev, status = v.verdict, v.confidence, v.recommended_severity, "ai"
        except (AIUnavailable, ValidationError) as exc:
            log.info("GUIDE %s: AI not used (%s)", p["incident_id"], str(exc)[:120])
            return guide_verdict(None, p)
    # post-guardrails: only more cautious
    if fired and verdict in ("benign_positive", "likely_false_positive"):
        verdict = "needs_investigation"
    if (_dial() and status == "ai" and verdict in ("benign_positive", "likely_false_positive") and conf != "high"):
        verdict = "needs_investigation"
    escalate = bool(fired) or verdict == "likely_true_positive"
    return verdict, conf, escalate, status, sev


def run_guide(settings: Settings, store: Store, llm: LLM | None, n: int = 300) -> dict:
    guide.load(settings)
    items = guide.sample(settings, n)
    con = duckdb.connect(str(guide.db_path(settings)), read_only=True)
    rows = []
    try:
        for i, item in enumerate(items, 1):
            t0 = time.monotonic()
            p = guide.replay_packet(settings, item, con)
            verdict, conf, escalate, status, sev = guide_verdict(llm, p)
            rows.append({"set_name": "guide", "item_id": p["incident_id"], "truth": guide.GRADES[item["grade"]],
                         "truth_detail": item["grade"], "category": ",".join(p["categories"])[:200],
                         "verdict": verdict, "confidence": conf, "escalate": escalate,
                         "high_severity": sev == "high", "baseline": guide.history_baseline(p),
                         "guardrails": guide_guardrails(p), "ai_status": status,
                         "seconds": round(time.monotonic() - t0, 2), "run_at": utcnow()})
            if i % 25 == 0:
                log.info("GUIDE backtest: %d/%d", i, len(items))
                store.upsert("backtest", rows[-25:])
    finally:
        con.close()
    store.execute("DELETE FROM backtest WHERE set_name = 'guide'")
    store.upsert("backtest", rows)
    return {"guide_incidents": len(rows)}


def grade_lab(store: Store) -> dict:
    rows = []
    for r in ledger.lab_results(store):
        g = ledger.grade(r)
        truth = "TP" if "likely_true_positive" in r["expected"] else (
            "FP" if ("benign_positive" in r["expected"] or "likely_false_positive" in r["expected"]) else "human")
        rows.append({"set_name": "lab", "item_id": r["incident_id"], "truth": truth, "truth_detail": r["expected"],
                     "category": r["name"], "verdict": r["verdict"], "confidence": r["confidence"],
                     "escalate": bool(r["escalate"]), "high_severity": (r["recommended_severity"] or "") == "high",
                     "baseline": "", "guardrails": r["guardrails"], "ai_status": r["ai_status"],
                     "seconds": None, "run_at": utcnow(),
                     "_correct": g["correct"], "_missed": g["missed_true_positive"]})
    store.execute("DELETE FROM backtest WHERE set_name = 'lab'")
    store.upsert("backtest", [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows])
    return {"lab_incidents": len(rows), "lab_correct": sum(r["_correct"] for r in rows),
            "lab_missed_tp": sum(r["_missed"] for r in rows)}


# ---------------------------------------------------------------- evaluation
def evaluate_rows(rows: list[dict]) -> dict:
    # three outcomes only: a benign positive (truth or baseline) counts as a false positive
    rows = [{**r, "truth": "FP" if r["truth"] == "BP" else r["truth"],
             "baseline": "FP" if r.get("baseline") == "BP" else r.get("baseline")} for r in rows]
    labels = ["TP", "FP"]
    preds = ["TP", "FP", "human"]
    matrix = {t: {p: 0 for p in preds} for t in labels}
    decided = correct = missed = 0
    base_correct = base_decided = 0
    for r in rows:
        t = r["truth"]
        p = TO_GRADE.get(r["verdict"], "human")
        if t in matrix:
            matrix[t][p] += 1
        if p != "human":
            decided += 1
            correct += p == t
        if t == "TP" and p == "FP":
            missed += 1
        b = r.get("baseline") or ""
        if b in labels:
            base_decided += 1
            base_correct += b == t
    n = len(rows)
    auto_close = sum(1 for r in rows if r["truth"] == "FP" and TO_GRADE.get(r["verdict"]) == "FP")
    closable = sum(1 for r in rows if r["truth"] == "FP")
    tp_total = sum(1 for r in rows if r["truth"] == "TP")
    tp_caught = sum(1 for r in rows if r["truth"] == "TP" and TO_GRADE.get(r["verdict"]) in ("TP", "human"))
    return {
        "n": n,
        "decided_pct": round(100 * decided / n, 1) if n else None,
        "accuracy_when_decided_pct": round(100 * correct / decided, 1) if decided else None,
        "missed_true_positives": missed,
        "real_attacks_kept_for_humans_pct": round(100 * tp_caught / tp_total, 1) if tp_total else None,
        "false_alarms_closable_pct": round(100 * auto_close / closable, 1) if closable else None,
        "baseline_history_accuracy_pct": round(100 * base_correct / base_decided, 1) if base_decided else None,
        "baseline_history_decided_pct": round(100 * base_decided / n, 1) if n else None,
        "confusion": matrix,
        "ai_used": sum(1 for r in rows if r.get("ai_status") == "ai"),
    }


def noisy_detectors(settings: Settings, min_incidents: int = 20, limit: int = 15) -> list[dict]:
    """GUIDE detectors that are almost always harmless: candidates for tuning (a free quick win)."""
    try:
        con = duckdb.connect(str(guide.db_path(settings)), read_only=True)
    except duckdb.Error:
        return []
    try:
        rows = con.execute("""
            SELECT DetectorId, COUNT(DISTINCT IncidentId) AS n,
                   COUNT(DISTINCT CASE WHEN IncidentGrade <> 'TruePositive' THEN IncidentId END) AS harmless
            FROM guide_train WHERE IncidentGrade IN ('TruePositive', 'BenignPositive', 'FalsePositive')
            GROUP BY DetectorId HAVING COUNT(DISTINCT IncidentId) >= ?
            ORDER BY harmless * 1.0 / n DESC, n DESC LIMIT ?""", [min_incidents, limit]).fetchall()
        return [{"detector": r[0], "incidents": r[1], "harmless_pct": round(100 * r[2] / r[1], 1)}
                for r in rows if r[2] / r[1] >= 0.8]
    except duckdb.Error:
        return []
    finally:
        con.close()


def report(settings: Settings, store: Store, full: bool = True) -> dict:
    """Write data/export/backtest.json. full=False (every normal run): reuse the previous noisy-detector list and
    skip the Excel file, so a 5-minute run stays fast."""
    previous = {}
    if not full:
        try:
            previous = json.loads((settings.export_dir / "backtest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = {}
    out = {"generated_at": utcnow().strftime("%Y-%m-%d %H:%M:%SZ"), "sets": {}}
    for name in ("guide", "lab"):
        rows = store.query("SELECT * FROM backtest WHERE set_name = ?", [name])
        if rows:
            out["sets"][name] = evaluate_rows(rows)
    lab_rows = ledger.lab_results(store)
    out["lab_detail"] = [{**{k: r[k] for k in ("incident_id", "name", "wave", "expected", "must_escalate", "verdict",
                                               "escalate", "ai_status", "title")}, **ledger.grade(r)}
                         for r in lab_rows]
    out["noisy_detectors"] = noisy_detectors(settings) if full else previous.get("noisy_detectors", [])
    settings.export_dir.mkdir(parents=True, exist_ok=True)
    (settings.export_dir / "backtest.json").write_text(json.dumps(out, default=str, indent=1), encoding="utf-8")
    if full:
        try:
            out["excel"] = str(_excel(settings, store, out))
        except Exception as exc:  # noqa: BLE001
            log.warning("Excel report failed: %s", exc)
    return out


def _excel(settings: Settings, store: Store, out: dict):
    from openpyxl import Workbook
    from openpyxl.styles import Font
    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    ws.append(["Alert Triage backtest", out["generated_at"]])
    ws["A1"].font = Font(bold=True, size=14)
    for name, ev in out["sets"].items():
        ws.append([])
        ws.append([f"{name.upper()} set", ""])
        ws.cell(ws.max_row, 1).font = Font(bold=True)
        for k, v in ev.items():
            if k != "confusion":
                ws.append([k.replace("_", " "), v])
        ws.append(["confusion (truth \\ agent)", "TP", "FP", "human"])
        for t, row in ev["confusion"].items():
            ws.append([t, row["TP"], row["FP"], row["human"]])
    ws.column_dimensions["A"].width = 42
    for name in ("guide", "lab"):
        rows = store.query("SELECT * FROM backtest WHERE set_name = ? ORDER BY item_id", [name])
        if not rows:
            continue
        sheet = wb.create_sheet(f"{name} incidents")
        cols = ["item_id", "truth", "truth_detail", "category", "verdict", "confidence", "escalate", "baseline",
                "guardrails", "ai_status"]
        sheet.append(cols)
        for r in rows:
            sheet.append([str(r.get(c)) if r.get(c) is not None else "" for c in cols])
    if out.get("noisy_detectors"):
        sheet = wb.create_sheet("Noisy detectors")
        sheet.append(["detector", "incidents", "harmless %"])
        for d in out["noisy_detectors"]:
            sheet.append([d["detector"], d["incidents"], d["harmless_pct"]])
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    path = settings.reports_dir / f"Alert_Triage_Backtest_{utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
    wb.save(path)
    return path
