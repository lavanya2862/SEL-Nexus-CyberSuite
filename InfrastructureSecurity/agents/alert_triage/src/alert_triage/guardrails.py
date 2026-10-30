"""Guardrails: fixed safety rules in code, enforced before AND after the AI. Loaded from config/guardrails.yaml.

Flow:
  1. `features()` reads plain facts from the enrichment (techniques, query hits, TI verdicts, watchlist hits...).
  2. `evaluate()` returns which rules fire and the constraints they force (escalate, min verdict, denied verdicts,
     forced severity). This is computed before the AI and passed into the prompt as "rules already in force".
  3. `apply()` takes the AI verdict (plus the AI's own severity/confidence) and makes it MORE cautious only:
     forces escalation, raises the verdict to the floor, replaces a denied verdict with needs_investigation.
The AI can never make a verdict less cautious than the guardrails require.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from alert_triage.config import CONFIG_DIR, read_yaml

_DEFAULT_ORDER = ["benign_positive", "likely_false_positive", "needs_investigation", "likely_true_positive"]


def load(base=None) -> dict:
    return read_yaml("guardrails.yaml", base or CONFIG_DIR)


def features(packet: dict, query_results: list[dict], ti_results: list[dict], context: dict,
            injection_hits: list[dict]) -> dict:
    techs = set(packet["techniques"]) | {t.split(".")[0] for t in packet["techniques"]}
    rows_by_q = {q["id"]: q for q in query_results}

    def has_rows(qid: str) -> bool:
        return rows_by_q.get(qid, {}).get("row_count", 0) > 0

    def flag(qid: str, column: str) -> bool:
        q = rows_by_q.get(qid)
        return bool(q and any(str(r.get(column)).lower() in ("true", "1") for r in q.get("rows", [])))

    categories = {a["category"].lower() for a in packet["alerts"] if a.get("category")}
    titles = " ".join(a["title"].lower() for a in packet["alerts"])
    return {
        "techniques": techs,
        "has_rows": has_rows,
        "flag": flag,
        "categories": categories,
        "titles": titles,
        "ti_malicious": any(t.get("verdict") == "malicious" for t in ti_results),
        "watchlist_hits": context.get("watchlist_hits", {}),
        "account_is_admin": context.get("account_is_admin", False),
        "incident_severity": packet.get("severity", ""),
        "injection": bool(injection_hits),
        # Defender's own verdicts on the evidence (malicious / suspicious / ...)
        "evidence_verdicts": {str(e.get("verdict") or "").lower() for kind in packet["entities"].values()
                              for e in kind if isinstance(e, dict)}
                             | {str(e.get("verdict") or "").lower() for a in packet["alerts"]
                                for e in a.get("evidence_verdicts") or []},
        "approved_admin": bool(context.get("watchlist_hits", {}).get("approved_admin")),
    }


@dataclass
class Outcome:
    triggered: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    escalate: bool = False
    min_verdict: str | None = None
    denied: set[str] = field(default_factory=set)
    severity: str | None = None


def _when_matches(rule_id: str, when: dict, f: dict, enabled: set[str]) -> bool:
    if rule_id not in enabled:
        return False
    if when.get("or_query_hits") and any(f["has_rows"](q) for q in when["or_query_hits"]):
        return True
    if when.get("techniques") and ({t.upper() for t in when["techniques"]} & f["techniques"]):
        return True
    if "categories" in when and ({c.lower() for c in when["categories"]} & f["categories"]):
        return True
    if when.get("title_any") and any(t.lower() in f["titles"] for t in when["title_any"]):
        return True
    if when.get("watchlist_hit") and any(k in f["watchlist_hits"] for k in when["watchlist_hit"]):
        return True
    if when.get("account_is_admin") and f["account_is_admin"]:
        return True
    if when.get("ti_verdict") and f["ti_malicious"]:
        return True
    for q_flag in when.get("query_flag", []):
        qid, _, col = q_flag.partition(":")
        if col and f["flag"](qid, col):
            return True
    if when.get("evidence_verdict") and {v.lower() for v in when["evidence_verdict"]} & f.get("evidence_verdicts", set()):
        return True
    if when.get("injection_detected") and f["injection"]:
        return True
    if when.get("incident_severity") and f["incident_severity"] in [s.lower() for s in when["incident_severity"]]:
        return True
    return False


def evaluate(rules_cfg: dict, enabled: set[str], f: dict) -> Outcome:
    """Pre-AI pass: everything except rules that need the AI's own output (recommended severity, confidence)."""
    out = Outcome()
    order = rules_cfg.get("verdict_order", _DEFAULT_ORDER)
    for rule in rules_cfg.get("rules", []):
        rid = rule.get("id")
        if rid in ("high_no_close", "low_confidence"):      # need AI output; handled in apply()
            continue
        if _when_matches(rid, rule.get("when", {}), f, enabled) and not _unless(rule.get("unless", {}), f):
            _absorb(out, rule, order)
    return out


def _unless(unless: dict, f: dict) -> bool:
    """A rule's documented exception, e.g. privileged_account does not fire for approved-admin activity."""
    return bool(unless.get("approved_admin") and f.get("approved_admin"))


def _absorb(out: Outcome, rule: dict, order: list[str]) -> None:
    out.triggered.append(rule["id"])
    if rule.get("reason"):
        out.reasons.append(rule["reason"])
    force = rule.get("force", {})
    if force.get("escalate"):
        out.escalate = True
    if force.get("severity"):
        out.severity = force["severity"]
    out.denied |= {v for v in force.get("deny_verdicts", [])}
    mv = force.get("min_verdict")
    if mv and (out.min_verdict is None or order.index(mv) > order.index(out.min_verdict)):
        out.min_verdict = mv


def apply(rules_cfg: dict, enabled: set[str], pre: Outcome, verdict: dict, f: dict,
          approved_test: bool = False) -> dict:
    """Post-AI pass. Returns the adjusted verdict dict plus guardrail metadata. Only makes it more cautious."""
    order = rules_cfg.get("verdict_order", _DEFAULT_ORDER)
    out = Outcome(triggered=list(pre.triggered), reasons=list(pre.reasons), escalate=pre.escalate,
                  min_verdict=pre.min_verdict, denied=set(pre.denied), severity=pre.severity)

    # rules that depend on the AI's own output
    rec_sev = (verdict.get("recommended_severity") or "").lower()
    for rule in rules_cfg.get("rules", []):
        rid = rule.get("id")
        if rid == "high_no_close" and rid in enabled:
            if f["incident_severity"] == "high" or rec_sev == "high":
                _absorb(out, rule, order)
        elif rid == "low_confidence" and rid in enabled:
            if (verdict.get("confidence") or "").lower() == "low":
                _absorb(out, rule, order)

    v = verdict.get("verdict", "needs_investigation")

    # approved-test easing (only if nothing escalating fired)
    escalating = {"credential_access", "ransomware", "privileged_account", "high_ti_match",
                  "logon_success_after_failures", "signin_success_after_failures", "mailbox_rule_hides_mail", "local_admin_added"}
    if approved_test and not (set(out.triggered) & escalating) and not out.escalate:
        out.reasons.append("Activity matches an approved-test watchlist; benign positive allowed.")

    # enforce denied verdicts
    if v in out.denied:
        v = "needs_investigation"
    # enforce the floor
    if out.min_verdict and order.index(v) < order.index(out.min_verdict):
        v = out.min_verdict
    if out.escalate and v in ("likely_false_positive", "benign_positive"):
        v = "needs_investigation"
    if (rules_cfg.get("close_requires_high_confidence") and v in ("likely_false_positive", "benign_positive")
            and (verdict.get("confidence") or "").lower() != "high"):
        v = "needs_investigation"
        out.triggered.append("close_needs_high_confidence")
        out.reasons.append("Closing is only recommended at high confidence (safety dial in config/guardrails.yaml).")

    severity = out.severity or rec_sev or "medium"
    verdict = dict(verdict)
    verdict["verdict"] = v
    verdict["recommended_severity"] = severity
    verdict["escalate"] = bool(out.escalate or v == "likely_true_positive")
    verdict["guardrails"] = out.triggered
    verdict["guardrail_reasons"] = out.reasons
    if out.triggered and not verdict.get("guardrail_triggered"):
        verdict["guardrail_triggered"] = out.triggered[0]
    return verdict
