"""Start a use case's real pipeline and follow it step by step (for the live run page).

The portal never imports UC code. Each run gets a folder under data/runs/<run_id>/:
  meta.json    who/when (written by the portal), plus the process ids (written by the wrapper)
  output.log   every line the pipeline prints (written live by dashboard.runner)
  result.json  exit code and finish time (written by dashboard.runner when the run ends)
The run itself is a separate process (dashboard.runner), so it survives a portal restart; the portal rebuilds the
step-by-step state from these files, using the timestamps on the log lines. The pipelines keep their own
one-run-at-a-time locks, so a scheduled run already in progress makes a portal run report "skipped".
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Callable
from urllib.parse import quote


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:[,.](\d{1,6}))?\s")


def line_time(line: str) -> str | None:
    """Local time stamp at the start of a UC log line → UTC ISO string."""
    m = _TS.match(line)
    if not m:
        return None
    dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    if m.group(2):
        dt = dt.replace(microsecond=int(m.group(2).ljust(6, "0")[:6]))
    return dt.astimezone().astimezone(timezone.utc).isoformat()


@dataclass
class Step:
    key: str
    label: str
    description: str
    members: tuple[str, ...] = ()           # Threat Intel: pipeline step names that make up this friendly step
    status: str = "pending"                 # pending | running | done | error | skipped
    detail: str = ""
    started_at: str | None = None
    finished_at: str | None = None


# Friendly steps, in order. Threat Intel groups its internal steps into 4 a person can follow, the attack check into 4, Alert Triage its 10 into 4.
# Members must follow the pipeline's own order (they are matched against the log one after another).
def vulnerability_steps() -> list[Step]:
    return [
        Step("download", "Defender Data Acquisition", "Retrieves vulnerability data and incremental updates from Microsoft Defender."),
        Step("check", "Data Validation", "Validates snapshot completeness and data integrity."),
        Step("score", "Vulnerability Prioritization & Reporting", "Prioritizes vulnerabilities and generates analytical reports."),
        Step("advice", "Remediation Drafting", "Drafts actionable remediation steps for identified vulnerabilities."),
        Step("fix", "Remediation Execution", "Executes approved remediation actions."),
    ]


def threat_intel_steps() -> list[Step]:
    return [
        Step("gather", "Intelligence Gathering", "Collects and analyses threat intelligence from multiple public sources.",
             ("collect", "inventory", "derive", "nvd_details", "epss", "products", "analyse")),
        Step("affects", "Threat Assessment", "Checks identified threats against managed device software to determine applicability and risk.",
             ("exposure", "score", "correlate")),
        Step("fixes", "Remediation Guidance", "Generates actionable remediation recommendations for identified vulnerabilities.",
             ("fix_advice",)),
        Step("outputs", "Security Reporting", "Generates security reports, updates dashboards, and distributes relevant alerts.",
             ("alerts", "report", "dashboard", "metrics")),
        Step("fix", "Remediation Approval", "Presents proposed remediation actions for analyst review, approval, or deferral.",
             ("fix_plan",)),
    ]


def attack_steps() -> list[Step]:
    """The Attack Detection Agent's run: its own devices and hunts, findings.json, then the fix engine's proposals."""
    return [
        Step("search", "Device Activity Hunting", "Retrieves managed devices from Microsoft Defender and searches the last 30 days of activity for techniques associated with 12 known attacks.",
             ("inputs", "hunt")),
        Step("evidence", "Evidence Correlation", "Links hunting findings to managed devices, signed-in users, Defender alerts, and activity timelines to establish investigation context.",
             ("correlate", "exposure", "rescore")),
        Step("resolve", "Remediation Drafting", "Generates evidence-backed remediation steps for newly identified detections, including host isolation, malware scanning, and account resets.",
             ("resolve",)),
        Step("publish", "Results & Report Publishing", "Updates the Attack Detection dashboard, publishes analytical reports, and distributes alerts for identified attacks.",
             ("report", "publish", "import", "rescore", "alerts", "report", "dashboard")),
        Step("fix", "Remediation Execution", "Prepares Defender scan-and-clean actions for detected attacks and executes approved actions when automated remediation is enabled.",
             ("fix", "fix_plan", "auto_fix", "threat_intel")),
    ]


def alert_triage_steps() -> list[Step]:
    return [
        # The pipeline's own housekeeping (feedback import, lab grading) still runs; it is just not shown as a step.
        Step("ingest", "Incident Retrieval", "Retrieves new and updated incidents from Microsoft Defender and Microsoft Sentinel.", ("ingest",)),
        Step("triage", "Incident Classification", "Analyzes incident evidence and classifies potential threats to determine the required response.",
             ("triage",)),
        Step("act", "Incident Response", "Executes response actions, escalates confirmed threats, and initiates Defender scans or cleanup when enabled.",
             ("auto_resolve", "respond", "writeback", "actions")),
        Step("publish", "Results & Report Publishing", "Publishes incident classification results, triage metrics, and reports to the Alert Triage dashboard.", ("metrics", "export", "report")),
    ]

STEPS = {"threat_intel": threat_intel_steps, "vulnerability": vulnerability_steps, "alert_triage": alert_triage_steps, "attack_detection": attack_steps}
AGENT_NAMES = {"threat_intel": "Threat Intel Agent", "vulnerability": "Vulnerability Agent", "alert_triage": "Alert Triage Agent", "attack_detection": "Attack Detection Agent"}
# Runs started before the agents got their names are stored under their old keys, and their logs use the old package
# names; both are read as today's.
OLD_KEYS = {"attack": "attack_detection"}
_OLD_LOGGERS = re.compile(r"\b(attack)\.")


def agent_key(key: str) -> str:
    return OLD_KEYS.get(key, key)


STEPS_AFTER_TRIAGE = {"auto_resolve", "respond", "defender_view", "writeback", "actions", "ledger", "accuracy", "metrics", "export"}
VERDICT_WORDS = {
    "likely_true_positive": "Potential threat identified",
    "likely_false_positive": "False alarm identified",
    "benign_positive": "Benign activity identified",
    "needs_investigation": "Requires analyst review",
}


def verdict_count(n: int, words: str) -> str:
    """ "2 false alarms", "1 real threat", "3 needs a person" """
    return f"{n} {words}" + ("s" if n != 1 and words.endswith(("threat", "alarm")) else "")


def ingest_counts(text: str) -> dict | None:
    """Alert Triage's ingest log line → what really changed. Defender also returns incidents whose last-update time moved for
    nothing that matters (a comment, a tag), so the raw "returned" number is never shown.
    "5 incident(s) returned, 0 need triage, 0 new, 0 status or classification change(s)" (older runs: first two only)"""
    got = [int(x) for x in re.findall(r"\d+", text)]
    if len(got) < 2:
        return None
    need = got[1]
    if len(got) >= 4:
        return {"new": got[2], "new_alerts": max(need - got[2], 0), "reclassified": got[3]}
    return {"new": None, "new_alerts": need, "reclassified": 0}


def ingest_parts(c: dict) -> list[str]:
    parts = []
    if c["new_alerts"]:
        parts.append(f"{_plural(c['new_alerts'], 'incident')} with new alerts" if c["new"] is not None
                     else f"{c['new_alerts']} new or changed to check")
    if c["reclassified"]:
        parts.append(f"{c['reclassified']} closed or reclassified in Defender")
    return parts


def ingest_words(text: str) -> str:
    """Alert Triage Stage 1: Incident Retrieval completion message."""
    c = ingest_counts(text)
    if c is None:
        return text or "No new incidents detected"
    if c.get("new"):
        return "New incidents retrieved"
    if c.get("new_alerts"):
        return "Incident updates retrieved"
    if c.get("reclassified"):
        return "Incident status updates retrieved"
    return "No new incidents detected"

REPORT_READY = "Vulnerability prioritization and reports completed"


def defender_new(info: dict) -> tuple[int, int] | None:
    """(new, fixed) vulnerabilities this run, from Defender's own change list (Vulnerability extract counts).
    Both 0 when Defender has not refreshed its data; None for runs from before Vulnerability counted them."""
    if "new" not in info:
        return None
    if info.get("defender_refreshed") is False:
        return 0, 0
    return int(info.get("new") or 0), int(info.get("fixed") or 0)


def download_words(info: dict, vulns: int | None = None) -> str:
    """Plain words for the Defender Data Acquisition step."""
    if info.get("vulnerability_rows") is None:
        return ""
    return "Defender data retrieved"


def advice_summary(info: dict, stopped: str = "") -> str:
    """The Remediation Drafting step: how many AI cards were written anew and how many were still current, or that the
    AI was not available (then the cards keep their last AI text and new ones have none)."""
    if stopped:
        return f"AI not available: {_short(stopped)}"



    return "Remediation drafting completed"


def fix_words(info: dict, uc: str = "vulnerability") -> str:
    """The Remediation Execution / Approval stage in plain words."""
    new, waiting = int(info.get("new") or 0), int(info.get("waiting") or 0)
    if uc == "threat_intel":
        if not new and not waiting:
            return "No new remediation proposals"
        if not new and waiting:
            return "Existing remediation proposals awaiting review"
        if new == 1:
            return "Remediation proposal awaiting approval"
        return "Remediation proposals awaiting approval"
    if uc == "attack_detection":
        if not new:
            return "No new remediation actions · Pending approvals remain" if waiting else "No new remediation actions"
        return "New remediation actions awaiting approval"
    # vulnerability (default)
    if not new:
        return "No new actions · Pending approvals exist" if waiting else "No new remediation actions"
    msg = "New remediation action awaiting approval" if new == 1 else "New remediation actions awaiting approval"
    return f"{msg} · Pending approvals exist" if waiting else msg


def auto_fix_words(info: dict) -> str:
    """Attack Detection auto-remediation completion message."""
    n = int(info.get("approved") or 0)
    if not n:
        return "No outstanding issues require remediation"
    if info.get("busy"):
        return "Remediation approved and queued for the next execution"
    done, failed = int(info.get("done") or 0), int(info.get("failed") or 0)
    if failed:
        return "Remediation completed with some issues still unresolved"
    return "Defender scan-and-clean completed"


STAGE_ERRORS = {
    "vulnerability": {
        "download": "Data retrieval failed",
        "validate": "Validation failed",
        "score": "Report generation failed",
        "advice": "Remediation drafting failed",
        "fix": "Remediation execution failed",
    },
    "threat_intel": {
        "gather": "Threat intelligence collection failed",
        "affects": "Threat assessment failed",
        "fixes": "Remediation guidance failed",
        "outputs": "Report generation failed",
        "fix": "Remediation approval failed",
    },
    "attack_detection": {
        "search": "Hunting failed",
        "evidence": "Evidence correlation failed",
        "resolve": "Remediation drafting failed",
        "publish": "Results and report publishing failed",
        "fix": "Remediation execution failed",
    },
    "alert_triage": {
        "ingest": "Incident retrieval failed",
        "triage": "Incident classification failed",
        "act": "Incident response failed",
        "publish": "Results and report publishing failed",
    },
}

# Why a run stopped, in plain words (no numbers): the first pattern found in the end of the log wins.
STOP_REASONS = [
    (r"quality FAIL", "a data quality check failed, so the new results were not published"),
    (r"AADSTS7000215|invalid_client|\b401\b|unauthori[sz]ed", "Microsoft refused the sign-in; check the app's keys in .env"),
    (r"\b403\b|forbidden|insufficient privileges", "the app registration is missing a permission"),
    (r"(Foundry|Gemini).*\b404\b|\b404\b.*(Foundry|Gemini)", "the AI model address or deployment name in .env is wrong"),
    (r"\b429\b|rate limit|quota", "Microsoft or the AI service asked us to slow down; try again later"),
    (r"timed? ?out|ConnectionError|Failed to establish|getaddrinfo|Name or service not known", "Microsoft could not be reached; check the internet connection"),
    (r"ConfigError|is missing|not set", "a setting in .env is missing or wrong"),
    (r"database is locked|being used by another process|PermissionError", "a file was in use by another program; close it and run again"),
]


def stop_reason(lines) -> str:
    text = "\n".join(lines)
    for pattern, words in STOP_REASONS:
        if re.search(pattern, text, re.I):
            return words
    return "an unexpected error; the full log is saved with this run"


def _short(text: str, limit: int = 110) -> str:
    text = re.sub(r"[A-Z]:\\[^ ,'}]+", "", text).strip(" :,")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _literal(text: str):
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return text


def _plural(n, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _n(v) -> str:
    return f"{v:,}" if isinstance(v, int) else str(v)


def _new_steps(d: dict) -> int:
    """Fix steps written in this run only; steps kept from earlier runs are not shown again."""
    return int(d.get("new_ai", 0) or 0) + int(d.get("new_standard", 0) or 0)


def _searched(d: dict) -> str:
    """The attack search in plain words."""
    return "Hunting completed with partial results" if d.get("errors") else "Hunting completed"


def threats_words(ex: dict) -> str:
    """Threat Intel Stage 2: Threat Assessment completion summary."""
    if "new_threats_exposed" not in ex:
        return "Threat applicability completed"
    new = ex.get("new_threats_exposed", 0)
    return "Applicable threats identified" if new else "No applicable threats identified"
def _alerts(n: int) -> str:
    return f"{_plural(n, 'alert')} sent" if n else "no alerts needed"


def feed_counts(feeds: dict) -> str:
    """e.g. "8 of 9 feeds OK · 1 skipped (no key)" """
    ok = sum(1 for v in feeds.values() if str(v).startswith("ok"))
    skipped = sum(1 for v in feeds.values() if str(v).startswith("skipped"))
    failed = [k for k, v in feeds.items() if not str(v).startswith(("ok", "skipped"))]
    text = f"{ok} of {len(feeds)} feeds OK"
    if skipped:
        text += f" · {skipped} skipped"
    if failed:
        text += f" · failed: {', '.join(failed)}"
    return text


def friendly(name: str, value, uc: str = "") -> str | None:
    """A Threat Intel / Attack Detection / Alert Triage step result as one plain sentence (None → show the raw text)."""
    d = value if isinstance(value, dict) else {}
    try:
        # Threat Intel sub-steps
        if name == "collect":
            return "Threat intelligence collected"
        if name in ("inventory", "derive"):
            return "Vulnerability inventory analysed"
        if name == "nvd_details":
            return f"Details for {_n(value)} CVEs from NVD"
        if name == "epss":
            return f"Exploit odds for {_n(value)} CVEs (EPSS)"
        if name == "products":
            return "Linked CVEs to the products they affect"
        if name == "analyse":
            return "Threat analysis completed"
        if name == "exposure":
            return "threat applicability assessed" if uc == "threat_intel" else f"{_n(d.get('threats_exposed', 0))} threats apply to devices"
        if name in ("score", "rescore"):
            return "Risk severity evaluated"
        if name == "correlate":
            if uc == "threat_intel":
                return "Security findings correlated"
            return f"{_n(d.get('exposure_findings', d.get('hit_findings', 0)))} findings linked to evidence"
        if name == "fix_advice":
            new = _new_steps(d)
            return "Remediation guidance generated" if new else "No remediation required"
        if name == "report":
            return "Reports generated" if uc == "threat_intel" else "Word and PDF report written"
        if name == "dashboard":
            return "Dashboard updated" if uc == "threat_intel" else "Dashboard rebuilt"

        # Attack Detection sub-steps
        if name == "inputs":
            return "Loading indicators and hunting queries"
        if name == "hunt":
            return "Hunting completed with partial results" if d.get("errors") else "Hunting completed"
        if name == "resolve":
            new = _new_steps(d)
            return "Remediation plans generated" if new else "No new remediation plans required"
        if name == "publish":
            return "Detection results and reports published"

        # Shared
        if name == "alerts":
            return _alerts(d.get("new_alerts", 0)).capitalize()
        if name == "metrics":
            return "Benefit metrics updated"
        if name in ("fix_plan", "fix"):
            return fix_words(d, uc)
        if name == "auto_fix":
            return auto_fix_words(d)

        # Alert Triage sub-steps
        if name == "feedback":
            return "Analyst feedback synchronized"
        if name == "auto_resolve":
            if d.get("failed"):
                return "Response actions completed with errors"
            if d.get("escalate"):
                return "Incidents escalated for review"
            if d.get("resolve"):
                return "Response actions completed"
            if d.get("needs_human"):
                return "Pending analyst review"
            return "No response actions required"
        if name == "writeback":
            return f"{_n(value)} comments posted in Defender"
        if name == "actions":
            return f"{_plural(d.get('actions', 0), 'action')} recorded"
        if name == "ledger":
            return f"{d.get('matched', 0)} of {d.get('loaded', 0)} known cases matched to incidents"
        if name == "accuracy":
            return f"{d.get('lab_correct', 0)} of {d.get('lab_incidents', 0)} benchmark cases classified correctly"
        if name == "export":
            return "Triage results and reports published"
    except (KeyError, TypeError, ValueError):
        return None
    return None


def group_summary(key: str, r: dict, uc: str = "") -> str | None:
    """A finished pipeline step in a few plain words, from its sub-steps' results (None → keep the last sub-step's text)."""
    def get(name: str) -> dict:
        return r[name] if isinstance(r.get(name), dict) else {}
    try:
        # Threat Intel
        if key == "gather":
            return "Threat intelligence collection completed"
        if key == "affects":
            return threats_words(get("exposure"))
        if key == "fixes":
            new = _new_steps(get("fix_advice"))
            return "Remediation guidance generated" if new else "No remediation required"
        if key == "outputs":
            return "Report generation completed"

        # Attack Detection
        if key == "search":
            return "Hunting completed with partial results" if get("hunt").get("errors") else "Hunting completed"
        if key in ("evidence", "attack"):
            co = get("correlate")
            new_hits = co.get("new_hits", co.get("hit_findings", 0))
            if not new_hits:
                return "No new detections identified"
            return "New detection identified" if new_hits == 1 else "New detections identified"
        if key == "resolve":
            new = _new_steps(get("resolve"))
            return "Remediation plans generated" if new else "No new remediation plans required"

        # Shared Remediation (Stage 5)
        if key == "fix":
            if get("auto_fix"):
                return auto_fix_words(get("auto_fix"))
            return fix_words(get("fix") or get("fix_plan"), uc)

        # Publish
        if key == "publish":
            if uc == "alert_triage" or "export" in r or "triage" in r or "auto_resolve" in r:
                return "Triage results and reports published"
            return "Detection results and reports published"

        # Alert Triage
        if key == "act":
            ar, rs = get("auto_resolve"), get("respond")
            failed = ar.get("failed", 0) + rs.get("failed", 0)
            if failed:
                return "Response actions completed with errors"
            if rs.get("requested"):
                return "Defender scan or cleanup initiated"
            if ar.get("escalate"):
                return "Incidents escalated for review"
            if ar.get("resolve"):
                return "Response actions completed"
            if ar.get("needs_human"):
                return "Pending analyst review"
            return "No response actions required"
    except (KeyError, TypeError, ValueError):
        return None
    return None


@dataclass
class RunState:
    uc: str
    steps: list[Step]
    run_id: str = ""
    status: str = "running"                 # running | ok | partial | failed | skipped
    message: str = ""
    started_at: str = field(default_factory=_now)
    finished_at: str | None = None
    exit_code: int | None = None
    lines: int = 0
    log_tail: deque = field(default_factory=lambda: deque(maxlen=40))
    results: dict = field(default_factory=dict)   # raw step results, for the summary
    clock: str = ""                               # time of the line being read (from its time stamp)
    # Threat Intel bookkeeping: the flat sequence of internal step names and their status
    _seq: list[tuple[int, str]] = field(default_factory=list)
    _seq_status: list[str] = field(default_factory=list)
    _ptr: int = 0

    def __post_init__(self) -> None:
        self.clock = self.started_at
        for gi, step in enumerate(self.steps):
            for name in step.members:
                self._seq.append((gi, name))
                self._seq_status.append("pending")
        self.steps[0].status, self.steps[0].started_at = "running", self.started_at

    # ---------- shared helpers ----------
    def _start(self, i: int) -> None:
        if i < len(self.steps) and self.steps[i].status == "pending":
            self.steps[i].status, self.steps[i].started_at = "running", self.clock

    def _finish(self, i: int, status: str = "done", detail: str | None = None) -> None:
        step = self.steps[i]
        if step.status in ("pending", "running"):
            step.status, step.finished_at = status, self.clock
            step.started_at = step.started_at or step.finished_at
        if detail:
            step.detail = detail

    def _index(self, key: str) -> int:
        return next(i for i, s in enumerate(self.steps) if s.key == key)

    # ---------- line parsing ----------
    def feed(self, line: str) -> None:
        line = _OLD_LOGGERS.sub(lambda m: OLD_KEYS[m.group(1)] + ".", line.rstrip())
        if not line:
            return
        self.lines += 1
        self.clock = line_time(line) or self.clock
        self.log_tail.append(line)
        if "run is skipped" in line or line.startswith("Run skipped"):
            self.status, self.message = "skipped", "Another run of this pipeline is already in progress, so this one was skipped."
            return
        if "Another run is in progress" in line:
            self.status, self.message = "skipped", "Another run of this pipeline is already in progress, so this one was skipped."
            return
        {"threat_intel": self._feed_threat_intel, "attack_detection": self._feed_threat_intel, "alert_triage": self._feed_alert_triage}.get(self.uc, self._feed_vulnerability)(line)

    def _feed_vulnerability(self, line: str) -> None:
        d, c = self._index("download"), self._index("check")
        sc, a, fx = self._index("score"), self._index("advice"), self._index("fix")
        line = (line.replace("Advice agent", "Remediation agent").replace("Fix stage", "Remediation stage")   # older logs
                .replace("AI fix card:", "AI remediation card:").replace("AI fix guide", "AI remediation guide"))
        if "Remediation stage started" in line:
            self._finish(a, detail=self.steps[a].detail or "Remediation drafting completed")
            self._start(fx)
            self.steps[fx].detail = "Checking pending remediation actions"
            return
        if "Remediation stage finished:" in line:
            info = _literal(line.split("Remediation stage finished:", 1)[1].strip())
            if isinstance(info, dict):
                self.results["fix"] = info
                self._finish(fx, detail=fix_words(info))
            return
        if "Remediation stage skipped:" in line:
            detail = line.split("Remediation stage skipped:", 1)[1].strip()
            detail_lower = detail.lower()
            if "setting" in detail_lower or "disabled" in detail_lower or "switched off" in detail_lower:
                msg = "Disabled in settings"
            elif "timeout" in detail_lower or "timed out" in detail_lower:
                msg = "Remediation engine timed out"
            elif "plan" in detail_lower or "refresh" in detail_lower:
                msg = "Remediation plan refresh failed"
            elif "unavailable" in detail_lower or "not respond" in detail_lower or "no remediation engine" in detail_lower:
                msg = "Remediation engine unavailable"
            else:
                msg = _short(detail)
            self._finish(fx, "skipped", msg)
            return
        if "Extract finished:" in line:
            info = _literal(line.split("Extract finished:", 1)[1].strip())
            if isinstance(info, dict):
                self.results["extract"] = info
            self.steps[d].detail = download_words(info) if isinstance(info, dict) else ""
        elif "Load finished:" in line:
            info = _literal(line.split("Load finished:", 1)[1].strip())
            if isinstance(info, dict) and isinstance(self.results.get("extract"), dict):
                self.steps[d].detail = download_words(self.results["extract"], int(info.get("vulnerabilities") or 0))
        elif "vulnerability.extract:" in line:
            self.steps[d].detail = line.split("vulnerability.extract:", 1)[1].strip()
        elif "Updating the data lake" in line:
            self._finish(d)
            self._start(c)
        elif "Quality check failed" in line:
            self._finish(c, "error", "Validation failed")
        elif "Publishing the dashboard" in line:
            self._finish(c, detail=self.steps[c].detail or "Validation checks completed")
            self._start(sc)
        elif "Score and report finished:" in line:
            self._finish(sc, detail=REPORT_READY)
        elif "Report files:" in line:
            files = _literal(line.split("Report files:", 1)[1].strip())
            if isinstance(files, dict):
                self.results["report"] = files
        elif "Remediation agent started" in line:
            self._finish(sc, detail=self.steps[sc].detail or REPORT_READY)
            self._start(a)
        elif "AI remediation card:" in line:
            if self.steps[a].status == "pending":           # logs written before the stage markers existed
                self._finish(sc, detail=self.steps[sc].detail or REPORT_READY)
                self._start(a)
            item = line.split("AI remediation card:", 1)[1].split("(")[0].strip()
            self.steps[a].detail = f"Writing remediation steps: {item}"
        elif "Remediation agent finished:" in line:
            info = _literal(line.split("Remediation agent finished:", 1)[1].strip())
            if isinstance(info, dict):
                self.results["advice"] = info
                self._finish(a, detail=advice_summary(info, self.results.get("ai_stopped", "")))
            else:
                self._finish(a, "error", "Remediation drafting failed")
        elif "Open findings by severity:" in line:
            sev = _literal(line.split("Open findings by severity:", 1)[1].strip())
            if isinstance(sev, dict):
                self.results["severity"] = sev
        elif "vulnerability.ai:" in line and ("AI stopped:" in line or "AI explanations off:" in line):
            self.results["ai_stopped"] = line.split("AI stopped:" if "AI stopped:" in line else "AI explanations off:", 1)[1].strip()
        elif "AI remediation guide" in line and ":" in line:
            self.results["ai_fixes"] = line.split(":", 1)[1].strip()
        elif "Quality:" in line:
            self.results["quality"] = line.rsplit("Quality:", 1)[1].strip()
            q = self.results["quality"]
            self.steps[c].detail = "Data validation passed" if "PASS" in q else "Data validation completed with warnings" if "WARN" in q else "Validation checks completed"
        elif "Daily run finished" in line:
            self._finish(sc, detail=self.steps[sc].detail or REPORT_READY)
            self._finish(a, detail=self.steps[a].detail if self.steps[a].detail and not self.steps[a].detail.startswith("Writing")
                         else "Remediation drafting completed")
        elif "Run FAILED" in line:
            raw_msg = line.split("Run FAILED", 1)[1].strip(" :")
            self.message = _short(raw_msg)
            stage_err = {d: "Authentication failed" if "401" in raw_msg or "auth" in raw_msg.lower() else "Export retrieval failed" if "link" in raw_msg.lower() or "export" in raw_msg.lower() else "Data retrieval failed", c: "Validation failed", sc: "Report generation failed", a: "Remediation drafting failed", fx: "Remediation execution failed"}
            for i, s in enumerate(self.steps):
                if s.status == "running":
                    self._finish(i, "error", stage_err.get(i, self.message))

    def _feed_threat_intel(self, line: str) -> None:
        m = re.search(r"Step (\w+) (ok|failed|skipped)(?::\s*(.*))?", line)
        if not m:
            if "threat_intel.feeds:" in line and "Feed " in line:          # live detail while collecting
                self.steps[0].detail = _short(line.split("threat_intel.feeds:", 1)[1].strip())
            elif "Waiting for the Threat Intel run" in line:      # attack check: the two runs share one database
                self.steps[0].detail = "Waiting for the Threat Intel run to finish"
            elif "Run FAILED" in line or "Traceback" in line:
                self.message = self.message or _short(line)
            return
        name, outcome, result = m.group(1), m.group(2), m.group(3) or ""
        idx = next((i for i in range(self._ptr, len(self._seq)) if self._seq[i][1] == name), None)
        if idx is None:
            return
        for j in range(self._ptr, idx):                       # optional steps the pipeline did not need
            if self._seq_status[j] == "pending":
                self._seq_status[j] = "skipped"
        self._seq_status[idx] = {"ok": "done", "failed": "error", "skipped": "skipped"}[outcome]
        self._ptr = idx + 1
        group = self._seq[idx][0]
        if result:
            value = _literal(result)
            self.steps[group].detail = (friendly(name, value, self.uc) if outcome == "ok" else None) or _short(result)
            if outcome == "ok":
                self.results[name] = value
        self._refresh_groups()

    def _feed_alert_triage(self, line: str) -> None:
        """Alert Triage logs "Step <name> ok: ..." like Threat Intel, except triage: one "Triaged <id> -> <verdict>" line per incident."""
        if "alert_triage.ingest:" in line and "Ingest:" in line:
            self.results["ingest_text"] = _short(line.split("Ingest:", 1)[1].strip())
            self.steps[self._index("ingest")].detail = ingest_words(self.results["ingest_text"])
            return
        t = re.search(r"alert_triage\.triage: Triaged (\S+) -> (\w+)", line)
        if t:
            self.results.setdefault("verdicts", []).append(t.group(2))
            i = self._index("triage")
            self._start(i)
            n = len(self.results["verdicts"])
            self.steps[i].detail = VERDICT_WORDS.get(t.group(2), t.group(2))
            return
        if "Triage of" in line and "failed" in line:
            self.results["triage_failed"] = self.results.get("triage_failed", 0) + 1
            return
        m = re.search(r"Step (\w+) (ok|failed|skipped)", line)
        if m and m.group(1) in STEPS_AFTER_TRIAGE and "triage" not in self.results:
            # triage has no Step line of its own: it is done once a later step reports
            n, bad = len(self.results.get("verdicts", [])), self.results.get("triage_failed", 0)
            self.results["triage"] = n
            self._feed_threat_intel(f"Step triage {'failed' if bad and not n else 'ok'}: " + self._triage_text(n, bad))
        self._feed_threat_intel(line)
        if m and m.group(1) == "ingest" and self.results.get("ingest_text"):
            self.steps[self._index("ingest")].detail = ingest_words(self.results["ingest_text"])

    def _triage_text(self, n: int, failed: int) -> str:
        if not n and not failed:
            return "No incidents requiring triage"
        if failed:
            return "Incident classification completed with errors"
        return "Incident classification completed"
    def _refresh_groups(self) -> None:
        for gi, step in enumerate(self.steps):
            states = [self._seq_status[i] for i, (g, _) in enumerate(self._seq) if g == gi]
            if all(s in ("done", "skipped", "error") for s in states):
                if all(s == "skipped" for s in states):
                    self._finish(gi, "skipped")
                else:
                    self._finish(gi, "error" if "error" in states else "done")
                    if "error" not in states:
                        step.detail = group_summary(step.key, self.results, self.uc) or step.detail
                    else:
                        step.detail = STAGE_ERRORS.get(self.uc, {}).get(step.key, "Operation failed")
            elif any(s != "pending" for s in states):
                self._start(gi)
        nxt = next((i for i, s in enumerate(self.steps) if s.status in ("pending", "running")), None)
        if nxt is not None:
            self._start(nxt)

    # ---------- end of run ----------
    def close(self, exit_code: int | None, finished_at: str | None = None, lost: bool = False) -> None:
        self.exit_code, self.finished_at = exit_code, finished_at or self.clock
        self.clock = self.finished_at
        if self.status == "skipped":
            for s in self.steps:
                if s.status in ("pending", "running"):
                    s.status = "skipped"
            return
        if lost:
            self.status = "failed"
            for i, s in enumerate(self.steps):
                if s.status == "running":
                    self._finish(i, "error", "Stopped here")
            self.message = ("The run stopped without finishing (the server or CyberSuite may have been restarted). "
                            "The log shows how far it got. Press Run to try again.")
            return
        if exit_code == 0:
            for i, s in enumerate(self.steps):
                if s.status in ("pending", "running"):
                    # Vulnerability's Fix stage is optional (and missing from runs before it existed): never "done" unseen
                    unseen = s.status == "pending" and (self.uc in ("threat_intel", "alert_triage", "attack_detection") or s.key == "fix")
                    self._finish(i, "skipped" if unseen else "done")
            errors = [s for s in self.steps if s.status == "error"]
            self.status = "partial" if errors else "ok"
            self.message = self.message or ("Finished with problems in: " + ", ".join(s.label for s in errors) if errors else "Finished")
        else:
            self.status = "failed"
            reason = stop_reason([self.message, *self.log_tail])
            for i, s in enumerate(self.steps):
                if s.status == "running":
                    self._finish(i, "error", "Stopped here")
            stopped = next((s.label for s in self.steps if s.status == "error"), "")
            self.message = (f"Stopped at {stopped} because {reason}." if stopped else f"The run stopped because {reason}.")

    # ---------- the plain-English summary shown when a run ends ----------
    def facts(self) -> list[dict]:
        r, out, named = self.results, [], self.new_ids()     # named: the items the run page lists by name

        def add(label: str, value, hint: str = "") -> None:
            if value not in (None, ""):
                out.append({"label": label, "value": str(value), "hint": hint})

        if self.uc == "vulnerability":
            # Only what this run did: totals of everything still open are on the Dashboard
            ex = r.get("extract") or {}
            counts = defender_new(ex)
            if counts is not None:
                stale = ex.get("defender_refreshed") is False
                add("New in this run", f"{counts[0]:,}",
                    "Defender has no newer data yet" if stale else "not there in the last run")
                add("Remediated since the last run", f"{counts[1]:,}",
                    "Defender has no newer data yet" if stale else "no longer found by Defender")
            adv = r.get("advice") if isinstance(r.get("advice"), dict) else {}
            if adv:
                settings = adv.get("settings", 0)
                total = int(adv.get("apps", 0) + settings)
                reused = adv.get("reused")
                asked = adv.get("asked")
                changes = int(asked) if asked is not None else (max(0, total - int(reused)) if reused is not None else total)
                # only cards this run wrote: the cards kept from earlier runs are in Remediation, not counted here
                add("Remediation cards written", f"{changes:,}",
                    "for new or changed findings in this run" if changes else "no new or changed findings in this run")
            fx = self.fix_result()
            if fx:
                new = int(fx.get("new") or 0)
                # fix_waiting() replaces this hint with the decisions made on the run page
                add(APPROVED_FACT, "0", f"{new} new remediation{'s' if new != 1 else ''} awaiting your approval below" if new
                    else "no new remediations in this run")
            return out
        if self.uc == "alert_triage":
            c = ingest_counts(r.get("ingest_text") or "")
            if c is not None:
                rest = ingest_parts({**c, "new_alerts": c["new_alerts"] if c["new"] is not None else 0})
                add("New incidents in Defender", c["new"] if c["new"] is not None else c["new_alerts"],
                    " · ".join(rest) if rest else "nothing else changed since the last check")
            verdicts = r.get("verdicts") or []
            if "triage" in r or verdicts:
                words = {}
                for v in verdicts:
                    words[VERDICT_WORDS.get(v, v)] = words.get(VERDICT_WORDS.get(v, v), 0) + 1
                add("Incidents triaged", len(verdicts), ", ".join(verdict_count(c, w) for w, c in words.items()) or "nothing new")
            ar = r.get("auto_resolve") if isinstance(r.get("auto_resolve"), dict) else None
            if ar is not None:
                add("Handled automatically", ar.get("resolve", 0) + ar.get("escalate", 0),
                    f"{ar.get('resolve', 0)} closed, {ar.get('escalate', 0)} escalated")
            acc = r.get("accuracy") if isinstance(r.get("accuracy"), dict) else {}
            if acc.get("lab_incidents"):
                add("Benchmark cases classified correctly", f"{acc.get('lab_correct', 0)} / {acc['lab_incidents']}",
                    f"{acc.get('lab_missed_tp', 0)} true positives missed")
            fb = r.get("feedback") if isinstance(r.get("feedback"), dict) else {}
            add("Your feedback imported", fb.get("feedback") if fb else None, "agree / disagree clicks")
            return out
        if self.uc == "attack_detection":
            # only what this run added: earlier signs and their fix steps are on the Attack detection page
            co = r.get("correlate") if isinstance(r.get("correlate"), dict) else {}
            if co:
                add("New detections", co.get("new_hits", 0),
                    ("since the last run" + (", listed below" if named.get("attack") else "")) if co.get("new_hits")
                    else "Defender hunts found nothing new on managed devices")
            rs = r.get("resolve") if isinstance(r.get("resolve"), dict) else {}
            if rs:
                add("Remediation steps written this run", _new_steps(rs), "for detections")
            al = r.get("alerts") if isinstance(r.get("alerts"), dict) else {}
            add("Alerts sent", al.get("new_alerts"),
                ("to the security team" + (", listed below" if named.get("alerts") else "")) if al.get("new_alerts")
                else "only for applicable Critical or High threats; none new this run")
            self._fix_fact(add)
            return out
        feeds = r.get("collect") if isinstance(r.get("collect"), dict) else {}
        new_items = sum(int(n) for v in feeds.values() for n in re.findall(r"\d+", str(v)))
        ok = sum(1 for v in feeds.values() if str(v).startswith("ok"))
        failed = sum(1 for v in feeds.values() if not str(v).startswith(("ok", "skipped")))
        add("Threat intelligence items checked", f"{new_items:,}" if feeds else None,
            f"from {_plural(ok, 'public source')}" + (f" · {failed} could not be reached" if failed else ""))
        ex = r.get("exposure") if isinstance(r.get("exposure"), dict) else {}
        add("New applicable threats", ex.get("new_threats_exposed"),
            ("since the last run" + (", listed below" if named.get("threats") else "")) if ex.get("new_threats_exposed")
            else "nothing new on managed devices")
        fx = r.get("fix_advice") if isinstance(r.get("fix_advice"), dict) else {}
        if fx:
            add("Remediation steps written this run", _new_steps(fx), "for applicable threats")
        self._fix_fact(add)
        return out

    def _fix_fact(self, add) -> None:
        fx = self.fix_result()
        if fx:
            new = int(fx.get("new") or 0)
            add("New remediations to approve", f"{new:,}", "proposed in this run: decide on each below" if new
                else "nothing new to approve in this run")

    def report_file(self) -> str | None:
        rep = self.results.get("report")
        path = rep.get("docx") if isinstance(rep, dict) else None
        return Path(path).name if path else None

    def report_files(self) -> list[str]:
        """This run's report files (Excel, Word, PDF) by name, for the download buttons."""
        rep = self.results.get("report")
        if not isinstance(rep, dict):
            return []
        return [Path(rep[k]).name for k in ("xlsx", "docx", "pdf") if isinstance(rep.get(k), str) and rep[k]]

    def fix_result(self) -> dict | None:
        """The Fix stage's result: Vulnerability logs it as "Fix stage finished", Threat Intel's two runs as step fix_plan."""
        fix = self.results.get("fix") or self.results.get("fix_plan")
        return fix if isinstance(fix, dict) and "new_ids" in fix else None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id, "uc": self.uc, "status": self.status, "message": self.message,
            "started_at": self.started_at, "finished_at": self.finished_at, "exit_code": self.exit_code,
            "steps": [{k: getattr(s, k) for k in ("key", "label", "description", "status", "detail", "started_at", "finished_at")}
                      for s in self.steps],
            "facts": self.facts(), "report_file": self.report_file(), "report_files": self.report_files(),
            "files_from": self.uc, "lines": self.lines,
            "log_tail": list(self.log_tail)[-12:],
            # Vulnerability's Fix stage: the fixes this run proposed (the run page shows them as cards to approve)
            "fix": self.fix_result(),
            "new_ids": self.new_ids(),
        }

    def new_ids(self) -> dict[str, list[str]]:
        """The new threats affecting us, signs of attack and alerts of a Threat Intel / Attack Detection run, by id
        (logged by those agents since 28 Oct 2026; older runs have none). run_findings() turns them into names."""
        def ids(step: str, key: str) -> list[str]:
            res = self.results.get(step)
            return [str(i) for i in res.get(key) or []] if isinstance(res, dict) else []
        if self.uc not in ("threat_intel", "attack_detection"):
            return {}
        return {"threats": ids("exposure", "new_threat_ids"), "attack": ids("correlate", "new_hit_ids"),
                "alerts": ids("alerts", "new_alert_ids")}


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    if sys.platform == "win32":
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))   # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        code = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(ok) and code.value == 259                                  # STILL_ACTIVE
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


FIX_TO_DO = {"approved", "queued", "running", "done", "failed", "verified", "still_there", "gone"}
APPROVED_FACT = "Remediations approved"       # Vulnerability's result card for this run's new fixes, kept current by fix_waiting()


def fix_waiting(run: dict, fix_dir: Path, read: Callable[[Path], dict | None] = _read_json) -> dict:
    """The Fix stage ends only when a person has decided on every new fix of the run (Fix or Save for later).

    Decisions live in the fix engine's data/fix/state.json; a new fix that left the plan (Defender stopped listing
    it) needs no decision any more. Until then the stage is "waiting" and the run page asks for the decisions.
    """
    fix, step = run.get("fix"), next((s for s in run.get("steps", []) if s["key"] == "fix"), None)
    if not fix or not step or run.get("status") not in ("ok", "partial") or step["status"] != "done":
        return run
    decided = (read(fix_dir / "state.json") or {}).get("fixes") or {}
    planned = {i.get("fix_id") for i in (read(fix_dir / "plan.json") or {}).get("items") or []}
    # only this run's remediations that still exist: one that left the plan undecided is not counted anywhere
    ids = [i for i in fix.get("new_ids") or [] if i in planned or i in decided]
    open_ids = [i for i in ids if i not in decided and i in planned]
    to_fix = sum(1 for i in ids if (decided.get(i) or {}).get("status") in FIX_TO_DO)
    saved = sum(1 for i in ids if (decided.get(i) or {}).get("status") == "saved")
    step = {**step}
    if open_ids:
        if run.get("uc") == "threat_intel":
            detail = "Awaiting analyst review" if len(open_ids) == len(ids) else "Remediation decisions pending"
        elif run.get("uc") == "attack_detection":
            detail = "Remediation decisions pending"
        else:
            detail = f"Awaiting your decision: {len(open_ids)} of {len(ids)} new remediation{'s' if len(ids) != 1 else ''}"
        step.update(status="waiting", finished_at=None, detail=detail)
    elif ids and not str(step.get("detail") or "").startswith("Auto-fix"):
        if run.get("uc") == "threat_intel":
            step["detail"] = "All remediation decisions recorded"
        elif run.get("uc") == "attack_detection":
            step["detail"] = "Remediation decisions completed"
        else:
            step["detail"] = f"All {len(ids)} decided: {to_fix} approved, {saved} deferred"
    hint = (f"{len(open_ids)} still waiting for you below" if open_ids
            else f"of {len(ids)} new remediation{'s' if len(ids) != 1 else ''} in this run" if ids else "no new remediations in this run")
    facts = [{**f, "value": str(to_fix), "hint": hint} if f.get("label") == APPROVED_FACT
             else {**f, "value": f"{len(open_ids):,}", "hint": "proposed in this run: decide on each below" if open_ids
                   else "nothing new to approve in this run"} if f.get("label") == "New remediations to approve" else f
             for f in run.get("facts") or []]
    return {**run, "fix": {**fix, "new_ids": ids, "new": len(ids), "open": len(open_ids), "to_fix": to_fix, "saved_now": saved}, "facts": facts,
            "steps": [step if s["key"] == "fix" else s for s in run["steps"]], "waiting_for_you": bool(open_ids)}


def _line(message: str, prefix: str) -> str:
    return next((ln[len(prefix):].strip() for ln in message.splitlines() if ln.startswith(prefix)), "")


def _clip(text: str | None, n: int = 220) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + "…"


def run_findings(new_ids: dict | None, dashboard: dict | None) -> list[dict]:
    """What a Threat Intel / Attack Detection run found, by name, with why it matters and the first thing to do.

    The run logs only ids; the details come from the Threat Intel Agent's dashboard_data.json, written at the end of
    the same run. Something the dashboard no longer lists (rescored, closed) is left out.
    """
    if not new_ids or not dashboard:
        return []
    out: list[dict] = []
    threats = {t.get("id"): t for t in dashboard.get("explorer") or []}
    for tid in new_ids.get("threats") or []:
        t = threats.get(tid)
        if t:
            out.append({"kind": "threat", "id": tid, "title": t.get("title") or tid, "rating": t.get("rating"),
                        "why": _clip(t.get("summary")), "where": t.get("devices") or "",
                        "action": t.get("action") or "", "test": bool(t.get("test")), "to": f"/threat-intel/threat/{quote(tid, safe='')}"})
    hits = {h.get("finding_id"): h for h in dashboard.get("hits") or []}
    for fid in new_ids.get("attack") or []:
        h = hits.get(fid)
        if h:
            res = h.get("resolution") or {}
            out.append({"kind": "attack", "id": fid, "title": str(h.get("title") or h.get("detail") or "").removeprefix("Hunt hit: "),
                        "rating": None, "why": _clip(res.get("what_happened") or h.get("detail")),
                        "where": h.get("device_name") or "", "action": ((res.get("steps") or [""])[0]),
                        "test": bool(h.get("is_test")), "to": "/attack-detection"})
    alerts = {a.get("alert_id"): a for a in dashboard.get("alerts") or []}
    for aid in new_ids.get("alerts") or []:
        a = alerts.get(aid)
        if a:
            msg = a.get("message") or ""
            out.append({"kind": "alert", "id": aid, "title": a.get("title") or "", "rating": a.get("rating"),
                        "why": f"Rated {a.get('rating')} and it applies to our devices, so the security team is told",
                        "where": _line(msg, "Affected:"), "action": _line(msg, "First action:"),
                        "test": bool(a.get("is_test")), "to": f"/threat-intel/threat/{quote(str(a.get('threat_id')), safe='')}"})
    return out


class _MtimeCache:
    """Reads a JSON file again only when it changed (the run page asks every few seconds; plan.json is large)."""

    def __init__(self):
        self._seen: dict[Path, tuple[float, dict | None]] = {}

    def __call__(self, path: Path) -> dict | None:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        if path not in self._seen or self._seen[path][0] != mtime:
            self._seen[path] = (mtime, _read_json(path))
        return self._seen[path][1]


class RunManager:
    """Runs live in data/runs/<run_id>/; the latest one per use case is what the run page shows."""

    def __init__(self, uc_dirs: dict[str, Path], runs_dir: Path | None = None,
                 spawn: Callable[..., subprocess.Popen] | None = None, alive: Callable[[int | None], bool] = _pid_alive,
                 audit_dir: Path | None = None):
        self.uc_dirs = uc_dirs
        self.runs_dir = runs_dir or Path(__file__).resolve().parents[2] / "data" / "runs"
        self.audit_dir = audit_dir      # the wrapper writes "run finished" to the audit log there (audit.py)
        self.spawn = spawn or subprocess.Popen
        self.alive = alive
        self.lock = threading.Lock()
        self._cache: dict[str, tuple[tuple, RunState]] = {}
        self._fix_files = _MtimeCache()
        # the fix engine (Threat Intel's data/fix) keeps the decisions on every agent's new fixes
        self.fix_dir = uc_dirs["threat_intel"] / "data" / "fix" if "threat_intel" in uc_dirs else None

    # ---------- reading ----------
    def _run_dirs(self, uc: str | None = None) -> list[Path]:
        if not self.runs_dir.is_dir():
            return []
        dirs = [d for d in self.runs_dir.iterdir() if d.is_dir() and (d / "meta.json").is_file()]
        if uc:
            dirs = [d for d in dirs if agent_key(d.name.rsplit("_", 1)[-1]) == uc or d.name.endswith("_" + uc)]
        return sorted(dirs, key=lambda d: d.name, reverse=True)

    def load(self, run_dir: Path) -> RunState | None:
        meta = _read_json(run_dir / "meta.json")
        if not meta:
            return None
        log, res = run_dir / "output.log", run_dir / "result.json"
        key = (log.stat().st_size if log.is_file() else -1, res.is_file(), meta.get("wrapper_pid"))
        cached = self._cache.get(run_dir.name)
        if cached and cached[0] == key and cached[1].status != "running":
            return cached[1]
        uc = agent_key(meta["uc"])
        state = RunState(uc, STEPS.get(uc, vulnerability_steps)(), run_id=run_dir.name, started_at=meta["started_at"])
        if log.is_file():
            with log.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    state.feed(line)
        result = _read_json(res)
        if result:
            state.close(result.get("exit_code"), result.get("finished_at"))
        elif not self.alive(meta.get("wrapper_pid")) and not self._just_started(meta):
            state.close(None, lost=True)
        self._cache[run_dir.name] = (key, state)
        return state

    @staticmethod
    def _just_started(meta: dict) -> bool:
        started = datetime.fromisoformat(meta["started_at"])
        return (datetime.now(timezone.utc) - started).total_seconds() < 20 and not meta.get("wrapper_pid")

    def latest(self, uc: str) -> RunState | None:
        dirs = self._run_dirs(uc)
        return self.load(dirs[0]) if dirs else None

    def running(self, uc: str) -> bool:
        st = self.latest(uc)
        return bool(st and st.status == "running")

    def typical_seconds(self, uc: str) -> int | None:
        durations = []
        for d in self._run_dirs(uc)[:10]:
            st = self.load(d)
            if st and st.status in ("ok", "partial") and st.finished_at:
                durations.append((datetime.fromisoformat(st.finished_at) - datetime.fromisoformat(st.started_at)).total_seconds())
        return int(median(durations)) if durations else None

    def snapshot(self) -> dict:
        with self.lock:
            out = {}
            for uc in self.uc_dirs:
                st = self.latest(uc)
                run = {**st.to_dict(), "typical_seconds": self.typical_seconds(uc)} if st else None
                if run and run["status"] != "running" and any((run.get("new_ids") or {}).values()):
                    if uc == "attack_detection":         # its own published detections (one per attack per device)
                        pub = self._fix_files(self.uc_dirs[uc] / "data" / "out" / "findings.json") or {}
                        run["findings"] = run_findings(run["new_ids"], {"hits": pub.get("findings") or []})
                        # count only the detections still published: merged or removed ones are not new detections
                        n = sum(1 for f in run["findings"] if f["kind"] == "attack")
                        run["facts"] = [{**f, "value": str(n), "hint": f["hint"] if n else "no new detections on managed devices"}
                                        if f.get("label") == "New detections" else f for f in run.get("facts") or []]
                    else:
                        run["findings"] = run_findings(run["new_ids"], self._fix_files(self.uc_dirs[uc] / "data" / "dashboard" / "dashboard_data.json"))
                out[uc] = fix_waiting(run, self.fix_dir, self._fix_files) if run and self.fix_dir else run
            return out

    def fixes_waiting(self, uc: str, current: RunState | None) -> int:
        """New fixes of the last run that nobody has decided on yet (Fix or Save for later)."""
        if not current or not self.fix_dir:
            return 0
        run = fix_waiting(current.to_dict(), self.fix_dir, self._fix_files)
        return int((run.get("fix") or {}).get("open") or 0) if run.get("waiting_for_you") else 0

    def history(self, limit: int = 12) -> list[dict]:
        with self.lock:
            rows = []
            for d in self._run_dirs()[:limit]:
                st = self.load(d)
                if st:
                    rows.append({k: v for k, v in st.to_dict().items() if k not in ("log_tail", "facts")})
            return rows

    # ---------- starting ----------
    def start(self, uc: str, by: dict | None = None) -> tuple[bool, RunState | None, str]:
        """by = who pressed Run ({email, name}); kept in meta.json and in the audit log."""
        root = self.uc_dirs.get(uc)
        if root is None:
            return False, None, "unknown use case"
        if not ((root / ".venv" / "Scripts" / "python.exe").is_file() or (root / ".venv" / "bin" / "python").is_file()):
            return False, None, f"{uc.upper()} has no Python environment at {root / '.venv'}"
        with self.lock:
            current = self.latest(uc)
            if current and current.status == "running":
                return False, current, "already running"
            # the run is not over until a person decided on its new fixes: a new run would bury them
            waiting = self.fixes_waiting(uc, current)
            if waiting:
                return False, current, (f"The last run is paused at the Remediation stage: {waiting} new "
                                        + ("remediation still needs" if waiting == 1 else "remediations still need")
                                        + " your decision. Approve or defer each one below, then run again.")
            # threat_intel and attack both run in Threat Intel's folder and open its one DuckDB file, which only one process may hold
            for other, other_root in self.uc_dirs.items():
                if other != uc and other_root == root and self.running(other):
                    return False, current, (f"The {AGENT_NAMES[other]} is still running and uses the same database. "
                                            f"Run the {AGENT_NAMES[uc]} again when it has finished.")
            run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uc
            run_dir = self.runs_dir / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "meta.json").write_text(json.dumps({"uc": uc, "run_id": run_id, "started_at": _now(), "by": by or "portal",
                                                           "agent": AGENT_NAMES.get(uc, uc)}), encoding="utf-8")
            cmd = [sys.executable, "-m", "dashboard.runner", "--uc", uc, "--root", str(root), "--run-dir", str(run_dir)]
            if self.audit_dir:
                cmd += ["--audit-dir", str(self.audit_dir)]
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
            self._spawn_detached(cmd, env)
            state = self.load(run_dir)
        return True, state, "started"

    def _spawn_detached(self, cmd: list[str], env: dict) -> None:
        """The wrapper must outlive the portal.

        On Windows a child process is ended together with the portal when the portal runs inside a job object (as it
        does when started by a launcher or an IDE), even with DETACHED_PROCESS. So we ask Windows (WMI
        Win32_Process.Create) to start it: the process then belongs to Windows, not to the portal. Fallback: a
        detached child, which survives a normal portal restart but not a killed job.
        """
        kwargs = dict(env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        if self.spawn is not subprocess.Popen:          # tests inject a fake
            self.spawn(cmd, **kwargs)
            return
        if sys.platform == "win32":
            if self._spawn_via_wmi(cmd):
                return
            base = 0x00000008 | 0x00000200 | 0x08000000      # DETACHED_PROCESS | NEW_PROCESS_GROUP | NO_WINDOW
            try:
                subprocess.Popen(cmd, creationflags=base | 0x01000000, **kwargs)   # + BREAKAWAY_FROM_JOB
            except OSError:
                subprocess.Popen(cmd, creationflags=base, **kwargs)
        else:
            subprocess.Popen(cmd, start_new_session=True, **kwargs)

    @staticmethod
    def _spawn_via_wmi(cmd: list[str]) -> bool:
        import base64
        q = lambda s: s.replace("'", "''")  # noqa: E731 - PowerShell single-quote escaping
        script = (
            "$si = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ShowWindow=[uint16]0};"
            f"$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine='{q(subprocess.list2cmdline(cmd))}';"
            f"CurrentDirectory='{q(str(Path(__file__).resolve().parents[2]))}';ProcessStartupInformation=$si}};"
            "exit [int]$r.ReturnValue"
        )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        try:
            done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                  capture_output=True, timeout=30, creationflags=0x08000000)
            return done.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
