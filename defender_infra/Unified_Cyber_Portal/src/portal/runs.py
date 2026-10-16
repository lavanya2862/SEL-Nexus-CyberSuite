"""Start a use case's real pipeline and follow it step by step (for the live run page).

The portal never imports UC code. Each run gets a folder under data/runs/<run_id>/:
  meta.json    who/when (written by the portal), plus the process ids (written by the wrapper)
  output.log   every line the pipeline prints (written live by portal.runner)
  result.json  exit code and finish time (written by portal.runner when the run ends)
The run itself is a separate process (portal.runner), so it survives a portal restart; the portal rebuilds the
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
    members: tuple[str, ...] = ()           # UC1: pipeline step names that make up this friendly step
    status: str = "pending"                 # pending | running | done | error | skipped
    detail: str = ""
    started_at: str | None = None
    finished_at: str | None = None


# Friendly steps, in order. UC1 groups its internal steps into 4 a person can follow, the attack check into 4, UC4 its 10 into 4.
# Members must follow the pipeline's own order (they are matched against the log one after another).
def uc3_steps() -> list[Step]:
    return [
        Step("download", "Extract", "Collect every weakness from Microsoft Defender"),
        Step("check", "Validate", "Save today's copy and check nothing is missing"),
        Step("score", "Score and report", "Rate each problem and prepare the report numbers"),
        Step("advice", "Advice agent", "AI writes the steps to fix every problem"),
    ]


def uc1_steps() -> list[Step]:
    return [
        Step("gather", "Gather threat news and understand it", "New threats from 10 public feeds; AI reads each one and how likely it is to be used",
             ("collect", "inventory", "derive", "nvd_details", "epss", "products", "analyse")),
        Step("affects", "Check if it affects us", "Is the software these threats target on our computers?",
             ("exposure", "score", "correlate")),
        Step("fixes", "Write fix steps", "AI writes how to fix each threat that affects us, checked against Defender's data",
             ("fix_advice",)),
        Step("outputs", "Write the report", "The new threats that affect us and how to fix them, alerts and the report",
             ("alerts", "report", "dashboard", "metrics")),
    ]


def attack_steps() -> list[Step]:
    """The Attack Detection Agent: UC1's `attack-check` run, on its own so it can run more often than the news."""
    return [
        Step("search", "Search our computers", "Look in Microsoft Defender (last 30 days) for the warning signs from threat news and known attacker tricks",
             ("hunt",)),
        Step("evidence", "Connect the evidence", "Who was logged in and what Defender said; earlier signs are kept, new ones added",
             ("correlate", "exposure", "rescore")),
        Step("resolve", "Write resolution steps", "AI writes how to resolve each new sign of attack, checked against the evidence",
             ("resolve",)),
        Step("publish", "Publish", "Update the Attack detection page and raise alerts", ("alerts", "dashboard")),
    ]


def uc4_steps() -> list[Step]:
    return [
        # The pipeline's own housekeeping (feedback import, lab grading) still runs; it is just not shown as a step.
        Step("ingest", "Read new alerts", "New or changed incidents from Microsoft Defender and Sentinel", ("ingest",)),
        Step("triage", "Check each alert", "AI looks at the evidence and decides: real threat, false alarm, or needs a person",
             ("triage",)),
        Step("act", "Take action", "Close false alarms, escalate real threats, ask Defender to scan or clean up (when switched on)",
             ("auto_resolve", "respond", "writeback", "actions")),
        Step("publish", "Update the queue", "Results ready to review on the Alert triage page", ("metrics", "export")),
    ]


STEPS = {"uc1": uc1_steps, "uc3": uc3_steps, "uc4": uc4_steps, "attack": attack_steps}
UC4_AFTER_TRIAGE = {"auto_resolve", "respond", "defender_view", "writeback", "actions", "ledger", "accuracy", "metrics", "export"}
VERDICT_WORDS = {"likely_true_positive": "real threat", "likely_false_positive": "false alarm",
                 "benign_positive": "false positive", "needs_investigation": "needs a person"}


def verdict_count(n: int, words: str) -> str:
    """ "2 false alarms", "1 real threat", "3 needs a person" """
    return f"{n} {words}" + ("s" if n != 1 and words.endswith(("threat", "alarm")) else "")


def ingest_words(text: str) -> str:
    """ "6 incident(s) returned, 0 need triage" → "6 incidents in Defender · none new" """
    got = re.findall(r"\d+", text)
    if len(got) < 2:
        return text
    total, new = int(got[0]), int(got[1])
    return f"{_plural(total, 'incident')} in Defender · " + (f"{new} new to check" if new else "none new")


REPORT_READY = "Report updated with today's numbers"


def advice_status(info: dict, stopped: str = "") -> tuple[str, str]:
    """UC3 advice agent result as (value, hint), e.g. ("24 waiting", "AI daily limit reached: ...").

    A fix card needs new AI text when its app or setting changed. Cards the AI could not write this run keep basic
    steps ("rules") or the older AI text ("previous facts": ai minus reused minus asked); both are "waiting".
    `stopped` is the reason from the "AI stopped" / "AI explanations off" warning, if the log had one.
    """
    asked = info.get("asked", 0)
    waiting = info.get("rules", 0) + max(0, info.get("ai", 0) - info.get("reused", 0) - asked)
    why = ("AI daily limit reached" if "quota" in stopped.lower() else "AI not available" if stopped
           else "AI answers did not pass the checks")
    if asked:
        return f"{asked} new", f"fixes written by AI" + (f" · {waiting} still waiting ({why})" if waiting else "")
    if waiting:
        return f"{waiting} waiting", f"{why}: basic or older steps shown until the next run"
    return "Up to date", "nothing changed, so no new advice was needed"


def advice_summary(info: dict, stopped: str = "") -> str:
    """The advice step in a few words: "3 new fixes written by AI", "AI daily limit reached: 24 fixes wait"…"""
    value, hint = advice_status(info, stopped)
    if value.endswith("new"):
        return f"{value} {hint}"
    if value.endswith("waiting"):
        return f"{hint.split(':')[0]}: {value.split()[0]} fixes wait for the next run"
    return "All fixes up to date"


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


def friendly(name: str, value) -> str | None:
    """A UC1 step result as one plain sentence (None → show the raw text)."""
    d = value if isinstance(value, dict) else {}
    try:
        if name == "collect":
            new = sum(int(n) for v in d.values() for n in re.findall(r"\d+", str(v)))
            return f"{_n(new)} new items · {feed_counts(d)}"
        if name == "inventory":
            return f"{_n(d['vulnerabilities'])} vulnerabilities on {d['devices']} computers"
        if name == "derive":
            return f"{_n(d.get('relevant_new_cves', 0))} new CVEs that matter to us"
        if name == "nvd_details":
            return f"Details for {_n(value)} CVEs from NVD"
        if name == "epss":
            return f"Exploit odds for {_n(value)} CVEs (EPSS)"
        if name == "products":
            return "Linked CVEs to the products they affect"
        if name == "analyse":
            return f"{_n(d['candidates'])} threats assessed · {_n(d.get('ai_done', 0))} by AI, {_n(d.get('rules_only', 0))} by rules"
        if name == "exposure":
            return f"{_n(d['threats_exposed'])} threats affect our {d.get('devices', '?')} computers"
        if name in ("score", "rescore"):
            return f"{d.get('Critical', 0)} critical · {d.get('High', 0)} high · {d.get('Medium', 0)} medium"
        if name == "hunt":
            return f"{d['ok']} of {d['hunts']} hunts ran · {_n(d.get('rows', 0))} rows found"
        if name == "correlate":
            return f"{_n(d.get('exposure_findings', 0))} findings linked to evidence"
        if name == "alerts":
            return f"{d['new_alerts']} new alerts"
        if name == "fix_advice":
            return f"Fix steps for {_plural(d['threats'], 'threat')} · {d['by_ai']} by AI"
        if name == "resolve":
            return f"Resolution steps for {_plural(d['signs'], 'sign')} of attack · {d['by_ai']} by AI"
        if name == "report":
            return "Word and PDF report written"
        if name == "dashboard":
            return "Dashboard rebuilt"
        if name == "metrics":
            return "Benefit metrics updated"
        # UC4
        if name == "feedback":
            return f"{_plural(d.get('feedback', 0), 'feedback click')} · {_plural(d.get('actions', 0), 'action')} imported"
        if name == "auto_resolve":
            return (f"{d.get('resolve', 0)} closed · {d.get('escalate', 0)} escalated · "
                    f"{d.get('needs_human', 0)} left for a person" + (f" · {d['failed']} failed" if d.get("failed") else ""))
        if name == "writeback":
            return f"{_n(value)} comments posted in Defender"
        if name == "actions":
            return f"{_plural(d.get('actions', 0), 'action')} recorded"
        if name == "ledger":
            return f"{d.get('matched', 0)} of {d.get('loaded', 0)} known cases matched to incidents"
        if name == "accuracy":
            return f"{d.get('lab_correct', 0)} of {d.get('lab_incidents', 0)} known cases called right"
        if name == "export":
            return "Triage queue published"
    except (KeyError, TypeError, ValueError):
        return None
    return None


def group_summary(key: str, r: dict) -> str | None:
    """A finished UC1 / UC4 step in a few plain words, from its sub-steps' results (None → keep the last sub-step's text)."""
    def get(name: str) -> dict:
        return r[name] if isinstance(r.get(name), dict) else {}
    try:
        if key == "gather":
            feeds, an = get("collect"), get("analyse")
            news = sum(int(n) for v in feeds.values() for n in re.findall(r"\d+", str(v)))
            failed = [k for k, v in feeds.items() if not str(v).startswith(("ok", "skipped"))]
            text = f"{_n(news)} news items · {_n(an['candidates'])} threats understood"
            return text + (f" · feed failed: {', '.join(failed)}" if failed else "")
        if key == "affects":
            ex = get("exposure")
            return f"{_plural(ex['threats_exposed'], 'threat')} hit our computers"
        if key == "fixes":
            fx = get("fix_advice")
            return f"Fix steps for {_plural(fx['threats'], 'threat')} that affect us · {fx['by_ai']} by AI"
        if key == "search":
            hu = get("hunt")
            return f"{hu['ok']} of {hu['hunts']} searches ran · {_n(hu.get('rows', 0))} rows found"
        if key == "resolve":
            rs = get("resolve")
            return f"Resolution steps for {_plural(rs['signs'], 'sign')} of attack · {rs['by_ai']} by AI"
        if key == "publish":
            al = get("alerts")
            return f"Attack detection page updated · {_plural(al['new_alerts'], 'new alert')}"
        if key in ("evidence", "attack"):
            # what this run added; the Attack detection page keeps every earlier sign as well
            co = get("correlate")
            if "new_hits" not in co:                                  # runs from before signs were kept
                return f"{_plural(co['hit_findings'], 'sign')} of attack found" if co["hit_findings"] else "No signs of attack found"
            return f"{_plural(co['new_hits'], 'new sign')} of attack found" if co["new_hits"] else "No new signs of attack"
        if key == "outputs":
            al, rs = get("alerts"), get("resolve")
            text = "Report ready"
            if rs.get("signs"):
                text += f" · resolution steps for {_plural(rs['signs'], 'sign')} of attack"
            return text + f" · {_plural(al['new_alerts'], 'new alert')}"
        # UC4
        if key == "act":
            ar, rs = get("auto_resolve"), get("respond")
            done = [f"{ar[k]} {w}" for k, w in (("resolve", "closed"), ("escalate", "escalated"),
                                                 ("needs_human", "left for a person")) if ar.get(k)]
            if rs.get("requested"):
                n, s = rs["requested"], "" if rs["requested"] == 1 else "s"
                done.append(f"Asked Defender for {n} scan{s} or clean-up{s}")
            failed = ar.get("failed", 0) + rs.get("failed", 0)
            return (" · ".join(done) or "Nothing needed action") + (f" · {failed} failed" if failed else "")
        if key == "publish":
            return "Ready to review"
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
    # UC1 bookkeeping: the flat sequence of internal step names and their status
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
        line = line.rstrip()
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
        {"uc1": self._feed_uc1, "attack": self._feed_uc1, "uc4": self._feed_uc4}.get(self.uc, self._feed_uc3)(line)

    def _feed_uc3(self, line: str) -> None:
        d, c = self._index("download"), self._index("check")
        sc, a = self._index("score"), self._index("advice")
        if "Extract finished:" in line:
            info = _literal(line.split("Extract finished:", 1)[1].strip())
            if isinstance(info, dict):
                self.results["extract"] = info
            rows = info.get("vulnerability_rows") if isinstance(info, dict) else None
            self.steps[d].detail = f"{int(rows):,} vulnerability rows downloaded" if rows is not None else ""
        elif "uc3.extract:" in line:
            self.steps[d].detail = line.split("uc3.extract:", 1)[1].strip()
        elif "Updating the data lake" in line:
            self._finish(d)
            self._start(c)
        elif "Quality check failed" in line:
            self._finish(c, "error", _short(line.split(":", 3)[-1]))
        elif "Publishing the dashboard" in line:
            self._finish(c, detail=self.steps[c].detail or "Quality checks done")
            self._start(sc)
        elif "Score and report finished:" in line:
            self._finish(sc, detail=REPORT_READY)
        elif "Advice agent started" in line:
            self._finish(sc, detail=self.steps[sc].detail or REPORT_READY)
            self._start(a)
        elif "AI fix card:" in line:
            if self.steps[a].status == "pending":           # logs written before the stage markers existed
                self._finish(sc, detail=self.steps[sc].detail or REPORT_READY)
                self._start(a)
            item = line.split("AI fix card:", 1)[1].split("(")[0].strip()
            self.steps[a].detail = f"Writing advice: {item}"
        elif "Advice agent finished:" in line:
            info = _literal(line.split("Advice agent finished:", 1)[1].strip())
            if isinstance(info, dict):
                self.results["advice"] = info
                self._finish(a, detail=advice_summary(info, self.results.get("ai_stopped", "")))
            else:
                self._finish(a, "error", "AI advice not updated this run (the rest of the run is fine)")
        elif "Open findings by severity:" in line:
            sev = _literal(line.split("Open findings by severity:", 1)[1].strip())
            if isinstance(sev, dict):
                self.results["severity"] = sev
        elif "uc3.ai:" in line and ("AI stopped:" in line or "AI explanations off:" in line):
            self.results["ai_stopped"] = line.split("AI stopped:" if "AI stopped:" in line else "AI explanations off:", 1)[1].strip()
        elif "AI fix guide" in line and ":" in line:
            self.results["ai_fixes"] = line.split(":", 1)[1].strip()
        elif "Quality:" in line:
            self.results["quality"] = line.rsplit("Quality:", 1)[1].strip()
            self.steps[c].detail = "Quality " + self.results["quality"]
        elif "Daily run finished" in line:
            self._finish(sc, detail=self.steps[sc].detail or REPORT_READY)
            self._finish(a, detail=self.steps[a].detail if self.steps[a].detail and not self.steps[a].detail.startswith("Writing")
                         else "Fix advice updated")
        elif "Run FAILED" in line:
            self.message = _short(line.split("Run FAILED", 1)[1].strip(" :"))
            for i, s in enumerate(self.steps):
                if s.status == "running":
                    self._finish(i, "error", self.message)

    def _feed_uc1(self, line: str) -> None:
        m = re.search(r"Step (\w+) (ok|failed|skipped)(?::\s*(.*))?", line)
        if not m:
            if "uc1.feeds:" in line and "Feed " in line:          # live detail while collecting
                self.steps[0].detail = _short(line.split("uc1.feeds:", 1)[1].strip())
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
            self.steps[group].detail = (friendly(name, value) if outcome == "ok" else None) or _short(result)
            if outcome == "ok":
                self.results[name] = value
        self._refresh_groups()

    def _feed_uc4(self, line: str) -> None:
        """UC4 logs "Step <name> ok: ..." like UC1, except triage: one "Triaged <id> -> <verdict>" line per incident."""
        if "uc4.ingest:" in line and "Ingest:" in line:
            self.results["ingest_text"] = _short(line.split("Ingest:", 1)[1].strip())
            self.steps[self._index("ingest")].detail = ingest_words(self.results["ingest_text"])
            return
        t = re.search(r"uc4\.triage: Triaged (\S+) -> (\w+)", line)
        if t:
            self.results.setdefault("verdicts", []).append(t.group(2))
            i = self._index("triage")
            self._start(i)
            n = len(self.results["verdicts"])
            self.steps[i].detail = f"{n} checked · latest: {VERDICT_WORDS.get(t.group(2), t.group(2))}"
            return
        if "Triage of" in line and "failed" in line:
            self.results["triage_failed"] = self.results.get("triage_failed", 0) + 1
            return
        m = re.search(r"Step (\w+) (ok|failed|skipped)", line)
        if m and m.group(1) in UC4_AFTER_TRIAGE and "triage" not in self.results:
            # triage has no Step line of its own: it is done once a later step reports
            n, bad = len(self.results.get("verdicts", [])), self.results.get("triage_failed", 0)
            self.results["triage"] = n
            self._feed_uc1(f"Step triage {'failed' if bad and not n else 'ok'}: " + self._triage_text(n, bad))
        self._feed_uc1(line)
        if m and m.group(1) == "ingest" and self.results.get("ingest_text"):
            self.steps[self._index("ingest")].detail = ingest_words(self.results["ingest_text"])

    def _triage_text(self, n: int, failed: int) -> str:
        if not n and not failed:
            return "No new alerts to check"
        counts: dict[str, int] = {}
        for v in self.results.get("verdicts", []):
            counts[VERDICT_WORDS.get(v, v)] = counts.get(VERDICT_WORDS.get(v, v), 0) + 1
        text = f"{n} checked" + (" · " + ", ".join(verdict_count(c, w) for w, c in counts.items()) if counts else "")
        return text + (f" · {failed} failed" if failed else "")

    def _refresh_groups(self) -> None:
        for gi, step in enumerate(self.steps):
            states = [self._seq_status[i] for i, (g, _) in enumerate(self._seq) if g == gi]
            if all(s in ("done", "skipped", "error") for s in states):
                if all(s == "skipped" for s in states):
                    self._finish(gi, "skipped")
                else:
                    self._finish(gi, "error" if "error" in states else "done")
                    if "error" not in states:
                        step.detail = group_summary(step.key, self.results) or step.detail
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
            self.message = ("The run stopped without finishing (the computer or the portal may have been restarted). "
                            "The log shows how far it got. Press Run to try again.")
            return
        if exit_code == 0:
            for i, s in enumerate(self.steps):
                if s.status in ("pending", "running"):
                    self._finish(i, "skipped" if s.status == "pending" and self.uc in ("uc1", "uc4", "attack") else "done")
            errors = [s for s in self.steps if s.status == "error"]
            self.status = "partial" if errors else "ok"
            self.message = self.message or ("Finished with problems in: " + ", ".join(s.label for s in errors) if errors else "Finished")
        else:
            self.status = "failed"
            for i, s in enumerate(self.steps):
                if s.status == "running":
                    self._finish(i, "error", self.message or "Stopped here")
            self.message = self.message or f"The pipeline stopped (exit code {exit_code}). See the log below for details."

    # ---------- the plain-English summary shown when a run ends ----------
    def facts(self) -> list[dict]:
        r, out = self.results, []

        def add(label: str, value, hint: str = "") -> None:
            if value not in (None, ""):
                out.append({"label": label, "value": str(value), "hint": hint})

        if self.uc == "uc3":
            ex = r.get("extract") or {}
            add("Vulnerability rows downloaded", f"{ex['vulnerability_rows']:,}" if "vulnerability_rows" in ex else None, f"from {ex.get('machines', '?')} devices")
            sev = r.get("severity") or {}
            if sev:
                add("Critical findings", f"{sev.get('Critical', 0):,}", f"{sev.get('High', 0):,} high · fix these first")
            add("Data quality", r.get("quality"), "all automatic checks")
            adv = r.get("advice") if isinstance(r.get("advice"), dict) else None
            if adv:
                add("Advice agent (AI)", *advice_status(adv, r.get("ai_stopped", "")))
            else:
                add("Advice agent (AI)", r.get("ai_fixes"))
            return out
        if self.uc == "uc4":
            got = re.findall(r"\d+", r.get("ingest_text") or "")
            if len(got) >= 2:
                add("Incidents read from Defender", got[0], f"{got[1]} new or changed, needing a verdict")
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
                add("Known cases called right", f"{acc.get('lab_correct', 0)} / {acc['lab_incidents']}",
                    f"{acc.get('lab_missed_tp', 0)} true positives missed")
            fb = r.get("feedback") if isinstance(r.get("feedback"), dict) else {}
            add("Your feedback imported", fb.get("feedback") if fb else None, "agree / disagree clicks")
            return out
        if self.uc == "attack":
            hu = r.get("hunt") if isinstance(r.get("hunt"), dict) else {}
            add("Searches run in Defender", f"{hu.get('ok', 0)}/{hu.get('hunts', 0)}" if hu else None,
                f"{hu.get('errors', 0)} errors · {hu.get('rows', 0)} rows found")
            co = r.get("correlate") if isinstance(r.get("correlate"), dict) else {}
            if co:
                add("New signs of attack", co.get("new_hits", 0), f"{co.get('hit_findings', 0)} kept in total")
            rs = r.get("resolve") if isinstance(r.get("resolve"), dict) else {}
            if rs:
                add("Resolution steps by AI", rs.get("by_ai", 0), f"of {rs.get('signs', 0)} signs of attack")
            al = r.get("alerts") if isinstance(r.get("alerts"), dict) else {}
            add("New alerts", al.get("new_alerts"))
            return out
        feeds = r.get("collect") if isinstance(r.get("collect"), dict) else {}
        new_items = sum(int(n) for v in feeds.values() for n in re.findall(r"\d+", str(v)))
        add("New threat items collected", f"{new_items:,}" if feeds else None, feed_counts(feeds) if feeds else "")
        an = r.get("analyse") if isinstance(r.get("analyse"), dict) else {}
        add("Threats assessed", an.get("candidates"), f"{an.get('ai_done', 0)} read by AI, {an.get('rules_only', 0)} by rules")
        ex = r.get("exposure") if isinstance(r.get("exposure"), dict) else {}
        add("Threats affecting our devices", ex.get("threats_exposed"), f"on {ex.get('devices', '?')} devices")
        sc = r.get("rescore") if isinstance(r.get("rescore"), dict) else r.get("score") if isinstance(r.get("score"), dict) else {}
        if sc:
            add("Critical / High threats", f"{sc.get('Critical', 0)} / {sc.get('High', 0)}", "after linking the evidence")
        fx = r.get("fix_advice") if isinstance(r.get("fix_advice"), dict) else {}
        if fx:
            add("Threats with fix steps", fx.get("threats"), f"{fx.get('by_ai', 0)} written by AI")
        hu = r.get("hunt") if isinstance(r.get("hunt"), dict) else {}
        add("Searches for attacks", f"{hu.get('ok', 0)}/{hu.get('hunts', 0)}" if hu else None, f"{hu.get('errors', 0)} errors · {hu.get('rows', 0)} rows found")
        co = r.get("correlate") if isinstance(r.get("correlate"), dict) else {}
        if co:
            add("New signs of attack", co.get("new_hits", co.get("hit_findings", 0)), f"{co.get('hit_findings', 0)} kept in total")
        al = r.get("alerts") if isinstance(r.get("alerts"), dict) else {}
        add("New alerts", al.get("new_alerts"))
        return out

    def report_file(self) -> str | None:
        rep = self.results.get("report")
        path = rep.get("docx") if isinstance(rep, dict) else None
        return Path(path).name if path else None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id, "uc": self.uc, "status": self.status, "message": self.message,
            "started_at": self.started_at, "finished_at": self.finished_at, "exit_code": self.exit_code,
            "steps": [{k: getattr(s, k) for k in ("key", "label", "description", "status", "detail", "started_at", "finished_at")}
                      for s in self.steps],
            "facts": self.facts(), "report_file": self.report_file(), "lines": self.lines,
            "log_tail": list(self.log_tail)[-12:],
        }


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


class RunManager:
    """Runs live in data/runs/<run_id>/; the latest one per use case is what the run page shows."""

    def __init__(self, uc_dirs: dict[str, Path], runs_dir: Path | None = None,
                 spawn: Callable[..., subprocess.Popen] | None = None, alive: Callable[[int | None], bool] = _pid_alive):
        self.uc_dirs = uc_dirs
        self.runs_dir = runs_dir or Path(__file__).resolve().parents[2] / "data" / "runs"
        self.spawn = spawn or subprocess.Popen
        self.alive = alive
        self.lock = threading.Lock()
        self._cache: dict[str, tuple[tuple, RunState]] = {}

    # ---------- reading ----------
    def _run_dirs(self, uc: str | None = None) -> list[Path]:
        if not self.runs_dir.is_dir():
            return []
        dirs = [d for d in self.runs_dir.iterdir() if d.is_dir() and (d / "meta.json").is_file()]
        if uc:
            dirs = [d for d in dirs if d.name.endswith("_" + uc)]
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
        uc = meta["uc"]
        state = RunState(uc, STEPS.get(uc, uc3_steps)(), run_id=run_dir.name, started_at=meta["started_at"])
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
                out[uc] = {**st.to_dict(), "typical_seconds": self.typical_seconds(uc)} if st else None
            return out

    def history(self, limit: int = 12) -> list[dict]:
        with self.lock:
            rows = []
            for d in self._run_dirs()[:limit]:
                st = self.load(d)
                if st:
                    rows.append({k: v for k, v in st.to_dict().items() if k not in ("log_tail", "facts")})
            return rows

    def log(self, uc: str, after: int = 0, run_id: str | None = None) -> dict:
        dirs = [self.runs_dir / run_id] if run_id else self._run_dirs(uc)
        if not dirs or not (dirs[0] / "output.log").is_file():
            return {"run_id": None, "lines": [], "next": 0}
        with (dirs[0] / "output.log").open(encoding="utf-8", errors="replace") as fh:
            lines = [ln.rstrip("\n") for ln in fh]
        return {"run_id": dirs[0].name, "lines": lines[after:after + 2000], "next": min(len(lines), after + 2000)}

    # ---------- starting ----------
    def start(self, uc: str) -> tuple[bool, RunState | None, str]:
        root = self.uc_dirs.get(uc)
        if root is None:
            return False, None, "unknown use case"
        if not ((root / ".venv" / "Scripts" / "python.exe").is_file() or (root / ".venv" / "bin" / "python").is_file()):
            return False, None, f"{uc.upper()} has no Python environment at {root / '.venv'}"
        with self.lock:
            current = self.latest(uc)
            if current and current.status == "running":
                return False, current, "already running"
            run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uc
            run_dir = self.runs_dir / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "meta.json").write_text(json.dumps({"uc": uc, "run_id": run_id, "started_at": _now(), "by": "portal"}),
                                               encoding="utf-8")
            cmd = [sys.executable, "-m", "portal.runner", "--uc", uc, "--root", str(root), "--run-dir", str(run_dir)]
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
