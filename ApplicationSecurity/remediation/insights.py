"""Plain-language views of a run: what each agent received, produced and concluded, what is left
for a human to do, and what went wrong. Everything here is derived from recorded run data, so the
UI never has to guess.

All functions take plain dicts (the JSON the API already serves) so they work for live runs
(stages only) and finished runs (report + findings) alike.
"""
from __future__ import annotations

import re
from collections import Counter

AGENTS = {
    "analysis": {
        "name": "Analysis Agent", "stage": "analysis",
        "role": "Finds every vulnerability and decides what matters most.",
        "contract_in": ["GitHub repository (cloned)", "Detected languages and dependency files",
                        "Scanners: CodeQL (primary), Trivy, OSV.dev, Semgrep/Bandit, built-in rules"],
        "contract_out": ["One de-duplicated list of findings", "Risk score and rank for each finding",
                         "Source-code context for review"],
    },
    "remediation": {
        "name": "Remediation Agent", "stage": "remediation",
        "role": "Fixes the issues it safely can, one Git commit per fix.",
        "contract_in": ["Ranked findings from the Analysis Agent", "Isolated Git branch",
                        "LLM for code changes (optional)"],
        "contract_out": ["Fix commits (dependency upgrades, rule rewrites, code fixes)",
                         "Issues it could not fix, with the reason"],
    },
    "validation": {
        "name": "Validation Agent", "stage": "validation",
        "role": "Proves each fix works and does not make anything worse.",
        "contract_in": ["Fix commits from the Remediation Agent", "Scanners for a rescan"],
        "contract_out": ["PASSED or NEEDS REVIEW verdict", "Evidence for every check", "Issues confirmed resolved"],
    },
    "reporting": {
        "name": "Reporting Agent", "stage": "reporting",
        "role": "Packages the evidence and hands the decision to a human.",
        "contract_in": ["Findings, fixes and validation results"],
        "contract_out": ["Report, SARIF, patch", "Pull request for review (draft if it needs review)"],
    },
}

# (pattern on the fix note, key, short label, what a person should do)
REASONS = [
    (r"quota", "llm_quota", "Remediation Agent: AI quota used up",
     "Enable billing for the LLM key or pick a model with quota in Settings, then re-run."),
    (r"high demand|overloaded|HTTP 50[234]|unavailable", "llm_unavailable", "Remediation Agent: AI provider busy",
     "Re-run later; the AI provider the Remediation Agent uses was temporarily overloaded."),
    (r"HTTP 40[0134]|no longer available|not found for API|invalid api key|permission", "llm_rejected",
     "Remediation Agent: AI model refused", "Check the model name and API key in Settings (the model may be retired)."),
    (r"turned off for this run", "ai_off", "Remediation Agent code fixes were off",
     "Re-run with 'Code fixes by the Remediation Agent' switched on."),
    (r"configure an LLM|No LLM", "needs_llm", "Remediation Agent needs an AI model",
     "Add an LLM in Settings and re-run so the Remediation Agent can patch it."),
    (r"search text not found|could not produce|did not apply|syntax error|neither the requested",
     "ai_failed", "Remediation Agent's fix did not apply", "Fix it by hand using the finding details, or re-run."),
    (r"declined", "ai_declined", "Remediation Agent judged it unsafe to fix", "Review and fix by hand."),
    (r"No patched version", "no_upstream", "No patched version exists yet",
     "Replace the package or add mitigations, and watch for a release."),
    (r"not a direct dependency|lockfile|regenerat|no automatic bump", "transitive", "Indirect dependency",
     "Upgrade the parent package, or run the lockfile command in the note."),
    (r"Still reported after", "partial", "Validation Agent still finds it after the fix",
     "Needs a bigger upgrade or a code change."),
    (r"reverted|broke", "reverted", "Validation Agent undid a fix that broke tests", "Fix it by hand."),
    (r"secret|credential|rotate", "secret", "Exposed secret", "Rotate the credential and purge it from Git history."),
    (r"Third-party library", "vendored", "Third-party library code",
     "Update the bundled library (e.g. replace the vendored .js file) to a current version."),
    (r"test code", "tests", "In test code", "Low priority; fix when convenient."),
    (r"budget", "budget", "Remediation Agent's fix limit reached", "Raise 'Max code fixes per run' in Settings and re-run."),
]
OPEN_STATUSES = ("manual", "failed", "skipped", "not_attempted")


def classify(finding: dict) -> tuple[str, str, str]:
    note = finding.get("fix_note") or ""
    for pattern, key, label, action in REASONS:
        if re.search(pattern, note, re.I):
            return key, label, action
    if finding.get("remediation_type") == "secret_removal":
        return "secret", "Exposed secret", "Rotate the credential and purge it from Git history."
    if finding.get("fix_status") == "not_attempted":
        return ("below_threshold", "Below your severity threshold",
                "Re-run with a lower minimum severity to have it fixed automatically.")
    return "manual", "Needs a human", "Review the finding and fix it by hand."


def _stage(job: dict, report: dict | None, stage_id: str) -> dict:
    for st in (report or {}).get("stages") or job.get("stages") or []:
        if st.get("id") == stage_id:
            return st
    return {"id": stage_id, "status": "pending", "steps": [], "metrics": {}, "summary": ""}


def _pct(a: int, b: int) -> str:
    return f"{round(100 * a / b)}%" if b else "0%"


def _kv(label: str, value, tone: str = "") -> dict:
    return {"label": label, "value": value, "tone": tone}


def _l(text: str, tone: str = "info") -> dict:
    return {"text": text, "tone": tone}


def _short(text: str | None, n: int = 70) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


# ---------------------------------------------------------------------------------------------
def analysis_view(job: dict, report: dict | None, findings: list[dict]) -> dict:
    st = _stage(job, report, "analysis")
    m = st.get("metrics") or {}
    r = report or {}
    inputs = [_kv("Repository", f"{job.get('repo')}@{(job.get('commit') or r.get('commit') or '')[:8]}")]
    if r.get("languages"):
        inputs.append(_kv("Languages", ", ".join(f"{k} ({v})" for k, v in list(r["languages"].items())[:5])))
    scanners = r.get("scanners") or []
    if scanners:
        ran = [s["name"] for s in scanners if s["status"] == "ok"]
        inputs.append(_kv("Scanners used", ", ".join(ran) or "none"))
    inputs.append(_kv("Severity threshold", (job.get("options") or {}).get("min_severity", "low")))
    outputs, learnings = [], []
    if findings or m.get("unique") is not None:
        sev = r.get("severity_counts") or {}
        outputs = [_kv("Raw scanner results", m.get("raw_results", "–")),
                   _kv("Unique issues", m.get("unique", len(findings))),
                   _kv("Critical / High", f"{sev.get('critical', 0)} / {sev.get('high', 0)}",
                       "bad" if sev.get("critical") else ""),
                   _kv("Selected for fixing", m.get("selected", r.get("findings_selected", "–")))]
        if findings:
            top = findings[0]
            outputs.append(_kv("Top risk", f"{_short(top.get('title'), 60)} ({top.get('priority_score')})", "bad"))
        raw, uniq = m.get("raw_results") or 0, m.get("unique") or len(findings)
        if raw and raw > uniq:
            learnings.append(_l(f"{raw} raw scanner results collapsed into {uniq} unique issues: "
                                f"{_pct(raw - uniq, raw)} were the same problem reported more than once."))
        corroborated = [f for f in findings if f.get("also_reported_by")]
        if corroborated:
            learnings.append(_l(f"{len(corroborated)} issues were confirmed by two or more scanners, so they are "
                                "high-confidence.", "good"))
        codeql_only = [f for f in findings if f.get("scanner") == "CodeQL" and not f.get("also_reported_by")]
        if codeql_only:
            learnings.append(_l(f"CodeQL's data-flow analysis found {len(codeql_only)} issue(s) no other scanner "
                                f"caught, e.g. {_short(codeql_only[0].get('title'), 60)}.", "good"))
        deps = [f for f in findings if f.get("package_name")]
        if deps:
            pkgs = Counter(f["package_name"] for f in deps)
            name, n = pkgs.most_common(1)[0]
            learnings.append(_l(f"{len(deps)} of {len(findings)} issues ({_pct(len(deps), len(findings))}) come from "
                                f"{len(pkgs)} outdated packages; {name} alone has {n} advisories."))
        code = [f for f in findings if not f.get("package_name") and f.get("file_path")]
        if code:
            file, n = Counter(f["file_path"] for f in code).most_common(1)[0]
            cat, cn = Counter(f.get("category", "") for f in code).most_common(1)[0]
            learnings.append(_l(f"{file} is the hotspot with {n} code issue(s); the most common class is "
                                f"{cat.replace('_', ' ')} ({cn}).", "warn"))
        missing = [s["name"] for s in scanners if s["status"] in ("unavailable", "failed")]
        if missing:
            learnings.append(_l(f"Not run: {', '.join(missing)}. Coverage relies on the other scanners.", "warn"))
        in_tests = [f for f in findings if (f.get("raw") or {}).get("in_tests")]
        if in_tests:
            learnings.append(_l(f"{len(in_tests)} issue(s) are in test code and were ranked lower."))
    return _view("analysis", st, inputs, outputs, learnings)


def remediation_view(job: dict, report: dict | None, findings: list[dict]) -> dict:
    st = _stage(job, report, "remediation")
    r = report or {}
    fixes = r.get("fixes") or []
    inputs = [_kv("Issues selected", r.get("findings_selected", "–")),
              _kv("Isolated branch", r.get("branch") or (job.get("summary") or {}).get("branch") or "–"),
              _kv("AI model", r.get("llm_model") or ("configured" if r.get("llm_enabled") else "not configured"),
                  "" if r.get("llm_enabled") else "warn")]
    outputs, learnings = [], []
    if report:
        by = Counter(f["method"] for f in fixes if f.get("status") == "applied")
        files = {p for f in fixes for p in f.get("files", [])}
        status = Counter(f.get("fix_status") for f in findings)
        fixed = status.get("fixed", 0) + status.get("verified", 0)
        outputs = [_kv("Fix commits", len(fixes)),
                   _kv("Dependency / Rule / Code", f"{by.get('dependency', 0)} / {by.get('rule', 0)} / {by.get('llm', 0)}"),
                   _kv("Files changed", len(files)),
                   _kv("Issues fixed", fixed, "good" if fixed else ""),
                   _kv("Still need work", sum(status.get(s, 0) for s in OPEN_STATUSES),
                       "warn" if any(status.get(s) for s in OPEN_STATUSES) else "")]
        selected = r.get("findings_selected") or len(findings)
        if selected:
            learnings.append(_l(f"Fixed {fixed} of {selected} selected issues automatically ({_pct(fixed, selected)}).",
                                "good" if fixed else "warn"))
        dep_issues = sum(len(f["finding_ids"]) for f in fixes if f["method"] == "dependency")
        if by.get("dependency"):
            learnings.append(_l(f"{by['dependency']} dependency upgrade(s) cleared {dep_issues} advisories, since one "
                                "upgrade usually fixes several at once."))
        majors = [f for f in fixes if "[MAJOR]" in f.get("summary", "")]
        if majors:
            learnings.append(_l(f"{len(majors)} upgrade(s) jump a major version, so expect breaking API changes and "
                                "test before merging.", "warn"))
        ai = [f for f in fixes if f["method"] == "llm"]
        if ai:
            ok = sum(1 for f in ai if f.get("verified"))
            learnings.append(_l(f"The Remediation Agent wrote {len(ai)} code fix(es); the Validation Agent's rescan confirmed {ok} of them.", "good"))
        reasons = Counter(classify(f)[1] for f in findings if f.get("fix_status") in OPEN_STATUSES)
        for label, n in reasons.most_common(4):
            learnings.append(_l(f"{n} issue(s) still open: {label}.", "warn"))
    return _view("remediation", st, inputs, outputs, learnings)


def validation_view(job: dict, report: dict | None, findings: list[dict]) -> dict:
    st = _stage(job, report, "validation")
    r = report or {}
    checks = [c for c in r.get("validation_checks") or [] if c["category"] != "functional"]  # older reports had one
    inputs = [_kv("Fixes to check", len([f for f in r.get("fixes", []) if f.get("status") == "applied"]) if report else "–"),
              _kv("Check layers", "syntax · regression guard · rescan")]
    outputs, learnings = [], []
    if report:
        cnt = Counter(c["status"] for c in checks)
        verdict = r.get("validation_status", "not_run")
        outputs = [_kv("Verdict", {"passed": "PASSED", "flagged": "NEEDS REVIEW", "not_run": "Not run"}.get(verdict, verdict),
                       {"passed": "good", "flagged": "warn"}.get(verdict, "")),
                   _kv("Checks passed", cnt.get("passed", 0), "good"),
                   _kv("Checks failed", cnt.get("failed", 0), "bad" if cnt.get("failed") else ""),
                   _kv("Warnings", cnt.get("warning", 0), "warn" if cnt.get("warning") else ""),
                   _kv("Issues confirmed gone", r.get("verified_fixed", 0), "good")]
        static = [c for c in checks if c["category"] == "static"]
        if static and all(c["status"] == "passed" for c in static):
            learnings.append(_l(f"All {len(static)} fixes still compile and parse cleanly.", "good"))
        guard = [c for c in checks if c["category"] == "security-regression"]
        bad_guard = [c for c in guard if c["status"] == "failed"]
        if guard and not bad_guard:
            learnings.append(_l("No fix weakens security (no suppressions, disabled checks, skipped tests or removed "
                                "controls).", "good"))
        for c in bad_guard[:3]:
            learnings.append(_l(f"Fix #{(c.get('fix_index') or 0) + 1} weakens security: {_short(c['detail'], 140)}", "bad"))
        if r.get("verified_fixed"):
            learnings.append(_l(f"The rescan confirmed {r['verified_fixed']} issues are really gone.", "good"))
        for c in checks:
            if c["status"] == "failed" and c["category"] != "security-regression":
                learnings.append(_l(f"Needs review: {c['name']}. {_short(c['detail'], 160)}", "bad"))
        majors = [c for c in checks if c["name"].startswith("Major-version")]
        if majors:
            learnings.append(_l(f"{len(majors)} fix(es) are major upgrades and need regression testing.", "warn"))
    return _view("validation", st, inputs, outputs, learnings)


def reporting_view(job: dict, report: dict | None, findings: list[dict], artifacts: list[dict]) -> dict:
    st = _stage(job, report, "reporting")
    r = report or {}
    s = job.get("summary") or {}
    inputs = [_kv("Verdict", (r.get("validation_status") or "–").replace("_", " ")),
              _kv("Fixes", r.get("patches_applied", "–")), _kv("Findings", r.get("findings_input", "–"))]
    outputs, learnings = [], []
    if report:
        outputs += [_kv(name, "PDF") for name in ("report.pdf", "findings.pdf", "fixes.pdf")]
        for a in artifacts:
            if a["name"] in ("findings.sarif", "fixes.patch"):
                outputs.append(_kv(a["name"], f"{a['size'] / 1024:.0f} KB"))
        pr = s.get("pull_request_url") or r.get("pull_request_url")
        approval = s.get("approval_status") or r.get("approval_status")
        outputs.append(_kv("Pull request", "opened" + (" (draft)" if s.get("pull_request_draft") else "") if pr
                           else (approval or "–").replace("_", " "), "good" if pr else "warn"))
        if pr:
            learnings.append(_l(f"Pull request is open for review: {pr}", "good"))
        elif r.get("patches_applied"):
            learnings.append(_l("Waiting for a reviewer: approve the fixes to push the branch and open a pull "
                                "request.", "warn"))
            if r.get("validation_status") == "flagged":
                learnings.append(_l("Because this scan needs review, the pull request will open as a draft "
                                    "labelled needs-investigation.", "warn"))
        else:
            learnings.append(_l("There is nothing to merge in this scan."))
        learnings.append(_l("report.pdf, findings.pdf and fixes.pdf are for people. findings.sarif can be uploaded "
                            "to GitHub code scanning; fixes.patch applies with git apply."))
    return _view("reporting", st, inputs, outputs, learnings)


def _view(agent_id: str, stage: dict, inputs, outputs, learnings) -> dict:
    meta = AGENTS[agent_id]
    return {"id": agent_id, "name": meta["name"], "role": meta["role"], "contract_in": meta["contract_in"],
            "contract_out": meta["contract_out"], "status": stage.get("status", "pending"),
            "summary": stage.get("summary", ""), "duration": stage.get("duration_seconds"),
            "steps": stage.get("steps") or [], "inputs": inputs, "outputs": outputs, "learnings": learnings}


def agent_views(job: dict, report: dict | None, findings: list[dict], artifacts: list[dict]) -> dict:
    return {"analysis": analysis_view(job, report, findings),
            "remediation": remediation_view(job, report, findings),
            "validation": validation_view(job, report, findings),
            "reporting": reporting_view(job, report, findings, artifacts)}


# ---------------------------------------------------------------------------------------------
def run_story(job: dict, report: dict | None, findings: list[dict]) -> dict:
    """A short plain-English account of the run and the decision it needs."""
    s = job.get("summary") or {}
    status = job.get("status")
    if status in ("queued", "running"):
        return {"headline": f"Working on {job.get('repo')}: {job.get('stage')} ({job.get('progress', 0)}%)",
                "lines": [], "decision": None}
    if status != "completed" or not report:
        return {"headline": f"Run {status}", "lines": [job.get("error") or ""],
                "decision": {"kind": "retry", "text": "Fix the problem above, then re-run."}}
    r = report
    sev = r.get("severity_counts") or {}
    fixes = r.get("fixes") or []
    ai = sum(1 for f in fixes if f["method"] == "llm")
    open_items = [f for f in findings if f.get("fix_status") in OPEN_STATUSES]
    lines = [
        f"The Analysis Agent found {r.get('findings_input', 0)} unique issues "
        f"({sev.get('critical', 0)} critical, {sev.get('high', 0)} high).",
        f"The Remediation Agent made {len(fixes)} fix(es)" + (f", {ai} of them code fixes" if ai else "") + ".",
    ]
    verdict = r.get("validation_status")
    failed = [c for c in r.get("validation_checks", []) if c["status"] == "failed"]
    if verdict == "passed":
        lines.append(f"The Validation Agent passed every check and confirmed {r.get('verified_fixed', 0)} issues are gone.")
    elif verdict == "flagged":
        lines.append(f"The Validation Agent confirmed {r.get('verified_fixed', 0)} issues are gone but the run needs review: "
                     f"{_short(failed[0]['name'] + ' (' + failed[0]['detail'] + ')', 170) if failed else 'see Validation'}.")
    if open_items:
        reasons = Counter(classify(f)[1] for f in open_items).most_common(3)
        lines.append(f"{len(open_items)} issue(s) still need attention: " + "; ".join(f"{l} ({n})" for l, n in reasons) + ".")
    decision = None
    if s.get("pull_request_url"):
        decision = {"kind": "pr", "text": "Review and merge the pull request on GitHub.", "url": s["pull_request_url"]}
    elif r.get("patches_applied"):
        decision = {"kind": "approve" if verdict != "flagged" else "investigate",
                    "text": ("Review the fixes and approve to open a pull request." if verdict != "flagged" else
                             "Investigate the failed check, then approve to open a draft pull request.")}
    headline = (f"{r.get('findings_input', 0)} issues found · {len(fixes)} fixed automatically · "
                f"{r.get('verified_fixed', 0)} confirmed resolved")
    return {"headline": headline, "lines": lines, "decision": decision}


def fixes_needed(job: dict, findings: list[dict]) -> list[dict]:
    items = []
    for f in findings:
        if f.get("fix_status") not in OPEN_STATUSES:
            continue
        key, label, action = classify(f)
        items.append({"job_id": job["id"], "repo": job.get("repo"), "finding_id": f["finding_id"],
                      "title": f.get("title"), "severity": f.get("severity"), "score": f.get("priority_score", 0),
                      "location": (f"{f.get('package_name')}@{f.get('installed_version')}" if f.get("package_name")
                                   else f"{f.get('file_path') or ''}{':' + str(f['line']) if f.get('line') else ''}"),
                      "reason_key": key, "reason": label, "action": action, "status": f.get("fix_status"),
                      "note": _short(f.get("fix_note"), 300)})
    return items


def run_errors(job: dict, report: dict | None, findings: list[dict]) -> list[dict]:
    """Problems with the pipeline itself (not vulnerabilities): failures a person should resolve."""
    base = {"job_id": job["id"], "repo": job.get("repo"), "when": job.get("finished_at") or job.get("created_at")}
    out = []
    if job.get("status") == "failed":
        out.append({**base, "severity": "high", "kind": "Run failed", "message": job.get("error") or "Unknown error",
                    "action": "Check the repository link and access, then re-run."})
    for s in (report or {}).get("scanners") or []:
        if s["status"] == "failed":
            out.append({**base, "severity": "medium", "kind": f"Scanner failed: {s['name']}",
                        "message": _short(s.get("message"), 300), "action": "Check the scanner installation and re-run."})
    groups: dict[str, list] = {}
    for f in findings:
        if f.get("fix_status") == "failed":
            groups.setdefault(classify(f)[0], []).append(f)
    for key, items in groups.items():
        _, label, action = classify(items[0])
        out.append({**base, "severity": "medium", "kind": f"Fix attempt failed: {label}",
                    "message": f"{len(items)} issue(s), e.g. {_short(items[0].get('title'), 80)}: "
                               f"{_short(items[0].get('fix_note'), 180)}", "action": action})
    for c in (report or {}).get("validation_checks") or []:
        if c["status"] == "failed":
            out.append({**base, "severity": "high" if c["category"] == "security-regression" else "medium",
                        "kind": f"Validation failed: {c['name']}", "message": _short(c["detail"], 300),
                        "action": "Open the run's Validation tab, investigate, and decide before approving."})
    if (job.get("summary") or {}).get("publish_error"):
        out.append({**base, "severity": "high", "kind": "Pull request could not be opened",
                    "message": job["summary"]["publish_error"],
                    "action": "Check the GitHub token's access to this repository, then approve again."})
    return out
