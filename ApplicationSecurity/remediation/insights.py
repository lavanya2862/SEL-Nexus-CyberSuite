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
        "role": "Detects vulnerabilities across the codebase and prioritises them by risk.",
        "contract_in": ["GitHub repository (cloned)", "Detected languages and dependency manifests",
                        "Scanners: CodeQL (primary), Trivy, OSV.dev, Semgrep/Bandit, built-in SAST rules"],
        "contract_out": ["A consolidated, de-duplicated list of findings", "A risk score and priority for each finding",
                         "Source-code context for review"],
    },
    "remediation": {
        "name": "Remediation Agent", "stage": "remediation",
        "role": "Remediates the vulnerabilities it can safely address, one Git commit per remediation.",
        "contract_in": ["Ranked findings from the Analysis Agent", "Isolated Git branch",
                        "AI model for AI-assisted remediation (optional)"],
        "contract_out": ["Remediation commits (dependency upgrades, rule-based and AI-assisted remediations)",
                         "Findings requiring manual remediation, with the root cause"],
    },
    "validation": {
        "name": "Validation Agent", "stage": "validation",
        "role": "Verifies each remediation is effective and introduces no regressions.",
        "contract_in": ["Remediation commits from the Remediation Agent", "Scanners for a confirmation scan"],
        "contract_out": ["A PASSED or REVIEW REQUIRED verdict", "Evidence for every check", "Findings verified as resolved"],
    },
    "reporting": {
        "name": "Reporting Agent", "stage": "reporting",
        "role": "Compiles the evidence and routes the decision to an authorised reviewer.",
        "contract_in": ["Findings, remediations and validation results"],
        "contract_out": ["Assessment report, SARIF file and patch", "Pull request for review (draft when review is required)"],
    },
}

# (pattern on the fix note, key, short label, what a person should do)
REASONS = [
    (r"quota", "llm_quota", "AI provider quota exhausted",
     "Enable billing for the API key or select a model with available quota in Settings, then re-run the scan."),
    (r"high demand|overloaded|HTTP 50[234]|unavailable", "llm_unavailable", "AI provider temporarily unavailable",
     "Re-run the scan later; the AI provider was temporarily overloaded."),
    (r"HTTP 40[0134]|no longer available|not found for API|invalid api key|permission", "llm_rejected",
     "AI model request rejected", "Verify the model and API key in Settings; the model may have been retired."),
    (r"turned off for this run", "ai_off", "AI-assisted remediation disabled for this scan",
     "Re-run the scan with AI-assisted remediation enabled."),
    (r"configure an LLM|No LLM", "needs_llm", "AI model not configured",
     "Configure an AI model in Settings and re-run the scan to enable AI-assisted remediation."),
    (r"search text not found|could not produce|did not apply|syntax error|neither the requested",
     "ai_failed", "Automated remediation could not be applied", "Remediate manually using the finding details, or re-run the scan."),
    (r"declined", "ai_declined", "Automated remediation assessed as unsafe", "Review the finding and remediate manually."),
    (r"No patched version", "no_upstream", "No patched version available",
     "Replace the package or apply compensating controls, and monitor for a patched release."),
    (r"not a direct dependency|lockfile|regenerat|no automatic bump", "transitive", "Transitive dependency",
     "Upgrade the parent package, or run the lockfile command provided in the note."),
    (r"Still reported after", "partial", "Still reported after remediation",
     "Requires a larger upgrade or a code change."),
    (r"reverted|broke", "reverted", "Remediation reverted after test failures", "Remediate manually."),
    (r"secret|credential|rotate", "secret", "Exposed secret", "Rotate the credential and remove it from the Git history."),
    (r"Third-party library", "vendored", "Vendored third-party code",
     "Update the bundled library (for example, replace the vendored .js file) to a supported version."),
    (r"test code", "tests", "Located in test code", "Low priority; remediate as part of routine maintenance."),
    (r"budget", "budget", "Per-scan remediation limit reached", "Increase 'Maximum remediations per scan' in Settings and re-run the scan."),
]
OPEN_STATUSES = ("manual", "failed", "skipped", "not_attempted")


def classify(finding: dict) -> tuple[str, str, str]:
    note = finding.get("fix_note") or ""
    for pattern, key, label, action in REASONS:
        if re.search(pattern, note, re.I):
            return key, label, action
    if finding.get("remediation_type") == "secret_removal":
        return "secret", "Exposed secret", "Rotate the credential and remove it from the Git history."
    if finding.get("fix_status") == "not_attempted":
        return ("below_threshold", "Below the severity threshold",
                "Re-run the scan with a lower minimum severity to remediate it automatically.")
    return "manual", "Manual remediation required", "Review the finding and remediate it manually."


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
                   _kv("Unique findings", m.get("unique", len(findings))),
                   _kv("Critical / High", f"{sev.get('critical', 0)} / {sev.get('high', 0)}",
                       "bad" if sev.get("critical") else ""),
                   _kv("In remediation scope", m.get("selected", r.get("findings_selected", "–")))]
        if findings:
            top = findings[0]
            outputs.append(_kv("Top risk", f"{_short(top.get('title'), 60)} ({top.get('priority_score')})", "bad"))
        raw, uniq = m.get("raw_results") or 0, m.get("unique") or len(findings)
        if raw and raw > uniq:
            learnings.append(_l(f"{raw} raw scanner results were consolidated into {uniq} unique findings; "
                                f"{_pct(raw - uniq, raw)} were duplicates reported by more than one scanner."))
        corroborated = [f for f in findings if f.get("also_reported_by")]
        if corroborated:
            learnings.append(_l(f"{len(corroborated)} findings were corroborated by two or more scanners and are "
                                "considered high-confidence.", "good"))
        codeql_only = [f for f in findings if f.get("scanner") == "CodeQL" and not f.get("also_reported_by")]
        if codeql_only:
            learnings.append(_l(f"CodeQL data-flow analysis identified {len(codeql_only)} finding(s) not detected by any other "
                                f"scanner, for example {_short(codeql_only[0].get('title'), 60)}.", "good"))
        deps = [f for f in findings if f.get("package_name")]
        if deps:
            pkgs = Counter(f["package_name"] for f in deps)
            name, n = pkgs.most_common(1)[0]
            learnings.append(_l(f"{len(deps)} of {len(findings)} findings ({_pct(len(deps), len(findings))}) originate from "
                                f"{len(pkgs)} outdated packages; {name} alone accounts for {n} advisories."))
        code = [f for f in findings if not f.get("package_name") and f.get("file_path")]
        if code:
            file, n = Counter(f["file_path"] for f in code).most_common(1)[0]
            cat, cn = Counter(f.get("category", "") for f in code).most_common(1)[0]
            learnings.append(_l(f"{file} is the principal hotspot with {n} code finding(s); the most prevalent category is "
                                f"{cat.replace('_', ' ')} ({cn}).", "warn"))
        missing = [s["name"] for s in scanners if s["status"] in ("unavailable", "failed")]
        if missing:
            learnings.append(_l(f"Not run: {', '.join(missing)}. Coverage relies on the remaining scanners.", "warn"))
        in_tests = [f for f in findings if (f.get("raw") or {}).get("in_tests")]
        if in_tests:
            learnings.append(_l(f"{len(in_tests)} finding(s) are located in test code and were assigned a lower priority."))
    return _view("analysis", st, inputs, outputs, learnings)


def remediation_view(job: dict, report: dict | None, findings: list[dict]) -> dict:
    st = _stage(job, report, "remediation")
    r = report or {}
    fixes = r.get("fixes") or []
    inputs = [_kv("Findings in scope", r.get("findings_selected", "–")),
              _kv("Isolated branch", r.get("branch") or (job.get("summary") or {}).get("branch") or "–"),
              _kv("AI model", r.get("llm_model") or ("Configured" if r.get("llm_enabled") else "Not configured"),
                  "" if r.get("llm_enabled") else "warn")]
    outputs, learnings = [], []
    if report:
        by = Counter(f["method"] for f in fixes if f.get("status") == "applied")
        files = {p for f in fixes for p in f.get("files", [])}
        status = Counter(f.get("fix_status") for f in findings)
        fixed = status.get("fixed", 0) + status.get("verified", 0)
        outputs = [_kv("Remediation commits", len(fixes)),
                   _kv("Dependency / Rule-based / AI-assisted", f"{by.get('dependency', 0)} / {by.get('rule', 0)} / {by.get('llm', 0)}"),
                   _kv("Files changed", len(files)),
                   _kv("Findings remediated", fixed, "good" if fixed else ""),
                   _kv("Manual remediation required", sum(status.get(s, 0) for s in OPEN_STATUSES),
                       "warn" if any(status.get(s) for s in OPEN_STATUSES) else "")]
        selected = r.get("findings_selected") or len(findings)
        if selected:
            learnings.append(_l(f"Remediated {fixed} of {selected} in-scope findings automatically ({_pct(fixed, selected)}).",
                                "good" if fixed else "warn"))
        dep_issues = sum(len(f["finding_ids"]) for f in fixes if f["method"] == "dependency")
        if by.get("dependency"):
            learnings.append(_l(f"{by['dependency']} dependency upgrade(s) resolved {dep_issues} advisories; a single "
                                "upgrade typically addresses several advisories."))
        majors = [f for f in fixes if "[MAJOR]" in f.get("summary", "")]
        if majors:
            learnings.append(_l(f"{len(majors)} upgrade(s) cross a major version; breaking API changes are likely, so "
                                "regression testing is required before merging.", "warn"))
        ai = [f for f in fixes if f["method"] == "llm"]
        if ai:
            ok = sum(1 for f in ai if f.get("verified"))
            learnings.append(_l(f"The Remediation Agent applied {len(ai)} AI-assisted remediation(s); the Validation Agent's confirmation scan verified {ok}.", "good"))
        reasons = Counter(classify(f)[1] for f in findings if f.get("fix_status") in OPEN_STATUSES)
        for label, n in reasons.most_common(4):
            learnings.append(_l(f"{n} finding(s) remain open: {label}.", "warn"))
    return _view("remediation", st, inputs, outputs, learnings)


def validation_view(job: dict, report: dict | None, findings: list[dict]) -> dict:
    st = _stage(job, report, "validation")
    r = report or {}
    checks = [c for c in r.get("validation_checks") or [] if c["category"] != "functional"]  # older reports had one
    inputs = [_kv("Remediations to verify", len([f for f in r.get("fixes", []) if f.get("status") == "applied"]) if report else "–"),
              _kv("Validation layers", "Syntax · regression guard · confirmation scan")]
    outputs, learnings = [], []
    if report:
        cnt = Counter(c["status"] for c in checks)
        verdict = r.get("validation_status", "not_run")
        outputs = [_kv("Verdict", {"passed": "PASSED", "flagged": "REVIEW REQUIRED", "not_run": "Not run"}.get(verdict, verdict),
                       {"passed": "good", "flagged": "warn"}.get(verdict, "")),
                   _kv("Checks passed", cnt.get("passed", 0), "good"),
                   _kv("Checks failed", cnt.get("failed", 0), "bad" if cnt.get("failed") else ""),
                   _kv("Warnings", cnt.get("warning", 0), "warn" if cnt.get("warning") else ""),
                   _kv("Findings verified resolved", r.get("verified_fixed", 0), "good")]
        static = [c for c in checks if c["category"] == "static"]
        if static and all(c["status"] == "passed" for c in static):
            learnings.append(_l(f"All {len(static)} remediations compile and parse cleanly.", "good"))
        guard = [c for c in checks if c["category"] == "security-regression"]
        bad_guard = [c for c in guard if c["status"] == "failed"]
        if guard and not bad_guard:
            learnings.append(_l("No remediation weakens the security posture (no suppressions, disabled checks, skipped tests "
                                "or removed controls).", "good"))
        for c in bad_guard[:3]:
            learnings.append(_l(f"Remediation #{(c.get('fix_index') or 0) + 1} weakens security: {_short(c['detail'], 140)}", "bad"))
        if r.get("verified_fixed"):
            learnings.append(_l(f"The confirmation scan verified that {r['verified_fixed']} findings are resolved.", "good"))
        for c in checks:
            if c["status"] == "failed" and c["category"] != "security-regression":
                learnings.append(_l(f"Review required: {c['name']}. {_short(c['detail'], 160)}", "bad"))
        majors = [c for c in checks if c["name"].startswith("Major-version")]
        if majors:
            learnings.append(_l(f"{len(majors)} remediation(s) are major-version upgrades and require regression testing.", "warn"))
    return _view("validation", st, inputs, outputs, learnings)


def reporting_view(job: dict, report: dict | None, findings: list[dict], artifacts: list[dict]) -> dict:
    st = _stage(job, report, "reporting")
    r = report or {}
    s = job.get("summary") or {}
    inputs = [_kv("Verdict", (r.get("validation_status") or "–").replace("_", " ")),
              _kv("Remediations", r.get("patches_applied", "–")), _kv("Findings", r.get("findings_input", "–"))]
    outputs, learnings = [], []
    if report:
        outputs += [_kv(name, "PDF") for name in ("report.pdf", "findings.pdf", "fixes.pdf")]
        for a in artifacts:
            if a["name"] in ("findings.sarif", "fixes.patch"):
                outputs.append(_kv(a["name"], f"{a['size'] / 1024:.0f} KB"))
        pr = s.get("pull_request_url") or r.get("pull_request_url")
        approval = s.get("approval_status") or r.get("approval_status")
        outputs.append(_kv("Pull request", "Raised" + (" (draft)" if s.get("pull_request_draft") else "") if pr
                           else (approval or "–").replace("_", " "), "good" if pr else "warn"))
        if pr:
            learnings.append(_l(f"Pull request raised for review: {pr}", "good"))
        elif r.get("patches_applied"):
            learnings.append(_l("Awaiting review: approve the remediations to push the branch and raise a pull "
                                "request.", "warn"))
            if r.get("validation_status") == "flagged":
                learnings.append(_l("As this scan requires review, the pull request will be raised as a draft "
                                    "labelled needs-investigation.", "warn"))
        else:
            learnings.append(_l("This scan produced no changes to merge."))
        learnings.append(_l("report.pdf, findings.pdf and fixes.pdf are intended for stakeholders. findings.sarif imports "
                            "into GitHub code scanning; fixes.patch applies with git apply."))
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
        return {"headline": f"Scanning {job.get('repo')}: {job.get('stage')} ({job.get('progress', 0)}%)",
                "lines": [], "decision": None}
    if status != "completed" or not report:
        return {"headline": f"Scan {status}", "lines": [job.get("error") or ""],
                "decision": {"kind": "retry", "text": "Resolve the issue above, then re-run the scan."}}
    r = report
    sev = r.get("severity_counts") or {}
    fixes = r.get("fixes") or []
    ai = sum(1 for f in fixes if f["method"] == "llm")
    open_items = [f for f in findings if f.get("fix_status") in OPEN_STATUSES]
    lines = [
        f"The Analysis Agent identified {r.get('findings_input', 0)} unique findings "
        f"({sev.get('critical', 0)} critical, {sev.get('high', 0)} high).",
        f"The Remediation Agent applied {len(fixes)} remediation(s)" + (f", {ai} of them AI-assisted" if ai else "") + ".",
    ]
    verdict = r.get("validation_status")
    failed = [c for c in r.get("validation_checks", []) if c["status"] == "failed"]
    if verdict == "passed":
        lines.append(f"The Validation Agent passed every check and verified {r.get('verified_fixed', 0)} findings as resolved.")
    elif verdict == "flagged":
        lines.append(f"The Validation Agent verified {r.get('verified_fixed', 0)} findings as resolved, but the scan requires review: "
                     f"{_short(failed[0]['name'] + ' (' + failed[0]['detail'] + ')', 170) if failed else 'see Validation'}.")
    if open_items:
        reasons = Counter(classify(f)[1] for f in open_items).most_common(3)
        lines.append(f"{len(open_items)} finding(s) require attention: " + "; ".join(f"{l} ({n})" for l, n in reasons) + ".")
    decision = None
    if s.get("pull_request_url"):
        decision = {"kind": "pr", "text": "Complete the review and merge the pull request on GitHub.", "url": s["pull_request_url"]}
    elif r.get("patches_applied"):
        decision = {"kind": "approve" if verdict != "flagged" else "investigate",
                    "text": ("Review the remediations and approve to raise a pull request." if verdict != "flagged" else
                             "Investigate the failed check, then approve to raise a draft pull request.")}
    headline = (f"{r.get('findings_input', 0)} findings identified · {len(fixes)} remediated automatically · "
                f"{r.get('verified_fixed', 0)} verified resolved")
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
        out.append({**base, "severity": "high", "kind": "Scan failed", "message": job.get("error") or "Unknown error",
                    "action": "Verify the repository URL and access permissions, then re-run the scan."})
    for s in (report or {}).get("scanners") or []:
        if s["status"] == "failed":
            out.append({**base, "severity": "medium", "kind": f"Scanner failed: {s['name']}",
                        "message": _short(s.get("message"), 300), "action": "Verify the scanner installation, then re-run the scan."})
    groups: dict[str, list] = {}
    for f in findings:
        if f.get("fix_status") == "failed":
            groups.setdefault(classify(f)[0], []).append(f)
    for key, items in groups.items():
        _, label, action = classify(items[0])
        out.append({**base, "severity": "medium", "kind": f"Remediation attempt failed: {label}",
                    "message": f"{len(items)} finding(s), for example {_short(items[0].get('title'), 80)}: "
                               f"{_short(items[0].get('fix_note'), 180)}", "action": action})
    for c in (report or {}).get("validation_checks") or []:
        if c["status"] == "failed":
            out.append({**base, "severity": "high" if c["category"] == "security-regression" else "medium",
                        "kind": f"Validation failed: {c['name']}", "message": _short(c["detail"], 300),
                        "action": "Open the scan's Validation tab and investigate before approving."})
    if (job.get("summary") or {}).get("publish_error"):
        out.append({**base, "severity": "high", "kind": "Pull request could not be raised",
                    "message": job["summary"]["publish_error"],
                    "action": "Verify the GitHub token's access to this repository, then approve again."})
    return out
