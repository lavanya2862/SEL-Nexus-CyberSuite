"""Report rendering: JSON, Markdown, SARIF 2.1.0 and pull-request bodies."""
from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .models import SEVERITIES, Finding, RemediationReport

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note",
                "unknown": "warning"}
_SEC_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0", "unknown": "5.0"}
_VERDICT = {"passed": "PASSED ✅", "flagged": "NEEDS REVIEW ⚠️", "failed": "FAILED ❌",
            "not_run": "NOT RUN (no fixes)"}
_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜", "unknown": "⬜"}


def _md_escape(text: str | None, limit: int = 140) -> str:
    text = " ".join(str(text or "").split())
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return text.replace("|", "\\|").replace("`", "'")


def _location(f: Finding) -> str:
    if not f.file_path:
        return "-"
    return f"`{_md_escape(f.file_path, 80)}{':' + str(f.line) if f.line else ''}`"


def render_markdown(report: RemediationReport, findings: list[Finding], max_rows: int = 150) -> str:
    sev = " · ".join(f"{_ICON[s]} {s}: **{report.severity_counts.get(s, 0)}**" for s in SEVERITIES
                     if report.severity_counts.get(s))
    lines = [f"# Security remediation report — {report.repo}", "",
             f"- Repository: {report.repo_url or report.repo}",
             f"- Ref / commit: `{report.ref or 'default'}` @ `{(report.commit or '')[:12]}`",
             f"- Run: `{report.run_id}` — status **{report.status}** — {report.duration_seconds:.0f}s",
             f"- Fix branch: `{report.branch or 'not created'}`" +
             (f" — PR: {report.pull_request_url}" if report.pull_request_url else ""),
             f"- Languages: {', '.join(f'{k} ({v})' for k, v in list(report.languages.items())[:6]) or 'n/a'}",
             f"- LLM remediation: {'enabled' if report.llm_enabled else 'disabled (deterministic fixes only)'}", "",
             "## Summary", "",
             f"- Findings: **{report.findings_input}** total, **{report.findings_selected}** at or above the threshold",
             f"- {sev or 'No findings'}",
             f"- Fixes applied: **{report.patches_applied}** (attempted {report.patches_proposed}); "
             f"findings confirmed resolved by rescan: **{report.verified_fixed}**",
             f"- Final validation status: **{_VERDICT.get(report.validation_status, report.validation_status)}**",
             f"- Approval: **{report.approval_status.replace('_', ' ')}**" +
             (f" — {'draft ' if report.pull_request_draft else ''}PR {report.pull_request_url}"
              if report.pull_request_url else ""), "",
             "## Pipeline", "", "| Stage | Component | Status | Duration | Result |", "|---|---|---|---:|---|"]
    for st in report.stages:
        dur = f"{st.duration_seconds:.1f}s" if st.duration_seconds is not None else "–"
        lines.append(f"| {st.name} | {st.agent or '–'} | {st.status} | {dur} | {_md_escape(st.summary, 120)} |")
    lines += ["", "## Scanners", "", "| Scanner | Status | Findings | Time | Notes |", "|---|---|---:|---:|---|"]
    for run in report.scanners:
        lines.append(f"| {run.name} | {run.status} | {run.findings} | {run.duration_seconds:.1f}s | {_md_escape(run.message, 90)} |")
    lines += ["", "## Fixes", ""]
    if not report.fixes:
        lines.append("No automatic fixes were applied.")
    else:
        lines += ["| # | Method | Change | Files | Risk | Verified | Validation | Status |",
                  "|---:|---|---|---|---|---|---|---|"]
        for i, fix in enumerate(report.fixes, 1):
            verified = {True: "✅", False: "⚠️ still reported", None: "–"}[fix.verified]
            lines.append(f"| {i} | {fix.method} | {_md_escape(fix.summary, 110)} | "
                         f"{_md_escape(', '.join(fix.files), 80)} | {fix.risk} | {verified} | "
                         f"{fix.validation_status} | {fix.status} |")
    if report.validation_checks:
        lines += ["", "## Validation checks", "", "| Check | Category | Fix | Status | Detail |", "|---|---|---:|---|---|"]
        for c in report.validation_checks:
            lines.append(f"| {c.name} | {c.category} | {'' if c.fix_index is None else c.fix_index + 1} | "
                         f"{c.status} | {_md_escape(c.detail, 140)} |")
    lines += ["", "## Findings", "", "| Severity | Title | Location | Scanner | Fix |", "|---|---|---|---|---|"]
    for f in findings[:max_rows]:
        title = _md_escape(f.title, 90)
        if f.is_dependency:
            title += f" — `{_md_escape(f.package_name, 40)}@{_md_escape(f.installed_version, 20)}`" + \
                     (f" → `{_md_escape(f.fixed_version, 20)}`" if f.fixed_version else " (no fix)")
        scanners = ", ".join([f.scanner, *f.also_reported_by])
        lines.append(f"| {_ICON.get(f.severity, '')} {f.severity} | {title} | {_location(f)} | {scanners} | {f.fix_status} |")
    if len(findings) > max_rows:
        lines.append(f"\n_{len(findings) - max_rows} more findings are in findings.json / findings.sarif._")
    if report.notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in report.notes]
    lines += ["", "---", "Automated changes must be reviewed by a human before merging. "
              "Rotate any credential reported as exposed — removing it from the code is not enough.", ""]
    return "\n".join(lines)


def render_pr_body(report: RemediationReport) -> str:
    verdict = _VERDICT.get(report.validation_status, report.validation_status)
    lines = ["## Automated security remediation", "",
             f"Generated by SEL Nexus CyberSuite Application Security (run `{report.run_id}`) against "
             f"`{(report.commit or '')[:12]}`.", "",
             f"**Validation status: {verdict}**", ""]
    if report.validation_status == "flagged":
        lines += ["> [!WARNING]", "> This change set needs review: a Testing & Validation Agent check failed. It is opened as a draft "
                  "for investigation and must not be merged until the failed checks below are resolved.", ""]
    lines += ["### Changes", "", "| # | Method | Change | Risk | Rescan | Validation |", "|---:|---|---|---|---|---|"]
    for i, fix in enumerate(report.fixes, 1):
        if fix.status != "applied":
            continue
        rescan = {True: "✅ resolved", False: "⚠️ still reported", None: "–"}[fix.verified]
        lines.append(f"| {i} | {fix.method} | {_md_escape(fix.summary, 120)} | {fix.risk} | {rescan} | "
                     f"{fix.validation_status} |")
    failed = [c for c in report.validation_checks if c.status in ("failed", "warning")]
    if failed:
        lines += ["", "### Checks needing attention", ""]
        lines += [f"- **{c.status.upper()}** {c.name}" + (f" (fix #{c.fix_index + 1})" if c.fix_index is not None
                                                          else "") + f": {_md_escape(c.detail, 250)}" for c in failed[:25]]
    passed = sum(c.status == "passed" for c in report.validation_checks)
    lines += ["", f"Findings: {report.findings_input} · fixes applied: {report.patches_applied} · "
                  f"verified by rescan: {report.verified_fixed} · checks passed: {passed}/{len(report.validation_checks)}",
              "", "Each fix is a separate commit. Review every change and run the full test suite before merging — "
                  "nothing is merged automatically.", ""]
    return "\n".join(lines)


def render_sarif(findings: list[Finding]) -> dict:
    rules, results = {}, []
    for f in findings:
        rule_id = f.rule_id or f.advisory_id or f.category
        if rule_id not in rules:
            rules[rule_id] = {"id": rule_id, "name": rule_id, "shortDescription": {"text": f.title[:200]},
                              "fullDescription": {"text": (f.description or f.title)[:1000]},
                              "helpUri": f.references[0] if f.references else None,
                              "properties": {"security-severity": _SEC_SCORE[f.severity],
                                             "tags": ["security", f.category] + [f"external/cwe/cwe-{c}" for c in f.cwe]}}
            if not rules[rule_id]["helpUri"]:
                rules[rule_id].pop("helpUri")
        msg = f.title if not f.is_dependency else \
            f"{f.title} ({f.package_name}@{f.installed_version}{' → ' + f.fixed_version if f.fixed_version else ''})"
        result = {"ruleId": rule_id, "level": _SARIF_LEVEL[f.severity], "message": {"text": msg[:1000]},
                  "partialFingerprints": {"primaryLocationLineHash": f.fingerprint()},
                  "properties": {"scanner": f.scanner, "fix_status": f.fix_status}}
        if f.file_path:
            region = {"startLine": max(1, f.line or 1)}
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": f.file_path},
                                                         "region": region}}]
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "ai-remediation-pipeline", "version": __version__,
                                          "informationUri": "https://github.com/", "rules": list(rules.values())}},
                      "results": results}]}


def build_artifacts(report: RemediationReport, findings: list[Finding], patch: str) -> dict[str, tuple[str, str]]:
    return {
        "report.json": (report.model_dump_json(indent=2), "application/json"),
        "report.md": (render_markdown(report, findings), "text/markdown; charset=utf-8"),
        "findings.json": (json.dumps([f.public_dict() for f in findings], indent=2), "application/json"),
        "findings.sarif": (json.dumps(render_sarif(findings), indent=2), "application/sarif+json"),
        "fixes.patch": (patch, "text/x-diff; charset=utf-8"),
    }


def write_artifacts(run_dir: Path, artifacts: dict[str, tuple[str, str]]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    for name, (content, _) in artifacts.items():
        (run_dir / name).write_text(content, encoding="utf-8")


def write_report(report: RemediationReport, run_dir: Path) -> None:
    """Legacy API kept for compatibility."""
    write_artifacts(run_dir, {k: v for k, v in build_artifacts(report, [], "").items()
                              if k in ("report.json", "report.md")})
