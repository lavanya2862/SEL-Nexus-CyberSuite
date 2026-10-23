"""Orchestrator: runs the agents in order for one GitHub repository.

    Repository Ingestion        validate link → shallow clone → detect languages/manifests
    Analysis Agent              CodeQL (primary) + Trivy + supporting scanners → normalise → dedupe → rank
    Remediation Agent           isolated branch → deterministic fixes + code fixes, one commit per fix
    Validation Agent            static · security-regression guard · functional tests · security rescan
    Reporting Component         report.md/json · findings.sarif · fixes.patch · fixes.mbox
    Human Approval & PR         push + PR (draft + needs-investigation when flagged); never auto-merged
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .agents import (AnalysisAgent, ConsoleReporter, JobCancelled, JobTimedOut, RemediationAgent, ReportingAgent,
                     Reporter, RunContext, ValidationAgent)
from .config import get_settings
from .detect import detect_project
from .github import GitHubClient, RepoAccessError, clone_repo, parse_repo_url
from .gitops import diff_since, format_patch, remove_tree
from .models import Finding, JobOptions, RemediationReport
from .parsers import deduplicate, parse_codeql, parse_trivy
from .publish import open_pull_request
from .report import build_artifacts, write_artifacts

log = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    report: RemediationReport
    findings: list[Finding]
    artifacts: dict[str, tuple[str, str]] = field(default_factory=dict)

    def summary(self) -> dict:
        r = self.report
        return {"status": r.status, "commit": r.commit, "findings": r.findings_input,
                "findings_selected": r.findings_selected, "severity_counts": r.severity_counts,
                "fixes_applied": r.patches_applied, "verified_fixed": r.verified_fixed,
                "pull_request_url": r.pull_request_url, "pull_request_draft": r.pull_request_draft,
                "branch": r.branch, "validation_status": r.validation_status,
                "approval_status": r.approval_status, "llm_enabled": r.llm_enabled,
                "ai_fixes": sum(1 for f in r.fixes if f.method == "llm" and f.status == "applied")}


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]


class RepositoryPipeline:
    def __init__(self, repo_url: str, options: JobOptions | None = None, reporter: Reporter | None = None,
                 run_id: str | None = None, imported: dict | None = None):
        options = options or JobOptions()
        repo = parse_repo_url(repo_url, options.ref)
        self.ctx = RunContext(repo, options, reporter or ConsoleReporter(), run_id or new_run_id(), imported)
        self.s = self.ctx.s
        self.options, self.repo, self.run_id = options, repo, self.ctx.run_id
        self.report = self.ctx.report

    # -- Repository Ingestion -----------------------------------------------------------------
    def _ingest(self) -> None:
        ctx = self.ctx
        ctx.start_stage("ingest", f"Fetching {self.repo.full_name}")
        ctx.progress("ingest", 5)
        ref = self.repo.ref
        try:
            with GitHubClient() as gh:
                meta = gh.get_repo(self.repo)
            if meta.size_kb and meta.size_kb > self.s.max_repo_size_mb * 1024:
                raise RepoAccessError(f"Repository is {meta.size_kb // 1024} MB; MAX_REPO_SIZE_MB is "
                                      f"{self.s.max_repo_size_mb}.")
            if meta.archived:
                self.report.notes.append("Repository is archived; pull requests cannot be opened.")
            ctx.default_branch = meta.default_branch
            ref = ref or meta.default_branch
            ctx.can_push = meta.can_push
            ctx.step("ingest", "GitHub metadata",
                     detail=f"default branch {meta.default_branch}, {'private' if meta.private else 'public'}, "
                            f"push access: {'yes' if meta.can_push else 'no' if meta.can_push is False else 'unknown'}")
        except RepoAccessError as exc:
            if "not found" in str(exc) or "MAX_REPO_SIZE" in str(exc) or "denied" in str(exc):
                raise
            ctx.log(f"GitHub API lookup failed ({exc}); falling back to git only.", "warning")
            ctx.step("ingest", "GitHub metadata", "warning", str(exc)[:300])
        ctx.log(f"Cloning {self.repo.html_url} @ {ref or 'default branch'}")
        sha = clone_repo(self.repo, ctx.src, ref)
        self.report.ref, self.report.commit = ref or "HEAD", sha
        ctx.step("ingest", "Shallow clone", detail=f"{ref or 'HEAD'} @ {sha[:12]}")
        ctx.progress("ingest", 12)
        ctx.info = detect_project(ctx.src)
        self.report.languages = ctx.info.languages
        langs = ", ".join(f"{k} ({v})" for k, v in list(ctx.info.languages.items())[:6]) or "none detected"
        ctx.step("ingest", "Detect languages & manifests",
                 detail=f"{langs}; manifests: {', '.join(ctx.info.manifests[:8]) or 'none'}")
        ctx.finish_stage("ingest", "completed", f"{self.repo.full_name}@{sha[:8]} · {langs}",
                         commit=sha[:12], files_languages=sum(ctx.info.languages.values()))

    # -- Human Approval & PR ------------------------------------------------------------------
    def _approval(self) -> None:
        ctx, rep = self.ctx, self.report
        applied = [f for f in rep.fixes if f.status == "applied"]
        if not applied:
            rep.approval_status = "not_required"
            ctx.skip_stage("approval", "No fixes to review")
            return
        ctx.start_stage("approval", "Preparing pull request for human review")
        flagged = rep.validation_status == "flagged"
        if not self.options.create_pr:
            rep.approval_status = "awaiting_approval"
            ctx.step("approval", "Awaiting reviewer approval", "warning",
                     "Push to GitHub was not requested. Review the fixes and click “Approve & open PR”.")
            ctx.finish_stage("approval", "warning", "Awaiting human approval")
            return
        if flagged and self.options.pr_on_flagged == "skip":
            rep.approval_status = "awaiting_approval"
            ctx.step("approval", "Held back: validation flagged", "warning",
                     "Policy pr_on_flagged=skip — investigate, then approve manually.")
            ctx.finish_stage("approval", "warning", "Validation flagged — held for investigation")
            return
        if not self.s.github_token:
            rep.approval_status = "awaiting_approval"
            rep.notes.append("Push requested but no GitHub token is configured (Settings → GitHub).")
            ctx.step("approval", "Push to GitHub", "failed", "No GitHub token configured — add one in Settings, "
                                                               "then use “Approve & open PR”.")
            ctx.finish_stage("approval", "failed", "GitHub token missing")
            return
        if ctx.can_push is False:
            rep.approval_status = "failed"
            rep.notes.append("The configured token has no push access to this repository; fork it or grant access.")
            ctx.step("approval", "Push to GitHub", "failed", "Token has no push access to this repository.")
            ctx.finish_stage("approval", "failed", "No push access")
            return
        try:
            ctx.progress("approval", 96)
            url, draft = open_pull_request(self.repo, ctx.src, rep, ctx.default_branch, ctx.log)
            rep.pull_request_url, rep.pull_request_draft, rep.approval_status = url, draft, "pr_opened"
            ctx.step("approval", "Branch pushed", detail=rep.branch)
            ctx.step("approval", "Draft PR (needs investigation)" if draft else "Pull request opened",
                     "warning" if draft else "completed", url)
            ctx.finish_stage("approval", "warning" if flagged else "completed",
                             ("Draft PR opened — flagged for investigation" if flagged
                              else "PR opened — awaiting human review & merge"), pull_request=url)
        except RepoAccessError as exc:
            rep.approval_status = "failed"
            rep.notes.append(f"Could not open pull request: {exc}")
            ctx.step("approval", "Push / pull request", "failed", str(exc)[:500])
            ctx.finish_stage("approval", "failed", "Publishing failed")

    # -- main ---------------------------------------------------------------------------------
    def run(self) -> PipelineResult:
        ctx, rep = self.ctx, self.report
        started = time.monotonic()
        rep.started_at = datetime.now(timezone.utc).isoformat()
        rep.status = "running"
        ctx.emit()
        try:
            self._ingest()
            analysis = AnalysisAgent(ctx)
            analysis.run()
            patch = mbox = ""
            if self.options.auto_fix and ctx.selected:
                remediation = RemediationAgent(ctx)
                base = remediation.create_branch()
                validation = ValidationAgent(ctx, analysis)
                validation.run_baseline()
                remediation.run()
                if rep.fixes:
                    validation.run()
                else:
                    ctx.skip_stage("validation", "No fixes to validate")
                patch, mbox = diff_since(ctx.src, base), format_patch(ctx.src, base)
            else:
                reason = "auto_fix disabled (scan only)" if not self.options.auto_fix else "No findings to remediate"
                if not self.options.auto_fix:
                    rep.notes.append("auto_fix disabled: scan only.")
                ctx.skip_stage("remediation", reason)
                ctx.skip_stage("validation", reason)

            rep.patches_applied = len([f for f in rep.fixes if f.status == "applied"])
            rep.status = ("clean" if not ctx.findings else "fixed" if rep.patches_applied else "findings_only")
            if rep.patches_applied and rep.validation_status == "flagged":
                rep.status = "fixed_flagged"
            if not rep.llm_enabled and any(f.fix_status == "skipped" for f in ctx.findings):
                rep.notes.append("Some findings need code changes; configure an LLM in Settings so the Remediation "
                                 "Agent can patch them.")
            rep.notes.append("Nothing is merged automatically. Every change goes through human review.")
            reporting = ReportingAgent(ctx)
            artifacts = reporting.run(patch, mbox)
            self._approval()
            rep.finished_at = datetime.now(timezone.utc).isoformat()
            rep.duration_seconds = round(time.monotonic() - started, 2)
            artifacts.update({k: v for k, v in reporting.build(patch, mbox).items()
                              if k in ("report.json", "report.md")})  # include PR URL + final timings
            ctx.log(f"Finished: {rep.status} · validation {rep.validation_status} · {rep.findings_input} findings, "
                    f"{rep.patches_applied} fix(es), {rep.verified_fixed} verified.")
            return PipelineResult(rep, ctx.findings, artifacts)
        except BaseException as exc:
            rep.finished_at = datetime.now(timezone.utc).isoformat()
            ctx.fail_running_stages(str(exc) or type(exc).__name__)
            raise
        finally:
            if not self.s.keep_workspaces:
                try:
                    remove_tree(ctx.workspace)
                except OSError as exc:  # pragma: no cover
                    log.warning("workspace cleanup failed: %s", exc)


def run_repository(repo_url: str, options: JobOptions | None = None, reporter: Reporter | None = None,
                   run_id: str | None = None, output_dir: Path | None = None,
                   imported: dict | None = None) -> PipelineResult:
    result = RepositoryPipeline(repo_url, options, reporter, run_id, imported).run()
    if output_dir is not None:
        write_artifacts(output_dir, result.artifacts)
    return result


# --- Legacy helpers (local scanner reports) ---------------------------------------------------

def load_findings(codeql_path=None, trivy_path=None) -> list[Finding]:
    findings = []
    if codeql_path:
        findings.extend(parse_codeql(codeql_path))
    if trivy_path:
        findings.extend(parse_trivy(trivy_path))
    return deduplicate(findings)


def get_report(run_id: str):
    path = get_settings().runs_dir / run_id / "report.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


__all__ = ["RepositoryPipeline", "run_repository", "PipelineResult", "JobCancelled", "JobTimedOut",
           "ConsoleReporter", "load_findings", "get_report", "build_artifacts"]
