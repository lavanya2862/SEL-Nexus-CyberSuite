"""AI Remediation Agent.

Works on an isolated ``ai-remediation/*`` branch of a fresh clone. For each prioritised finding
it picks the safest strategy that can fix it:

    dependency upgrade (deterministic)  →  rule rewrite (deterministic)  →  secret → env var
    →  LLM-generated patch (search/replace edits, self-corrected)

Every fix is syntax-checked and committed separately so it can be validated, reverted or
reviewed on its own.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextvars import copy_context
from pathlib import Path

from ..fixers import (FixAttempt, fix_action_pin, fix_dependency_group, fix_secret_to_env, fix_with_llm, fix_with_rule,
                      group_dependency_findings, is_mutable_action_finding, npm_lockfile_dirs, propose_fix,
                      refresh_npm_lockfile)
from ..gitops import commit_all, commit_diff, create_branch, discard_changes, head_sha
from ..llm import LLMQuotaExhausted
from ..models import Finding, FixRecord
from .base import RunContext

METHOD_LABEL = {"dependency": "Dependency upgrade", "rule": "Deterministic rewrite", "llm": "Code fix"}


# Lines of code -> AI remediation calls at the same time: bigger code bases have more findings and larger files
WORKER_TIERS = ((10_000, 4), (50_000, 8), (150_000, 16))
LARGEST_TIER = 32


def ai_workers(s, lines_of_code: int, queued: int) -> tuple[int, str]:
    """How many findings the model works on at the same time in one scan, and why. "auto" (the default) sizes it from
    the repository's lines of code, never above llm_max_workers, the number of findings waiting, or what the
    provider's requests-per-minute allows (a remediation call takes several seconds, so about 4 per worker)."""
    setting = str(getattr(s, "llm_workers", "auto") or "auto").strip().lower()
    ceiling = max(1, int(getattr(s, "llm_max_workers", 8) or 8))
    if setting != "auto" and setting.isdigit():
        wanted, why = int(setting), "fixed"
    else:
        wanted = next((n for limit, n in WORKER_TIERS if lines_of_code < limit), LARGEST_TIER)
        wanted, why = min(wanted, ceiling), f"auto for {lines_of_code:,} lines of code"
    rpm = int(getattr(s, "llm_rpm", 0) or 0)
    if rpm:
        wanted = min(wanted, max(1, rpm // 4))
    return max(1, min(wanted, queued)), why


class RemediationAgent:
    stage_id = "remediation"

    def __init__(self, ctx: RunContext):
        self.ctx = ctx
        self.attempted = 0
        self.quota_message = ""

    def create_branch(self) -> str:
        ctx = self.ctx
        base = head_sha(ctx.src)
        ctx.report.base_commit = base
        ctx.report.branch = f"ai-remediation/{base[:8]}-{ctx.run_id[-8:]}"
        create_branch(ctx.src, ctx.report.branch)
        return base

    def _risk(self, method: str, attempt: FixAttempt) -> str:
        if "[MAJOR]" in attempt.summary:
            return "high"
        if method == "llm" or "credential" in attempt.summary.lower() or "package-lock" in attempt.summary:
            return "medium"
        return "low"

    def record(self, findings: list[Finding], method: str, attempt: FixAttempt) -> FixRecord | None:
        ctx = self.ctx
        ids = [f.finding_id for f in findings]
        if not attempt.ok:
            for f in findings:
                f.fix_status = "manual" if attempt.manual else "failed"
                f.fix_note = attempt.detail[:1000]
            if not attempt.manual:
                ctx.log(f"{', '.join(ids)[:120]}: fix failed — {attempt.detail[:300]}", "warning")
                ctx.step(self.stage_id, f"✗ {findings[0].title[:80] if findings else 'fix'}", "failed",
                         attempt.detail[:400])
            return None
        message = (f"fix(security): {attempt.summary[:150]}\n\n{attempt.detail[:1500]}\n\n"
                   f"Findings: {', '.join(ids)[:500]}\nGenerated-by: ai-remediation-pipeline run {ctx.run_id}")
        sha = commit_all(ctx.src, message, attempt.files)
        if not sha:
            for f in findings:
                f.fix_status, f.fix_note = "failed", "Fix produced no change."
            return None
        record = FixRecord(finding_ids=ids, method=method, summary=attempt.summary, files=attempt.files, commit=sha,
                           detail=attempt.detail[:2000], diff=commit_diff(ctx.src, sha),
                           explanation=attempt.detail[:2000] if method == "llm" else "",
                           risk=self._risk(method, attempt))
        ctx.report.fixes.append(record)
        ctx.fix_commits.append((sha, record))
        for f in findings:
            f.fix_status, f.fix_note = "fixed", attempt.summary[:500]
        ctx.log(f"Applied {method} fix: {attempt.summary[:200]} ({sha[:10]})")
        ctx.step(self.stage_id, f"{METHOD_LABEL[method]}: {attempt.summary[:110]}", "completed",
                 f"commit {sha[:10]} · {', '.join(attempt.files)[:200]}")
        return record

    def _dependencies(self, selected: list[Finding]) -> None:
        ctx = self.ctx
        for (manifest, package), group in group_dependency_findings(selected).items():
            ctx.checkpoint()
            self.attempted += 1
            self.record(group, "dependency", fix_dependency_group(ctx.src, manifest, package, group))
        for rel_dir in npm_lockfile_dirs(ctx.src, selected):
            ctx.checkpoint()
            lock_rel = (Path(rel_dir) / "package-lock.json").as_posix()
            pending = [f for f in selected if f.is_dependency and f.ecosystem == "npm"
                       and Path(f.file_path or "").parent.as_posix() in (rel_dir or ".", rel_dir)
                       and f.fix_status != "fixed"]
            ctx.log(f"Refreshing {lock_rel} with npm (lockfile only, scripts disabled)")
            attempt = refresh_npm_lockfile(ctx.src, rel_dir)
            self.attempted += 1
            if attempt.ok:
                self.record(pending, "dependency", attempt)
            else:
                ctx.step(self.stage_id, f"npm lockfile refresh ({lock_rel})", "warning", attempt.detail[:400])

    def _code(self, selected: list[Finding]) -> None:
        """Every code finding in the scan's scope (the severities chosen for it), in risk order: rule-based fixes
        first, then AI-assisted remediation. The model is asked about all remaining findings at the same time
        (LLM_MAX_CONCURRENCY calls, paced to the provider's limit); the answers are applied one by one."""
        ctx = self.ctx
        limit = ctx.options.max_findings or ctx.s.max_findings_per_run  # 0 = no ceiling: the scope decides
        candidates = [f for f in selected if not f.is_dependency and f.fix_status == "not_attempted"]
        queue: list[Finding] = []
        for idx, finding in enumerate(candidates):
            ctx.checkpoint()
            ctx.reporter.stage("remediation", 50 + int(10 * idx / max(1, len(candidates))))
            if finding.remediation_type == "dependency_upgrade":
                finding.fix_status, finding.fix_note = "manual", "Dependency finding without package metadata."
                continue
            if finding.remediation_type == "secret_removal":
                attempt = fix_secret_to_env(ctx.src, finding)
                if attempt is not None:
                    self.attempted += 1
                    if self.record([finding], "rule", attempt):
                        continue
                finding.fix_status = "manual"
                finding.fix_note = ("Remove the secret from source and history, rotate it, and load it from a secret "
                                    "store (no safe automatic rewrite for this location).")
                continue
            if is_mutable_action_finding(finding):
                pin = fix_action_pin(ctx.src, finding)
                if pin is not None:
                    self.attempted += 1
                    self.record([finding], "rule", pin)
                    continue
            rule_attempt = fix_with_rule(ctx.src, finding)
            if rule_attempt is not None:
                self.attempted += 1
                if self.record([finding], "rule", rule_attempt):
                    continue
            if (finding.raw or {}).get("vendored"):
                finding.fix_status = "skipped"
                finding.fix_note = ("Third-party library code: update the bundled library to a current version instead of "
                                    "patching its source.")
                continue
            if (finding.raw or {}).get("in_tests"):
                finding.fix_status, finding.fix_note = "skipped", "Located in test code (reported, not patched)."
                continue
            if not ctx.report.llm_enabled:
                finding.fix_status = "skipped"
                finding.fix_note = ("AI-assisted remediation was turned off for this scan; re-run with it switched on."
                                    if ctx.s.llm_enabled and not ctx.options.use_llm else
                                    "Needs AI-assisted remediation: the organisation's AI model is not configured on this "
                                    "server.")
                continue
            if limit and len(queue) >= limit:
                finding.fix_status, finding.fix_note = "skipped", ("The optional per-scan ceiling on AI-assisted "
                                                                   "remediations was reached (max_findings budget).")
                continue
            queue.append(finding)
        if queue:
            self._ai(queue)

    def _ai(self, queue: list[Finding]) -> None:
        ctx = self.ctx
        workers, why = ai_workers(ctx.s, getattr(ctx.report, "lines_of_code", 0), len(queue))
        ctx.report.ai_workers = workers
        ctx.step(self.stage_id, f"AI-assisted remediation of {len(queue)} finding(s)",
                 detail=f"{ctx.s.llm_model} · {workers} at a time ({why})")
        proposals: dict[str, tuple[list[dict], str] | Exception] = {}
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="remediation-ai") as pool:
            # each call runs in a copy of this thread's context, so it uses the same person's settings
            futures = {pool.submit(copy_context().run, propose_fix, ctx.src, f): f for f in queue}
            for done, future in enumerate(as_completed(futures), 1):
                finding = futures[future]
                try:
                    proposals[finding.finding_id] = future.result()
                except Exception as exc:  # noqa: BLE001 - recorded per finding below
                    proposals[finding.finding_id] = exc
                ctx.reporter.stage("remediation", 60 + int(10 * done / len(queue)))
        for idx, finding in enumerate(queue):
            ctx.checkpoint()
            ctx.reporter.stage("remediation", 70 + int(5 * idx / len(queue)))
            self.attempted += 1
            proposal = proposals.get(finding.finding_id)
            if isinstance(proposal, LLMQuotaExhausted):  # answers that already arrived are still applied
                self.quota_message = self.quota_message or str(proposal)
                finding.fix_status = "skipped"
                finding.fix_note = f"Remediation Agent could not use its AI model: {self.quota_message}"
                continue
            if isinstance(proposal, Exception):
                self.record([finding], "llm", FixAttempt(False, detail=str(proposal)[:1000]))
                continue
            ctx.log(f"Remediation Agent → AI: {finding.finding_id} ({finding.title[:90]})")
            try:
                attempt = fix_with_llm(ctx.src, finding, ctx.s.llm_fix_attempts, ctx.log, proposal=proposal)
            except LLMQuotaExhausted as exc:
                discard_changes(ctx.src)
                self.quota_message = str(exc)
                finding.fix_status, finding.fix_note = "skipped", f"Remediation Agent could not use its AI model: {exc}"
                continue
            self.record([finding], "llm", attempt)
        if self.quota_message:
            # Circuit breaker: the quota will not come back during this run, so the rest waits for the next scan.
            ctx.log(f"LLM quota exhausted — remaining code findings will wait for the next run. {self.quota_message}",
                    "warning")
            ctx.step(self.stage_id, "LLM quota exhausted", "warning", self.quota_message[:400])
            ctx.report.notes.append(self.quota_message)

    def run(self) -> None:
        ctx = self.ctx
        ctx.start_stage(self.stage_id, "Generating and applying patches on an isolated branch")
        ctx.progress("remediation", 50)
        ctx.step(self.stage_id, f"Isolated branch {ctx.report.branch}", detail=f"base {ctx.report.base_commit[:12]}")
        if ctx.options.fix_dependencies:
            self._dependencies(ctx.selected)
        self._code(ctx.selected)
        discard_changes(ctx.src)
        rep = ctx.report
        rep.patches_proposed = self.attempted
        rep.patches_applied = len(rep.fixes)
        by_method = {m: sum(1 for f in rep.fixes if f.method == m) for m in ("dependency", "rule", "llm")}
        manual = sum(1 for f in ctx.selected if f.fix_status == "manual")
        skipped = sum(1 for f in ctx.selected if f.fix_status == "skipped")
        if manual:
            ctx.step(self.stage_id, f"{manual} finding(s) need manual remediation", "warning",
                     "See the fix note on each finding (e.g. no upstream patch, transitive dependency, secret rotation).")
        if skipped and not rep.llm_enabled:
            ctx.step(self.stage_id, f"{skipped} code finding(s) waiting for a Remediation Agent code fix", "warning",
                     "The organisation's AI model is not configured on this server; once it is, re-run the scan.")
        status = "completed" if rep.fixes else ("warning" if ctx.selected else "skipped")
        ctx.finish_stage(self.stage_id, status,
                         f"{len(rep.fixes)} fix commit(s): {by_method['dependency']} dependency, {by_method['rule']} "
                         f"deterministic, {by_method['llm']} code fixes · {manual} manual · {skipped} skipped",
                         fixes=len(rep.fixes), attempted=self.attempted, ai_fixes=by_method["llm"], manual=manual,
                         skipped=skipped)
