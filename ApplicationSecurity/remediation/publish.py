"""Pushing the remediation branch and opening the pull request (the human-approval gate).

Three paths:
* automatic – at the end of a run, from the worker's workspace (``create_pr`` option);
* approval  – later, when a reviewer clicks "Approve & open PR": the per-fix commits stored in
              ``fixes.mbox`` are replayed with ``git am`` onto a fresh clone of the base commit;
* tested    – approval after the Test & Fix loop (testloop.py) already pushed the branch: the PR is opened from that
              branch as it is, test workflow and Remediation Agent test fixes included.

Runs flagged by the Validation Agent become draft PRs labelled ``needs-investigation``.
Nothing is ever merged automatically.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Callable

from .config import get_settings
from .github import GitHubClient, RepoAccessError, RepoRef, clone_repo, parse_repo_url, push_branch
from .gitops import apply_mbox, create_branch, remove_tree
from .models import RemediationReport
from .report import render_pr_body

LABELS_OK = ["security", "ai-remediation"]
LABELS_FLAGGED = ["security", "ai-remediation", "needs-investigation"]


def _pr_base(report: RemediationReport, default_branch: str | None) -> str:
    ref = report.ref or ""
    if not ref or ref == "HEAD" or re.fullmatch(r"[0-9a-f]{7,40}", ref) or ref.startswith("refs/tags/"):
        return default_branch or "main"
    return ref


def open_pull_request(repo: RepoRef, workdir: Path | None, report: RemediationReport, default_branch: str | None,
                      log: Callable[[str], None], extra_body: str = "") -> tuple[str, bool]:
    """Push ``report.branch`` from ``workdir`` (None: it is already on GitHub) and open the PR. Returns (url, draft)."""
    s = get_settings()
    if not s.github_token:
        raise RepoAccessError("No GitHub token configured — add one in Settings to push fixes.")
    applied = [f for f in report.fixes if f.status == "applied"]
    flagged = report.validation_status == "flagged"
    if workdir is not None:
        push_branch(repo, workdir, report.branch)
        log(f"Pushed branch {report.branch} to {repo.html_url}")
    title = f"Security remediation: {len(applied)} automated fix(es)"
    if flagged:
        title = "[Needs investigation] " + title
    with GitHubClient() as gh:
        if default_branch is None:
            try:
                default_branch = gh.get_repo(repo).default_branch
            except RepoAccessError:
                default_branch = None
        url, number, draft = gh.create_pull_request(repo, report.branch, _pr_base(report, default_branch), title,
                                                    render_pr_body(report) + extra_body, draft=flagged)
        if number:
            try:
                gh.add_labels(repo, number, LABELS_FLAGGED if flagged else LABELS_OK)
            except Exception:  # noqa: BLE001 - labels are cosmetic
                pass
    log(f"Opened {'draft ' if draft else ''}pull request {url}")
    return url, draft


def publish_from_artifacts(repo_url: str, report: RemediationReport, mbox: str,
                           log: Callable[[str], None]) -> tuple[str, bool]:
    """Approval path: rebuild the remediation branch from the stored commits and open the PR."""
    if not mbox.strip():
        raise RepoAccessError("This scan has no replayable fix commits (fixes.mbox is empty).")
    if not report.base_commit or not report.branch:
        raise RepoAccessError("The run did not record a base commit/branch; re-run it to publish.")
    repo: RepoRef = parse_repo_url(repo_url)
    workdir = get_settings().workspaces_dir / f"publish-{uuid.uuid4().hex[:10]}"
    try:
        log(f"Cloning {repo.full_name} @ {report.base_commit[:12]} to replay {len(report.fixes)} fix commit(s)")
        clone_repo(repo, workdir, report.base_commit)
        create_branch(workdir, report.branch)
        ok, message = apply_mbox(workdir, mbox)
        if not ok:
            raise RepoAccessError(f"Could not replay the fix commits: {message[-500:]}")
        return open_pull_request(repo, workdir, report, None, log)
    finally:
        if not get_settings().keep_workspaces:
            remove_tree(workdir)


def tests_section(tests: dict) -> str:
    """The Test & Fix loop's results for the pull request description."""
    runs = tests.get("runs") or []
    lines = ["", "", "## Tests on GitHub Actions", "",
             f"**{tests.get('message') or tests.get('status', '')}** Test command: `{tests.get('test_command', '?')}`", ""]
    for r in runs:
        result = r.get("conclusion") or r.get("status") or "?"
        link = f"[run {r.get('n')}]({r['url']})" if r.get("url") else f"run {r.get('n')}"
        failed = f", {len(r['failed'])} failing test(s)" if r.get("failed") else ""
        lines.append(f"- {link}: {result}{failed}")
        fix = r.get("fix")
        if fix:
            note = " (changed a test: please review it)" if fix.get("touched_tests") else ""
            lines.append(f"  - Remediation Agent fix: {fix.get('explanation', '')} ({', '.join(fix.get('files') or [])}){note}")
    return "\n".join(lines) + "\n"


def publish_tested_branch(repo_url: str, report: RemediationReport, tests: dict,
                          log: Callable[[str], None]) -> tuple[str, bool]:
    """Approval after the Test & Fix loop: the branch is already on GitHub, so only the PR is opened."""
    report.branch = tests["branch"]
    if tests.get("status") != "passed":
        report.validation_status = "flagged"  # tests did not pass: the PR opens as a draft for investigation
    log(f"Opening the pull request from {report.branch}, which the test loop already pushed")
    return open_pull_request(parse_repo_url(repo_url), None, report, None, log, extra_body=tests_section(tests))


__all__ = ["open_pull_request", "publish_from_artifacts", "publish_tested_branch", "tests_section"]
