"""Testing & Validation Agent.

Four layers of evidence for every fix:

1. static            – edited files still parse (no repository code is executed)
2. security-regression – the patch itself must not weaken security (suppressions, disabled TLS,
                         skipped/deleted tests, removed auth/CSRF controls, new hard-coded secrets)
3. functional        – the project's test suite, baseline vs. after, in a sandbox; a fix that
                       breaks a previously passing suite is isolated and reverted
4. security-rescan   – scanners re-run on the patched branch: each finding must be gone and no
                       new high/critical finding may appear

Any failure flags the run for investigation instead of letting it through.
"""
from __future__ import annotations

import re

from ..gitops import git, revert_commit
from ..models import FixRecord, ValidationCheck, ValidationResult
from ..sandbox import run_in_sandbox, sandbox_available
from ..validate import static_check
from .base import RunContext

GUARD_ADDED = [
    (re.compile(r"(#|//)\s*(nosec|nosemgrep|noqa|NOLINT)|eslint-disable|@SuppressWarnings|lgtm\[|codeql\["),
     "adds a scanner/linter suppression"),
    (re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CERT_NONE"),
     "disables TLS certificate verification"),
    (re.compile(r"@pytest\.mark\.skip|unittest\.skip|\bxit\(|\bit\.skip\(|describe\.skip\(|@Disabled|@Ignore|t\.Skip\("),
     "skips tests"),
    (re.compile(r"(?i)\b(password|passwd|secret|api_?key|access_?token|private_?key)\w*\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"),
     "introduces a hard-coded credential"),
    (re.compile(r"(?i)\bdebug\s*=\s*True\b"), "enables debug mode"),
    (re.compile(r"\b(eval|exec)\s*\(|shell\s*=\s*True|pickle\.loads?\("), "introduces a dangerous API call"),
    (re.compile(r"(?i)hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|blake2\w?)\s*\([^)]*pass|"
                r"pass\w*\s*=\s*hashlib\.(md5|sha1|sha224|sha256|sha384|sha512)"),
     "hashes a password with a fast unsalted digest (use bcrypt/argon2/scrypt/PBKDF2)"),
]
GUARD_REMOVED = [
    (re.compile(r"@login_required|@requires_auth|@permission_required|@csrf_protect|authorize|authenticate|"
                r"csrf|helmet\(|sanitize|escape\("), "removes an authentication/authorization or input-handling control"),
]
TEST_PATH = re.compile(r"(^|/)(tests?|spec|__tests__)/|(^|/)test_[^/]*$|_test\.\w+$|\.(spec|test)\.\w+$")


def issue_key(f) -> str:
    """Version-independent identity of an issue (used to decide whether a rescan finding is new)."""
    if f.is_dependency:
        ids = sorted({a.upper() for a in [f.advisory_id or "", *f.aliases] if a})
        return f"dep|{(f.package_name or '').lower().replace('_', '-')}|{ids[0] if ids else f.title.lower()}"
    return f.fingerprint()


def diff_guard(diff: str) -> list[str]:
    """Security-regression lint of a single fix's diff."""
    problems: list[str] = []
    added: dict[str, list[str]] = {}
    removed: dict[str, list[str]] = {}
    current_file = ""
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            current_file = line.split(" b/", 1)[-1]
            continue
        if line.startswith("deleted file mode") and TEST_PATH.search(current_file):
            problems.append(f"deletes test file {current_file}")
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("+"):
            added.setdefault(current_file, []).append(line[1:])
        elif line.startswith("-"):
            removed.setdefault(current_file, []).append(line[1:])

    def present(lines: list[str], token: str) -> bool:
        return any(token in l for l in lines)

    # Only flag what the patch changes: a pattern that also exists on the other side of the
    # same hunk (i.e. a modified line that already contained it) is not a regression.
    for file, lines in added.items():
        for line in lines:
            for pattern, why in GUARD_ADDED:
                m = pattern.search(line)
                if m and not present(removed.get(file, []), m.group(0)):
                    problems.append(f"{why}: `{line.strip()[:120]}` ({file})")
    for file, lines in removed.items():
        for line in lines:
            for pattern, why in GUARD_REMOVED:
                m = pattern.search(line)
                if m and not present(added.get(file, []), m.group(0)):
                    problems.append(f"{why}: `{line.strip()[:120]}` ({file})")
            if TEST_PATH.search(file) and re.search(r"\bassert|expect\(", line) and not present(
                    added.get(file, []), line.strip()[:40]):
                problems.append(f"removes a test assertion in {file}")
    return list(dict.fromkeys(problems))[:10]


class ValidationAgent:
    stage_id = "validation"

    def __init__(self, ctx: RunContext, analysis_agent):
        self.ctx = ctx
        self.analysis = analysis_agent
        self.tests_on = False
        self.test_cmd: str | None = None
        self.install_cmd: str | None = None
        self.baseline: ValidationResult | None = None

    # -- functional tests -----------------------------------------------------------------
    def plan_tests(self) -> None:
        ctx, info = self.ctx, self.ctx.info
        if ctx.options.run_tests is False:
            return
        available, why = sandbox_available()
        command = ctx.options.test_command or (info.test_command if info else None)
        if not command:
            if ctx.options.run_tests:
                ctx.report.notes.append("Tests requested but no test command was detected; pass test_command.")
            return
        if not available:
            if ctx.options.run_tests:
                ctx.report.notes.append(f"Tests requested but the sandbox is unavailable ({why}).")
            return
        self.tests_on, self.test_cmd = True, command
        self.install_cmd = ctx.options.install_command or (info.install_command if info else None)

    def _run_tests(self, name: str) -> ValidationResult:
        full = f"{self.install_cmd} && {self.test_cmd}" if self.install_cmd else self.test_cmd
        self.ctx.log(f"Validation Agent: running {name}: {full}")
        result = run_in_sandbox(name, full, self.ctx.src, self.ctx.info.docker_image)
        self.ctx.log(f"{name}: {'skipped' if result.skipped else ('passed' if result.passed else 'FAILED')} "
                     f"({result.duration_seconds:.0f}s)", "info" if result.passed else "warning")
        return result

    def run_baseline(self) -> None:
        """Called before remediation so failures can be attributed to the fixes."""
        self.plan_tests()
        if self.tests_on:
            self.ctx.progress("baseline-tests", 45)
            self.baseline = self._run_tests("baseline-tests")
            self.ctx.report.validation.append(self.baseline)

    def _rollback_culprit(self, checks: list[ValidationCheck]) -> None:
        ctx = self.ctx
        ctx.log("Functional tests regressed after the fixes; isolating the responsible commit.", "warning")
        for sha, record in reversed(list(ctx.fix_commits)):
            ctx.checkpoint()
            if record.status != "applied" or not revert_commit(ctx.src, sha):
                continue
            result = self._run_tests(f"tests-without-{sha[:8]}")
            if result.passed:
                record.status, record.validation_status = "reverted", "flagged"
                record.detail = (record.detail + " | Reverted: broke the functional test suite.").strip(" |")
                for f in ctx.findings:
                    if f.finding_id in record.finding_ids:
                        f.fix_status, f.fix_note = "failed", "Fix reverted because it broke the test suite."
                ctx.report.validation.append(result)
                idx = ctx.report.fixes.index(record)
                checks.append(ValidationCheck(name="Regression isolated and reverted", category="functional",
                                              status="warning", fix_index=idx,
                                              detail=f"{record.summary[:120]} broke the tests and was reverted."))
                return
            git(["reset", "-q", "--hard", "HEAD~1"], ctx.src)
        checks.append(ValidationCheck(name="Regression isolation", category="functional", status="failed",
                                      detail="Tests fail after the fixes and no single fix could be isolated."))

    # -- main -----------------------------------------------------------------------------
    def run(self) -> None:
        ctx = self.ctx
        rep = ctx.report
        ctx.start_stage(self.stage_id, "Validating every fix")
        ctx.progress("validation", 78)
        checks: list[ValidationCheck] = []
        applied = [(i, f) for i, f in enumerate(rep.fixes) if f.status == "applied"]

        # 1. static
        bad = 0
        for idx, fix in applied:
            ok, problem = static_check(ctx.src, fix.files)
            bad += not ok
            checks.append(ValidationCheck(name="Syntax / parse check", category="static",
                                          status="passed" if ok else "failed", fix_index=idx,
                                          detail=problem or f"{len(fix.files)} file(s) parse cleanly"))
        ctx.step(self.stage_id, "Static checks (syntax, manifests)", "failed" if bad else "completed",
                 f"{len(applied) - bad}/{len(applied)} fixes parse cleanly")

        # 2. security-regression guard
        flagged = 0
        for idx, fix in applied:
            problems = diff_guard(fix.diff)
            flagged += bool(problems)
            checks.append(ValidationCheck(name="Security regression guard", category="security-regression",
                                          status="failed" if problems else "passed", fix_index=idx,
                                          detail="; ".join(problems) or "No weakening patterns in the patch"))
            if "[MAJOR]" in fix.summary:
                checks.append(ValidationCheck(name="Major-version upgrade", category="policy", status="warning",
                                              fix_index=idx, detail="Breaking API changes possible; run the full "
                                                                    "test suite before merging."))
        ctx.step(self.stage_id, "Security regression guard", "failed" if flagged else "completed",
                 f"{flagged} patch(es) contain weakening patterns" if flagged else "No suppressions, disabled checks, "
                 "skipped tests or removed controls introduced")

        # 3. functional tests
        if self.baseline is not None:
            ctx.step(self.stage_id, "Baseline functional tests",
                     "completed" if self.baseline.passed else "warning",
                     f"{self.baseline.command} → exit {self.baseline.exit_code}")
        if self.tests_on and applied:
            ctx.progress("functional-tests", 80)
            final = self._run_tests("tests-after-fixes")
            rep.validation.append(final)
            if final.passed:
                checks.append(ValidationCheck(name="Functional test suite", category="functional", status="passed",
                                              detail=f"{final.command} passed in {final.duration_seconds:.0f}s"))
            elif self.baseline and not self.baseline.passed:
                checks.append(ValidationCheck(name="Functional test suite", category="functional", status="warning",
                                              detail="Suite was already failing before any change; results cannot "
                                                     "confirm the fixes."))
            else:
                checks.append(ValidationCheck(name="Functional test suite", category="functional", status="failed",
                                              detail=f"exit {final.exit_code}: {(final.stderr or final.stdout)[-400:]}"))
                if self.baseline and self.baseline.passed:
                    self._rollback_culprit(checks)
            ctx.step(self.stage_id, "Functional tests after fixes", "completed" if final.passed else "failed",
                     f"exit {final.exit_code} in {final.duration_seconds:.0f}s")
        else:
            why = "disabled (enable SANDBOX_MODE and 'Run functional tests')" if not self.tests_on else "no fixes"
            checks.append(ValidationCheck(name="Functional test suite", category="functional", status="skipped",
                                          detail=f"Not run: {why}."))
            ctx.step(self.stage_id, "Functional tests", "skipped", f"Not run: {why}")

        # 4. security rescan
        verified = 0
        if ctx.options.verify_with_rescan and applied:
            ctx.progress("security-rescan", 85)
            after, _ = self.analysis.rescan()
            remaining = {f.fingerprint() for f in after}
            before = {f.fingerprint() for f in ctx.findings}
            imported = self.analysis._imported_names()
            for idx, fix in enumerate(rep.fixes):
                if fix.status != "applied":
                    continue
                fixed = [f for f in ctx.findings if f.finding_id in fix.finding_ids]
                rescannable = [f for f in fixed if f.scanner.lower() not in imported]
                resolved = [f for f in rescannable if f.fingerprint() not in remaining]
                fix.verified = bool(rescannable) and len(resolved) == len(rescannable) if rescannable else None
                if fixed and rescannable and len(resolved) != len(rescannable):
                    fix.detail = (f"{len(resolved)}/{len(rescannable)} findings resolved. " + fix.detail)[:2000]
                for f in fixed:
                    if f in resolved:
                        f.fix_status = "verified"
                        verified += 1
                    elif f in rescannable:
                        f.fix_status = "manual"
                        f.fix_note = ("Still reported after the automated change (" + fix.summary[:120] +
                                      "); a larger upgrade or a code change is required.")
                status = "passed" if fix.verified else ("skipped" if fix.verified is None else "failed")
                checks.append(ValidationCheck(name="Security rescan", category="security-rescan", status=status,
                                              fix_index=idx,
                                              detail=(f"{len(resolved)}/{len(rescannable)} targeted finding(s) no "
                                                      "longer reported") if rescannable else
                                              "Imported scanner results cannot be re-run on this worker"))
            # A dependency advisory that was already reported (against the old version) is not "new"
            # just because the version changed; it is an advisory without a usable fix.
            before_issues = {issue_key(f) for f in ctx.findings}
            introduced = [f for f in after if f.fingerprint() not in before and issue_key(f) not in before_issues]
            severe = [f for f in introduced if f.severity in ("critical", "high")]
            if introduced:
                checks.append(ValidationCheck(
                    name="No new vulnerabilities introduced", category="security-rescan",
                    status="failed" if severe else "warning",
                    detail=f"{len(introduced)} new finding(s) after the fixes ({len(severe)} high/critical), e.g. "
                           f"{introduced[0].title[:90]} in {introduced[0].file_path}"))
                rep.notes.append(f"Rescan reports {len(introduced)} finding(s) not present before the fixes; review them.")
            else:
                checks.append(ValidationCheck(name="No new vulnerabilities introduced", category="security-rescan",
                                              status="passed", detail="Rescan found no new issues"))
            ctx.step(self.stage_id, "Security rescan", "failed" if severe else ("warning" if introduced else "completed"),
                     f"{verified} finding(s) confirmed resolved, {len(introduced)} new")
        rep.verified_fixed = verified

        # verdicts
        for idx, fix in enumerate(rep.fixes):
            mine = [c for c in checks if c.fix_index == idx]
            if fix.status != "applied" or any(c.status == "failed" for c in mine) or fix.verified is False:
                fix.validation_status = "flagged"
            else:
                fix.validation_status = "passed"
        rep.validation_checks = checks
        global_fail = any(c.status == "failed" and c.fix_index is None for c in checks)
        any_flagged = any(f.validation_status == "flagged" for f in rep.fixes)
        rep.validation_status = "flagged" if (global_fail or any_flagged) else ("passed" if applied else "not_run")
        failed = sum(c.status == "failed" for c in checks)
        ctx.finish_stage(self.stage_id, "warning" if rep.validation_status == "flagged" else "completed",
                         ("FLAGGED for investigation" if rep.validation_status == "flagged" else "All checks passed") +
                         f" · {sum(c.status == 'passed' for c in checks)} passed, {failed} failed, "
                         f"{sum(c.status == 'warning' for c in checks)} warnings",
                         verified=verified, checks=len(checks), failed_checks=failed,
                         verdict=rep.validation_status)


__all__ = ["ValidationAgent", "diff_guard", "FixRecord"]
