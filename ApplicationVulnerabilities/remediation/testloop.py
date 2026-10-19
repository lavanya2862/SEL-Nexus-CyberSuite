"""Test & Fix loop: the repository's own tests on GitHub Actions, with the AI fixing failures until they pass.

When someone presses "Run tests on GitHub" for a completed run (or ticked that option on New scan):
  1. Prepare the run's fix branch: the branch already on GitHub (an earlier loop or an opened pull request), otherwise
     a fresh clone of the scanned commit with the run's fix commits (fixes.mbox) replayed on it.
  2. Add .github/workflows/sel-nexus-tests.yml (made for the repository's language and test command) and push the
     branch. The push starts the workflow on GitHub Actions, which runs every test in the repository.
  3. Wait for the run. Passed: done. Failed: the AI reads the failure log and the files it points at, and changes the
     code (or a test that is itself wrong). The change must still parse and must not skip or delete tests or add other
     security regressions (the Validation Agent's diff guard); it is committed and pushed, which starts the workflow
     again.
  4. After TEST_FIX_ATTEMPTS fixes that still fail, it stops and a person takes over (listed under Errors).
Nothing is merged: the branch becomes the pull request when someone approves the run.
Progress lives in the job summary under "tests", so the website follows it live.
"""
from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from . import jobqueue
from .agents.validation import TEST_PATH, diff_guard
from .config import get_settings
from .context import resolve_in_repo
from .db import Job, JobArtifact, session_scope
from .detect import detect_project, iter_files
from .edits import EditError, apply_edits, parse_edits
from .github import (GitHubClient, RepoAccessError, RepoRef, _auth_config, _redact, clone_repo, parse_repo_url,
                     resolve_remote_ref)
from .gitops import apply_mbox, commit_all, create_branch, discard_changes, git, head_sha, remove_tree
from .llm import LLMError, chat, extract_json
from .scanners.builtin_secrets import redact
from .validate import static_check

log = logging.getLogger(__name__)

WORKFLOW_PATH = ".github/workflows/sel-nexus-tests.yml"
ACTIVE = ("starting", "running")


class Cancelled(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- 1. What to run: the repository's test setup and the workflow that runs it -------------------------------

_SETUP_STEP = {
    "python": "      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n",
    "node": "      - uses: actions/setup-node@v4\n        with:\n          node-version: '20'\n",
    "go": "      - uses: actions/setup-go@v5\n        with:\n          go-version-file: go.mod\n",
    "java": "      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: '21'\n",
    "gradle": ("      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: '21'\n"
               "      - uses: gradle/actions/setup-gradle@v4\n"),
    "ruby": "      - uses: ruby/setup-ruby@v1\n        with:\n          ruby-version: '3.3'\n          bundler-cache: true\n",
    "rust": "",
}


def find_test_setup(root: Path) -> dict | None:
    """The language, install and test commands for the repository's tests, or None when it has no tests."""
    info = detect_project(root)
    top = {p.name for p in root.iterdir()}
    command = info.test_command
    if not command and (info.primary_language == "python" or {"pyproject.toml", "setup.py", "requirements.txt"} & top):
        # pytest also finds test_*.py / *_test.py outside a tests/ folder
        if any(p.suffix == ".py" and (p.name.startswith("test_") or p.name.endswith("_test.py")) for p in iter_files(root)):
            command = "python -m pytest"
    if not command:
        return None
    if "pytest" in command:
        installs = ["python -m pip install --upgrade pip"]
        if "requirements.txt" in top:
            installs.append("pip install -r requirements.txt")
        elif "pyproject.toml" in top or "setup.py" in top:
            installs.append("pip install -e .")
        installs.append("pip install pytest")
        return {"language": "python", "install": " && ".join(installs), "test": "python -m pytest -rA --tb=short"}
    if command.startswith("npm"):
        return {"language": "node", "install": "npm ci" if "package-lock.json" in top else "npm install", "test": "npm test"}
    if command.startswith("go "):
        return {"language": "go", "install": "go mod download", "test": "go test ./..."}
    if command.startswith("cargo"):
        return {"language": "rust", "install": "cargo fetch", "test": "cargo test"}
    if command.startswith("mvn"):
        return {"language": "java", "install": "", "test": "mvn -B test"}
    if command.startswith("gradle"):
        return {"language": "gradle", "install": "", "test": "./gradlew test" if "gradlew" in top else "gradle test"}
    if command.startswith("bundle"):
        return {"language": "ruby", "install": "", "test": "bundle exec rake test"}
    return None


def workflow_yaml(setup: dict, branch: str) -> str:
    """The GitHub Actions workflow that runs the tests on every push to the fix branch."""
    install = (f"      - name: Install dependencies\n        run: {setup['install']}\n") if setup.get("install") else ""
    return (
        "# Added by SEL Nexus CyberSuite (Application Vulnerabilities): runs this repository's tests on the AI fix\n"
        "# branch. When a test fails, the suite's AI fixes it and pushes again, which runs this workflow again.\n"
        "name: SEL Nexus tests\n"
        "on:\n"
        "  push:\n"
        f"    branches: ['{branch}']\n"
        "  workflow_dispatch:\n"
        "permissions:\n"
        "  contents: read\n"
        "concurrency:\n"
        "  group: sel-nexus-tests-${{ github.ref }}\n"
        "  cancel-in-progress: true\n"
        "jobs:\n"
        "  tests:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 30\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        f"{_SETUP_STEP.get(setup['language'], '')}"
        f"{install}"
        "      - name: Run all tests\n"
        f"        run: {setup['test']}\n"
    )


# --- 2. Reading a failed run ------------------------------------------------------------------------------------

_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z ?", re.M)
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_RUNNER_PREFIX = re.compile(r"/home/runner/work/[^/\s]+/[^/\s]+/")
_FAILED_PATTERNS = [
    re.compile(r"^(?:FAILED|ERROR) (\S+)", re.M),                 # pytest -rA
    re.compile(r"^\s*--- FAIL: (\S+)", re.M),                     # go test
    re.compile(r"^\s*[✕×] (.+?)(?: \(\d+ ?ms\))?$", re.M),        # jest / vitest
    re.compile(r"^\s*● (.+ › .+)$", re.M),                        # jest summary
    re.compile(r"^\[ERROR\]\s+(\w[\w.$]*[.:]\w+)", re.M),          # maven surefire
    re.compile(r"^test (\S+) \.\.\. FAILED$", re.M),               # cargo test
]
_FILE_REFS = [
    re.compile(r'File "([^"]+)", line (\d+)'),
    re.compile(r"((?:[\w.-]+/)*[\w.-]+\.(?:py|js|jsx|ts|tsx|mjs|cjs|go|java|kt|rb|rs|php|cs)):(\d+)"),
]


def clean_log(text: str) -> str:
    return _RUNNER_PREFIX.sub("", _ANSI.sub("", _TIMESTAMP.sub("", text)))


def failed_tests(log_text: str, limit: int = 40) -> list[str]:
    names: list[str] = []
    for pattern in _FAILED_PATTERNS:
        for m in pattern.finditer(log_text):
            name = m.group(1).strip()
            if name and name not in names:
                names.append(name)
    return names[:limit]


def failure_excerpt(log_text: str, limit: int = 14000) -> str:
    """The part of the log that explains the failure (pytest's FAILURES section when there is one)."""
    for marker in ("= FAILURES =", "= ERRORS ="):
        idx = log_text.find(marker)
        if idx != -1:
            start = log_text.rfind("\n", 0, idx) + 1
            return log_text[start:start + limit]
    return log_text[-limit:]


def referenced_files(root: Path, log_text: str, limit: int = 6) -> list[str]:
    """Repository files the failure points at (tracebacks, file:line), most mentioned first."""
    counts: dict[str, int] = {}
    for pattern in _FILE_REFS:
        for m in pattern.finditer(log_text):
            raw = m.group(1)
            if "site-packages" in raw or "node_modules" in raw or "hostedtoolcache" in raw or raw.startswith(("/usr/", "/opt/")):
                continue
            target = resolve_in_repo(root, raw.lstrip("/") if raw.startswith("/") else raw)
            if target:
                rel = target.relative_to(root.resolve()).as_posix()
                counts[rel] = counts.get(rel, 0) + 1
    return [f for f, _ in sorted(counts.items(), key=lambda kv: -kv[1])][:limit]


_PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import\s+([\w, ()]+)|import\s+([\w.]+))", re.M)
_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".rb", ".rs", ".php", ".cs",
                    ".html", ".vue", ".svelte", ".sql", ".toml", ".cfg", ".ini", ".json", ".yml", ".yaml"}
_LOCK_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}
_MANIFEST = re.compile(r"(^|/)(requirements[\w.-]*\.txt|Pipfile|go\.mod|pom\.xml|Gemfile|Cargo\.toml|build\.gradle(\.kts)?)$")


def _imported_files(root: Path, rel: str) -> list[str]:
    """Repository modules a Python file imports (``from app.routes import utilities`` -> app/routes/utilities.py)."""
    if not rel.endswith(".py"):
        return []
    try:
        text = (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    found: list[str] = []
    for m in _PY_IMPORT.finditer(text):
        module = (m.group(1) or m.group(3)).replace(".", "/")
        names = [n.strip().split(" ")[0] for n in (m.group(2) or "").replace("(", "").replace(")", "").split(",") if n.strip()]
        for base in [module, *(f"{module}/{n}" for n in names)]:
            for cand in (f"{base}.py", f"{base}/__init__.py"):
                if (root / cand).is_file() and cand not in found:
                    found.append(cand)
    return found


def files_for_fix(root: Path, log_text: str, budget: int = 60000) -> list[str]:
    """The files the AI sees: the whole source when the repository is small, otherwise the files the failure points at
    plus what they import (the code under test rarely appears in the failure log itself). Referenced files come first."""
    sources = []
    for p in iter_files(root, max_files=2000, max_bytes=200_000):
        rel = p.relative_to(root).as_posix()
        if ((p.suffix.lower() in _SOURCE_SUFFIXES or _MANIFEST.search(rel)) and p.name not in _LOCK_FILES
                and not rel.startswith((".github/", ".git/"))):
            sources.append(rel)
    referenced = referenced_files(root, log_text)
    total = sum((root / rel).stat().st_size for rel in sources)
    if total <= budget:
        return referenced + [s for s in sorted(sources) if s not in referenced]
    chosen = list(referenced)
    for rel in referenced:
        chosen += [imp for imp in _imported_files(root, rel) if imp not in chosen]
    return chosen


# --- 3. The AI fix -------------------------------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a senior engineer fixing failing automated tests in a software repository.
Find the root cause from the test output and change the code so the tests pass. Fix the application code when it is
wrong. Change a test only when the test itself is clearly wrong (for example it checks outdated behaviour), and say so
in the explanation.
Never skip, disable, delete or weaken a test, never remove assertions, never edit CI workflow files, and never add
security problems (no disabled TLS checks, hard-coded secrets, eval/exec, shell=True, debug mode).
Reply with ONE JSON object only:
{"explanation": "<what was wrong and what you changed, 1-3 sentences>",
 "edits": [{"file": "<path relative to the repository root>", "search": "<exact text copied from the file>",
            "replace": "<the new text>"}]}
"search" must be copied verbatim from the file contents you are given and match exactly once. Keep edits minimal.
If the failure cannot be fixed in the repository (missing service, network, secrets, broken CI infrastructure), reply
{"status": "cannot_fix", "explanation": "<why>"}."""


def _fix_prompt(root: Path, setup: dict, log_text: str, history: list[str]) -> str:
    failing = failed_tests(log_text)
    files = files_for_fix(root, log_text)
    parts = [f"Test command: {setup['test']}",
             "Failing tests:\n" + ("\n".join(f"- {t}" for t in failing) if failing else "- (see the output)"),
             f"Test output (trimmed):\n```\n{redact(failure_excerpt(log_text))}\n```"]
    if history:
        parts.append("Earlier fix attempts that did not make the tests pass (do not repeat them):\n"
                     + "\n".join(f"- {h}" for h in history))
    budget, shown = 60000, set()
    for rel in files:
        try:
            content = (root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        content = redact(content[:12000])
        if len(content) > budget:
            continue
        budget -= len(content)
        shown.add(rel)
        parts.append(f"File {rel}:\n```\n{content}\n```")
    others = [p.relative_to(root).as_posix() for p in iter_files(root, max_files=400)
              if p.relative_to(root).as_posix() not in shown and not p.relative_to(root).as_posix().startswith(".git/")]
    parts.append("Other files in the repository (to fix one of them, edit it anyway: you will be shown its exact "
                 "contents and asked again):\n" + "\n".join(others[:200]))
    return "\n\n".join(parts)


def _show_files(root: Path, files: list[str]) -> str:
    """The exact current contents of files whose edits did not apply (the AI had not seen them, or misquoted them)."""
    out = []
    for rel in dict.fromkeys(files):
        try:
            content = (root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        out.append(f"\nHere is {rel} exactly as it is now; copy the search text from it:\n```\n{redact(content[:15000])}\n```")
    return "".join(out)


def _apply_each(root: Path, edits: list) -> tuple[list[str], list[tuple[str, str]]]:
    """Apply edits one by one: (changed files, [(file, why it did not apply)]). One misquoted edit no longer sinks the
    others, which matters with smaller models that bundle several edits."""
    files: list[str] = []
    failed: list[tuple[str, str]] = []
    for edit in edits:
        try:
            files += [f for f in apply_edits(root, [edit]) if f not in files]
        except EditError as exc:
            failed.append((edit.file, str(exc)))
    return files, failed


def ai_fix(root: Path, setup: dict, log_text: str, history: list[str], tries: int = 3) -> dict:
    """Ask the AI for a fix and apply it to the working tree (not committed). Returns
    {"ok", "files", "explanation", "touched_tests", "error"}. If some edits keep failing to apply, the last try keeps
    the ones that did (the next test run shows what is still failing)."""
    messages = [{"role": "user", "content": _fix_prompt(root, setup, log_text, history)}]
    error = ""
    for attempt in range(1, tries + 1):
        reply = chat(SYSTEM_PROMPT, messages)
        data = extract_json(reply)
        failed: list[tuple[str, str]] = []
        try:
            if data is None:
                raise EditError("The reply was not the requested JSON object.")
            if str(data.get("status", "")).lower() == "cannot_fix":
                return {"ok": False, "error": f"The AI says this cannot be fixed in the code: {str(data.get('explanation', ''))[:400]}"}
            files, failed = _apply_each(root, parse_edits(data))
            if not files:
                raise EditError("; ".join(msg for _, msg in failed) or "The reply contained no edits.")
            if failed and attempt < tries:
                raise EditError("Some edits did not apply: " + "; ".join(msg for _, msg in failed))
            ok, problem = static_check(root, files)
            if not ok:
                raise EditError(f"The edit breaks the code: {problem}")
            problems = diff_guard(git(["diff"], root).stdout)
            if problems:
                raise EditError("The edit was rejected by the security-regression guard: " + "; ".join(problems))
            explanation = str(data.get("explanation", ""))[:1000]
            if failed:
                explanation += f" ({len(failed)} edit(s) could not be applied and were left out: " \
                               f"{', '.join(dict.fromkeys(f for f, _ in failed))}.)"
            return {"ok": True, "files": files, "explanation": explanation,
                    "touched_tests": any(TEST_PATH.search(f) for f in files)}
        except (EditError, OSError, UnicodeDecodeError) as exc:
            discard_changes(root)
            error = str(exc)
            messages += [{"role": "assistant", "content": reply[:8000]},
                         {"role": "user", "content": f"That could not be used: {error}{_show_files(root, [f for f, _ in failed])}\n"
                                                     "Return the corrected JSON object with ALL edits only."}]
    return {"ok": False, "error": error}


# --- 4. The loop ---------------------------------------------------------------------------------------------------

_running: set[str] = set()
_cancel: set[str] = set()
_lock = threading.Lock()


def is_running(job_id: str) -> bool:
    with _lock:
        return job_id in _running


def start(job_id: str) -> bool:
    """Start the loop for a completed run in the background. False when it is already running."""
    with _lock:
        if job_id in _running:
            return False
        _running.add(job_id)
        _cancel.discard(job_id)
    jobqueue.update_summary(job_id, tests={"status": "starting", "phase": "Starting", "runs": [], "attempt": 0,
                                           "max_attempts": get_settings().test_fix_attempts, "started_at": _now()})
    threading.Thread(target=_run, args=(job_id,), name=f"tests-{job_id[:8]}", daemon=True).start()
    return True


def cancel(job_id: str) -> None:
    with _lock:
        if job_id in _running:
            _cancel.add(job_id)


class _State:
    def __init__(self, job_id: str):
        self.job_id = job_id
        self.data: dict = {"status": "starting", "runs": [], "attempt": 0, "max_attempts": get_settings().test_fix_attempts,
                           "started_at": _now(), "finished_at": None, "message": "", "phase": "Starting"}

    def update(self, **changes) -> None:
        self.data.update(changes)
        jobqueue.update_summary(self.job_id, tests=self.data)

    def log(self, message: str, level: str = "info") -> None:
        jobqueue.add_event(self.job_id, f"Tests: {message}", level)

    def finish(self, status: str, message: str) -> None:
        self.update(status=status, message=message, phase="", finished_at=_now())
        self.log(message, "info" if status == "passed" else "warning")

    def check_cancel(self) -> None:
        with _lock:
            if self.job_id in _cancel:
                raise Cancelled()


def _load(job_id: str) -> tuple[dict, dict, str]:
    import json
    with session_scope() as db:
        job = db.get(Job, job_id)
        if job is None:
            raise RepoAccessError("Run not found.")
        info = {"id": job.id, "repo_url": job.repo_url, "commit": job.commit_sha, "status": job.status,
                "summary": job.summary or {}}
        arts = {a.name: a.content for a in db.scalars(select(JobArtifact).where(
            JobArtifact.job_id == job_id, JobArtifact.name.in_(["report.json", "fixes.mbox"])))}
    report = json.loads(arts["report.json"]) if arts.get("report.json") else {}
    return info, report, arts.get("fixes.mbox") or ""


def _push(repo: RepoRef, workdir: Path, branch: str) -> None:
    token = get_settings().github_token
    res = git(["push", "-q", "origin", f"HEAD:refs/heads/{branch}"], workdir, timeout=300, extra_config=_auth_config(token))
    if not res.ok:
        msg = _redact(res.stderr.strip(), token)
        if "workflow" in msg.lower():
            msg += ("\nThe GitHub token needs permission to change workflows (fine-grained token: Workflows read & "
                    "write; classic token: the workflow scope) to add the test workflow.")
        raise RepoAccessError(f"Push to {branch} failed: {msg[-1200:]}")


def _start_run(repo: RepoRef, workdir: Path, branch: str, sha: str, st: _State) -> set[int]:
    """Push the branch, which starts the workflow. When GitHub already has this exact commit ("Run again" with nothing
    new), a push would start nothing, so the workflow is started directly. Returns the runs to ignore (older runs of
    the same commit)."""
    if resolve_remote_ref(repo, branch) != sha:
        _push(repo, workdir, branch)
        return set()
    with GitHubClient() as gh:
        seen = {r["id"] for r in gh.workflow_runs(repo, WORKFLOW_PATH, branch, sha)}
        gh.dispatch_workflow(repo, WORKFLOW_PATH, branch)
    st.log("nothing new to push, so GitHub Actions was asked to run the tests again")
    return seen


def _wait_for_run(repo: RepoRef, branch: str, sha: str, st: _State, entry: dict, exclude: set[int]) -> dict:
    s = get_settings()
    with GitHubClient() as gh:
        run = None
        deadline = time.monotonic() + 180
        while run is None:
            st.check_cancel()
            run = gh.find_workflow_run(repo, WORKFLOW_PATH, branch, sha, exclude)
            if run is None:
                if time.monotonic() > deadline:
                    raise RepoAccessError("GitHub did not start the test workflow within 3 minutes. Check that GitHub "
                                          "Actions is enabled for the repository (Settings > Actions).")
                time.sleep(s.test_poll_seconds)
        entry.update(run_id=run["id"], url=run.get("html_url"), status=run.get("status"), started_at=run.get("created_at"))
        st.update(phase=f"Tests running on GitHub Actions (run {len(st.data['runs'])})")
        deadline = time.monotonic() + s.test_run_timeout_minutes * 60
        while run.get("status") != "completed":
            st.check_cancel()
            if time.monotonic() > deadline:
                raise RepoAccessError(f"The test run did not finish within {s.test_run_timeout_minutes} minutes.")
            time.sleep(s.test_poll_seconds)
            run = gh.get_workflow_run(repo, run["id"])
            if run.get("status") != entry.get("status"):
                entry["status"] = run.get("status")
                st.update()
        entry.update(status="completed", conclusion=run.get("conclusion"), finished_at=run.get("updated_at"))
        st.update()
        return run


def _prepare(repo: RepoRef, job: dict, report: dict, mbox: str, workdir: Path, branch: str, st: _State) -> None:
    if resolve_remote_ref(repo, branch):
        clone_repo(repo, workdir, branch)
        create_branch(workdir, branch)
        st.log(f"continuing on {branch}, which is already on GitHub")
        return
    base = report.get("base_commit") or job.get("commit")
    if not base:
        raise RepoAccessError("The run did not record the scanned commit; run the scan again.")
    clone_repo(repo, workdir, base)
    create_branch(workdir, branch)
    if mbox.strip():
        ok, message = apply_mbox(workdir, mbox)
        if not ok:
            raise RepoAccessError(f"Could not replay the run's fix commits: {message[-500:]}")
        st.log(f"rebuilt {branch} from the run's fix commits")


def run_loop(job_id: str, st: _State) -> None:
    s = get_settings()
    job, report, mbox = _load(job_id)
    if job["status"] != "completed":
        raise RepoAccessError("Only completed runs can be tested.")
    if not s.github_token:
        raise RepoAccessError("Add a GitHub token in Settings: it pushes the fix branch so GitHub Actions can test it.")
    repo = parse_repo_url(job["repo_url"])
    branch = report.get("branch") or (job["summary"] or {}).get("branch") or f"ai-remediation/tests-{job_id[:8]}"
    st.update(status="running", phase="Preparing the fix branch", branch=branch, workflow=WORKFLOW_PATH)
    workdir = s.workspaces_dir / f"tests-{job_id[:10]}-{uuid.uuid4().hex[:6]}"
    try:
        _prepare(repo, job, report, mbox, workdir, branch, st)
        setup = find_test_setup(workdir)
        if not setup:
            st.finish("no_tests", "No test cases were found in this repository, so there is nothing to run.")
            return
        st.update(test_command=setup["test"], language=setup["language"])
        wf = workdir / WORKFLOW_PATH
        content = workflow_yaml(setup, branch)
        if not wf.is_file() or wf.read_text(encoding="utf-8") != content:
            wf.parent.mkdir(parents=True, exist_ok=True)
            wf.write_text(content, encoding="utf-8")
            commit_all(workdir, "ci: run the repository's tests on GitHub Actions (SEL Nexus CyberSuite)", [WORKFLOW_PATH])
            st.log(f"added the test workflow {WORKFLOW_PATH} ({setup['test']})")
        history: list[str] = []
        attempt = 0
        while True:
            st.check_cancel()
            sha = head_sha(workdir)
            st.update(phase=f"Pushing {branch} to GitHub")
            seen = _start_run(repo, workdir, branch, sha, st)
            st.update(branch_pushed=True)
            entry = {"n": len(st.data["runs"]) + 1, "sha": sha, "status": "queued", "conclusion": None, "failed": [],
                     "fix": None}
            st.data["runs"].append(entry)
            st.update(phase="Waiting for GitHub Actions to start the tests")
            run = _wait_for_run(repo, branch, sha, st, entry, seen)
            conclusion = run.get("conclusion")
            if conclusion == "success":
                st.finish("passed", "All tests passed on GitHub Actions" + (f" after {attempt} AI fix(es)." if attempt else "."))
                return
            if conclusion != "failure":
                st.finish("error", f"The test run ended as '{conclusion}'. Open it on GitHub to see why.")
                return
            with GitHubClient() as gh:
                log_text = clean_log(gh.workflow_run_logs(repo, run["id"]))
            entry["failed"] = failed_tests(log_text)
            st.update()
            st.log(f"run {entry['n']} failed ({len(entry['failed']) or 'some'} test(s))", "warning")
            if attempt >= s.test_fix_attempts:
                st.finish("failed", f"Tests still fail after {attempt} AI fix(es). A person needs to look at the last run.")
                return
            if not s.llm_enabled:
                st.finish("failed", "Tests failed. Connect an AI model in Settings so it can fix them.")
                return
            st.check_cancel()
            st.update(phase=f"AI fix {attempt + 1} of {s.test_fix_attempts}: reading the failure")
            try:
                fix = ai_fix(workdir, setup, log_text, history)
            except LLMError as exc:
                fix = {"ok": False, "error": f"The AI model could not be reached: {exc}"}
            if not fix["ok"]:
                entry["fix_error"] = fix["error"]
                st.finish("failed", f"Tests failed and the AI could not fix them: {fix['error'][:300]}")
                return
            attempt += 1
            commit = commit_all(workdir, f"fix(tests): AI fix {attempt} for failing tests\n\n{fix['explanation']}")
            entry["fix"] = {"files": fix["files"], "explanation": fix["explanation"], "commit": commit,
                            "touched_tests": fix["touched_tests"]}
            history.append(fix["explanation"])
            st.update(attempt=attempt)
            st.log(f"AI fix {attempt}: {fix['explanation'][:200]} ({', '.join(fix['files'])})")
    finally:
        if not s.keep_workspaces:
            remove_tree(workdir)


def _run(job_id: str) -> None:
    st = _State(job_id)
    try:
        st.log("started: run the repository's tests on GitHub Actions and fix failures with AI")
        run_loop(job_id, st)
    except Cancelled:
        st.finish("cancelled", "Stopped on request.")
    except (RepoAccessError, RuntimeError, OSError) as exc:
        st.finish("error", str(exc)[:800])
    except Exception as exc:  # noqa: BLE001
        log.exception("test loop failed for %s", job_id)
        st.finish("error", f"Unexpected error: {exc}"[:800])
    finally:
        with _lock:
            _running.discard(job_id)
            _cancel.discard(job_id)


def recover_interrupted() -> None:
    """At start-up: loops that were running when the server stopped cannot resume; say so instead of showing them as
    running forever."""
    try:
        with session_scope() as db:
            for job in db.scalars(select(Job).order_by(Job.created_at.desc()).limit(500)):
                tests = (job.summary or {}).get("tests") or {}
                if tests.get("status") in ACTIVE and not is_running(job.id):
                    job.summary = {**job.summary, "tests": {**tests, "status": "interrupted", "phase": "",
                                                            "message": "The server stopped while the tests were running. Run them again.",
                                                            "finished_at": _now()}}
    except Exception:  # noqa: BLE001 - best effort
        log.exception("could not mark interrupted test loops")
