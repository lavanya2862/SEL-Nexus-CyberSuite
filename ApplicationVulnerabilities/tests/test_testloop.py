"""The Test & Fix loop (remediation/testloop.py) with a fake GitHub and a fake AI: nothing leaves this computer."""
import json
import shutil

import pytest
import yaml
from fastapi.testclient import TestClient

from remediation import config, jobqueue, testloop
from remediation.models import JobOptions
from tests.conftest import make_git_repo

APP = {
    "requirements.txt": "",
    "app/calc.py": "def add(a, b):\n    return a - b\n",
    "tests/test_calc.py": "from app.calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n",
}

FAILED_LOG = """2026-10-19T08:00:01.0000000Z ============================= FAILURES =============================
2026-10-19T08:00:01.0000000Z ___________________________ test_add ___________________________
2026-10-19T08:00:01.0000000Z     def test_add():
2026-10-19T08:00:01.0000000Z >       assert add(2, 3) == 5
2026-10-19T08:00:01.0000000Z E       assert -1 == 5
2026-10-19T08:00:01.0000000Z /home/runner/work/demo/demo/tests/test_calc.py:5: AssertionError
2026-10-19T08:00:01.0000000Z   File "/home/runner/work/demo/demo/app/calc.py", line 2, in add
2026-10-19T08:00:01.0000000Z =========================== short test summary info ===========================
2026-10-19T08:00:01.0000000Z FAILED tests/test_calc.py::test_add - assert -1 == 5
"""

GOOD_FIX = {"explanation": "add() subtracted instead of adding.",
            "edits": [{"file": "app/calc.py", "search": "return a - b", "replace": "return a + b"}]}
SKIP_FIX = {"explanation": "Skip the failing test.",
            "edits": [{"file": "tests/test_calc.py", "search": "def test_add():",
                       "replace": "import pytest\n\n\n@pytest.mark.skip\ndef test_add():"}]}


# --- what to run ---------------------------------------------------------------------------------------------

def test_python_repo_gets_pytest_and_a_valid_workflow(tmp_path):
    repo = make_git_repo(tmp_path / "r", APP)
    setup = testloop.find_test_setup(repo)
    assert setup["language"] == "python" and "pytest" in setup["test"] and "requirements.txt" in setup["install"]
    wf = yaml.safe_load(testloop.workflow_yaml(setup, "ai-remediation/abc"))
    assert wf[True]["push"]["branches"] == ["ai-remediation/abc"]  # YAML reads the key `on` as True
    steps = wf["jobs"]["tests"]["steps"]
    assert steps[-1]["run"] == setup["test"] and any("setup-python" in s.get("uses", "") for s in steps)


def test_node_repo_uses_npm_test_and_repos_without_tests_are_skipped(tmp_path):
    node = make_git_repo(tmp_path / "n", {"package.json": json.dumps({"scripts": {"test": "jest"}}), "a.js": "1\n"})
    assert testloop.find_test_setup(node) == {"language": "node", "install": "npm install", "test": "npm test"}
    plain = make_git_repo(tmp_path / "p", {"requirements.txt": "", "app.py": "print(1)\n"})
    assert testloop.find_test_setup(plain) is None


# --- reading a failed run ------------------------------------------------------------------------------------

def test_failure_log_is_cleaned_and_read(tmp_path):
    repo = make_git_repo(tmp_path / "r", APP)
    log = testloop.clean_log(FAILED_LOG)
    assert "/home/runner" not in log and not log.startswith("2026")
    assert testloop.failed_tests(log) == ["tests/test_calc.py::test_add"]
    assert testloop.failure_excerpt(log).lstrip().startswith("====")
    assert set(testloop.referenced_files(repo, log)) == {"tests/test_calc.py", "app/calc.py"}


# --- the AI fix ----------------------------------------------------------------------------------------------

def _llm(monkeypatch, replies):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "gpt-test")
    config.reset_settings_cache()
    queue = list(replies)
    monkeypatch.setattr(testloop, "chat", lambda system, messages: json.dumps(queue.pop(0) if queue else GOOD_FIX))


def test_ai_fix_changes_the_code(tmp_path, monkeypatch):
    repo = make_git_repo(tmp_path / "r", APP)
    _llm(monkeypatch, [GOOD_FIX])
    out = testloop.ai_fix(repo, {"test": "python -m pytest"}, testloop.clean_log(FAILED_LOG), [])
    assert out["ok"] and out["files"] == ["app/calc.py"] and not out["touched_tests"]
    assert "return a + b" in (repo / "app/calc.py").read_text()


def test_ai_fix_that_skips_a_test_is_rejected(tmp_path, monkeypatch):
    repo = make_git_repo(tmp_path / "r", APP)
    _llm(monkeypatch, [SKIP_FIX] * 3)  # every try skips the test
    out = testloop.ai_fix(repo, {"test": "python -m pytest"}, testloop.clean_log(FAILED_LOG), [])
    assert not out["ok"] and "skips tests" in out["error"]
    assert "pytest.mark.skip" not in (repo / "tests/test_calc.py").read_text()  # the edit was undone


# --- the whole loop, with a fake GitHub ---------------------------------------------------------------------

class FakeGitHub:
    """GitHub Actions stand-in: each push gets a run whose result comes from ``results`` in order."""
    results: list[str] = []
    runs: dict[int, dict] = {}

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def find_workflow_run(self, repo, path, branch, sha, exclude=frozenset()):
        assert path == testloop.WORKFLOW_PATH
        run_id = len(FakeGitHub.runs) + 1
        FakeGitHub.runs[run_id] = {"id": run_id, "status": "completed", "conclusion": FakeGitHub.results.pop(0),
                                   "html_url": f"https://github.com/o/r/actions/runs/{run_id}", "head_sha": sha}
        return FakeGitHub.runs[run_id]

    def get_workflow_run(self, repo, run_id):
        return FakeGitHub.runs[run_id]

    def workflow_run_logs(self, repo, run_id):
        return FAILED_LOG


@pytest.fixture
def loop(tmp_path, monkeypatch):
    """Runs the loop on a local copy of APP; returns (run, pushes, summary)."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.setenv("TEST_POLL_SECONDS", "0")
    config.reset_settings_cache()
    source = make_git_repo(tmp_path / "source", APP)
    pushes, saved = [], {}

    def prepare(repo, job, report, mbox, workdir, branch, st):
        shutil.copytree(source, workdir)
        testloop.create_branch(workdir, branch)

    monkeypatch.setattr(testloop, "_prepare", prepare)
    monkeypatch.setattr(testloop, "_start_run", lambda repo, workdir, branch, sha, st: (pushes.append(sha), set())[1])
    monkeypatch.setattr(testloop, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(testloop, "_load", lambda job_id: (
        {"id": job_id, "repo_url": "https://github.com/o/r", "commit": "abc", "status": "completed", "summary": {}},
        {"branch": "ai-remediation/r-1", "base_commit": "abc"}, ""))
    monkeypatch.setattr(testloop.jobqueue, "update_summary", lambda job_id, **c: saved.update(c))
    monkeypatch.setattr(testloop.jobqueue, "add_event", lambda *a, **k: None)
    FakeGitHub.runs = {}

    def run(results):
        FakeGitHub.results = list(results)
        st = testloop._State("job1")
        testloop.run_loop("job1", st)
        return st.data
    return run, pushes, saved


def test_failing_tests_are_fixed_by_ai_and_run_again(loop, monkeypatch):
    run, pushes, saved = loop
    _llm(monkeypatch, [GOOD_FIX])
    data = run(["failure", "success"])
    assert data["status"] == "passed" and data["attempt"] == 1 and len(data["runs"]) == 2
    assert data["runs"][0]["failed"] == ["tests/test_calc.py::test_add"]
    assert data["runs"][0]["fix"]["files"] == ["app/calc.py"] and data["runs"][1]["conclusion"] == "success"
    assert len(pushes) == 2 and pushes[0] != pushes[1]  # the fix was committed and pushed, which re-ran the tests
    assert data["branch_pushed"] and data["test_command"].startswith("python -m pytest")
    assert saved["tests"] is data


def test_it_stops_after_three_ai_fixes(loop, monkeypatch):
    run, pushes, _ = loop
    _llm(monkeypatch, [GOOD_FIX, GOOD_FIX, GOOD_FIX])

    attempts = iter(["return a + b", "return b + a", "return (a + b)"])

    def fix(root, setup, log_text, history):  # each attempt changes the code but the tests keep failing
        target = root / "app/calc.py"
        target.write_text(f"def add(a, b):\n    {next(attempts)}\n")
        return {"ok": True, "files": ["app/calc.py"], "explanation": f"attempt {len(history) + 1}", "touched_tests": False}

    monkeypatch.setattr(testloop, "ai_fix", fix)
    data = run(["failure"] * 4)
    assert data["status"] == "failed" and data["attempt"] == 3 and len(data["runs"]) == 4 and len(pushes) == 4
    assert "after 3 AI fix" in data["message"]


def test_without_an_ai_model_failures_go_to_a_person(loop):
    run, pushes, _ = loop
    data = run(["failure"])
    assert data["status"] == "failed" and "Connect an AI model" in data["message"] and len(pushes) == 1


# --- the API -------------------------------------------------------------------------------------------------

def test_only_completed_runs_can_be_tested():
    from remediation.api import app
    job, _ = jobqueue.enqueue("https://github.com/a/b", "a/b", JobOptions())
    with TestClient(app) as client:
        assert client.post(f"/api/v1/jobs/{job.id}/tests").status_code == 409
        assert client.post(f"/api/v1/jobs/{job.id}/tests/cancel").json() == {"status": "idle"}


def test_github_tests_option_does_not_change_the_cache_key():
    assert JobOptions(github_tests=True).cache_key_material() == JobOptions().cache_key_material()


# --- the code under test reaches the AI even when the failure log never names it -----------------------------

def test_the_ai_sees_the_code_the_failing_tests_import(tmp_path):
    files = {"app/__init__.py": "", "app/routes/__init__.py": "",
             "app/routes/utilities.py": "def ping(host):\n    return host\n",
             "app/big.py": "x = 1\n" * 15000,  # makes the repository too big to show whole
             "tests/test_security.py": "from app.routes import utilities\n\n\ndef test_ping():\n    assert utilities.ping('a;b') is None\n"}
    repo = make_git_repo(tmp_path / "r", files)
    log = "FAILED tests/test_security.py::test_ping - assert 'a;b' is None\ntests/test_security.py:5: AssertionError\n"
    chosen = testloop.files_for_fix(repo, log)
    assert chosen[0] == "tests/test_security.py" and "app/routes/utilities.py" in chosen and "app/big.py" not in chosen


def test_small_repositories_are_shown_whole(tmp_path):
    repo = make_git_repo(tmp_path / "r", APP)
    assert set(testloop.files_for_fix(repo, testloop.clean_log(FAILED_LOG))) >= {"app/calc.py", "tests/test_calc.py", "requirements.txt"} - {"requirements.txt"}


def test_a_misquoted_file_is_shown_to_the_ai_and_retried(tmp_path, monkeypatch):
    repo = make_git_repo(tmp_path / "r", APP)
    wrong = {"explanation": "guess", "edits": [{"file": "app/calc.py", "search": "return a-b  # guessed", "replace": "return a + b"}]}
    prompts = []
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "gpt-test")
    config.reset_settings_cache()
    replies = [wrong, GOOD_FIX]
    monkeypatch.setattr(testloop, "chat", lambda system, messages: (prompts.append(messages[-1]["content"]), json.dumps(replies.pop(0)))[1])
    out = testloop.ai_fix(repo, {"test": "python -m pytest"}, testloop.clean_log(FAILED_LOG), [])
    assert out["ok"] and "Here is app/calc.py exactly as it is now" in prompts[1] and "return a - b" in prompts[1]


def test_partial_edits_are_kept_on_the_last_try(tmp_path, monkeypatch):
    repo = make_git_repo(tmp_path / "r", APP)
    mixed = {"explanation": "fix add; also bump a dependency",
             "edits": [{"file": "app/calc.py", "search": "return a - b", "replace": "return a + b"},
                       {"file": "requirements.txt", "search": "idna==3.6", "replace": "idna==3.7"}]}
    _llm(monkeypatch, [mixed] * 3)
    out = testloop.ai_fix(repo, {"test": "python -m pytest"}, testloop.clean_log(FAILED_LOG), [])
    assert out["ok"] and out["files"] == ["app/calc.py"] and "left out: requirements.txt" in out["explanation"]


def test_run_again_with_nothing_new_starts_the_workflow_directly(monkeypatch):
    calls = []

    class GH(FakeGitHub):
        def workflow_runs(self, repo, path, branch, sha):
            return [{"id": 7}]

        def dispatch_workflow(self, repo, path, branch):
            calls.append(("dispatch", branch))

    monkeypatch.setattr(testloop, "GitHubClient", GH)
    monkeypatch.setattr(testloop, "resolve_remote_ref", lambda repo, branch: "abc")
    monkeypatch.setattr(testloop, "_push", lambda *a: calls.append("push"))
    st = type("St", (), {"log": lambda self, m, level="info": None})()
    assert testloop._start_run(None, None, "b", "abc", st) == {7} and calls == [("dispatch", "b")]
    calls.clear()
    assert testloop._start_run(None, None, "b", "new-sha", st) == set() and calls == ["push"]
