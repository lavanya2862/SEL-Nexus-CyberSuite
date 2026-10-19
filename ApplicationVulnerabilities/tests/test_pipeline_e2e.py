"""Full pipeline run, offline: GitHub, OSV and the LLM are replaced with fakes."""
import json
import shutil

import pytest
from fastapi.testclient import TestClient

from remediation import config, jobqueue
from remediation.github import RepoMetadata
from remediation.gitops import head_sha
from remediation.models import JobOptions
from remediation.pipeline import RepositoryPipeline
from remediation.scanners.osv import OsvScanner
from remediation.worker import Worker
from tests.conftest import make_git_repo

APP = """import subprocess
import yaml


def load(raw):
    return yaml.load(raw)


def run(cmd):
    return subprocess.call(cmd, shell=True)
"""


@pytest.fixture
def fake_world(tmp_path, monkeypatch):
    origin = make_git_repo(tmp_path / "origin", {
        "requirements.txt": "pyyaml==5.3\nflask==2.3.3\n",
        "app.py": APP,
        "tests/test_app.py": "def test_ok():\n    expr = '1+1'\n    assert eval(expr) == 2\n",
    })
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "fake-model")
    monkeypatch.setenv("ENABLE_OSV", "true")
    config.reset_settings_cache()

    class FakeGitHub:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def get_repo(self, repo): return RepoMetadata(default_branch="main", size_kb=10, can_push=False)

    def fake_clone(repo, dest, ref, timeout=None):
        shutil.copytree(origin, dest)
        return head_sha(dest)

    def fake_post(self, path, payload):
        results = []
        for q in payload["queries"]:
            vulnerable = q["package"]["name"] == "pyyaml" and q["version"] == "5.3"
            results.append({"vulns": [{"id": "GHSA-fake-yaml"}]} if vulnerable else {})
        return {"results": results}

    def fake_details(self, vid):
        return {"id": vid, "summary": "PyYAML arbitrary code execution", "aliases": ["CVE-2020-14343"],
                "database_specific": {"severity": "CRITICAL"},
                "affected": [{"package": {"name": "PyYAML", "ecosystem": "PyPI"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]}

    calls = []

    def fake_chat(system, messages):
        calls.append(messages)
        if len(calls) == 1:  # first answer has a search block that does not exist -> must self-correct
            return json.dumps({"status": "fixed", "edits": [{"file": "app.py", "search": "nope", "replace": "x"}]})
        return "```json\n" + json.dumps({"status": "fixed", "explanation": "Avoid the shell.", "edits": [
            {"file": "app.py", "search": "import subprocess\n", "replace": "import shlex\nimport subprocess\n"},
            {"file": "app.py", "search": "    return subprocess.call(cmd, shell=True)",
             "replace": "    return subprocess.call(shlex.split(cmd))"}]}) + "\n```"

    monkeypatch.setattr("remediation.pipeline.GitHubClient", FakeGitHub)
    monkeypatch.setattr("remediation.pipeline.clone_repo", fake_clone)
    monkeypatch.setattr(OsvScanner, "_post", fake_post)
    monkeypatch.setattr(OsvScanner, "_vuln_details", fake_details)
    monkeypatch.setattr("remediation.fixers.chat", fake_chat)
    return calls


def test_pipeline_end_to_end(fake_world):
    result = RepositoryPipeline("https://github.com/acme/shop").run()
    report = result.report
    assert report.status == "fixed"
    methods = sorted(f.method for f in report.fixes)
    assert methods == ["dependency", "llm", "rule"]
    assert all(f.verified for f in report.fixes), report.fixes
    assert len(fake_world) == 2 and "could not be applied" in fake_world[1][-1]["content"]
    patch = result.artifacts["fixes.patch"][0]
    assert "-pyyaml==5.3\n+pyyaml==5.4" in patch
    assert "+    return yaml.safe_load(raw)" in patch
    assert "+    return subprocess.call(shlex.split(cmd))" in patch
    statuses = {f.rule_id or f.advisory_id: f.fix_status for f in result.findings}
    assert statuses["PY-EVAL"] == "skipped"  # test code is reported, not auto-patched
    sarif = json.loads(result.artifacts["findings.sarif"][0])
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert "Security remediation report" in result.artifacts["report.md"][0]
    assert not (config.get_settings().workspaces_dir / report.run_id).exists()  # workspace cleaned up


def test_scan_only_mode(fake_world):
    result = RepositoryPipeline("https://github.com/acme/shop", JobOptions(auto_fix=False)).run()
    assert result.report.status == "findings_only" and not result.report.fixes
    assert result.artifacts["fixes.patch"][0] == ""


def test_worker_processes_job_and_api_serves_results(fake_world):
    job, _ = jobqueue.enqueue("https://github.com/acme/shop", "acme/shop", JobOptions(use_cache=False))
    worker = Worker(concurrency=1, worker_id="test")
    claimed = jobqueue.claim_next("test/0")
    worker.process(claimed, "test/0")
    from remediation.api import app
    with TestClient(app) as c:
        data = c.get(f"/api/v1/jobs/{job.id}").json()
        assert data["status"] == "completed", data
        assert data["summary"]["fixes_applied"] == 3
        assert {a["name"] for a in data["artifacts"]} == {"report.json", "report.md", "findings.json",
                                                          "findings.sarif", "fixes.patch", "fixes.mbox"}
        crit = c.get(f"/api/v1/jobs/{job.id}/findings", params={"severity": "critical"}).json()
        assert crit["count"] == 1 and crit["items"][0]["package_name"] == "pyyaml"
        assert "shlex" in c.get(f"/api/v1/jobs/{job.id}/artifacts/fixes.patch").text
        stages = [e["message"] for e in c.get(f"/api/v1/jobs/{job.id}/events").json()["items"]]
        assert any("Applied llm fix" in m for m in stages)


def test_invalid_repo_fails_cleanly():
    job, _ = jobqueue.enqueue("https://github.com/acme/x", "acme/x", JobOptions(use_cache=False))
    claimed = jobqueue.claim_next("t/0")

    def boom(*a, **k):
        from remediation.github import RepoAccessError
        raise RepoAccessError("Repository acme/x was not found or is not accessible.")
    import remediation.pipeline as p
    orig = p.GitHubClient.get_repo
    p.GitHubClient.get_repo = boom
    try:
        Worker(1, "t").process(claimed, "t/0")
    finally:
        p.GitHubClient.get_repo = orig
    from remediation.db import Job, session_scope
    with session_scope() as db:
        j = db.get(Job, job.id)
        assert j.status == "failed" and "not found" in j.error and j.attempts == 1


def test_rescan_matches_findings_without_snippets(fake_world, monkeypatch, tmp_path):
    """CodeQL SARIF has no line text; an untouched finding must not look 'new' (or 'fixed') after the rescan."""
    from remediation.models import Finding
    from remediation.scanners.base import Scanner
    from remediation.scanners.builtin_sast import BuiltinSastScanner

    class FakeCodeQL(Scanner):
        name, kind = "codeql", "sast"

        def enabled(self): return True
        def available(self): return True

        def scan(self, root, workdir):
            return [Finding(finding_id="CQ-1", scanner="CodeQL", category="ssrf", severity="high", title="SSRF",
                            file_path="app.py", line=1, rule_id="py/ssrf", remediation_type="source_code_fix")]

    scanners = lambda: [FakeCodeQL(), OsvScanner(), BuiltinSastScanner()]  # noqa: E731
    monkeypatch.setattr("remediation.scanners.all_scanners", scanners)
    monkeypatch.setattr("remediation.agents.analysis.all_scanners", scanners)
    result = RepositoryPipeline("https://github.com/acme/shop", JobOptions(use_llm=False)).run()
    rep = result.report
    cq = next(f for f in result.findings if f.rule_id == "py/ssrf")
    assert cq.snippet == "import subprocess" and cq.fix_status == "skipped"
    new_check = next(c for c in rep.validation_checks if c.name == "No new vulnerabilities introduced")
    assert new_check.status == "passed", new_check.detail
    assert rep.validation_status == "passed"


def test_vendored_library_findings_are_not_patched(tmp_path):
    from remediation.detect import is_vendored
    from remediation.insights import classify
    assert is_vendored("sqli/static/js/materialize.js") and is_vendored("web/vendor/lib.js")
    assert not is_vendored("src/app.js")
    note = "Third-party library code: update the bundled library to a current version instead of patching its source."
    assert classify({"fix_status": "skipped", "fix_note": note})[0] == "vendored"
