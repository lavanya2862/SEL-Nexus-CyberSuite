"""Remediation quality: test code recognised for every scanner, GitHub Actions pinned without the AI model, the AI's
"false positive" answer reported as such, regressions reverted by the Validation Agent, and a current model list."""
import subprocess
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from remediation import fixers, llm
from remediation.agents.analysis import AnalysisAgent
from remediation.agents.validation import ValidationAgent
from remediation.gitops import CmdResult
from remediation.insights import classify
from remediation.models import Finding, FixRecord, RemediationReport


def _finding(**kw) -> Finding:
    base = dict(finding_id="f1", scanner="Bandit", title="t", severity="low", category="misc", file_path="app/x.py", line=1)
    return Finding(**{**base, **kw})


def test_test_code_is_recognised_for_every_scanner_and_test_asserts_are_dropped():
    findings = [_finding(finding_id="a", rule_id="B101", file_path="tests/test_app.py"),
                _finding(finding_id="b", rule_id="B101", file_path="app/views.py"),
                _finding(finding_id="c", scanner="Semgrep", rule_id="x", file_path="tests/test_security.py"),
                _finding(finding_id="d", scanner="CodeQL", rule_id="py/sql-injection", file_path="app/db.py")]
    kept, marked, dropped = AnalysisAgent.mark_test_code(findings)
    assert [f.finding_id for f in kept] == ["b", "c", "d"] and marked == 1 and dropped == 1
    assert kept[1].raw["in_tests"] is True and not (kept[2].raw or {}).get("in_tests")


def test_mutable_github_action_is_pinned_to_its_commit(tmp_path, monkeypatch):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
                               "      - uses: 'github/codeql-action/init@v3' # init\n", encoding="utf-8")
    sha_tag, sha_peeled = "a" * 40, "b" * 40
    calls = []

    def fake(args, cwd=None, timeout=600, env=None, input_text=None):
        calls.append(args)
        out = f"{sha_tag}\trefs/tags/v4\n" if "actions/checkout" in args[2] else \
            f"{sha_tag}\trefs/tags/v3\n{sha_peeled}\trefs/tags/v3^{{}}\n"
        return CmdResult(0, out, "")
    monkeypatch.setattr(fixers, "run_cmd", fake)
    rule = "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag"
    one = _finding(scanner="Semgrep", rule_id=rule, file_path=".github/workflows/ci.yml", line=4)
    two = _finding(scanner="Semgrep", rule_id=rule, file_path=".github/workflows/ci.yml", line=5)
    assert fixers.is_mutable_action_finding(one)
    a = fixers.fix_action_pin(tmp_path, one)
    b = fixers.fix_action_pin(tmp_path, two)
    text = (wf / "ci.yml").read_text(encoding="utf-8")
    assert a.ok and b.ok and calls[0][:2] == ["git", "ls-remote"]
    assert f"      - uses: actions/checkout@{sha_tag} # v4\n" in text
    assert f"      - uses: 'github/codeql-action/init@{sha_peeled}' # init\n" in text  # annotated tag: the commit
    assert fixers.fix_action_pin(tmp_path, one) is None  # already pinned


def test_unresolvable_action_goes_to_a_person(tmp_path, monkeypatch):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("steps:\n  - uses: acme/gone@v1\n", encoding="utf-8")
    monkeypatch.setattr(fixers, "run_cmd", lambda *a, **k: CmdResult(128, "", "not found"))
    f = _finding(rule_id="github-actions-mutable-action-tag", file_path=".github/workflows/ci.yml", line=2)
    attempt = fixers.fix_action_pin(tmp_path, f)
    assert not attempt.ok and attempt.manual and "by hand" in attempt.detail


def test_false_positive_answer_is_its_own_root_cause(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("import subprocess\nsubprocess.run(['ping', '-c', '1', host])\n", encoding="utf-8")
    monkeypatch.setattr(fixers, "chat", lambda *a, **k: '{"status": "false_positive", "explanation": "Argument list, '
                                                         'no shell.", "edits": []}')
    attempt = fixers.fix_with_llm(tmp_path, _finding(file_path="app.py", line=2))
    assert not attempt.ok and attempt.manual and attempt.detail.startswith("Likely false positive")
    key, label, _ = classify({"fix_note": attempt.detail, "fix_status": "manual"})
    assert key == "false_positive" and label == "Assessed as likely false positive"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@x", "-c", "core.autocrlf=false", *args],
                          cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def test_validation_reverts_a_remediation_that_introduced_a_new_finding(tmp_path):
    repo = tmp_path
    _git(repo, "init", "-q")
    (repo / "a.py").write_bytes(b"x = 1\n")
    (repo / "b.py").write_bytes(b"y = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    (repo / "a.py").write_bytes(b"x = 2\n")
    _git(repo, "commit", "-qam", "fix a")
    sha_a = _git(repo, "rev-parse", "HEAD")
    (repo / "b.py").write_bytes(b"y = 2\n")
    _git(repo, "commit", "-qam", "fix b")
    sha_b = _git(repo, "rev-parse", "HEAD")

    report = RemediationReport.model_construct(fixes=[
        FixRecord(finding_ids=["fa"], method="llm", summary="fix a", files=["a.py"], commit=sha_a),
        FixRecord(finding_ids=["fb"], method="llm", summary="fix b", files=["b.py"], commit=sha_b)])
    findings = [_finding(finding_id="fa", file_path="a.py", fix_status="verified"),
                _finding(finding_id="fb", file_path="b.py", fix_status="verified")]
    steps = []
    ctx = SimpleNamespace(src=repo, report=report, findings=findings, log=lambda *a, **k: None,
                          step=lambda *a, **k: steps.append(a))
    new = _finding(finding_id="n1", scanner="CodeQL", title="Full server-side request forgery", severity="high",
                   file_path="a.py")
    reverted, remaining = ValidationAgent(ctx, None).revert_regressions([new])

    assert [f.summary for f in reverted] == ["fix a"] and remaining == []
    assert report.fixes[0].status == "reverted" and report.fixes[1].status == "applied"
    assert (repo / "a.py").read_bytes() == b"x = 1\n" and (repo / "b.py").read_bytes() == b"y = 2\n"
    assert findings[0].fix_status == "manual" and findings[0].fix_note.startswith("Reverted")
    assert findings[1].fix_status == "verified"
    assert _git(repo, "log", "-1", "--format=%s").startswith("Revert remediation: fix a")


class _Resp:
    def __init__(self, code, text):
        self.status_code, self.text, self.is_success, self.headers = code, text, code < 400, {}

    def json(self):
        return {}


@pytest.mark.parametrize("code,body,match", [
    (429, '{"error": {"message": "Quota exceeded for metric: free_tier_requests, limit: 0, model: gemini-4-argon"}}',
     "no quota for the model 'm'"),
    (403, '{"error": {"message": "This model is no longer available to new users."}}', "cannot use the model 'm'"),
    (400, '{"error": {"message": "API key not valid. Please pass a valid API key.", "status": "API_KEY_INVALID"}}',
     "refused this API key"),
])
def test_provider_errors_are_explained_without_retrying(monkeypatch, code, body, match):
    calls = []
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: calls.append(1) or _Resp(code, body))
    with pytest.raises(llm.LLMError, match=match):
        llm._post_with_retries("https://x/chat/completions", {}, {"model": "m"})
    assert len(calls) == 1


def test_model_list_is_current_and_recommended_first(monkeypatch):
    names = ["gemini-4-argon", "gemini-3.8-flash", "gemini-3.6-flash", "gemini-3.5-flash", "gemini-3.7-flash",
             "gemini-3.5-flash-lite", "gemini-3.1-pro-preview", "gemini-flash-latest", "gemini-2.5-flash", "gemini-2.5-pro",
             "gemini-2.0-flash-001", "gemini-exp-1206", "gemini-robotics-er-1.6-preview", "gemini-3.1-flash-tts-preview",
             "gemini-embedding-001", "gemma-3-27b-it"]
    monkeypatch.setattr(llm.httpx, "get", lambda *a, **k: httpx.Response(
        200, json={"data": [{"id": f"models/{n}"} for n in names]}, request=httpx.Request("GET", "https://x")))
    assert llm.list_models("gemini", "k") == ["gemini-flash-latest", "gemini-3.8-flash", "gemini-3.6-flash",
                                              "gemini-3.5-flash-lite", "gemini-4-argon", "gemini-3.1-pro-preview"]
    monkeypatch.setattr(llm.httpx, "get", lambda *a, **k: httpx.Response(200, json={"data": [
        {"id": i} for i in ("gpt-4o", "gpt-4o-2024-08-06", "gpt-3.5-turbo", "gpt-4-0613", "gpt-4.1", "o3-mini")]},
        request=httpx.Request("GET", "https://x")))
    assert llm.list_models("openai", "k") == ["o3-mini", "gpt-4o", "gpt-4.1"]


def _agent_ctx(max_findings: int | None):
    return SimpleNamespace(src=Path("."), checkpoint=lambda: None, reporter=SimpleNamespace(stage=lambda *a: None),
                           options=SimpleNamespace(max_findings=max_findings, use_llm=True),
                           s=SimpleNamespace(max_findings_per_run=0, llm_fix_attempts=1, llm_enabled=True,
                                             llm_max_concurrency=8, llm_model="gpt-5"),
                           report=SimpleNamespace(llm_enabled=True, notes=[]), log=lambda *a, **k: None,
                           step=lambda *a, **k: None)


def test_every_finding_in_scope_is_remediated_in_parallel(monkeypatch):
    """No fixed cap: the scan's severity scope decides. The model is asked about all findings at once (up to the
    configured workers) and the answers are applied in risk order."""
    import threading
    import time
    from remediation.agents import remediation as agent_mod
    asked, applied, running, peak, lock = [], [], [0], [0], threading.Lock()

    def propose(root, f):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.05)
        with lock:
            running[0] -= 1
            asked.append(f.finding_id)
        return [{"role": "user", "content": "p"}], f"answer for {f.finding_id}"

    def apply(root, f, attempts, log, proposal=None):
        applied.append((f.finding_id, proposal[1]))
        return fixers.FixAttempt(False, manual=True, detail="Model declined: test")
    monkeypatch.setattr(agent_mod, "fix_with_rule", lambda root, f: None)
    monkeypatch.setattr(agent_mod, "propose_fix", propose)
    monkeypatch.setattr(agent_mod, "fix_with_llm", apply)
    findings = [_finding(finding_id=f"f{i}", severity="medium", category="xss") for i in range(20)]
    agent_mod.RemediationAgent(_agent_ctx(None))._code(findings)
    assert sorted(asked) == sorted(f.finding_id for f in findings) and 1 < peak[0] <= 8
    assert [a[0] for a in applied] == [f.finding_id for f in findings]  # applied in risk order
    assert all(a[1] == f"answer for {a[0]}" for a in applied)

    # an explicit ceiling for one scan is still honoured, highest risk first
    asked.clear()
    applied.clear()
    findings = [_finding(finding_id=f"g{i}", severity="high", category="xss") for i in range(5)]
    agent_mod.RemediationAgent(_agent_ctx(2))._code(findings)
    assert [a[0] for a in applied] == ["g0", "g1"]
    assert [f.fix_status for f in findings[2:]] == ["skipped"] * 3 and "budget" in findings[4].fix_note


def test_a_working_fix_that_only_adds_low_severity_noise_is_kept(tmp_path):
    fix = FixRecord(finding_ids=["f"], method="llm", summary="list args instead of shell=True", files=["app/u.py"],
                    commit="abc", verified=True)
    report = RemediationReport.model_construct(fixes=[fix])
    ctx = SimpleNamespace(src=tmp_path, report=report, findings=[_finding(finding_id="f", file_path="app/u.py")],
                          log=lambda *a, **k: None, step=lambda *a, **k: None)
    note = _finding(finding_id="n", rule_id="B603", title="subprocess call - check for execution of untrusted input.",
                    severity="low", file_path="app/u.py")
    reverted, remaining = ValidationAgent(ctx, None).revert_regressions([note])
    assert reverted == [] and remaining == [note] and fix.status == "applied"


def test_ai_workers_follow_the_size_of_the_code_base():
    from remediation.agents.remediation import ai_workers
    s = SimpleNamespace(llm_workers="auto", llm_max_workers=32, llm_rpm=2500)
    assert [ai_workers(s, loc, 500)[0] for loc in (3_000, 20_000, 85_000, 400_000)] == [4, 8, 16, 32]
    assert ai_workers(s, 85_000, 5)[0] == 5                                  # never more than the findings waiting
    assert ai_workers(SimpleNamespace(llm_workers="auto", llm_max_workers=8, llm_rpm=0), 400_000, 500)[0] == 8
    assert ai_workers(SimpleNamespace(llm_workers="auto", llm_max_workers=32, llm_rpm=20), 400_000, 500)[0] == 5
    assert ai_workers(SimpleNamespace(llm_workers="12", llm_max_workers=32, llm_rpm=0), 3_000, 500) == (12, "fixed")
    assert "85,000 lines of code" in ai_workers(s, 85_000, 500)[1]


def test_lines_of_code_are_counted_without_vendored_code(tmp_path):
    from remediation.detect import detect_project
    (tmp_path / "app.py").write_bytes(b"a = 1\nb = 2\nc = 3")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "main.js").write_bytes(b"x()\n" * 10)
    (tmp_path / "web" / "jquery.min.js").write_bytes(b"y()\n" * 1000)
    (tmp_path / "README.md").write_bytes(b"docs\n" * 50)
    assert detect_project(tmp_path).lines_of_code == 13
