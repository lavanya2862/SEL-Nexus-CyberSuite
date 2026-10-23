"""Approval/publish flow, runtime settings, dashboard and chat assistant."""
import json
import time

from fastapi.testclient import TestClient

from remediation import config, jobqueue
from remediation.models import JobOptions
from remediation.pipeline import RepositoryPipeline
from remediation.worker import Worker
from tests.test_pipeline_e2e import fake_world  # noqa: F401  (fixture)


def _client():
    from remediation.api import app
    return TestClient(app)


def _completed_job():
    job, _ = jobqueue.enqueue("https://github.com/acme/shop", "acme/shop", JobOptions(use_cache=False))
    claimed = jobqueue.claim_next("t/0")
    Worker(1, "t").process(claimed, "t/0")
    return job.id


def test_stage_timeline_and_validation_verdict(fake_world):
    result = RepositoryPipeline("https://github.com/acme/shop").run()
    stages = {s.id: s for s in result.report.stages}
    assert [s.id for s in result.report.stages] == ["ingest", "analysis", "remediation", "validation", "reporting",
                                                    "approval"]
    assert stages["ingest"].status == stages["analysis"].status == stages["remediation"].status == "completed"
    assert stages["validation"].status == "completed" and result.report.validation_status == "passed"
    assert stages["approval"].status == "warning" and result.report.approval_status == "awaiting_approval"
    assert stages["analysis"].metrics["unique"] == 4 and any("Risk-based" in s.name for s in stages["analysis"].steps)
    cats = {c.category for c in result.report.validation_checks}
    assert {"static", "security-regression", "security-rescan", "functional"} <= cats
    assert all(f.validation_status == "passed" and f.diff.startswith("diff --git") for f in result.report.fixes)
    llm_fix = next(f for f in result.report.fixes if f.method == "llm")
    assert llm_fix.explanation == "Avoid the shell." and llm_fix.risk == "medium"
    assert "fixes.mbox" in result.artifacts and "From " in result.artifacts["fixes.mbox"][0]
    top = result.findings[0]
    assert top.priority_rank == 1 and top.code_context is None or top.package_name  # dep finding ranks first


def test_worker_persists_stages_and_dashboard(fake_world):
    job_id = _completed_job()
    with _client() as c:
        job = c.get(f"/api/v1/jobs/{job_id}").json()
        assert [s["status"] for s in job["stages"]][:5] == ["completed"] * 5
        assert job["summary"]["validation_status"] == "passed"
        assert job["summary"]["approval_status"] == "awaiting_approval"
        dash = c.get("/api/v1/dashboard").json()
        assert dash["runs"] == 1 and dash["fixes_applied"] == 3 and dash["validation"] == {"passed": 1}
        assert dash["severity"]["critical"] == 1 and dash["recent"][0]["id"] == job_id


def test_approval_publishes_pull_request(fake_world, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    config.reset_settings_cache()
    job_id = _completed_job()
    seen = {}

    def fake_publish(repo_url, report, mbox, log):
        seen.update(repo=repo_url, base=report.base_commit, commits=mbox.count("\nSubject: "))
        log("pushed")
        return "https://github.com/acme/shop/pull/7", False
    monkeypatch.setattr("remediation.publish.publish_from_artifacts", fake_publish)
    with _client() as c:
        assert c.post(f"/api/v1/jobs/{job_id}/publish").json()["status"] == "publishing"
        for _ in range(50):
            summary = c.get(f"/api/v1/jobs/{job_id}").json()["summary"]
            if summary.get("approval_status") == "pr_opened":
                break
            time.sleep(0.1)
        assert summary["pull_request_url"] == "https://github.com/acme/shop/pull/7"
        assert seen == {"repo": "https://github.com/acme/shop", "base": seen["base"], "commits": 3} and seen["base"]
        report = c.get(f"/api/v1/jobs/{job_id}/report").json()
        assert report["pull_request_url"].endswith("/pull/7") and report["approval_status"] == "pr_opened"
        assert c.post(f"/api/v1/jobs/{job_id}/publish").json()["status"] == "exists"


def test_publish_requires_token(fake_world):
    job_id = _completed_job()
    with _client() as c:
        r = c.post(f"/api/v1/jobs/{job_id}/publish")
        assert r.status_code == 422 and "GitHub token" in r.json()["detail"]


def test_runtime_settings_round_trip_and_masking():
    with _client() as c:
        before = c.get("/api/v1/settings").json()
        assert before["llm_enabled"] is False and before["settings"]["llm_provider"]["source"] == "default"
        r = c.put("/api/v1/settings", json={"llm_api_key": "sk-test-1234567890", "llm_model": "gpt-test",
                                             "github_token": "ghp_abcdefghijklmnop"}).json()
        assert r["llm_enabled"] is True
        assert r["settings"]["llm_api_key"]["value"].endswith("7890") and "sk-test" not in json.dumps(r)
        assert r["settings"]["github_token"]["source"] == "ui"
        assert c.get("/api/v1/capabilities").json()["github_token_configured"] is True
        # masked placeholder means "unchanged"; empty clears
        c.put("/api/v1/settings", json={"llm_api_key": "••••••••7890"})
        assert config.get_settings().llm_api_key == "sk-test-1234567890"
        c.put("/api/v1/settings", json={"github_token": None})
        assert config.get_settings().github_token == ""
        assert c.put("/api/v1/settings", json={"llm_provider": "bogus"}).status_code == 422


def test_settings_blocked_for_remote_clients_without_api_keys():
    from remediation.api import app
    with TestClient(app, client=("203.0.113.9", 5555)) as c:
        assert c.get("/api/v1/settings").status_code == 403


def test_chat_assistant_is_grounded_in_run(fake_world, monkeypatch):
    job_id = _completed_job()
    captured = {}

    def fake_chat(system, messages):
        captured["system"], captured["messages"] = system, messages
        return "The most critical issue is **PyYAML**."
    monkeypatch.setattr("remediation.assistant.chat", fake_chat)
    with _client() as c:
        findings = c.get(f"/api/v1/jobs/{job_id}/findings").json()["items"]
        fid = next(f["finding_id"] for f in findings if f.get("rule_id") == "PY-YAML-LOAD")
        r = c.post("/api/v1/assistant/chat", json={"job_id": job_id, "finding_id": fid, "messages": [
            {"role": "assistant", "content": "hello"}, {"role": "user", "content": "What is most critical?"}]})
        assert r.status_code == 200 and "PyYAML" in r.json()["reply"]
        assert "acme/shop" in captured["system"] and "FOCUSED FINDING" in captured["system"]
        assert "yaml.load(raw)" in captured["system"]  # code context
        assert captured["messages"] == [{"role": "user", "content": "What is most critical?"}]
        bad = c.post("/api/v1/assistant/chat", json={"messages": [{"role": "assistant", "content": "x"}]})
        assert bad.status_code == 422


def test_chat_requires_llm(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "")
    config.reset_settings_cache()
    with _client() as c:
        r = c.post("/api/v1/assistant/chat", json={"messages": [{"role": "user", "content": "hi"}]})
        assert r.status_code == 503 and "Settings" in r.json()["detail"]


def test_agent_views_story_and_action_center(fake_world):
    job_id = _completed_job()
    with _client() as c:
        d = c.get(f"/api/v1/jobs/{job_id}/agents").json()
        assert set(d["agents"]) == {"analysis", "remediation", "validation", "reporting"}
        story = d["story"]
        assert story["headline"].startswith("4 issues found") and story["decision"]["kind"] == "approve"
        rem = d["agents"]["remediation"]
        outs = {o["label"]: o["value"] for o in rem["outputs"]}
        assert outs["Fix commits"] == 3 and outs["Dependency / Rule / Code"] == "1 / 1 / 1"
        assert any("Remediation Agent wrote 1 code fix" in l["text"] for l in rem["learnings"])
        assert any(l["tone"] == "good" for l in d["agents"]["validation"]["learnings"])
        assert d["agents"]["analysis"]["inputs"][0]["label"] == "Repository"

        att = c.get("/api/v1/attention").json()
        assert att["counts"]["approvals"] == 1 and att["approvals"][0]["id"] == job_id
        # the eval() in test code is left open and explained
        left = att["fixes_needed"]
        assert len(left) == 1 and left[0]["reason"] == "In test code" and left[0]["action"]
        assert any(e["kind"] == "No GitHub token" for e in att["config_errors"])

        hist = c.get("/api/v1/agents/remediation/history").json()
        assert hist["agent"]["name"] == "Remediation Agent" and hist["runs"][0]["job_id"] == job_id
        assert c.get("/api/v1/agents/bogus/history").status_code == 404

        vulns = c.get("/api/v1/vulnerabilities").json()
        assert vulns["count"] == 4 and all(v["repo"] == "acme/shop" for v in vulns["items"])
        repos = c.get("/api/v1/repositories").json()["items"]
        assert repos[0]["repo"] == "acme/shop" and repos[0]["runs"] == 1 and repos[0]["history"][0]["findings"] == 4


def test_running_job_agent_views_have_no_outputs_yet(fake_world):
    job, _ = jobqueue.enqueue("https://github.com/acme/shop", "acme/shop", JobOptions(use_cache=False))
    with _client() as c:
        d = c.get(f"/api/v1/jobs/{job.id}/agents").json()
        assert d["story"]["headline"].startswith("Working on acme/shop")
        assert all(v["outputs"] == [] and v["status"] == "pending" for v in d["agents"].values())


def test_fix_reason_classification():
    from remediation.insights import classify
    cases = {
        "LLM quota exhausted for model x (resets in about 18 h).": "llm_quota",
        "LLM request failed after 5 attempts: HTTP 503: high demand": "llm_unavailable",
        "LLM request rejected (HTTP 404: model is no longer available)": "llm_rejected",
        "Could not produce an applicable fix: search text not found in app.py.": "ai_failed",
        "No patched version has been published for these advisories": "no_upstream",
        "package.json: lodash is not a direct dependency": "transitive",
    }
    for note, key in cases.items():
        assert classify({"fix_note": note, "fix_status": "failed"})[0] == key, note
    assert classify({"fix_status": "not_attempted"})[0] == "below_threshold"
