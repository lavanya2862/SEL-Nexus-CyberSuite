"""Everyone sees every scan (RUNS_VISIBLE_TO=everyone, the default), and the activity log shows who started, re-ran,
approved and tested what, with their name, email and the time. Every action uses the acting person's own keys."""
import threading
import time

from fastapi.testclient import TestClient

from remediation import credentials, jobqueue, testloop
from remediation.config import get_settings
from remediation.models import JobOptions
from tests.test_per_user import ANA, BEN, WRITE, _completed_job, private, suite  # noqa: F401  (fixtures)
from tests.test_pipeline_e2e import fake_world  # noqa: F401  (fixture)


def _log(browser, **params):
    return browser.get("/api/v1/activity", params=params).json()["items"]


def test_everyone_sees_every_scan_and_who_started_it(suite):
    legacy, _ = jobqueue.enqueue("https://github.com/acme/old", "acme/old", JobOptions())  # before sign-in existed
    ana, ben = suite(ANA), suite(BEN)
    job_id = ana.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop"}).json()["job"]["id"]
    items = {j["id"]: j for j in ben.get("/api/v1/jobs").json()["items"]}
    assert set(items) == {job_id, legacy.id}
    assert items[job_id]["started_by"] == {"email": ANA, "name": "Ana"} and items[legacy.id]["started_by"] is None
    assert ben.get(f"/api/v1/jobs/{job_id}").status_code == 200 and ben.get("/api/v1/dashboard").json()["runs"] == 2
    events = [e["message"] for e in ben.get(f"/api/v1/jobs/{job_id}/events").json()["items"]]
    assert "Started by Ana (ana@example.com)" in events
    entry = _log(ben)[0]
    assert entry["action"] == "scan_started" and entry["name"] == "Ana" and entry["email"] == ANA
    assert entry["job_id"] == job_id and entry["repo"] == "acme/shop" and entry["ts"]


def test_approval_by_someone_else_uses_their_own_token_and_is_logged(suite, fake_world, monkeypatch):
    job_id = _completed_job(ANA)
    credentials.save(ANA, {"github_token": "ghp_ana_secret_123456"})
    ben = suite(BEN)
    ben.put("/api/v1/settings", headers=WRITE, json={"github_token": "ghp_ben_secret_abcdef"})
    used = {}

    def fake_publish(repo_url, report, mbox, log):
        used["token"] = get_settings().github_token
        return "https://github.com/acme/shop/pull/9", False
    monkeypatch.setattr("remediation.publish.publish_from_artifacts", fake_publish)
    assert ben.post(f"/api/v1/jobs/{job_id}/publish").json()["status"] == "publishing"
    for _ in range(100):
        summary = ben.get(f"/api/v1/jobs/{job_id}").json()["summary"]
        if summary.get("approval_status") == "pr_opened":
            break
        time.sleep(0.05)
    assert used["token"] == "ghp_ben_secret_abcdef"  # Ben approved, so the pull request is Ben's
    assert summary["approved_by"]["email"] == BEN and summary["approved_by"]["name"] == "Ben" and summary["approved_by"]["at"]
    events = [e["message"] for e in ben.get(f"/api/v1/jobs/{job_id}/events").json()["items"]]
    assert any(m.startswith("Ben (ben@example.com) approved the fixes") for m in events)
    stage = next(s for s in ben.get(f"/api/v1/jobs/{job_id}").json()["stages"] if s["id"] == "approval")
    assert stage["summary"] == "Approved by Ben (ben@example.com) — PR opened"
    log = _log(ben)
    assert [e["action"] for e in log[:2]] == ["pr_opened", "fixes_approved"]
    assert all(e["email"] == BEN and e["job_id"] == job_id for e in log[:2])
    assert log[0]["detail"] == "https://github.com/acme/shop/pull/9"
    assert "ghp_" not in str(log)  # settings_changed says which setting, never the value
    settings = next(e for e in log if e["action"] == "settings_changed")
    assert settings["detail"] == "saved GitHub token" and settings["email"] == BEN


def test_a_rerun_and_github_tests_run_as_the_person_who_asked(suite, fake_world, monkeypatch):
    ana, ben = suite(ANA), suite(BEN)
    job_id = ana.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop",
                                            "options": {"use_cache": False}}).json()["job"]["id"]
    jobqueue.fail(job_id, None, "boom")
    again = ben.post(f"/api/v1/jobs/{job_id}/retry").json()["job"]
    assert again["status"] == "queued" and again["started_by"] == {"email": BEN, "name": "Ben"}
    rerun = _log(ben, action="scan_rerun")[0]
    assert rerun["email"] == BEN and rerun["detail"] == "first started by Ana (ana@example.com)"
    # the re-run scan works with Ben's keys
    from remediation.worker import Worker
    credentials.save(BEN, {"github_token": "ghp_ben_secret_abcdef"})
    Worker(1, "t").process(jobqueue.claim_next("t/0"), "t/0")
    assert ben.get(f"/api/v1/jobs/{job_id}").json()["status"] == "completed"

    credentials.save(ANA, {"github_token": "ghp_ana_secret_123456"})
    done, used = threading.Event(), {}

    def fake_loop(jid, st):
        used["token"] = get_settings().github_token
        done.set()
    monkeypatch.setattr(testloop, "run_loop", fake_loop)
    assert ana.post(f"/api/v1/jobs/{job_id}/tests").json()["status"] == "started"
    assert done.wait(5) and used["token"] == "ghp_ana_secret_123456"  # Ana asked, so Ana's token pushes
    tests = _log(ana, action="tests_started")[0]
    assert tests["email"] == ANA and tests["job_id"] == job_id
    for _ in range(100):
        if ana.get(f"/api/v1/jobs/{job_id}").json()["summary"]["tests"].get("started_by"):
            break
        time.sleep(0.05)
    assert ana.get(f"/api/v1/jobs/{job_id}").json()["summary"]["tests"]["started_by"] == {"email": ANA, "name": "Ana"}


def test_the_log_filters_and_cancellations(suite):
    ana, ben = suite(ANA), suite(BEN)
    job_id = ana.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop",
                                            "options": {"create_pr": False, "ref": "main"}}).json()["job"]["id"]
    ben.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/api"})
    ben.post(f"/api/v1/jobs/{job_id}/cancel")
    log = _log(ana)
    assert [e["action"] for e in log] == ["scan_cancelled", "scan_started", "scan_started"]
    assert log[0]["email"] == BEN and log[0]["repo"] == "acme/shop"
    assert log[2]["detail"] == "ref main"
    assert [e["email"] for e in _log(ana, q="ben")] == [BEN, BEN]
    assert [e["repo"] for e in _log(ana, q="acme/api")] == ["acme/api"]
    assert len(_log(ana, action="scan_started")) == 2
    assert ana.get("/api/v1/activity", params={"limit": 1}).json()["total"] == 3


def test_with_private_scans_the_log_shows_only_your_own_actions(suite, private):
    ana, ben = suite(ANA), suite(BEN)
    ana.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop"})
    ben.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/api"})
    assert [e["repo"] for e in _log(ana)] == ["acme/shop"]
    assert [e["repo"] for e in _log(ben)] == ["acme/api"]


def test_without_the_shared_sign_in_the_local_user_is_logged():
    from remediation.api import app
    c = TestClient(app)
    job = c.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop"}).json()["job"]
    assert job["started_by"] == {"email": None, "name": "Local user"}
    entry = c.get("/api/v1/activity").json()["items"][0]
    assert entry["name"] == "Local user" and entry["email"] is None and entry["action"] == "scan_started"
