"""Everyone sees every scan (RUNS_VISIBLE_TO=everyone, the default) and can download its reports, but only the person
who started a scan can act on it, with their own keys. The activity log shows who did what, with name, email and time."""
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


def test_others_can_view_and_download_but_not_act(suite, fake_world, monkeypatch):
    job_id = _completed_job(ANA)
    ben = suite(BEN)
    ben.put("/api/v1/settings", headers=WRITE, json={"github_token": "ghp_ben_secret_abcdef"})
    pushed = []
    monkeypatch.setattr("remediation.publish.publish_from_artifacts", lambda *a: pushed.append(a) or ("x", False))
    monkeypatch.setattr(testloop, "run_loop", lambda *a: pushed.append(a))
    job = ben.get(f"/api/v1/jobs/{job_id}").json()
    assert job["can_act"] is False and job["started_by"]["email"] == ANA
    # looking and downloading is fine
    for url in (f"/api/v1/jobs/{job_id}/report", f"/api/v1/jobs/{job_id}/findings", f"/api/v1/jobs/{job_id}/agents",
                f"/api/v1/jobs/{job_id}/events", f"/api/v1/jobs/{job_id}/artifacts/fixes.patch?download=true",
                f"/api/v1/jobs/{job_id}/artifacts/report.pdf?download=true"):
        assert ben.get(url).status_code == 200, url
    # every action is refused, and names who can do it
    for url in ("publish", "tests", "tests/cancel", "cancel", "retry", "draft-reviewed"):
        r = ben.post(f"/api/v1/jobs/{job_id}/{url}")
        assert r.status_code == 403, url
        assert r.json()["detail"].startswith("Only ana@example.com, who started this scan, can do that."), url
    assert pushed == [] and ben.get(f"/api/v1/jobs/{job_id}").json()["status"] == "completed"
    assert not [e for e in _log(ben) if e["action"] != "settings_changed"]  # nothing happened
    # his own Action Center does not ask him to approve someone else's scan
    assert ben.get("/api/v1/attention").json()["approvals"] == []
    # scans from before sign-ins were recorded: everyone may look, nobody may act
    legacy, _ = jobqueue.enqueue("https://github.com/acme/old", "acme/old", JobOptions())
    assert ben.get(f"/api/v1/jobs/{legacy.id}").json()["can_act"] is False
    assert "before sign-ins were recorded" in ben.post(f"/api/v1/jobs/{legacy.id}/cancel").json()["detail"]


def test_the_starter_approves_and_tests_with_their_own_token_and_it_is_logged(suite, fake_world, monkeypatch):
    job_id = _completed_job(ANA)
    ana = suite(ANA)
    ana.put("/api/v1/settings", headers=WRITE, json={"github_token": "ghp_ana_secret_123456"})
    assert ana.get(f"/api/v1/jobs/{job_id}").json()["can_act"] is True
    assert ana.get("/api/v1/attention").json()["approvals"][0]["id"] == job_id
    used = {}

    def fake_publish(repo_url, report, mbox, log):
        used["publish"] = get_settings().github_token
        return "https://github.com/acme/shop/pull/9", False
    monkeypatch.setattr("remediation.publish.publish_from_artifacts", fake_publish)
    assert ana.post(f"/api/v1/jobs/{job_id}/publish").json()["status"] == "publishing"
    for _ in range(100):
        summary = ana.get(f"/api/v1/jobs/{job_id}").json()["summary"]
        if summary.get("approval_status") == "pr_opened":
            break
        time.sleep(0.05)
    assert used["publish"] == "ghp_ana_secret_123456"
    assert summary["approved_by"]["email"] == ANA and summary["approved_by"]["name"] == "Ana" and summary["approved_by"]["at"]
    events = [e["message"] for e in ana.get(f"/api/v1/jobs/{job_id}/events").json()["items"]]
    assert any(m.startswith("Ana (ana@example.com) approved the fixes") for m in events)
    stage = next(s for s in ana.get(f"/api/v1/jobs/{job_id}").json()["stages"] if s["id"] == "approval")
    assert stage["summary"] == "Approved by Ana (ana@example.com) — PR opened"
    log = _log(ana)
    assert [e["action"] for e in log[:2]] == ["pr_opened", "fixes_approved"]
    assert all(e["email"] == ANA and e["job_id"] == job_id for e in log[:2])
    assert log[0]["detail"] == "https://github.com/acme/shop/pull/9"
    assert "ghp_" not in str(log)  # settings_changed says which setting, never the value
    settings = next(e for e in log if e["action"] == "settings_changed")
    assert settings["detail"] == "saved GitHub token" and settings["email"] == ANA

    done = threading.Event()

    def fake_loop(jid, st):
        used["tests"] = get_settings().github_token
        done.set()
    monkeypatch.setattr(testloop, "run_loop", fake_loop)
    assert ana.post(f"/api/v1/jobs/{job_id}/tests").json()["status"] == "started"
    assert done.wait(5) and used["tests"] == "ghp_ana_secret_123456"
    assert _log(ana, action="tests_started")[0]["email"] == ANA


def test_the_starter_can_rerun_and_cancel(suite, fake_world):
    ana = suite(ANA)
    job_id = ana.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop",
                                            "options": {"use_cache": False}}).json()["job"]["id"]
    jobqueue.fail(job_id, None, "boom")
    again = ana.post(f"/api/v1/jobs/{job_id}/retry").json()["job"]
    assert again["status"] == "queued" and again["started_by"] == {"email": ANA, "name": "Ana"} and again["can_act"]
    assert _log(ana, action="scan_rerun")[0]["email"] == ANA
    assert ana.post(f"/api/v1/jobs/{job_id}/cancel").json()["job"]["status"] == "cancelled"
    assert _log(ana, action="scan_cancelled")[0]["email"] == ANA


def test_the_log_filters(suite):
    ana, ben = suite(ANA), suite(BEN)
    job_id = ana.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop",
                                            "options": {"create_pr": False, "ref": "main"}}).json()["job"]["id"]
    ben.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/api"})
    ana.post(f"/api/v1/jobs/{job_id}/cancel")
    log = _log(ben)
    assert [e["action"] for e in log] == ["scan_cancelled", "scan_started", "scan_started"]
    assert log[0]["email"] == ANA and log[0]["repo"] == "acme/shop"
    assert log[2]["detail"] == "ref main"
    assert [e["email"] for e in _log(ana, q="ben")] == [BEN]
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
