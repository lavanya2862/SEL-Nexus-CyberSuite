"""With the shared sign-in on, every person uses only their own keys; with RUNS_VISIBLE_TO=owner they also see only
their own scans."""
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time

import pytest
from fastapi.testclient import TestClient

from remediation import config, credentials, jobqueue, testloop
from remediation.config import get_settings, user_scope
from remediation.db import Job, UserCredentials, session_scope
from remediation.github import RepoAccessError
from remediation.models import JobOptions
from remediation.worker import Worker
from tests.test_pipeline_e2e import fake_world  # noqa: F401  (fixture)

ANA, BEN = "ana@example.com", "ben@example.com"
WRITE = {"X-CyberSuite": "settings"}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@pytest.fixture
def suite(tmp_path, monkeypatch):
    """Shared sign-in on; ``suite(email)`` is a browser signed in as that person."""
    auth = tmp_path / "auth"
    auth.mkdir()
    key = secrets.token_bytes(32)
    (auth / "session.key").write_text(_b64(key), encoding="utf-8")
    monkeypatch.setenv("SUITE_LOGIN_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("SUITE_AUTH_DIR", str(auth))
    monkeypatch.setenv("CREDENTIALS_KEY_FILE", str(tmp_path / "secrets" / "credentials.key"))
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_server_token_never_used")  # the server's own keys must never be used
    config.reset_settings_cache()
    from remediation.api import app

    def browser(email: str, client: tuple[str, int] = ("testclient", 50000)) -> TestClient:
        now = int(time.time())
        name = email.split("@")[0].title()
        body = _b64(json.dumps({"sub": email, "name": name, "via": "local", "iat": now, "exp": now + 3600}).encode())
        c = TestClient(app, base_url="http://127.0.0.1:8500", client=client)
        c.cookies.set("portal_session", f"{body}.{_b64(hmac.new(key, body.encode(), hashlib.sha256).digest())}")
        return c
    return browser


@pytest.fixture
def private(monkeypatch):
    """RUNS_VISIBLE_TO=owner: every person sees only the scans they started."""
    monkeypatch.setenv("RUNS_VISIBLE_TO", "owner")
    config.reset_settings_cache()


def _completed_job(owner):
    job, _ = jobqueue.enqueue("https://github.com/acme/shop", "acme/shop", JobOptions(use_cache=False), owner=owner)
    Worker(1, "t").process(jobqueue.claim_next("t/0"), "t/0")
    return job.id


def _job_urls(job_id):
    return [("get", f"/api/v1/jobs/{job_id}"), ("get", f"/api/v1/jobs/{job_id}/events"),
            ("get", f"/api/v1/jobs/{job_id}/report"), ("get", f"/api/v1/jobs/{job_id}/findings"),
            ("get", f"/api/v1/jobs/{job_id}/artifacts/findings.json"), ("get", f"/api/v1/jobs/{job_id}/artifacts/report.pdf"),
            ("get", f"/api/v1/jobs/{job_id}/agents"), ("post", f"/api/v1/jobs/{job_id}/cancel"),
            ("post", f"/api/v1/jobs/{job_id}/retry"), ("post", f"/api/v1/jobs/{job_id}/publish"),
            ("post", f"/api/v1/jobs/{job_id}/tests"), ("post", f"/api/v1/jobs/{job_id}/tests/cancel"),
            ("post", f"/api/v1/jobs/{job_id}/draft-reviewed")]


def test_nobody_sees_or_touches_another_persons_scan(suite, private, fake_world):
    job_id = _completed_job(ANA)
    ana, ben = suite(ANA), suite(BEN)
    for method, url in _job_urls(job_id):
        r = getattr(ben, method)(url)
        assert r.status_code == 404 and r.json()["detail"] == "Job not found.", (url, r.status_code)
    chat = ben.post("/api/v1/assistant/chat", json={"job_id": job_id, "messages": [{"role": "user", "content": "hi"}]})
    assert chat.status_code in (404, 503)  # no AI key of his own, and never Ana's run either way
    assert ben.get("/api/v1/jobs").json() == {"total": 0, "items": []}
    assert ben.get("/api/v1/dashboard").json()["runs"] == 0
    assert ben.get("/api/v1/vulnerabilities").json()["count"] == 0
    assert ben.get("/api/v1/repositories").json()["items"] == []
    att = ben.get("/api/v1/attention").json()
    assert att["approvals"] == [] and att["fixes_needed"] == [] and att["errors"] == []
    assert ben.get("/api/v1/agents/remediation/history").json()["runs"] == []
    # nothing above changed Ana's scan
    assert ana.get(f"/api/v1/jobs/{job_id}").json()["status"] == "completed"
    # while Ana sees all of it
    for url in (f"/api/v1/jobs/{job_id}", f"/api/v1/jobs/{job_id}/findings", f"/api/v1/jobs/{job_id}/agents"):
        assert ana.get(url).status_code == 200
    assert ana.get("/api/v1/jobs").json()["total"] == 1
    assert ana.get("/api/v1/dashboard").json()["runs"] == 1
    assert ana.get("/api/v1/vulnerabilities").json()["count"] == 4
    assert ana.get("/api/v1/repositories").json()["items"][0]["repo"] == "acme/shop"
    assert ana.get("/api/v1/attention").json()["counts"]["approvals"] == 1
    assert ana.get("/api/v1/agents/remediation/history").json()["runs"][0]["job_id"] == job_id


def test_scans_belong_to_whoever_started_them_and_old_scans_are_hidden(suite, private):
    legacy, _ = jobqueue.enqueue("https://github.com/acme/old", "acme/old", JobOptions())  # made before sign-in
    ana, ben = suite(ANA), suite(BEN)
    r = ana.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop"})
    assert r.status_code == 202
    job_id = r.json()["job"]["id"]
    with session_scope() as db:
        assert db.get(Job, job_id).owner == ANA
    # the same scan by Ben is his own scan, not Ana's (no shared queue entry)
    r = ben.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop"})
    assert r.status_code == 202 and r.json()["deduplicated"] is False and r.json()["job"]["id"] != job_id
    assert ana.post("/api/v1/jobs", json={"repo_url": "https://github.com/acme/shop"}).json()["deduplicated"] is True
    for browser in (ana, ben):
        ids = [j["id"] for j in browser.get("/api/v1/jobs").json()["items"]]
        assert legacy.id not in ids and len(ids) == 1
        assert browser.get(f"/api/v1/jobs/{legacy.id}").status_code == 404


def test_cached_results_are_never_shared_between_people(suite, fake_world):
    ana_job, _ = jobqueue.enqueue("https://github.com/acme/shop", "acme/shop", JobOptions(), owner=ANA)
    ben_job, _ = jobqueue.enqueue("https://github.com/acme/shop", "acme/shop", JobOptions(), owner=BEN)
    assert ana_job.cache_key != ben_job.cache_key
    with session_scope() as db:
        done = db.get(Job, ana_job.id)
        done.status, done.commit_sha, done.finished_at = "completed", "a" * 40, done.created_at
    with session_scope() as db:
        ben_row = db.get(Job, ben_job.id)
        ben_row.cache_key = ana_job.cache_key  # even with an identical key, the owner must match
    assert jobqueue.find_cached_result(ben_row, "a" * 40) is None
    ana_again, _ = jobqueue.enqueue("https://github.com/acme/shop", "acme/shop", JobOptions(use_cache=True), owner=ANA,
                                    dedupe=False)
    assert jobqueue.find_cached_result(ana_again, "a" * 40).id == ana_job.id


def test_each_person_keeps_their_own_keys(suite, tmp_path):
    ana, ben = suite(ANA), suite(BEN)
    view = ana.get("/api/v1/settings").json()
    assert view["per_user"] is True and view["user"] == ANA
    assert view["settings"]["github_token"]["configured"] is False  # the server's GITHUB_TOKEN is not hers
    r = ana.put("/api/v1/settings", headers=WRITE, json={"github_token": "ghp_ana_secret_123456",
                                                         "llm_api_key": "sk-ana-secret-7890", "llm_model": "gpt-test"})
    assert r.status_code == 200
    mine = r.json()
    assert mine["settings"]["github_token"]["source"] == "ui" and mine["llm_enabled"] is True
    assert mine["settings"]["github_token"]["value"].endswith("3456") and "ghp_ana" not in json.dumps(mine)
    assert "sk-ana" not in json.dumps(mine)
    # Ben sees none of it, and his own saves do not touch hers
    theirs = ben.get("/api/v1/settings").json()
    assert theirs["settings"]["github_token"]["configured"] is False and theirs["llm_enabled"] is False
    ben.put("/api/v1/settings", headers=WRITE, json={"github_token": "ghp_ben_secret_abcdef"})
    with user_scope(ANA):
        assert get_settings().github_token == "ghp_ana_secret_123456" and get_settings().llm_api_key == "sk-ana-secret-7890"
    with user_scope(BEN):
        assert get_settings().github_token == "ghp_ben_secret_abcdef" and get_settings().llm_api_key == ""
    assert get_settings().github_token == "" and get_settings().llm_api_key == ""  # nobody: no keys at all
    # the masked placeholder keeps the key, None removes it
    ana.put("/api/v1/settings", headers=WRITE, json={"github_token": "••••••••3456", "llm_api_key": None})
    with user_scope(ANA):
        assert get_settings().github_token == "ghp_ana_secret_123456" and get_settings().llm_api_key == ""
    # stored encrypted, with the key file kept where CREDENTIALS_KEY_FILE says
    with session_scope() as db:
        blobs = [row.data for row in db.query(UserCredentials).all()]
    assert len(blobs) == 2 and not any("secret" in b for b in blobs)
    assert (tmp_path / "secrets" / "credentials.key").is_file()
    assert ana.get("/api/v1/capabilities").json()["github_token_configured"] is True


def test_settings_changes_need_the_header_and_work_from_any_computer(suite):
    remote = suite(ANA, client=("203.0.113.9", 5555))
    assert remote.get("/api/v1/settings").status_code == 200  # deployed: not only from localhost
    assert remote.put("/api/v1/settings", json={"github_token": "ghp_x_123456789"}).status_code == 400
    assert remote.post("/api/v1/settings/test-github").status_code == 400
    assert remote.put("/api/v1/settings", headers=WRITE, json={"github_token": "ghp_x_123456789"}).status_code == 200
    assert remote.post("/api/v1/settings/test-llm", headers=WRITE).status_code == 422  # no model yet: checked, not refused
    assert remote.put("/api/v1/settings", headers=WRITE, json={"llm_provider": "bogus"}).status_code == 422


def test_keys_that_cannot_be_decrypted_count_as_not_set(suite, monkeypatch):
    with user_scope(ANA):
        credentials.save(ANA, {"github_token": "ghp_ana_secret_123456"})
    from cryptography.fernet import Fernet
    monkeypatch.setenv("CREDENTIALS_KEY", Fernet.generate_key().decode())
    config.reset_settings_cache()
    with user_scope(ANA):
        assert get_settings().github_token == ""
    assert suite(ANA).get("/api/v1/settings").json()["settings"]["github_token"]["configured"] is False


def test_the_worker_runs_a_scan_with_its_owners_keys(suite, monkeypatch):
    credentials.save(ANA, {"github_token": "ghp_ana_secret_123456", "llm_api_key": "sk-ana", "llm_model": "m"})
    credentials.save(BEN, {"github_token": "ghp_ben_secret_abcdef"})
    seen = {}

    class Spy:
        def __init__(self, repo_url, *a, **k):
            self.repo_url = repo_url

        def run(self):
            s = get_settings()
            seen[self.repo_url] = (s.github_token, s.llm_api_key)
            raise RepoAccessError("stop here")  # not retried: the next claim is the next job
    monkeypatch.setattr("remediation.worker.RepositoryPipeline", Spy)
    for owner, repo in ((ANA, "acme/a"), (BEN, "acme/b")):
        jobqueue.enqueue(f"https://github.com/{repo}", repo, JobOptions(use_cache=False), owner=owner)
        Worker(1, "t").process(jobqueue.claim_next("t/0"), "t/0")
    assert seen == {"https://github.com/acme/a": ("ghp_ana_secret_123456", "sk-ana"),
                    "https://github.com/acme/b": ("ghp_ben_secret_abcdef", "")}


def test_pull_requests_and_tests_use_the_owners_token(suite, fake_world, monkeypatch):
    job_id = _completed_job(ANA)
    ana = suite(ANA)
    assert ana.post(f"/api/v1/jobs/{job_id}/publish").status_code == 422  # no token of her own yet
    ana.put("/api/v1/settings", headers=WRITE, json={"github_token": "ghp_ana_secret_123456"})
    credentials.save(BEN, {"github_token": "ghp_ben_secret_abcdef"})
    used = {}

    def fake_publish(repo_url, report, mbox, log):
        used["publish"] = get_settings().github_token
        return "https://github.com/acme/shop/pull/7", False
    monkeypatch.setattr("remediation.publish.publish_from_artifacts", fake_publish)
    assert ana.post(f"/api/v1/jobs/{job_id}/publish").json()["status"] == "publishing"
    for _ in range(100):
        if ana.get(f"/api/v1/jobs/{job_id}").json()["summary"].get("approval_status") == "pr_opened":
            break
        time.sleep(0.05)
    assert used["publish"] == "ghp_ana_secret_123456"

    done = threading.Event()

    def fake_loop(jid, st):
        used["tests"] = get_settings().github_token
        done.set()
    monkeypatch.setattr(testloop, "run_loop", fake_loop)
    assert testloop.start(job_id)  # a thread of its own, started outside any request
    assert done.wait(5) and used["tests"] == "ghp_ana_secret_123456"
