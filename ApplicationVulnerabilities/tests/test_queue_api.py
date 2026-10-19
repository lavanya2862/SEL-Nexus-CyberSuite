from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from remediation import config, jobqueue
from remediation.db import Job, session_scope, utcnow
from remediation.models import JobOptions


@pytest.fixture
def client():
    from remediation.api import app
    with TestClient(app) as c:
        yield c


def test_claim_is_exclusive_and_priority_ordered():
    low, _ = jobqueue.enqueue("https://github.com/a/low", "a/low", JobOptions())
    high, _ = jobqueue.enqueue("https://github.com/a/high", "a/high", JobOptions(), priority=5)
    first = jobqueue.claim_next("w1")
    second = jobqueue.claim_next("w2")
    assert (first.id, second.id) == (high.id, low.id)
    assert jobqueue.claim_next("w3") is None
    assert jobqueue.heartbeat(first.id, "w1") and not jobqueue.heartbeat(first.id, "intruder")


def test_identical_active_jobs_are_deduplicated():
    a, dup_a = jobqueue.enqueue("https://github.com/a/b", "a/b", JobOptions())
    b, dup_b = jobqueue.enqueue("https://github.com/a/b", "a/b", JobOptions())
    c, _ = jobqueue.enqueue("https://github.com/a/b", "a/b", JobOptions(min_severity="high"))
    assert (dup_a, dup_b) == (False, True) and a.id == b.id and c.id != a.id


def test_stale_lease_is_requeued_then_failed(monkeypatch):
    monkeypatch.setenv("MAX_JOB_ATTEMPTS", "2")
    config.reset_settings_cache()
    job, _ = jobqueue.enqueue("https://github.com/a/b", "a/b", JobOptions())
    for expected in ("queued", "failed"):
        claimed = jobqueue.claim_next("w")
        assert claimed.id == job.id
        assert jobqueue.recover_stale(now=utcnow() + timedelta(hours=1)) == 1
        with session_scope() as db:
            assert db.get(Job, job.id).status == expected


def test_cancel_and_retry():
    job, _ = jobqueue.enqueue("https://github.com/a/b", "a/b", JobOptions())
    assert jobqueue.request_cancel(job.id).status == "cancelled"
    assert jobqueue.claim_next("w") is None
    assert jobqueue.retry_job(job.id).status == "queued"


def test_queue_backpressure(monkeypatch):
    monkeypatch.setenv("MAX_QUEUED_JOBS", "1")
    config.reset_settings_cache()
    jobqueue.enqueue("https://github.com/a/one", "a/one", JobOptions())
    with pytest.raises(jobqueue.QueueFull):
        jobqueue.enqueue("https://github.com/a/two", "a/two", JobOptions())


def test_api_submit_validate_and_fetch(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").status_code == 200
    bad = client.post("/api/v1/jobs", json={"repo_url": "https://gitlab.com/x/y"})
    assert bad.status_code == 422 and "github.com" in bad.json()["detail"]
    ok = client.post("/api/v1/jobs", json={"repo_url": "https://github.com/octo/demo/tree/dev"})
    assert ok.status_code == 202
    job = ok.json()["job"]
    assert job["repo"] == "octo/demo" and job["ref"] == "dev" and job["status"] == "queued"
    again = client.post("/api/v1/jobs", json={"repo_url": "github.com/octo/demo", "options": {"ref": "dev"}})
    assert again.status_code == 200 and again.json()["deduplicated"]
    detail = client.get(f"/api/v1/jobs/{job['id']}").json()
    assert detail["artifacts"] == []
    assert client.get(f"/api/v1/jobs/{job['id']}/events").json()["items"][0]["message"].startswith("Job queued")
    assert client.get(f"/api/v1/jobs/{job['id']}/report").status_code == 404
    assert client.get("/api/v1/jobs").json()["total"] == 1
    assert client.post(f"/api/v1/jobs/{job['id']}/cancel").json()["job"]["status"] == "cancelled"
    assert "remediation_jobs" in client.get("/metrics").text
    assert client.get("/api/v1/jobs/not-a-valid-id!").status_code in (400, 404)
    assert client.get("/").status_code == 200


def test_api_key_auth_and_rate_limit(monkeypatch):
    monkeypatch.setenv("API_KEYS", "s3cret,other")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    config.reset_settings_cache()
    from remediation.api import app, rate_limiter
    rate_limiter._hits.clear()
    with TestClient(app) as c:
        assert c.get("/api/v1/jobs").status_code == 401
        assert c.get("/api/v1/jobs", headers={"X-API-Key": "wrong"}).status_code == 401
        h = {"Authorization": "Bearer s3cret"}
        assert c.get("/api/v1/jobs", headers=h).status_code == 200
        codes = [c.post("/api/v1/jobs", headers=h, json={"repo_url": f"https://github.com/o/r{i}"}).status_code
                 for i in range(3)]
        assert codes == [202, 202, 429]
        assert c.get("/health").status_code == 200  # health stays public
