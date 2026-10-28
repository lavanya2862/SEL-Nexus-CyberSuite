import json

from fastapi.testclient import TestClient

from portal import app as portal_app
from portal import fixproxy
from portal.audit import AuditLog
from portal.config import Settings


def _settings(tmp_path):
    for uc in ("uc1", "uc3", "uc4"):
        (tmp_path / uc).mkdir()
    return Settings(uc1_dir=tmp_path / "uc1", uc3_dir=tmp_path / "uc3", uc4_dir=tmp_path / "uc4", auth_mode="off",
                    auth_dir=tmp_path / "auth", audit_dir=tmp_path / "audit")


def test_chain_verifies_and_catches_an_edit(tmp_path):
    log = AuditLog(tmp_path)
    for i in range(3):
        log.record({"email": "a@x.com", "name": "A"}, "fix.approve", target=f"item {i}")
    assert log.verify() == {**log.verify(), "ok": True, "count": 3}
    lines = log.path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["user_email"] = "someone-else@x.com"
    lines[1] = json.dumps(row)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = log.verify()
    assert not result["ok"] and result["broken_at"] == 2


def test_removed_line_breaks_the_chain(tmp_path):
    log = AuditLog(tmp_path)
    for i in range(3):
        log.record(None, "run.start", target=str(i))
    lines = log.path.read_text(encoding="utf-8").splitlines()
    log.path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert log.verify()["broken_at"] == 2


def test_remediation_action_is_recorded_with_who_and_what(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    fix_dir = settings.uc1_dir / "data" / "fix"
    fix_dir.mkdir(parents=True)
    (fix_dir / "plan.json").write_text(json.dumps({"items": [{"fix_id": "fx_1", "app": "Mozilla Firefox", "device_name": "wks-01"}]}))
    monkeypatch.setattr(fixproxy, "post_fix", lambda base, action, body: (200, {"ok": True}))
    client = TestClient(portal_app.create_app(settings))

    assert client.post("/api/fix/approve", json={"ids": ["fx_1"], "method": "runcommand"}, headers={"X-Portal": "fix"}).status_code == 200
    assert client.post("/api/fix/approve", json={"ids": ["fx_1"]}).status_code == 403   # no header: not an action, not logged

    assert AuditLog(settings.audit_dir).verify()["count"] == 1
    rows = [i for i in client.get("/api/activity").json()["items"] if i["source"] == "audit"]   # not the portal's real run history
    row = rows[0]
    assert len(rows) == 1 and row["label"] == "Approved remediation" and row["name"] == "Local user"
    assert row["target"] == "Mozilla Firefox on wks-01" and "runcommand" in row["detail"]


def test_refused_run_is_recorded(tmp_path):
    client = TestClient(portal_app.create_app(_settings(tmp_path)))
    assert client.post("/api/runs/uc3", headers={"X-Portal": "run"}).status_code == 409   # no Python environment
    row = client.get("/api/activity").json()["items"][0]
    assert row["action"] == "run.refused" and row["agent"] == "Vulnerability Agent" and row["outcome"] == "refused"
    assert client.get("/api/audit").status_code != 200   # the Audit log is gone


def test_activity_log_lists_agent_runs_and_actions(tmp_path):
    settings = _settings(tmp_path)
    settings.auth_dir.mkdir()
    (settings.auth_dir / "signins.jsonl").write_text(json.dumps({"at": "2026-01-01T00:00:00+00:00", "event": "login", "email": "a@x.com"}) + "\n")
    log = AuditLog(settings.audit_dir)
    log.record({"email": "ana@x.com", "name": "Ana"}, "run.start", agent="Threat Intelligence Agent", ref="20260101_000000_uc1")
    log.record({"email": "bo@x.com", "name": "Bo"}, "fix.approve", target="Mozilla Firefox on wks-01")
    client = TestClient(portal_app.create_app(settings))

    items = [i for i in client.get("/api/activity").json()["items"] if i["source"] == "audit"]
    assert [i["action"] for i in items] == ["fix.approve", "run.start"]
    run = items[1]
    assert run["name"] == "Ana" and run["email"] == "ana@x.com" and run["agent"] == "Threat Intelligence Agent"
    assert run["run"] == "20260101_000000_uc1" and run["label"] == "Started a pipeline run" and run["ts"]

    assert [i["name"] for i in client.get("/api/activity?action=run").json()["items"] if i["source"] == "audit"] == ["Ana"]
    assert [i["name"] for i in client.get("/api/activity?q=firefox").json()["items"]] == ["Bo"]


def test_activity_log_includes_history_from_before_the_trail(tmp_path):
    from portal import activity
    runs_dir = tmp_path / "runs" / "20261009_124626_uc1"
    runs_dir.mkdir(parents=True)
    (runs_dir / "meta.json").write_text(json.dumps({"uc": "uc1", "started_at": "2026-10-09T07:16:26+00:00", "by": "portal"}))
    (runs_dir / "result.json").write_text(json.dumps({"exit_code": 1, "finished_at": "2026-10-09T07:20:00+00:00"}))
    fix_dir = tmp_path / "uc1" / "data" / "fix"
    fix_dir.mkdir(parents=True)
    (fix_dir / "state.json").write_text(json.dumps({"fixes": {"fx_1": {
        "status": "verified", "method": "runcommand", "approved_by": "2868006", "approved_at": "2026-10-06T05:52:38",
        "finished_at": "2026-10-06T06:00:42", "message": "Updated", "item": {"app": "WinRAR", "device_name": "opca-wks-01"}}}}))
    trail = AuditLog(tmp_path / "audit")
    trail.record({"email": "ana@x.com", "name": "Ana"}, "run.start", agent="Threat Intel Agent", ref="20261028_120000_uc1")

    data = activity.listing(trail.entries(), tmp_path / "runs", tmp_path / "uc1")
    assert [i["action"] for i in data["items"]] == ["run.start", "run.finish", "run.start", "fix.run", "fix.approve"]
    finished = data["items"][1]
    assert finished["agent"] == "Threat Intel Agent" and finished["outcome"] == "failed" and finished["name"] == "Not recorded"
    approve = data["items"][-1]
    assert approve["name"] == "2868006" and approve["target"] == "WinRAR on opca-wks-01" and approve["ts"].startswith("2026-10-06T05:52:38")
    assert data["items"][3]["outcome"] == "success"
    assert activity.listing(trail.entries(), tmp_path / "runs", tmp_path / "uc1", action="fix")["total"] == 2
