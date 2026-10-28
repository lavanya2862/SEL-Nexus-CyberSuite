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

    data = client.get("/api/audit").json()
    assert data["integrity"]["ok"] and data["integrity"]["count"] == 1
    row = data["entries"][0]
    assert row["label"] == "Approved remediation" and row["user_name"] == "Local user"
    assert row["target"] == "Mozilla Firefox on wks-01" and "runcommand" in row["detail"]


def test_refused_run_is_recorded(tmp_path):
    client = TestClient(portal_app.create_app(_settings(tmp_path)))
    assert client.post("/api/runs/uc3", headers={"X-Portal": "run"}).status_code == 409   # no Python environment
    row = client.get("/api/audit").json()["entries"][0]
    assert row["action"] == "run.refused" and row["agent"] == "Vulnerability Agent" and row["outcome"] == "refused"
