import json

from fastapi.testclient import TestClient

from dashboard import app as portal_app
from dashboard import fixproxy
from dashboard.audit import AuditLog
from dashboard.config import Settings


def _settings(tmp_path):
    for uc in ("threat_intel", "vulnerability", "alert_triage"):
        (tmp_path / uc).mkdir()
    return Settings(threat_intel_dir=tmp_path / "threat_intel", vulnerability_dir=tmp_path / "vulnerability", alert_triage_dir=tmp_path / "alert_triage", auth_mode="off",
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
    fix_dir = settings.threat_intel_dir / "data" / "fix"
    fix_dir.mkdir(parents=True)
    (fix_dir / "plan.json").write_text(json.dumps({"items": [{"fix_id": "fx_1", "app": "Mozilla Firefox", "device_name": "wks-01"}]}))
    sent = []
    monkeypatch.setattr(fixproxy, "post_fix", lambda base, action, body, by=None: (sent.append(by), (200, {"ok": True}))[1])
    client = TestClient(portal_app.create_app(settings))

    assert client.post("/api/fix/approve", json={"ids": ["fx_1"], "method": "runcommand", "by": "Mallory"},
                       headers={"X-Portal": "fix"}).status_code == 200
    assert sent == ["Local user"]   # the signed-in person goes to Threat Intel, never a name the browser sends
    assert client.post("/api/fix/approve", json={"ids": ["fx_1"]}).status_code == 403   # no header: not an action, not logged

    assert AuditLog(settings.audit_dir).verify()["count"] == 1
    rows = [i for i in client.get("/api/activity").json()["items"] if i["source"] == "audit"]   # not the portal's real run history
    row = rows[0]
    assert len(rows) == 1 and row["label"] == "Approved remediation" and row["name"] == "Local user"
    assert row["target"] == "Mozilla Firefox on wks-01" and "runcommand" in row["detail"]


def test_refused_run_is_recorded(tmp_path):
    client = TestClient(portal_app.create_app(_settings(tmp_path)))
    assert client.post("/api/runs/vulnerability", headers={"X-Portal": "run"}).status_code == 409   # no Python environment
    row = client.get("/api/activity").json()["items"][0]
    assert row["action"] == "run.refused" and row["agent"] == "Vulnerability Agent" and row["outcome"] == "refused"
    assert client.get("/api/audit").status_code != 200   # the Audit log is gone


def test_activity_log_lists_agent_runs_and_actions(tmp_path):
    settings = _settings(tmp_path)
    settings.auth_dir.mkdir()
    (settings.auth_dir / "signins.jsonl").write_text(json.dumps({"at": "2026-01-01T00:00:00+00:00", "event": "login", "email": "a@x.com"}) + "\n")
    log = AuditLog(settings.audit_dir)
    log.record({"email": "ana@x.com", "name": "Ana"}, "run.start", agent="Threat Intelligence Agent", ref="20260101_000000_threat_intel")
    log.record({"email": "bo@x.com", "name": "Bo"}, "fix.approve", target="Mozilla Firefox on wks-01")
    client = TestClient(portal_app.create_app(settings))

    items = [i for i in client.get("/api/activity").json()["items"] if i["source"] == "audit"]
    assert [i["action"] for i in items] == ["fix.approve", "run.start"]
    run = items[1]
    assert run["name"] == "Ana" and run["email"] == "ana@x.com" and run["agent"] == "Threat Intelligence Agent"
    assert run["run"] == "20260101_000000_threat_intel" and run["label"] == "Started a pipeline run" and run["ts"]

    assert [i["name"] for i in client.get("/api/activity?action=run").json()["items"] if i["source"] == "audit"] == ["Ana"]
    assert [i["name"] for i in client.get("/api/activity?q=firefox").json()["items"]] == ["Bo"]


def test_activity_log_includes_history_from_before_the_trail(tmp_path):
    from dashboard import activity
    runs_dir = tmp_path / "runs" / "20261009_124626_threat_intel"
    runs_dir.mkdir(parents=True)
    (runs_dir / "meta.json").write_text(json.dumps({"uc": "threat_intel", "started_at": "2026-10-09T07:16:26+00:00", "by": "portal"}))
    (runs_dir / "result.json").write_text(json.dumps({"exit_code": 1, "finished_at": "2026-10-09T07:20:00+00:00"}))
    fix_dir = tmp_path / "threat_intel" / "data" / "fix"
    fix_dir.mkdir(parents=True)
    (fix_dir / "state.json").write_text(json.dumps({"fixes": {"fx_1": {
        "status": "verified", "method": "runcommand", "approved_by": "2868006", "approved_at": "2026-10-06T05:52:38",
        "finished_at": "2026-10-06T06:00:42", "message": "Updated", "item": {"app": "WinRAR", "device_name": "opca-wks-01"}}}}))
    trail = AuditLog(tmp_path / "audit")
    trail.record({"email": "ana@x.com", "name": "Ana"}, "run.start", agent="Threat Intel Agent", ref="20261028_120000_threat_intel")

    data = activity.listing(trail.entries(), tmp_path / "runs", tmp_path / "threat_intel")
    assert [i["action"] for i in data["items"]] == ["run.start", "run.finish", "run.start", "fix.run", "fix.approve"]
    finished = data["items"][1]
    assert finished["agent"] == "Threat Intel Agent" and finished["outcome"] == "failed" and finished["name"] == "Not recorded"
    approve = data["items"][-1]
    assert approve["name"] == "Not recorded" and approve["target"] == "WinRAR on opca-wks-01" and approve["ts"].startswith("2026-10-06T05:52:38")
    assert data["items"][3]["outcome"] == "success"
    assert activity.listing(trail.entries(), tmp_path / "runs", tmp_path / "threat_intel", action="fix")["total"] == 2


def test_fix_view_shows_people_not_computer_accounts(tmp_path):
    trail = AuditLog(tmp_path)
    trail.record({"email": "lav@x.com", "name": "Lavanya"}, "fix.approve", target="PuTTY on wks-01")
    at = trail.entries()[0]["at"][:19]   # Threat Intel writes UTC without a zone
    view = {"rows": [{"fix_id": "fx_1", "approved_by": "2862390", "approved_at": at},
                     {"fix_id": "fx_2", "saved_by": "2862390", "saved_at": "2026-01-01T00:00:00"},
                     {"fix_id": "fx_3", "approved_by": "Bo", "approved_at": at}],
            "events": [{"at": at, "fix_id": "fx_1", "text": "Approved by 2862390 (Azure Run Command): PuTTY 0.76 on wks-01"},
                       {"at": "2026-01-01T00:00:00", "fix_id": "fx_2", "text": "Saved for later by 2862390: Disable Autoplay on wks-02"},
                       {"at": at, "fix_id": "fx_3", "text": "Approved by Bo (Azure Run Command): WinRAR on wks-03"},
                       {"at": at, "fix_id": "fx_1", "text": "wks-01: upgrade PuTTY 0.76 via runcommand"}]}

    out = fixproxy.named(view, trail.entries)
    assert [r.get("approved_by") or r.get("saved_by") for r in out["rows"]] == ["Lavanya", None, "Bo"]
    assert [e["text"] for e in out["events"]] == [
        "Approved by Lavanya (Azure Run Command): PuTTY 0.76 on wks-01",
        "Saved for later: Disable Autoplay on wks-02",            # nobody recorded that long ago: no name, not the login
        "Approved by Bo (Azure Run Command): WinRAR on wks-03",
        "wks-01: upgrade PuTTY 0.76 via runcommand"]
    clean = {"rows": [view["rows"][2]], "events": [view["events"][2]]}
    assert fixproxy.named(clean, lambda: 1 / 0) == clean     # nothing to translate: the trail is not read
