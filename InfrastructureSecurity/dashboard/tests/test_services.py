"""The service watcher restarts a service that holds its port but no longer answers its API."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from dashboard import services


@pytest.fixture
def stuck(tmp_path, monkeypatch):
    """A fixing service that listens on its port but drops every API request, until it is stopped and relaunched."""
    threat_intel = tmp_path / "threat_intel"
    (threat_intel / ".venv" / "Scripts").mkdir(parents=True)
    (threat_intel / ".venv" / "Scripts" / "python.exe").write_text("")
    state = {"up": True, "answers": False, "killed": [], "launched": 0,
             "owner": (4242, f"{threat_intel}\\.venv\\Scripts\\python.exe -m threat_intel serve")}

    def kill(pid, sig):
        state["killed"].append(pid)
        state["up"] = False

    def launch(cmd, cwd):
        state["launched"] += 1
        state["up"] = state["answers"] = True

    monkeypatch.setattr(services, "listening", lambda base, timeout=1.0: state["up"])
    monkeypatch.setattr(services, "answering", lambda name, base: state["answers"])
    monkeypatch.setattr(services, "_port_owner", lambda base: state["owner"])
    monkeypatch.setattr(services.os, "kill", kill)
    monkeypatch.setattr(services, "_launch", launch)
    monkeypatch.setattr(services, "_strikes", {})
    settings = SimpleNamespace(fix_site="http://127.0.0.1:8700", threat_intel_dir=threat_intel,
                               triage_site="http://127.0.0.1:8800", alert_triage_dir=tmp_path / "alert_triage")
    return settings, state


def test_restarts_after_repeated_failed_checks(stuck):
    settings, state = stuck
    assert services.start_one(settings, "fixing") is False      # first failed check: give it another chance
    assert state["killed"] == [] and state["launched"] == 0
    assert services.start_one(settings, "fixing") is True       # second: stop the stuck copy, start a fresh one
    assert state["killed"] == [4242] and state["launched"] == 1
    assert services.start_one(settings, "fixing") is True       # healthy again: nothing more to do
    assert state["launched"] == 1


def test_healthy_check_resets_strikes(stuck):
    settings, state = stuck
    services.start_one(settings, "fixing")
    state["answers"] = True
    assert services.start_one(settings, "fixing") is True
    state["answers"] = False
    assert services.start_one(settings, "fixing") is False
    assert state["killed"] == []


def test_leaves_another_program_on_the_port_alone(stuck):
    settings, state = stuck
    state["owner"] = (777, r"C:\Program Files\something\else.exe --port 8700")
    for _ in range(3):
        assert services.start_one(settings, "fixing") is False
    assert state["killed"] == [] and state["launched"] == 0


def test_never_stops_the_fixer_while_it_runs_remediations(stuck):
    settings, state = stuck
    (settings.threat_intel_dir / "data" / "fix").mkdir(parents=True)
    (settings.threat_intel_dir / "data" / "fix" / ".fix.lock").write_text("4242")
    for _ in range(3):
        assert services.start_one(settings, "fixing") is False
    assert state["killed"] == []
