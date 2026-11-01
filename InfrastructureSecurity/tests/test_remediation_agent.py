"""The Remediation Agent retries a failed remediation under the original approval, only with the allowed moves, and an
update that no source can make newer ends as awaiting_vendor instead of failed. Runs in the Threat Intel Agent's
Python with a fake computer and a fake model, so nothing reaches Azure, Defender or a VM."""
from __future__ import annotations

import json
import subprocess

import pytest

from layout import part_dir, python

SCRIPT = r'''
import json, sys, tempfile, threading
from pathlib import Path
from types import SimpleNamespace
from threat_intel.fix.runner import FixRunner
from threat_intel.fix.state import FixState

def app(version):
    return {"name": "Mozilla Firefox (x64 en-US)", "version": version}

# what the fake computer reports per engine, for each scenario
SCENARIOS = {
    "vendor": {"winget": {"exit": 0, "no_newer": True, "available": "157.0.1", "before": app("157.0.1"), "after": app("157.0.1")},
               "choco": {"exit": 0, "before": app("157.0.1"), "after": app("157.0.1")}},
    "first_ok": {"winget": {"exit": 0, "before": app("115.0"), "after": app("157.0.1")}},
    "choco_ok": {"winget": {"exit": -1978335224, "before": app("115.0"), "after": app("115.0")},
                 "choco": {"exit": 0, "before": app("115.0"), "after": app("157.0.2")}},
    "not_found": {"winget": {"exit": -995, "not_found": True, "before": [], "after": []}},
}

class Computer:
    def __init__(self, replies):
        self.replies, self.engines = replies, []
    def run(self, device, device_id, spec, say):
        engine = spec.get("engine") or "winget"
        self.engines.append(engine)
        return "FIXRESULT " + json.dumps({**self.replies[engine], "action": spec["action"]})

class Model:
    def __init__(self, moves):
        self.moves, self.calls = list(moves), 0
    def json(self, purpose, system, prompt, schema, max_tokens=0):
        self.calls += 1
        assert "{moves}" not in system and "{max_moves}" not in system
        action, summary = self.moves.pop(0)
        return schema(action=action, reason="Model reason", summary=summary)

def run(name, model_moves, ai=True):
    tmp = Path(tempfile.mkdtemp())
    state = FixState(tmp / "state.json")
    item = {"fix_id": "fx_1", "device_name": "opcc-wks-01", "device_id": "d1", "action": "upgrade",
            "app": "Mozilla Firefox", "version": "157.0.1.0", "findings": 247, "stage": 1,
            "winget_id": "Mozilla.Firefox", "choco_id": "firefox", "match": "Mozilla Firefox*"}
    with state.edit() as data:
        data["fixes"]["fx_1"] = {"status": "approved", "item": item, "method": "runcommand",
                                 "spec": {"action": "upgrade", "winget": "Mozilla.Firefox", "choco": "firefox"}}
    computer, model = Computer(SCENARIOS[name]), Model(model_moves)
    r = FixRunner.__new__(FixRunner)
    r.settings = SimpleNamespace(fix_method="runcommand", fix_allow_choco=True, fix_dir=tmp)
    r.ai, r.state, r.on_step, r._executors, r._lock = (model if ai else None), state, (lambda t: None), {}, threading.Lock()
    r.factory = lambda method, settings: computer
    r._device_worker("opcc-wks-01", [("fx_1", state.read()["fixes"]["fx_1"])], {})
    f = state.read()["fixes"]["fx_1"]
    out = {"status": f["status"], "message": f["message"], "engines": computer.engines, "ai_calls": model.calls,
           "moves": [m["action"] for m in f.get("agent") or []], "handover": f.get("handover")}
    if name == "not_found":                       # then a person remediates it by hand
        from threat_intel.fix import plan
        settings = SimpleNamespace(fix_dir=tmp)
        out["marked"] = plan.mark_manual(settings, ["fx_1"], "Lavanya", "Removed with the vendor uninstaller")
        g = state.read()
        out["after_manual"] = {k: g["fixes"]["fx_1"].get(k) for k in ("status", "manual")}
        out["events"] = [e["text"] for e in g.get("events") or []]
        # approving it again starts a new attempt: the earlier one and the fix's own trail are kept for its record
        (tmp / "plan.json").write_text(json.dumps({"items": [item]}))
        settings.fix_method, settings.fix_allow_choco = "runcommand", True
        out["reapproved"] = plan.approve(settings, ["fx_1"], who="Lavanya")
        d = plan.detail(settings, "fx_1")
        out["detail"] = {"status": d["row"]["status"], "attempts": [x.get("status") for x in d["attempts"]],
                         "trail": len(d["trail"]), "allowed": d["allowed"]}
    return out

out = {
    "vendor_ai": run("vendor", [("choco", ""), ("stop", "No newer Firefox build is published yet.")]),
    "vendor_no_ai": run("vendor", [], ai=False),
    "first_ok": run("first_ok", []),
    "choco_ok": run("choco_ok", [("choco", "")]),
    "bad_move": run("choco_ok", [("powershell -c evil", "")]),
    "not_found": run("not_found", []),
}
print(json.dumps(out))
'''


@pytest.fixture(scope="module")
def results():
    py = python("threat_intel")
    if not py.exists():
        pytest.skip("threat_intel has no .venv yet")
    done = subprocess.run([str(py), "-c", SCRIPT], cwd=part_dir("threat_intel"), capture_output=True, text=True,
                          timeout=120)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_no_newer_version_anywhere_is_awaiting_vendor(results):
    r = results["vendor_ai"]
    assert r["status"] == "awaiting_vendor"
    assert r["engines"] == ["winget", "choco"]
    assert r["moves"] == ["winget", "choco", "stop"]
    assert r["message"].startswith("No newer Firefox build is published yet.")
    assert "Awaiting vendor package" in r["message"]


def test_without_ai_the_ladder_runs_and_ends_awaiting_vendor(results):
    r = results["vendor_no_ai"]
    assert r["status"] == "awaiting_vendor" and r["engines"] == ["winget", "choco"] and r["ai_calls"] == 0


def test_success_on_the_first_attempt_never_calls_the_model(results):
    r = results["first_ok"]
    assert r["status"] == "done" and r["engines"] == ["winget"] and r["ai_calls"] == 0


def test_model_picks_the_retry_that_fixes_it(results):
    r = results["choco_ok"]
    assert r["status"] == "done" and r["engines"] == ["winget", "choco"]


def test_a_move_outside_the_list_becomes_the_standard_move(results):
    assert results["bad_move"]["engines"] == ["winget", "choco"]


def test_nothing_installed_is_not_retried_and_goes_to_a_person(results):
    r = results["not_found"]
    assert r["status"] == "manual_required" and r["engines"] == ["winget"]
    h = r["handover"]
    assert h["owner"] == "IT operations" and len(h["steps"]) >= 3 and "exit code -995" in h["evidence"]
    assert any(e.startswith("Manual action required: Mozilla Firefox on opcc-wks-01") for e in r["events"])


def test_a_person_marks_it_done_and_it_is_logged(results):
    r = results["not_found"]
    assert r["marked"] == {"marked": ["fx_1"], "skipped": []}
    assert r["after_manual"]["status"] == "done"
    assert r["after_manual"]["manual"]["by"] == "Lavanya"
    assert any(e.startswith("Remediated manually by Lavanya") and "vendor uninstaller" in e for e in r["events"])


def test_reapproval_keeps_earlier_attempts_and_the_trail(results):
    d = results["not_found"]["detail"]
    assert results["not_found"]["reapproved"]["approved"] == ["fx_1"]
    assert d["status"] == "approved" and d["attempts"] == ["done"]
    assert d["trail"] >= 4                                 # approve, attempt, handover, manual, approve again
    assert d["allowed"]["winget"] == "Mozilla.Firefox"


def test_a_no_fix_item_is_handed_to_a_person():
    """No automatic fix (action none): a person hands it over, it becomes manual_required with steps and an owner."""
    py = python("threat_intel")
    if not py.exists():
        pytest.skip("threat_intel has no .venv yet")
    script = r"""
import json, tempfile
from pathlib import Path
from types import SimpleNamespace
from threat_intel.fix import plan
tmp = Path(tempfile.mkdtemp())
item = {"fix_id": "fx_000000000001", "device_name": "opcc-wks-01", "app": "log4j", "version": "2.14.1.0", "action": "none",
        "note": "No remediation defined yet: add a row to config/fix_catalog.csv to enable automated remediation"}
(tmp / "plan.json").write_text(json.dumps({"items": [item]}))
s = SimpleNamespace(fix_dir=tmp)
out = {"handed": plan.hand_over(s, ["fx_000000000001"], "Lavanya")}
out["again"] = plan.hand_over(s, ["fx_000000000001"], "Lavanya")
d = plan.detail(s, "fx_000000000001")
out["row"] = {k: d["row"].get(k) for k in ("status", "handed_by")}
out["owner"] = d["row"]["handover"]["owner"]; out["steps"] = len(d["row"]["handover"]["steps"])
out["marked"] = plan.mark_manual(s, ["fx_000000000001"], "Lavanya", "Deleted C:/LabApps/log4j")
out["trail"] = [e["text"] for e in plan.detail(s, "fx_000000000001")["trail"]]
print(json.dumps(out))
"""
    done = subprocess.run([str(py), "-c", script], cwd=part_dir("threat_intel"), capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    r = json.loads(done.stdout.strip().splitlines()[-1])
    assert r["handed"] == {"handed": ["fx_000000000001"], "skipped": []}
    assert r["again"]["skipped"] == ["fx_000000000001"]          # already with a person: not handed twice
    assert r["row"] == {"status": "manual_required", "handed_by": "Lavanya"}
    assert r["owner"] == "IT operations" and r["steps"] == 3
    assert r["marked"]["marked"] == ["fx_000000000001"]
    assert r["trail"][0].startswith("Handed to a person by Lavanya") and r["trail"][1].startswith("Remediated manually by Lavanya")
