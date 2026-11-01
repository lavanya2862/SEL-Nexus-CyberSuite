"""The Attack Detection Agent on its own, on a copy of its database (no Defender, no AI, nothing sent):

Attack Detection publishes findings.json -> the Attack detection page reads it through the dashboard adapter, and the
fix engine turns each behaviour hit into a scan-and-clean proposal. The Threat Intel Agent's database is not involved.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from layout import ROOT, part_dir, python


def _run(part: str, code: str, env: dict) -> str:
    done = subprocess.run([str(python(part)), "-c", code], cwd=part_dir(part), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=600, env={**os.environ, "PYTHONIOENCODING": "utf-8", **env})
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-3000:]
    return done.stdout


def test_attack_detection_stands_alone(tmp_path):
    ad_db = part_dir("attack_detection") / "data" / "attack_detection.duckdb"
    if not (python("threat_intel").exists() and python("attack_detection").exists() and ad_db.exists()):
        pytest.skip("both agents need a .venv and Attack Detection data on this computer")
    ad = tmp_path / "ad"
    (ad / "data").mkdir(parents=True)
    shutil.copy2(ad_db, ad / "data" / ad_db.name)
    _run("attack_detection", "from attack_detection.config import load_settings; from attack_detection.store import Store; "
         "from attack_detection import publish; s = load_settings(); publish.write(Store(s.db_path), s, None)",
         {"ATTACK_DATA_DIR": str(ad / "data")})

    published = json.loads((ad / "data" / "out" / "findings.json").read_text(encoding="utf-8"))
    assert published["schema_version"] == 1 and "devices" in published

    sys.path.insert(0, str(ROOT / "dashboard" / "src"))
    from dashboard.agents.attack_detection import AttackDetectionSource
    page = AttackDetectionSource(ad).page()
    assert page is not None and {"generated", "hits", "hunts", "devices"} <= set(page)
    assert len(page["hits"]) == len(published["findings"])

    # the fix engine reads only the published file (no Threat Intel import)
    out = _run("threat_intel", "from threat_intel.config import load_settings; from threat_intel.fix import plan; "
               "print(len(plan._attack_findings(load_settings())))", {"THREAT_INTEL_ATTACK_AGENT_DIR": str(ad)})
    behaviour = [f for f in published["findings"] if f.get("kind") == "behaviour_hit" and f.get("device_name")]
    assert int(out.strip().splitlines()[-1]) == len(behaviour)
