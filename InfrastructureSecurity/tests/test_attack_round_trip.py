"""The Attack Detection split, end to end on copies of both databases (no Defender, no AI, nothing sent):

Threat Intel publishes hunt_inputs.json -> Attack Detection loads it and publishes findings.json -> Threat Intel imports
that and rebuilds its dashboard data, which must keep its shape (the Attack detection page reads it).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from layout import part_dir, python
from shape import check, shape


def _run(part: str, code: str, env: dict) -> None:
    done = subprocess.run([str(python(part)), "-c", code], cwd=part_dir(part), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=600, env={**os.environ, "PYTHONIOENCODING": "utf-8", **env})
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-3000:]


def test_attack_detection_round_trip(tmp_path):
    ti_db = part_dir("threat_intel") / "data" / "threat_intel.duckdb"
    ad_db = part_dir("attack_detection") / "data" / "attack_detection.duckdb"
    if not (python("threat_intel").exists() and python("attack_detection").exists() and ti_db.exists() and ad_db.exists()):
        pytest.skip("both agents need a .venv and data on this computer")
    ti, ad = tmp_path / "ti", tmp_path / "ad"
    (ti / "data").mkdir(parents=True)
    (ad / "data").mkdir(parents=True)
    shutil.copy2(ti_db, ti / "data" / ti_db.name)
    shutil.copy2(ad_db, ad / "data" / ad_db.name)
    for side in (ti, ad):            # the copies point at each other, like the real folders do
        (side / ".venv").mkdir()
    ti_env = {"THREAT_INTEL_DATA_DIR": str(ti / "data"), "THREAT_INTEL_ATTACK_AGENT_DIR": str(ad)}
    ad_env = {"ATTACK_DATA_DIR": str(ad / "data"), "ATTACK_THREAT_INTEL_DIR": str(ti)}

    _run("threat_intel", "from threat_intel.config import load_settings; from threat_intel.store import Store; "
         "from threat_intel import hunt_inputs; s = load_settings(); hunt_inputs.write(Store(s.db_path), s)", ti_env)
    _run("attack_detection", "from attack_detection.config import load_settings; from attack_detection.store import Store; "
         "from attack_detection import inputs, publish; s = load_settings(); st = Store(s.db_path); "
         "r = inputs.load(st, s); assert r['loaded'], r; publish.write(st, s, None)", ad_env)
    _run("threat_intel", "from threat_intel.config import load_settings; from threat_intel.store import Store; "
         "from threat_intel import attack_import, dashboard; s = load_settings(); st = Store(s.db_path); "
         "r = attack_import.run(st, s); assert r['imported'], r; dashboard.build(st, s)", ti_env)

    published = json.loads((ad / "data" / "out" / "findings.json").read_text(encoding="utf-8"))
    assert published["schema_version"] == 1
    out = ti / "data" / "dashboard"
    shapes = {name: shape(json.loads((out / name).read_text(encoding="utf-8")))
              for name in ("dashboard_data.json", "site_data.json", "clues.json", "threat_matches.json")}
    assert check("rebuild_threat_intel", {f"dashboard/{k}": v for k, v in shapes.items()}) == []
