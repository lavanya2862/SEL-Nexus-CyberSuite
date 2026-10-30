"""Every read-only dashboard API answers, and each answer keeps its shape (keys and types, not values).

Runs the dashboard in-process against the real local data, with sign-in switched off. Endpoints that only forward
to the Fix Centre or the Alert Triage service are checked when the module runs, not here.
"""
from __future__ import annotations

import sys

import pytest

from layout import API, PARTS, part_dir
from shape import check, shape


@pytest.fixture(scope="module")
def client():
    if not (part_dir("dashboard") / ".venv").exists():
        pytest.skip("the dashboard has no .venv yet")
    sys.path.insert(0, str(part_dir("dashboard") / "src"))
    pkg = PARTS["dashboard"]["package"]
    app_module = __import__(f"{pkg}.app", fromlist=["create_app"])
    config = __import__(f"{pkg}.config", fromlist=["load_settings"])
    from fastapi.testclient import TestClient

    mp = pytest.MonkeyPatch()
    mp.setenv("PORTAL_AUTH", "off")
    settings = config.load_settings()
    mp.undo()
    with TestClient(app_module.create_app(settings)) as c:
        yield c


def _first(items, key):
    for item in items or []:
        if isinstance(item, dict) and item.get(key):
            return str(item[key])
    return None


def test_every_read_api_keeps_its_shape(client):
    fill: dict[str, str] = {}
    shapes, failures = {}, []
    for name, path in API.items():
        if "{" in path:
            needed = path[path.index("{") + 1:path.index("}")]
            if needed not in fill:
                continue
            path = path.format(**fill)
        r = client.get(path)
        if r.status_code != 200:
            failures.append(f"{name} {path}: HTTP {r.status_code} {r.text[:200]}")
            continue
        body = r.json()
        shapes[name] = shape(body)
        if name == "threat_intel.dashboard":
            fill["threat"] = _first(body.get("top"), "id") or _first(body.get("explorer"), "id") or ""
        if name == "threat_intel.matches":
            soft = body.get("counts") if isinstance(body, dict) else None
            fill["software"] = next(iter(soft), "") if isinstance(soft, dict) and soft else "firefox"
        if name == "alert_triage.queue":
            fill["incident"] = _first(body.get("queue"), "incident_id") or ""
    assert failures == []
    assert check("dashboard_api", shapes) == []
