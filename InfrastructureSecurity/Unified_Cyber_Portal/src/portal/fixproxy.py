"""The portal's Fix Centre talks to UC1's own fix engine through UC1's website API (no copied code).

UC1 keeps the plan, the approvals, the safety rules and the one-fixer-at-a-time lock; the portal only forwards
requests to it: GET /api/fix (plan + approvals + results + what the fixer is doing) and POST /api/fix/approve |
unapprove | save | unsave | run | probe with UC1's header X-UC1: fix. Only the fields UC1 expects are forwarded (ids, method).
If The fix engine is not running, the portal can start it with UC1's own Python (127.0.0.1 only).
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ACTIONS = {"approve", "unapprove", "save", "unsave", "run", "probe"}
METHODS = {"runcommand", "liveresponse"}


class Uc1Unavailable(RuntimeError):
    pass


def _call(base: str, path: str, body: dict | None = None, timeout: float = 15) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Host": "127.0.0.1", "Content-Type": "application/json"}
    if body is not None:
        headers["X-UC1"] = "fix"
    req = urllib.request.Request(base.rstrip("/") + path, data=data, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": f"The fix engine answered {e.code}"}
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        raise Uc1Unavailable(f"The fix engine is not running at {base} ({getattr(e, 'reason', e)})") from e


def get_fix(base: str) -> dict:
    status, body = _call(base, "/api/fix")
    if status != 200:
        raise Uc1Unavailable(body.get("error") or f"The fix engine answered {status}")
    return body


def post_fix(base: str, action: str, body: dict) -> tuple[int, dict]:
    if action not in ACTIONS:
        return 404, {"error": "unknown action"}
    clean: dict = {"ids": [str(i) for i in body.get("ids", []) if isinstance(i, str)][:200]}
    if body.get("method") in METHODS:
        clean["method"] = body["method"]
    return _call(base, f"/api/fix/{action}", clean, timeout=30)


def start_uc1_site(uc1_dir: Path, base: str, wait_s: float = 12) -> bool:
    """Start UC1's service (python -m uc1 serve) in the background and wait until it answers."""
    python = uc1_dir / ".venv" / "Scripts" / "python.exe"
    if not python.is_file():
        python = uc1_dir / ".venv" / "bin" / "python"
    if not python.is_file():
        raise Uc1Unavailable(f"The fix engine has no Python environment at {uc1_dir / '.venv'}")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    subprocess.Popen([str(python), "-m", "uc1", "serve"], cwd=str(uc1_dir), creationflags=flags,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        try:
            get_fix(base)
            return True
        except Uc1Unavailable:
            time.sleep(0.5)
    return False
