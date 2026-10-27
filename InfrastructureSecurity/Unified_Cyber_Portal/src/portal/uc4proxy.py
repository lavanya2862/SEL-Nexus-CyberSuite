"""Triage: the analyst's agree/disagree click goes to UC4's own website API (no copied code).

UC4 keeps the feedback file, its checks and its accuracy maths; the portal only forwards POST /api/feedback with
UC4's header X-UC4: feedback, passing just the fields UC4 expects. Questions ("Ask about this incident") are forwarded
the same way to POST /api/ask (X-UC4: ask); UC4 answers from the saved evidence and changes nothing. Reopen (a person undoing an automatic close) goes to
POST /api/reopen (X-UC4: reopen). Containment
(isolating a device) is NOT forwarded: the portal is advise-only for UC4. If UC4's website is not running, the portal can start it with UC4's own Python
(127.0.0.1 only).
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

VERDICTS = {"likely_true_positive", "likely_false_positive", "benign_positive", "needs_investigation"}


class Uc4Unavailable(RuntimeError):
    pass


def _call(base: str, path: str, body: dict | None = None, timeout: float = 15, header: str = "feedback") -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Host": "127.0.0.1", "Content-Type": "application/json"}
    if body is not None:
        headers["X-UC4"] = header
    req = urllib.request.Request(base.rstrip("/") + path, data=data, headers=headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": f"UC4 answered {e.code}"}
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        raise Uc4Unavailable(f"UC4's website is not running at {base} ({getattr(e, 'reason', e)})") from e


def site_up(base: str) -> bool:
    try:
        return _call(base, "/api/status", timeout=3)[0] == 200
    except Uc4Unavailable:
        return False


def clean_feedback(body: dict) -> dict:
    """Only the fields UC4's /api/feedback reads, with simple type checks (UC4 validates again)."""
    out: dict = {"incident_id": str(body.get("incident_id") or "")[:80], "agree": body.get("agree") is True,
                 "reason": str(body.get("reason") or "")[:500], "mode": "assisted"}
    if body.get("analyst_verdict") in VERDICTS:
        out["analyst_verdict"] = body["analyst_verdict"]
    minutes = body.get("minutes")
    if isinstance(minutes, (int, float)) and not isinstance(minutes, bool) and 0 <= minutes <= 600:
        out["minutes"] = minutes
    if body.get("mode") in ("assisted", "manual"):
        out["mode"] = body["mode"]
    return out


def post_feedback(base: str, body: dict) -> tuple[int, dict]:
    clean = clean_feedback(body)
    if not clean["incident_id"]:
        return 400, {"error": "incident_id missing"}
    return _call(base, "/api/feedback", clean)


def post_ask(base: str, body: dict) -> tuple[int, dict]:
    """"Ask about this incident": UC4 answers from the incident's saved evidence (Gemini, read-only, never acts)."""
    clean = {"incident_id": str(body.get("incident_id") or "")[:80], "question": str(body.get("question") or "")[:500]}
    if not clean["incident_id"] or not clean["question"].strip():
        return 400, {"error": "incident_id or question missing"}
    return _call(base, "/api/ask", clean, timeout=60, header="ask")


def post_reopen(base: str, body: dict) -> tuple[int, dict]:
    """Undo an automatic close: UC4 reopens the incident in Defender (needs a person's click + confirm)."""
    clean = {"incident_id": str(body.get("incident_id") or "")[:80], "confirm": body.get("confirm") is True,
             "reason": str(body.get("reason") or "Reopened from the portal")[:300]}
    if not clean["incident_id"]:
        return 400, {"error": "incident_id missing"}
    return _call(base, "/api/reopen", clean, timeout=30, header="reopen")


def start_uc4_site(uc4_dir: Path, base: str, wait_s: float = 12) -> bool:
    """Start UC4's service (python -m uc4 serve) in the background and wait until it answers."""
    python = uc4_dir / ".venv" / "Scripts" / "python.exe"
    if not python.is_file():
        python = uc4_dir / ".venv" / "bin" / "python"
    if not python.is_file():
        raise Uc4Unavailable(f"UC4 has no Python environment at {uc4_dir / '.venv'}")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    subprocess.Popen([str(python), "-m", "uc4", "serve"], cwd=str(uc4_dir), creationflags=flags,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if site_up(base):
            return True
        time.sleep(0.5)
    return False
