"""The portal's Fix Centre talks to UC1's own fix engine through UC1's website API (no copied code).

UC1 keeps the plan, the approvals, the safety rules and the one-fixer-at-a-time lock; the portal only forwards
requests to it: GET /api/fix (plan + approvals + results + what the fixer is doing) and POST /api/fix/approve |
unapprove | save | unsave | run | probe with UC1's header X-UC1: fix. Only the fields UC1 expects are forwarded (ids, method),
plus `by`: the signed-in person's name, taken from the session (never from the browser's request body).
If The fix engine is not running, the portal can start it with UC1's own Python (127.0.0.1 only).

People, not computer accounts: before the portal passed `by`, UC1 wrote the Windows login of the machine it runs on
("Approved by 2862390"). named() swaps such an account for the person the activity trail (audit.py) recorded for the
same action at the same moment, or leaves the name out when nobody was recorded.
"""
from __future__ import annotations

import getpass
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

ACTIONS = {"approve", "unapprove", "save", "unsave", "run", "probe"}
METHODS = {"runcommand", "liveresponse"}
MATCH_S = 120     # an audit line this close to UC1's own timestamp is the same click


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


def post_fix(base: str, action: str, body: dict, by: str | None = None) -> tuple[int, dict]:
    if action not in ACTIONS:
        return 404, {"error": "unknown action"}
    clean: dict = {"ids": [str(i) for i in body.get("ids", []) if isinstance(i, str)][:200]}
    if body.get("method") in METHODS:
        clean["method"] = body["method"]
    if by:
        clean["by"] = by[:80]
    return _call(base, f"/api/fix/{action}", clean, timeout=30)


def _machine_accounts() -> set[str]:
    try:
        me = getpass.getuser().lower()
    except Exception:  # noqa: BLE001
        me = ""
    return {a for a in (me, "unknown", "portal", "system") if a}


_ACCOUNTS = _machine_accounts()
# UC1's event texts that carry a person: "Approved by X (Azure Run Command): …", "Saved for later by X: …"
_BY = re.compile(r"^(Approved|Saved for later|Approval withdrawn|No longer saved for later) by (.+?)(?= \(|: )")
_EVENT_ACTION = {"Approved": "fix.approve", "Saved for later": "fix.save",
                 "Approval withdrawn": "fix.unapprove", "No longer saved for later": "fix.unsave"}


def is_account(who) -> bool:
    """A computer login (this machine's account, an employee number), not a person's name."""
    w = str(who or "").strip().lower()
    return bool(w) and (w in _ACCOUNTS or w.isdigit())


def _when(value) -> float | None:
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp()   # UC1 writes UTC without a zone


def named(view: dict, audit_rows: Callable[[], list[dict]]) -> dict:
    """The fix view with every approver / saver shown as the person, never as a computer account (see top)."""
    rows, events = view.get("rows") or [], view.get("events") or []
    if not (any(is_account(r.get(k)) for r in rows for k in ("approved_by", "saved_by"))
            or any((m := _BY.match(str(e.get("text") or ""))) and is_account(m.group(2)) for e in events)):
        return view                                   # nothing old to translate: skip reading the trail
    clicks = [(t, r.get("action"), str(r.get("user_name")))
              for r in audit_rows() if r.get("outcome") == "success" and str(r.get("action", "")).startswith("fix.")
              and r.get("user_name") and r.get("user_name") != "Unknown" and (t := _when(r.get("at"))) is not None]

    def person(action: str, at) -> str | None:
        t = _when(at) if at else None
        if t is None:
            return None
        near = [(abs(c - t), name) for c, a, name in clicks if a == action and abs(c - t) <= MATCH_S]
        return min(near)[1] if near else None

    out_rows = []
    for r in rows:
        r = dict(r)
        for key, at, action in (("approved_by", "approved_at", "fix.approve"), ("saved_by", "saved_at", "fix.save")):
            if is_account(r.get(key)):
                r[key] = person(action, r.get(at))
        out_rows.append(r)
    out_events = []
    for e in events:
        m = _BY.match(str(e.get("text") or ""))
        if m and is_account(m.group(2)):
            name = person(_EVENT_ACTION[m.group(1)], e.get("at"))
            e = {**e, "text": m.group(1) + (f" by {name}" if name else "") + e["text"][m.end():]}
        out_events.append(e)
    return {**view, "rows": out_rows, "events": out_events}


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
