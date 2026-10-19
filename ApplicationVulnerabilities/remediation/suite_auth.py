"""Shared SEL Nexus CyberSuite sign-in: who is looking at the Application Vulnerabilities site.

People sign in once on the suite's sign-in page (../login, http://127.0.0.1:8000). It sets a signed, HttpOnly
`portal_session` cookie that every module on 127.0.0.1 receives, because browsers share cookies between ports of
the same host. This module only *checks* that cookie with the suite's key (login/data/auth/session.key); it never
creates accounts or cookies of its own. The format matches login/accounts.py (`Sessions.read`).

Switched on by SUITE_LOGIN_URL (the Start script sets it). Empty = no shared sign-in (local use, tests).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from pathlib import Path

COOKIE = "portal_session"


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class SuiteSessions:
    """Reads the suite's session cookie. The key file is re-read when it changes (or first appears, if the sign-in
    page starts after this site), so deleting it on the sign-in page signs people out here too."""

    def __init__(self, auth_dir: Path):
        self.key_path = Path(auth_dir) / "session.key"
        self._key: bytes | None = None
        self._mtime: float | None = None
        self._lock = threading.Lock()

    def _current_key(self) -> bytes | None:
        try:
            mtime = self.key_path.stat().st_mtime
        except OSError:
            return None
        with self._lock:
            if self._key is None or mtime != self._mtime:
                try:
                    self._key = _unb64(self.key_path.read_text(encoding="utf-8").strip())
                    self._mtime = mtime
                except (OSError, ValueError):
                    return None
            return self._key

    def read(self, token: str | None) -> dict | None:
        if not token or token.count(".") != 1:
            return None
        key = self._current_key()
        if key is None:
            return None
        body, sig = token.split(".")
        expected = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            data = json.loads(_unb64(body))
        except ValueError:
            return None
        if not isinstance(data, dict) or int(data.get("exp", 0)) < time.time():
            return None
        return {"email": data.get("sub"), "name": data.get("name"), "via": data.get("via"), "expires": data.get("exp")}
