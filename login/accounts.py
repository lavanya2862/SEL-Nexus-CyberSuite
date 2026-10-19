"""Accounts and session cookies for the SEL Nexus CyberSuite sign-in page.

One account list for the whole suite, kept in data/auth/users.json (passwords stored only as scrypt hashes). After a
good sign-in the browser gets a signed, HttpOnly `portal_session` cookie. Browsers share cookies between ports on the
same host, so every module on 127.0.0.1 (Defender & Infrastructure on :8800, Application Vulnerabilities on :8500) receives the
same cookie and checks it with the same key in data/auth/session.key.

The file formats match defender_infra/Unified_Cyber_Portal/src/portal/auth.py, which reads the same folder
(PORTAL_AUTH_DIR) to check the cookie. Change one, change the other.

Sign-in, sign-up and sign-out are written to data/auth/signins.jsonl (who, when, from where, ok or not; never a password).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

COOKIE = "portal_session"
PASSWORD_RULE = "At least 8 characters, with an upper-case letter, a lower-case letter, a number and a symbol"
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}
MAX_FAILURES = 5                      # wrong passwords per email ...
FAILURE_WINDOW = 15 * 60              # ... within this many seconds locks that email out for the rest of the window


class AuthError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def normalise_email(email: Any) -> str:
    return str(email or "").strip().lower()


def password_problem(password: str) -> str | None:
    if len(password) < 8 or len(password) > 256:
        return PASSWORD_RULE
    if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password) and re.search(r"\d", password)
            and re.search(r"[^A-Za-z0-9]", password)):
        return PASSWORD_RULE
    return None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${_b64(salt)}${_b64(digest)}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        expected = _unb64(digest)
        got = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))   # checked for unknown emails, so timing does not reveal accounts


class UserStore:
    """One JSON file, written atomically."""

    def __init__(self, folder: Path):
        self.path = folder / "users.json"
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, users: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(users, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def create(self, email: str, name: str, password: str) -> dict:
        with self._lock:
            users = self._load()
            if email in users:
                raise AuthError("An account with this email already exists. Sign in instead.", 409)
            users[email] = {"email": email, "name": name, "password": hash_password(password), "created_at": _now_iso()}
            self._save(users)
            return users[email]

    def verify(self, email: str, password: str) -> dict | None:
        user = self._load().get(email)
        ok = check_password(password, user["password"] if user else _DUMMY_HASH)
        return user if user and ok else None


class Sessions:
    """Signed session cookies: base64(payload).HMAC-SHA256 with the key in data/auth/session.key (made on first start;
    deleting it signs everybody out of every module)."""

    def __init__(self, folder: Path, hours: int):
        self.hours = hours
        self.key = self._key_file(folder / "session.key")

    @staticmethod
    def _key_file(path: Path) -> bytes:
        try:
            return _unb64(path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            path.parent.mkdir(parents=True, exist_ok=True)
            key = secrets.token_bytes(32)
            path.write_text(_b64(key), encoding="utf-8")
            return key

    def _sign(self, body: str) -> str:
        return _b64(hmac.new(self.key, body.encode(), hashlib.sha256).digest())

    def issue(self, email: str, name: str) -> str:
        now = int(time.time())
        body = _b64(json.dumps({"sub": email, "name": name, "via": "local", "iat": now,
                                "exp": now + self.hours * 3600}, separators=(",", ":")).encode())
        return f"{body}.{self._sign(body)}"

    def read(self, token: str | None) -> dict | None:
        if not token or token.count(".") != 1:
            return None
        body, sig = token.split(".")
        if not hmac.compare_digest(sig, self._sign(body)):
            return None
        try:
            data = json.loads(_unb64(body))
        except ValueError:
            return None
        if not isinstance(data, dict) or int(data.get("exp", 0)) < time.time():
            return None
        return {"email": data.get("sub"), "name": data.get("name"), "via": data.get("via"), "expires": data.get("exp")}


class Accounts:
    def __init__(self, folder: Path, session_hours: int, signup_open: bool, allowed_email_domains: tuple[str, ...]):
        self.folder = folder
        self.signup_open = signup_open
        self.allowed_email_domains = allowed_email_domains
        self.users = UserStore(folder)
        self.sessions = Sessions(folder, session_hours)
        self._failures: dict[str, list[float]] = {}
        self._fail_lock = threading.Lock()

    def _check_email(self, email: str) -> None:
        if not _EMAIL.match(email) or len(email) > 254:
            raise AuthError("Enter a valid email address.")
        domains = self.allowed_email_domains
        if domains and email.rsplit("@", 1)[1] not in domains:
            raise AuthError("Use your work email address (" + ", ".join("@" + d for d in domains) + ").", 403)

    def _locked(self, email: str) -> int:
        """Seconds left before this email may try again (0 = not locked)."""
        with self._fail_lock:
            recent = [t for t in self._failures.get(email, []) if t > time.time() - FAILURE_WINDOW]
            self._failures[email] = recent
            return int(recent[0] + FAILURE_WINDOW - time.time()) + 1 if len(recent) >= MAX_FAILURES else 0

    def _failed(self, email: str) -> None:
        with self._fail_lock:
            self._failures.setdefault(email, []).append(time.time())

    def signup(self, body: dict) -> dict:
        if not self.signup_open:
            raise AuthError("New accounts are switched off. Ask the CyberSuite owner for access.", 403)
        email, name, password = normalise_email(body.get("email")), str(body.get("name") or "").strip(), str(body.get("password") or "")
        if not 1 <= len(name) <= 80:
            raise AuthError("Enter your name.")
        self._check_email(email)
        problem = password_problem(password)
        if problem:
            raise AuthError(problem)
        user = self.users.create(email, name, password)
        return {"email": user["email"], "name": user["name"]}

    def login(self, body: dict) -> dict:
        email, password = normalise_email(body.get("email")), str(body.get("password") or "")
        wait = self._locked(email)
        if wait:
            raise AuthError(f"Too many wrong passwords. Try again in {max(1, wait // 60)} minute(s).", 429)
        user = self.users.verify(email, password) if email and password else None
        if not user:
            self._failed(email)
            raise AuthError("Wrong email or password.", 401)
        return {"email": user["email"], "name": user["name"]}

    def log(self, event: str, email: str, ok: bool, ip: str | None, detail: str = "") -> None:
        path = self.folder / "signins.jsonl"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"at": _now_iso(), "event": event, "email": email, "ok": ok, "ip": ip,
                                    "mode": "local", "via": "cybersuite-login", "detail": detail}) + "\n")
        except OSError:
            pass
