"""Portal sign-in: who may open the portal.

Three modes (PORTAL_AUTH in the suite .env):
  local    (default) the portal keeps its own accounts in data/auth/users.json (passwords stored only as scrypt hashes)
  cognito  an Amazon Cognito user pool checks the password; the browser talks to Cognito directly and hands the
           portal Cognito's signed ID token, which is verified here against the pool's public keys
  off      nobody signs in (tests)
Both real modes end the same way: the portal gives the browser its own signed, HttpOnly session cookie, so every
other /api/* endpoint only checks that cookie and never knows which mode is on. Moving to AWS is a settings change.

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

from dashboard.config import Settings

COOKIE = "portal_session"
DOMAIN = "infrastructure_security"   # this portal's id on the shared CyberSuite sign-in page
OLD_DOMAINS = {"defender_infra", "infrastructure_vulnerabilities"}   # its ids before the rename, still in older accounts and cookies
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
    """Same default rule as an Amazon Cognito user pool, so accounts behave the same after the move."""
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
    """Local accounts: one JSON file, written atomically. Only used when PORTAL_AUTH=local."""

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

    def count(self) -> int:
        return len(self._load())

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
    """Signed session cookies: base64(payload).HMAC-SHA256. The key is PORTAL_SESSION_SECRET, or a random key kept in
    data/auth/session.key (made on first start; deleting it signs everybody out)."""

    def __init__(self, folder: Path, hours: int, secret: str | None = None):
        self.hours = hours
        self.key = secret.encode() if secret else self._key_file(folder / "session.key")

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

    def issue(self, email: str, name: str, via: str) -> str:
        now = int(time.time())
        body = _b64(json.dumps({"sub": email, "name": name, "via": via, "iat": now,
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
        return {"email": data.get("sub"), "name": data.get("name"), "via": data.get("via"), "expires": data.get("exp"),
                "domains": data.get("domains"), "domain": data.get("domain")}


class CognitoVerifier:
    """Checks an ID token from the Cognito user pool: RS256 signature (pool's published keys), issuer, audience
    (our app client), token_use=id and expiry. Needs PyJWT[crypto] (requirements.txt)."""

    def __init__(self, region: str, pool_id: str, client_id: str):
        if not (region and pool_id and client_id):
            raise AuthError("Cognito is not set up: fill PORTAL_COGNITO_REGION, PORTAL_COGNITO_USER_POOL_ID and "
                            "PORTAL_COGNITO_CLIENT_ID in the suite .env", 500)
        import jwt  # only needed in cognito mode

        self.jwt = jwt
        self.issuer = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"
        self.client_id = client_id
        self.keys = jwt.PyJWKClient(f"{self.issuer}/.well-known/jwks.json", cache_keys=True, lifespan=3600)

    def verify(self, id_token: str) -> dict:
        jwt = self.jwt
        try:
            key = self.keys.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(id_token, key.key, algorithms=["RS256"], audience=self.client_id, issuer=self.issuer,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except jwt.PyJWTError as exc:
            raise AuthError(f"The sign-in token was not accepted ({exc.__class__.__name__}).", 401) from exc
        if claims.get("token_use") != "id":
            raise AuthError("The sign-in token was not accepted (not an ID token).", 401)
        email = normalise_email(claims.get("email") or claims.get("cognito:username"))
        if not email:
            raise AuthError("The Cognito account has no email address.", 401)
        if claims.get("email") and claims.get("email_verified") is False:
            raise AuthError("Confirm your email address first.", 401)
        return {"email": email, "name": str(claims.get("name") or email.split("@")[0])}


class Auth:
    def __init__(self, settings: Settings, session_secret: str | None = None):
        if settings.auth_mode not in ("local", "cognito", "off"):
            raise ValueError(f"PORTAL_AUTH must be local, cognito or off (got {settings.auth_mode!r})")
        self.settings = settings
        self.mode = settings.auth_mode
        self.users = UserStore(settings.auth_dir)
        self.sessions = Sessions(settings.auth_dir, settings.session_hours, session_secret) if self.mode != "off" else None
        self._cognito: CognitoVerifier | None = None
        self._failures: dict[str, list[float]] = {}
        self._fail_lock = threading.Lock()

    # ---- what the sign-in page needs to know (nothing secret)
    def public_config(self) -> dict:
        s = self.settings
        return {
            "mode": self.mode,
            "signup_open": s.signup_open,
            "password_rule": PASSWORD_RULE,
            "allowed_email_domains": list(s.allowed_email_domains),
            "login_url": s.login_url or None,
            "cognito": {"region": s.cognito_region, "user_pool_id": s.cognito_user_pool_id,
                        "client_id": s.cognito_client_id} if self.mode == "cognito" else None,
        }

    def current_user(self, cookie: str | None) -> dict | None:
        if self.mode == "off":
            return {"email": "local", "name": "Local user", "via": "off", "expires": None}
        user = self.sessions.read(cookie) if self.sessions else None
        # shared CyberSuite sign-in: an account made with a domain choice may only open the domains it picked
        if user and self.settings.login_url and isinstance(user.get("domains"), list) and not ({DOMAIN} | OLD_DOMAINS) & set(user["domains"]):
            return None
        return user

    # ---- checks shared by both modes
    def _check_email(self, email: str) -> None:
        if not _EMAIL.match(email) or len(email) > 254:
            raise AuthError("Enter a valid email address.")
        domains = self.settings.allowed_email_domains
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

    def _need(self, mode: str) -> None:
        if self.mode != mode:
            raise AuthError(f"CyberSuite signs in with {self.mode}, not {mode}.", 404)

    # ---- local accounts
    def signup(self, body: dict) -> dict:
        self._need("local")
        if not self.settings.signup_open:
            raise AuthError("New accounts are switched off on this portal. Ask the portal owner for access.", 403)
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
        self._need("local")
        email, password = normalise_email(body.get("email")), str(body.get("password") or "")
        wait = self._locked(email)
        if wait:
            raise AuthError(f"Too many wrong passwords. Try again in {max(1, wait // 60)} minute(s).", 429)
        user = self.users.verify(email, password) if email and password else None
        if not user:
            self._failed(email)
            raise AuthError("Wrong email or password.", 401)
        return {"email": user["email"], "name": user["name"]}

    # ---- Amazon Cognito
    def cognito(self, body: dict) -> dict:
        self._need("cognito")
        if self._cognito is None:
            s = self.settings
            self._cognito = CognitoVerifier(s.cognito_region, s.cognito_user_pool_id, s.cognito_client_id)
        user = self._cognito.verify(str(body.get("id_token") or ""))
        self._check_email(user["email"])
        return user

    def issue(self, user: dict) -> str:
        assert self.sessions is not None
        return self.sessions.issue(user["email"], user["name"], self.mode)

    def log(self, event: str, email: str, ok: bool, ip: str | None, detail: str = "") -> None:
        path = self.settings.auth_dir / "signins.jsonl"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"at": _now_iso(), "event": event, "email": email, "ok": ok, "ip": ip,
                                    "mode": self.mode, "detail": detail}) + "\n")
        except OSError:
            pass
