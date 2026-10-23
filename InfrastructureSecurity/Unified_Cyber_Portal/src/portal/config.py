"""Portal settings: where UC1/UC3/UC4 live, which port to use and how people sign in.

Defaults assume the portal folder sits next to the use-case folders. Override with environment variables
or `config/portal.env` (KEY=value lines, see config/portal.env.example).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PORTAL_DIR = Path(__file__).resolve().parents[2]
ROOT_DIR = PORTAL_DIR.parent


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"')
    return values


@dataclass(frozen=True)
class Settings:
    uc1_dir: Path
    uc3_dir: Path
    uc4_dir: Path
    host: str = "127.0.0.1"
    port: int = 8800
    uc1_site: str = "http://127.0.0.1:8700"
    uc3_site: str = "http://127.0.0.1:8600"
    uc4_site: str = "http://127.0.0.1:8900"
    # sign-in (see auth.py): local = accounts kept by the portal, cognito = Amazon Cognito user pool, off = nobody signs in
    auth_mode: str = "local"
    signup_open: bool = True
    allowed_email_domains: tuple[str, ...] = ()
    session_hours: int = 12
    cookie_secure: bool = False          # True once the portal is behind HTTPS (AWS load balancer)
    cognito_region: str = ""
    cognito_user_pool_id: str = ""
    cognito_client_id: str = ""
    auth_dir: Path = PORTAL_DIR / "data" / "auth"   # local accounts, session key, sign-in log
    # the shared SEL Nexus CyberSuite sign-in page (../../login). When set, people sign in and out there instead of
    # on this portal, and auth_dir should point at that page's data/auth so both check the same session cookie.
    login_url: str = ""

    @property
    def web_dist(self) -> Path:
        return PORTAL_DIR / "web" / "dist"


def _on(value: str | None, default: bool) -> bool:
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def load_settings() -> Settings:
    env = {**_load_env_file(PORTAL_DIR / "config" / "portal.env"), **os.environ}
    return Settings(
        uc1_dir=Path(env.get("PORTAL_UC1_DIR", ROOT_DIR / "UC1_Threat_Intel_Hunting_Agent")),
        uc3_dir=Path(env.get("PORTAL_UC3_DIR", ROOT_DIR / "UC3_MDE_Vuln_Extraction")),
        uc4_dir=Path(env.get("PORTAL_UC4_DIR", ROOT_DIR / "UC4_Alert_Triage_Agent")),
        port=int(env.get("PORTAL_PORT", 8800)),
        uc1_site=env.get("PORTAL_UC1_SITE", "http://127.0.0.1:8700"),
        uc3_site=env.get("PORTAL_UC3_SITE", "http://127.0.0.1:8600"),
        uc4_site=env.get("PORTAL_UC4_SITE", "http://127.0.0.1:8900"),
        auth_mode=env.get("PORTAL_AUTH", "local").strip().lower(),
        signup_open=_on(env.get("PORTAL_SIGNUP"), True),
        allowed_email_domains=tuple(d.strip().lower().lstrip("@") for d in env.get("PORTAL_ALLOWED_EMAIL_DOMAINS", "").split(",")
                                    if d.strip()),
        session_hours=int(env.get("PORTAL_SESSION_HOURS", 12)),
        cookie_secure=_on(env.get("PORTAL_COOKIE_SECURE"), False),
        cognito_region=env.get("PORTAL_COGNITO_REGION", ""),
        cognito_user_pool_id=env.get("PORTAL_COGNITO_USER_POOL_ID", ""),
        cognito_client_id=env.get("PORTAL_COGNITO_CLIENT_ID", ""),
        auth_dir=(PORTAL_DIR / env["PORTAL_AUTH_DIR"]).resolve() if env.get("PORTAL_AUTH_DIR") else PORTAL_DIR / "data" / "auth",
        login_url=env.get("PORTAL_LOGIN_URL", "").strip().rstrip("/"),
    )
