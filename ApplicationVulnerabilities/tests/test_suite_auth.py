"""The shared SEL Nexus CyberSuite sign-in: only people signed in on the suite's sign-in page get in."""
import base64
import hashlib
import hmac
import json
import secrets
import time

from fastapi.testclient import TestClient

from remediation import config


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _cookie(key: bytes, exp_in: int = 3600, domains: list[str] | None = None) -> str:
    """A cookie exactly as login/accounts.py issues it (`domains` absent = an account from before domains existed)."""
    now = int(time.time())
    payload = {"sub": "ana@example.com", "name": "Ana", "via": "local", "iat": now, "exp": now + exp_in}
    if domains is not None:
        payload |= {"domains": domains, "domain": domains[0]}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    return f"{body}.{_b64(hmac.new(key, body.encode(), hashlib.sha256).digest())}"


def _client(tmp_path, monkeypatch):
    auth = tmp_path / "auth"
    auth.mkdir()
    key = secrets.token_bytes(32)
    (auth / "session.key").write_text(_b64(key), encoding="utf-8")
    monkeypatch.setenv("SUITE_LOGIN_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("SUITE_AUTH_DIR", str(auth))
    config.reset_settings_cache()
    from remediation.api import app
    return TestClient(app, base_url="http://127.0.0.1:8500"), key


def test_signed_out_is_sent_to_the_sign_in_page(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    page = client.get("/runs", follow_redirects=False)
    assert page.status_code == 303
    assert page.headers["location"].startswith("http://127.0.0.1:8000/?next=http%3A%2F%2F127.0.0.1%3A8500%2Fruns")
    assert client.get("/api/v1/dashboard").status_code == 401
    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/auth/me").json() == {"user": None, "login_url": "http://127.0.0.1:8000"}


def test_signed_in_gets_in_and_can_sign_out(tmp_path, monkeypatch):
    client, key = _client(tmp_path, monkeypatch)
    client.cookies.set("portal_session", _cookie(key))
    assert client.get("/api/v1/dashboard").status_code == 200
    assert client.get("/runs", follow_redirects=False).status_code == 200
    assert client.get("/api/v1/auth/me").json()["user"]["email"] == "ana@example.com"
    assert client.post("/api/v1/auth/logout").status_code == 400  # needs the X-CyberSuite header
    out = client.post("/api/v1/auth/logout", headers={"X-CyberSuite": "auth"})
    assert out.status_code == 200 and "portal_session=" in out.headers["set-cookie"]


def test_expired_or_forged_cookies_are_refused(tmp_path, monkeypatch):
    client, key = _client(tmp_path, monkeypatch)
    client.cookies.set("portal_session", _cookie(key, exp_in=-10))
    assert client.get("/api/v1/dashboard").status_code == 401
    client.cookies.set("portal_session", _cookie(secrets.token_bytes(32)))
    assert client.get("/api/v1/dashboard").status_code == 401


def test_without_suite_login_everyone_is_the_local_user(tmp_path, monkeypatch):
    from remediation.api import app
    client = TestClient(app)
    assert client.get("/api/v1/auth/me").json()["user"]["via"] == "off"
    assert client.get("/api/v1/dashboard").status_code == 200


def test_only_accounts_with_this_domain_get_in(tmp_path, monkeypatch):
    client, key = _client(tmp_path, monkeypatch)
    client.cookies.set("portal_session", _cookie(key, domains=["defender_infra"]))
    assert client.get("/api/v1/dashboard").status_code == 401
    assert client.get("/runs", follow_redirects=False).status_code == 303
    client.cookies.set("portal_session", _cookie(key, domains=["defender_infra", "application_vulnerabilities"]))
    assert client.get("/api/v1/dashboard").status_code == 200
    assert client.get("/api/v1/auth/me").json()["user"]["domains"] == ["defender_infra", "application_vulnerabilities"]
