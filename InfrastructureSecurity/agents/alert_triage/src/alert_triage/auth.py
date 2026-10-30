"""Microsoft Entra access tokens (msal, app-only). Copied from Threat Intel and extended: one login, two APIs
(Microsoft Graph for incidents and hunting, the Defender API for device details and isolation)."""

from __future__ import annotations

import threading
from typing import Protocol

import msal

from alert_triage.config import Settings

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default"

# Common Entra error codes -> what the user should check (the codes appear in msal's error_description)
HINTS = {
    "AADSTS7000215": "The client secret is wrong. Copy the secret *Value* (not the Secret ID) into TRIAGE_CLIENT_SECRET.",
    "AADSTS7000222": "The client secret has expired. Create a new one under Certificates & secrets.",
    "AADSTS700016": "Application (client) ID not found in this tenant. Check TRIAGE_CLIENT_ID and TRIAGE_TENANT_ID.",
    "AADSTS90002": "Tenant not found. Check TRIAGE_TENANT_ID (Directory (tenant) ID on the app's Overview page).",
}


class AuthError(RuntimeError):
    pass


class TokenProvider(Protocol):
    def token(self) -> str: ...


class EntraLogin:
    """One confidential client for the app registration; msal caches a token per scope and renews it."""

    def __init__(self, settings: Settings, app_factory=msal.ConfidentialClientApplication):
        if not settings.has_microsoft:
            raise AuthError("Microsoft login details are missing in .env "
                            "(TRIAGE_TENANT_ID, TRIAGE_CLIENT_ID, TRIAGE_CLIENT_SECRET).")
        self.app = app_factory(settings.client_id, client_credential=settings.client_secret,
                               authority=f"https://login.microsoftonline.com/{settings.tenant_id}")
        self._lock = threading.Lock()

    def token_for(self, scope: str) -> str:
        with self._lock:
            result = self.app.acquire_token_for_client(scopes=[scope])
        if "access_token" in result:
            return result["access_token"]
        description = (result.get("error_description") or result.get("error") or "unknown error").splitlines()[0]
        hint = next((h for code, h in HINTS.items() if code in description), "")
        raise AuthError(f"Microsoft login failed: {description}" + (f"\nHint: {hint}" if hint else ""))

    def provider(self, scope: str) -> TokenProvider:
        return _Scoped(self, scope)


class _Scoped:
    def __init__(self, login: EntraLogin, scope: str):
        self.login, self.scope = login, scope

    def token(self) -> str:
        return self.login.token_for(self.scope)
