"""Microsoft Entra access tokens (msal, app-only) for the Defender API. Copied from Vulnerability and adapted."""

from __future__ import annotations

from typing import Protocol

import msal

from attack_detection.config import Settings

SCOPE = "https://api.securitycenter.microsoft.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"   # Azure Resource Manager (fix loop: Run Command)

# Common Entra error codes -> what the user should check (the codes appear in msal's error_description)
HINTS = {
    "AADSTS7000215": "The client secret is wrong. Copy the secret *Value* (not the Secret ID) into DEFENDER_CLIENT_SECRET.",
    "AADSTS7000222": "The client secret has expired. Create a new one under Certificates & secrets.",
    "AADSTS700016": "Application (client) ID not found in this tenant. Check DEFENDER_CLIENT_ID and DEFENDER_TENANT_ID.",
    "AADSTS90002": "Tenant not found. Check DEFENDER_TENANT_ID (Directory (tenant) ID on the app's Overview page).",
}


class AuthError(RuntimeError):
    pass


class TokenProvider(Protocol):
    def token(self) -> str: ...


class EntraTokenProvider:
    """App-only (client credentials) token. msal caches it and renews it before expiry."""

    def __init__(self, settings: Settings, app_factory=msal.ConfidentialClientApplication, scope: str = SCOPE):
        if not settings.has_defender:
            raise AuthError("Defender login details are missing in .env "
                            "(DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, DEFENDER_CLIENT_SECRET).")
        self.scope = scope
        self.app = app_factory(settings.client_id, client_credential=settings.client_secret,
                               authority=f"https://login.microsoftonline.com/{settings.tenant_id}")

    def token(self) -> str:
        result = self.app.acquire_token_for_client(scopes=[self.scope])
        if "access_token" in result:
            return result["access_token"]
        description = (result.get("error_description") or result.get("error") or "unknown error").splitlines()[0]
        hint = next((h for code, h in HINTS.items() if code in description), "")
        raise AuthError(f"Microsoft login failed: {description}" + (f"\nHint: {hint}" if hint else ""))
