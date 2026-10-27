"""`python -m uc1 live-test`: tiny real calls to each service, with plain-language results. Never prints secrets."""

from __future__ import annotations

import requests

from uc1.ai.azure_client import make_client
from uc1.ai.gemini_client import AIUnavailable
from uc1.api_client import ApiError, DefenderClient
from uc1.auth import AuthError, EntraTokenProvider
from uc1.config import Settings
from uc1.feeds.iocs import THREATFOX


def _line(ok: bool | None, name: str, message: str) -> tuple[bool | None, str]:
    mark = {True: "OK  ", False: "FAIL", None: "SKIP"}[ok]
    print(f"  [{mark}] {name}: {message}")
    return ok, name


def run(settings: Settings) -> bool:
    print("UC1 live test (small real calls)\n")
    results = []

    # Defender
    if not settings.has_defender:
        results.append(_line(False, "Defender login", "DEFENDER_TENANT_ID / CLIENT_ID / CLIENT_SECRET missing in .env"))
    else:
        try:
            client = DefenderClient(settings.api_base, EntraTokenProvider(settings))
            client.tokens.token()
            results.append(_line(True, "Defender login", "token received"))
            machines = client.get_json("/api/machines", {"$top": 5}).get("value", [])
            results.append(_line(True, "Defender machines (Machine.Read.All)", f"{len(machines)} device(s) visible"))
            rows = client.run_query("DeviceInfo | where Timestamp > ago(1d) | summarize by DeviceName | take 10")
            results.append(_line(True, "Advanced Hunting (AdvancedQuery.Read.All)",
                                 f"{len(rows)} device(s) reported in the last day"))
            vulns = client.run_query("DeviceTvmSoftwareVulnerabilities | count")
            results.append(_line(True, "Vulnerability data", f"{vulns[0].get('Count') if vulns else 0} rows in Defender"))
            try:
                alerts = client.get_json("/api/alerts", {"$top": 1}).get("value", [])
                results.append(_line(True, "Alerts (Alert.Read.All)", f"readable ({len(alerts)} shown)"))
            except ApiError as exc:
                results.append(_line(False, "Alerts (Alert.Read.All)", str(exc).splitlines()[0]
                                     + " (add Alert.Read.All + admin consent; hunts still work without it)"))
        except (AuthError, ApiError) as exc:
            results.append(_line(False, "Defender", str(exc).replace("\n", " ")))

    # AI: Azure AI Foundry or Gemini (AI_PROVIDER)
    name = {"azure": "Azure AI Foundry", "gemini": "Gemini"}.get(settings.ai_provider, "AI")
    if settings.ai_provider is None:
        results.append(_line(False, name, "no AI set in .env: AZURE_FOUNDRY_ENDPOINT + _API_KEY + _DEPLOYMENT, "
                                          "or GEMINI_API_KEY"))
    else:
        try:
            ai = make_client(settings)
            model = ai.model()
            answer = ai.text("live-test", "Answer with one word.", "Reply with the word READY.", max_tokens=20)
            results.append(_line(True, name, f"model {model} answered '{answer[:20]}'"))
        except AIUnavailable as exc:
            results.append(_line(False, name, str(exc)))

    # NVD
    try:
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": "CVE-2021-44228"},
                         headers=headers, timeout=60)
        ok = r.status_code == 200
        note = "with API key" if settings.nvd_api_key else "without key (slower; optional)"
        results.append(_line(ok, "NVD", f"HTTP {r.status_code}, {note}"))
    except requests.RequestException as exc:
        results.append(_line(False, "NVD", str(exc)[:150]))

    # abuse.ch
    if not settings.abusech_auth_key:
        results.append(_line(False, "abuse.ch", "ABUSECH_AUTH_KEY missing in .env"))
    else:
        try:
            r = requests.post(THREATFOX, json={"query": "get_iocs", "days": 1},
                              headers={"Auth-Key": settings.abusech_auth_key}, timeout=60)
            status = r.json().get("query_status") if r.ok else r.status_code
            results.append(_line(r.ok and status == "ok", "abuse.ch ThreatFox", f"status {status}"))
        except (requests.RequestException, ValueError) as exc:
            results.append(_line(False, "abuse.ch", str(exc)[:150]))

    # OTX (optional)
    if not settings.otx_api_key:
        results.append(_line(None, "AlienVault OTX", "no key (optional)"))
    else:
        try:
            r = requests.get("https://otx.alienvault.com/api/v1/users/me",
                             headers={"X-OTX-API-KEY": settings.otx_api_key}, timeout=30)
            results.append(_line(r.ok, "AlienVault OTX", f"HTTP {r.status_code}"))
        except requests.RequestException as exc:
            results.append(_line(False, "AlienVault OTX", f"unreachable ({exc.__class__.__name__}); optional feed"))

    required_failed = [n for ok, n in results if ok is False and n not in ("AlienVault OTX", "Alerts (Alert.Read.All)")]
    print("\nResult:", "all required checks passed" if not required_failed else f"fix: {', '.join(required_failed)}")
    return not required_failed
