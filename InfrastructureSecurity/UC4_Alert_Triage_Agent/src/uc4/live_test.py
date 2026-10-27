"""`python -m uc4 live-test`: tiny real calls to each service, with plain-language results. Never prints secrets."""

from __future__ import annotations

from uc4.api import ApiError, DefenderClient, graph_client
from uc4.auth import DEFENDER_SCOPE, AuthError, EntraLogin
from uc4.config import Settings
from uc4.llm import AIUnavailable, make_llm
from uc4.tools.ti import ThreatIntel


def _line(ok: bool | None, name: str, message: str) -> bool | None:
    mark = {True: "OK  ", False: "FAIL", None: "SKIP"}[ok]
    print(f"  [{mark}] {name}: {message}")
    return ok


SENTINEL_TABLES = ("SigninLogs_CL", "OfficeActivity_CL", "SecurityEvent_CL")


def _sentinel(graph) -> None:
    """Optional Sentinel track: never fails the live test, only says how far the set-up has got."""
    try:
        incidents = graph.get_json("security/incidents", {"$expand": "alerts", "$top": "50"}).get("value", [])
        n = sum(1 for i in incidents if any(a.get("serviceSource") == "microsoftSentinel" for a in i.get("alerts") or []))
    except ApiError as exc:
        _line(None, "Sentinel incidents", str(exc).splitlines()[0])
        return
    tables = []
    for table in SENTINEL_TABLES:
        try:
            rows = graph.hunt(f"{table} | where TimeGenerated > ago(30d) | count")
            tables.append(f"{table} {rows[0].get('Count', 0) if rows else 0} rows")
        except ApiError:
            pass
    if not n and not tables:
        _line(None, "Sentinel", "not connected yet (optional)")
        return
    _line(True, "Sentinel incidents", f"{n} of the latest {len(incidents)} incident(s) come from Sentinel")
    _line(True if tables else None, "Sentinel tables (Training Lab)",
          ", ".join(tables) if tables else "not readable yet: sample data still loading, or the app registration's "
                                           "Reader roles are missing")


def run(settings: Settings) -> bool:
    print("UC4 live test (small real calls)\n")
    results = []
    if not settings.has_microsoft:
        results.append(_line(False, "Microsoft login", "UC4_TENANT_ID / UC4_CLIENT_ID / UC4_CLIENT_SECRET missing in .env"))
    else:
        try:
            login = EntraLogin(settings)
            graph = graph_client(settings, login)
            defender = DefenderClient(settings.defender_base, login.provider(DEFENDER_SCOPE))
            graph.tokens.token()
            results.append(_line(True, "Microsoft login", "token received"))
            for name, call in [
                ("Incidents (SecurityIncident.Read.All)",
                 lambda: f"{len(graph.get_json('security/incidents', {'$top': '5'}).get('value', []))} incident(s) visible"),
                ("Hunting incl. alert tables (ThreatHunting.Read.All)",
                 lambda: f"{len(graph.hunt('AlertInfo | where Timestamp > ago(30d) | take 5'))} alert row(s) in 30 days"),
                ("Device details (Machine.Read.All)",
                 lambda: f"{len(defender.get_json('api/machines', {'$top': '5'}).get('value', []))} device(s) visible"),
            ]:
                try:
                    results.append(_line(True, name, call()))
                except ApiError as exc:
                    results.append(_line(False, name, str(exc).splitlines()[0]
                                         + " -> add this permission in Entra and click 'Grant admin consent'"))
            _sentinel(graph)
        except (AuthError, ApiError) as exc:
            results.append(_line(False, "Microsoft", str(exc).replace("\n", " ")))
        for flag, name, perm in [(settings.writeback, "Pilot comments", "Graph SecurityIncident.ReadWrite.All"),
                                 (settings.contain, "Isolate stretch", "WindowsDefenderATP Machine.Isolate")]:
            _line(None, name, f"switched {'ON' if flag else 'off'} in .env (needs {perm}; tested on first use)")

    name = {"azure": "Azure AI Foundry", "gemini": "Gemini"}.get(settings.ai_provider, "AI")
    llm = make_llm(settings)
    if llm is None:
        results.append(_line(False, name, "no AI set in .env: AZURE_FOUNDRY_ENDPOINT + _API_KEY + _DEPLOYMENT, "
                                          "or GEMINI_API_KEY (without it: rules-only triage)"))
    else:
        try:
            answer = llm.json("live-test", "Reply in JSON.", 'Return {"status": "READY"}', max_tokens=30)
            results.append(_line(True, name, f"model {llm.model()} answered {answer}"))
        except AIUnavailable as exc:
            results.append(_line(False, name, str(exc)))

    ti = ThreatIntel(settings)
    for name, key, fn, value in [
        ("abuse.ch (URLhaus)", settings.abusech_auth_key, ti._domain, "example.com"),
        ("AbuseIPDB", settings.abuseipdb_api_key, ti._ip, "8.8.8.8"),
    ]:
        if not key:
            _line(None, name, "no key in .env (optional)")
            continue
        r = fn(value)
        results.append(_line(bool(r.get("sources")) or r.get("verdict") == "unknown", name,
                             f"look-up of a harmless test value -> {r.get('verdict')} {r.get('detail') or ''}".strip()))
    ok = all(r is not False for r in results)
    print("\n" + ("All required checks passed." if ok else "Some checks failed - see the hints above."))
    return ok
