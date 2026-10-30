"""HTTP clients for Microsoft Graph (incidents, hunting, comments) and the Defender API (devices, files, IPs,
isolation). Retry logic copied from Threat Intel/Vulnerability.

Retry rules: 429 -> wait `Retry-After`; 500/502/503/504 and network errors -> exponential back-off with jitter;
401 -> fetch a fresh token once. Hunting calls are throttled below Microsoft's limit (45 calls/minute).
"""

from __future__ import annotations

import json
import logging
import random
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote, urljoin

import requests

from alert_triage.auth import TokenProvider

log = logging.getLogger("alert_triage.api")

RETRYABLE_STATUS = {500, 502, 503, 504}
HINTS = {
    401: "The token was rejected. Check the app registration and that UC4_TENANT_ID is your Defender trial tenant.",
    403: "Access denied. In Entra ID, add these permissions (Graph SecurityIncident.Read.All, "
         "SecurityAlert.Read.All, ThreatHunting.Read.All; WindowsDefenderATP Machine.Read.All) and click "
         "'Grant admin consent'.",
    404: "Not found.",
}


class ApiError(RuntimeError):
    def __init__(self, status: int | None, message: str):
        hint = HINTS.get(status or 0)
        super().__init__(f"HTTP {status}: {message}" + (f"\nHint: {hint}" if hint else ""))
        self.status = status
        self.detail = message


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 6
    base_delay: float = 1.0
    max_delay: float = 60.0
    timeout: float = 120.0


class RateLimiter:
    """At most `per_minute` calls per rolling minute (thread-safe)."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.interval = 60.0 / max(1, per_minute)
        self.clock, self.sleep = clock, sleep
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = self.clock()
            start = max(now, self._next)
            self._next = start + self.interval
        if start > now:
            self.sleep(start - now)


class ApiClient:
    def __init__(self, base_url: str, tokens: TokenProvider, retry: RetryPolicy = RetryPolicy(),
                 session: requests.Session | None = None, sleep: Callable[[float], None] = time.sleep):
        self.base_url = base_url.rstrip("/") + "/"
        self.tokens = tokens
        self.retry = retry
        self.session = session or requests.Session()
        self.sleep = sleep
        self.retries = 0
        self.calls = 0

    def _url(self, path_or_url: str) -> str:
        return urljoin(self.base_url, path_or_url.lstrip("/")) if "://" not in path_or_url else path_or_url

    def _backoff(self, attempt: int) -> float:
        return min(self.retry.max_delay, self.retry.base_delay * 2 ** (attempt - 1)) * random.uniform(0.8, 1.2)

    def request(self, method: str, path_or_url: str, *, params: dict | None = None,
                json_body: dict | None = None) -> requests.Response:
        url = self._url(path_or_url)
        refreshed = False
        for attempt in range(1, self.retry.max_attempts + 1):
            headers = {"Authorization": f"Bearer {self.tokens.token()}"}
            self.calls += 1
            try:
                response = self.session.request(method, url, headers=headers, params=params, json=json_body,
                                                timeout=self.retry.timeout)
            except (requests.ConnectionError, requests.Timeout) as exc:
                wait, reason = self._backoff(attempt), f"network error ({exc.__class__.__name__})"
            else:
                status = response.status_code
                if status < 400:
                    return response
                body = response.text[:2000]
                if status == 401 and not refreshed:
                    refreshed, wait, reason = True, 0.0, "token rejected, getting a new one"
                elif status == 429:
                    wait = min(self.retry.max_delay, float(response.headers.get("Retry-After") or self._backoff(attempt)))
                    reason = "rate limited (429)"
                elif status in RETRYABLE_STATUS:
                    wait, reason = self._backoff(attempt), f"server error ({status})"
                else:
                    raise ApiError(status, _error_message(body))
            if attempt == self.retry.max_attempts:
                raise ApiError(None, f"Gave up after {attempt} attempts: {reason} on {method} {url.split('?')[0]}")
            self.retries += 1
            log.info("Retry %d/%d in %.1fs: %s", attempt, self.retry.max_attempts - 1, wait, reason)
            self.sleep(wait)
        raise AssertionError("unreachable")

    def get_json(self, path: str, params: dict | None = None) -> dict:
        return self.request("GET", path, params=params).json()

    def get_all(self, path: str, params: dict | None = None, max_pages: int = 50) -> list[dict]:
        """All `value` rows, following @odata.nextLink."""
        rows: list[dict] = []
        body = self.get_json(path, params)
        for _ in range(max_pages):
            rows.extend(body.get("value", []))
            next_link = body.get("@odata.nextLink")
            if not next_link:
                return rows
            body = self.get_json(next_link)
        log.warning("Stopped after %d pages of %s", max_pages, path)
        return rows


CUSTOM_LOG = re.compile(r"\b\w+_CL\b")


class LogAnalyticsClient(ApiClient):
    """Log Analytics query API for one Sentinel workspace (role: Log Analytics Reader). Used for the Sentinel
    custom-log tables (`..._CL`, e.g. the Training Lab's sample data), which Graph hunting does not resolve."""

    def __init__(self, base_url: str, tokens: TokenProvider, workspace_id: str, **kwargs):
        super().__init__(base_url, tokens, **kwargs)
        self.workspace_id = workspace_id

    def query(self, kql: str, timespan: str = "P30D") -> list[dict]:
        body = self.request("POST", f"workspaces/{quote(self.workspace_id, safe='')}/query",
                            json_body={"query": kql, "timespan": timespan}).json()
        tables = body.get("tables") or []
        if not tables:
            return []
        cols = [c["name"] for c in tables[0].get("columns", [])]
        return [dict(zip(cols, row)) for row in tables[0].get("rows", [])]


class GraphClient(ApiClient):
    """Microsoft Graph security API: unified Defender XDR (+ Sentinel, when connected) incidents and hunting.
    Queries on Sentinel custom-log tables go to the workspace's Log Analytics API when `workspace` is given."""

    def __init__(self, base_url: str, tokens: TokenProvider, hunt_calls_per_minute: int = 40,
                 workspace: Callable[[str], LogAnalyticsClient] | None = None, workspace_id: str | None = None,
                 **kwargs):
        super().__init__(base_url, tokens, **kwargs)
        self.hunt_limiter = RateLimiter(hunt_calls_per_minute, sleep=self.sleep)
        self._workspace_factory, self._workspace_id, self._workspace = workspace, workspace_id, None

    def workspace(self) -> LogAnalyticsClient | None:
        """The Sentinel workspace client. Its ID comes from .env, or else from Sentinel's own SecurityIncident table
        (its TenantId column is the workspace ID), so no extra setting is needed."""
        if self._workspace is None and self._workspace_factory is not None:
            wid = self._workspace_id
            if not wid:
                try:
                    rows = self.hunt("SecurityIncident | where TimeGenerated > ago(90d) | take 1 | project TenantId",
                                     route=False)
                    wid = rows[0].get("TenantId") if rows else None
                except ApiError as exc:
                    log.info("No Sentinel workspace found: %s", str(exc).splitlines()[0])
            if wid:
                self._workspace = self._workspace_factory(str(wid))
            else:
                self._workspace_factory = None          # no Sentinel here: don't look again in this run
        return self._workspace

    def incidents(self, since: datetime | None, top: int = 50) -> list[dict]:
        params = {"$expand": "alerts", "$top": str(top), "$orderby": "lastUpdateDateTime desc"}
        if since is not None:
            params["$filter"] = f"lastUpdateDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        return self.get_all("security/incidents", params)

    def incident(self, incident_id: str) -> dict:
        return self.get_json(f"security/incidents/{quote(str(incident_id), safe='')}", {"$expand": "alerts"})

    def hunt(self, query: str, timespan: str | None = None, route: bool = True) -> list[dict]:
        """Run one read-only KQL query (Graph runHuntingQuery: Defender XDR tables, Sentinel tables if connected).
        Sentinel custom-log tables (`..._CL`) go to the workspace's Log Analytics API instead."""
        if route and CUSTOM_LOG.search(query) and self._workspace_factory is not None:
            ws = self.workspace()
            if ws is not None:
                return ws.query(query)
        self.hunt_limiter.wait()
        body = {"Query": query}
        if timespan:
            body["Timespan"] = timespan
        return self.request("POST", "security/runHuntingQuery", json_body=body).json().get("results", [])

    def update_incident(self, incident_id: str, changes: dict) -> dict:
        """PATCH status / classification / determination / tags (SecurityIncident.ReadWrite.All). Human-approved only."""
        return self.request("PATCH", f"security/incidents/{quote(str(incident_id), safe='')}", json_body=changes).json()

    def add_comment(self, incident_id: str, text: str) -> None:
        self.request("POST", f"security/incidents/{quote(str(incident_id), safe='')}/comments",
                     json_body={"@odata.type": "microsoft.graph.security.alertComment", "comment": text[:1000]})


class DefenderClient(ApiClient):
    """Defender for Endpoint API: device details, file and IP information, isolation (human-approved only)."""

    def machine(self, machine_id: str) -> dict:
        return self.get_json(f"api/machines/{quote(machine_id, safe='')}")

    def file_info(self, sha: str) -> dict:
        return self.get_json(f"api/files/{quote(sha, safe='')}")

    def ip_stats(self, ip: str) -> dict:
        return self.get_json(f"api/ips/{quote(ip, safe='')}/stats")

    def isolate(self, machine_id: str, comment: str) -> dict:
        return self.request("POST", f"api/machines/{quote(machine_id, safe='')}/isolate",
                            json_body={"Comment": comment[:200], "IsolationType": "Selective"}).json()

    def release(self, machine_id: str, comment: str) -> dict:
        return self.request("POST", f"api/machines/{quote(machine_id, safe='')}/unisolate",
                            json_body={"Comment": comment[:200]}).json()

    def antivirus_scan(self, machine_id: str, comment: str, scan_type: str = "Full") -> dict:
        """Ask Defender Antivirus on the device to scan (Machine.Scan)."""
        return self.request("POST", f"api/machines/{quote(machine_id, safe='')}/runAntiVirusScan",
                            json_body={"Comment": comment[:200], "ScanType": scan_type}).json()

    def stop_and_quarantine(self, machine_id: str, sha1: str, comment: str) -> dict:
        """Ask Defender to stop a file's processes and quarantine it (Machine.StopAndQuarantine). Reversible in
        Defender (restore from quarantine)."""
        return self.request("POST", f"api/machines/{quote(machine_id, safe='')}/StopAndQuarantineFile",
                            json_body={"Comment": comment[:200], "Sha1": sha1}).json()

    def machine_action(self, action_id: str) -> dict:
        return self.get_json(f"api/machineactions/{quote(action_id, safe='')}")

    def machine_actions(self, machine_id: str, top: int = 20) -> list[dict]:
        return self.get_json("api/machineactions", {"$filter": f"machineId eq '{machine_id}'", "$top": str(top)}
                             ).get("value", [])


def _error_message(body: str) -> str:
    try:
        error = json.loads(body).get("error", {})
        return f"{error.get('code', '')}: {error.get('message', '')}".strip(": ") or body
    except (ValueError, AttributeError):
        return body


LOGANALYTICS_BASE = "https://api.loganalytics.io/v1"
LOGANALYTICS_SCOPE = "https://api.loganalytics.io/.default"


def graph_client(settings, login) -> GraphClient:
    """The Graph client Alert Triage uses everywhere, with the Sentinel workspace route for custom-log tables."""
    from alert_triage.auth import GRAPH_SCOPE
    return GraphClient(settings.graph_base, login.provider(GRAPH_SCOPE), workspace_id=settings.sentinel_workspace_id,
                       workspace=lambda wid: LogAnalyticsClient(LOGANALYTICS_BASE, login.provider(LOGANALYTICS_SCOPE), wid))
