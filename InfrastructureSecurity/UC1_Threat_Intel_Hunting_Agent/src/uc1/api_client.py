"""HTTP client for the Defender API with retries, plus the Advanced Hunting runner. Retry logic copied from UC3.

Retry rules: 429 -> wait `Retry-After`; 500/502/503/504 and network errors -> exponential back-off with
jitter; 401 -> fetch a fresh token once. Advanced Hunting calls are additionally throttled below
Defender's limit (45 calls/minute).
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin

import requests

from uc1.auth import TokenProvider

log = logging.getLogger("uc1.api")

RETRYABLE_STATUS = {500, 502, 503, 504}
HINTS = {
    401: "The token was rejected. Check the app registration and that the tenant ID matches your Defender tenant.",
    403: "Access denied. In Entra ID, add the WindowsDefenderATP application permissions "
         "(AdvancedQuery.Read.All, Machine.Read.All, Vulnerability.Read.All, Alert.Read.All) "
         "and click 'Grant admin consent'.",
    404: "Endpoint not found. Check DEFENDER_API_BASE.",
}
MAX_HUNT_ROWS = 100_000   # Defender's Advanced Hunting API row limit


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
    timeout: float = 180.0


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


class DefenderClient:
    def __init__(self, base_url: str, tokens: TokenProvider, retry: RetryPolicy = RetryPolicy(),
                 session: requests.Session | None = None, sleep: Callable[[float], None] = time.sleep,
                 hunt_calls_per_minute: int = 40):
        self.base_url = base_url.rstrip("/") + "/"
        self.tokens = tokens
        self.retry = retry
        self.session = session or requests.Session()
        self.sleep = sleep
        self.retries = 0
        self.hunt_limiter = RateLimiter(hunt_calls_per_minute, sleep=sleep)

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

    def get_all(self, path: str, params: dict | None = None) -> list[dict]:
        """All `value` rows, following @odata.nextLink."""
        rows: list[dict] = []
        body = self.get_json(path, params)
        while True:
            rows.extend(body.get("value", []))
            next_link = body.get("@odata.nextLink")
            if not next_link:
                return rows
            body = self.get_json(next_link)

    def run_query(self, query: str) -> list[dict]:
        """Run one Advanced Hunting (KQL) query. Read-only by design of the API."""
        self.hunt_limiter.wait()
        body = self.request("POST", "/api/advancedqueries/run", json_body={"Query": query}).json()
        results = body.get("Results", [])
        if len(results) >= MAX_HUNT_ROWS:
            log.warning("Query hit Defender's %d-row limit; results are incomplete", MAX_HUNT_ROWS)
        return results


def _error_message(body: str) -> str:
    try:
        error = json.loads(body).get("error", {})
        return f"{error.get('code', '')}: {error.get('message', '')}".strip(": ") or body
    except ValueError:
        return body
