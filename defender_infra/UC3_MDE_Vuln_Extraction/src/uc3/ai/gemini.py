"""Minimal Google Gemini client over plain HTTPS (no extra library): model choice, rate limit, retries, JSON answers.

Models: GEMINI_MODEL (default gemini-3.5-flash-lite), then GEMINI_FALLBACK_MODEL; the first one the key can use is
picked ('-preview' variants accepted). The free tier allows only a few requests per minute, so calls are spaced
GEMINI_RPM apart and a 429 answer slows down further.
"""

from __future__ import annotations

import json
import logging
import re
import time

import requests

from uc3.config import Settings

log = logging.getLogger("uc3.ai")
API = "https://generativelanguage.googleapis.com/v1beta"


class AIUnavailable(RuntimeError):
    """No key, quota used up or the service keeps failing: callers keep the data-only card."""


class GeminiClient:
    def __init__(self, settings: Settings, session=None, sleep=time.sleep, clock=time.monotonic):
        if not settings.gemini_keys:
            raise AIUnavailable("GEMINI_API_KEY is not set in .env")
        self.settings = settings
        self.keys = settings.gemini_keys      # GEMINI_API_KEY, GEMINI_API_KEY_2, ...: the next takes over when one runs out
        self.key_index = 0
        self.session = session or requests.Session()
        self.session.headers.update({"x-goog-api-key": self.keys[0]})
        self.sleep, self.clock = sleep, clock
        self.interval = 60.0 / settings.gemini_rpm
        self._next = 0.0
        self._model: str | None = None
        self.calls = 0

    def _next_key(self, why: str) -> bool:
        """Move on to the next key; False when the current one was the last."""
        if self.key_index + 1 >= len(self.keys):
            return False
        self.key_index += 1
        self.session.headers["x-goog-api-key"] = self.keys[self.key_index]
        log.warning("Gemini key %d of %d %s; switching to key %d", self.key_index, len(self.keys), why,
                    self.key_index + 1)
        return True

    def model(self) -> str:
        if self._model:
            return self._model
        while True:                                   # a key that is refused: try the next one
            try:
                response = self.session.get(f"{API}/models", params={"pageSize": 1000}, timeout=30)
            except requests.RequestException as exc:
                raise AIUnavailable(f"Gemini unreachable: {_short(exc)}") from exc
            if response.status_code == 200 or not self._next_key(f"was refused ({response.status_code})"):
                break
        if response.status_code != 200:
            raise AIUnavailable(f"Gemini refused the key ({response.status_code}): {_short(response.text)}")
        names = sorted(m["name"].removeprefix("models/") for m in response.json().get("models", []))
        for wanted in self.settings.gemini_models:
            match = [n for n in names if n == wanted] or sorted(n for n in names if n.startswith(wanted + "-"))
            if match:
                self._model = match[0]
                log.info("Gemini model: %s", self._model)
                return self._model
        lite = ", ".join(n for n in names if "flash-lite" in n) or "none"
        raise AIUnavailable(f"None of {', '.join(self.settings.gemini_models)} is available to this key "
                            f"(flash-lite models it can use: {lite}). Set GEMINI_MODEL in .env.")

    def _wait_turn(self) -> None:
        now = self.clock()
        if now < self._next:
            self.sleep(self._next - now)
        self._next = max(now, self._next) + self.interval

    def json(self, system: str, prompt: str, schema: dict, max_tokens: int = 2048, attempts: int = 5) -> dict:
        """Answer that follows `schema` (OpenAPI subset), parsed into a dict."""
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": max_tokens,
                                 "responseMimeType": "application/json", "responseSchema": schema},
        }
        url = f"{API}/models/{self.model()}:generateContent"
        for attempt in range(1, attempts + 1):
            self._wait_turn()
            try:
                response = self.session.post(url, json=body, timeout=120)
            except requests.RequestException as exc:
                if attempt == attempts:
                    raise AIUnavailable(f"Gemini unreachable: {_short(exc)}") from exc
                self.sleep(2 ** attempt)
                continue
            self.calls += 1
            if response.status_code == 200:
                text = "".join(p.get("text", "") for c in response.json().get("candidates", [])[:1]
                               for p in c.get("content", {}).get("parts", []) if not p.get("thought"))
                try:
                    return json.loads(text)
                except ValueError:
                    if attempt == attempts:
                        raise AIUnavailable("Gemini answer was not valid JSON")
                    continue
            detail = response.text
            code = response.status_code
            if (code in (401, 403) or (code == 400 and "API key" in detail)) and self._next_key(f"was refused ({code})"):
                continue
            if code in (400, 401, 403, 404):
                raise AIUnavailable(f"Gemini refused the request ({code}): {_short(detail)}")
            if code == 429 and "PerDay" in detail:
                if self._next_key("used up its daily quota"):
                    continue
                on_all = f" on all {len(self.keys)} keys" if len(self.keys) > 1 else ""
                raise AIUnavailable(f"Gemini daily free quota used up{on_all}; "
                                    "the remaining apps are explained on the next run")
            if attempt == attempts:
                raise AIUnavailable(f"Gemini failed after {attempts} attempts ({response.status_code})")
            if response.status_code == 429:
                self.interval = min(12.0, self.interval * 2)   # adapt to the key's real per-minute limit
            hinted = re.search(r'"retryDelay":\s*"(\d+)s"', detail)
            wait = int(hinted.group(1)) + 1 if hinted else min(60, 5 * 2 ** attempt)
            log.info("Gemini %s, retrying in %ss", response.status_code, wait)
            self.sleep(wait)
        raise AssertionError("unreachable")


def _short(text) -> str:
    return str(text).strip().splitlines()[0][:300] if str(text).strip() else ""
