"""Gemini API client (free tier), adapted from UC1: model auto-selection, adaptive per-minute rate limiting, daily
cap, retries, JSON output. One interface (`LLM`) so a client-approved model can replace Gemini later without
touching the triage code.

The agent works without AI: if no key / quota is exhausted, `available` is False and the triage falls back to a
deterministic rules-only verdict.
"""

from __future__ import annotations

import json
import logging
import random
import re
import threading
import time

from uc4.api import RateLimiter
from uc4.config import Settings
from uc4.store import Store

log = logging.getLogger("uc4.ai")


class AIUnavailable(RuntimeError):
    """No key, quota used up, or the service keeps failing: callers fall back to rules-only output."""


class LLM:
    """Interface the triage code depends on. GeminiLLM implements it; a stub implements it in tests."""

    available: bool = False

    def json(self, purpose: str, system: str, prompt: str, max_tokens: int = 1500) -> dict:
        raise NotImplementedError


class GeminiLLM(LLM):
    def __init__(self, settings: Settings, store: Store | None = None, client=None, sleep=time.sleep):
        self.settings = settings
        self.store = store
        self.sleep = sleep
        self.available = bool(settings.has_gemini) or client is not None
        self._client = client
        self._model: str | None = None
        self._lock = threading.Lock()
        self.limiter = RateLimiter(settings.gemini_rpm, sleep=sleep)
        self.exhausted: str | None = None
        self._last_slowdown = 0.0
        self.keys = settings.gemini_keys      # GEMINI_API_KEY, GEMINI_API_KEY_2, ...: the next takes over when one runs out
        self.key_index = 0

    def _get_client(self):
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self.keys[self.key_index])
        return self._client

    def _next_key(self, used: int, why: str) -> bool:
        """Move on from key number `used` (0-based) to the next one; False when it was the last."""
        with self._lock:
            if self.key_index != used:
                return True
            if used + 1 >= len(self.keys):
                return False
            self.key_index = used + 1
            self._client = None                 # rebuilt with the new key on the next call
        log.warning("Gemini key %d of %d %s; switching to key %d", used + 1, len(self.keys), why, used + 2)
        return True

    def model(self) -> str:
        if self._model:
            return self._model
        while True:                                   # a key that can't even list models: try the next one
            used = self.key_index
            try:
                names = sorted(m.name.removeprefix("models/") for m in self._get_client().models.list())
                break
            except Exception as exc:  # noqa: BLE001
                if not self._next_key(used, f"could not list models ({_short(exc)[:80]})"):
                    raise AIUnavailable(f"Could not list Gemini models: {_short(exc)}") from exc
        with self._lock:
            if self._model:
                return self._model
            for wanted in self.settings.gemini_models:
                match = [n for n in names if n == wanted] or sorted(n for n in names if n.startswith(wanted + "-"))
                if match:
                    self._model = match[0]
                    log.info("Gemini model: %s", self._model)
                    return self._model
            lite = [n for n in names if "flash-lite" in n]
            raise AIUnavailable(f"None of {', '.join(self.settings.gemini_models)} is available to this key. "
                                f"Flash-lite models it can use: {', '.join(lite) or 'none'}.")

    def _count(self, purpose: str, ok: bool) -> None:
        if self.store is not None:
            self.store.count_ai_call(self._model or "?", purpose, ok)

    def json(self, purpose: str, system: str, prompt: str, max_tokens: int = 1500) -> dict:
        if not self.available:
            raise AIUnavailable("Gemini is not configured")
        if self.exhausted:
            raise AIUnavailable(self.exhausted)
        if self.store is not None and self.store.ai_calls_today() >= self.settings.gemini_daily_cap:
            raise AIUnavailable(f"Daily Gemini cap reached ({self.settings.gemini_daily_cap})")
        from google.genai import errors, types
        model = self.model()
        config = types.GenerateContentConfig(system_instruction=system, temperature=0.0,
                                             max_output_tokens=max_tokens, response_mime_type="application/json")
        last = None
        for attempt in range(1, 6):
            self.limiter.wait()
            used = self.key_index
            try:
                resp = self._get_client().models.generate_content(model=model, contents=prompt, config=config)
                self._count(purpose, True)
                return _parse_json(resp.text or "")
            except errors.APIError as exc:
                self._count(purpose, False)
                last = exc
                code = getattr(exc, "code", None)
                if (code in (401, 403) or (code == 400 and "API key" in str(exc))) \
                        and self._next_key(used, f"was refused ({code})"):
                    continue
                if code in (400, 401, 403, 404):
                    raise AIUnavailable(f"Gemini refused the request ({code}): {_short(exc)}") from exc
                if code == 429:
                    detail = str(exc)
                    if "PerDay" in detail and self._next_key(used, "used up its daily quota"):
                        continue
                    if "PerDay" in detail:
                        on_all = f" on all {len(self.keys)} keys" if len(self.keys) > 1 else ""
                        self.exhausted = f"Gemini daily quota used up{on_all}; remaining incidents retry next run"
                        raise AIUnavailable(self.exhausted) from exc
                    with self._lock:
                        if self.limiter.interval < 6.0 and time.monotonic() - self._last_slowdown > 15:
                            self._last_slowdown = time.monotonic()
                            self.limiter.interval = min(6.0, self.limiter.interval * 2)
                            log.info("Gemini per-minute limit: slowing to %.0f/min", 60 / self.limiter.interval)
                m = re.search(r"retryDelay'?:\s*'?(\d+)s", str(exc))
                wait = (int(m.group(1)) + 1 if m else min(30, 2 ** attempt)) * random.uniform(1.0, 1.3)
                self.sleep(wait)
            except Exception as exc:  # noqa: BLE001 - network, parse
                self._count(purpose, False)
                last = exc
                if attempt == 5:
                    break
                self.sleep(2 ** attempt)
        raise AIUnavailable(f"Gemini failed: {_short(last)}")


def _parse_json(text: str) -> dict:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    try:
        return json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            return json.loads(text[start:end + 1])
        raise AIUnavailable("Gemini did not return JSON")


def _short(exc) -> str:
    return str(exc).splitlines()[0][:300] if exc else ""
