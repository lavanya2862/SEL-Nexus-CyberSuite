"""Gemini API client: model selection, rate limiting (RPM), daily cap, retries, JSON-schema answers.

Models: GEMINI_MODEL (default gemini-3.5-flash-lite) with GEMINI_FALLBACK_MODEL (gemini-3.1-flash-lite).
The first one the API key can actually use is picked automatically (a '-preview' suffix is accepted).
"""

from __future__ import annotations

import logging
import re
import random
import threading
import time
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from attack_detection.api_client import RateLimiter
from attack_detection.config import Settings
from attack_detection.store import Store

log = logging.getLogger("attack_detection.ai")
T = TypeVar("T", bound=BaseModel)


class AIUnavailable(RuntimeError):
    """No key, quota used up, or the service keeps failing: callers fall back to rules-only output."""


class GeminiClient:
    def __init__(self, settings: Settings, store: Store | None = None, client=None, sleep=time.sleep):
        if not settings.has_gemini and client is None:
            raise AIUnavailable("GEMINI_API_KEY is not set in .env")
        self.keys = settings.gemini_keys      # GEMINI_API_KEY, GEMINI_API_KEY_2, ...: the next takes over when one runs out
        self.key_index = 0
        self.client = client if client is not None else self._new_client(self.keys[0])
        self.settings = settings
        self.store = store
        self.sleep = sleep
        self.limiter = RateLimiter(settings.gemini_rpm, sleep=sleep)
        self._lock = threading.Lock()
        self._model: str | None = None
        self.calls = 0
        self.exhausted: str | None = None      # set when a daily quota is hit: later calls fail fast
        self._consecutive_429 = 0
        self._last_slowdown = 0.0

    # ---------- keys ----------
    @staticmethod
    def _new_client(key: str):
        from google import genai
        return genai.Client(api_key=key)

    def _next_key(self, used: int, why: str) -> bool:
        """Move on from key number `used` (0-based) to the next one; False when it was the last.
        Parallel workers that hit the same key's limit together move on only once."""
        with self._lock:
            if self.key_index != used:
                return True
            if used + 1 >= len(self.keys):
                return False
            self.key_index = used + 1
            self.client = self._new_client(self.keys[self.key_index])
            self._consecutive_429 = 0
        log.warning("Gemini key %d of %d %s; switching to key %d", used + 1, len(self.keys), why, used + 2)
        return True

    def _all_keys(self) -> str:
        return f" on all {len(self.keys)} keys" if len(self.keys) > 1 else ""

    # ---------- model ----------
    def available_models(self) -> list[str]:
        return sorted(m.name.removeprefix("models/") for m in self.client.models.list())

    def model(self) -> str:
        if self._model:
            return self._model
        while True:                                   # a key that can't even list models: try the next one
            used = self.key_index
            try:
                names = self.available_models()
                break
            except Exception as exc:  # noqa: BLE001
                if not self._next_key(used, f"could not list models ({_short(exc)[:80]})"):
                    raise AIUnavailable(f"Could not list Gemini models: {_short(exc)}") from exc
        with self._lock:
            if self._model:
                return self._model
            for wanted in self.settings.gemini_models:
                exact = [n for n in names if n == wanted]
                close = [n for n in names if n.startswith(wanted + "-")]
                if exact or close:
                    self._model = (exact or sorted(close))[0]
                    log.info("Gemini model: %s", self._model)
                    return self._model
            lite = [n for n in names if "flash-lite" in n]
            raise AIUnavailable(f"None of {', '.join(self.settings.gemini_models)} is available to this key. "
                                f"Flash-lite models it can use: {', '.join(lite) or 'none'}. "
                                "Set GEMINI_MODEL in .env to one of these.")

    # ---------- calls ----------
    def _check_cap(self) -> None:
        if self.store is not None:
            with self._lock:
                if self.store.ai_calls_today() >= self.settings.gemini_daily_cap:
                    raise AIUnavailable(f"Daily Gemini cap reached ({self.settings.gemini_daily_cap}); "
                                        "remaining items stay 'AI pending' until tomorrow")

    def _count(self, purpose: str, ok: bool) -> None:
        with self._lock:
            self.calls += 1
            if self.store is not None:
                self.store.count_ai_call(self._model or "?", purpose, ok)

    def _generate(self, purpose: str, system: str, prompt: str, schema: type[BaseModel] | None,
                  max_tokens: int, attempts: int = 6):
        from google.genai import errors, types
        model = self.model()
        config = types.GenerateContentConfig(system_instruction=system, temperature=0.1,
                                             max_output_tokens=max_tokens)
        if schema is not None:
            config.response_mime_type = "application/json"
            config.response_schema = schema
        for attempt in range(1, attempts + 1):
            if self.exhausted:
                raise AIUnavailable(self.exhausted)
            self._check_cap()
            self.limiter.wait()
            used = self.key_index
            try:
                response = self.client.models.generate_content(model=model, contents=prompt, config=config)
                self._count(purpose, True)
                with self._lock:
                    self._consecutive_429 = 0
                return response
            except errors.APIError as exc:
                self._count(purpose, False)
                code = getattr(exc, "code", None)
                if (code in (401, 403) or (code == 400 and "API key" in str(exc))) \
                        and self._next_key(used, f"was refused ({code})"):
                    continue
                if code in (400, 401, 403, 404):
                    raise AIUnavailable(f"Gemini refused the request ({code}): {_short(exc)}") from exc
                if code == 429:
                    detail = str(exc)
                    quota = ", ".join(sorted(set(re.findall(r"quotaId'?:\s*'?([A-Za-z0-9_-]+)", detail)))) or "unknown"
                    if "PerDay" in detail and self._next_key(used, f"used up its daily quota ({quota})"):
                        continue
                    with self._lock:
                        self._consecutive_429 += 1
                        first = self._consecutive_429 == 1
                        if "PerDay" in detail:
                            self.exhausted = (f"Gemini daily quota used up{self._all_keys()} ({quota}); "
                                              "remaining items retry next run")
                        elif ("PerMinute" in detail and self.limiter.interval < 6.0
                              and time.monotonic() - self._last_slowdown > 15):
                            # adapt to the key's real per-minute limit (free tier is far below 500/min);
                            # at most once per 15 s, so parallel workers hitting 429 together count once
                            self._last_slowdown = time.monotonic()
                            self.limiter.interval = min(6.0, self.limiter.interval * 2)
                            log.info("Gemini per-minute limit: slowing to %.0f requests/min", 60 / self.limiter.interval)
                        elif self._consecutive_429 >= 30:
                            self.exhausted = (f"Gemini keeps refusing with 429 ({quota}); pausing AI for this run. "
                                              "Lower GEMINI_RPM / GEMINI_WORKERS in .env if this repeats")
                    if first or self.exhausted:
                        log.warning("Gemini 429, quota: %s", quota)
                    if self.exhausted:
                        raise AIUnavailable(self.exhausted) from exc
                if attempt == attempts:
                    raise AIUnavailable(f"Gemini failed after {attempts} attempts ({code}): {_short(exc)}") from exc
                suggested = re.search(r"retryDelay'?:\s*'?(\d+)s", str(exc))
                wait = (int(suggested.group(1)) + 1 if suggested else min(60, 2 ** attempt * (5 if code == 429 else 1)))
                wait *= random.uniform(1.0, 1.3)
                log.info("Gemini %s, retry in %.0fs", code, wait)
                self.sleep(wait)
            except Exception as exc:  # network errors
                self._count(purpose, False)
                if attempt == attempts:
                    raise AIUnavailable(f"Gemini unreachable: {_short(exc)}") from exc
                self.sleep(2 ** attempt)
        raise AssertionError("unreachable")

    def json(self, purpose: str, system: str, prompt: str, schema: type[T], max_tokens: int = 2048) -> T:
        """Structured answer validated against `schema`; one retry if the JSON is malformed."""
        last_error = None
        for _ in range(2):
            response = self._generate(purpose, system, prompt, schema, max_tokens)
            try:
                return schema.model_validate_json(response.text or "")
            except ValidationError as exc:
                last_error = exc
                log.info("Gemini returned invalid JSON for %s, retrying once", purpose)
        raise AIUnavailable(f"Gemini answer did not match the expected format: {_short(last_error)}")

    def text(self, purpose: str, system: str, prompt: str, max_tokens: int = 1024) -> str:
        return (self._generate(purpose, system, prompt, None, max_tokens).text or "").strip()


def _short(exc) -> str:
    return str(exc).splitlines()[0][:300] if exc else ""
