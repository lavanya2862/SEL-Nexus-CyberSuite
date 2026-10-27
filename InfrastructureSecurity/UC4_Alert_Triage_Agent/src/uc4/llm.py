"""AI clients behind one interface (`LLM`), so the triage code does not care which model answers:

- AzureFoundryLLM: a model deployment in Azure AI Foundry (AZURE_FOUNDRY_ENDPOINT / _API_KEY / _DEPLOYMENT), over its
  OpenAI-compatible chat API. Used whenever it is set (AI_PROVIDER=auto, the default).
- GeminiLLM: the Gemini API (free tier), adapted from UC1: model auto-selection, adaptive per-minute rate limiting,
  daily cap, retries, JSON output.

`make_llm` picks the one AI_PROVIDER asks for.

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

import requests

from uc4.api import RateLimiter
from uc4.config import Settings
from uc4.store import Store

log = logging.getLogger("uc4.ai")


class AIUnavailable(RuntimeError):
    """No key, quota used up, or the service keeps failing: callers fall back to rules-only output."""


class LLM:
    """Interface the triage code depends on. AzureFoundryLLM and GeminiLLM implement it; a stub in tests."""

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


JSON_ONLY = "\n\nAnswer with one JSON object only: no markdown, no text before or after it."
TUNABLE = ("reasoning_effort", "temperature", "max_completion_tokens", "response_format")  # options some deployments refuse
REASONING_ROOM = 8000   # extra tokens a reasoning model (gpt-5, o-series) may spend thinking before it answers


def chat_url(endpoint: str) -> str:
    """Chat-completions URL from what the Foundry portal shows: the resource endpoint
    (https://<resource>.openai.azure.com or https://<resource>.services.ai.azure.com), its /openai/v1 address,
    a project endpoint (.../api/projects/<name>), or the full .../chat/completions URL (used as it is)."""
    url = endpoint.strip().rstrip("/")
    if "/chat/completions" in url:
        return url
    url = re.sub(r"/api/projects/[^/]+$", "", url)
    return url + "/chat/completions" if url.endswith("/openai/v1") else url + "/openai/v1/chat/completions"


class AzureFoundryLLM(LLM):
    """A model deployment in Azure AI Foundry, over its OpenAI-compatible chat API (key in the api-key header)."""

    def __init__(self, settings: Settings, store: Store | None = None, session=None, sleep=time.sleep):
        self.settings = settings
        self.store = store
        self.sleep = sleep
        self.available = settings.has_azure or session is not None
        self.url = chat_url(settings.azure_endpoint or "")
        self.session = session or requests.Session()
        self.session.headers.update({"api-key": settings.azure_api_key or ""})
        self.limiter = RateLimiter(settings.azure_rpm, sleep=sleep)
        self._lock = threading.Lock()
        self._dropped: set[str] = set()       # options this deployment refused (e.g. temperature on reasoning models)

    def model(self) -> str:
        return self.settings.azure_deployment or "?"

    def _count(self, purpose: str, ok: bool) -> None:
        if self.store is not None:
            self.store.count_ai_call(self.model(), purpose, ok)

    def _body(self, system: str, prompt: str, max_tokens: int) -> dict:
        effort = None if "reasoning_effort" in self._dropped else self.settings.azure_reasoning_effort
        budget = max_tokens + REASONING_ROOM if effort else max_tokens   # a reasoning model thinks inside this budget
        body = {"model": self.model(), "temperature": 0.0, "max_completion_tokens": budget,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system + JSON_ONLY}, {"role": "user", "content": prompt}]}
        if effort:
            body["reasoning_effort"] = effort
        for name in self._dropped:
            body.pop(name, None)
        if "max_completion_tokens" in self._dropped:
            body["max_tokens"] = budget       # older chat APIs only know max_tokens
        return body

    def _adapt(self, detail: str) -> bool:
        """A 400 that names one of the TUNABLE options: leave it out from now on. False when there is none left."""
        low = detail.lower()
        with self._lock:
            name = next((n for n in TUNABLE if n in low and n not in self._dropped), None)
            if name:
                self._dropped.add(name)
        if name:
            log.info("Azure AI Foundry deployment %s refused '%s'; sending without it", self.model(), name)
        return name is not None

    def json(self, purpose: str, system: str, prompt: str, max_tokens: int = 1500) -> dict:
        if not self.available:
            raise AIUnavailable("Azure AI Foundry is not configured")
        if self.store is not None and self.store.ai_calls_today() >= self.settings.azure_daily_cap:
            raise AIUnavailable(f"Daily AI cap reached ({self.settings.azure_daily_cap})")
        attempt = 0
        while True:
            self.limiter.wait()
            try:
                resp = self.session.post(self.url, json=self._body(system, prompt, max_tokens), timeout=120)
            except requests.RequestException as exc:
                self._count(purpose, False)
                attempt += 1
                if attempt >= 5:
                    raise AIUnavailable(f"Azure AI Foundry unreachable: {_short(exc)}") from exc
                self.sleep(2 ** attempt)
                continue
            code = resp.status_code
            self._count(purpose, code == 200)
            if code == 200:
                return _parse_json(_answer(resp))
            detail = resp.text
            if code == 400 and self._adapt(detail):
                continue
            if code in (400, 401, 403, 404):
                raise AIUnavailable(f"Azure AI Foundry refused the request ({code}): {_short(detail)}{_hint(code)}")
            attempt += 1
            if attempt >= 5:
                raise AIUnavailable(f"Azure AI Foundry failed after {attempt} attempts ({code}): {_short(detail)}")
            if code == 429:
                with self._lock:
                    if self.limiter.interval < 6.0:
                        self.limiter.interval = min(6.0, self.limiter.interval * 2)
                        log.info("Azure AI Foundry rate limit: slowing to %.0f/min", 60 / self.limiter.interval)
            self.sleep((_retry_after(resp) or min(30, 2 ** attempt)) * random.uniform(1.0, 1.3))


def _answer(resp) -> str:
    choice = (resp.json().get("choices") or [{}])[0]
    text = (choice.get("message") or {}).get("content") or ""
    if not text.strip():
        reason = choice.get("finish_reason")
        tip = (" (the model used all its tokens thinking: set AZURE_FOUNDRY_REASONING_EFFORT=minimal in .env)"
               if reason == "length" else "")
        raise AIUnavailable(f"Azure AI Foundry gave an empty answer (finish_reason {reason}){tip}")
    return text


def _retry_after(resp) -> float | None:
    """Seconds Azure asks us to wait (retry-after-ms, then Retry-After)."""
    for name, scale in (("retry-after-ms", 1000.0), ("Retry-After", 1.0)):
        try:
            return float(resp.headers[name]) / scale + 1
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _hint(code: int) -> str:
    return {401: " - check AZURE_FOUNDRY_API_KEY",
            403: " - check AZURE_FOUNDRY_API_KEY and the resource's network rules",
            404: " - check AZURE_FOUNDRY_ENDPOINT and AZURE_FOUNDRY_DEPLOYMENT"}.get(code, "")


def make_llm(settings: Settings, store: Store | None = None) -> LLM | None:
    """The AI that AI_PROVIDER picks (Azure AI Foundry first when set), or None for rules-only triage."""
    if settings.ai_provider == "azure":
        return AzureFoundryLLM(settings, store)
    if settings.ai_provider == "gemini":
        return GeminiLLM(settings, store)
    return None


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
        raise AIUnavailable("The AI did not return JSON")


def _short(exc) -> str:
    return str(exc).splitlines()[0][:300] if exc else ""
