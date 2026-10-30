"""Azure AI Foundry client: a model deployment over its OpenAI-compatible chat API, with the same methods as
GeminiClient (model, json, text) so the pipeline uses either one.

Settings: AZURE_FOUNDRY_ENDPOINT, AZURE_FOUNDRY_API_KEY, AZURE_FOUNDRY_DEPLOYMENT (the deployment name in Foundry).
JSON answers: the schema goes into the system prompt, the answer is checked with pydantic (one retry), as with Gemini.
"""

from __future__ import annotations

import json
import logging
import random
import re
import threading
import time
from typing import TypeVar

import requests
from pydantic import BaseModel, ValidationError

from attack_detection.ai.gemini_client import AIUnavailable, GeminiClient
from attack_detection.api_client import RateLimiter
from attack_detection.config import Settings
from attack_detection.store import Store

log = logging.getLogger("attack_detection.ai")
T = TypeVar("T", bound=BaseModel)
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


class AzureFoundryClient:
    def __init__(self, settings: Settings, store: Store | None = None, session=None, sleep=time.sleep):
        if not settings.has_azure and session is None:
            raise AIUnavailable("AZURE_FOUNDRY_ENDPOINT, AZURE_FOUNDRY_API_KEY and AZURE_FOUNDRY_DEPLOYMENT "
                                "are not all set in .env")
        self.settings = settings
        self.store = store
        self.sleep = sleep
        self.url = chat_url(settings.azure_endpoint or "")
        self.session = session or requests.Session()
        self.session.headers.update({"api-key": settings.azure_api_key or ""})
        self.limiter = RateLimiter(settings.azure_rpm, sleep=sleep)
        self._lock = threading.Lock()
        self._dropped: set[str] = set()       # options this deployment refused (e.g. temperature on reasoning models)
        self.calls = 0
        self.exhausted: str | None = None

    # ---------- model ----------
    def model(self) -> str:
        return self.settings.azure_deployment or "?"

    def available_models(self) -> list[str]:
        return [self.model()]                 # a Foundry key reaches the deployments of one resource; we use one

    # ---------- calls ----------
    def _check_cap(self) -> None:
        if self.store is not None:
            with self._lock:
                if self.store.ai_calls_today() >= self.settings.azure_daily_cap:
                    raise AIUnavailable(f"Daily AI cap reached ({self.settings.azure_daily_cap}); "
                                        "remaining items stay 'AI pending' until tomorrow")

    def _count(self, purpose: str, ok: bool) -> None:
        with self._lock:
            self.calls += 1
            if self.store is not None:
                self.store.count_ai_call(self.model(), purpose, ok)

    def _body(self, system: str, prompt: str, max_tokens: int, as_json: bool) -> dict:
        effort = None if "reasoning_effort" in self._dropped else self.settings.azure_reasoning_effort
        budget = max_tokens + REASONING_ROOM if effort else max_tokens   # a reasoning model thinks inside this budget
        body = {"model": self.model(), "temperature": 0.1, "max_completion_tokens": budget,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
        if as_json:
            body["response_format"] = {"type": "json_object"}
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

    def _generate(self, purpose: str, system: str, prompt: str, max_tokens: int, as_json: bool,
                  attempts: int = 6) -> str:
        attempt = 0
        while True:
            if self.exhausted:
                raise AIUnavailable(self.exhausted)
            self._check_cap()
            self.limiter.wait()
            try:
                resp = self.session.post(self.url, json=self._body(system, prompt, max_tokens, as_json), timeout=120)
            except requests.RequestException as exc:
                self._count(purpose, False)
                attempt += 1
                if attempt >= attempts:
                    raise AIUnavailable(f"Azure AI Foundry unreachable: {_short(exc)}") from exc
                self.sleep(2 ** attempt)
                continue
            code = resp.status_code
            self._count(purpose, code == 200)
            if code == 200:
                return _answer(resp)
            detail = resp.text
            if code == 400 and self._adapt(detail):
                continue
            if code in (401, 403):
                self.exhausted = f"Azure AI Foundry refused the key ({code}): {_short(detail)}{_hint(code)}"
                raise AIUnavailable(self.exhausted)
            if code in (400, 404):
                raise AIUnavailable(f"Azure AI Foundry refused the request ({code}): {_short(detail)}{_hint(code)}")
            attempt += 1
            if attempt >= attempts:
                raise AIUnavailable(f"Azure AI Foundry failed after {attempts} attempts ({code}): {_short(detail)}")
            if code == 429:
                with self._lock:
                    if self.limiter.interval < 6.0:
                        self.limiter.interval = min(6.0, self.limiter.interval * 2)
                        log.info("Azure AI Foundry rate limit: slowing to %.0f requests/min", 60 / self.limiter.interval)
            wait = (_retry_after(resp) or min(60, 2 ** attempt * (5 if code == 429 else 1))) * random.uniform(1.0, 1.3)
            log.info("Azure AI Foundry %s, retry in %.0fs", code, wait)
            self.sleep(wait)

    def json(self, purpose: str, system: str, prompt: str, schema: type[T], max_tokens: int = 2048) -> T:
        """Structured answer validated against `schema`; one retry if the JSON is malformed."""
        system = (f"{system}\n\nAnswer with one JSON object only (no markdown, no text around it) that matches this "
                  f"JSON schema:\n{json.dumps(schema.model_json_schema())}")
        last_error = None
        for _ in range(2):
            text = self._generate(purpose, system, prompt, max_tokens, as_json=True)
            try:
                return schema.model_validate_json(_strip_fence(text))
            except ValidationError as exc:
                last_error = exc
                log.info("Azure AI Foundry returned invalid JSON for %s, retrying once", purpose)
        raise AIUnavailable(f"AI answer did not match the expected format: {_short(last_error)}")

    def text(self, purpose: str, system: str, prompt: str, max_tokens: int = 1024) -> str:
        return self._generate(purpose, system, prompt, max_tokens, as_json=False).strip()


def make_client(settings: Settings, store: Store | None = None) -> AzureFoundryClient | GeminiClient | None:
    """The AI that AI_PROVIDER picks (Azure AI Foundry first when set), or None when no AI is set."""
    if settings.ai_provider == "azure":
        return AzureFoundryClient(settings, store)
    if settings.ai_provider == "gemini":
        return GeminiClient(settings, store)
    return None


def _answer(resp) -> str:
    choice = (resp.json().get("choices") or [{}])[0]
    text = (choice.get("message") or {}).get("content") or ""
    if not text.strip():
        reason = choice.get("finish_reason")
        tip = (" (the model used all its tokens thinking: set AZURE_FOUNDRY_REASONING_EFFORT=minimal in .env)"
               if reason == "length" else "")
        raise AIUnavailable(f"Azure AI Foundry gave an empty answer (finish_reason {reason}){tip}")
    return text


def _strip_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
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


def _short(exc) -> str:
    return str(exc).splitlines()[0][:300] if exc else ""
