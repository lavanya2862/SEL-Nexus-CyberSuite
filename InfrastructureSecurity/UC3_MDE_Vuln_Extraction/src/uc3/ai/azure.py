"""Minimal Azure AI Foundry client over plain HTTPS (no extra library), with the same methods as GeminiClient
(model, json) so the AI Fix Guide uses either one.

Settings: AZURE_FOUNDRY_ENDPOINT, AZURE_FOUNDRY_API_KEY, AZURE_FOUNDRY_DEPLOYMENT (the deployment name in Foundry).
The deployment's OpenAI-compatible chat API is called with the key in the api-key header; the answer schema goes
into the system prompt and the answer comes back as a JSON object.
"""

from __future__ import annotations

import json
import logging
import re
import time

import requests

from uc3.ai.gemini import AIUnavailable, GeminiClient
from uc3.config import Settings

log = logging.getLogger("uc3.ai")
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
    def __init__(self, settings: Settings, session=None, sleep=time.sleep, clock=time.monotonic):
        if not settings.has_azure and session is None:
            raise AIUnavailable("AZURE_FOUNDRY_ENDPOINT, AZURE_FOUNDRY_API_KEY and AZURE_FOUNDRY_DEPLOYMENT "
                                "are not all set in .env")
        self.settings = settings
        self.url = chat_url(settings.azure_endpoint or "")
        self.session = session or requests.Session()
        self.session.headers.update({"api-key": settings.azure_api_key or ""})
        self.sleep, self.clock = sleep, clock
        self.interval = 60.0 / settings.azure_rpm
        self._next = 0.0
        self._dropped: set[str] = set()       # options this deployment refused (e.g. temperature on reasoning models)
        self.calls = 0

    def model(self) -> str:
        return self.settings.azure_deployment or "?"

    def _wait_turn(self) -> None:
        now = self.clock()
        if now < self._next:
            self.sleep(self._next - now)
        self._next = max(now, self._next) + self.interval

    def _body(self, system: str, prompt: str, max_tokens: int) -> dict:
        effort = None if "reasoning_effort" in self._dropped else self.settings.azure_reasoning_effort
        budget = max_tokens + REASONING_ROOM if effort else max_tokens   # a reasoning model thinks inside this budget
        body = {"model": self.model(), "temperature": 0.1, "max_completion_tokens": budget,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
        if effort:
            body["reasoning_effort"] = effort
        for name in self._dropped:
            body.pop(name, None)
        if "max_completion_tokens" in self._dropped:
            body["max_tokens"] = budget       # older chat APIs only know max_tokens
        return body

    def json(self, system: str, prompt: str, schema: dict, max_tokens: int = 2048, attempts: int = 5) -> dict:
        """Answer that follows `schema` (OpenAPI subset), parsed into a dict."""
        system = (f"{system}\n\nAnswer with one JSON object only (no markdown, no text around it) that follows this "
                  f"schema:\n{json.dumps(schema)}")
        attempt = 0
        while True:
            self._wait_turn()
            try:
                response = self.session.post(self.url, json=self._body(system, prompt, max_tokens), timeout=120)
            except requests.RequestException as exc:
                attempt += 1
                if attempt >= attempts:
                    raise AIUnavailable(f"Azure AI Foundry unreachable: {_short(exc)}") from exc
                self.sleep(2 ** attempt)
                continue
            self.calls += 1
            code, detail = response.status_code, response.text
            if code == 200:
                try:
                    return json.loads(_strip_fence(_answer(response)))
                except ValueError:
                    attempt += 1
                    if attempt >= attempts:
                        raise AIUnavailable("Azure AI Foundry answer was not valid JSON")
                    continue
            if code == 400 and self._adapt(detail):
                continue
            if code in (400, 401, 403, 404):
                raise AIUnavailable(f"Azure AI Foundry refused the request ({code}): {_short(detail)}{_hint(code)}")
            attempt += 1
            if attempt >= attempts:
                raise AIUnavailable(f"Azure AI Foundry failed after {attempts} attempts ({code})")
            if code == 429:
                self.interval = min(12.0, self.interval * 2)   # adapt to the deployment's real per-minute limit
            wait = _retry_after(response) or min(60, 5 * 2 ** attempt)
            log.info("Azure AI Foundry %s, retrying in %.0fs", code, wait)
            self.sleep(wait)

    def _adapt(self, detail: str) -> bool:
        """A 400 that names one of the TUNABLE options: leave it out from now on. False when there is none left."""
        low = detail.lower()
        name = next((n for n in TUNABLE if n in low and n not in self._dropped), None)
        if name:
            self._dropped.add(name)
            log.info("Azure AI Foundry deployment %s refused '%s'; sending without it", self.model(), name)
        return name is not None


def make_client(settings: Settings) -> AzureFoundryClient | GeminiClient:
    """The AI that AI_PROVIDER picks (Azure AI Foundry first when set); AIUnavailable when none is set."""
    if settings.ai_provider == "azure":
        return AzureFoundryClient(settings)
    if settings.ai_provider == "gemini":
        return GeminiClient(settings)
    raise AIUnavailable("No AI set in .env (AZURE_FOUNDRY_ENDPOINT + _API_KEY + _DEPLOYMENT, or GEMINI_API_KEY)")


def _answer(response) -> str:
    choice = (response.json().get("choices") or [{}])[0]
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


def _retry_after(response) -> float | None:
    """Seconds Azure asks us to wait (retry-after-ms, then Retry-After)."""
    for name, scale in (("retry-after-ms", 1000.0), ("Retry-After", 1.0)):
        try:
            return float(response.headers[name]) / scale + 1
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _hint(code: int) -> str:
    return {401: " - check AZURE_FOUNDRY_API_KEY",
            403: " - check AZURE_FOUNDRY_API_KEY and the resource's network rules",
            404: " - check AZURE_FOUNDRY_ENDPOINT and AZURE_FOUNDRY_DEPLOYMENT"}.get(code, "")


def _short(text) -> str:
    return str(text).strip().splitlines()[0][:300] if str(text).strip() else ""
