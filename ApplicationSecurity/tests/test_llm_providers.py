import httpx
import pytest
from fastapi.testclient import TestClient

from remediation import config
from remediation.llm import chat


class _Capture:
    def __init__(self, response_json):
        self.calls = []
        self.response_json = response_json

    def __call__(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "json": json})
        return httpx.Response(200, json=self.response_json, request=httpx.Request("POST", url))


OPENAI_STYLE = {"choices": [{"message": {"content": "OK"}}]}


@pytest.mark.parametrize("env,expected_url", [
    ({"LLM_PROVIDER": "gemini", "LLM_MODEL": "gemini-2.5-flash"},
     "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
    ({"LLM_PROVIDER": "auto", "LLM_MODEL": "gemini-2.5-pro"},  # detected from the model name
     "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
    ({"LLM_PROVIDER": "openai", "LLM_MODEL": "gpt-4o"}, "https://api.openai.com/v1/chat/completions"),
    ({"LLM_PROVIDER": "gemini", "LLM_MODEL": "gemini-2.5-flash", "LLM_BASE_URL": "https://gw.example.com/v1"},
     "https://gw.example.com/v1/chat/completions"),  # a custom gateway URL is respected
])
def test_openai_compatible_routing(monkeypatch, env, expected_url):
    for k, v in {"LLM_API_KEY": "test-key", **env}.items():
        monkeypatch.setenv(k, v)
    config.reset_settings_cache()
    cap = _Capture(OPENAI_STYLE)
    monkeypatch.setattr("remediation.llm.httpx.post", cap)
    assert chat("sys", [{"role": "user", "content": "ping"}]) == "OK"
    call = cap.calls[0]
    assert call["url"] == expected_url
    assert call["headers"]["Authorization"] == "Bearer test-key"
    assert call["json"]["model"] == env["LLM_MODEL"]
    assert call["json"]["messages"][0] == {"role": "system", "content": "sys"}


def test_anthropic_routing(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "claude-test")
    config.reset_settings_cache()
    cap = _Capture({"content": [{"type": "text", "text": "OK"}]})
    monkeypatch.setattr("remediation.llm.httpx.post", cap)
    assert chat("sys", [{"role": "user", "content": "ping"}]) == "OK"
    assert cap.calls[0]["url"] == "https://api.anthropic.com/v1/messages"
    assert cap.calls[0]["headers"]["x-api-key"] == "test-key" and cap.calls[0]["json"]["system"] == "sys"


def test_settings_accept_gemini_provider():
    from remediation.api import app
    with TestClient(app) as c:
        r = c.put("/api/v1/settings", json={"llm_provider": "gemini", "llm_model": "gemini-2.5-flash",
                                             "llm_api_key": "AIzaTestKey1234567890"}).json()
        assert r["llm_enabled"] is True and r["llm_provider"] == "gemini"
        assert r["llm_endpoint"] == "https://generativelanguage.googleapis.com/v1beta/openai"
        assert c.get("/api/v1/capabilities").json()["llm"]["provider"] == "gemini"


def test_daily_quota_fails_fast_without_retrying(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "k")
    monkeypatch.setenv("LLM_MODEL", "gemini-test")
    config.reset_settings_cache()
    calls = []
    body = ('[{"error": {"code": 429, "message": "Quota exceeded", "details": [{"quotaId": '
            '"GenerateRequestsPerDayPerProjectPerModel-FreeTier"}, {"retryDelay": "64377s"}]}}]')

    def post(url, headers=None, json=None, timeout=None):
        calls.append(url)
        return httpx.Response(429, text=body, request=httpx.Request("POST", url))
    monkeypatch.setattr("remediation.llm.httpx.post", post)
    from remediation.llm import LLMQuotaExhausted
    with pytest.raises(LLMQuotaExhausted, match="resets in about 18 h"):
        chat("s", [{"role": "user", "content": "x"}])
    assert len(calls) == 1  # no pointless retries against a daily limit


def test_an_unknown_model_says_so_without_retrying(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "k")
    monkeypatch.setenv("LLM_MODEL", "gemini-3.5-flashlite")
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    config.reset_settings_cache()
    calls = []
    body = ('[{"error": {"code": 404, "message": "models/gemini-3.5-flashlite is not found for API version v1main, or '
            'is not supported for generateContent.", "status": "NOT_FOUND"}}]')

    def post(url, headers=None, json=None, timeout=None):
        calls.append(url)
        return httpx.Response(404, text=body, request=httpx.Request("POST", url))
    monkeypatch.setattr("remediation.llm.httpx.post", post)
    from remediation.llm import LLMError
    with pytest.raises(LLMError, match="the model 'gemini-3.5-flashlite' is not available for this API key. Choose one"):
        chat("s", [{"role": "user", "content": "x"}])
    assert len(calls) == 1
    from remediation.insights import classify
    assert classify({"fix_status": "failed", "fix_note": "LLM request rejected (HTTP 404: the model 'x' is not "
                                                           "available for this API key.)"})[0] == "llm_rejected"


class _Get:
    def __init__(self, status, payload):
        self.calls, self.status, self.payload = [], status, payload

    def __call__(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        return httpx.Response(self.status, json=self.payload, request=httpx.Request("GET", url))


GEMINI_MODELS = {"object": "list", "data": [
    {"id": "models/gemini-2.5-flash"}, {"id": "models/gemini-2.5-flash-lite"}, {"id": "models/gemini-3-pro-preview"},
    {"id": "models/text-embedding-004"}, {"id": "models/gemini-embedding-001"}, {"id": "models/imagen-4.0-generate"},
    {"id": "models/gemini-2.5-flash-preview-tts"}, {"id": "models/aqa"}, {"id": "models/gemma-3-27b-it"}]}


def test_list_models_per_provider(monkeypatch):
    from remediation.llm import LLMError, list_models
    get = _Get(200, GEMINI_MODELS)
    monkeypatch.setattr("remediation.llm.httpx.get", get)
    assert list_models("gemini", "k") == ["gemini-3-pro-preview", "gemini-2.5-flash-lite", "gemini-2.5-flash"]
    assert get.calls[0]["url"] == "https://generativelanguage.googleapis.com/v1beta/openai/models"
    assert get.calls[0]["headers"] == {"Authorization": "Bearer k"}

    get = _Get(200, {"data": [{"id": "gpt-4o"}, {"id": "text-embedding-3-small"}, {"id": "whisper-1"},
                              {"id": "dall-e-3"}, {"id": "gpt-4o-realtime-preview"}, {"id": "o3-mini"}]})
    monkeypatch.setattr("remediation.llm.httpx.get", get)
    assert list_models("openai", "k") == ["o3-mini", "gpt-4o"]
    assert get.calls[0]["url"] == "https://api.openai.com/v1/models"
    list_models("openai", "k", "https://gw.example.com/v1/")
    assert get.calls[1]["url"] == "https://gw.example.com/v1/models"  # "Other": the gateway's own list

    get = _Get(200, {"data": [{"id": "claude-sonnet-x", "type": "model"}, {"id": "claude-haiku-y", "type": "model"}]})
    monkeypatch.setattr("remediation.llm.httpx.get", get)
    assert list_models("anthropic", "k") == ["claude-sonnet-x", "claude-haiku-y"]
    assert get.calls[0]["url"] == "https://api.anthropic.com/v1/models"
    assert get.calls[0]["headers"]["x-api-key"] == "k" and get.calls[0]["headers"]["anthropic-version"]

    monkeypatch.setattr("remediation.llm.httpx.get", _Get(401, {"error": {"message": "API key not valid"}}))
    with pytest.raises(LLMError, match="refused this API key"):
        list_models("gemini", "bad")


def test_settings_need_only_provider_key_and_a_listed_model(monkeypatch):
    from remediation.api import app
    get = _Get(200, GEMINI_MODELS)
    monkeypatch.setattr("remediation.llm.httpx.get", get)
    with TestClient(app) as c:
        assert c.post("/api/v1/settings/models", json={"llm_provider": "gemini"}).status_code == 422  # no key yet
        # a key typed but not saved yet is used for the list
        r = c.post("/api/v1/settings/models", json={"llm_provider": "gemini", "llm_api_key": "AIzaTyped123"})
        assert r.json()["models"][0] == "gemini-3-pro-preview" and get.calls[-1]["headers"]["Authorization"] == "Bearer AIzaTyped123"
        # save provider, key and model: no address needed
        view = c.put("/api/v1/settings", json={"llm_provider": "gemini", "llm_model": "gemini-2.5-flash",
                                                "llm_api_key": "AIzaSaved4567890", "llm_base_url": None}).json()
        assert view["llm_enabled"] is True and view["llm_endpoint"] == "https://generativelanguage.googleapis.com/v1beta/openai"
        # later the saved key is used (the masked placeholder means "the saved one")
        c.post("/api/v1/settings/models", json={"llm_provider": "gemini", "llm_api_key": "••••7890"})
        assert get.calls[-1]["headers"]["Authorization"] == "Bearer AIzaSaved4567890"
        # switching provider to Anthropic with an empty address goes to Anthropic, not to the old one
        view = c.put("/api/v1/settings", json={"llm_provider": "anthropic", "llm_model": "claude-x",
                                                "llm_base_url": None}).json()
        assert view["llm_endpoint"] == "https://api.anthropic.com/v1"
        # a custom address only for "Other" (sent as provider openai)
        c.post("/api/v1/settings/models", json={"llm_provider": "gemini", "llm_base_url": "https://evil.example.com/v1"})
        assert get.calls[-1]["url"] == "https://generativelanguage.googleapis.com/v1beta/openai/models"
        c.post("/api/v1/settings/models", json={"llm_provider": "openai", "llm_base_url": "https://gw.example.com/v1"})
        assert get.calls[-1]["url"] == "https://gw.example.com/v1/models"
