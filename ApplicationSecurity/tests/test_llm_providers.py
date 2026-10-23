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
