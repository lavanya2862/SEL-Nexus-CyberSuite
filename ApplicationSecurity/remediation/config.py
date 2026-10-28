"""Central configuration, loaded from environment variables and an optional .env file."""
from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


OPENAI_BASE_URL = "https://api.openai.com/v1"
PROVIDER_BASE_URLS = {
    "anthropic": "https://api.anthropic.com/v1",
    # Gemini's OpenAI-compatible endpoint (Authorization: Bearer <GEMINI_API_KEY>).
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=Path(__file__).resolve().parents[2] / ".env", env_file_encoding="utf-8", extra="ignore")

    # --- LLM -------------------------------------------------------------------------------
    llm_provider: Literal["auto", "openai", "anthropic", "gemini", "none"] = "auto"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_timeout_seconds: int = 120
    llm_max_retries: int = 4
    llm_max_concurrency: int = 4
    llm_max_tokens: int = 4096
    llm_fix_attempts: int = 2

    # --- GitHub ------------------------------------------------------------------------------
    github_token: str = ""
    github_api_url: str = "https://api.github.com"
    allowed_git_hosts: str = "github.com"
    git_author_name: str = "SEL Nexus Remediation Agent"
    git_author_email: str = "ai-remediation-bot@users.noreply.github.com"

    # --- Storage -----------------------------------------------------------------------------
    data_dir: Path = Path("./data")
    database_url: str = ""  # default: sqlite file inside data_dir
    max_artifact_bytes: int = 8 * 1024 * 1024
    keep_workspaces: bool = False

    # --- Limits ------------------------------------------------------------------------------
    max_repo_size_mb: int = 750
    clone_timeout_seconds: int = 600
    scanner_timeout_seconds: int = 1200
    job_timeout_seconds: int = 3600
    max_findings_per_run: int = 15
    max_queued_jobs: int = 500
    max_job_attempts: int = 2
    rate_limit_per_minute: int = 30

    # --- Workers / queue ---------------------------------------------------------------------
    embedded_worker: bool = True
    worker_concurrency: int = 2
    lease_seconds: int = 180
    poll_interval_seconds: float = 2.0
    result_cache_ttl_hours: int = 24

    # --- Scanners ----------------------------------------------------------------------------
    enable_trivy: bool = True
    enable_semgrep: bool = True
    enable_bandit: bool = True
    enable_codeql: bool = True
    codeql_path: str = ""  # path to the codeql executable when it is not on PATH
    enable_osv: bool = True
    enable_builtin_sast: bool = True
    enable_builtin_secrets: bool = True
    enable_lockfile_refresh: bool = True  # npm --package-lock-only --ignore-scripts (no repo code runs)
    osv_api_url: str = "https://api.osv.dev"
    semgrep_config: str = "p/default"
    trivy_cache_dir: Path | None = None

    # --- Test & Fix loop on GitHub Actions (testloop.py) --------------------------------------
    test_fix_attempts: int = 3            # Remediation Agent fixes before a person takes over
    test_run_timeout_minutes: int = 30    # how long to wait for one GitHub Actions test run
    test_poll_seconds: float = 10.0       # how often to ask GitHub how the run is doing

    # --- API ---------------------------------------------------------------------------------
    api_keys: str = ""  # comma separated; empty disables auth (local/trusted use only)
    cors_origins: str = ""
    log_level: str = "INFO"
    log_json: bool = False

    allow_workflow_edits: bool = False

    # --- SEL Nexus CyberSuite shared sign-in (see suite_auth.py) ------------------------------
    suite_login_url: str = ""  # e.g. http://127.0.0.1:8000; empty = no shared sign-in (local use, tests)
    suite_auth_dir: Path = Path("../login/data/auth")  # the sign-in page's folder holding session.key

    # --- Each person's own keys (credentials.py), used when the shared sign-in is on -------------
    credentials_key: str = ""  # Fernet key (base64) that encrypts saved keys; best supplied by a secret store
    credentials_key_file: Path | None = None  # else this file (made on first use); default DATA_DIR/credentials.key

    @field_validator("data_dir", "suite_auth_dir", mode="after")
    @classmethod
    def _resolve_dir(cls, value: Path) -> Path:
        return value.expanduser().resolve()

    @field_validator("credentials_key_file", mode="before")
    @classmethod
    def _empty_is_default(cls, value):
        return value or None  # CREDENTIALS_KEY_FILE= in a .env means the default, not the current folder

    @property
    def per_user(self) -> bool:
        """With the shared sign-in on, every person brings their own GitHub token and AI model key."""
        return bool(self.suite_login_url)

    # Derived ------------------------------------------------------------------------------
    @property
    def workspaces_dir(self) -> Path:
        return self.data_dir / "workspaces"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    @property
    def effective_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'remediation.db').as_posix()}"

    @property
    def api_key_set(self) -> set[str]:
        return {k.strip() for k in self.api_keys.split(",") if k.strip()}

    @property
    def allowed_hosts(self) -> set[str]:
        return {h.strip().lower() for h in self.allowed_git_hosts.split(",") if h.strip()}

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def resolved_llm_provider(self) -> str:
        if self.llm_provider != "auto":
            return self.llm_provider
        if not self.llm_api_key or not self.llm_model:
            return "none"
        if "anthropic.com" in self.llm_base_url or self.llm_model.startswith("claude"):
            return "anthropic"
        if "generativelanguage.googleapis.com" in self.llm_base_url or self.llm_model.startswith("gemini"):
            return "gemini"
        return "openai"

    @property
    def effective_llm_base_url(self) -> str:
        """Base URL actually used; fills in the provider's endpoint when the OpenAI default was left in place."""
        base = (self.llm_base_url or "").rstrip("/")
        provider = self.resolved_llm_provider
        if provider in PROVIDER_BASE_URLS and (not base or base == OPENAI_BASE_URL):
            return PROVIDER_BASE_URLS[provider]
        return base or OPENAI_BASE_URL

    @property
    def llm_enabled(self) -> bool:
        return self.resolved_llm_provider != "none" and bool(self.llm_api_key and self.llm_model)

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.workspaces_dir, self.cache_dir, self.runs_dir):
            path.mkdir(parents=True, exist_ok=True)


# Settings that may be changed at runtime from the web UI (persisted in DATA_DIR/runtime_settings.json).
RUNTIME_KEYS = {"llm_provider", "llm_base_url", "llm_model", "llm_api_key", "github_token", "max_findings_per_run",
                "llm_fix_attempts"}
SECRET_KEYS = {"llm_api_key", "github_token"}
_runtime_lock = threading.Lock()
_runtime_cache: tuple[tuple, Settings] | None = None


@lru_cache
def _base_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s


def runtime_settings_path() -> Path:
    return _base_settings().data_dir / "runtime_settings.json"


def load_runtime_overrides() -> dict:
    path = runtime_settings_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if k in RUNTIME_KEYS and v not in (None, "")}


def save_runtime_overrides(updates: dict) -> dict:
    """Merge ``updates`` (None/"" clears a key) into the runtime settings file atomically."""
    current = load_runtime_overrides()
    for key, value in updates.items():
        if key not in RUNTIME_KEYS:
            continue
        if value is None or value == "":
            current.pop(key, None)
        else:
            current[key] = value
    validated = Settings.model_validate({**_base_settings().model_dump(), **current})  # raises on bad values
    del validated
    path = runtime_settings_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    # Two saves within the file system's timestamp resolution keep the same mtime, so the mtime-keyed cache would
    # still return the previous values; drop it so the next get_settings() reads this file.
    global _runtime_cache
    _runtime_cache = None
    return current


def base_settings() -> Settings:
    """Environment settings only: no UI overrides and no person's keys (database, key files, sign-in)."""
    return _base_settings()


# Whose keys get_settings() returns: the signed-in person for a web request, the person who started the scan for the
# worker, the publish thread and the test loop. Each new thread starts without one, so it must set it (user_scope).
_current_user: ContextVar[str | None] = ContextVar("appsec_user", default=None)


def current_user() -> str | None:
    return _current_user.get()


@contextmanager
def user_scope(email: str | None):
    token = _current_user.set(email.strip().lower() if email else None)
    try:
        yield
    finally:
        _current_user.reset(token)


def get_settings() -> Settings:
    """Environment settings with UI-managed runtime overrides applied (re-read when the file changes).

    With the shared sign-in on, the overrides are the current person's own (credentials.py) instead, and the
    server's own GitHub token and AI key are never used: without a person, there are no keys at all."""
    global _runtime_cache
    base = _base_settings()
    if base.per_user:
        from .credentials import settings_for
        return settings_for(base, _current_user.get())
    path = base.data_dir / "runtime_settings.json"
    try:
        stamp = (id(base), path.stat().st_mtime_ns)
    except OSError:
        return base
    with _runtime_lock:
        if _runtime_cache is None or _runtime_cache[0] != stamp:
            overrides = load_runtime_overrides()
            _runtime_cache = (stamp, base.model_copy(update=overrides) if overrides else base)
        return _runtime_cache[1]


def reset_settings_cache() -> None:
    global _runtime_cache
    _base_settings.cache_clear()
    _runtime_cache = None
    from .credentials import clear_cache
    clear_cache()


# Backwards compatible module-level accessor used by older imports.
class _LazySettings:
    def __getattr__(self, item):
        return getattr(get_settings(), item)


settings = _LazySettings()


SECRET_ENV_NAMES = ("LLM_API_KEY", "GITHUB_TOKEN", "API_KEYS", "DATABASE_URL", "CREDENTIALS_KEY")


def scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for child processes with service secrets removed."""
    import os

    env = {k: v for k, v in os.environ.items()
           if k.upper() not in SECRET_ENV_NAMES and not k.upper().endswith(("_TOKEN", "_API_KEY", "_SECRET"))
           and not k.upper().startswith(("AWS_", "AZURE_", "GOOGLE_", "OPENAI", "ANTHROPIC"))}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env["GCM_INTERACTIVE"] = "never"
    if extra:
        env.update(extra)
    return env

