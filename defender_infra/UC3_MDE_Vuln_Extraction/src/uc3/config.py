"""Settings for the UC3 pipeline, read from environment variables and the project's .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_API_BASE = "https://api.security.microsoft.com"


class ConfigError(ValueError):
    """Raised when settings are missing or invalid."""


@dataclass(frozen=True)
class Settings:
    api_base: str
    data_dir: Path
    log_dir: Path
    tenant_id: str | None = None
    client_id: str | None = None
    cert_thumbprint: str | None = None
    cert_path: Path | None = None
    client_secret: str | None = None
    gemini_api_key: str | None = None          # optional: AI fix guide (uc3.ai); without it cards show data only
    gemini_models: tuple[str, ...] = ("gemini-3.5-flash-lite", "gemini-3.1-flash-lite")
    gemini_rpm: int = 10

    @property
    def has_credentials(self) -> bool:
        return bool(self.tenant_id and self.client_id and (self.client_secret or (self.cert_thumbprint and self.cert_path)))

    @property
    def ai_dir(self) -> Path:
        return self.data_dir / "ai"

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def lake_dir(self) -> Path:
        return self.data_dir / "lake"

    @property
    def reporting_dir(self) -> Path:
        return self.data_dir / "reporting"

    @property
    def duckdb_path(self) -> Path:
        return self.data_dir / "uc3.duckdb"

    def ensure_dirs(self) -> None:
        for path in (self.raw_dir, self.lake_dir, self.reporting_dir, self.log_dir):
            path.mkdir(parents=True, exist_ok=True)


def _env(name: str) -> str | None:
    """Return a stripped environment value, treating empty strings as unset."""
    value = os.getenv(name, "").strip()
    return value or None


def _resolve(path_str: str) -> Path:
    path = Path(path_str)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_settings(env_file: Path | None = None, require_credentials: bool = True) -> Settings:
    """Load settings; real environment variables take precedence over the .env file.

    `require_credentials=False` allows offline steps (load, quality checks) to run without Defender login details.
    """
    load_dotenv(env_file if env_file is not None else PROJECT_ROOT / ".env", override=False)
    cert_path = _env("UC3_CERT_PATH")
    settings = Settings(
        api_base=(_env("UC3_API_BASE") or DEFAULT_API_BASE).rstrip("/"),
        data_dir=_resolve(_env("UC3_DATA_DIR") or "./data"),
        log_dir=_resolve(_env("UC3_LOG_DIR") or "./logs"),
        tenant_id=_env("UC3_TENANT_ID"),
        client_id=_env("UC3_CLIENT_ID"),
        cert_thumbprint=_env("UC3_CERT_THUMBPRINT"),
        cert_path=_resolve(cert_path) if cert_path else None,
        client_secret=_env("UC3_CLIENT_SECRET"),
        gemini_api_key=_env("GEMINI_API_KEY"),
        gemini_models=tuple(m for m in (_env("GEMINI_MODEL") or "gemini-3.5-flash-lite",
                                        _env("GEMINI_FALLBACK_MODEL") or "gemini-3.1-flash-lite") if m),
        gemini_rpm=max(1, int(_env("GEMINI_RPM") or 10)),
    )
    if require_credentials:
        validate_credentials(settings)
    return settings


def validate_credentials(settings: Settings) -> None:
    problems = []
    if not settings.api_base.startswith("https://"):
        problems.append("UC3_API_BASE must be an https:// address")
    if not settings.tenant_id:
        problems.append("UC3_TENANT_ID is missing")
    if not settings.client_id:
        problems.append("UC3_CLIENT_ID is missing")
    has_cert = bool(settings.cert_thumbprint and settings.cert_path)
    if not has_cert and not settings.client_secret:
        problems.append("set UC3_CLIENT_SECRET (or UC3_CERT_THUMBPRINT + UC3_CERT_PATH)")
    if settings.cert_path and not settings.cert_path.is_file():
        problems.append(f"certificate file not found: {settings.cert_path}")
    if problems:
        raise ConfigError("Defender settings invalid: " + "; ".join(problems))
