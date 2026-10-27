"""Settings for UC1, read from environment variables and this folder's .env file.

Secrets are never printed: `missing()` and `describe()` only report whether a value is set.
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_API_BASE = "https://api.security.microsoft.com"


class ConfigError(ValueError):
    """Raised when settings are missing or invalid."""


def _env(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def _int(name: str, default: int) -> int:
    value = _env(name)
    try:
        return int(value) if value else default
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number") from exc


def _extra_gemini_keys() -> tuple[str, ...]:
    """GEMINI_API_KEY_2 ... GEMINI_API_KEY_9: spare keys, used in order when the one before runs out for the day."""
    return tuple(k for n in range(2, 10) if (k := _env(f"GEMINI_API_KEY_{n}")))


def _key_count(settings: "Settings") -> str:
    n = len(settings.gemini_keys)
    return f" ({n} keys: the next takes over when one runs out)" if n > 1 else ""


def _effort() -> str | None:
    """AZURE_FOUNDRY_REASONING_EFFORT: minimal | low (default) | medium | high; "off" sends none."""
    value = (_env("AZURE_FOUNDRY_REASONING_EFFORT") or "low").lower()
    return None if value == "off" else value


def _provider() -> str:
    value = (_env("AI_PROVIDER") or "auto").lower()
    if value not in ("auto", "azure", "gemini"):
        raise ConfigError("AI_PROVIDER must be auto, azure or gemini")
    return value


def _resolve(path_str: str) -> Path:
    path = Path(path_str)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    log_dir: Path
    api_base: str = DEFAULT_API_BASE
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = field(default=None, repr=False)
    gemini_api_key: str | None = field(default=None, repr=False)
    gemini_extra_keys: tuple[str, ...] = field(default=(), repr=False)   # GEMINI_API_KEY_2, _3 ...
    gemini_models: tuple[str, ...] = ("gemini-3.5-flash-lite", "gemini-3.1-flash-lite")
    gemini_rpm: int = 15
    gemini_daily_cap: int = 5000
    gemini_workers: int = 2
    ai_provider_choice: str = "auto"             # AI_PROVIDER: auto (Azure Foundry when set, else Gemini) | azure | gemini
    azure_endpoint: str | None = None            # AZURE_FOUNDRY_ENDPOINT, e.g. https://<resource>.openai.azure.com
    azure_api_key: str | None = field(default=None, repr=False)
    azure_deployment: str | None = None          # AZURE_FOUNDRY_DEPLOYMENT: the deployment name in Foundry
    azure_rpm: int = 60
    azure_reasoning_effort: str | None = "low"   # AZURE_FOUNDRY_REASONING_EFFORT for gpt-5 / o-series; off = not sent
    azure_daily_cap: int = 5000
    azure_workers: int = 4
    nvd_api_key: str | None = field(default=None, repr=False)
    abusech_auth_key: str | None = field(default=None, repr=False)
    otx_api_key: str | None = field(default=None, repr=False)
    teams_webhook_url: str | None = field(default=None, repr=False)
    kev_backfill_days: int = 30
    nvd_backfill_days: int = 3
    feed_backfill_days: int = 7
    hunt_lookback_days: int = 30
    # fix loop: which lab VMs UC1 may fix and how
    azure_subscription_id: str | None = None        # empty = found automatically (the one UC1 has a role on)
    fix_resource_group: str = "rg-uc3-lab"          # Run Command only touches VMs in this resource group
    fix_method: str = "runcommand"                  # runcommand | liveresponse (default for new approvals)
    fix_allow_choco: bool = False                   # Chocolatey fallback (downloads + runs its installer as SYSTEM): opt-in
    fix_start_vms: bool = True                      # start a stopped lab VM before fixing it
    fix_devices: tuple[str, ...] = ()               # empty = every Defender device in the plan

    # ---------- paths ----------
    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def dashboard_dir(self) -> Path:
        return self.data_dir / "dashboard"

    @property
    def fix_dir(self) -> Path:
        return self.data_dir / "fix"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "uc1.duckdb"

    def ensure_dirs(self) -> None:
        for path in (self.raw_dir, self.cache_dir, self.reports_dir, self.dashboard_dir, self.log_dir, self.fix_dir):
            path.mkdir(parents=True, exist_ok=True)

    # ---------- what is available ----------
    @property
    def has_defender(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    @property
    def has_gemini(self) -> bool:
        return bool(self.gemini_keys)

    @property
    def has_azure(self) -> bool:
        return bool(self.azure_endpoint and self.azure_api_key and self.azure_deployment)

    @property
    def ai_provider(self) -> str | None:
        """"azure", "gemini" or None (no AI). AI_PROVIDER=auto prefers Azure Foundry when it is set."""
        if self.ai_provider_choice == "azure":
            return "azure" if self.has_azure else None
        if self.ai_provider_choice == "gemini":
            return "gemini" if self.has_gemini else None
        return "azure" if self.has_azure else "gemini" if self.has_gemini else None

    @property
    def ai_workers(self) -> int:
        """Parallel AI calls in the analyse step, for the AI in use."""
        return self.azure_workers if self.ai_provider == "azure" else self.gemini_workers

    @property
    def gemini_keys(self) -> tuple[str, ...]:
        """GEMINI_API_KEY, then the spare keys: the next one takes over when one uses up its daily quota."""
        return tuple(dict.fromkeys(k for k in (self.gemini_api_key, *self.gemini_extra_keys) if k))

    def describe(self) -> list[tuple[str, bool, str]]:
        """(setting, is_set, why it matters) for every secret/key. Never includes values."""
        return [
            ("DEFENDER_TENANT_ID", bool(self.tenant_id), "Defender login (inventory, hunts)"),
            ("DEFENDER_CLIENT_ID", bool(self.client_id), "Defender login (inventory, hunts)"),
            ("DEFENDER_CLIENT_SECRET", bool(self.client_secret), "Defender login (inventory, hunts)"),
            ("AZURE_FOUNDRY_API_KEY", self.has_azure, "AI via Azure AI Foundry (with ENDPOINT + DEPLOYMENT)"
             + (" - in use" if self.ai_provider == "azure" else "")),
            ("GEMINI_API_KEY", self.has_gemini, "AI via Gemini: summaries, KQL drafts, report summary"
             + _key_count(self) + (" - in use" if self.ai_provider == "gemini" else "")),
            ("NVD_API_KEY", bool(self.nvd_api_key), "optional: 10x faster NVD downloads"),
            ("ABUSECH_AUTH_KEY", bool(self.abusech_auth_key), "IOC feeds (ThreatFox, URLhaus, MalwareBazaar)"),
            ("OTX_API_KEY", bool(self.otx_api_key), "optional: AlienVault OTX pulses"),
        ]


def load_settings(env_file: Path | None = None) -> Settings:
    """Real environment variables take precedence over the .env file."""
    load_dotenv(env_file if env_file is not None else PROJECT_ROOT / ".env", override=False)
    models = tuple(m for m in (_env("GEMINI_MODEL") or "gemini-3.5-flash-lite",
                               _env("GEMINI_FALLBACK_MODEL") or "gemini-3.1-flash-lite") if m)
    api_base = (_env("DEFENDER_API_BASE") or DEFAULT_API_BASE).rstrip("/")
    if not api_base.startswith("https://"):
        raise ConfigError("DEFENDER_API_BASE must be an https:// address")
    return Settings(
        data_dir=_resolve(_env("UC1_DATA_DIR") or "./data"),
        log_dir=_resolve(_env("UC1_LOG_DIR") or "./logs"),
        api_base=api_base,
        tenant_id=_env("DEFENDER_TENANT_ID"),
        client_id=_env("DEFENDER_CLIENT_ID"),
        client_secret=_env("DEFENDER_CLIENT_SECRET"),
        gemini_api_key=_env("GEMINI_API_KEY"),
        gemini_extra_keys=_extra_gemini_keys(),
        gemini_models=models,
        gemini_rpm=_int("GEMINI_RPM", 15),
        gemini_daily_cap=_int("GEMINI_DAILY_CAP", 5000),
        gemini_workers=max(1, _int("GEMINI_WORKERS", 2)),
        ai_provider_choice=_provider(),
        azure_endpoint=_env("AZURE_FOUNDRY_ENDPOINT"),
        azure_api_key=_env("AZURE_FOUNDRY_API_KEY"),
        azure_deployment=_env("AZURE_FOUNDRY_DEPLOYMENT"),
        azure_rpm=max(1, _int("AZURE_FOUNDRY_RPM", 60)),
        azure_reasoning_effort=_effort(),
        azure_daily_cap=_int("AZURE_FOUNDRY_DAILY_CAP", 5000),
        azure_workers=max(1, _int("AZURE_FOUNDRY_WORKERS", 4)),
        nvd_api_key=_env("NVD_API_KEY"),
        abusech_auth_key=_env("ABUSECH_AUTH_KEY"),
        otx_api_key=_env("OTX_API_KEY"),
        teams_webhook_url=_env("TEAMS_WEBHOOK_URL"),
        kev_backfill_days=_int("KEV_BACKFILL_DAYS", 30),
        nvd_backfill_days=_int("NVD_BACKFILL_DAYS", 3),
        feed_backfill_days=_int("FEED_BACKFILL_DAYS", 7),
        hunt_lookback_days=min(30, _int("HUNT_LOOKBACK_DAYS", 30)),
        azure_subscription_id=_env("AZURE_SUBSCRIPTION_ID"),
        fix_resource_group=_env("FIX_RESOURCE_GROUP") or "rg-uc3-lab",
        fix_method=_method(_env("FIX_METHOD") or "runcommand"),
        fix_allow_choco=(_env("FIX_ALLOW_CHOCO") or "0").lower() in ("1", "true", "yes"),
        fix_start_vms=(_env("FIX_START_VMS") or "1") not in ("0", "false", "no"),
        fix_devices=tuple(d.strip().lower() for d in (_env("FIX_DEVICES") or "").split(",") if d.strip()),
    )


def _method(value: str) -> str:
    value = value.lower().replace("_", "").replace("-", "")
    if value not in ("runcommand", "liveresponse"):
        raise ConfigError("FIX_METHOD must be runcommand or liveresponse")
    return value


def read_csv(name: str) -> list[dict[str, str]]:
    """Read a config CSV (UTF-8, header row). Missing file -> empty list."""
    path = CONFIG_DIR / name
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return [{k.strip(): (v or "").strip() for k, v in row.items() if k} for row in csv.DictReader(fh)]


def read_policy(name: str = "risk_policy.csv") -> dict[str, float]:
    return {row["setting"]: float(row["value"]) for row in read_csv(name) if row.get("setting")}
