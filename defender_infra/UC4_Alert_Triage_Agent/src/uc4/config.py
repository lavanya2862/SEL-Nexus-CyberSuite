"""Settings for UC4, read from environment variables and this folder's .env file.

Secrets are never printed: `describe()` only reports whether a value is set. Structure copied from UC1.
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
DEFENDER_BASE = "https://api.security.microsoft.com"


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


def _flag(name: str, default: bool = False) -> bool:
    value = _env(name)
    return default if value is None else value.lower() not in ("0", "false", "no", "off")


def _resolve(path_str: str) -> Path:
    path = Path(path_str)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


LAB_ALERT_TITLES = ("sign-ins from ips that attempt sign-ins to disabled accounts", "malicious inbox rule",
                    "solorigate network beacon")


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    log_dir: Path
    graph_base: str = GRAPH_BASE
    defender_base: str = DEFENDER_BASE
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = field(default=None, repr=False)
    gemini_api_key: str | None = field(default=None, repr=False)
    gemini_models: tuple[str, ...] = ("gemini-3.5-flash-lite", "gemini-3.1-flash-lite")
    gemini_rpm: int = 15
    gemini_daily_cap: int = 1500
    abusech_auth_key: str | None = field(default=None, repr=False)
    otx_api_key: str | None = field(default=None, repr=False)
    abuseipdb_api_key: str | None = field(default=None, repr=False)
    greynoise_api_key: str | None = field(default=None, repr=False)
    lookback_days: int = 14                      # first ingest: incidents updated in the last N days
    window_hours: int = 24                       # related-log searches: +- N hours around the alerts
    max_queries: int = 12                        # searches per incident
    max_rows: int = 500                          # rows per search (fetched); fewer go to the AI
    ai_rows: int = 15                            # rows per search shown to the AI
    max_ti_lookups: int = 20                     # threat-intel look-ups per incident
    writeback: bool = False                      # pilot: post an "AI-triage" comment on the incident
    contain: bool = False                        # stretch: allow human-approved isolate / release
    close: bool = False                          # allow "Agree & close in Defender" after a human decision
    auto_resolve: bool = False                   # automatic resolve / escalate per config/auto_resolve.yaml
    respond: bool = False                        # response playbook: ask Defender to scan / quarantine
    auto_isolate: bool = False                   # playbook may isolate a lab VM by itself (sure, high-severity TP)
    scan_type: str = "Full"                      # Defender antivirus scan the playbook asks for: Full | Quick
    ask_daily_cap: int = 100                     # "Ask about this incident" questions per day (keeps AI quota for triage)
    uc1_dir: Path | None = None                  # UC1 folder: its fix plan is shown as "Fix it with UC1" (read-only)
    lab_devices: tuple[str, ...] = ("opca-wks-01", "opcc-wks-01")
    # Alerts from these rules are lab incidents even without a lab device: the Sentinel Training Lab's analytics
    # rules, which fire on Microsoft's recorded sample data. Lower-case title prefixes (Sentinel can add
    # details to a title, e.g. "Malicious Inbox Rule, affected user ...").
    lab_alert_titles: tuple[str, ...] = LAB_ALERT_TITLES
    sentinel_workspace_id: str | None = None

    # ---------- paths ----------
    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def packets_dir(self) -> Path:
        return self.data_dir / "packets"

    @property
    def verdicts_dir(self) -> Path:
        return self.data_dir / "verdicts"

    @property
    def feedback_dir(self) -> Path:
        return self.data_dir / "feedback"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def export_dir(self) -> Path:
        return self.data_dir / "export"

    @property
    def inbox_dir(self) -> Path:
        return self.data_dir / "inbox"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "uc4.duckdb"

    def ensure_dirs(self) -> None:
        for path in (self.raw_dir, self.cache_dir / "ti", self.packets_dir, self.verdicts_dir, self.feedback_dir,
                     self.reports_dir, self.export_dir, self.inbox_dir / "guide", self.inbox_dir / "ledger",
                     self.log_dir):
            path.mkdir(parents=True, exist_ok=True)

    # ---------- what is available ----------
    @property
    def has_microsoft(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    @property
    def has_gemini(self) -> bool:
        return bool(self.gemini_api_key)

    def describe(self) -> list[tuple[str, bool, str]]:
        """(setting, is_set, why it matters) for every secret/key. Never includes values."""
        return [
            ("UC4_TENANT_ID", bool(self.tenant_id), "Microsoft login (incidents, searches, device info)"),
            ("UC4_CLIENT_ID", bool(self.client_id), "Microsoft login (incidents, searches, device info)"),
            ("UC4_CLIENT_SECRET", bool(self.client_secret), "Microsoft login (incidents, searches, device info)"),
            ("GEMINI_API_KEY", bool(self.gemini_api_key), "AI verdicts (without it: rules-only triage)"),
            ("ABUSECH_AUTH_KEY", bool(self.abusech_auth_key), "threat intel: URLhaus, ThreatFox, MalwareBazaar"),
            ("OTX_API_KEY", bool(self.otx_api_key), "optional threat intel: AlienVault OTX"),
            ("ABUSEIPDB_API_KEY", bool(self.abuseipdb_api_key), "optional threat intel: AbuseIPDB (IP reputation)"),
            ("GREYNOISE_API_KEY", bool(self.greynoise_api_key), "optional threat intel: GreyNoise (internet noise)"),
        ]


def load_settings(env_file: Path | None = None) -> Settings:
    """Real environment variables take precedence over the .env file."""
    load_dotenv(env_file if env_file is not None else PROJECT_ROOT / ".env", override=False)
    models = tuple(m for m in (_env("GEMINI_MODEL") or "gemini-3.5-flash-lite",
                               _env("GEMINI_FALLBACK_MODEL") or "gemini-3.1-flash-lite") if m)
    devices = tuple(d.strip().lower() for d in (_env("UC4_LAB_DEVICES") or "opca-wks-01,opcc-wks-01").split(",")
                    if d.strip())
    return Settings(
        data_dir=_resolve(_env("UC4_DATA_DIR") or "./data"),
        log_dir=_resolve(_env("UC4_LOG_DIR") or "./logs"),
        tenant_id=_env("UC4_TENANT_ID"),
        client_id=_env("UC4_CLIENT_ID"),
        client_secret=_env("UC4_CLIENT_SECRET"),
        gemini_api_key=_env("GEMINI_API_KEY"),
        gemini_models=models,
        gemini_rpm=_int("GEMINI_RPM", 15),
        gemini_daily_cap=_int("GEMINI_DAILY_CAP", 1500),
        abusech_auth_key=_env("ABUSECH_AUTH_KEY"),
        otx_api_key=_env("OTX_API_KEY"),
        abuseipdb_api_key=_env("ABUSEIPDB_API_KEY"),
        greynoise_api_key=_env("GREYNOISE_API_KEY"),
        lookback_days=_int("UC4_LOOKBACK_DAYS", 14),
        window_hours=min(72, max(1, _int("UC4_WINDOW_HOURS", 24))),
        max_queries=_int("UC4_MAX_QUERIES", 12),
        max_rows=min(1000, _int("UC4_MAX_ROWS", 500)),
        ai_rows=_int("UC4_AI_ROWS", 15),
        max_ti_lookups=_int("UC4_MAX_TI_LOOKUPS", 20),
        writeback=_flag("UC4_WRITEBACK"),
        contain=_flag("UC4_CONTAIN"),
        close=_flag("UC4_CLOSE"),
        auto_resolve=_flag("UC4_AUTO_RESOLVE"),
        respond=_flag("UC4_RESPOND"),
        auto_isolate=_flag("UC4_AUTO_ISOLATE"),
        ask_daily_cap=max(0, _int("UC4_ASK_DAILY_CAP", 100)),
        scan_type="Quick" if (_env("UC4_SCAN_TYPE") or "").lower() == "quick" else "Full",
        uc1_dir=_resolve(_env("UC4_UC1_DIR") or "../UC1_Threat_Intel_Hunting_Agent"),
        lab_devices=devices,
        lab_alert_titles=tuple(t.strip().lower() for t in (_env("UC4_LAB_ALERT_TITLES") or "").split("|") if t.strip())
        or LAB_ALERT_TITLES,
        sentinel_workspace_id=_env("UC4_SENTINEL_WORKSPACE_ID"),
    )


def read_csv(name: str, base: Path | None = None) -> list[dict[str, str]]:
    """Read a config CSV (UTF-8, header row). Missing file -> empty list."""
    path = (base or CONFIG_DIR) / name
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return [{k.strip(): (v or "").strip() for k, v in row.items() if k} for row in csv.DictReader(fh)]


def read_yaml(name: str, base: Path | None = None) -> dict:
    path = (base or CONFIG_DIR) / name
    if not path.is_file():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
