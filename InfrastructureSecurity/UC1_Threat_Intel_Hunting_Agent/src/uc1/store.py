"""DuckDB storage: one file (data/uc1.duckdb) with every table the agent uses.

All timestamps are stored as naive UTC. Writes go through `upsert`, which replaces rows with the same key,
so running a step twice never creates duplicates.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path

import duckdb

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id VARCHAR PRIMARY KEY, command VARCHAR, started_at TIMESTAMP, finished_at TIMESTAMP,
    status VARCHAR, steps JSON);
CREATE TABLE IF NOT EXISTS feed_state (
    feed VARCHAR PRIMARY KEY, cursor VARCHAR, last_run_at TIMESTAMP, last_success_at TIMESTAMP,
    last_status VARCHAR, last_count INTEGER, last_error VARCHAR);
CREATE TABLE IF NOT EXISTS threats (
    threat_id VARCHAR PRIMARY KEY, source VARCHAR, kind VARCHAR, title VARCHAR, text VARCHAR, url VARCHAR,
    published_at TIMESTAMP, first_seen_at TIMESTAMP, content_hash VARCHAR, is_test BOOLEAN DEFAULT FALSE);
CREATE TABLE IF NOT EXISTS threat_links (
    threat_id VARCHAR, link_type VARCHAR, value VARCHAR, origin VARCHAR,
    PRIMARY KEY (threat_id, link_type, value));
CREATE TABLE IF NOT EXISTS cves (
    cve_id VARCHAR PRIMARY KEY, description VARCHAR, published_at TIMESTAMP, last_modified_at TIMESTAMP,
    cvss DOUBLE, severity VARCHAR, vector VARCHAR, products JSON,
    kev_added DATE, kev_due DATE, kev_ransomware VARCHAR, kev_action VARCHAR, kev_name VARCHAR,
    epss DOUBLE, epss_percentile DOUBLE, epss_date DATE, updated_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS iocs (
    ioc_type VARCHAR, value VARCHAR, source VARCHAR, malware VARCHAR, confidence INTEGER,
    first_seen TIMESTAMP, reference VARCHAR, tags VARCHAR, is_test BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (ioc_type, value));
CREATE TABLE IF NOT EXISTS attack_techniques (
    technique_id VARCHAR PRIMARY KEY, name VARCHAR, tactics VARCHAR, platforms VARCHAR, url VARCHAR);
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR PRIMARY KEY, device_name VARCHAR, os_platform VARCHAR, os_version VARCHAR,
    rbac_group VARCHAR, tags VARCHAR, opco VARCHAR, health VARCHAR, last_seen TIMESTAMP, snapshot_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS software (
    device_id VARCHAR, device_name VARCHAR, vendor VARCHAR, name VARCHAR, version VARCHAR, snapshot_at TIMESTAMP,
    PRIMARY KEY (device_id, vendor, name, version));
CREATE TABLE IF NOT EXISTS device_vulns (
    device_id VARCHAR, device_name VARCHAR, cve_id VARCHAR, vendor VARCHAR, name VARCHAR, version VARCHAR,
    severity VARCHAR, cvss DOUBLE, exploit_available BOOLEAN, recommended_update VARCHAR, snapshot_at TIMESTAMP,
    PRIMARY KEY (device_id, cve_id, vendor, name, version));
CREATE TABLE IF NOT EXISTS device_settings (
    device_id VARCHAR, device_name VARCHAR, config_id VARCHAR, name VARCHAR, category VARCHAR, subcategory VARCHAR,
    impact DOUBLE, snapshot_at TIMESTAMP, PRIMARY KEY (device_id, config_id));
CREATE TABLE IF NOT EXISTS analysis (
    threat_id VARCHAR PRIMARY KEY, summary VARCHAR, threat_type VARCHAR, products JSON, techniques JSON,
    actions JSON, confidence VARCHAR, ai_status VARCHAR, ai_model VARCHAR, dropped JSON, error VARCHAR,
    content_hash VARCHAR, analysed_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS exposure (
    threat_id VARCHAR, device_id VARCHAR, device_name VARCHAR, opco VARCHAR, match_type VARCHAR,
    detail VARCHAR, recommended_update VARCHAR, found_at TIMESTAMP,
    PRIMARY KEY (threat_id, device_id, match_type, detail));
CREATE TABLE IF NOT EXISTS scores (
    threat_id VARCHAR PRIMARY KEY, score INTEGER, rating VARCHAR, factors JSON, why VARCHAR, scored_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS hunts (
    hunt_id VARCHAR PRIMARY KEY, run_id VARCHAR, threat_id VARCHAR, name VARCHAR, template VARCHAR,
    origin VARCHAR, technique VARCHAR, query VARCHAR, status VARCHAR, row_count INTEGER, error VARCHAR,
    started_at TIMESTAMP, duration_s DOUBLE);
CREATE TABLE IF NOT EXISTS hunt_results (
    hunt_id VARCHAR, row_no INTEGER, device_id VARCHAR, device_name VARCHAR, event_time TIMESTAMP,
    account VARCHAR, summary VARCHAR, row_json JSON, PRIMARY KEY (hunt_id, row_no));
CREATE TABLE IF NOT EXISTS findings (
    finding_id VARCHAR PRIMARY KEY, threat_id VARCHAR, hunt_id VARCHAR, kind VARCHAR, device_id VARCHAR,
    device_name VARCHAR, opco VARCHAR, detail VARCHAR, users JSON, alerts JSON, timeline JSON,
    is_test BOOLEAN, first_hit TIMESTAMP, created_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id VARCHAR PRIMARY KEY, threat_id VARCHAR, rating VARCHAR, title VARCHAR, message VARCHAR,
    is_test BOOLEAN, created_at TIMESTAMP, delivered VARCHAR);
CREATE TABLE IF NOT EXISTS reports (
    report_id VARCHAR PRIMARY KEY, run_id VARCHAR, docx_path VARCHAR, pdf_path VARCHAR, threat_count INTEGER,
    created_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS resolutions (
    finding_id VARCHAR PRIMARY KEY, what_happened VARCHAR, steps JSON, done_when VARCHAR, source VARCHAR,
    model VARCHAR, dropped JSON, created_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS threat_fixes (
    threat_id VARCHAR PRIMARY KEY, basis VARCHAR, steps JSON, done_when VARCHAR, source VARCHAR, model VARCHAR,
    dropped JSON, created_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS ai_usage (
    day DATE, model VARCHAR, purpose VARCHAR, calls INTEGER, failures INTEGER, PRIMARY KEY (day, model, purpose));
"""

# Step results name at most this many new threats / signs of attack / alerts (by id) for the portal's run page
NEW_IDS_SHOWN = 20


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def to_utc(value) -> datetime | None:
    """Parse many timestamp styles (ISO, 'Z', offsets, RFC-822 from RSS) into naive UTC."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" UTC", "+00:00"))
        except ValueError:
            from email.utils import parsedate_to_datetime
            try:
                dt = parsedate_to_datetime(text)
            except (TypeError, ValueError):
                return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0)


def dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


class Store:
    def __init__(self, path: Path | str = ":memory:"):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.con = duckdb.connect(str(path))
        self.lock = threading.RLock()   # one connection, used by the main thread and AI worker threads
        self.con.execute(SCHEMA)
        # when a threat was FIRST assessed (analysed_at changes when a source updates its text)
        self.con.execute("ALTER TABLE analysis ADD COLUMN IF NOT EXISTS first_assessed_at TIMESTAMP")

    def close(self) -> None:
        self.con.close()

    # ---------- generic ----------
    def upsert(self, table: str, rows: Iterable[dict], columns: Sequence[str] | None = None) -> int:
        rows = list(rows)
        if not rows:
            return 0
        cols = list(columns or rows[0].keys())
        placeholders = ", ".join("?" for _ in cols)
        values = [[_param(row.get(c)) for c in cols] for row in rows]
        with self.lock:
            self.con.executemany(f"INSERT OR REPLACE INTO {table} ({', '.join(cols)}) VALUES ({placeholders})", values)
        return len(rows)

    def insert_new(self, table: str, key: str, rows: Iterable[dict]) -> int:
        """Insert rows whose `key` value isn't stored yet (keeps first_seen timestamps stable)."""
        rows = list(rows)
        if not rows:
            return 0
        existing = {r[0] for r in self.con.execute(f"SELECT {key} FROM {table}").fetchall()}
        fresh = [r for r in rows if r[key] not in existing]
        return self.upsert(table, fresh)

    def query(self, sql: str, params: Sequence | None = None) -> list[dict]:
        with self.lock:
            cur = self.con.execute(sql, params or [])
            names = [d[0] for d in cur.description]
            return [dict(zip(names, row)) for row in cur.fetchall()]

    def scalar(self, sql: str, params: Sequence | None = None):
        with self.lock:
            row = self.con.execute(sql, params or []).fetchone()
        return row[0] if row else None

    def execute(self, sql: str, params: Sequence | None = None) -> None:
        with self.lock:
            self.con.execute(sql, params or [])

    # ---------- threats ----------
    def add_threats(self, threats: Iterable[dict]) -> int:
        """Insert new threats; for known ones, update text/title only (first_seen_at stays)."""
        count = 0
        now = utcnow()
        for t in threats:
            known = self.scalar("SELECT content_hash FROM threats WHERE threat_id = ?", [t["threat_id"]])
            if known is None:
                row = {"first_seen_at": now, "is_test": False, **t}
                self.upsert("threats", [row])
                count += 1
            elif known != t.get("content_hash"):
                self.execute("UPDATE threats SET title = ?, text = ?, url = ?, content_hash = ? WHERE threat_id = ?",
                             [t.get("title"), t.get("text"), t.get("url"), t.get("content_hash"), t["threat_id"]])
        return count

    def link(self, threat_id: str, link_type: str, values: Iterable[str], origin: str = "source") -> None:
        rows = [{"threat_id": threat_id, "link_type": link_type, "value": v, "origin": origin}
                for v in dict.fromkeys(v for v in values if v)]
        if rows:
            # keep 'source' origin if the same link was already found in the source
            existing = {r["value"] for r in self.query(
                "SELECT value FROM threat_links WHERE threat_id = ? AND link_type = ?", [threat_id, link_type])}
            self.upsert("threat_links", [r for r in rows if r["value"] not in existing])

    # ---------- feed state ----------
    def feed_state(self, feed: str) -> dict:
        rows = self.query("SELECT * FROM feed_state WHERE feed = ?", [feed])
        return rows[0] if rows else {"feed": feed, "cursor": None}

    def save_feed_state(self, feed: str, status: str, count: int = 0, cursor: str | None = None,
                        error: str | None = None) -> None:
        prev = self.feed_state(feed)
        now = utcnow()
        self.upsert("feed_state", [{
            "feed": feed, "cursor": cursor if cursor is not None else prev.get("cursor"),
            "last_run_at": now, "last_success_at": now if status == "ok" else prev.get("last_success_at"),
            "last_status": status, "last_count": count, "last_error": (error or "")[:500] or None}])

    # ---------- AI usage ----------
    def count_ai_call(self, model: str, purpose: str, ok: bool) -> None:
        day = utcnow().date()
        self.execute("""INSERT INTO ai_usage VALUES (?, ?, ?, 1, ?)
                        ON CONFLICT (day, model, purpose) DO UPDATE SET calls = calls + 1,
                        failures = failures + EXCLUDED.failures""", [day, model, purpose, 0 if ok else 1])

    def ai_calls_today(self) -> int:
        return int(self.scalar("SELECT COALESCE(SUM(calls), 0) FROM ai_usage WHERE day = ?", [utcnow().date()]))


def _param(value):
    if isinstance(value, (dict, list, tuple)):
        return dumps(value)
    return value
