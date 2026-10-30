"""DuckDB storage: one file (data/alert_triage.duckdb) with every table the agent uses.

All timestamps are naive UTC. Writes go through `upsert`, which replaces rows with the same key, so running a step
twice never creates duplicates. One connection per process, guarded by a lock (Threat Intel lesson: DuckDB + threads).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable, Sequence
from datetime import date, datetime, timezone
from pathlib import Path

import duckdb

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id VARCHAR PRIMARY KEY, command VARCHAR, started_at TIMESTAMP, finished_at TIMESTAMP,
    status VARCHAR, steps JSON);
CREATE TABLE IF NOT EXISTS state (key VARCHAR PRIMARY KEY, value VARCHAR);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id VARCHAR PRIMARY KEY, title VARCHAR, severity VARCHAR, status VARCHAR, classification VARCHAR,
    determination VARCHAR, created_at TIMESTAMP, updated_at TIMESTAMP, web_url VARCHAR, alert_count INTEGER,
    sources VARCHAR, devices JSON, accounts JSON, techniques JSON, playbook VARCHAR, fingerprint VARCHAR,
    is_lab BOOLEAN DEFAULT FALSE, origin VARCHAR DEFAULT 'live', ingested_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS verdicts (
    incident_id VARCHAR PRIMARY KEY, fingerprint VARCHAR, playbook VARCHAR, verdict VARCHAR, confidence VARCHAR,
    recommended_severity VARCHAR, escalate BOOLEAN, guardrails JSON, containment JSON, summary VARCHAR,
    ai_status VARCHAR, ai_model VARCHAR, checker_notes JSON, queries_run INTEGER, ti_lookups INTEGER,
    seconds DOUBLE, triaged_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id VARCHAR PRIMARY KEY, incident_id VARCHAR, agree BOOLEAN, analyst_verdict VARCHAR, reason VARCHAR,
    minutes DOUBLE, mode VARCHAR, created_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS actions (
    action_id VARCHAR PRIMARY KEY, incident_id VARCHAR, action VARCHAR, target VARCHAR, status VARCHAR,
    detail VARCHAR, requested_at TIMESTAMP, done_at TIMESTAMP);
CREATE TABLE IF NOT EXISTS ledger (
    run_id VARCHAR PRIMARY KEY, wave VARCHAR, device VARCHAR, account VARCHAR, technique VARCHAR, name VARCHAR,
    match_terms VARCHAR, expected VARCHAR, must_escalate VARCHAR, started_at TIMESTAMP, ended_at TIMESTAMP,
    source_file VARCHAR);
CREATE TABLE IF NOT EXISTS ledger_matches (
    incident_id VARCHAR PRIMARY KEY, run_id VARCHAR, how VARCHAR);
CREATE TABLE IF NOT EXISTS backtest (
    set_name VARCHAR, item_id VARCHAR, truth VARCHAR, truth_detail VARCHAR, category VARCHAR, verdict VARCHAR,
    confidence VARCHAR, escalate BOOLEAN, high_severity BOOLEAN, baseline VARCHAR, guardrails JSON,
    ai_status VARCHAR, seconds DOUBLE, run_at TIMESTAMP, PRIMARY KEY (set_name, item_id));
CREATE TABLE IF NOT EXISTS ai_usage (
    day DATE, model VARCHAR, purpose VARCHAR, calls INTEGER, failures INTEGER, PRIMARY KEY (day, model, purpose));
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def to_utc(value) -> datetime | None:
    """ISO text / datetime -> naive UTC datetime (None if empty or unreadable)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        if "." in text:                     # Microsoft sends 7 decimal places; Python accepts up to 6
            head, _, tail = text.partition(".")
            digits = "".join(c for c in tail if c.isdigit())
            rest = tail[len(digits):]
            text = f"{head}.{digits[:6]}{rest}"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0)


def dumps(value) -> str:
    return json.dumps(value, default=str, ensure_ascii=False)


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path) if str(path) != ":memory:" else path
        if isinstance(self.path, Path):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.con = duckdb.connect(str(path))
        self._lock = threading.RLock()
        self.con.execute(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self.con.close()

    def execute(self, sql: str, params: Sequence | None = None) -> None:
        with self._lock:
            self.con.execute(sql, [_param(p) for p in params] if params else None)

    def query(self, sql: str, params: Sequence | None = None) -> list[dict]:
        with self._lock:
            cur = self.con.execute(sql, [_param(p) for p in params] if params else None)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def scalar(self, sql: str, params: Sequence | None = None):
        rows = self.query(sql, params)
        return next(iter(rows[0].values())) if rows else None

    def upsert(self, table: str, rows: Iterable[dict]) -> int:
        rows = list(rows)
        if not rows:
            return 0
        cols = list(rows[0].keys())
        sql = f"INSERT OR REPLACE INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})"
        with self._lock:
            self.con.executemany(sql, [[_param(r.get(c)) for c in cols] for r in rows])
        return len(rows)

    # ---------- small helpers ----------
    def get_state(self, key: str) -> str | None:
        return self.scalar("SELECT value FROM state WHERE key = ?", [key])

    def set_state(self, key: str, value: str) -> None:
        self.upsert("state", [{"key": key, "value": value}])

    def count_ai_call(self, model: str, purpose: str, ok: bool) -> None:
        self.execute("""INSERT INTO ai_usage VALUES (?, ?, ?, 1, ?)
                        ON CONFLICT (day, model, purpose) DO UPDATE SET calls = calls + 1,
                        failures = failures + EXCLUDED.failures""", [utcnow().date(), model, purpose, 0 if ok else 1])

    def ai_calls_today(self) -> int:
        return int(self.scalar("SELECT COALESCE(SUM(calls), 0) FROM ai_usage WHERE day = ?", [utcnow().date()]))


def _param(value):
    if isinstance(value, (dict, list, tuple)):
        return dumps(value)
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    return value
