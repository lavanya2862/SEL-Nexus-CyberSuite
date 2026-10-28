"""Persistence (SQLAlchemy 2). SQLite for single-node use, PostgreSQL for horizontal scaling."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import (JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, create_engine,
                        event)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import base_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repo_url: Mapped[str] = mapped_column(String(500))
    repo_full_name: Mapped[str] = mapped_column(String(200), index=True)
    ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    stage: Mapped[str] = mapped_column(String(40), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    stages: Mapped[list | None] = mapped_column(JSON, nullable=True)
    cache_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    cached_from: Mapped[str | None] = mapped_column(String(64), nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # The signed-in person who started (or last re-ran) the scan: it runs with their keys, and with RUNS_VISIBLE_TO=owner
    # only they see it. Empty for scans made without the shared sign-in.
    owner: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    owner_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_jobs_queue", "status", "priority", "created_at"),)


class JobEvent(Base):
    __tablename__ = "job_events"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(64), ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    level: Mapped[str] = mapped_column(String(10), default="info")
    message: Mapped[str] = mapped_column(Text)


class JobArtifact(Base):
    __tablename__ = "job_artifacts"

    job_id: Mapped[str] = mapped_column(String(64), ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), primary_key=True)
    content_type: Mapped[str] = mapped_column(String(100))
    content: Mapped[str] = mapped_column(Text)
    size: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserCredentials(Base):
    """One person's own settings (GitHub token, AI model and key), encrypted as a whole (credentials.py)."""
    __tablename__ = "user_credentials"

    email: Mapped[str] = mapped_column(String(320), primary_key=True)
    data: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Activity(Base):
    """Who did what and when (activity.py): started, re-ran or cancelled a scan, approved fixes, opened a pull
    request, ran tests, changed their settings. Kept when a scan is gone, so it is not tied to the jobs table."""
    __tablename__ = "activity"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    action: Mapped[str] = mapped_column(String(40), index=True)
    job_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    repo: Mapped[str | None] = mapped_column(String(200), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")


_engine: Engine | None = None
_Session: sessionmaker | None = None
_lock = threading.Lock()


def engine() -> Engine:
    global _engine, _Session
    with _lock:
        if _engine is None:
            url = base_settings().effective_database_url  # never a person's settings: they live in this database
            if url.startswith("sqlite"):
                _engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30},
                                        pool_pre_ping=True)

                @event.listens_for(_engine, "connect")
                def _pragmas(dbapi_conn, _):  # pragma: no cover - driver specific
                    cur = dbapi_conn.cursor()
                    cur.execute("PRAGMA journal_mode=WAL")
                    cur.execute("PRAGMA busy_timeout=30000")
                    cur.execute("PRAGMA foreign_keys=ON")
                    cur.execute("PRAGMA synchronous=NORMAL")
                    cur.close()
            else:
                _engine = create_engine(url, pool_size=10, max_overflow=20, pool_pre_ping=True, pool_recycle=1800)
            Base.metadata.create_all(_engine)
            _migrate(_engine)
            _Session = sessionmaker(bind=_engine, expire_on_commit=False)
        return _engine


def _migrate(eng: Engine) -> None:
    """Additive, idempotent schema upgrades for databases created by older versions."""
    from sqlalchemy import inspect, text
    added = {"jobs": {"stages": "JSON", "owner": "VARCHAR(320)", "owner_name": "VARCHAR(200)"}}
    insp = inspect(eng)
    for table, columns in added.items():
        existing = {c["name"] for c in insp.get_columns(table)}
        for name, ddl in columns.items():
            if name not in existing:
                with eng.begin() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
    with eng.begin() as conn:  # every list is filtered by owner
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_jobs_owner ON jobs (owner)"))


def reset_engine() -> None:
    global _engine, _Session
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine, _Session = None, None


@contextmanager
def session_scope():
    engine()
    session = _Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def as_aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
