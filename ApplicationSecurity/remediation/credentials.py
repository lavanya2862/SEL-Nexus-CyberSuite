"""Each signed-in person's own GitHub token and AI model settings, encrypted at rest.

With the suite's shared sign-in on (SUITE_LOGIN_URL), nobody shares keys: every person saves their own GitHub token
and AI model key under the email they signed in with, and a scan, its pull request and its GitHub tests use the keys of
the person who started it. The server's own GITHUB_TOKEN / LLM_API_KEY are never used then.

Each person's settings are stored as one Fernet token (AES-128-CBC + HMAC-SHA256) in the user_credentials table. The
key comes from CREDENTIALS_KEY (best: injected by a secret store such as Azure Key Vault) or a key file made on first
use (CREDENTIALS_KEY_FILE, default DATA_DIR/credentials.key; keep it outside DATA_DIR so a copy of the data alone
cannot be read). Saved keys are never sent back in full.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .config import RUNTIME_KEYS, SECRET_KEYS, Settings, base_settings

log = logging.getLogger(__name__)

CACHE_SECONDS = 30  # other processes (a separate worker) see a change within this time
_cache: dict[str, tuple[float, dict, Settings]] = {}
_lock = threading.Lock()
_NO_SECRETS = {key: "" for key in SECRET_KEYS}


def clear_cache() -> None:
    with _lock:
        _cache.clear()
    _fernet.cache_clear()


def _key_file(s: Settings) -> Path:
    return (s.credentials_key_file or s.data_dir / "credentials.key").expanduser().resolve()


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    s = base_settings()
    if s.credentials_key:
        return Fernet(s.credentials_key.strip().encode())
    path = _key_file(s)
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass  # another process made it first
        else:
            with os.fdopen(fd, "wb") as fh:
                fh.write(Fernet.generate_key())
            log.info("made the key that encrypts saved keys: %s", path)
    if s.data_dir in path.parents:
        log.warning("Saved keys are encrypted with %s, inside DATA_DIR. Set CREDENTIALS_KEY (or CREDENTIALS_KEY_FILE "
                    "outside DATA_DIR) so a copy of the data folder alone cannot be decrypted.", path)
    return Fernet(path.read_bytes().strip())


def load(email: str | None) -> dict:
    """The person's own saved settings ({} when none, or when they can no longer be decrypted)."""
    if not email:
        return {}
    return _entry(email.strip().lower())[1]


def _entry(email: str) -> tuple[float, dict, Settings]:
    now = time.monotonic()
    with _lock:
        hit = _cache.get(email)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit
    from .db import UserCredentials, session_scope
    with session_scope() as db:
        row = db.get(UserCredentials, email)
        blob = row.data if row else None
    data: dict = {}
    if blob:
        try:
            data = json.loads(_fernet().decrypt(blob.encode()))
        except (InvalidToken, ValueError):
            log.error("the saved keys of %s cannot be decrypted (was the encryption key changed?); they must be "
                      "entered again", email)
    data = {k: v for k, v in data.items() if k in RUNTIME_KEYS and v not in (None, "")}
    entry = (now, data, base_settings().model_copy(update={**_NO_SECRETS, **data}))
    with _lock:
        _cache[email] = entry
    return entry


def settings_for(base: Settings, email: str | None) -> Settings:
    """``base`` with this person's own settings applied; without a person, ``base`` without any keys."""
    if not email:
        return base.model_copy(update=_NO_SECRETS)
    return _entry(email.strip().lower())[2]


def save(email: str, updates: dict) -> dict:
    """Merge ``updates`` (None/"" removes a value) into the person's own settings."""
    from .db import UserCredentials, session_scope
    email = email.strip().lower()
    current = dict(load(email))
    changed, removed = [], []
    for key, value in updates.items():
        if key not in RUNTIME_KEYS:
            continue
        if value is None or value == "":
            if current.pop(key, None) is not None:
                removed.append(key)
        else:
            current[key] = value
            changed.append(key)
    Settings.model_validate({**base_settings().model_dump(), **current})  # raises on bad values
    blob = _fernet().encrypt(json.dumps(current).encode()).decode()
    with session_scope() as db:
        row = db.get(UserCredentials, email)
        if row is None:
            db.add(UserCredentials(email=email, data=blob))
        else:
            row.data = blob
    with _lock:
        _cache.pop(email, None)
    # audit trail: who changed which of their settings (never the values)
    log.info("settings of %s changed: saved %s, removed %s", email, sorted(changed) or "-", sorted(removed) or "-")
    return current
