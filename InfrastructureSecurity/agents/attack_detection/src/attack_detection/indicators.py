"""Small helpers for the threats this agent creates."""

from __future__ import annotations

import hashlib


def content_hash(*parts: str | None) -> str:
    return hashlib.sha256("\x1f".join(p or "" for p in parts).encode("utf-8")).hexdigest()[:16]

