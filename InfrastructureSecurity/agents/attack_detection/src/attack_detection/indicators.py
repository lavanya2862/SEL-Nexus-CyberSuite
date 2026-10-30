"""Small indicator helpers the hunts need (the same rules the Threat Intel Agent uses when it collects them)."""

from __future__ import annotations

import hashlib

from attack_detection.config import read_csv


def content_hash(*parts: str | None) -> str:
    return hashlib.sha256("\x1f".join(p or "" for p in parts).encode("utf-8")).hexdigest()[:16]


def allowlisted(domain: str, allow: list[str] | None = None) -> bool:
    """True for big shared/legitimate domains (config/ioc_allowlist.csv) and their subdomains.
    A bad file on github.com must not make all of github.com 'bad'; exact URL IOCs still cover it."""
    allow = allow if allow is not None else [r["domain"].lower() for r in read_csv("ioc_allowlist.csv") if r.get("domain")]
    d = (domain or "").lower().strip(".")
    return any(d == a or d.endswith("." + a) for a in allow)
