"""Shared helpers for the feed collectors: HTTP with retries, raw-file saving, text utilities.

Safety: collectors only download the feeds themselves. IOC values (bad URLs, IPs, domains) are stored as
text and never requested.
"""

from __future__ import annotations

import gzip
import hashlib
import html
import json
import logging
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from threat_intel.config import Settings
from threat_intel.store import Store

log = logging.getLogger("threat_intel.feeds")

USER_AGENT = "Threat Intel-ThreatIntel-PoC/0.1 (research; contact via project owner)"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
TAG_RE = re.compile(r"<[^>]+>")


class FeedError(RuntimeError):
    pass


class FeedSkipped(FeedError):
    """An optional feed without its key: reported as 'skipped', not as a failure."""


@dataclass
class FeedContext:
    settings: Settings
    store: Store
    run_dir: Path
    session: requests.Session = field(default_factory=requests.Session)
    sleep: object = time.sleep

    def save_raw(self, name: str, payload) -> Path:
        """Keep an exact copy of what a feed returned (gzip JSON or text) for audit and debugging."""
        self.run_dir.mkdir(parents=True, exist_ok=True)
        is_text = isinstance(payload, (str, bytes))
        path = self.run_dir / (f"{name}.txt.gz" if is_text else f"{name}.json.gz")
        data = payload.encode("utf-8") if isinstance(payload, str) else payload
        with gzip.open(path, "wb") as fh:
            fh.write(data if is_text else json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        return path


def http(ctx: FeedContext, method: str, url: str, *, attempts: int = 5, timeout: float = 90, **kwargs) -> requests.Response:
    headers = {"User-Agent": USER_AGENT, **kwargs.pop("headers", {})}
    for attempt in range(1, attempts + 1):
        try:
            response = ctx.session.request(method, url, headers=headers, timeout=timeout, **kwargs)
        except (requests.ConnectionError, requests.Timeout, requests.exceptions.ChunkedEncodingError) as exc:
            reason = f"network error ({exc.__class__.__name__})"
        else:
            if response.status_code < 400:
                return response
            if response.status_code in (401, 403):
                raise FeedError(f"{response.status_code} from {url.split('?')[0]}: access denied. Check the API key in .env.")
            if response.status_code not in (429, 500, 502, 503, 504):
                raise FeedError(f"{response.status_code} from {url.split('?')[0]}: {response.text[:200]}")
            reason = f"HTTP {response.status_code}"
        if attempt == attempts:
            raise FeedError(f"Gave up on {url.split('?')[0]} after {attempts} attempts ({reason})")
        wait = min(60, 2 ** attempt) * random.uniform(0.8, 1.2)
        log.info("Feed retry %d in %.0fs: %s", attempt, wait, reason)
        ctx.sleep(wait)
    raise AssertionError("unreachable")


def content_hash(*parts: str | None) -> str:
    return hashlib.sha256("\x1f".join(p or "" for p in parts).encode("utf-8")).hexdigest()[:16]


def clean_text(value: str | None) -> str:
    """HTML/RSS text -> plain text."""
    text = html.unescape(TAG_RE.sub(" ", html.unescape(value or "")))
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", text)).strip()


def find_cves(text: str | None) -> list[str]:
    return list(dict.fromkeys(m.upper() for m in CVE_RE.findall(text or "")))


def norm_name(value: str | None) -> str:
    """'Adobe Acrobat Reader DC' -> 'adobe_acrobat_reader_dc' (Defender/CPE naming style)."""
    return re.sub(r"[^a-z0-9]+", "_", (value or "").lower()).strip("_")
