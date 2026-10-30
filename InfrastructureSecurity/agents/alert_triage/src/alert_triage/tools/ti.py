"""Threat-intelligence look-ups for the entities on an incident: file hashes, domains/URLs and public IPs.

Free sources: abuse.ch (URLhaus, ThreatFox, MalwareBazaar), AlienVault OTX, AbuseIPDB, GreyNoise Community.
Each result is normalised to {indicator, type, verdict (malicious|suspicious|benign|unknown), sources, detail}.
Results are cached on disk per indicator so a re-run (and the free-tier limits) are respected. Private/lab IPs are
skipped. Everything degrades gracefully: a missing key or a failed call shows "unknown", never an error that stops
the triage.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

import requests

from alert_triage.config import Settings
from alert_triage.packet import is_public_ip

log = logging.getLogger("alert_triage.ti")
CACHE_TTL = 24 * 3600


class ThreatIntel:
    def __init__(self, settings: Settings, session: requests.Session | None = None):
        self.s = settings
        self.http = session or requests.Session()
        self.cache = settings.cache_dir / "ti"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.lookups = 0

    # ---------- cache ----------
    def _cache_path(self, kind: str, value: str) -> Path:
        key = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:24]
        return self.cache / f"{kind}_{key}.json"

    def _cached(self, kind: str, value: str) -> dict | None:
        path = self._cache_path(kind, value)
        if path.is_file() and time.time() - path.stat().st_mtime < CACHE_TTL:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                return None
        return None

    def _store(self, kind: str, value: str, result: dict) -> None:
        try:
            self._cache_path(kind, value).write_text(json.dumps(result), encoding="utf-8")
        except OSError:
            pass

    def _get(self, url: str, **kwargs) -> dict | None:
        try:
            r = self.http.get(url, timeout=20, **kwargs)
            if r.status_code == 200:
                return r.json()
        except (requests.RequestException, ValueError):
            return None
        return None

    def _post(self, url: str, **kwargs) -> dict | None:
        try:
            r = self.http.post(url, timeout=20, **kwargs)
            if r.status_code == 200:
                return r.json()
        except (requests.RequestException, ValueError):
            return None
        return None

    # ---------- per-source ----------
    def _hash(self, sha256: str) -> dict:
        sources, verdict, detail = [], "unknown", []
        if self.s.abusech_auth_key:
            data = self._post("https://mb-api.abuse.ch/api/v1/",
                              data={"query": "get_info", "hash": sha256},
                              headers={"Auth-Key": self.s.abusech_auth_key})
            if data and data.get("query_status") == "ok" and data.get("data"):
                d = data["data"][0]
                sources.append("MalwareBazaar")
                verdict = "malicious"
                detail.append(f"MalwareBazaar: {d.get('signature') or 'known malware sample'}")
        return {"indicator": sha256, "type": "sha256", "verdict": verdict, "sources": sources,
                "detail": "; ".join(detail)}

    def _domain(self, domain: str) -> dict:
        sources, verdict, detail = [], "unknown", []
        if self.s.abusech_auth_key:
            data = self._post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain},
                              headers={"Auth-Key": self.s.abusech_auth_key})
            if data and data.get("query_status") == "ok":
                count = int(data.get("url_count") or 0)
                if count:
                    sources.append("URLhaus")
                    verdict = "malicious"
                    detail.append(f"URLhaus: {count} malicious URL(s) on this host")
        return {"indicator": domain, "type": "domain", "verdict": verdict, "sources": sources,
                "detail": "; ".join(detail)}

    def _ip(self, ip: str) -> dict:
        sources, verdict, detail, score = [], "unknown", [], 0
        if self.s.abuseipdb_api_key:
            data = self._get("https://api.abuseipdb.com/api/v2/check",
                             headers={"Key": self.s.abuseipdb_api_key, "Accept": "application/json"},
                             params={"ipAddress": ip, "maxAgeInDays": "90"})
            d = (data or {}).get("data") if data else None
            if d:
                score = int(d.get("abuseConfidenceScore") or 0)
                sources.append("AbuseIPDB")
                detail.append(f"AbuseIPDB confidence {score}% ({d.get('totalReports', 0)} reports)")
                verdict = "malicious" if score >= 50 else "suspicious" if score >= 10 else "benign"
        if self.s.greynoise_api_key:
            data = self._get(f"https://api.greynoise.io/v3/community/{ip}",
                             headers={"key": self.s.greynoise_api_key})
            if data and data.get("classification"):
                cls = data["classification"]
                sources.append("GreyNoise")
                detail.append(f"GreyNoise: {cls} ({data.get('name') or 'internet scanner/noise'})")
                if cls == "malicious" and verdict != "malicious":
                    verdict = "malicious"
                elif cls == "benign" and verdict == "unknown":
                    verdict = "benign"
        return {"indicator": ip, "type": "ip", "verdict": verdict, "sources": sources, "detail": "; ".join(detail)}

    # ---------- public ----------
    def lookup_all(self, packet: dict) -> list[dict]:
        ent = packet["entities"]
        results, seen = [], set()

        def do(kind: str, value: str, fn):
            value = (value or "").strip()
            if not value or (kind, value.lower()) in seen or self.lookups >= self.s.max_ti_lookups:
                return
            seen.add((kind, value.lower()))
            cached = self._cached(kind, value)
            if cached is None:
                self.lookups += 1
                cached = fn(value)
                self._store(kind, value, cached)
            if cached.get("sources"):
                results.append(cached)

        for f in ent["files"]:
            if f.get("sha256"):
                do("sha256", f["sha256"], self._hash)
        for d in ent["domains"]:
            do("domain", d.get("value"), self._domain)
        for ip in ent["ips"]:
            if ip.get("public") or is_public_ip(ip.get("value", "")):
                do("ip", ip.get("value"), self._ip)
        return results
