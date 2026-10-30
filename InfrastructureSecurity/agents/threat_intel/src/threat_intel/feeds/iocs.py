"""IOC feeds: abuse.ch (ThreatFox, URLhaus, MalwareBazaar), AlienVault OTX, and our lab TEST indicators.

IOCs are grouped into one threat per malware family per day (e.g. "ThreatFox: Lumma Stealer, 2026-09-30"),
so the hunt step can search Defender for each group in a handful of queries. IOC values are stored as text
only and never visited.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from datetime import timedelta
from urllib.parse import urlsplit

from threat_intel.config import read_csv
from threat_intel.feeds.common import FeedContext, FeedError, FeedSkipped, content_hash, find_cves, http
from threat_intel.store import to_utc, utcnow

THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"
OTX = "https://otx.alienvault.com/api/v1/pulses/subscribed"
MAX_IOCS_PER_THREAT = 300

HEX = {"md5": 32, "sha1": 40, "sha256": 64}
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


# ---------------------------------------------------------------- validation
def allowlisted(domain: str, allow: list[str] | None = None) -> bool:
    """True for big shared/legitimate domains (config/ioc_allowlist.csv) and their subdomains.
    A bad file on github.com must not make all of github.com 'bad'; exact URL IOCs still cover it."""
    allow = allow if allow is not None else [r["domain"].lower() for r in read_csv("ioc_allowlist.csv") if r.get("domain")]
    d = (domain or "").lower().strip(".")
    return any(d == a or d.endswith("." + a) for a in allow)


def normalise_ioc(ioc_type: str, value: str) -> tuple[str, str] | None:
    """Return a clean (type, value) or None if the value isn't a valid indicator of that type."""
    value = (value or "").strip().strip(".").replace("[.]", ".").replace("hxxp", "http")
    t = ioc_type.lower()
    if t in ("ip", "ip:port", "ipv4", "ipv6"):
        host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return None
        return None if (ip.is_private or ip.is_loopback or ip.is_reserved) else ("ip", str(ip))
    if t in ("domain", "hostname"):
        v = value.lower()
        return ("domain", v) if DOMAIN_RE.match(v) and not allowlisted(v) else None
    if t == "url":
        parts = urlsplit(value)
        return ("url", value) if parts.scheme in ("http", "https") and parts.hostname else None
    for name, length in HEX.items():
        if name in t:
            v = value.lower()
            return (name, v) if len(v) == length and all(c in "0123456789abcdef" for c in v) else None
    return None


def host_of(url: str) -> tuple[str, str] | None:
    host = urlsplit(url).hostname or ""
    return normalise_ioc("ip", host) or normalise_ioc("domain", host)


# ---------------------------------------------------------------- grouping into threats
def save_groups(ctx: FeedContext, source: str, prefix: str, groups: dict[tuple[str, str], list[dict]],
                describe) -> int:
    """groups: (family, day) -> list of ioc rows. Stores IOCs, one threat per group, links."""
    new = 0
    for (family, day), items in groups.items():
        items = items[:MAX_IOCS_PER_THREAT]
        ctx.store.upsert("iocs", [{k: i[k] for k in ("ioc_type", "value", "source", "malware", "confidence",
                                                        "first_seen", "reference", "tags", "is_test")} for i in items])
        tid = f"{prefix}:{family}:{day}".lower().replace(" ", "_")
        counts = defaultdict(int)
        for i in items:
            counts[i["ioc_type"]] += 1
        text = describe(family, day, items, counts)
        new += ctx.store.add_threats([{
            "threat_id": tid, "source": source, "kind": "ioc", "title": f"{source}: {family} indicators ({day})",
            "text": text, "url": items[0].get("reference") or "", "published_at": to_utc(day),
            "content_hash": content_hash(text, str(len(items))), "is_test": items[0].get("is_test", False)}])
        ctx.store.link(tid, "ioc", [f"{i['ioc_type']}|{i['value']}" for i in items])
    return new


def _describe(family, day, items, counts):
    kinds = ", ".join(f"{n} {t}" for t, n in sorted(counts.items()))
    tags = sorted({t for i in items for t in (i.get("tags") or "").split(",") if t})[:10]
    return (f"{len(items)} new indicators of compromise for '{family}' reported on {day}: {kinds}. "
            f"Tags: {', '.join(tags) or 'none'}. Source reference: {items[0].get('reference') or 'n/a'}.")


# ---------------------------------------------------------------- abuse.ch
def parse_threatfox(payload: dict, min_confidence: int = 75) -> list[dict]:
    rows = []
    for d in payload.get("data") or []:
        if int(d.get("confidence_level") or 0) < min_confidence:
            continue
        clean = normalise_ioc(d.get("ioc_type", ""), d.get("ioc", ""))
        if not clean:
            continue
        rows.append({"ioc_type": clean[0], "value": clean[1], "source": "ThreatFox",
                     "malware": d.get("malware_printable") or d.get("malware") or "unknown",
                     "confidence": int(d.get("confidence_level") or 0), "first_seen": to_utc(d.get("first_seen")),
                     "reference": d.get("malware_malpedia") or f"https://threatfox.abuse.ch/ioc/{d.get('id')}/",
                     "tags": ",".join(d.get("tags") or []), "is_test": False,
                     "threat_type": d.get("threat_type_desc") or d.get("threat_type")})
    return rows


def parse_urlhaus(payload: dict) -> list[dict]:
    rows = []
    for d in payload.get("urls") or []:
        clean = normalise_ioc("url", d.get("url", ""))
        if not clean:
            continue
        base = {"source": "URLhaus", "malware": (d.get("tags") or ["malware_download"])[0] if d.get("tags") else "malware_download",
                "confidence": 90, "first_seen": to_utc(d.get("date_added")), "reference": d.get("urlhaus_reference"),
                "tags": ",".join(d.get("tags") or []), "is_test": False}
        rows.append({"ioc_type": "url", "value": clean[1], **base})
        host = host_of(clean[1])
        if host:
            rows.append({"ioc_type": host[0], "value": host[1], **base})
    return rows


def parse_bazaar(payload: dict) -> list[dict]:
    rows = []
    data = payload.get("data")
    for d in data if isinstance(data, list) else []:
        clean = normalise_ioc("sha256", d.get("sha256_hash", ""))
        if not clean:
            continue
        rows.append({"ioc_type": "sha256", "value": clean[1], "source": "MalwareBazaar",
                     "malware": d.get("signature") or "unknown", "confidence": 90,
                     "first_seen": to_utc(d.get("first_seen")),
                     "reference": f"https://bazaar.abuse.ch/sample/{clean[1]}/",
                     "tags": ",".join(d.get("tags") or []), "is_test": False})
    return rows


def _group(rows: list[dict]) -> dict[tuple[str, str], list[dict]]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        day = (r["first_seen"] or utcnow()).date().isoformat()
        groups[(r["malware"] or "unknown", day)].append(r)
    return groups


def collect_abusech(ctx: FeedContext) -> dict[str, int]:
    key = ctx.settings.abusech_auth_key
    if not key:
        raise FeedError("ABUSECH_AUTH_KEY is not set in .env (free key from https://auth.abuse.ch/)")
    headers = {"Auth-Key": key}
    results = {}
    tf = http(ctx, "POST", THREATFOX, json={"query": "get_iocs", "days": 1}, headers=headers).json()
    ctx.save_raw("threatfox", tf)
    results["threatfox"] = save_groups(ctx, "ThreatFox", "threatfox", _group(parse_threatfox(tf)), _describe)
    ctx.store.save_feed_state("threatfox", "ok", results["threatfox"])

    uh = http(ctx, "GET", URLHAUS.format(limit=500), headers=headers).json()
    ctx.save_raw("urlhaus", uh)
    results["urlhaus"] = save_groups(ctx, "URLhaus", "urlhaus", _group(parse_urlhaus(uh)), _describe)
    ctx.store.save_feed_state("urlhaus", "ok", results["urlhaus"])

    mb = http(ctx, "POST", BAZAAR, data={"query": "get_recent", "selector": "100"}, headers=headers).json()
    ctx.save_raw("malwarebazaar", mb)
    results["malwarebazaar"] = save_groups(ctx, "MalwareBazaar", "bazaar", _group(parse_bazaar(mb)), _describe)
    ctx.store.save_feed_state("malwarebazaar", "ok", results["malwarebazaar"])
    return results


# ---------------------------------------------------------------- AlienVault OTX
OTX_TYPES = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain", "URL": "url",
             "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256"}


def parse_otx(payload: dict) -> list[dict]:
    pulses = []
    for p in payload.get("results") or []:
        iocs, cves = [], []
        for ind in p.get("indicators") or []:
            if ind.get("type") == "CVE":
                cves.append(ind.get("indicator", "").upper())
                continue
            kind = OTX_TYPES.get(ind.get("type"))
            clean = normalise_ioc(kind, ind.get("indicator", "")) if kind else None
            if clean:
                iocs.append({"ioc_type": clean[0], "value": clean[1], "source": "AlienVault OTX",
                             "malware": (p.get("malware_families") or [{}])[0].get("display_name", "") if isinstance(
                                 (p.get("malware_families") or [{}])[0], dict) else "",
                             "confidence": 70, "first_seen": to_utc(ind.get("created")),
                             "reference": f"https://otx.alienvault.com/pulse/{p.get('id')}", "tags": "",
                             "is_test": False})
        techniques = [a.get("id") if isinstance(a, dict) else a for a in p.get("attack_ids") or []]
        text = f"{p.get('name', '')}\n{p.get('description', '')}\nReferences: {' '.join(p.get('references') or [])[:1000]}"
        pulses.append({"id": p.get("id"), "name": p.get("name", ""), "text": text, "iocs": iocs[:MAX_IOCS_PER_THREAT],
                       "cves": list(dict.fromkeys(cves + find_cves(text))), "techniques": [t for t in techniques if t],
                       "modified": to_utc(p.get("modified")), "created": to_utc(p.get("created"))})
    return pulses


def collect_otx(ctx: FeedContext) -> int:
    key = ctx.settings.otx_api_key
    if not key:
        raise FeedSkipped("OTX_API_KEY is not set in .env (optional feed)")
    state = ctx.store.feed_state("otx")
    since = to_utc(state.get("cursor")) or utcnow() - timedelta(days=ctx.settings.feed_backfill_days)
    started, new, page = utcnow(), 0, 1
    while page <= 5:
        payload = http(ctx, "GET", OTX, params={"modified_since": since.isoformat(), "limit": 20, "page": page},
                       headers={"X-OTX-API-KEY": key}, timeout=60).json()
        ctx.save_raw(f"otx_{page}", payload)
        for p in parse_otx(payload):
            ctx.store.upsert("iocs", [{k: i[k] for k in ("ioc_type", "value", "source", "malware", "confidence",
                                                           "first_seen", "reference", "tags", "is_test")} for i in p["iocs"]])
            tid = f"otx:{p['id']}"
            new += ctx.store.add_threats([{"threat_id": tid, "source": "AlienVault OTX", "kind": "pulse",
                                           "title": p["name"][:200], "text": p["text"][:20000],
                                           "url": f"https://otx.alienvault.com/pulse/{p['id']}",
                                           "published_at": p["created"], "content_hash": content_hash(p["text"])}])
            ctx.store.link(tid, "ioc", [f"{i['ioc_type']}|{i['value']}" for i in p["iocs"]])
            ctx.store.link(tid, "cve", p["cves"])
            ctx.store.link(tid, "technique", p["techniques"])
        if not payload.get("next"):
            break
        page += 1
    ctx.store.save_feed_state("otx", "ok", new, cursor=started.isoformat())
    return new


# ---------------------------------------------------------------- lab TEST indicators
def load_lab_test_iocs(ctx: FeedContext) -> int:
    """Harmless lab-only indicators from config/lab_test_iocs.csv, always marked TEST."""
    rows = []
    for r in read_csv("lab_test_iocs.csv"):
        clean = normalise_ioc(r.get("ioc_type", ""), r.get("value", ""))
        if clean:
            rows.append({"ioc_type": clean[0], "value": clean[1], "source": "LAB TEST", "malware": "LAB TEST",
                         "confidence": 100, "first_seen": utcnow(), "reference": r.get("note", ""), "tags": "test",
                         "is_test": True})
    if not rows:
        return 0
    ctx.store.upsert("iocs", rows)
    text = ("LAB TEST ONLY. Harmless indicators we created ourselves to prove that the hunt finds activity "
            "end-to-end. Not a real threat. Indicators: " + ", ".join(f"{r['ioc_type']} {r['value']}" for r in rows))
    new = ctx.store.add_threats([{"threat_id": "test:lab-indicators", "source": "LAB TEST", "kind": "test",
                                  "title": "TEST: lab test indicators (not a real threat)", "text": text, "url": "",
                                  "published_at": utcnow(), "content_hash": content_hash(text), "is_test": True}])
    ctx.store.link("test:lab-indicators", "ioc", [f"{r['ioc_type']}|{r['value']}" for r in rows])
    ctx.store.link("test:lab-indicators", "technique", ["T1059.001", "T1027"])
    return new
