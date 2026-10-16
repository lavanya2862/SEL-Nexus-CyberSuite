"""Security advisories: NCSC-NL and CERT-EU (RSS), and Microsoft's monthly security updates (MSRC CVRF)."""

from __future__ import annotations

import re

import feedparser

from uc1.feeds.common import FeedContext, clean_text, content_hash, find_cves, http
from uc1.store import to_utc

RSS_FEEDS = {
    "ncsc_nl": ("NCSC-NL", "https://advisories.ncsc.nl/rss/advisories"),
    "cert_eu": ("CERT-EU", "https://cert.europa.eu/publications/security-advisories-rss"),
}
MSRC_UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
NCSC_ID = re.compile(r"NCSC-\d{4}-\d{4}")


def parse_rss(feed_key: str, raw: bytes) -> list[dict]:
    source, _ = RSS_FEEDS[feed_key]
    parsed = feedparser.parse(raw)
    items = []
    for e in parsed.entries:
        title = clean_text(e.get("title"))
        text = clean_text(e.get("content", [{}])[0].get("value") if e.get("content") else e.get("summary") or e.get("description"))
        link = (e.get("link") or "").strip()
        if feed_key == "ncsc_nl":
            m = NCSC_ID.search(title)
            ident = m.group(0) if m else content_hash(title)
        else:
            ident = (e.get("id") or e.get("guid") or link or content_hash(title)).strip()
        items.append({"threat_id": f"{feed_key}:{ident}", "source": source, "kind": "advisory", "title": title,
                      "text": text[:20000], "url": link,
                      "published_at": to_utc(e.get("published") or e.get("updated")),
                      "content_hash": content_hash(title, text), "cves": find_cves(f"{title}\n{text}")})
    return items


def collect_rss(ctx: FeedContext, feed_key: str) -> int:
    _, url = RSS_FEEDS[feed_key]
    raw = http(ctx, "GET", url).content
    ctx.save_raw(feed_key, raw)
    items = parse_rss(feed_key, raw)
    new = ctx.store.add_threats({k: v for k, v in i.items() if k != "cves"} for i in items)
    for i in items:
        ctx.store.link(i["threat_id"], "cve", i["cves"])
    ctx.store.save_feed_state(feed_key, "ok", new)
    return new


# ---------------------------------------------------------------- MSRC
def _threat_value(vuln: dict, kind: int) -> str:
    for t in vuln.get("Threats", []):
        if t.get("Type") == kind and t.get("Description", {}).get("Value"):
            return t["Description"]["Value"]
    return ""


def parse_msrc(doc: dict) -> dict:
    """Summarise one monthly CVRF document: exploited / publicly disclosed / critical CVEs."""
    title = doc.get("DocumentTitle", {}).get("Value", "Microsoft security updates")
    rows = []
    for v in doc.get("Vulnerability", []):
        cve = (v.get("CVE") or "").upper()
        if not cve:
            continue
        status = _threat_value(v, 1)
        severity = _threat_value(v, 3)
        scores = [s.get("BaseScore") for s in v.get("CVSSScoreSets", []) if s.get("BaseScore")]
        rows.append({"cve": cve, "title": v.get("Title", {}).get("Value", ""), "severity": severity,
                     "exploited": "Exploited:Yes" in status, "disclosed": "Publicly Disclosed:Yes" in status,
                     "cvss": max(scores) if scores else None})
    return {"title": title, "rows": rows}


def msrc_threats(month_id: str, url: str, summary: dict, released) -> list[dict]:
    rows = summary["rows"]
    important = [r for r in rows if r["exploited"] or r["disclosed"] or r["severity"] == "Critical"]
    threats = []
    for r in rows:
        if r["exploited"] or r["disclosed"]:
            state = "exploited in the wild" if r["exploited"] else "publicly disclosed before a fix"
            text = (f"Microsoft {summary['title']}: {r['cve']} {r['title']}. Severity {r['severity'] or 'n/a'}, "
                    f"CVSS {r['cvss'] or 'n/a'}. Microsoft marks this vulnerability as {state}. "
                    f"Install the {month_id} security updates.")
            threats.append({"threat_id": f"msrc:{r['cve']}", "source": "Microsoft MSRC", "kind": "advisory",
                            "title": f"Microsoft {month_id}: {r['cve']} {state}", "text": text,
                            "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{r['cve']}",
                            "published_at": released, "content_hash": content_hash(text), "cves": [r["cve"]]})
    crit = [r for r in rows if r["severity"] == "Critical"]
    text = (f"{summary['title']}: {len(rows)} vulnerabilities fixed, {len(crit)} rated Critical, "
            f"{sum(r['exploited'] for r in rows)} exploited in the wild, {sum(r['disclosed'] for r in rows)} publicly "
            f"disclosed. Critical: " + "; ".join(f"{r['cve']} {r['title']}" for r in crit[:40]))
    threats.append({"threat_id": f"msrc:{month_id}", "source": "Microsoft MSRC", "kind": "advisory",
                    "title": summary["title"], "text": text[:20000], "url": url, "published_at": released,
                    "content_hash": content_hash(text), "cves": [r["cve"] for r in important][:300]})
    return threats


def collect_msrc(ctx: FeedContext) -> int:
    updates = http(ctx, "GET", MSRC_UPDATES, headers={"Accept": "application/json"}).json().get("value", [])
    updates = sorted(updates, key=lambda u: u.get("InitialReleaseDate") or "")[-2:]   # current + previous month
    state = ctx.store.feed_state("msrc")
    seen = dict(p.split("=", 1) for p in (state.get("cursor") or "").split(";") if "=" in p)
    new = 0
    for u in updates:
        month_id, revised = u["ID"], u.get("CurrentReleaseDate") or ""
        if seen.get(month_id) == revised:
            continue
        doc = http(ctx, "GET", u["CvrfUrl"], headers={"Accept": "application/json"}, timeout=300).json()
        for t in msrc_threats(month_id, f"https://msrc.microsoft.com/update-guide/releaseNote/{month_id}",
                              parse_msrc(doc), to_utc(u.get("InitialReleaseDate"))):
            new += ctx.store.add_threats([{k: v for k, v in t.items() if k != "cves"}])
            ctx.store.link(t["threat_id"], "cve", t["cves"])
        seen[month_id] = revised
    ctx.store.save_feed_state("msrc", "ok", new, cursor=";".join(f"{k}={v}" for k, v in seen.items()))
    return new
