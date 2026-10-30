"""FIRST EPSS: probability (0-1) that a CVE will be exploited in the next 30 days.

Only fetched for CVEs we care about: those linked to threats and those on our Defender devices.
"""

from __future__ import annotations

from datetime import date

from threat_intel.feeds.common import FeedContext, http
from threat_intel.store import utcnow

URL = "https://api.first.org/data/v1/epss"
BATCH = 80   # keeps the URL well under length limits


def parse(payload: dict) -> list[dict]:
    return [{"cve_id": d["cve"].upper(), "epss": float(d["epss"]), "percentile": float(d["percentile"]),
             "date": date.fromisoformat(d["date"])} for d in payload.get("data", [])]


def wanted_cves(ctx: FeedContext) -> list[str]:
    rows = ctx.store.query("""
        SELECT DISTINCT value AS cve FROM threat_links WHERE link_type = 'cve'
        UNION SELECT DISTINCT cve_id FROM device_vulns""")
    today = date.today()
    fresh = {r["cve_id"] for r in ctx.store.query("SELECT cve_id FROM cves WHERE epss_date >= ?", [today])}
    return sorted(r["cve"] for r in rows if r["cve"] and r["cve"] not in fresh)


def collect(ctx: FeedContext) -> int:
    cves = wanted_cves(ctx)
    count = 0
    for i in range(0, len(cves), BATCH):
        payload = http(ctx, "GET", URL, params={"cve": ",".join(cves[i:i + BATCH])}).json()
        now = utcnow()
        for row in parse(payload):
            ctx.store.execute("""
                INSERT INTO cves (cve_id, epss, epss_percentile, epss_date, updated_at) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (cve_id) DO UPDATE SET epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile,
                    epss_date = EXCLUDED.epss_date""",
                [row["cve_id"], row["epss"], row["percentile"], row["date"], now])
            count += 1
        ctx.sleep(0.5)
    ctx.store.save_feed_state("epss", "ok", count)
    return count
