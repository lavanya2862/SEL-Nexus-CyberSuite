"""Create threats that only make sense once we know our environment (after the Defender inventory):

1. KEV entries of any age that Defender finds on our devices ("we are exposed to an actively attacked flaw").
2. New serious NVD CVEs (CVSS >= 7, published in the last KEV_BACKFILL_DAYS) on our devices, either mapped
   by Defender or matching an installed product by NVD's CPE vendor/product.
"""

from __future__ import annotations

import json
from datetime import timedelta

from uc1.feeds.common import content_hash, norm_name
from uc1.store import Store, utcnow


def _kev_text(c: dict) -> str:
    return (f"{c.get('kev_name') or c['cve_id']}.\n{c.get('description') or ''}\n"
            f"Known ransomware use: {c.get('kev_ransomware') or 'Unknown'}.\n"
            f"Required action: {c.get('kev_action') or ''}\nCISA remediation due date: {c.get('kev_due')}.")


def exposed_kev(store: Store) -> int:
    rows = store.query("""
        SELECT c.* FROM cves c
        WHERE c.kev_added IS NOT NULL AND c.cve_id IN (SELECT cve_id FROM device_vulns)""")
    new = 0
    for c in rows:
        text = _kev_text(c)
        tid = f"kev:{c['cve_id']}"
        title = f"Actively exploited: {c['cve_id']} ({c.get('kev_name') or 'see CISA KEV'})"
        store.execute("UPDATE threats SET title = ? WHERE threat_id = ?", [title, tid])
        new += store.add_threats([{"threat_id": tid, "source": "CISA KEV", "kind": "kev",
                                   "title": title,
                                   "text": text, "url": f"https://nvd.nist.gov/vuln/detail/{c['cve_id']}",
                                   "published_at": c["kev_added"], "content_hash": content_hash(text)}])
        store.link(tid, "cve", [c["cve_id"]])
    return new


def relevant_new_cves(store: Store, days: int) -> int:
    since = utcnow() - timedelta(days=days)
    installed = {(norm_name(r["vendor"]), norm_name(r["name"])) for r in store.query("SELECT DISTINCT vendor, name FROM software")}
    on_devices = {r["cve_id"] for r in store.query("SELECT DISTINCT cve_id FROM device_vulns")}
    rows = store.query("""SELECT * FROM cves WHERE cvss >= 7 AND published_at >= ? AND kev_added IS NULL""", [since])
    new = 0
    for c in rows:
        products = json.loads(c["products"] or "[]")
        hit = c["cve_id"] in on_devices or any((norm_name(p["vendor"]), norm_name(p["product"])) in installed
                                               for p in products)
        if not hit:
            continue
        names = ", ".join(sorted({f"{p['vendor']} {p['product']}" for p in products})[:5])
        text = f"{c['cve_id']} (CVSS {c['cvss']}, {c['severity']}). Affects: {names}.\n{c['description'] or ''}"
        tid = f"cve:{c['cve_id']}"
        new += store.add_threats([{"threat_id": tid, "source": "NVD", "kind": "cve",
                                   "title": f"New {c['severity'] or ''} vulnerability {c['cve_id']} in {names or 'installed software'}",
                                   "text": text, "url": f"https://nvd.nist.gov/vuln/detail/{c['cve_id']}",
                                   "published_at": c["published_at"], "content_hash": content_hash(text)}])
        store.link(tid, "cve", [c["cve_id"]])
    return new


def run(store: Store, days: int) -> dict:
    return {"exposed_kev": exposed_kev(store), "relevant_new_cves": relevant_new_cves(store, days)}
