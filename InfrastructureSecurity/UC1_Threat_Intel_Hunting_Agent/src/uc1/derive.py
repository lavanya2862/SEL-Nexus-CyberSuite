"""Create threats that only make sense once we know our environment (after the Defender inventory):

New serious NVD CVEs (CVSS >= 7, published in the last KEV_BACKFILL_DAYS) that match an installed product by NVD's
CPE vendor/product, before Defender lists them on our devices.

A CVE Defender already lists is the Vulnerability Agent's finding: a threat made from it would only repeat Defender's
list (and always later), so none is made, and `forget_repeats` removes the ones earlier versions made.
"""

from __future__ import annotations

import json
from datetime import timedelta

from uc1.feeds.common import content_hash, norm_name
from uc1.store import Store, utcnow

# every table that reports a threat; hunts and their results stay (a record of the searches that ran)
_THREAT_TABLES = ("threat_links", "analysis", "exposure", "scores", "threat_fixes", "findings", "alerts", "threats")


def _installed(store: Store) -> set[tuple[str, str]]:
    return {(norm_name(r["vendor"]), norm_name(r["name"])) for r in store.query("SELECT DISTINCT vendor, name FROM software")}


def _matches_installed(products: list[dict], installed: set[tuple[str, str]]) -> bool:
    return any((norm_name(p["vendor"]), norm_name(p["product"])) in installed for p in products)


def relevant_new_cves(store: Store, days: int) -> int:
    since = utcnow() - timedelta(days=days)
    installed = _installed(store)
    on_devices = {r["cve_id"] for r in store.query("SELECT DISTINCT cve_id FROM device_vulns")}
    rows = store.query("""SELECT * FROM cves WHERE cvss >= 7 AND published_at >= ? AND kev_added IS NULL""", [since])
    new = 0
    for c in rows:
        products = json.loads(c["products"] or "[]")
        if c["cve_id"] in on_devices or not _matches_installed(products, installed):
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


def forget_repeats(store: Store) -> int:
    """Delete the threats earlier versions made from Defender's own list: CISA entries made only because Defender
    found the CVE (their text has no CISA notes, unlike the feed's) and NVD CVEs that match no installed product."""
    installed = _installed(store)
    if not installed:                    # no software inventory (Defender not reached): never treat everything as a repeat
        return 0
    ids = [r["threat_id"] for r in store.query(
        "SELECT threat_id FROM threats WHERE kind = 'kev' AND source = 'CISA KEV' AND text NOT LIKE '%Notes: %'")]
    ids += [f"cve:{r['cve_id']}" for r in store.query(
                "SELECT c.cve_id, c.products FROM threats t JOIN cves c ON t.threat_id = 'cve:' || c.cve_id WHERE t.kind = 'cve'")
            if not _matches_installed(json.loads(r["products"] or "[]"), installed)]
    if not ids:
        return 0
    marks = ", ".join("?" * len(ids))
    for table in _THREAT_TABLES:
        store.execute(f"DELETE FROM {table} WHERE threat_id IN ({marks})", ids)
    return len(ids)


def run(store: Store, days: int) -> dict:
    # older versions titled CISA entries "Actively exploited: …" (feeds/kev.py now says "CISA alert: …")
    store.execute("UPDATE threats SET title = 'CISA alert: ' || substr(title, 21) WHERE title LIKE 'Actively exploited: %'")
    return {"repeats_removed": forget_repeats(store), "relevant_new_cves": relevant_new_cves(store, days)}
