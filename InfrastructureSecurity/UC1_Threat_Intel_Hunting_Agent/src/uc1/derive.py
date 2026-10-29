"""Create threats that only make sense once we know our environment (after the Defender inventory):

New serious NVD CVEs (CVSS >= 7, published in the last CVE_WINDOW_DAYS) that match an installed product by NVD's
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
    rows = store.query("""SELECT * FROM cves WHERE cvss >= 7 AND published_at >= ?""", [since])
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
    """Delete NVD CVE threats earlier versions made that match no installed product."""
    installed = _installed(store)
    if not installed:                    # no software inventory (Defender not reached): never treat everything as a repeat
        return 0
    ids = [f"cve:{r['cve_id']}" for r in store.query(
                "SELECT c.cve_id, c.products FROM threats t JOIN cves c ON t.threat_id = 'cve:' || c.cve_id WHERE t.kind = 'cve'")
            if not _matches_installed(json.loads(r["products"] or "[]"), installed)]
    if not ids:
        return 0
    marks = ", ".join("?" * len(ids))
    for table in _THREAT_TABLES:
        store.execute(f"DELETE FROM {table} WHERE threat_id IN ({marks})", ids)
    return len(ids)


def forget_retired(store: Store) -> int:
    """Delete threats from sources that are no longer used: the retired government feed and Microsoft's per-CVE
    entries that existed only because of Microsoft's exploitation flag (Microsoft entries now come from disclosure
    and severity only); drop that flag's count from the monthly summaries too."""
    ids = [r["threat_id"] for r in store.query(
        """SELECT threat_id FROM threats WHERE kind = 'kev' OR threat_id LIKE 'kev:%'
           OR (source = 'Microsoft MSRC' AND (title LIKE '%marked urgent%' OR title LIKE '%in the wild%'))""")]
    if ids:
        marks = ", ".join("?" * len(ids))
        for table in _THREAT_TABLES:
            store.execute(f"DELETE FROM {table} WHERE threat_id IN ({marks})", ids)
    store.execute("""UPDATE threats SET text = regexp_replace(text, ', [0-9]+ marked urgent', '')
                     WHERE source = 'Microsoft MSRC' AND text LIKE '%marked urgent%'""")
    return len(ids)


def run(store: Store, days: int) -> dict:
    return {"retired_removed": forget_retired(store), "repeats_removed": forget_repeats(store),
            "relevant_new_cves": relevant_new_cves(store, days)}
