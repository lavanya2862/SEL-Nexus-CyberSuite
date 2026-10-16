"""Exposure: which of our devices are affected by each threat.

1. By CVE (exact): the threat's CVEs that Defender reports on a device.
2. Not in Defender yet ("early"): a CVE of the threat that Defender does NOT list on a device, but NVD says the
   installed version of that app is affected (version checked against NVD's ranges, never by name alone).
   Defender needs time to add new holes to its catalogue; the news has them on day 0. After EARLY_DAYS without
   Defender confirming, the match is "closed" (Defender says not affected, or it was patched).
3. By product (possible): only for threats WITHOUT CVEs (e.g. an advisory that names a product).
4. Watch-list (not verified): products Defender can't see, from config/tech_watchlist.csv (if present).
"""

from __future__ import annotations

import json
import re
from datetime import timedelta

from rapidfuzz import fuzz

from uc1.config import read_csv
from uc1.feeds.common import norm_name
from uc1.store import Store, utcnow

EARLY_DAYS = 30   # how long a hole the news names may wait for Defender before we call it "not confirmed"


def _version(value) -> tuple[int, ...]:
    """'3.5.7.0' -> (3, 5, 7): numbers only, trailing zeros dropped so 157.0.1 equals 157.0.1.0."""
    parts = [int(x) for x in re.findall(r"\d+", str(value or ""))]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def in_range(installed: str, ranges: list[dict]) -> bool | None:
    """Is the installed version inside one of the affected ranges (NVD CPE or CNA style)? None = no versions given."""
    v = _version(installed)
    if not ranges or not v:
        return None
    for r in ranges:
        if r.get("status") == "unaffected":
            continue
        bounds = {"versionStartIncluding": lambda b: v >= b, "versionStartExcluding": lambda b: v > b,
                  "versionEndIncluding": lambda b: v <= b, "versionEndExcluding": lambda b: v < b,
                  "lessThanOrEqual": lambda b: v <= b, "lessThan": lambda b: v < b}
        given = [k for k in bounds if r.get(k) not in (None, "", "*")]
        if given:
            start = r.get("version") if any(k.startswith("less") for k in given) else None   # CNA: version..lessThan
            if all(bounds[k](_version(r[k])) for k in given) and (not start or start in ("0", "*") or v >= _version(start)):
                return True
        elif r.get("version") not in (None, "", "*", "-") and _version(r["version"]) == v:
            return True
    return False


def _fixed_in(ranges: list[dict]) -> str | None:
    """The first safe version, when the range says so ('fixed in 4.0.3')."""
    for r in ranges:
        if r.get("versionEndExcluding") or r.get("lessThan"):
            return r.get("versionEndExcluding") or r.get("lessThan")
    return None


def _words(value: str) -> str:
    return norm_name(value).replace("_", " ")


def product_matches(vendor: str, product: str, installed: list[dict]) -> list[dict]:
    """Installed software rows that look like vendor/product (vendor must agree, product must be close)."""
    v, p = _words(vendor), _words(product)
    if len(p) < 3:
        return []
    hits = []
    for s in installed:
        sv, sp = _words(s["vendor"]), _words(s["name"])
        vendor_ok = not v or v == sv or fuzz.ratio(v, sv) >= 85 or v in sp
        if not vendor_ok:
            continue
        if p == sp or (fuzz.token_set_ratio(p, sp) >= 90 and len(set(p.split()) & set(sp.split())) > 0):
            hits.append(s)
    return hits


def compute(store: Store) -> dict:
    now = utcnow()
    devices = {d["device_id"]: d for d in store.query("SELECT * FROM devices")}
    installed = store.query("SELECT DISTINCT device_id, device_name, vendor, name, version FROM software")
    watchlist = read_csv("tech_watchlist.csv")
    links = store.query("SELECT threat_id, link_type, value FROM threat_links WHERE link_type IN ('cve', 'product')")
    by_threat: dict[str, dict[str, set]] = {}
    for l in links:
        by_threat.setdefault(l["threat_id"], {"cve": set(), "product": set()})[l["link_type"]].add(l["value"])

    listed = {(r["device_id"], r["cve_id"]) for r in store.query("SELECT DISTINCT device_id, cve_id FROM device_vulns")}
    cve_info = {c["cve_id"]: c for c in store.query("SELECT cve_id, products, published_at FROM cves WHERE products IS NOT NULL")}
    wait_from = now - timedelta(days=EARLY_DAYS)

    store.execute("DELETE FROM exposure")
    rows = []
    for tid, lk in by_threat.items():
        if lk["cve"]:
            placeholders = ",".join("?" for _ in lk["cve"])
            for v in store.query(f"SELECT * FROM device_vulns WHERE cve_id IN ({placeholders})", sorted(lk["cve"])):
                d = devices.get(v["device_id"], {})
                rows.append({"threat_id": tid, "device_id": v["device_id"], "device_name": v["device_name"],
                             "opco": d.get("opco", "Unassigned"), "match_type": "cve",
                             "detail": f"{v['cve_id']} via {v['name']} {v['version']}",
                             "recommended_update": v["recommended_update"] or
                                 f"Update {v['name'].replace('_', ' ')} (installed {v['version']}) to the latest version",
                             "found_at": now})
            # holes Defender doesn't list (yet) on a device whose installed version NVD says is affected
            for cve in sorted(lk["cve"]):
                info = cve_info.get(cve)
                if not info:
                    continue
                waiting = info["published_at"] is not None and info["published_at"] >= wait_from
                for prod in json.loads(info["products"] or "[]")[:10]:
                    # Windows itself: NVD has one product per release (windows_11_26h1, ...) that the name match
                    # can't tell apart, and Defender knows Microsoft's monthly fixes on the day they come out
                    if _words(prod["product"]).startswith("windows"):
                        continue
                    for s in product_matches(prod["vendor"], prod["product"], installed):
                        if (s["device_id"], cve) in listed or not in_range(s["version"], prod.get("versions") or []):
                            continue
                        d = devices.get(s["device_id"], {})
                        safe = _fixed_in(prod.get("versions") or [])
                        rows.append({"threat_id": tid, "device_id": s["device_id"], "device_name": s["device_name"],
                                     "opco": d.get("opco", "Unassigned"), "match_type": "early" if waiting else "closed",
                                     "detail": f"{cve} via {s['name']} {s['version']}",
                                     "recommended_update": f"Update {s['name'].replace('_', ' ')} (installed {s['version']}) "
                                                           + (f"to {safe} or later" if safe else "to the latest version"),
                                     "found_at": now})
            continue
        for pv in lk["product"]:
            vendor, _, product = pv.partition("|")
            for s in product_matches(vendor, product, installed):
                d = devices.get(s["device_id"], {})
                rows.append({"threat_id": tid, "device_id": s["device_id"], "device_name": s["device_name"],
                             "opco": d.get("opco", "Unassigned"), "match_type": "product",
                             "detail": f"possible: {s['vendor']} {s['name']} {s['version']} (version not checked)",
                             "recommended_update": "", "found_at": now})
            for w in watchlist:
                if product_matches(vendor, product, [{"vendor": w.get("vendor", ""), "name": w.get("product", "")}]):
                    rows.append({"threat_id": tid, "device_id": f"watchlist:{norm_name(w.get('product'))}",
                                 "device_name": f"{w.get('vendor')} {w.get('product')} (watch-list)",
                                 "opco": w.get("opco") or "n/a", "match_type": "watchlist",
                                 "detail": "watch-list match, not verified in Defender", "recommended_update": "",
                                 "found_at": now})
    rows = list({(r["threat_id"], r["device_id"], r["match_type"], r["detail"]): r for r in rows}.values())
    store.upsert("exposure", rows)
    return {"exposure_rows": len(rows), "threats_exposed": len({r["threat_id"] for r in rows if r["match_type"] == "cve"}),
            "not_in_defender_yet": len({(r["device_id"], r["detail"]) for r in rows if r["match_type"] == "early"}),
            "devices": len({r["device_id"] for r in rows if r["match_type"] != "watchlist"})}


def products_from_cves(store: Store) -> None:
    """Add NVD's vendor/product of each linked CVE as product links (used when no Defender CVE match)."""
    rows = store.query("""SELECT l.threat_id, c.products FROM threat_links l JOIN cves c ON c.cve_id = l.value
                          WHERE l.link_type = 'cve' AND c.products IS NOT NULL""")
    for r in rows:
        prods = json.loads(r["products"] or "[]")[:10]
        store.link(r["threat_id"], "product", [f"{p['vendor']}|{p['product']}" for p in prods], origin="nvd")
