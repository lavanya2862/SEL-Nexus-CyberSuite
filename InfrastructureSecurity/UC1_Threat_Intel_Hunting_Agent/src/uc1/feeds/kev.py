"""CISA Known Exploited Vulnerabilities (KEV): flaws with proof that attackers have used them in real attacks.

Every KEV entry is stored in `cves` (so scoring and exposure know the full list). Entries added in the last
KEV_BACKFILL_DAYS become threats straight away; older ones do not (Defender's list already shows them on our devices).
"""

from __future__ import annotations

from datetime import date, timedelta

from uc1.feeds.common import FeedContext, content_hash, http
from uc1.store import dumps, utcnow

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse(payload: dict) -> list[dict]:
    rows = []
    for v in payload.get("vulnerabilities", []):
        rows.append({
            "cve_id": v["cveID"].upper(),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "added": date.fromisoformat(v["dateAdded"]),
            "due": date.fromisoformat(v["dueDate"]) if v.get("dueDate") else None,
            "ransomware": v.get("knownRansomwareCampaignUse") or "Unknown",
            "action": v.get("requiredAction", ""),
            "description": v.get("shortDescription", ""),
            "notes": v.get("notes", ""),
            "cwes": v.get("cwes", []),
        })
    return rows


def threat_from_entry(e: dict) -> dict:
    text = (f"{e['name']}.\n{e['description']}\nAffected: {e['vendor']} {e['product']}.\n"
            f"Known ransomware use: {e['ransomware']}.\nRequired action: {e['action']}\n"
            f"CISA remediation due date: {e['due']}.\nNotes: {e['notes']}")
    return {"threat_id": f"kev:{e['cve_id']}", "source": "CISA KEV", "kind": "kev",
            "title": f"CISA alert: {e['cve_id']} in {e['vendor']} {e['product']}",
            "text": text, "url": f"https://nvd.nist.gov/vuln/detail/{e['cve_id']}",
            "published_at": e["added"], "content_hash": content_hash(text)}


def store_entries(ctx: FeedContext, entries: list[dict]) -> int:
    now = utcnow()
    for e in entries:
        ctx.store.execute("""
            INSERT INTO cves (cve_id, kev_added, kev_due, kev_ransomware, kev_action, kev_name, products, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (cve_id) DO UPDATE SET kev_added = EXCLUDED.kev_added, kev_due = EXCLUDED.kev_due,
                kev_ransomware = EXCLUDED.kev_ransomware, kev_action = EXCLUDED.kev_action,
                kev_name = EXCLUDED.kev_name, products = COALESCE(cves.products, EXCLUDED.products),
                updated_at = EXCLUDED.updated_at""",
            [e["cve_id"], e["added"], e["due"], e["ransomware"], e["action"], e["name"],
             dumps([{"vendor": e["vendor"], "product": e["product"]}]), now])
    cutoff = date.today() - timedelta(days=ctx.settings.kev_backfill_days)
    recent = [e for e in entries if e["added"] >= cutoff]
    new = ctx.store.add_threats(threat_from_entry(e) for e in recent)
    for e in recent:
        ctx.store.link(f"kev:{e['cve_id']}", "cve", [e["cve_id"]])
        ctx.store.link(f"kev:{e['cve_id']}", "product", [f"{e['vendor']}|{e['product']}"])
    return new


def collect(ctx: FeedContext) -> int:
    payload = http(ctx, "GET", URL).json()
    ctx.save_raw("kev", payload)
    entries = parse(payload)
    new = store_entries(ctx, entries)
    ctx.store.save_feed_state("kev", "ok", new, cursor=payload.get("catalogVersion"))
    return new

