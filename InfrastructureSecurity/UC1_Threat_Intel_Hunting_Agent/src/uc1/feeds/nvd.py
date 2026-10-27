"""NVD CVE API 2.0: official details (description, CVSS, affected products) of every CVE.

Downloads CVEs modified since the last run (first run: NVD_BACKFILL_DAYS). NVD CVEs are enrichment, not
threats by themselves (hundreds change every day); `derive.py` turns a CVE into a threat only when it is
serious (CVSS >= 7) and its product is installed on one of our Defender devices.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from uc1.feeds.common import FeedContext, http, norm_name
from uc1.store import dumps, to_utc, utcnow

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 200    # NVD cuts off or stalls on bigger pages; 200 come back in about 15 s
MAX_WINDOW = timedelta(days=120)   # NVD's limit for one lastMod range


def best_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Prefer CVSS v3.1, then v4.0, v3.0, v2; within a version prefer the NVD ('Primary') score."""
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            item = next((m for m in items if m.get("type") == "Primary"), items[0])
            data = item.get("cvssData", {})
            severity = data.get("baseSeverity") or item.get("baseSeverity")
            return data.get("baseScore"), severity, data.get("vectorString")
    return None, None, None


def products_of(cve: dict) -> list[dict]:
    """Affected vendor/product pairs from CPE configurations and the CNA 'affected' block."""
    found: dict[tuple[str, str], dict] = {}
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match.get("criteria", "").split(":")
                if len(parts) > 5 and parts[2] in ("a", "o"):
                    key = (parts[3], parts[4])
                    entry = found.setdefault(key, {"vendor": parts[3], "product": parts[4], "versions": []})
                    rng = {k: match[k] for k in ("versionStartIncluding", "versionStartExcluding",
                                                 "versionEndIncluding", "versionEndExcluding") if k in match}
                    if parts[5] not in ("*", "-"):
                        rng["version"] = parts[5]
                    if rng and len(entry["versions"]) < 10:
                        entry["versions"].append(rng)
    for affected in cve.get("affected", []):
        for data in affected.get("affectedData", []):
            vendor, product = norm_name(data.get("vendor")), norm_name(data.get("product"))
            if vendor and product and (vendor, product) not in found:
                found[(vendor, product)] = {"vendor": vendor, "product": product,
                                            "versions": [v for v in data.get("versions", [])][:10]}
    return list(found.values())[:40]


def parse(payload: dict) -> list[dict]:
    rows = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        score, severity, vector = best_cvss(cve.get("metrics", {}))
        description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        rows.append({"cve_id": cve["id"].upper(), "description": description,
                     "published_at": to_utc(cve.get("published")), "last_modified_at": to_utc(cve.get("lastModified")),
                     "cvss": score, "severity": (severity or "").upper() or None, "vector": vector,
                     "products": products_of(cve), "status": cve.get("vulnStatus")})
    return rows


def store_rows(ctx: FeedContext, rows: list[dict]) -> None:
    now = utcnow()
    for r in rows:
        if r.get("status") == "Rejected":
            continue
        ctx.store.execute("""
            INSERT INTO cves (cve_id, description, published_at, last_modified_at, cvss, severity, vector, products, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (cve_id) DO UPDATE SET description = EXCLUDED.description,
                published_at = EXCLUDED.published_at, last_modified_at = EXCLUDED.last_modified_at,
                cvss = EXCLUDED.cvss, severity = EXCLUDED.severity, vector = EXCLUDED.vector,
                products = CASE WHEN json_array_length(EXCLUDED.products) > 0 THEN EXCLUDED.products
                                ELSE cves.products END,
                updated_at = EXCLUDED.updated_at""",
            [r["cve_id"], r["description"], r["published_at"], r["last_modified_at"], r["cvss"],
             r["severity"], r["vector"], dumps(r["products"]), now])


def fetch_window(ctx: FeedContext, start: datetime, end: datetime, *, tag: str) -> int:
    headers = {"apiKey": ctx.settings.nvd_api_key} if ctx.settings.nvd_api_key else {}
    pause = 0.7 if ctx.settings.nvd_api_key else 6.5          # 50 / 30 s with key, 5 / 30 s without
    total, index, page_no = 0, 0, 0
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    while True:
        params = {"lastModStartDate": start.strftime(fmt), "lastModEndDate": end.strftime(fmt),
                  "resultsPerPage": PAGE, "startIndex": index}
        payload = http(ctx, "GET", URL, params=params, headers=headers, timeout=120).json()
        ctx.save_raw(f"nvd_{tag}_{page_no:03d}", payload)
        rows = parse(payload)
        store_rows(ctx, rows)
        total += len(rows)
        index += payload.get("resultsPerPage", len(rows)) or PAGE
        page_no += 1
        if index >= payload.get("totalResults", 0) or not rows:
            return total
        ctx.sleep(pause)


def fetch_cves(ctx: FeedContext, cve_ids: list[str]) -> int:
    """Fetch specific CVEs (e.g. KEV entries Defender shows on our devices) that aren't in `cves` yet."""
    headers = {"apiKey": ctx.settings.nvd_api_key} if ctx.settings.nvd_api_key else {}
    pause = 0.7 if ctx.settings.nvd_api_key else 6.5
    count = 0
    for cve_id in cve_ids:
        payload = http(ctx, "GET", URL, params={"cveId": cve_id}, headers=headers).json()
        store_rows(ctx, parse(payload))
        count += 1
        ctx.sleep(pause)
    return count


def collect(ctx: FeedContext) -> int:
    state = ctx.store.feed_state("nvd")
    end = utcnow()
    start = to_utc(state.get("cursor")) or end - timedelta(days=ctx.settings.nvd_backfill_days)
    start = max(start - timedelta(minutes=5), end - MAX_WINDOW)      # small overlap, NVD window limit
    total = fetch_window(ctx, start, end, tag=end.strftime("%H%M"))
    ctx.store.save_feed_state("nvd", "ok", total, cursor=end.isoformat())
    return total
