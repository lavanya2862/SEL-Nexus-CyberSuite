"""Phase 7: the data behind the portal's Threats and Attack detection pages (data/dashboard/*.json).

The agent makes no web pages of its own: the Unified Cyber Portal reads these files (read-only) and draws them.
  dashboard_data.json   headline numbers, charts, the threat explorer, hunts, devices, metrics
  site_data.json        one threat's full detail, per threat id
  clues.json            every clue (IP, domain, web link, file hash) collected
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path

from uc1 import fix_advice, metrics, resolve
from uc1.config import Settings
from uc1.report import defang
from uc1.store import Store, utcnow

SOURCE_GROUPS = {"CISA KEV": "Vulnerability lists", "NVD": "Vulnerability lists",
                 "NCSC-NL": "Advisories", "CERT-EU": "Advisories", "Microsoft MSRC": "Advisories",
                 "ThreatFox": "IOC feeds", "URLhaus": "IOC feeds", "MalwareBazaar": "IOC feeds",
                 "AlienVault OTX": "IOC feeds", "Proactive hunt": "Hunt hits", "LAB TEST": "Lab tests"}
KILL_CHAIN = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
              "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
              "collection", "command-and-control", "exfiltration", "impact"]
RATING_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _j(v):
    return json.loads(v) if isinstance(v, str) else (v or [])


def factor_chips(factors: list[str]) -> list[str]:
    """Turn the scoring reasons into short labels for the risk cards."""
    chips = []
    for f in factors:
        low = f.lower()
        if "actively-exploited" in low:
            chips.append("CISA KEV")
        elif "ransomware" in low:
            chips.append("Ransomware")
        elif low.startswith("epss"):
            m = re.search(r"EPSS (\d+)%", f)
            chips.append(f"EPSS {m.group(1)}%" if m else "EPSS")
        elif low.startswith("cvss"):
            m = re.search(r"CVSS ([\d.]+)", f)
            chips.append(f"CVSS {m.group(1)}" if m else "CVSS")
        elif "public exploit" in low:
            chips.append("Public exploit")
        elif "of our devices exposed" in low:
            m = re.match(r"(\d+) of our devices", f)
            chips.append(f"{m.group(1)} device(s) exposed" if m else "Exposed")
        elif "not in defender yet" in low:
            chips.append("Not in Defender yet")
        elif "possibly exposed" in low:
            chips.append("Possible match")
        elif "ncsc-nl" in low:
            chips.append("NCSC-NL H/H")
        elif "fresh indicators" in low:
            chips.append("Fresh IOCs")
        elif "hunt found activity" in low:
            chips.append("Hunt hit")
        elif low.startswith("capped"):
            chips.append("Monitor only")
    return chips


def _window(store: Store, since, now) -> dict:
    """Everything the portal's period filter (7 days / 30 days / all time) changes, for threats collected since
    `since` (None = everything). One date decides: when we collected the threat, so every number adds up.
    A threat is never an IOC feed's daily bundle ("ThreatFox: X indicators", kind 'ioc'): those are counted as clues."""
    q = store.query
    first_ever = store.scalar("SELECT MIN(first_seen_at) FROM threats WHERE NOT is_test") or now
    start = max(since, first_ever) if since else first_ever     # no empty days before the agent's first run
    cond, args = ("AND t.first_seen_at >= ?", [since]) if since else ("", [])
    threat = f"NOT t.is_test AND t.kind <> 'ioc' {cond}"
    # per day by source type, on publication date; anything published before the window goes in one "earlier" bar
    first = start.date()
    days = [(first + timedelta(days=i)).isoformat() for i in range((now.date() - first).days + 1)]
    groups = ["Vulnerability lists", "Advisories", "Hunt hits"]
    series, earlier = {g: [0] * len(days) for g in groups}, {g: 0 for g in groups}
    for r in q(f"""SELECT CAST(COALESCE(t.published_at, t.first_seen_at) AS DATE) AS day, t.source, COUNT(*) AS n
                   FROM threats t WHERE {threat} GROUP BY ALL""", args):
        g = SOURCE_GROUPS.get(r["source"], "Advisories")
        if g not in series:
            continue
        if r["day"].isoformat() in days:
            series[g][days.index(r["day"].isoformat())] += r["n"]
        else:
            earlier[g] += r["n"]
    ratings = {r["rating"]: r["n"] for r in q(f"""
        SELECT s.rating, COUNT(*) n FROM scores s JOIN threats t USING (threat_id) WHERE {threat} GROUP BY 1""",
        args)}
    threats_collected = store.scalar(f"SELECT COUNT(*) FROM threats t WHERE {threat}", args) or 0
    assessed = store.scalar(f"""SELECT COUNT(*) FROM threats t JOIN analysis a USING (threat_id)
                                WHERE {threat} AND a.ai_status IN ('done', 'skipped')""", args) or 0
    affecting = q(f"""SELECT s.rating FROM threats t JOIN scores s USING (threat_id)
                      WHERE NOT t.is_test AND t.threat_id IN (SELECT threat_id FROM findings) {cond}""", args)
    urgent = sum(1 for r in affecting if r["rating"] in ("Critical", "High"))
    fixes_needed = store.scalar(f"""SELECT COUNT(DISTINCT e.recommended_update) FROM exposure e JOIN scores s USING (threat_id)
                                    JOIN threats t USING (threat_id)
                                    WHERE s.rating IN ('Critical', 'High') AND e.recommended_update <> '' {cond}""", args) or 0
    funnel = [
        {"stage": "Threats collected", "value": threats_collected, "note": "attack news, advisories, vulnerability lists, hunts"},
        {"stage": "Assessed by the agent", "value": assessed, "note": "AI summary + fact checks"},
        {"stage": "Affect our devices", "value": len(affecting), "note": "matched with Defender"},
        {"stage": "Critical / High on our devices", "value": urgent, "note": "act now"},
        {"stage": "Updates to install", "value": fixes_needed, "note": "clears the urgent list"},
    ]
    tactic_counts = {t: set() for t in KILL_CHAIN}
    for r in q(f"""SELECT l.threat_id, a.tactics FROM threat_links l JOIN attack_techniques a ON a.technique_id = l.value
                   JOIN threats t ON t.threat_id = l.threat_id
                   WHERE l.link_type = 'technique' AND {threat}""", args):
        for tactic in (r["tactics"] or "").split(", "):
            if tactic in tactic_counts:
                tactic_counts[tactic].add(r["threat_id"])
    tactics = [{"tactic": t.replace("-", " ").title().replace("And", "and"), "threats": len(v)}
               for t, v in tactic_counts.items()]
    ioc_types: dict[str, int] = {}
    for r in q(f"""SELECT DISTINCT l.value FROM threat_links l JOIN threats t USING (threat_id)
                   WHERE l.link_type = 'ioc' AND NOT t.is_test {cond}""", args):
        kind = r["value"].split("|", 1)[0]
        ioc_types[kind] = ioc_types.get(kind, 0) + 1
    # per source: threats (no clue bundles), clues (distinct values), threats that affect us
    sources = {r["source"]: {"threats": r["threats"], "clues": 0, "affect": r["affect"]} for r in q(f"""
        SELECT t.source, COUNT(*) AS threats,
               COUNT(*) FILTER (WHERE t.threat_id IN (SELECT threat_id FROM findings)) AS affect
        FROM threats t WHERE {threat} GROUP BY 1""", args)}
    for r in q(f"""SELECT t.source, COUNT(DISTINCT l.value) AS clues FROM threat_links l JOIN threats t USING (threat_id)
                   WHERE l.link_type = 'ioc' AND NOT t.is_test {cond} GROUP BY 1""", args):
        sources.setdefault(r["source"], {"threats": 0, "clues": 0, "affect": 0})["clues"] = r["clues"]
    return {"start": start.isoformat(), "days": days, "series": series, "earlier": earlier, "ratings": ratings,
            "threats_collected": threats_collected, "sources": sources, "funnel": funnel, "tactics": tactics,
            "ioc_types": ioc_types}


def gather(store: Store, settings: Settings | None = None) -> dict:
    now = utcnow()
    q = store.query
    week, month = now - timedelta(days=7), now - timedelta(days=30)

    # ---- the period-dependent numbers (threats per day, ratings, funnel, tactics): the same counting as the
    # portal's period filter, last 30 days; clue bundles are clues, not threats (see _window)
    w30 = _window(store, month, now)
    days, series, ratings, funnel, tactics = w30["days"], w30["series"], w30["ratings"], w30["funnel"], w30["tactics"]
    threats_collected = w30["threats_collected"]

    # ---- posture: what affects our computers right now
    affecting = q("""SELECT s.rating, t.kind, t.threat_id FROM threats t JOIN scores s USING (threat_id)
                     WHERE NOT t.is_test AND t.threat_id IN (SELECT threat_id FROM findings)""")
    worst = min((r["rating"] for r in affecting), key=lambda r: RATING_ORDER.get(r, 9), default=None)
    urgent = [r for r in affecting if r["rating"] in ("Critical", "High")]
    posture = {"rating": worst or "Clear", "urgent": len(urgent),
               "kev": sum(1 for r in affecting if r["kind"] == "kev"), "affecting": len(affecting)}

    # ---- exposure heatmap: device x app (Defender's full picture)
    matrix = q("""SELECT v.device_name, v.name AS app, COUNT(DISTINCT v.cve_id) AS cves,
                         COUNT(DISTINCT CASE WHEN c.kev_added IS NOT NULL THEN v.cve_id END) AS kev
                  FROM device_vulns v LEFT JOIN cves c USING (cve_id) GROUP BY ALL""")
    app_totals: dict[str, int] = {}
    for r in matrix:
        app_totals[r["app"]] = app_totals.get(r["app"], 0) + r["cves"]
    apps = [a for a, _ in sorted(app_totals.items(), key=lambda x: -x[1])][:12]
    matrix = [r for r in matrix if r["app"] in apps]

    # ---- fix these first: one update per app clears all its known flaws
    fixes = q("""SELECT v.name AS app, string_agg(DISTINCT v.version, ', ') AS versions,
                        COUNT(DISTINCT v.cve_id) AS cves, COUNT(DISTINCT v.device_name) AS devices,
                        COUNT(DISTINCT CASE WHEN c.kev_added IS NOT NULL THEN v.cve_id END) AS kev,
                        MAX(v.cvss) AS max_cvss
                 FROM device_vulns v LEFT JOIN cves c USING (cve_id)
                 GROUP BY 1 ORDER BY kev DESC, cves DESC LIMIT 10""")

    # ---- priority quadrant: every flaw on our devices, CVSS x EPSS
    scatter = [[r["cvss"], r["epss"], r["cve_id"], r["apps"], bool(r["kev"])] for r in q("""
        SELECT v.cve_id, MAX(v.cvss) AS cvss, MAX(c.epss) AS epss, string_agg(DISTINCT v.name, ', ') AS apps,
               MAX(CASE WHEN c.kev_added IS NOT NULL THEN 1 ELSE 0 END) AS kev
        FROM device_vulns v JOIN cves c USING (cve_id)
        WHERE c.epss IS NOT NULL AND v.cvss IS NOT NULL GROUP BY 1""")]

    # ---- IOC sweep: what the hunts searched for
    ioc_types: dict[str, int] = {}
    for r in q("""SELECT DISTINCT l.value FROM threat_links l JOIN threats t USING (threat_id)
                  WHERE l.link_type = 'ioc' AND NOT t.is_test AND t.first_seen_at >= ?""", [week]):
        kind = r["value"].split("|", 1)[0]
        ioc_types[kind] = ioc_types.get(kind, 0) + 1
    ioc_hits = store.scalar("SELECT COUNT(*) FROM findings WHERE kind = 'ioc_hit' AND NOT is_test") or 0

    # ---- top risk cards and the threat explorer
    rows = q("""
        SELECT t.threat_id, t.title, t.source, t.kind, t.url, t.is_test, t.published_at, t.first_seen_at,
               s.rating, s.score, s.why, s.factors, a.actions, a.summary,
               (SELECT max(e.recommended_update) FROM exposure e WHERE e.threat_id = t.threat_id AND e.recommended_update <> ''
                       AND e.match_type <> 'closed') AS fix,
               (SELECT string_agg(DISTINCT f.device_name, ', ') FROM findings f WHERE f.threat_id = t.threat_id) AS devices,
               (SELECT COUNT(*) FROM findings f WHERE f.threat_id = t.threat_id AND f.kind <> 'exposure') AS hits
        FROM threats t JOIN scores s USING (threat_id) LEFT JOIN analysis a USING (threat_id)
        ORDER BY s.score DESC, t.published_at DESC NULLS LAST""")   # all of it: the portal filters by period
    # what each threat's CVEs match on our computers, with the dates for the portal's "Affects us" timeline:
    # announced (NVD) -> we knew (first time any news named the CVE); the portal adds Defender's dates
    known = {r["cve"]: r["at"] for r in q("""SELECT l.value AS cve, MIN(t.first_seen_at) AS at FROM threat_links l
                                             JOIN threats t USING (threat_id)
                                             WHERE l.link_type = 'cve' AND NOT t.is_test GROUP BY 1""")}
    on_us: dict[str, list] = {}
    for e in q("""SELECT e.threat_id, e.device_name, e.match_type, e.detail, c.published_at FROM exposure e
                  LEFT JOIN cves c ON c.cve_id = split_part(e.detail, ' ', 1)
                  WHERE e.match_type IN ('cve', 'early', 'closed') ORDER BY e.device_name, e.detail"""):
        cve, _, rest = e["detail"].partition(" via ")
        app, _, version = rest.rpartition(" ")
        mine = on_us.setdefault(e["threat_id"], [])
        if len(mine) < 30:
            mine.append({"cve": cve, "device": e["device_name"], "app": app, "version": version, "match": e["match_type"],
                         "announced": str(e["published_at"] or "")[:16], "known": str(known.get(cve) or "")[:16]})

    def match_of(r: dict, mine: list) -> str | None:
        """How the threat reaches us: a sign of attack, confirmed by Defender, not in Defender yet, or closed."""
        if r["hits"] or r["kind"] in ("hunt", "test"):
            return "sign"
        kinds = {x["match"] for x in mine}
        return next((name for kind, name in (("cve", "defender"), ("early", "early"), ("closed", "closed")) if kind in kinds), None)

    explorer = []
    for r in rows:
        actions = ([r["fix"]] if r["fix"] else []) + _j(r["actions"])
        mine = on_us.get(r["threat_id"], [])
        explorer.append({"id": r["threat_id"], "title": r["title"], "source": r["source"], "kind": r["kind"],
                         "url": r["url"], "test": r["is_test"], "published": str(r["published_at"] or "")[:10], "first_seen": str(r["first_seen_at"] or "")[:16],
                         "rating": r["rating"], "score": r["score"], "why": r["why"],
                         "chips": factor_chips(_j(r["factors"])), "action": actions[0] if actions else "",
                         "summary": (r["summary"] or "")[:420], "devices": r["devices"] or "", "hits": r["hits"],
                         "match": match_of(r, mine), **({"on_us": mine} if mine else {})})
    urgent_cards = [e for e in explorer if e["rating"] in ("Critical", "High") and (e["devices"] or e["hits"])]
    top = ([e for e in urgent_cards if not e["test"]][:9] + [e for e in urgent_cards if e["test"]][:3])   # real first

    hits = q("""SELECT f.*, t.title FROM findings f JOIN threats t USING (threat_id)
                WHERE f.kind <> 'exposure' ORDER BY f.first_hit DESC NULLS LAST LIMIT 200""")
    resolutions = resolve.for_findings(store)
    for h in hits:
        h["resolution"] = resolutions.get(h["finding_id"])
        h["users"] = list(dict.fromkeys(u["account"] for u in _j(h["users"])))[:3]
        h["alerts"] = [a["title"] for a in _j(h["alerts"])][:2]
        h["timeline"] = _j(h["timeline"])[:6]
    devices = q("""
        SELECT d.device_name, d.opco, d.os_platform, d.last_seen,
               COUNT(DISTINCT CASE WHEN f.kind = 'exposure' THEN f.threat_id END) AS exposed,
               COUNT(DISTINCT CASE WHEN f.kind <> 'exposure' AND NOT f.is_test THEN f.finding_id END) AS hits,
               COUNT(DISTINCT CASE WHEN f.kind <> 'exposure' AND f.is_test THEN f.finding_id END) AS test_hits,
               (SELECT COUNT(*) FROM device_vulns v WHERE v.device_id = d.device_id) AS vulns
        FROM devices d LEFT JOIN findings f ON f.device_id = d.device_id GROUP BY ALL ORDER BY exposed DESC""")
    alerts = q("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 12")
    feeds = q("SELECT * FROM feed_state ORDER BY feed")
    last_run = (q("SELECT * FROM runs ORDER BY started_at DESC LIMIT 1") or [None])[0]
    hunt_run = store.scalar("SELECT run_id FROM hunts ORDER BY started_at DESC LIMIT 1")
    hunts = q("""SELECT name, origin, technique, status, row_count, error FROM hunts WHERE run_id = ?
                 ORDER BY origin DESC, name""", [hunt_run]) if hunt_run else []
    model = store.scalar("SELECT model FROM ai_usage ORDER BY day DESC LIMIT 1")
    return {"generated": now.isoformat(), "days": days, "series": series, "ratings": ratings, "posture": posture,
            "funnel": funnel, "matrix": matrix, "apps": apps, "fixes": fixes, "scatter": scatter, "tactics": tactics,
            "ioc_types": ioc_types, "ioc_hits": ioc_hits, "threats_collected": threats_collected, "top": top, "explorer": explorer, "hits": hits,
            "devices": devices, "alerts": alerts, "feeds": feeds, "last_run": last_run, "hunts": hunts,
            "model": model, "metrics": metrics.compute(store, settings),
            "periods": {"7": _window(store, week, now), "30": w30, "all": _window(store, None, now)}}


def build(store: Store, settings: Settings) -> Path:
    """Write the portal's data for the Threat Intel Agent: dashboard_data.json, site_data.json and clues.json."""
    out_dir = settings.dashboard_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "dashboard_data.json"
    path.write_text(json.dumps(gather(store, settings), default=str, ensure_ascii=False), encoding="utf-8")
    export_site_data(store, settings)
    export_clues(store, settings)
    return path


def export_site_data(store: Store, settings: Settings) -> Path:
    """Everything the portal's threat detail page needs, as data/dashboard/site_data.json."""
    q = store.query
    month = utcnow() - timedelta(days=30)
    threats = q("""
        SELECT t.threat_id, t.title, t.source, t.kind, t.url, t.published_at, t.first_seen_at, t.is_test, t.text,
               s.score, s.rating, s.factors, s.why, a.summary, a.threat_type, a.techniques AS ai_techniques,
               a.actions, a.confidence, a.ai_status, a.ai_model, a.dropped, a.analysed_at
        FROM threats t LEFT JOIN scores s USING (threat_id) LEFT JOIN analysis a USING (threat_id)
        WHERE t.first_seen_at >= ? OR t.threat_id IN (SELECT threat_id FROM findings)""", [month])
    ids = {t["threat_id"] for t in threats}
    links: dict[str, dict[str, list]] = {}
    for l in q("SELECT threat_id, link_type, value, origin FROM threat_links"):
        if l["threat_id"] in ids:
            links.setdefault(l["threat_id"], {}).setdefault(l["link_type"], []).append((l["value"], l["origin"]))
    cve_ids = sorted({v for lk in links.values() for v, _ in lk.get("cve", [])})
    cves = {}
    for i in range(0, len(cve_ids), 500):
        chunk = cve_ids[i:i + 500]
        for c in q(f"""SELECT cve_id, cvss, severity, epss, epss_percentile, kev_added, kev_due, kev_ransomware, description
                       FROM cves WHERE cve_id IN ({",".join("?" for _ in chunk)})""", chunk):
            cves[c["cve_id"]] = c
    techniques = {t["technique_id"]: t for t in q("SELECT * FROM attack_techniques")}
    exposure: dict[str, list] = {}
    for e in q("SELECT * FROM exposure ORDER BY device_name"):
        exposure.setdefault(e["threat_id"], []).append({k: e[k] for k in ("device_name", "opco", "match_type", "detail",
                                                                          "recommended_update")})
    findings: dict[str, list] = {}
    resolutions = resolve.for_findings(store)
    threat_fixes = fix_advice.for_threats(store)
    for f in q("SELECT * FROM findings WHERE kind <> 'exposure' ORDER BY first_hit DESC NULLS LAST"):
        findings.setdefault(f["threat_id"], []).append({
            "kind": f["kind"], "device": f["device_name"], "opco": f["opco"], "detail": f["detail"], "is_test": f["is_test"],
            "first_hit": f["first_hit"], "hunt_id": f["hunt_id"], "users": _j(f["users"]), "alerts": _j(f["alerts"]),
            "timeline": _j(f["timeline"]), "resolution": resolutions.get(f["finding_id"])})
    hunt_ids = {f["hunt_id"] for fl in findings.values() for f in fl if f["hunt_id"]}
    hunts: dict[str, list] = {}
    for h in q("SELECT * FROM hunts ORDER BY started_at DESC"):
        keys = [h["threat_id"]] if h["threat_id"] in ids else []
        if h["hunt_id"] in hunt_ids:
            keys += [f_tid for f_tid, fl in findings.items() if any(f["hunt_id"] == h["hunt_id"] for f in fl)]
        for key in dict.fromkeys(keys):
            if len(hunts.setdefault(key, [])) < 4:
                hunts[key].append({k: h[k] for k in ("name", "origin", "technique", "status", "row_count", "error",
                                                     "started_at", "query")})

    out = {}
    for t in threats:
        tid = t["threat_id"]
        lk = links.get(tid, {})
        fixes = [e["recommended_update"] for e in exposure.get(tid, []) if e["recommended_update"]]
        ai_tech = {x["id"]: x.get("reason", "") for x in _j(t["ai_techniques"])}
        out[tid] = {
            "id": tid, "title": t["title"], "source": t["source"], "kind": t["kind"], "url": t["url"],
            "published": t["published_at"], "first_seen": t["first_seen_at"], "is_test": t["is_test"],
            "text": (t["text"] or "")[:8000], "score": t["score"], "rating": t["rating"], "factors": _j(t["factors"]),
            "why": t["why"], "summary": t["summary"], "threat_type": t["threat_type"], "confidence": t["confidence"],
            "ai_status": t["ai_status"], "ai_model": t["ai_model"], "dropped": _j(t["dropped"]) or {},
            "analysed_at": t["analysed_at"],
            "actions": list(dict.fromkeys(fixes + _j(t["actions"]))),
            "cves": [{"id": v, "origin": o, **{k: cves.get(v, {}).get(k) for k in (
                "cvss", "severity", "epss", "epss_percentile", "kev_added", "kev_due", "kev_ransomware")},
                "description": (cves.get(v, {}).get("description") or "")[:400]} for v, o in lk.get("cve", [])][:80],
            "techniques": [{"id": v, "origin": o, "name": techniques.get(v, {}).get("name", ""),
                            "tactics": techniques.get(v, {}).get("tactics", ""), "url": techniques.get(v, {}).get("url", ""),
                            "reason": ai_tech.get(v, "")} for v, o in lk.get("technique", [])],
            "products": [{"value": v.replace("|", " · "), "origin": o} for v, o in lk.get("product", [])][:30],
            "ioc_count": len(lk.get("ioc", [])),
            "iocs": [{"type": v.split("|", 1)[0], "value": defang(v.split("|", 1)[1]), "origin": o}
                     for v, o in lk.get("ioc", [])[:60]],
            "exposure": exposure.get(tid, []), "findings": findings.get(tid, []), "hunts": hunts.get(tid, []),
            "fix": threat_fixes.get(tid) if exposure.get(tid) else None,
        }
    path = settings.dashboard_dir / "site_data.json"
    path.write_text(json.dumps(out, default=str, ensure_ascii=False), encoding="utf-8")
    return path


def export_clues(store: Store, settings: Settings) -> Path:
    """Every clue (IP, domain, web link, file hash) we ever collected, one row each, as data/dashboard/clues.json:
    found on our computers first, then newest first. "collected" is when we last got it (the portal's period filter uses
    it). Values are made safe (hxxp, [.]) so they can't be clicked."""
    q = store.query
    seen: dict[str, set[str]] = {}
    for f in q("SELECT device_name, detail FROM findings WHERE kind = 'ioc_hit'"):
        _, kind, value = ((f["detail"] or "") + "  ").split(" ", 2)      # "matched <type> <value>"
        seen.setdefault(f"{kind}|{value.strip()}", set()).add(f["device_name"])
    out: dict[str, dict] = {}
    for r in q("""SELECT l.value, l.threat_id, t.title, t.source, t.is_test, t.first_seen_at, i.malware, i.first_seen
                  FROM threat_links l JOIN threats t USING (threat_id)
                  LEFT JOIN iocs i ON i.ioc_type || '|' || i.value = l.value
                  WHERE l.link_type = 'ioc' ORDER BY t.first_seen_at DESC"""):   # latest sighting first
        key = r["value"]
        if key in out:
            continue
        kind, _, value = key.partition("|")
        out[key] = {"type": kind, "value": defang(value), "malware": r["malware"] or "", "source": r["source"],
                    "first_seen": str(r["first_seen"] or r["first_seen_at"])[:16],
                    "collected": str(r["first_seen_at"])[:16], "test": r["is_test"],
                    "threat_id": r["threat_id"], "threat": r["title"], "seen_on": sorted(seen.get(key, ()))}
    clues = sorted(out.values(), key=lambda c: c["first_seen"], reverse=True)
    clues.sort(key=lambda c: not c["seen_on"])      # stable: found on our computers first, each part newest first
    path = settings.dashboard_dir / "clues.json"
    path.write_text(json.dumps(clues, ensure_ascii=False), encoding="utf-8")
    return path
