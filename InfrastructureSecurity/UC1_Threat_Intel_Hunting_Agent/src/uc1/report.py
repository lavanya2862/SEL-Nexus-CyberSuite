"""Threat Intelligence Report for one Threat Intel run (Word + PDF): what this run gathered, what affects us, and the
fix steps written in it. Signs of attack have their own report (attack_report.py, the Attack Detection Agent).

Numbers and tables come from the database and the run's own step results; nothing here asks the AI again.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from datetime import datetime

from uc1 import docstyle as ds
from uc1.config import Settings
from uc1.store import Store, utcnow

log = logging.getLogger("uc1.report")

RATINGS = ("Critical", "High", "Medium", "Low")
RATING_COLOURS = {"Critical": ds.BAD, "High": ds.SERIOUS, "Medium": ds.WARN, "Low": "16A34A"}
CARDS_MAX = 40


def defang(value: str) -> str:
    return (value or "").replace("http", "hxxp").replace(".", "[.]")


def _j(value):
    if value is None:
        return []
    return json.loads(value) if isinstance(value, str) else value


def run_window(store: Store, run_id: str | None, command: str) -> tuple[str | None, datetime, datetime, dict]:
    """(run_id, started, finished, steps) of this run, or of the latest run of that kind when built by hand."""
    rows = store.query("SELECT * FROM runs WHERE run_id = ?", [run_id]) if run_id else \
        store.query("SELECT * FROM runs WHERE command = ? AND finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 1", [command])
    if not rows:
        now = utcnow()
        return run_id, now, now, {}
    r = rows[0]
    return r["run_id"], r["started_at"], r["finished_at"] or utcnow(), _j(r["steps"]) or {}


def cover_lines(started: datetime, finished: datetime, extra: str) -> list[str]:
    mins = max(0, int((finished - started).total_seconds()))
    return [f"Run of {started:%d %b %Y, %H:%M} UTC · took {mins // 60} min {mins % 60} s",
            extra,
            f"Created {utcnow():%d %b %Y, %H:%M} UTC · this report shows this run only"]


def _num(text) -> int:
    return sum(int(n) for n in re.findall(r"\d+", str(text)))


def gather(store: Store, started: datetime, finished: datetime, steps: dict) -> dict:
    window = [started, finished]
    res = lambda name: (steps.get(name) or {}).get("result") or {}
    new = store.query("""
        SELECT t.*, s.score, s.rating, s.why, a.summary, a.techniques,
               (SELECT max(c.epss) FROM threat_links l JOIN cves c ON c.cve_id = l.value
                WHERE l.threat_id = t.threat_id AND l.link_type = 'cve') AS epss,
               (SELECT count(DISTINCT e.device_id) FROM exposure e WHERE e.threat_id = t.threat_id AND e.match_type = 'cve') AS exposed
        FROM threats t JOIN scores s USING (threat_id) LEFT JOIN analysis a USING (threat_id)
        WHERE t.first_seen_at BETWEEN ? AND ? ORDER BY s.score DESC, t.published_at DESC NULLS LAST""", window)
    affecting = store.query("""
        SELECT t.threat_id, t.title, t.source, t.published_at, s.score, s.rating, s.why,
               string_agg(DISTINCT e.device_name, ', ') AS computers, count(DISTINCT e.device_id) AS exposed,
               string_agg(DISTINCT e.recommended_update, ' | ') FILTER (WHERE e.recommended_update <> '') AS fix
        FROM exposure e JOIN threats t USING (threat_id) JOIN scores s USING (threat_id)
        WHERE e.match_type = 'cve' GROUP BY ALL ORDER BY s.score DESC""")
    fixes = store.query("""
        SELECT f.*, t.title, t.source, t.published_at, s.rating, s.score, s.why, a.summary,
               (SELECT string_agg(DISTINCT e.device_name, ', ') FROM exposure e WHERE e.threat_id = f.threat_id) AS computers
        FROM threat_fixes f JOIN threats t USING (threat_id) JOIN scores s USING (threat_id)
        LEFT JOIN analysis a USING (threat_id)
        WHERE f.created_at BETWEEN ? AND ? ORDER BY s.score DESC""", window)
    alerts = store.query("SELECT * FROM alerts WHERE created_at BETWEEN ? AND ? ORDER BY created_at", window)
    iocs = store.query("""SELECT * FROM iocs WHERE first_seen BETWEEN ? AND ? ORDER BY confidence DESC NULLS LAST""", window)
    tech = Counter(x["id"] for t in new for x in _j(t["techniques"]) if isinstance(x, dict) and x.get("id"))
    names = {r["technique_id"]: r for r in store.query("SELECT technique_id, name, tactics FROM attack_techniques")}
    feeds = res("collect") if isinstance(res("collect"), dict) else {}
    return {"new": new, "affecting": affecting, "fixes": fixes, "alerts": alerts, "iocs": iocs, "feeds": feeds,
            "techniques": [(k, names.get(k, {}).get("name", ""), names.get(k, {}).get("tactics", ""), n)
                           for k, n in tech.most_common(25)],
            "devices": store.query("SELECT * FROM devices ORDER BY device_name"),
            "exposure_step": res("exposure"), "fix_step": res("fix_advice"), "alerts_step": res("alerts"),
            "analyse_step": res("analyse")}


def build(store: Store, settings: Settings, run_id: str | None, ai=None, steps: dict | None = None) -> dict:
    run_id, started, finished, stored_steps = run_window(store, run_id, "run")
    d = gather(store, started, finished, steps or stored_steps)
    real_new = [t for t in d["new"] if not t["is_test"]]
    ok_feeds = sum(1 for v in d["feeds"].values() if str(v).startswith("ok"))
    checked = sum(_num(v) for v in d["feeds"].values() if str(v).startswith("ok"))
    ex, fx = d["exposure_step"], d["fix_step"]
    new_fixes = (fx.get("new_ai") or 0) + (fx.get("new_standard") or 0) if fx else len(d["fixes"])

    r = ds.Report("Threat Intelligence Report", "Threat Intel Agent",
                  cover_lines(started, finished, f"{ok_feeds} public sources checked · {len(d['devices'])} computers in "
                                                 "Microsoft Defender compared with the threats"))
    r.h1("1. Summary")
    r.tiles([(f"{checked:,}", "News items checked", f"from {ok_feeds} public sources", ds.BLUE),
             (f"{len(real_new):,}", "New threats", "first seen in this run", ds.SERIOUS),
             (f"{ex.get('new_threats_exposed', 0):,}", "New threats affecting us", "since the last run", ds.BAD),
             (f"{new_fixes:,}", "Fix steps written", "for threats that affect us", ds.GOOD),
             (f"{len(d['affecting']):,}", "Threats affecting us now", "on our computers' software", ds.SERIOUS),
             (f"{len(d['alerts']):,}", "Alerts sent", "to the security team" if d["alerts"] else "no one needed to be told",
              ds.BAD if d["alerts"] else ds.INK_3)])
    by_rating = Counter(t["rating"] for t in real_new)
    top = [t for t in real_new if t["rating"] in ("Critical", "High")]
    r.para(f"This run checked {checked:,} news items from {ok_feeds} public sources and kept {len(real_new):,} new threats "
           f"({by_rating.get('Critical', 0)} Critical, {by_rating.get('High', 0)} High, {by_rating.get('Medium', 0)} Medium). "
           f"{ex.get('new_threats_exposed', 0):,} newly affect software on our computers; in total {len(d['affecting']):,} "
           f"threats affect us. The agent wrote fix steps for {new_fixes:,} of them in this run.")
    aff_rating = Counter(t["rating"] for t in d["affecting"])
    r.images_side_by_side([
        ds.donut(list(RATINGS), [by_rating.get(x, 0) for x in RATINGS], [RATING_COLOURS[x] for x in RATINGS],
                 f"{len(real_new):,}", "new threats"),
        ds.donut(list(RATINGS), [aff_rating.get(x, 0) for x in RATINGS], [RATING_COLOURS[x] for x in RATINGS],
                 f"{len(d['affecting']):,}", "affecting us")])
    sources = Counter(t["source"] for t in real_new).most_common(10)
    if sources:
        r.image(ds.hbar([s for s, _ in sources], [n for _, n in sources], ds.BLUE, "New threats by source"))

    r.h1("2. Sources checked in this run")
    r.table(["Source", "Result"], [[k, str(v)] for k, v in d["feeds"].items()], [5, 12],
            colour_cols={})

    r.h1("3. New threats in this run")
    shown = [t for t in real_new if t["rating"] != "Low"] or real_new[:30]
    r.table(["Rating", "Threat", "Source", "Published", "Chance of attack (EPSS)", "Our computers"],
            [[t["rating"], t["title"][:140], t["source"], f"{t['published_at']:%d %b %Y}" if t["published_at"] else "",
              f"{t['epss']:.0%}" if t["epss"] is not None else "", t["exposed"] or "not affected"] for t in shown[:60]],
            [1.8, 8, 2.6, 2.2, 2.2, 2.2], colour_cols={0: RATING_COLOURS})
    if len(real_new) > len(shown[:60]):
        r.note(f"Showing {len(shown[:60])} of {len(real_new):,} new threats (the rest are rated Low).")

    r.h1("4. Threats that affect our computers")
    r.para("Threats whose vulnerable software Microsoft Defender finds on our computers, most serious first.")
    r.table(["Rating", "Threat", "Computers", "Fix from Defender"],
            [[t["rating"], t["title"][:140], t["computers"], (t["fix"] or "")[:120]] for t in d["affecting"]
             if t["rating"] != "Low"][:50], [1.8, 8, 3.5, 4.5], colour_cols={0: RATING_COLOURS})

    r.h1("5. Fix steps written in this run")
    fixes = d["fixes"]
    if fixes:
        r.para(f"{len(fixes):,} threats got fix steps in this run. The {min(len(fixes), CARDS_MAX)} most serious are shown "
               "in full; the rest are listed after them.")
        for f in fixes[:CARDS_MAX]:
            meta = (f"{f['source']} · published {f['published_at']:%d %b %Y}" if f["published_at"] else f["source"]) + \
                   (f" · computers: {f['computers']}" if f["computers"] else "")
            r.card(f["title"], meta,
                   [("What it is", f["summary"]), ("Why this rating", f["why"]), ("How to fix it", _j(f["steps"])),
                    ("Done when", f["done_when"]),
                    ("Source", f"Steps written by AI ({f['model'] or 'AI'}), checked against the data."
                     if f["source"] == "ai" else "Standard steps from Defender's recommended updates.")],
                   RATING_COLOURS.get(f["rating"], ds.BLUE), f["rating"])
        if len(fixes) > CARDS_MAX:
            r.h2("Other threats with new fix steps")
            r.table(["Rating", "Threat", "Computers", "First step"],
                    [[f["rating"], f["title"][:120], f["computers"], (_j(f["steps"]) or [""])[0][:160]] for f in fixes[CARDS_MAX:]],
                    [1.8, 7, 3, 7], colour_cols={0: RATING_COLOURS})
    else:
        r.note("No new fix steps were needed in this run.")

    r.h1("6. Attacker techniques in the new threats (MITRE ATT&CK)")
    r.table(["Technique", "Name", "Tactic", "New threats"], [list(x) for x in d["techniques"]], [2.4, 7, 5, 2.2])

    r.h1("7. Warning signs collected (defanged)")
    r.para(f"{len(d['iocs']):,} warning signs (addresses, domains, file hashes) were collected in this run. The Attack "
           "Detection Agent searches our computers for them. They are written in a safe form (hxxp, [.]).")
    kinds = Counter(i["ioc_type"] for i in d["iocs"]).most_common()
    if kinds:
        r.image(ds.hbar([k for k, _ in kinds], [n for _, n in kinds], ds.BLUE, "Warning signs by type"), 12)
    r.table(["Type", "Warning sign", "Malware", "Source", "Confidence"],
            [[i["ioc_type"], defang(i["value"])[:90], i["malware"], i["source"], i["confidence"]] for i in d["iocs"][:40]],
            [2, 8, 3.5, 2.5, 2])

    r.h1("8. Alerts sent in this run")
    r.table(["Rating", "Alert", "Sent"], [[a["rating"], a["title"], f"{a['created_at']:%d %b %H:%M}"] for a in d["alerts"]],
            [2, 12, 3], colour_cols={0: RATING_COLOURS})

    r.h1("Appendix: how this report was produced")
    r.bullets([
        "Threats come from free public sources: CISA KEV, NVD, FIRST EPSS, MITRE ATT&CK, NCSC-NL, CERT-EU, Microsoft MSRC, "
        "abuse.ch and (optionally) AlienVault OTX.",
        "Our computers' software comes from Microsoft Defender for Endpoint.",
        "Ratings come from fixed rules: on the CISA KEV list, ransomware use, EPSS (chance of attack in 30 days), CVSS, "
        "a public exploit, and whether our computers are exposed.",
        "The AI reads each threat and writes fix steps; its answers are checked against the data before they are used.",
    ])
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%d_%H%M")
    out = r.save(settings.reports_dir / f"Threat_Intel_Report_{stamp}.docx")
    store.upsert("reports", [{"report_id": f"report:{stamp}", "run_id": run_id, "docx_path": out["docx"],
                              "pdf_path": out["pdf"], "threat_count": len(d["new"]), "created_at": utcnow()}])
    return out
