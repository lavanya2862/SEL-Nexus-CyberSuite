"""Vulnerability Report for one scan (Word + PDF), built from the reporting tables, this scan's raw files and the AI fix guide.

data/reporting/Vulnerability_Report_<snapshot>.docx / .pdf. `gather()` is shared with the Excel workbook (excel.py),
so the three files always show the same numbers. Nothing here asks the AI: the guides were written in the Advice step.
"""

from __future__ import annotations

import gzip
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import duckdb

from uc3 import docstyle as ds
from uc3.config import Settings

SEVS = ("Critical", "High", "Medium", "Low")
SEV_RANK = "CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END"
AGES = ("0-30", "31-60", "61-90", "90+")
URGENCY_COLOURS = {1: ds.BAD, 2: ds.SERIOUS, 3: ds.WARN}
EXPLOIT_WORDS = {"NoExploit": "None known", "ExploitIsPublic": "Public exploit", "ExploitIsVerified": "Verified exploit",
                 "ExploitIsInKit": "In attack kits"}
TABLES = ("fact_vulnerability", "fact_daily_summary", "dim_device", "dim_cve", "dq_status", "run_history")


def _json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _changes(path: Path, opco_of: dict[str, str]) -> dict[str, list[dict]]:
    """This scan's change list from Defender (the same rows the New / Fixed counts come from), by status."""
    out: dict[str, list[dict]] = {"New": [], "Fixed": [], "Updated": []}
    if not path.is_file():
        return out
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            out.setdefault(r.get("status") or "Updated", []).append({
                "device": r.get("deviceName"), "opco": opco_of.get(r.get("deviceName") or "", ""),
                "app": " ".join(x for x in (r.get("softwareVendor"), r.get("softwareName")) if x),
                "software": r.get("softwareName"), "version": r.get("softwareVersion"), "cve": r.get("cveId"),
                "severity": r.get("vulnerabilitySeverityLevel") or "Unrated", "cvss": r.get("cvssScore"),
                "exploit": EXPLOIT_WORDS.get(r.get("exploitabilityLevel"), r.get("exploitabilityLevel") or ""),
                "update": r.get("recommendedSecurityUpdate") or "", "when": (r.get("eventTimestamp") or "")[:16].replace("T", " ")})
    rank = {s: i for i, s in enumerate(SEVS)}
    for rows in out.values():
        rows.sort(key=lambda r: (rank.get(r["severity"], 9), -(r["cvss"] or 0), r["app"] or "", r["cve"] or ""))
    return out


def gather(settings: Settings) -> dict:
    rep = settings.reporting_dir
    con = duckdb.connect()
    for name in TABLES:
        con.execute(f"CREATE VIEW {name} AS SELECT * FROM read_parquet('{(rep / name).as_posix()}.parquet')")

    def q(sql: str) -> list[dict]:
        cur = con.execute(sql)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    snapshot = str(con.execute("SELECT max(snapshot_date) FROM fact_vulnerability").fetchone()[0])
    raw = settings.raw_dir / snapshot
    manifest, quality = _json(raw / "manifest.json"), _json(raw / "quality.json")
    fixes = _json(rep / "ai_fixes.json")
    guides = {a["key"]: a for a in fixes.get("apps", [])}

    vulns = q(f"""
        SELECT v.device_name, v.opco, v.software_vendor, v.software_name, v.software_version, v.cve_id, v.severity,
               v.cvss_score, v.exploitability, v.priority, CAST(v.first_seen AS DATE) AS first_seen,
               v.age_days, v.age_bucket, v.sla_days, CAST(v.first_seen AS DATE) + CAST(v.sla_days AS INTEGER) AS fix_by,
               v.sla_breached, v.recommended_update, v.security_update_available
        FROM fact_vulnerability v
        ORDER BY {SEV_RANK.replace('severity', 'v.severity')}, v.cvss_score DESC NULLS LAST, v.software_name, v.device_name, v.cve_id""")
    for v in vulns:
        v["guide"] = guides.get(f"{v['software_vendor']}:{v['software_name']}")
        v["exploit_words"] = EXPLOIT_WORDS.get(v["exploitability"], v["exploitability"] or "")

    devices = q(f"""
        SELECT d.device_name, d.opco, d.os_platform, d.os_version, d.exposure_level, d.risk_score, d.health_status,
               CAST(d.last_seen AS DATE) AS last_seen,
               count(v.cve_id) AS findings,
               {", ".join(f"count(v.cve_id) FILTER (WHERE v.severity = '{s}') AS {s.lower()}" for s in SEVS)},
               count(v.cve_id) FILTER (WHERE v.priority = 'P1') AS p1,
               count(v.cve_id) FILTER (WHERE v.sla_breached) AS overdue,
               count(DISTINCT v.software_name || ' ' || v.software_version) AS app_versions
        FROM dim_device d LEFT JOIN fact_vulnerability v ON v.device_id = d.device_id
        GROUP BY ALL ORDER BY findings DESC""")
    opco_of = {d["device_name"]: d["opco"] for d in devices}
    changes = _changes(raw / "changes.json.gz", opco_of)

    sev = {r["severity"]: r["n"] for r in q("SELECT severity, count(*) AS n FROM fact_vulnerability GROUP BY 1")}
    prio = {r["priority"]: r["n"] for r in q("SELECT priority, count(*) AS n FROM fact_vulnerability WHERE priority IS NOT NULL GROUP BY 1")}
    by_opco = q(f"""SELECT opco, {", ".join(f"count(*) FILTER (WHERE severity = '{s}') AS {s.lower()}" for s in SEVS)},
                           count(*) AS total, count(*) FILTER (WHERE priority = 'P1') AS p1,
                           count(*) FILTER (WHERE sla_breached) AS overdue, count(DISTINCT device_id) AS devices
                    FROM fact_vulnerability GROUP BY opco ORDER BY total DESC""")
    ages = {r["age_bucket"]: r for r in q(f"""SELECT age_bucket, {", ".join(f"count(*) FILTER (WHERE severity = '{s}') AS {s.lower()}" for s in SEVS)}
                                              FROM fact_vulnerability GROUP BY 1""")}
    sla = q(f"""SELECT severity, any_value(sla_days) AS days, count(*) AS open, count(*) FILTER (WHERE sla_breached) AS overdue
                FROM fact_vulnerability GROUP BY severity ORDER BY {SEV_RANK}""")
    trend = q(f"""SELECT strftime(snapshot_date, '%Y-%m-%d') AS day,
                         {", ".join(f"coalesce(sum(vulnerabilities) FILTER (WHERE severity = '{s}'), 0) AS {s.lower()}" for s in SEVS)}
                  FROM fact_daily_summary GROUP BY 1 ORDER BY 1""")
    top_cves = q(f"""
        SELECT cve_id, any_value(severity) AS severity, max(cvss_score) AS cvss, min(priority) AS priority,
               any_value(exploitability) AS exploitability, count(DISTINCT device_id) AS devices,
               string_agg(DISTINCT software_name, ', ') AS apps, string_agg(DISTINCT opco, ', ') AS opcos, count(*) AS findings
        FROM fact_vulnerability GROUP BY cve_id
        ORDER BY min(priority), count(DISTINCT device_id) DESC, max(cvss_score) DESC NULLS LAST LIMIT 100""")
    apps = q(f"""SELECT software_vendor, software_name, software_version,
                        {", ".join(f"count(*) FILTER (WHERE severity = '{s}') AS {s.lower()}" for s in SEVS)},
                        count(*) AS findings, count(DISTINCT device_id) AS devices, any_value(recommended_update) AS update
                 FROM fact_vulnerability GROUP BY ALL ORDER BY findings DESC""")
    oldest = [v for v in vulns if v["severity"] in ("Critical", "High")]
    oldest.sort(key=lambda v: -(v["age_days"] or 0))
    history = q("SELECT * FROM run_history ORDER BY run_date DESC")
    counts = manifest.get("counts", {})
    total_rows = counts.get("vulnerability_rows") or len(vulns)
    return {
        "snapshot": snapshot, "manifest": manifest, "counts": counts, "quality": quality, "fixes": fixes,
        "vulns": vulns, "devices": devices, "changes": changes, "sev": sev, "prio": prio, "by_opco": by_opco,
        "ages": ages, "sla": sla, "trend": trend, "top_cves": top_cves, "apps": apps,
        "oldest": oldest[:25], "history": history,
        "totals": {
            "defender_rows": total_rows, "unique": len(vulns), "repeats": max(0, total_rows - len(vulns)),
            "machines": counts.get("machines") or len(devices),
            "new": len(changes["New"]) if changes["New"] or "new" not in counts else counts["new"],
            "fixed": len(changes["Fixed"]) if changes["Fixed"] or "fixed" not in counts else counts["fixed"],
            "updated": len(changes["Updated"]),
            "critical": sev.get("Critical", 0), "high": sev.get("High", 0), "p1": prio.get("P1", 0),
            "overdue": sum(1 for v in vulns if v["sla_breached"]),
            "app_versions": len(apps), "quality": quality.get("overall") or (history[0]["quality"] if history else "n/a"),
        },
    }


# ---------------------------------------------------------------- small helpers
def fmt_date(value) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (date, datetime)):
        return value.strftime("%d %b %Y")
    try:
        return datetime.fromisoformat(str(value)[:10]).strftime("%d %b %Y")
    except ValueError:
        return str(value)


def run_lines(d: dict) -> list[str]:
    m, t = d["manifest"], d["totals"]
    started = m.get("started_at")
    when = datetime.fromisoformat(started).astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC") if started else d["snapshot"]
    export = m.get("export_generated_time")
    lines = [f"Scan of {when}" + (f" · Defender data exported {str(export)[:16].replace('T', ' ')} UTC" if export else ""),
             f"{t['machines']} computers · {t['unique']:,} vulnerabilities in Defender · data quality {t['quality']}",
             f"Created {datetime.now(timezone.utc):%d %b %Y, %H:%M} UTC · this report shows this scan only"]
    return lines


def summary_tiles(t: dict) -> list[tuple]:
    """The same six numbers and wording as the portal's run card."""
    return [
        (f"{t['unique']:,}", "Vulnerabilities in Defender", f"found on {t['machines']} computers", ds.BLUE),
        (f"{t['new']:,}", "New in this run", "not there in the last run", ds.SERIOUS),
        (f"{t['fixed']:,}", "Fixed since the last run", "no longer found by Defender", ds.GOOD),
        (f"{t['critical']:,}", "Critical vulnerabilities", "most dangerous: remediate these first", ds.BAD),
        (f"{t['high']:,}", "High vulnerabilities", "remediate after the critical ones", ds.SERIOUS),
        (t["quality"], "Data quality", {"PASS": "every automatic check passed", "WARN": "some checks need a look",
                                        "FAIL": "a check failed"}.get(t["quality"], ""),
         {"PASS": ds.GOOD, "WARN": ds.WARN, "FAIL": ds.BAD}.get(t["quality"], ds.INK_3)),
    ]


def guide_sections(g: dict) -> list[tuple]:
    ai, fix = g.get("ai") or {}, g.get("fix") or {}
    cmd = fix.get("command")
    return [("What is wrong", ai.get("what_is_wrong")), ("Worst case", ai.get("worst_case")),
            ("Why now", ai.get("why_now")), ("Remediation", fix.get("action")), ("Steps", ai.get("steps") or []),
            ("Command", ("code", cmd) if cmd else None), ("How to check it worked", ai.get("verify")),
            ("Side effects", ai.get("side_effects"))]


def guide_source(g: dict) -> str:
    if (g.get("source") or "").startswith("ai"):
        older = " (written for the previous scan's facts)" if "previous" in g["source"] else ""
        return f"Explained by AI ({g.get('model') or 'AI'}){older}; facts, versions and commands come from the data."
    return "Standard steps from the data (AI was not available for this one)."


# ---------------------------------------------------------------- Word / PDF
def build_report(settings: Settings, d: dict | None = None) -> dict:
    d = d or gather(settings)
    t = d["totals"]
    r = ds.Report("Vulnerability Report", "Vulnerability Agent", run_lines(d))

    # 1. Summary
    r.h1("1. Summary")
    r.tiles(summary_tiles(t))
    r.tiles([(f"{t['overdue']:,}", "Overdue", "past their due date", ds.BAD),
             (f"{t['p1']:,}", "Priority P1", "remediate first (see appendix)", ds.SERIOUS),
             (f"{t['app_versions']:,}", "App versions to update", "each clears several findings", ds.BLUE)])
    r.para(f"This scan found {t['unique']:,} vulnerabilities on {t['machines']} computers. "
           f"{t['critical']:,} are Critical and {t['high']:,} High; {t['overdue']:,} are past their due date. "
           f"Since the last scan, {t['new']:,} appeared and {t['fixed']:,} were fixed.")
    sev_names = [*SEVS, "Unrated"]
    sev_vals = [d["sev"].get(s, 0) for s in sev_names]
    prio_names = ("P1", "P2", "P3", "P4")
    r.images_side_by_side([
        ds.donut(sev_names, sev_vals, [ds.SEVERITY[s] for s in sev_names], f"{sum(sev_vals):,}", "by severity"),
        ds.donut(list(prio_names), [d["prio"].get(p, 0) for p in prio_names], [ds.BAD, ds.SERIOUS, ds.WARN, "16A34A"],
                 f"{t['p1']:,}", "P1 to remediate first")])
    if d["by_opco"]:
        r.image(ds.stacked([o["opco"] for o in d["by_opco"]], {s: [o[s.lower()] for o in d["by_opco"]] for s in SEVS},
                           ds.SEVERITY, "Vulnerabilities by OpCo and severity", height=2.4))
    if len(d["trend"]) > 1:
        r.image(ds.line([x["day"][5:] for x in d["trend"]], {s: [x[s.lower()] for x in d["trend"]] for s in SEVS},
                        ds.SEVERITY, "Open vulnerabilities per scan"))

    # 2. Fix these first
    r.h1("2. Remediate these first")
    r.para("One update or setting change clears many findings at once. These are ordered by priority, then by how many "
           "findings each remediation clears.")
    apps = sorted(d["fixes"].get("apps", []), key=lambda a: (a["urgency"]["level"], -a["findings"]))
    if apps:
        top = apps[:10]
        r.image(ds.hbar([a["app"][:40] for a in top], [a["findings"] for a in top],
                        [URGENCY_COLOURS.get(a["urgency"]["level"], ds.BLUE) for a in top],
                        "Findings each remediation clears (top 10)"))
        r.table(["App", "Priority", "Remediation", "Findings", "Critical", "High", "Due date"],
                [[a["app"], a["urgency"]["label"], (a.get("fix") or {}).get("action"), f"{a['findings']:,}", a["critical"],
                  a["high"], fmt_date(a.get("fix_by"))] for a in apps[:20]],
                [4, 4, 5, 1.6, 1.5, 1.4, 2.2])
    else:
        r.note("The remediation guide has not been built for this scan.")

    # 3. Where the risk is
    r.h1("3. Where the risk is")
    r.h2("By OpCo")
    r.table(["OpCo", "Critical", "High", "Medium", "Low", "Total", "P1", "Overdue", "Computers"],
            [[o["opco"], o["critical"], o["high"], o["medium"], o["low"], f"{o['total']:,}", o["p1"], o["overdue"], o["devices"]]
             for o in d["by_opco"]], [3, 1.5, 1.5, 1.5, 1.5, 1.5, 1.3, 1.5, 1.8])
    r.h2("By computer")
    r.table(["Computer", "OpCo", "OS", "Findings", "Critical", "High", "P1", "Overdue", "Exposure", "Last seen"],
            [[x["device_name"], x["opco"], f"{x['os_platform'] or ''} {x['os_version'] or ''}".strip(), f"{x['findings']:,}",
              x["critical"], x["high"], x["p1"], x["overdue"], x["exposure_level"] or "", fmt_date(x["last_seen"])]
             for x in d["devices"]], [3, 2, 3, 1.5, 1.4, 1.2, 1.1, 1.4, 1.6, 2])

    # 4. Deadlines
    r.h1("4. Deadlines and the oldest findings")
    r.image(ds.stacked(list(AGES), {s: [(d["ages"].get(a) or {}).get(s.lower(), 0) for a in AGES] for s in SEVS},
                       ds.SEVERITY, "How long findings have been open (days)", height=2.3))
    r.table(["Severity", "Remediation SLA (days)", "Open", "Overdue"],
            [[s["severity"], s["days"] if s["days"] is not None else "no deadline", f"{s['open']:,}", f"{s['overdue']:,}"]
             for s in d["sla"]], [3, 3, 2.5, 2.5], severity_col=0)
    r.h2("Oldest Critical and High findings")
    r.table(["CVE", "App", "Computer", "Severity", "Open (days)", "Due date", "Overdue"],
            [[v["cve_id"], f"{v['software_name']} {v['software_version']}", v["device_name"], v["severity"], v["age_days"],
              fmt_date(v["fix_by"]), "Yes" if v["sla_breached"] else ""] for v in d["oldest"]],
            [3, 4, 2.6, 1.8, 1.6, 2.2, 1.4], severity_col=3, colour_cols={6: {"Yes": ds.BAD}})

    # 5. What changed
    r.h1("5. What changed in this scan")
    ch = d["changes"]
    r.tiles([(f"{t['new']:,}", "New", "not there in the last run", ds.SERIOUS),
             (f"{t['fixed']:,}", "Fixed", "no longer found by Defender", ds.GOOD),
             (f"{t['updated']:,}", "Updated", "Defender changed their details", ds.BLUE)])
    if ch["New"] or ch["Fixed"]:
        r.image(ds.stacked(["New", "Fixed"], {s: [sum(x["severity"] == s for x in ch["New"]),
                                                   sum(x["severity"] == s for x in ch["Fixed"])] for s in SEVS},
                           ds.SEVERITY, "New and remediated by severity", horizontal=True, height=1.7))
    r.h2("New Critical and High vulnerabilities")
    new_top = [x for x in ch["New"] if x["severity"] in ("Critical", "High")]
    r.table(["CVE", "App", "Version", "Computer", "Severity", "CVSS", "Exploit"],
            [[x["cve"], x["app"], x["version"], x["device"], x["severity"], x["cvss"], x["exploit"]] for x in new_top[:40]],
            [3, 3.5, 2.5, 2.5, 1.7, 1.2, 2.4], severity_col=4)
    if len(new_top) > 40:
        r.note(f"Showing 40 of {len(new_top):,}. The Excel workbook lists every new and remediated vulnerability.")
    r.h2("Remediated, by app")
    fixed_apps: dict[str, list] = {}
    for x in ch["Fixed"]:
        fixed_apps.setdefault(f"{x['app']} {x['version']}", []).append(x)
    r.table(["App and version", "Remediated", "Critical", "High", "Computers"],
            [[k, len(v), sum(x["severity"] == "Critical" for x in v), sum(x["severity"] == "High" for x in v),
              ", ".join(sorted({x["device"] for x in v}))] for k, v in sorted(fixed_apps.items(), key=lambda kv: -len(kv[1]))[:30]],
            [6, 1.6, 1.6, 1.6, 4])

    # 6. Top CVEs
    r.h1("6. Top 25 CVEs")
    r.table(["CVE", "Severity", "CVSS", "Priority", "Computers", "Apps"],
            [[c["cve_id"], c["severity"], c["cvss"], c["priority"], c["devices"], c["apps"]]
             for c in d["top_cves"][:25]], [3, 1.8, 1.2, 1.4, 1.6, 5], severity_col=1)

    # 7. Fix guides
    r.page_break()
    r.h1("7. Remediation for each one (AI remediation guides)")
    r.para("One guide per vulnerable app and per weak security setting. Versions, CVEs, computers, deadlines and commands "
           "come from the data; the AI explains them in plain words. Check the steps before acting.")
    r.h2(f"Apps ({len(apps)})")
    for a in apps:
        vers = ", ".join(v["version"] for v in a["versions"])
        meta = (f"{a.get('fix_type', '')} · versions {vers} · {len(a['devices'])} computer(s): "
                f"{', '.join(x['name'] for x in a['devices'])} · {a['cves']} CVEs ({a['critical']} critical, {a['high']} high)"
                + (f" · fix by {fmt_date(a['fix_by'])}" if a.get("fix_by") else ""))
        r.card(a["app"], meta, guide_sections(a) + [("Source", guide_source(a))],
               URGENCY_COLOURS.get(a["urgency"]["level"], ds.BLUE), a["urgency"]["label"])
    settings_cards = sorted(d["fixes"].get("settings", []), key=lambda s: ((s.get("urgency") or {}).get("level", 9), -s.get("impact", 0)))
    r.h2(f"Security settings ({len(settings_cards)})")
    for s in settings_cards:
        u = s.get("urgency") or {}
        meta = (f"{s.get('fix_type', '')} · {s.get('category', '')} / {s.get('subcategory', '')} · impact {s.get('impact', 0):g}/10 · "
                f"{len(s.get('devices', []))} computer(s): {', '.join(x['name'] for x in s.get('devices', []))}")
        r.card(s["app"], meta, guide_sections(s) + [("Source", guide_source(s))],
               URGENCY_COLOURS.get(u.get("level"), ds.BLUE), u.get("label", ""))

    # Appendix
    r.page_break()
    r.h1("Appendix A: data quality checks")
    r.para(f"Downloaded {t['defender_rows']:,} rows from Microsoft Defender. {t['repeats']:,} of them were repeats "
           f"(Defender listed the same vulnerability twice), so {t['unique']:,} vulnerabilities were kept."
           if t["repeats"] else f"Downloaded {t['defender_rows']:,} rows from Microsoft Defender, with no repeats.")
    checks = d["quality"].get("checks", [])
    r.table(["Check", "Result", "Value", "Expected"],
            [[c["name"].replace("_", " "), c["status"], c["value"], c["expected"]] for c in checks],
            [4, 1.6, 5, 6], colour_cols={1: {"PASS": ds.GOOD, "WARN": ds.WARN, "FAIL": ds.BAD, "INFO": ds.BLUE}})
    r.h1("Appendix B: how the ratings work")
    r.bullets([
        "Severity (Critical, High, Medium, Low) comes from Microsoft Defender, mostly from the CVE's CVSS score. "
        "A brand-new CVE Microsoft has not rated yet is shown as Unrated.",
        "Priority adds whether a working exploit exists: P1 = Critical, or High with a verified exploit or one in attack "
        "kits; P2 = High, or Medium with such an exploit; P3 = Medium or Unrated; P4 = Low.",
        "Due date = the day Defender first saw it + the deadline for its severity: Critical 15 days, High 30, "
        "Medium 90, Low 180. After that it is overdue.",
        "New and Remediated come from Defender's own change list for this scan.",
    ])
    out = settings.reporting_dir / f"Vulnerability_Report_{d['snapshot']}.docx"
    return r.save(out)
