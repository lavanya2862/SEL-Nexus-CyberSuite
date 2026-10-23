"""Daily Excel summary (opens in LibreOffice Calc or Excel), built from the reporting tables only.

data/reporting/UC3_Vulnerability_Summary_<snapshot>.xlsx with sheets: Overview, By OpCo, Top CVEs,
Apps to update, Age & SLA, Trend, Data health
(+ AI Fix Plan when the AI fix guide exists). Summaries only — no million-row sheets.
"""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
from openpyxl import Workbook
from openpyxl.chart import BarChart, LineChart, Reference
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from uc3.config import Settings

HEADER_FILL = PatternFill("solid", fgColor="1C5CAB")
HEADER_FONT = Font(bold=True, color="FFFFFF")
TITLE_FONT = Font(bold=True, size=14)
SEVS = ("Critical", "High", "Medium", "Low")


def _table(ws, top: int, headers: list[str], rows: list, widths: dict[int, int] | None = None) -> int:
    """Write a header row + data rows starting at row `top`; return the next free row."""
    for col, name in enumerate(headers, 1):
        cell = ws.cell(row=top, column=col, value=name)
        cell.fill, cell.font = HEADER_FILL, HEADER_FONT
        cell.alignment = Alignment(horizontal="center")
    for r, row in enumerate(rows, top + 1):
        for c, value in enumerate(row, 1):
            ws.cell(row=r, column=c, value=value)
    for col in range(1, len(headers) + 1):
        width = (widths or {}).get(col) or max(12, min(60, max(len(str(ws.cell(row=r, column=col).value or ""))
                                                                  for r in range(top, top + len(rows) + 1)) + 2))
        ws.column_dimensions[get_column_letter(col)].width = max(ws.column_dimensions[get_column_letter(col)].width or 0, width)
    return top + len(rows) + 2


def _bar(ws, title: str, data_ref: tuple, cats_ref: tuple, anchor: str, stacked: bool = True, horizontal: bool = False):
    chart = BarChart()
    chart.type = "bar" if horizontal else "col"
    chart.title, chart.height, chart.width = title, 8, 16
    if stacked:
        chart.grouping, chart.overlap = "stacked", 100
    chart.add_data(Reference(ws, min_col=data_ref[0], min_row=data_ref[1], max_col=data_ref[2], max_row=data_ref[3]),
                   titles_from_data=True)
    chart.set_categories(Reference(ws, min_col=cats_ref[0], min_row=cats_ref[1], max_row=cats_ref[2]))
    ws.add_chart(chart, anchor)


def build_excel(settings: Settings) -> Path:
    rep = settings.reporting_dir
    con = duckdb.connect()
    for name in ("fact_vulnerability", "fact_daily_summary", "fact_remediation", "dim_device", "dq_status", "run_history"):
        con.execute(f"CREATE VIEW {name} AS SELECT * FROM read_parquet('{(rep / name).as_posix()}.parquet')")
    q = lambda sql: con.execute(sql).fetchall()
    snapshot = q("SELECT max(snapshot_date) FROM dim_device")[0][0]
    wb = Workbook()

    # --- Overview
    ws = wb.active
    ws.title = "Overview"
    ws["A1"], ws["A1"].font = f"UC3 vulnerability summary — snapshot {snapshot}", TITLE_FONT
    run = q("SELECT vulnerability_rows, defender_count, coverage, machines, duration_seconds FROM run_history ORDER BY run_date DESC LIMIT 1")
    total, crit, p1, kev, apps = q("""SELECT count(*), count(*) FILTER (WHERE severity = 'Critical'), count(*) FILTER (WHERE priority = 'P1'),
                                      count(DISTINCT cve_id) FILTER (WHERE in_cisa_kev), count(DISTINCT (software_name, software_version))
                                      FROM fact_vulnerability""")[0]
    facts = [("Open findings", total), ("Critical", crit), ("P1 (fix first)", p1), ("CVEs exploited in the wild (CISA KEV)", kev),
             ("App versions to update", apps)]
    if run:
        rows_exported, defender, coverage, machines, duration = run[0]
        facts += [("Devices", machines), ("Rows exported", rows_exported), ("Rows in Defender (own count)", defender),
                  ("Coverage", f"{coverage:.1%}" if coverage is not None else "n/a"), ("Run time (s)", duration)]
    _table(ws, 3, ["Measure", "Value"], facts, {1: 40, 2: 16})

    # --- By OpCo
    ws = wb.create_sheet("By OpCo")
    rows = q(f"""SELECT opco, {", ".join(f"count(*) FILTER (WHERE severity = '{s}')" for s in SEVS)}, count(*),
                        count(*) FILTER (WHERE priority = 'P1'), count(*) FILTER (WHERE sla_breached)
                 FROM fact_vulnerability GROUP BY opco ORDER BY opco""")
    _table(ws, 1, ["OpCo", *SEVS, "Total", "P1", "SLA breached"], rows)
    if rows:
        _bar(ws, "Findings by OpCo and severity", (2, 1, 5, len(rows) + 1), (1, 2, len(rows) + 1), "J2")

    # --- Top CVEs
    ws = wb.create_sheet("Top CVEs")
    rows = q("""SELECT cve_id, any_value(severity), max(cvss_score), any_value(priority), bool_or(in_cisa_kev),
                       count(DISTINCT device_id), string_agg(DISTINCT software_name, ', '), string_agg(DISTINCT opco, ', ')
                FROM fact_vulnerability GROUP BY cve_id
                ORDER BY any_value(priority), bool_or(in_cisa_kev) DESC, count(DISTINCT device_id) DESC, max(cvss_score) DESC
                LIMIT 100""")
    _table(ws, 1, ["CVE", "Severity", "CVSS", "Priority", "On CISA KEV", "Devices", "Apps", "OpCos"],
           [(*r[:4], "yes" if r[4] else "", *r[5:]) for r in rows])

    # --- Apps to update
    ws = wb.create_sheet("Apps to update")
    rows = q(f"""SELECT software_name || ' ' || software_version, {", ".join(f"count(*) FILTER (WHERE severity = '{s}')" for s in SEVS)},
                        count(*), count(DISTINCT device_id)
                 FROM fact_vulnerability GROUP BY 1 ORDER BY count(*) DESC""")
    _table(ws, 1, ["App (installed version)", *SEVS, "Findings cleared by updating", "Devices"], rows)
    if rows:
        _bar(ws, "Findings per app version", (2, 1, 5, min(len(rows), 12) + 1), (1, 2, min(len(rows), 12) + 1), "J2",
             horizontal=True)

    # --- Age & SLA
    ws = wb.create_sheet("Age & SLA")
    rows = q(f"""SELECT b, {", ".join(f"count(v.severity) FILTER (WHERE v.severity = '{s}')" for s in SEVS)}
                 FROM (VALUES ('0-30'), ('31-60'), ('61-90'), ('90+')) t(b) LEFT JOIN fact_vulnerability v ON v.age_bucket = t.b
                 GROUP BY b ORDER BY b""")
    rows.sort(key=lambda r: ["0-30", "31-60", "61-90", "90+"].index(r[0]))
    nxt = _table(ws, 1, ["Age (days)", *SEVS], rows)
    _bar(ws, "Findings by age", (2, 1, 5, len(rows) + 1), (1, 2, len(rows) + 1), "H2")
    sla = q("""SELECT severity, any_value(sla_days), count(*), count(*) FILTER (WHERE sla_breached)
               FROM fact_vulnerability GROUP BY severity ORDER BY any_value(sla_days)""")
    _table(ws, nxt, ["Severity", "Fix within (days)", "Open", "Breached"], sla)

    # --- Trend
    ws = wb.create_sheet("Trend")
    rows = q(f"""SELECT strftime(snapshot_date, '%Y-%m-%d'), {", ".join(f"coalesce(sum(vulnerabilities) FILTER (WHERE severity = '{s}'), 0)" for s in SEVS)}
                 FROM fact_daily_summary GROUP BY 1 ORDER BY 1""")
    _table(ws, 1, ["Date", *SEVS], rows)
    if len(rows) > 1:
        chart = LineChart()
        chart.title, chart.height, chart.width = "Open findings per day", 8, 16
        chart.add_data(Reference(ws, min_col=2, min_row=1, max_col=5, max_row=len(rows) + 1), titles_from_data=True)
        chart.set_categories(Reference(ws, min_col=1, min_row=2, max_row=len(rows) + 1))
        ws.add_chart(chart, "H2")

    # --- Data health
    ws = wb.create_sheet("Data health")
    nxt = _table(ws, 1, ["Check", "Status", "Value", "Expected", "Message"],
                 q("SELECT check_name, status, value, expected, message FROM dq_status WHERE run_date = (SELECT max(run_date) FROM dq_status)"),
                 {5: 70})
    _table(ws, nxt, ["Run date", "Rows exported", "Rows in Defender", "Coverage", "Devices", "Run time (s)", "Quality"],
           [(r[0], r[1], r[2], f"{r[3]:.1%}" if r[3] is not None else "", r[4], r[5], r[6]) for r in
            q("SELECT run_date, vulnerability_rows, defender_count, coverage, machines, duration_seconds, quality FROM run_history ORDER BY run_date DESC")])

    # --- AI Fix Plan (only when `uc3 ai-fixes` / the run has built it)
    fixes_path = rep / "ai_fixes.json"
    if fixes_path.is_file():
        fixes = json.loads(fixes_path.read_text(encoding="utf-8"))
        ws = wb.create_sheet("AI Fix Plan")
        ws["A1"], ws["A1"].font = "AI fix plan: one row per app and per security setting. Facts and commands come from the data; AI text must be checked before acting", TITLE_FONT
        source = lambda a: "AI (" + (a.get("model") or "?") + ")" if a["source"].startswith("ai") else "Data only"
        steps = lambda a: "\n".join(f"{n}. {s}" for n, s in enumerate(a["ai"]["steps"], 1))
        rows = [(i, "App", a.get("fix_type", "Update the app"), a["app"], ", ".join(v["version"] for v in a["versions"]),
                 a["urgency"]["label"], a["fix_by"], a["cves"], a["p1"], len(a["kev_cves"]),
                 ", ".join(d["name"] for d in a["devices"]), a["fix"]["action"], a["fix"]["command"] or "",
                 a["ai"]["what_is_wrong"], steps(a), a["ai"]["verify"], source(a))
                for i, a in enumerate(fixes["apps"], 1)]
        rows += [(len(rows) + i, "Setting", s["fix_type"], s["app"], f"{s['category']} · impact {s['impact']:g}/10",
                  s["urgency"]["label"], None, None, None, None, ", ".join(d["name"] for d in s["devices"]),
                  s["fix"]["action"], s["fix"]["command"] or "(see Microsoft's instructions)", s["ai"]["what_is_wrong"],
                  steps(s), s["ai"]["verify"], source(s))
                 for i, s in enumerate(fixes.get("settings", []), 1)]
        _table(ws, 3, ["#", "Kind", "Fix type", "App / setting", "Installed versions / category", "Urgency", "Fix by", "CVEs",
                       "P1", "Used by attackers", "Devices", "Fix", "Command", "What is wrong", "Steps", "How to check",
                       "Text source"], rows,
               {1: 5, 2: 9, 3: 26, 4: 34, 5: 24, 6: 24, 7: 12, 11: 26, 12: 36, 13: 44, 14: 60, 15: 70, 16: 45, 17: 22})
        for row in ws.iter_rows(min_row=4, max_row=3 + len(rows)):
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")

    out = settings.reporting_dir / f"UC3_Vulnerability_Summary_{snapshot}.xlsx"
    wb.save(out)
    return out
