"""Phase 7: threat-hunting report (Word + PDF).

Numbers and tables come from the database. Gemini writes only the executive summary, from a JSON block
of facts; if the summary contains a number that isn't in the facts, it's replaced by a template summary.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from datetime import timedelta
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor

from uc1.ai.gemini_client import AIUnavailable, GeminiClient
from uc1.ai.guard import numbers_supported
from uc1.ai.prompts import SUMMARY_SYSTEM
from uc1.ai.schemas import ExecutiveSummary
from uc1.config import Settings
from uc1.fix_advice import for_threats
from uc1.resolve import for_findings
from uc1.store import Store, dumps, utcnow

log = logging.getLogger("uc1.report")

RATING_COLOURS = {"Critical": "B42318", "High": "C4320A", "Medium": "B54708", "Low": "475467"}
SOFFICE = [Path(r"C:\Program Files\LibreOffice\program\soffice.exe"),
           Path(r"C:\Program Files (x86)\LibreOffice\program\soffice.exe")]


def defang(value: str) -> str:
    return (value or "").replace("http", "hxxp").replace(".", "[.]")


def _j(value):
    if value is None:
        return []
    return json.loads(value) if isinstance(value, str) else value


# ---------------------------------------------------------------- data
def gather(store: Store, run_id: str | None, window_days: int = 7) -> dict:
    since = utcnow() - timedelta(days=window_days)
    threats = store.query("""
        SELECT t.*, s.score, s.rating, s.why, a.summary, a.actions, a.techniques, a.ai_status,
               (SELECT string_agg(DISTINCT e.recommended_update, '||') FROM exposure e
                WHERE e.threat_id = t.threat_id AND e.recommended_update <> '') AS fix,
               (SELECT COUNT(DISTINCT f.device_id) FROM findings f WHERE f.threat_id = t.threat_id AND f.kind = 'exposure') AS exposed,
               (SELECT COUNT(*) FROM findings f WHERE f.threat_id = t.threat_id AND f.kind <> 'exposure') AS hits
        FROM threats t JOIN scores s ON s.threat_id = t.threat_id LEFT JOIN analysis a ON a.threat_id = t.threat_id
        WHERE t.first_seen_at >= ? OR t.threat_id IN (SELECT threat_id FROM findings)
        ORDER BY s.score DESC, t.published_at DESC NULLS LAST""", [since])
    for t in threats:   # Defender's concrete fixes for our devices come first (one per installed version)
        fixes = sorted((t["fix"] or "").split("||")) if t["fix"] else []
        t["actions"] = list(dict.fromkeys(fixes + _j(t["actions"])))
    findings = store.query("SELECT * FROM findings ORDER BY kind DESC, first_hit DESC NULLS LAST")
    hunts = store.query("SELECT * FROM hunts WHERE run_id = ? ORDER BY origin, name", [run_id]) if run_id else []
    devices = store.query("SELECT * FROM devices ORDER BY device_name")
    techniques = store.query("""
        SELECT l.value AS technique_id, COALESCE(a.name, '') AS name, COALESCE(a.tactics, '') AS tactics,
               COUNT(DISTINCT l.threat_id) AS threats
        FROM threat_links l LEFT JOIN attack_techniques a ON a.technique_id = l.value
        WHERE l.link_type = 'technique' AND l.threat_id IN (SELECT threat_id FROM threats WHERE first_seen_at >= ?
                                                             OR threat_id IN (SELECT threat_id FROM findings))
        GROUP BY ALL ORDER BY threats DESC LIMIT 40""", [since])
    hit_iocs = {f["detail"].split(" ", 2)[-1] for f in findings if f["kind"] == "ioc_hit"}
    iocs = store.query("""
        SELECT i.* FROM iocs i WHERE i.is_test OR i.first_seen >= ? ORDER BY i.is_test DESC, i.confidence DESC LIMIT 60""", [since])
    by_threat_findings: dict[str, list[dict]] = {}
    for f in findings:
        by_threat_findings.setdefault(f["threat_id"], []).append(f)
    return {"threats": threats, "findings": findings, "by_threat": by_threat_findings, "hunts": hunts,
            "devices": devices, "techniques": techniques, "iocs": iocs, "hit_iocs": hit_iocs,
            "window_days": window_days}


def facts(d: dict) -> dict:
    real = [t for t in d["threats"] if not t["is_test"]]
    return {
        "report_window_days": d["window_days"],
        "threats_reviewed": len(real),
        "ratings": {r: sum(t["rating"] == r for t in real) for r in ("Critical", "High", "Medium", "Low")},
        "threats_affecting_our_devices": sum(1 for t in real if t["exposed"] or t["hits"]),
        "devices_monitored": len(d["devices"]),
        "hunts_run_this_cycle": len(d["hunts"]),
        "hunts_with_results": sum(1 for h in d["hunts"] if (h["row_count"] or 0) > 0),
        "top_risks": [{"title": t["title"], "rating": t["rating"], "score": t["score"], "exposed_devices": t["exposed"],
                       "hunt_hits": t["hits"], "first_action": (_j(t["actions"]) or [""])[0], "is_test": t["is_test"]}
                      for t in d["threats"] if t["rating"] in ("Critical", "High")][:8],
        "lab_tests_detected": sum(1 for f in d["findings"] if f["is_test"] and f["kind"] != "exposure"),
    }


def template_summary(f: dict) -> dict:
    top = [r for r in f["top_risks"] if not r["is_test"]]
    headline = (f"{f['threats_affecting_our_devices']} of {f['threats_reviewed']} threats reviewed affect our devices; "
                f"{f['ratings']['Critical']} rated Critical and {f['ratings']['High']} High."
                if f["threats_reviewed"] else "No new threats in this period.")
    paragraphs = [f"The agent reviewed {f['threats_reviewed']} threats from public intelligence feeds over the last "
                  f"{f['report_window_days']} days and checked them against the {f['devices_monitored']} devices in "
                  f"Microsoft Defender. It ran {f['hunts_run_this_cycle']} hunts in this cycle; "
                  f"{f['hunts_with_results']} returned results."]
    if f["lab_tests_detected"]:
        paragraphs.append(f"{f['lab_tests_detected']} harmless lab tests were detected as expected (not real attacks).")
    return {"headline": headline, "paragraphs": paragraphs,
            "top_actions": [r["first_action"] for r in top if r["first_action"]][:5]}


def executive_summary(f: dict, ai: GeminiClient | None) -> tuple[dict, str]:
    if ai is None:
        return template_summary(f), "template (AI not configured)"
    data = dumps(f)
    try:
        s = ai.json("summary", SUMMARY_SYSTEM, f"<<<DATA\n{data}\nDATA>>>", ExecutiveSummary, max_tokens=1500)
    except AIUnavailable as exc:
        return template_summary(f), f"template (AI unavailable: {exc})"
    text = " ".join([s.headline, *s.paragraphs, *s.top_actions])
    if not numbers_supported(text, data):
        return template_summary(f), "template (AI summary contained numbers not in the data)"
    return s.model_dump(), f"AI-written ({ai.model()}), numbers checked"


# ---------------------------------------------------------------- docx helpers
def _shade(cell, hex_colour: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_colour)
    tc_pr.append(shd)


def _table(doc, headers: list[str], rows: list[list], widths_small: bool = True):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Light Grid Accent 1"
    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h
    for row in rows:
        cells = table.add_row().cells
        for i, value in enumerate(row):
            cells[i].text = "" if value is None else str(value)
    if widths_small:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    for r in p.runs:
                        r.font.size = Pt(8.5)
    return table


def _rating_cell(cell, rating: str) -> None:
    colour = RATING_COLOURS.get(rating)
    if colour:
        _shade(cell, colour)
        for p in cell.paragraphs:
            for r in p.runs:
                r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                r.font.bold = True


# ---------------------------------------------------------------- build
def build(store: Store, settings: Settings, run_id: str | None, ai: GeminiClient | None, window_days: int = 7) -> dict:
    d = gather(store, run_id, window_days)
    f = facts(d)
    summary, summary_source = executive_summary(f, ai)
    now = utcnow()
    doc = Document()
    styles = doc.styles
    styles["Normal"].font.name = "Calibri"
    styles["Normal"].font.size = Pt(10)

    title = doc.add_heading("Threat Intelligence & Threat Hunting Report", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.LEFT
    doc.add_paragraph(f"Generated {now:%Y-%m-%d %H:%M} UTC · run {run_id or 'manual'} · window: last {window_days} days · "
                      "UC1 PoC: public threat feeds + our own Defender lab (no client data)")

    doc.add_heading("1. Executive summary", 1)
    p = doc.add_paragraph()
    p.add_run(summary["headline"]).bold = True
    for para in summary["paragraphs"]:
        doc.add_paragraph(para)
    if summary["top_actions"]:
        doc.add_paragraph("Recommended actions:").runs[0].bold = True
        for a in summary["top_actions"]:
            doc.add_paragraph(a, style="List Number")
    doc.add_paragraph(f"Summary source: {summary_source}.").runs[0].italic = True

    doc.add_heading("2. At a glance", 1)
    _table(doc, ["Measure", "Value"], [
        ["Threats reviewed (excluding lab tests)", f["threats_reviewed"]],
        ["Critical / High / Medium / Low", " / ".join(str(f["ratings"][r]) for r in ("Critical", "High", "Medium", "Low"))],
        ["Threats affecting our devices", f["threats_affecting_our_devices"]],
        ["Devices monitored in Defender", f["devices_monitored"]],
        ["Hunts run this cycle / with results", f"{f['hunts_run_this_cycle']} / {f['hunts_with_results']}"],
        ["Lab tests detected (harmless, on purpose)", f["lab_tests_detected"]],
    ])

    doc.add_heading("3. Top risks", 1)
    top = [t for t in d["threats"] if t["rating"] in ("Critical", "High", "Medium")][:25]
    if top:
        table = _table(doc, ["Rating", "Threat", "Our exposure", "First action"], [
            [t["rating"], ("[TEST] " if t["is_test"] else "") + t["title"],
             f"{t['exposed']} device(s) exposed" + (f", {t['hits']} hunt hit(s)" if t["hits"] else "") if (t["exposed"] or t["hits"]) else "not found on our devices",
             (_j(t["actions"]) or ["see details"])[0]] for t in top])
        for i, t in enumerate(top, start=1):
            _rating_cell(table.rows[i].cells[0], t["rating"])
    else:
        doc.add_paragraph("No Medium or higher risks in this period.")

    doc.add_heading("4. Signs of attack and how to resolve them", 1)
    signs = [fi for fi in d["findings"] if fi["kind"] != "exposure"]
    if signs:
        resolutions = for_findings(store)
        for fi in signs:
            res = resolutions.get(fi["finding_id"])
            doc.add_heading(f"{fi['device_name']}: {fi['detail']}", 2)
            doc.add_paragraph(f"First seen {fi['first_hit'] or 'n/a'} · {fi['opco']}")
            if not res:
                doc.add_paragraph("Resolution steps are written in the next run.").runs[0].italic = True
                continue
            doc.add_paragraph(res["what_happened"])
            doc.add_paragraph("How to resolve:").runs[0].bold = True
            for step in res["steps"]:
                doc.add_paragraph(step, style="List Number")
            doc.add_paragraph(f"Done when: {res['done_when']}")
            doc.add_paragraph("Steps written by AI (" + (res["model"] or "Gemini") + "), checked against the evidence."
                              if res["source"] == "ai" else "Standard steps (AI not available).").runs[0].italic = True
    else:
        doc.add_paragraph("No signs of attack found.")

    doc.add_heading("5. Findings in detail", 1)
    detailed = [t for t in d["threats"] if t["exposed"] or t["hits"] or t["rating"] in ("Critical", "High")][:15]
    fixes = for_threats(store)
    for t in detailed:
        doc.add_heading(("[TEST] " if t["is_test"] else "") + f"{t['rating']}: {t['title']}", 2)
        doc.add_paragraph(f"Source: {t['source']} · published {t['published_at'] or 'n/a'} · {t['url'] or ''}")
        doc.add_paragraph(t["summary"] or "")
        doc.add_paragraph(f"Why this rating: {t['why']}").runs[0].italic = True
        fs = d["by_threat"].get(t["threat_id"], [])
        if fs:
            rows = []
            for fi in fs:
                users = ", ".join(u["account"] for u in _j(fi["users"])[:3]) or "n/a"
                alerts = "; ".join(a["title"] for a in _j(fi["alerts"])[:2]) or "none"
                rows.append([fi["kind"].replace("_", " "), fi["device_name"], fi["opco"], fi["detail"][:200], users, alerts])
            _table(doc, ["Type", "Device", "OpCo", "Detail", "Recent users", "Related Defender alerts"], rows)
            for fi in fs:
                timeline = _j(fi["timeline"])
                if timeline:
                    doc.add_paragraph(f"Timeline on {fi['device_name']}:").runs[0].bold = True
                    for ev in timeline[:12]:
                        doc.add_paragraph(f"{ev['time']}  {ev['what'][:300]}", style="List Bullet")
        fix = fixes.get(t["threat_id"]) if t["exposed"] else None
        actions = _j(t["actions"])
        if fix:
            doc.add_paragraph("How to fix it on our computers:").runs[0].bold = True
            for step in fix["steps"]:
                doc.add_paragraph(step, style="List Number")
            doc.add_paragraph(f"Done when: {fix['done_when']}")
            doc.add_paragraph("Steps written by AI (" + (fix["model"] or "Gemini") + "), checked against the data."
                              if fix["source"] == "ai" else "Standard steps from Defender's recommended updates (AI not available).").runs[0].italic = True
        elif actions:
            doc.add_paragraph("Recommended actions:").runs[0].bold = True
            for a in actions:
                doc.add_paragraph(a, style="List Bullet")
        techs = _j(t["techniques"])
        if techs:
            doc.add_paragraph("ATT&CK: " + ", ".join(x["id"] for x in techs))

    doc.add_heading("6. Hunts performed this cycle", 1)
    if d["hunts"]:
        _table(doc, ["Hunt", "Made by", "Technique", "Status", "Rows"],
               [[h["name"], "AI (validated)" if h["origin"] == "ai" else "template", h["technique"] or "",
                 h["status"] + (f": {h['error'][:80]}" if h["error"] else ""), h["row_count"]] for h in d["hunts"]])
    else:
        doc.add_paragraph("No hunts ran in this cycle (Defender not configured or unavailable).")

    doc.add_heading("7. Impacted assets", 1)
    rows = []
    for dev in d["devices"]:
        mine = [fi for fi in d["findings"] if fi["device_id"] == dev["device_id"]]
        users = {u["account"] for fi in mine for u in _j(fi["users"])}
        rows.append([dev["device_name"], dev["opco"], dev["os_platform"],
                     sum(fi["kind"] == "exposure" for fi in mine), sum(fi["kind"] != "exposure" for fi in mine),
                     ", ".join(sorted(users)[:4]) or "n/a"])
    _table(doc, ["Device", "OpCo", "OS", "Threats exposed to", "Hunt hits", "Recent users"], rows)

    doc.add_heading("8. MITRE ATT&CK mapping", 1)
    if d["techniques"]:
        _table(doc, ["Technique", "Name", "Tactic", "Threats"],
               [[t["technique_id"], t["name"], t["tactics"], t["threats"]] for t in d["techniques"]])

    doc.add_heading("9. Indicators of compromise (defanged)", 1)
    doc.add_paragraph("Indicators are written in a safe form (hxxp, [.]) so they can't be clicked by accident.")
    if d["iocs"]:
        _table(doc, ["Type", "Indicator", "Malware / source", "Found on our devices?"],
               [[i["ioc_type"], defang(i["value"])[:100], f"{i['malware']} ({i['source']})",
                 "YES" if i["value"] in d["hit_iocs"] else "no"] for i in d["iocs"]])

    doc.add_heading("Appendix A: queries run", 1)
    for h in d["hunts"]:
        doc.add_paragraph(h["name"]).runs[0].bold = True
        q = doc.add_paragraph()
        run = q.add_run((h["query"] or "")[:3000])
        run.font.name = "Consolas"
        run.font.size = Pt(7.5)

    doc.add_heading("Appendix B: how this report was produced", 1)
    for line in [
        "Threats come from free public feeds: CISA KEV, NVD, FIRST EPSS, MITRE ATT&CK, NCSC-NL, CERT-EU, Microsoft MSRC, "
        "abuse.ch and (optionally) AlienVault OTX.",
        "Our environment is the UC1 lab in Microsoft Defender for Endpoint (trial), not a client environment.",
        "Risk ratings come from fixed rules (config/risk_policy.csv). The AI (Google Gemini) writes summaries and drafts "
        "extra hunt queries; its output is checked against the sources, and AI-drafted queries are validated before running.",
        "Items marked [TEST] are harmless lab tests created on purpose to prove detection end-to-end.",
        "Limits: 2 lab devices; Sentinel not included; free feeds only.",
    ]:
        doc.add_paragraph(line, style="List Bullet")

    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%d_%H%M")
    docx_path = settings.reports_dir / f"UC1_Threat_Hunting_Report_{stamp}.docx"
    doc.save(docx_path)
    pdf_path = to_pdf(docx_path)
    report_id = f"report:{stamp}"
    store.upsert("reports", [{"report_id": report_id, "run_id": run_id, "docx_path": str(docx_path),
                              "pdf_path": str(pdf_path) if pdf_path else None, "threat_count": len(d["threats"]),
                              "created_at": now}])
    return {"docx": str(docx_path), "pdf": str(pdf_path) if pdf_path else None, "summary_source": summary_source}


def to_pdf(docx_path: Path) -> Path | None:
    soffice = next((p for p in SOFFICE if p.is_file()), None) or (shutil.which("soffice") and Path(shutil.which("soffice")))
    if not soffice:
        log.warning("LibreOffice not found: PDF skipped (the Word file is ready)")
        return None
    with tempfile.TemporaryDirectory() as profile:
        cmd = [str(soffice), f"-env:UserInstallation={Path(profile).as_uri()}", "--headless", "--convert-to", "pdf",
               "--outdir", str(docx_path.parent), str(docx_path)]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=240)
        except (subprocess.SubprocessError, OSError) as exc:
            log.warning("PDF conversion failed: %s", exc)
            return None
    pdf = docx_path.with_suffix(".pdf")
    return pdf if pdf.is_file() else None
