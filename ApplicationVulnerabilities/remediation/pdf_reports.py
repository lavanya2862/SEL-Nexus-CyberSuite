"""PDF documents for people: the run report, the findings and the fixes.

They are built on request from a run's report.json and findings.json, so every run (old ones too) gets them and
nothing binary is stored. Machine-readable files (SARIF, patch, JSON) stay as they are.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (CondPageBreak, Flowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from .models import SEVERITIES, Finding, FixRecord, RemediationReport

PDF_NAMES = ("report.pdf", "findings.pdf", "fixes.pdf")

NAVY = colors.HexColor("#0f1b2d")
SKY = colors.HexColor("#0369a1")
INK = colors.HexColor("#1f2937")
INK_3 = colors.HexColor("#6b7280")
BORDER = colors.HexColor("#d7dde5")
WELL = colors.HexColor("#f3f6f9")
HEAD = colors.HexColor("#e6edf4")
SEV_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d4ed8", "info": "#6b7280",
             "unknown": "#6b7280"}
STATUS_COLOR = {"passed": "#15803d", "completed": "#15803d", "ok": "#15803d", "applied": "#15803d",
                "fixed": "#15803d", "verified": "#15803d", "pr_opened": "#15803d",
                "flagged": "#b45309", "warning": "#b45309", "awaiting_approval": "#b45309", "manual": "#b45309",
                "failed": "#b91c1c", "reverted": "#b91c1c"}
VERDICT = {"passed": "PASSED", "flagged": "FLAGGED FOR INVESTIGATION", "failed": "FAILED",
           "not_run": "NOT RUN (no fixes)"}
METHOD = {"dependency": "Dependency upgrade", "rule": "Deterministic rewrite", "llm": "AI patch"}

PAGE_W, PAGE_H = A4
MARGIN = 16 * mm
WIDTH = PAGE_W - 2 * MARGIN
MAX_FINDING_ROWS = 300
MAX_DIFF_LINES = 400

_TEXT = {"→": "->", "←": "<-", "⇒": "=>", "≥": ">=", "≤": "<=", "✅": "", "⚠️": "", "⚠": "", "❌": "", "✓": "",
         "️": "", "\t": "    ", "\r": ""}


def _clean(value) -> str:
    """Text the built-in PDF fonts can draw (Windows-1252); anything else becomes '?'."""
    text = str(value if value is not None else "")
    for a, b in _TEXT.items():
        text = text.replace(a, b)
    return text.encode("cp1252", "replace").decode("cp1252")


def _x(value, limit: int | None = None) -> str:
    """Escaped one-line text for a Paragraph."""
    text = " ".join(_clean(value).split())
    if limit and len(text) > limit:
        text = text[:limit - 3] + "..."
    return escape(text)


def _style(name: str, **kw) -> ParagraphStyle:
    base = dict(fontName="Helvetica", fontSize=9, leading=12, textColor=INK)
    base.update(kw)
    return ParagraphStyle(name, **base)


S = {
    "title": _style("title", fontName="Helvetica-Bold", fontSize=20, leading=25, textColor=NAVY),
    "subtitle": _style("subtitle", fontSize=11, leading=15, textColor=INK_3),
    "h2": _style("h2", fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=NAVY, spaceBefore=12,
                 spaceAfter=6),
    "h3": _style("h3", fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK, spaceBefore=4,
                 spaceAfter=3),
    "body": _style("body"),
    "small": _style("small", fontSize=8, leading=10.5, textColor=INK_3),
    "th": _style("th", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=NAVY),
    "td": _style("td", fontSize=8, leading=10.5),
    "tdr": _style("tdr", fontSize=8, leading=10.5, alignment=TA_RIGHT),
    "key": _style("key", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=INK_3),
    "tile_v": _style("tile_v", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY),
    "tile_l": _style("tile_l", fontSize=7.5, leading=10, textColor=INK_3),
    "code": _style("code", fontName="Courier", fontSize=7.2, leading=9, wordWrap="CJK"),
}


def _p(text, style: str = "td", limit: int | None = None) -> Paragraph:
    return Paragraph(_x(text, limit), S[style])


def _colored(text: str, color: str, bold: bool = True, style: str = "td") -> Paragraph:
    inner = f"<b>{_x(text)}</b>" if bold else _x(text)
    return Paragraph(f'<font color="{color}">{inner}</font>', S[style])


def _sev(severity: str) -> Paragraph:
    return _colored((severity or "unknown").upper(), SEV_COLOR.get(severity, "#6b7280"))


def _status(status: str | None) -> Paragraph:
    text = (status or "-").replace("_", " ")
    return _colored(text, STATUS_COLOR.get(status or "", "#374151"), bold=status in STATUS_COLOR)


def _table(head: list[str], rows: list[list], widths: list[float], right: tuple[int, ...] = ()) -> Table:
    data = [[_p(h, "th") for h in head]]
    for row in rows:
        data.append([c if isinstance(c, Flowable) else _p("-" if c is None else c, "tdr" if i in right else "td")
                     for i, c in enumerate(row)])
    table = Table(data, colWidths=[w * WIDTH for w in widths], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEAD),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, WELL]),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _facts(pairs: list[tuple[str, object]]) -> Table:
    """Two-column key/value table."""
    data = [[_p(k, "key"), v if isinstance(v, Paragraph) else _p(v if v not in (None, "") else "-", "body")]
            for k, v in pairs]
    table = Table(data, colWidths=[0.24 * WIDTH, 0.76 * WIDTH])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return table


def _tiles(items: list[tuple[str, str, str | None]]) -> Table:
    """A row of headline numbers: (value, label, colour)."""
    cells = []
    for value, label, color in items:
        style = ParagraphStyle("tv", parent=S["tile_v"], textColor=colors.HexColor(color) if color else NAVY)
        cells.append([Paragraph(_x(value), style), _p(label, "tile_l")])
    gap = 4
    width = (WIDTH - gap * (len(items) - 1)) / len(items)
    inner = [Table([[c[0]], [c[1]]], colWidths=[width - 14]) for c in cells]
    for t in inner:
        t.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 0),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
    row, widths = [], []
    for i, t in enumerate(inner):
        if i:
            row.append("")
            widths.append(gap)
        row.append(t)
        widths.append(width)
    table = Table([row], colWidths=widths)
    cmds = [("VALIGN", (0, 0), (-1, -1), "TOP")]
    for i in range(0, len(row), 2):
        cmds += [("BACKGROUND", (i, 0), (i, 0), WELL), ("BOX", (i, 0), (i, 0), 0.5, BORDER),
                 ("LEFTPADDING", (i, 0), (i, 0), 7), ("TOPPADDING", (i, 0), (i, 0), 6),
                 ("BOTTOMPADDING", (i, 0), (i, 0), 6)]
    table.setStyle(TableStyle(cmds))
    return table


def _code(text: str, start_line: int | None = None, diff: bool = False, max_lines: int = MAX_DIFF_LINES) -> Table:
    """A code or diff box; long lines wrap, + and - lines are coloured in diffs."""
    lines = _clean(text).rstrip("\n").split("\n")
    extra = len(lines) - max_lines
    lines = lines[:max_lines]
    rows, cmds = [], []
    for i, line in enumerate(lines):
        shown = escape(line).replace(" ", "&nbsp;") or "&nbsp;"
        if start_line is not None:
            shown = f'<font color="#9ca3af">{start_line + i:>5}&nbsp;&nbsp;</font>' + shown
        rows.append([Paragraph(shown, S["code"])])
        if diff and line.startswith("+") and not line.startswith("+++"):
            cmds.append(("BACKGROUND", (0, i), (0, i), colors.HexColor("#e7f6ec")))
        elif diff and line.startswith("-") and not line.startswith("---"):
            cmds.append(("BACKGROUND", (0, i), (0, i), colors.HexColor("#fdecec")))
        elif diff and line.startswith("@@"):
            cmds.append(("TEXTCOLOR", (0, i), (0, i), SKY))
    if extra > 0:
        rows.append([_p(f"... {extra} more line(s) not shown; the full change is in fixes.patch.", "small")])
    table = Table(rows or [[_p("(empty)", "small")]], colWidths=[WIDTH])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), WELL), ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                               ("TOPPADDING", (0, 0), (-1, -1), 0.6), ("BOTTOMPADDING", (0, 0), (-1, -1), 0.6),
                               ("LEFTPADDING", (0, 0), (-1, -1), 6)] + cmds))
    return table


def _canvas(doc_title: str, run_id: str):
    """Canvas that draws the header and the 'Page n of N' footer once the page count is known."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    class NumberedCanvas(pdfcanvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages: list[dict] = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._chrome(total)
                super().showPage()
            super().save()

        def _chrome(self, total: int) -> None:
            self.saveState()
            self.setFillColor(NAVY)
            self.rect(0, PAGE_H - 11 * mm, PAGE_W, 11 * mm, stroke=0, fill=1)
            self.setFillColor(colors.white)
            self.setFont("Helvetica-Bold", 8.5)
            self.drawString(MARGIN, PAGE_H - 7 * mm, "SEL Nexus CyberSuite")
            self.setFont("Helvetica", 8.5)
            self.drawString(MARGIN + 33 * mm, PAGE_H - 7 * mm, "Application Vulnerabilities")
            self.drawRightString(PAGE_W - MARGIN, PAGE_H - 7 * mm, _clean(doc_title))
            self.setStrokeColor(BORDER)
            self.line(MARGIN, 12 * mm, PAGE_W - MARGIN, 12 * mm)
            self.setFillColor(INK_3)
            self.setFont("Helvetica", 7.5)
            self.drawString(MARGIN, 8 * mm, _clean(f"Run {run_id[:12]} - generated {generated}"))
            self.drawRightString(PAGE_W - MARGIN, 8 * mm,
                                 f"Confidential, for internal security review - Page {self._pageNumber} of {total}")
            self.restoreState()

    return NumberedCanvas


def _build(doc_title: str, report: RemediationReport, story: list) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=19 * mm,
                            bottomMargin=17 * mm, title=_clean(f"{doc_title} - {report.repo}"),
                            author="SEL Nexus CyberSuite", subject="Application Vulnerabilities")
    doc.build(story, canvasmaker=_canvas(doc_title, report.run_id))
    return buf.getvalue()


def _cover(title: str, report: RemediationReport, subtitle: str) -> list:
    return [Paragraph(_x(title), S["title"]), Spacer(1, 2),
            Paragraph(f"{_x(report.repo)} &nbsp;&middot;&nbsp; {_x(subtitle)}", S["subtitle"]), Spacer(1, 10)]


def _run_facts(report: RemediationReport) -> Table:
    langs = ", ".join(f"{k} ({v})" for k, v in list(report.languages.items())[:6]) or "n/a"
    pr = report.pull_request_url
    return _facts([
        ("Repository", report.repo_url or report.repo),
        ("Ref / commit", f"{report.ref or 'default'} @ {(report.commit or '')[:12] or '-'}"),
        ("Run", f"{report.run_id} - {report.duration_seconds:.0f}s"),
        ("Finished", (report.finished_at or "-")[:19].replace("T", " ") + (" UTC" if report.finished_at else "")),
        ("Fix branch", report.branch or "not created"),
        ("Pull request", f"{'Draft: ' if report.pull_request_draft else ''}{pr}" if pr
         else report.approval_status.replace("_", " ")),
        ("Languages", langs),
        ("AI remediation", f"enabled ({report.llm_model})" if report.llm_enabled and report.llm_model
         else "enabled" if report.llm_enabled else "disabled (deterministic fixes only)"),
    ])


def _verdict_color(status: str) -> str:
    return {"passed": "#15803d", "flagged": "#b45309", "failed": "#b91c1c"}.get(status, "#374151")


def _severity_table(counts: dict[str, int]) -> Table | Paragraph:
    present = [s for s in SEVERITIES if counts.get(s)]
    if not present:
        return _p("No findings.", "body")
    return _table([s.capitalize() for s in present], [[str(counts[s]) for s in present]],
                  [1 / len(present)] * len(present))


def _location(f: Finding) -> str:
    if not f.file_path:
        return "-"
    return f"{f.file_path}{':' + str(f.line) if f.line else ''}"


def _finding_title(f: Finding) -> str:
    if f.is_dependency:
        return (f"{f.title} - {f.package_name}@{f.installed_version} "
                + (f"-> {f.fixed_version}" if f.fixed_version else "(no fix)"))
    return f.title


def _closing() -> list:
    return [Spacer(1, 14), _p("Automated changes must be reviewed by a person before merging. Rotate any credential "
                              "reported as exposed: removing it from the code is not enough.", "small")]


# --- report.pdf ---------------------------------------------------------------------------------------------------

def render_report_pdf(report: RemediationReport, findings: list[Finding]) -> bytes:
    story = _cover("Security remediation report", report, "Application Vulnerabilities pipeline run")
    verdict = VERDICT.get(report.validation_status, report.validation_status)
    story += [_tiles([(str(report.findings_input), "Findings", None),
                      (str(report.patches_applied), "Fixes applied", None),
                      (str(report.verified_fixed), "Confirmed fixed by rescan", None),
                      (verdict.split(" ")[0], "Validation", _verdict_color(report.validation_status))]),
              Spacer(1, 10), Paragraph("Run details", S["h2"]), _run_facts(report)]

    story += [Paragraph("Summary", S["h2"]),
              _p(f"{report.findings_input} findings in total, {report.findings_selected} at or above the threshold. "
                 f"{report.patches_applied} fix(es) applied out of {report.patches_proposed} attempted; "
                 f"{report.verified_fixed} finding(s) confirmed resolved by the security rescan. "
                 f"Final validation status: {verdict}. Approval: {report.approval_status.replace('_', ' ')}.", "body"),
              Spacer(1, 6), _severity_table(report.severity_counts)]

    story += [Paragraph("Pipeline", S["h2"]),
              _table(["Stage", "Component", "Status", "Duration", "Result"],
                     [[st.name, st.agent or "-", _status(st.status),
                       f"{st.duration_seconds:.1f}s" if st.duration_seconds is not None else "-", _p(st.summary, limit=220)]
                      for st in report.stages], [0.2, 0.2, 0.11, 0.1, 0.39], right=(3,))]

    if report.scanners:
        story += [Paragraph("Scanners", S["h2"]),
                  _table(["Scanner", "Status", "Findings", "Time", "Notes"],
                         [[r.name, _status(r.status), str(r.findings), f"{r.duration_seconds:.1f}s",
                           _p(r.message, limit=200)] for r in report.scanners],
                         [0.18, 0.12, 0.1, 0.1, 0.5], right=(2, 3))]

    story += [CondPageBreak(60 * mm), Paragraph("Fixes", S["h2"])]
    if report.fixes:
        story.append(_table(["#", "Method", "Change", "Risk", "Rescan", "Validation", "Status"],
                            [[str(i), METHOD.get(fx.method, fx.method), _p(fx.summary, limit=200), fx.risk,
                              {True: "resolved", False: "still reported", None: "-"}[fx.verified],
                              _status(fx.validation_status), _status(fx.status)]
                             for i, fx in enumerate(report.fixes, 1)],
                            [0.05, 0.15, 0.36, 0.08, 0.12, 0.12, 0.12], right=(0,)))
        story.append(Spacer(1, 4))
        story.append(_p("Each fix, with its explanation and code changes, is in fixes.pdf.", "small"))
    else:
        story.append(_p("No automatic fixes were applied.", "body"))

    if report.validation_checks:
        story += [Paragraph("Validation checks", S["h2"]),
                  _table(["Check", "Category", "Fix", "Status", "Detail"],
                         [[c.name, c.category, "" if c.fix_index is None else str(c.fix_index + 1), _status(c.status),
                           _p(c.detail, limit=260)] for c in report.validation_checks],
                         [0.22, 0.18, 0.05, 0.1, 0.45], right=(2,))]

    story += [CondPageBreak(60 * mm), Paragraph("Findings", S["h2"])]
    if findings:
        shown = findings[:MAX_FINDING_ROWS]
        story.append(_table(["Severity", "Title", "Location", "Scanner", "Fix"],
                            [[_sev(f.severity), _p(_finding_title(f), limit=180), _p(_location(f), limit=90),
                              ", ".join([f.scanner, *f.also_reported_by]), _status(f.fix_status)] for f in shown],
                            [0.11, 0.4, 0.24, 0.13, 0.12]))
        story.append(Spacer(1, 4))
        more = f"{len(findings) - len(shown)} more findings are not listed here. " if len(findings) > len(shown) else ""
        story.append(_p(more + "Every finding, with its description, code and references, is in findings.pdf.", "small"))
    else:
        story.append(_p("No findings.", "body"))

    failed = [v for v in report.validation if not v.passed and not v.skipped]
    if report.validation:
        story += [Paragraph("Validation commands", S["h2"]),
                  _table(["Check", "Command", "Exit code", "Result"],
                         [[v.name, _p(v.command, limit=160), str(v.exit_code),
                           _status("skipped" if v.skipped else "passed" if v.passed else "failed")]
                          for v in report.validation], [0.22, 0.52, 0.1, 0.16], right=(2,))]
        for v in failed:
            tail = (v.stderr or v.stdout or "")[-2500:]
            if tail:
                story += [Paragraph(f"{_x(v.name)}: output", S["h3"]), _code(tail, max_lines=60)]

    if report.notes:
        story += [Paragraph("Notes", S["h2"])] + [_p(f"- {n}", "body") for n in report.notes]
    story += _closing()
    return _build("Security remediation report", report, story)


# --- findings.pdf -------------------------------------------------------------------------------------------------

def render_findings_pdf(report: RemediationReport, findings: list[Finding]) -> bytes:
    story = _cover("Findings", report, f"{len(findings)} security finding(s), highest risk first")
    story += [_severity_table(report.severity_counts or {s: sum(f.severity == s for f in findings)
                                                        for s in SEVERITIES}), Spacer(1, 6)]
    if not findings:
        story.append(_p("The scanners reported no security findings for this run.", "body"))
    shown = findings[:MAX_FINDING_ROWS]
    for n, f in enumerate(shown, 1):
        facts = [("Severity", _sev(f.severity)), ("Location", _location(f)),
                 ("Reported by", ", ".join([f.scanner, *f.also_reported_by])),
                 ("Rule / advisory", " / ".join(x for x in (f.rule_id, f.advisory_id) if x) or "-")]
        if f.cwe:
            facts.append(("CWE", ", ".join(f"CWE-{c}" for c in f.cwe)))
        if f.is_dependency:
            facts.append(("Package", f"{f.package_name}@{f.installed_version} ({f.ecosystem or 'unknown'})"))
            facts.append(("Fixed in", f.fixed_version or "no fixed version published"))
        if f.priority_rank:
            facts.append(("Priority", f"#{f.priority_rank} (score {f.priority_score:.1f})"))
        facts.append(("Fix status", _status(f.fix_status)))
        if f.fix_note:
            facts.append(("Fix note", _p(f.fix_note, "body", limit=600)))
        head = [Paragraph(f'<font color="{SEV_COLOR.get(f.severity, "#6b7280")}">{n}.</font> {_x(f.title, 200)}',
                          S["h3"]), _facts(facts)]
        block: list = [KeepTogether(head)]
        if f.description and f.description.strip() != f.title.strip():
            block += [Spacer(1, 4), _p(f.description, "body", limit=1500)]
        if f.priority_reasons:
            block += [Spacer(1, 3), _p("Why it ranks here: " + "; ".join(f.priority_reasons), "small", limit=600)]
        code, start = (f.code_context, f.context_start_line) if f.code_context else (f.snippet, f.line)
        if code:
            block += [Spacer(1, 4), _code(code, start_line=start, max_lines=40)]
        if f.references:
            block += [Spacer(1, 3), _p("References: " + "  ".join(f.references[:5]), "small", limit=700)]
        story += block + [Spacer(1, 10)]
    if len(findings) > len(shown):
        story.append(_p(f"{len(findings) - len(shown)} lower-priority findings are not shown. "
                        "Every finding is in findings.json and findings.sarif.", "small"))
    story += _closing()
    return _build("Findings", report, story)


# --- fixes.pdf ----------------------------------------------------------------------------------------------------

def render_fixes_pdf(report: RemediationReport, findings: list[Finding]) -> bytes:
    by_id = {f.finding_id: f for f in findings}
    applied = [fx for fx in report.fixes if fx.status == "applied"]
    story = _cover("Fixes", report, f"{len(applied)} applied fix(es) for review")
    story += [_tiles([(str(len(applied)), "Fixes applied", None),
                      (str(sum(fx.method == "llm" for fx in report.fixes)), "AI patches", None),
                      (str(sum(fx.verified is True for fx in report.fixes)), "Confirmed fixed by rescan", None),
                      (VERDICT.get(report.validation_status, report.validation_status).split(" ")[0], "Validation",
                       _verdict_color(report.validation_status))]),
              Spacer(1, 8),
              _facts([("Fix branch", report.branch or "not created"),
                      ("Pull request", report.pull_request_url or report.approval_status.replace("_", " "))])]
    if not report.fixes:
        story += [Spacer(1, 8), _p("No automatic fixes were made in this run.", "body")]
    checks = {}
    for c in report.validation_checks:
        if c.fix_index is not None:
            checks.setdefault(c.fix_index, []).append(c)
    for i, fx in enumerate(report.fixes, 1):
        story += _fix_block(i, fx, by_id, checks.get(i - 1, []))
    story += _closing()
    return _build("Fixes", report, story)


def _fix_block(i: int, fx: FixRecord, by_id: dict[str, Finding], checks: list) -> list:
    fixed = [by_id[x] for x in fx.finding_ids if x in by_id]
    facts = [("Method", METHOD.get(fx.method, fx.method)), ("Status", _status(fx.status)),
             ("Risk", fx.risk), ("Rescan", {True: "finding no longer reported", False: "finding still reported",
                                            None: "not checked"}[fx.verified]),
             ("Validation", _status(fx.validation_status)), ("Files", ", ".join(fx.files) or "-"),
             ("Commit", (fx.commit or "-")[:12])]
    if fixed:
        facts.append(("Fixes", _p("; ".join(f"[{f.severity}] {_finding_title(f)}" for f in fixed), "body", limit=800)))
    story = [CondPageBreak(50 * mm),
             KeepTogether([Paragraph(f"Fix {i}: {_x(fx.summary, 200)}", S["h2"]), _facts(facts)])]
    why = fx.explanation or fx.detail
    if why:
        story += [Paragraph("What changed and why", S["h3"]), _p(why, "body", limit=2000)]
    if checks:
        story += [Spacer(1, 4), _table(["Check", "Status", "Detail"],
                                       [[c.name, _status(c.status), _p(c.detail, limit=240)] for c in checks],
                                       [0.3, 0.12, 0.58])]
    if fx.diff:
        story += [Paragraph("Code changes", S["h3"]), _code(fx.diff, diff=True)]
    return story + [Spacer(1, 8)]


RENDERERS = {"report.pdf": render_report_pdf, "findings.pdf": render_findings_pdf, "fixes.pdf": render_fixes_pdf}


def render_pdf(name: str, report: RemediationReport, findings: list[Finding]) -> bytes:
    return RENDERERS[name](report, findings)
