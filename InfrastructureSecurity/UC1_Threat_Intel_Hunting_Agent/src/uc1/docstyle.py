"""The suite's report look for Word and PDF: cover band, number tiles, charts, styled tables and AI fix-guide boxes.

The same file sits in every agent (uc1, uc3, uc4) so the agents stay independent and their reports look alike.
Charts are drawn with matplotlib (PNG); the PDF is the Word file saved as PDF by Microsoft Word on this computer
(skipped, with the Word file still ready, when no converter is installed).
"""

from __future__ import annotations

import io
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from docx import Document  # noqa: E402
from docx.enum.section import WD_ORIENT  # noqa: E402
from docx.enum.table import WD_TABLE_ALIGNMENT  # noqa: E402
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK  # noqa: E402
from docx.oxml import OxmlElement  # noqa: E402
from docx.oxml.ns import qn  # noqa: E402
from docx.shared import Cm, Pt, RGBColor  # noqa: E402

log = logging.getLogger(__name__)

# Colours match the portal (theme.tsx statusColor and the electric-blue brand)
NAVY, BLUE, INK, INK_2, INK_3 = "0E1631", "1D5CFF", "121212", "475467", "667085"
HAIRLINE, WELL, ZEBRA = "D0D5DD", "F2F4F7", "F8F9FB"
GOOD, WARN, SERIOUS, BAD = "0CA30C", "FAB219", "EC835A", "D03B3B"
SEVERITY = {"Critical": BAD, "High": SERIOUS, "Medium": WARN, "Low": "16A34A", "Unrated": "98A2B3"}
SERIES = ["1D5CFF", "F97316", "22C55E", "8B5CF6", "FACC15", "F43F5E", "06B6D4", "98A2B3"]
DARK_TEXT_ON = {WARN, "FACC15", "22C55E"}       # fills that need black text, not white

SOFFICE = [Path(r"C:\Program Files\LibreOffice\program\soffice.exe"),
           Path(r"C:\Program Files (x86)\LibreOffice\program\soffice.exe")]


def clean(text) -> str:
    """Report text without internal project names ("the next UC3 run" -> "the next run")."""
    return re.sub(r"\bUC\d\b[ /]?", "", str(text or "")).replace("  ", " ").strip()


def _rgb(hex_colour: str) -> RGBColor:
    return RGBColor.from_string(hex_colour.upper())


# ---------------------------------------------------------------- low-level cell styling
def shade(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    for old in tc_pr.findall(qn("w:shd")):
        tc_pr.remove(old)
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def borders(cell, **sides) -> None:
    """borders(cell, top=("single", 18, "1D5CFF"), left=None, ...): None removes that side."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_borders = tc_pr.find(qn("w:tcBorders"))
    if tc_borders is None:
        tc_borders = OxmlElement("w:tcBorders")
        tc_pr.append(tc_borders)
    for side in ("top", "left", "bottom", "right"):
        if side not in sides:
            continue
        el = OxmlElement(f"w:{side}")
        spec = sides[side]
        if spec is None:
            el.set(qn("w:val"), "nil")
        else:
            val, size, colour = spec
            el.set(qn("w:val"), val)
            el.set(qn("w:sz"), str(size))
            el.set(qn("w:color"), colour)
        tc_borders.append(el)


def cell_margins(cell, top=60, bottom=60, left=100, right=100) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for side, value in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:w"), str(value))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    tc_pr.append(mar)


def _no_table_borders(table) -> None:
    tbl_pr = table._tbl.tblPr
    tb = OxmlElement("w:tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "nil")
        tb.append(el)
    tbl_pr.append(tb)


def _fixed_widths(table, widths_cm: list[float]) -> None:
    """Column widths every PDF converter respects: fixed layout + the grid columns, not only each cell."""
    table.autofit = False
    tbl_pr = table._tbl.tblPr
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tbl_pr.append(layout)
    for col, w in zip(table.columns, widths_cm):
        col.width = Cm(w)
    for row in table.rows:
        for cell, w in zip(row.cells, widths_cm):
            cell.width = Cm(w)


def _repeat_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader")
    el.set(qn("w:val"), "true")
    tr_pr.append(el)


def _no_split(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tr_pr.append(OxmlElement("w:cantSplit"))


def _write(cell, text, size=9.0, bold=False, colour=INK, italic=False, font=None, align=None) -> None:
    cell.text = ""
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    if align:
        p.alignment = align
    run = p.add_run("" if text is None else str(text))
    run.font.size, run.bold, run.italic = Pt(size), bold, italic
    run.font.color.rgb = _rgb(colour)
    if font:
        run.font.name = font


def _add_field(paragraph, code: str) -> None:
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), code)
    r = OxmlElement("w:r")
    t = OxmlElement("w:t")
    t.text = "1"
    r.append(t)
    fld.append(r)
    paragraph._p.append(fld)


# ---------------------------------------------------------------- charts (PNG bytes)
def _fig(width=6.4, height=3.0):
    fig, ax = plt.subplots(figsize=(width, height), dpi=200)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#" + HAIRLINE)
    ax.tick_params(colors="#" + INK_2, labelsize=8)
    return fig, ax


def _png(fig) -> bytes:
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png", facecolor="white", bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)
    return buf.getvalue()


def donut(labels: list[str], values: list[float], colours: list[str] | None = None, centre: str = "",
          title: str = "") -> bytes:
    fig, ax = plt.subplots(figsize=(3.6, 2.4), dpi=200)
    pairs = [(lab, v, c) for lab, v, c in zip(labels, values, colours or SERIES * 4) if v]
    if not pairs:
        pairs = [("none", 1, HAIRLINE)]
    ax.pie([p[1] for p in pairs], colors=["#" + p[2] for p in pairs], startangle=90, counterclock=False,
           wedgeprops={"width": 0.34, "edgecolor": "white", "linewidth": 2})
    ax.text(0, 0.06, centre, ha="center", va="center", fontsize=15, fontweight="bold", color="#" + INK)
    if title:
        ax.text(0, -0.2, title, ha="center", va="center", fontsize=7.5, color="#" + INK_3)
    ax.legend([f"{p[0]}  {p[1]:,.0f}" for p in pairs], loc="center left", bbox_to_anchor=(1.0, 0.5), frameon=False,
              fontsize=7.5, labelcolor="#" + INK_2)
    ax.set_aspect("equal")
    return _png(fig)


def hbar(labels: list[str], values: list[float], colour: str | list[str] = BLUE, title: str = "",
         width=6.4) -> bytes:
    labels, values = labels[::-1], values[::-1]
    colours = colour[::-1] if isinstance(colour, list) else [colour] * len(values)
    fig, ax = _fig(width, max(1.6, 0.32 * len(labels) + 0.7))
    bars = ax.barh(labels, values, color=["#" + c for c in colours], height=0.62)
    top = max(values or [1])
    for b, v in zip(bars, values):
        ax.text(b.get_width() + top * 0.01, b.get_y() + b.get_height() / 2, f"{v:,.0f}", va="center", fontsize=7.5,
                color="#" + INK_2)
    ax.set_xlim(0, top * 1.12)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    if title:
        ax.set_title(title, loc="left", fontsize=9, color="#" + INK, fontweight="bold")
    return _png(fig)


def stacked(categories: list[str], series: dict[str, list[float]], colours: dict[str, str] | None = None,
            title: str = "", horizontal: bool = False, width=6.4, height=2.8) -> bytes:
    fig, ax = _fig(width, height)
    base = [0.0] * len(categories)
    for name, values in series.items():
        c = "#" + ((colours or {}).get(name) or SERIES[list(series).index(name) % len(SERIES)])
        if horizontal:
            ax.barh(categories, values, left=base, color=c, label=name, height=0.6)
        else:
            ax.bar(categories, values, bottom=base, color=c, label=name, width=0.6)
        base = [b + v for b, v in zip(base, values)]
    ax.legend(frameon=False, fontsize=7.5, ncol=min(len(series), 5), loc="lower right", bbox_to_anchor=(1.0, 1.0),
              labelcolor="#" + INK_2)
    if not horizontal:
        ax.set_ylim(0, max(base or [1]) * 1.08)
    if title:
        ax.set_title(title, loc="left", fontsize=9, color="#" + INK, fontweight="bold")
    return _png(fig)


def line(x: list[str], series: dict[str, list[float]], colours: dict[str, str] | None = None, title: str = "",
         width=6.4, height=2.6) -> bytes:
    fig, ax = _fig(width, height)
    for name, values in series.items():
        c = "#" + ((colours or {}).get(name) or SERIES[list(series).index(name) % len(SERIES)])
        ax.plot(x, values, color=c, linewidth=1.8, marker="o", markersize=2.5, label=name)
    ax.legend(frameon=False, fontsize=7.5, ncol=min(len(series), 5), loc="upper left", labelcolor="#" + INK_2)
    step = max(1, len(x) // 8)
    ax.set_xticks(range(0, len(x), step))
    ax.set_xticklabels([x[i] for i in range(0, len(x), step)], fontsize=7)
    ax.grid(axis="y", color="#" + WELL)
    if title:
        ax.set_title(title, loc="left", fontsize=9, color="#" + INK, fontweight="bold")
    return _png(fig)


# ---------------------------------------------------------------- the document
class Report:
    """A Word report in the suite's look. Build it top to bottom, then save() (writes .docx and, if possible, .pdf)."""

    def __init__(self, title: str, agent: str, run_lines: list[str], landscape: bool = False):
        self.doc = Document()
        self.title, self.agent = title, agent
        sec = self.doc.sections[0]
        if landscape:
            sec.orientation = WD_ORIENT.LANDSCAPE
            sec.page_width, sec.page_height = sec.page_height, sec.page_width
        for side in ("left_margin", "right_margin"):
            setattr(sec, side, Cm(1.8))
        sec.top_margin, sec.bottom_margin = Cm(1.6), Cm(1.6)
        self.width_cm = (sec.page_width - sec.left_margin - sec.right_margin) / 360000
        normal = self.doc.styles["Normal"]
        normal.font.name, normal.font.size = "Calibri", Pt(10)
        normal.font.color.rgb = _rgb(INK)
        normal.element.rPr.rFonts.set(qn("w:eastAsia"), "Calibri")
        normal.paragraph_format.space_after = Pt(4)
        for name, size, colour in (("Heading 1", 15, NAVY), ("Heading 2", 12, NAVY), ("Heading 3", 10.5, INK)):
            st = self.doc.styles[name]
            st.font.name, st.font.size, st.font.bold = "Calibri", Pt(size), True
            st.font.color.rgb = _rgb(colour)
            st.paragraph_format.space_before = Pt(14 if name == "Heading 1" else 10)
            st.paragraph_format.space_after = Pt(4)
            st.paragraph_format.keep_with_next = True
        self._footer()
        self._cover(run_lines)

    def _footer(self) -> None:
        sec = self.doc.sections[0]
        p = sec.footer.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        r = p.add_run(f"{self.agent} · {self.title} · page ")
        r.font.size, r.font.color.rgb = Pt(7.5), _rgb(INK_3)
        _add_field(p, "PAGE")
        for run in p.runs:
            run.font.size = Pt(7.5)

    def _cover(self, run_lines: list[str]) -> None:
        t = self.doc.add_table(rows=1, cols=1)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        _no_table_borders(t)
        c = t.rows[0].cells[0]
        shade(c, NAVY)
        borders(c, top=("single", 36, BLUE))
        cell_margins(c, 260, 260, 320, 320)
        _write(c, self.agent.upper(), 8.5, True, "9DB4FF")
        p = c.add_paragraph()
        p.paragraph_format.space_before, p.paragraph_format.space_after = Pt(4), Pt(6)
        r = p.add_run(self.title)
        r.font.size, r.bold, r.font.color.rgb = Pt(22), True, _rgb("FFFFFF")
        for line_text in run_lines:
            p = c.add_paragraph()
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(line_text)
            r.font.size, r.font.color.rgb = Pt(9), _rgb("C7D2FE")
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # ---- text
    def h1(self, text: str) -> None:
        self.doc.add_heading(clean(text), 1)

    def h2(self, text: str) -> None:
        self.doc.add_heading(clean(text), 2)

    def h3(self, text: str) -> None:
        self.doc.add_heading(clean(text), 3)

    def para(self, text: str, bold=False, italic=False, colour=INK, size=10.0):
        p = self.doc.add_paragraph()
        r = p.add_run(clean(text))
        r.bold, r.italic, r.font.size, r.font.color.rgb = bold, italic, Pt(size), _rgb(colour)
        return p

    def note(self, text: str):
        return self.para(text, italic=True, colour=INK_3, size=8.5)

    def bullets(self, items, numbered=False) -> None:
        for item in items:
            p = self.doc.add_paragraph(clean(item), style="List Number" if numbered else "List Bullet")
            p.paragraph_format.space_after = Pt(1)

    def page_break(self) -> None:
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # ---- visuals
    def tiles(self, items: list[tuple]) -> None:
        """items: (value, label, hint, colour). One row of up to 6 tiles with a coloured top edge."""
        for start in range(0, len(items), 6):
            chunk = items[start:start + 6]
            t = self.doc.add_table(rows=1, cols=len(chunk))
            _no_table_borders(t)
            t.alignment = WD_TABLE_ALIGNMENT.CENTER
            _fixed_widths(t, [self.width_cm / len(chunk)] * len(chunk))
            for cell, (value, label, hint, colour) in zip(t.rows[0].cells, chunk):
                shade(cell, WELL)
                borders(cell, top=("single", 36, colour or BLUE), left=("single", 24, "FFFFFF"),
                        right=("single", 24, "FFFFFF"))
                cell_margins(cell, 140, 140, 140, 120)
                _write(cell, value, 18, True, INK)
                p = cell.add_paragraph()
                p.paragraph_format.space_after = Pt(0)
                r = p.add_run(label)
                r.bold, r.font.size, r.font.color.rgb = True, Pt(8.5), _rgb(INK)
                if hint:
                    p = cell.add_paragraph()
                    p.paragraph_format.space_after = Pt(0)
                    r = p.add_run(clean(hint))
                    r.font.size, r.font.color.rgb = Pt(7.5), _rgb(INK_3)
            self.doc.add_paragraph().paragraph_format.space_after = Pt(0)

    def image(self, png: bytes, width_cm: float | None = None) -> None:
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run().add_picture(io.BytesIO(png), width=Cm(width_cm or self.width_cm))

    def images_side_by_side(self, pngs: list[bytes]) -> None:
        t = self.doc.add_table(rows=1, cols=len(pngs))
        _no_table_borders(t)
        w = self.width_cm / len(pngs)
        _fixed_widths(t, [w] * len(pngs))
        for cell, png in zip(t.rows[0].cells, pngs):
            cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            cell.paragraphs[0].add_run().add_picture(io.BytesIO(png), width=Cm(w - 0.3))

    def table(self, headers: list[str], rows: list[list], widths: list[float] | None = None,
              severity_col: int | None = None, colour_cols: dict[int, dict[str, str]] | None = None,
              size: float = 8.0) -> None:
        """A styled table: navy header (repeats on each page), zebra rows; severity_col gets coloured pills."""
        if not rows:
            self.note("Nothing to show.")
            return
        t = self.doc.add_table(rows=1, cols=len(headers))
        _no_table_borders(t)
        widths = widths or [self.width_cm / len(headers)] * len(headers)
        scale = self.width_cm / sum(widths)
        widths = [w * scale for w in widths]
        colour_cols = dict(colour_cols or {})
        if severity_col is not None:
            colour_cols[severity_col] = SEVERITY
        for i, h in enumerate(headers):
            c = t.rows[0].cells[i]
            shade(c, NAVY)
            cell_margins(c, 70, 70, 90, 90)
            _write(c, h, size, True, "FFFFFF")
        _repeat_header(t.rows[0])
        for n, row in enumerate(rows):
            r = t.add_row()
            _no_split(r)
            for i, value in enumerate(row):
                c = r.cells[i]
                cell_margins(c, 50, 50, 90, 90)
                borders(c, bottom=("single", 4, HAIRLINE))
                if n % 2:
                    shade(c, ZEBRA)
                text = "" if value is None else clean(value)
                fill = colour_cols.get(i, {}).get(text) if i in colour_cols else None
                if fill:
                    shade(c, fill)
                    _write(c, text, size, True, INK if fill in DARK_TEXT_ON else "FFFFFF")
                else:
                    _write(c, text, size)
        _fixed_widths(t, widths)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(0)

    def card(self, title: str, meta: str, sections: list[tuple[str, object]], colour: str = BLUE,
             badge: str = "") -> None:
        """A boxed guide (an AI fix, a sign of attack, an incident): coloured left edge, title, meta line, sections.
        A section value can be text, a list (numbered steps) or ("code", text) for a command."""
        t = self.doc.add_table(rows=1, cols=1)
        _no_table_borders(t)
        _fixed_widths(t, [self.width_cm])
        _no_split(t.rows[0])                     # a guide stays on one page (longer ones still flow on)
        c = t.rows[0].cells[0]
        shade(c, "FFFFFF")
        borders(c, left=("single", 48, colour), top=("single", 4, HAIRLINE), bottom=("single", 4, HAIRLINE),
                right=("single", 4, HAIRLINE))
        cell_margins(c, 120, 140, 220, 160)
        p = c.paragraphs[0]
        p.paragraph_format.space_after = Pt(1)
        if badge:
            r = p.add_run(f" {badge} ")
            r.bold, r.font.size = True, Pt(7.5)
            r.font.color.rgb = _rgb(INK if colour in DARK_TEXT_ON else "FFFFFF")
            rpr = r._r.get_or_add_rPr()
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:fill"), colour)
            rpr.append(shd)
            p.add_run("  ")
        r = p.add_run(clean(title))
        r.bold, r.font.size, r.font.color.rgb = True, Pt(11), _rgb(NAVY)
        if meta:
            p = c.add_paragraph()
            p.paragraph_format.space_after = Pt(4)
            r = p.add_run(clean(meta))
            r.font.size, r.font.color.rgb = Pt(8), _rgb(INK_3)
        for label, value in sections:
            if value in (None, "", []):
                continue
            p = c.add_paragraph()
            p.paragraph_format.space_before, p.paragraph_format.space_after = Pt(3), Pt(1)
            r = p.add_run(label)
            r.bold, r.font.size, r.font.color.rgb = True, Pt(8.5), _rgb(INK_2)
            if isinstance(value, tuple) and value[0] == "code":
                p = c.add_paragraph()
                p.paragraph_format.space_after = Pt(1)
                r = p.add_run(str(value[1]))
                r.font.name, r.font.size = "Consolas", Pt(8)
                r.font.color.rgb = _rgb(NAVY)
                rpr = r._r.get_or_add_rPr()
                shd = OxmlElement("w:shd")
                shd.set(qn("w:val"), "clear")
                shd.set(qn("w:fill"), WELL)
                rpr.append(shd)
            elif isinstance(value, list):
                for n, step in enumerate(value, 1):
                    p = c.add_paragraph()
                    p.paragraph_format.space_after = Pt(0)
                    p.paragraph_format.left_indent = Cm(0.45)
                    p.paragraph_format.first_line_indent = Cm(-0.45)
                    r = p.add_run(f"{n}.  ")
                    r.bold, r.font.size, r.font.color.rgb = True, Pt(9), _rgb(colour if colour not in DARK_TEXT_ON else INK)
                    r = p.add_run(clean(step))
                    r.font.size = Pt(9)
            else:
                p = c.add_paragraph()
                p.paragraph_format.space_after = Pt(1)
                r = p.add_run(clean(value))
                r.font.size = Pt(9)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # ---- output
    def save(self, docx_path: Path) -> dict:
        docx_path.parent.mkdir(parents=True, exist_ok=True)
        self.doc.save(docx_path)
        pdf = to_pdf(docx_path)
        return {"docx": str(docx_path), "pdf": str(pdf) if pdf else None}


# Word opens the report read-only and exports it (17 = wdExportFormatPDF); paths come in through the environment
WORD_TO_PDF = r"""
$ErrorActionPreference = 'Stop'
$word = New-Object -ComObject Word.Application
try {
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $doc = $word.Documents.Open($env:REPORT_DOCX, $false, $true, $false)
    try { $doc.ExportAsFixedFormat($env:REPORT_PDF, 17) } finally { $doc.Close(0) }
} finally {
    $word.Quit()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($word)
}
"""


def _word_installed() -> bool:
    if sys.platform != "win32":
        return False
    import winreg
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"Word.Application\CLSID"))
        return True
    except OSError:
        return False


def _soffice() -> Path | None:
    return next((p for p in SOFFICE if p.is_file()), None) or (shutil.which("soffice") and Path(shutil.which("soffice")))


def pdf_converter() -> str | None:
    """What will turn the Word reports into PDF on this computer, or None (then only the Word file is made)."""
    return "Microsoft Word" if _word_installed() else "LibreOffice" if _soffice() else None


def _word_pdf(docx_path: Path, pdf: Path) -> None:
    env = {**os.environ, "REPORT_DOCX": str(docx_path.resolve()), "REPORT_PDF": str(pdf.resolve())}
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", WORD_TO_PDF],
                   env=env, check=True, capture_output=True, timeout=300,
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _soffice_pdf(docx_path: Path, soffice: Path) -> None:
    with tempfile.TemporaryDirectory() as profile:
        subprocess.run([str(soffice), f"-env:UserInstallation={Path(profile).as_uri()}", "--headless", "--convert-to",
                        "pdf", "--outdir", str(docx_path.parent), str(docx_path)], check=True, capture_output=True, timeout=300)


def to_pdf(docx_path: Path) -> Path | None:
    """Save the report as PDF next to it: Microsoft Word when installed, else LibreOffice; None if neither worked."""
    pdf = docx_path.with_suffix(".pdf")
    pdf.unlink(missing_ok=True)                 # an old PDF must never pass for this run's
    converters = ([("Microsoft Word", lambda: _word_pdf(docx_path, pdf))] if _word_installed() else []) + \
                 ([("LibreOffice", lambda s=_soffice(): _soffice_pdf(docx_path, s))] if _soffice() else [])
    if not converters:
        log.warning("PDF skipped: Microsoft Word is not installed on this computer (the Word file is ready)")
        return None
    for name, convert in converters:
        try:
            convert()
        except (subprocess.SubprocessError, OSError) as exc:
            detail = (getattr(exc, "stderr", b"") or b"").decode(errors="replace").strip().splitlines()
            log.warning("PDF conversion with %s failed: %s", name, detail[-1] if detail else exc)
        if pdf.is_file():
            return pdf
    return None
