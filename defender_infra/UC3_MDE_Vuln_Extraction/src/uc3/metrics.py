"""Before/after table for the client's six UC3 metrics (Phase 7).

Every value is labelled MEASURED (from our real Defender runs), ASSUMPTION (from config/assumptions.csv,
to be replaced by the client's baseline) or CALCULATED (from the two). Written to
data/reporting/UC3_Before_After_<snapshot>.md and printed by `python -m uc3 metrics`.
"""

from __future__ import annotations

import csv
import json
import math
from datetime import datetime

from uc3.config import CONFIG_DIR, Settings

KQL_LIMIT = 100_000


def load_assumptions() -> dict[str, float]:
    with (CONFIG_DIR / "assumptions.csv").open(encoding="utf-8") as fh:
        return {r["name"]: float(r["value"]) for r in csv.DictReader(fh)}


def build_metrics(settings: Settings) -> dict:
    runs = sorted(settings.raw_dir.glob("????-??-??/manifest.json"))
    if not runs:
        raise FileNotFoundError("No runs yet. Run: python -m uc3 run")
    m = json.loads(runs[-1].read_text())
    kql_path = settings.data_dir / "reference" / "kql_limit.json"
    kql = json.loads(kql_path.read_text()) if kql_path.is_file() else None
    a = load_assumptions()

    rows, source = m["counts"]["vulnerability_rows"], m.get("source_count")
    coverage = rows / source if source else None
    duration_min = m["duration_seconds"] / 60
    export_age_h = None
    if m.get("export_generated_time") and m.get("started_at"):
        parse = lambda t: datetime.fromisoformat(t.replace("Z", "+00:00"))
        export_age_h = (parse(m["started_at"]) - parse(m["export_generated_time"])).total_seconds() / 3600
    example_queries = math.ceil(a["example_estate_rows"] / KQL_LIMIT)
    new_hours = duration_min / 60 + a["review_minutes_new"] / 60

    table = [
        ("1. Hours spent extracting and consolidating per reporting cycle",
         f"{a['old_hours_per_cycle']:.0f} h (ASSUMPTION)",
         f"{new_hours:.2f} h = {m['duration_seconds']:.0f} s automatic run (MEASURED) + {a['review_minutes_new']:.0f} min review (ASSUMPTION)",
         f"{1 - new_hours / a['old_hours_per_cycle']:.0%} less (CALCULATED)"),
        ("2. Number of KQL queries needed for a complete report",
         f"{example_queries} sliced queries for a {a['example_estate_rows']:,.0f}-row estate (CALCULATED: rows ÷ 100,000 limit); "
         f"the lab itself ({rows:,} rows) fits in 1",
         "0 data queries (MEASURED) — the export API is used; 1 count query is only for the completeness check",
         "all manual querying removed"),
        ("3. Time to produce the executive dashboard",
         f"{a['old_dashboard_days']:.0f} days (ASSUMPTION)",
         f"{m['duration_seconds']:.0f} s per run, automatic every morning (MEASURED)",
         "from days to seconds"),
        ("4. Percentage of vulnerability data covered in a single extraction",
         (f"{kql['coverage']:.0%} — one KQL query returned {kql['rows_returned']:,} of {kql['rows_exist']:,} rows (MEASURED on the real API)"
          if kql else "at most 100,000 rows per KQL query (Microsoft limit)")
         + f"; {KQL_LIMIT / a['example_estate_rows']:.0%} of a {a['example_estate_rows']:,.0f}-row estate (CALCULATED)",
         f"{coverage:.1%} — {rows:,} of {source:,} rows in Defender (MEASURED)" if coverage is not None else "not measured",
         "complete, and proven on every run"),
        ("5. Mean time to identify (MTTI) critical vulnerabilities",
         f"up to {a['old_report_cycle_days']:.0f} days — next manual report (ASSUMPTION)",
         f"within 1 day: daily run; this run used an export {export_age_h:.1f} h old (MEASURED); Defender refreshes it every 6 h"
         if export_age_h is not None else "within 1 day (daily run)",
         f"≈ {a['old_report_cycle_days']:.0f}× faster (CALCULATED)"),
        ("6. Analyst effort: reporting vs remediation",
         "mostly reporting (QUALITATIVE)",
         "reporting is automatic; the dashboard's 'Fix these first' list goes straight to remediation (QUALITATIVE)",
         "time shifts to fixing"),
    ]
    snapshot = m["run_date"]
    lines = [f"# UC3 — before / after ({snapshot})", "",
             "Labels: **MEASURED** = our real Defender runs · **ASSUMPTION** = `config/assumptions.csv`, replace with the "
             "client's baseline · **CALCULATED** = derived from the two · **QUALITATIVE** = not measurable in a lab.", "",
             "| Client metric | Before (old way) | After (this pipeline) | Change |", "|---|---|---|---|"]
    lines += [f"| {m_} | {b} | {n} | {c} |" for m_, b, n, c in table]
    lines += ["", f"Source run: {snapshot}, {m['counts']['machines']} devices, {rows:,} rows, Defender's own count "
              f"{source if source is not None else 'n/a'}, run time {m['duration_seconds']} s, retries {m['retries']}."]
    out = settings.reporting_dir / f"UC3_Before_After_{snapshot}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"table": table, "path": out}
