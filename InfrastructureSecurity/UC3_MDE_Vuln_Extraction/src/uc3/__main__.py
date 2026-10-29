"""Command line entry point: `python -m uc3 <command>`.

  check       is everything installed and configured?
  live-test   step-by-step connection test against Defender
  extract     download devices, full vulnerability export and changes      (Phase 2)
  load        put a downloaded day into the data lake and refresh the views (Phase 3)
  quality     run the data-quality checks for a day                         (Phase 4)
  publish     reporting tables + portal data + Excel summary + report       (Phase 5)
  run         extract + load + quality + publish in one go (the daily job)
  summary     short overview of the latest data
  demo-limit  measure the KQL 100,000-row limit on the real Defender API    (Phase 7)
  metrics     before/after table for the client's six metrics               (Phase 7)
  ai-fixes    AI fix guide: one fix card per vulnerable app, then rebuild the portal data + Excel
"""

from __future__ import annotations

import argparse
import importlib
import logging
import os
import shutil
import sys
import tempfile
from datetime import date
from pathlib import Path

from uc3 import __version__
from uc3.config import ConfigError, load_settings

LIBRARIES = ("msal", "requests", "duckdb", "pyarrow", "dotenv")


def cmd_check(_args: argparse.Namespace) -> int:
    """Verify the environment is ready; exit code 0 when nothing FAILs."""
    results: list[tuple[str, str, str]] = []

    def record(status: str, name: str, detail: str) -> None:
        results.append((status, name, detail))

    py_ok = sys.version_info >= (3, 12)
    record("OK" if py_ok else "FAIL", "Python", sys.version.split()[0])

    for lib in LIBRARIES:
        try:
            module = importlib.import_module(lib)
            record("OK", f"library {lib}", getattr(module, "__version__", "installed"))
        except ImportError as exc:
            record("FAIL", f"library {lib}", str(exc))

    settings = None
    try:
        settings = load_settings()
        record("OK", "settings", f"Defender API {settings.api_base}, login details present")
    except ConfigError as exc:
        record("FAIL", "settings", str(exc))

    if settings is not None:
        try:
            settings.ensure_dirs()
            probe = settings.data_dir / ".write_test"
            probe.write_text("ok")
            probe.unlink()
            record("OK", "data folder", str(settings.data_dir))
        except OSError as exc:
            record("FAIL", "data folder", str(exc))

    try:
        record("OK", "Parquet + DuckDB", _parquet_duckdb_roundtrip())
    except Exception as exc:  # any failure here means the core stack is broken
        record("FAIL", "Parquet + DuckDB", repr(exc))

    if settings is not None:
        keys = len(settings.gemini_keys)
        if settings.ai_provider == "azure":
            record("OK", "AI (optional)", f"Azure AI Foundry deployment {settings.azure_deployment} - AI remediation guide on")
        else:
            record("OK" if keys else "WARN", "Gemini key (optional)",
                   (f"{keys} keys set - AI remediation guide on, the next key takes over when one runs out" if keys > 1
                    else "set - AI remediation guide on") if keys
                   else "no AI set (AZURE_FOUNDRY_* or GEMINI_API_KEY) - fix cards without AI text")

    from uc3.docstyle import pdf_converter
    converter = pdf_converter()
    record("OK" if converter else "WARN", "PDF report",
           f"made by {converter}" if converter else "Microsoft Word not installed - reports come as Word and Excel only")

    width = max(len(name) for _, name, _ in results)
    print(f"UC3 environment check (uc3 {__version__})\n")
    for status, name, detail in results:
        print(f"  [{status:<4}] {name:<{width}}  {detail}")
    failed = sum(status == "FAIL" for status, _, _ in results)
    print("\nRESULT:", "FAIL" if failed else "OK")
    return 1 if failed else 0


def _parquet_duckdb_roundtrip() -> str:
    """Write a small Parquet file with pyarrow and aggregate it with DuckDB."""
    import duckdb
    import pyarrow as pa
    import pyarrow.parquet as pq

    table = pa.table({"severity": ["Critical", "High", "High"], "cve": ["CVE-1", "CVE-2", "CVE-3"]})
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.parquet"
        pq.write_table(table, path)
        rows = duckdb.sql(
            f"SELECT severity, COUNT(*) FROM read_parquet('{path.as_posix()}') GROUP BY 1 ORDER BY 1"
        ).fetchall()
    if rows != [("Critical", 1), ("High", 2)]:
        raise RuntimeError(f"unexpected result {rows}")
    return "write/read/aggregate works"


def _logging(settings=None) -> None:
    """Log to the screen and, when settings are given, to logs/uc3_<date>.log (kept 90 days)."""
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if settings is not None:
        settings.log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(settings.log_dir / f"uc3_{date.today().isoformat()}.log", encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S", handlers=handlers, force=True)


def cmd_live_test(_args: argparse.Namespace) -> int:
    from uc3.live_test import run

    return run()


def _print_extract(settings, manifest: dict) -> None:
    counts = manifest["counts"]
    print(f"\nExtract OK in {manifest['duration_seconds']}s -> {settings.raw_dir / manifest['run_date']}")
    print(f"  Devices              : {counts['machines']:,}")
    print(f"  Vulnerability export : {counts['vulnerability_rows']:,} rows in {len(manifest['files'])} file(s)")
    if manifest.get("source_count") is not None:
        print(f"  Defender's own count : {manifest['source_count']:,} rows")
    print(f"  Changes since {manifest['changes_since'][:16]} : {counts['change_rows']:,}")
    print(f"  Retries needed       : {manifest['retries']}  (export requested {manifest['export_attempts']}x)")


def cmd_extract(args: argparse.Namespace) -> int:
    from uc3.api_client import ApiError
    from uc3.auth import AuthError
    from uc3.extract import run_extract

    _logging()
    settings = load_settings()
    try:
        manifest = run_extract(settings, args.date)
    except (ApiError, AuthError) as exc:
        print(f"\nExtract FAILED: {exc}")
        return 1
    _print_extract(settings, manifest)
    return 0


def _print_load(loaded: dict) -> None:
    c = loaded["counts"]
    print(f"Loaded {loaded['run_date']} into the data lake: {c['vulnerability_rows']:,} vulnerability rows, "
          f"{c['devices']:,} devices, {c['change_rows']:,} change events")


def cmd_load(args: argparse.Namespace) -> int:
    from uc3.load import run_load
    from uc3.transform import refresh_views

    settings = load_settings(require_credentials=False)
    loaded = run_load(settings, args.date)
    refresh_views(settings)
    _print_load(loaded)
    return cmd_summary(args)


def cmd_quality(args: argparse.Namespace) -> int:
    from uc3.quality import format_report, run_checks

    report = run_checks(load_settings(require_credentials=False), args.date)
    print(format_report(report))
    return 1 if report["overall"] == "FAIL" else 0


def cmd_run(args: argparse.Namespace) -> int:
    """The daily job. Exit code 0 = published (PASS or WARN), 1 = something failed (see logs/ and the dashboard alert)."""
    from uc3.pipeline import daily_job
    from uc3.quality import format_report

    base = load_settings(require_credentials=False)
    _logging(base)
    log = logging.getLogger("uc3.run")
    log.info("Run started")
    job = daily_job(args.date)
    if job["outcome"] == "skipped":
        print(f"\nRun skipped: {job['message']}.")
        return 0
    if job["outcome"] == "error":
        print(f"\nRun FAILED: {job['error']}\nDetails: {base.log_dir}")
        return 1
    settings, result = job["settings"], job["result"]
    _print_extract(settings, result["extract"])
    print()
    _print_load(result["load"])
    print()
    report = format_report(result["quality"])
    print(report)
    log.info("Quality: %s", result["quality"]["overall"])
    print()
    if result["publish"]:
        _print_publish(result["publish"])
        log.info("Published: %s", result["publish"]["dashboard"])
        removed = {k: v for k, v in result["retention"].items() if v}
        print(f"  Old files removed: {removed or 'none'}")
        fix = result.get("fix")
        print(f"  Remediation stage: {fix['new']} new remediations proposed, awaiting approval on the run page"
              if fix else "  Remediation stage: skipped (see the log)")
    else:
        print("Publishing SKIPPED because a quality check failed; the dashboard shows the last good data with a red alert.")
        log.error("Publishing skipped: quality FAIL")
    log.info("Daily run finished")
    return 1 if result["quality"]["overall"] == "FAIL" else 0


def _print_publish(published: dict) -> None:
    print(f"Published {len(published['tables'])} reporting tables to data/reporting/")
    print(f"  CyberSuite data: {published['dashboard']}")
    print(f"  Excel report  : {published['excel']}")
    print(f"  Word report   : {published['report']['docx']}")
    print(f"  PDF report    : {published['report']['pdf'] or 'not made (Microsoft Word not installed)'}")
    fixes = published.get("ai_fixes")
    print(f"  AI remediation guide: " + (f"{fixes['apps']} apps, {fixes['ai']} explained by AI ({fixes['asked']} asked now)"
                                   if fixes else "not updated (see log)"))


def cmd_metrics(_args: argparse.Namespace) -> int:
    from uc3.metrics import build_metrics

    result = build_metrics(load_settings(require_credentials=False))
    for metric, before, after, change in result["table"]:
        print(f"\n{metric}\n  Before : {before}\n  After  : {after}\n  Change : {change}")
    print("\n(edit assumptions in config/assumptions.csv)")
    return 0


def cmd_ai_fixes(args: argparse.Namespace) -> int:
    from uc3.ai.fixes import build_fixes
    from uc3.dashboard.build import build_dashboard
    from uc3.excel import build_excel

    settings = load_settings(require_credentials=False)
    _logging(settings)
    result = build_fixes(settings, use_ai=not args.no_ai, force=args.force)
    c = result["counts"]
    print(f"\nAI remediation guide for snapshot {result['snapshot']}: {c['apps']} apps + {c.get('settings', 0)} security settings")
    print("  Remediation types: " + ", ".join(f"{t} {n}" for t, n in c.get("by_fix_type", {}).items()))
    print(f"  AI explained : {c['ai']}  (asked now {c['asked']}, unchanged from cache {c['reused']})")
    print(f"  Data only    : {c['rules']}" + (f"  - {result['ai_message']}" if result["ai_message"] else ""))
    print(f"  Fact check   : {c['corrections']} AI sentence(s) removed because they were not backed by the data")
    print(f"  CVE texts    : {result['kb']['entries']:,} Microsoft descriptions ({result['kb']['status']})")
    for i, a in enumerate(result["apps"], 1):
        print(f"  {i:>2}. [{a['urgency']['label']}] {a['app']} ({', '.join(v['version'] for v in a['versions'])}): "
              f"{a['cves']} CVEs, {len(a['devices'])} device(s) - {a['source']}")
    print(f"\n  CyberSuite data: {build_dashboard(settings)}  (CyberSuite's Remediation page)")
    print(f"  Excel summary : {build_excel(settings)}  (sheet 'Remediation plan (AI)')")
    return 0


def cmd_publish(_args: argparse.Namespace) -> int:
    from uc3.pipeline import publish_all

    _logging()
    _print_publish(publish_all(load_settings(require_credentials=False)))
    return 0


def cmd_demo_limit(_args: argparse.Namespace) -> int:
    from uc3.api_client import ApiError
    from uc3.auth import AuthError
    from uc3.proof import run_kql_limit

    try:
        result = run_kql_limit(load_settings())
    except (ApiError, AuthError) as exc:
        print(f"demo-limit FAILED: {exc}")
        return 1
    print("KQL row limit, measured on the real Defender advanced-hunting API:")
    print(f"  Query          : {result['query']}")
    print(f"  Rows that exist: {result['rows_exist']:,}   (from '| count', which returns one row and is never capped)")
    print(f"  Rows returned  : {result['rows_returned']:,}   -> coverage {result['coverage']:.0%}")
    print("Saved to data/reference/kql_limit.json (shown on the dashboard banner after the next publish).")
    return 0


def cmd_summary(_args: argparse.Namespace) -> int:
    from uc3.transform import connect

    with connect(load_settings(require_credentials=False), read_only=True) as con:
        q = lambda sql: con.execute(sql).fetchall()
        day = q("SELECT max(snapshot_date) FROM lake_vulnerabilities")[0][0]
        print(f"\nLatest snapshot: {day}")
        print("  Vulnerabilities by OpCo and severity:")
        for opco, crit, high, med, low, total, devices in q("""
                SELECT opco, count(*) FILTER (WHERE severity = 'Critical'), count(*) FILTER (WHERE severity = 'High'),
                       count(*) FILTER (WHERE severity = 'Medium'), count(*) FILTER (WHERE severity = 'Low'),
                       count(*), count(DISTINCT device_id)
                FROM vuln_current WHERE cve_id IS NOT NULL GROUP BY 1 ORDER BY 1"""):
            print(f"    {opco:<10} Critical {crit:>5,}  High {high:>5,}  Medium {med:>5,}  Low {low:>5,}"
                  f"  | total {total:>6,} on {devices} device(s)")
        print("  Priority: " + "  ".join(f"{p} {n:,}" for p, n in q(
            "SELECT priority, count(*) FROM vuln_current WHERE priority IS NOT NULL GROUP BY 1 ORDER BY 1")))
        print("  Top software to update:")
        for name, version, vulns, critical in q("""SELECT software_name, software_version, vulnerabilities, critical
                FROM software_summary ORDER BY vulnerabilities DESC LIMIT 5"""):
            print(f"    {name} {version}: {vulns:,} vulnerabilities ({critical:,} critical)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m uc3", description="UC3 vulnerability extraction")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="verify the environment is ready").set_defaults(func=cmd_check)
    sub.add_parser("live-test", help="check the connection to Defender step by step").set_defaults(func=cmd_live_test)
    for name, func, text in (
        ("extract", cmd_extract, "download devices, full vulnerability export and changes"),
        ("load", cmd_load, "put a downloaded day into the data lake and refresh the views"),
        ("quality", cmd_quality, "run the data-quality checks for a day"),
        ("run", cmd_run, "extract + load + quality in one go"),
    ):
        command = sub.add_parser(name, help=text)
        command.add_argument("--date", type=date.fromisoformat,
                             help="run date YYYY-MM-DD (default: today for extract/run, latest download otherwise)")
        command.set_defaults(func=func)
    sub.add_parser("summary", help="short overview of the latest data").set_defaults(func=cmd_summary)
    sub.add_parser("publish", help="reporting tables + CyberSuite data + Excel summary + report").set_defaults(func=cmd_publish)
    sub.add_parser("demo-limit", help="measure the KQL 100,000-row limit on the real API").set_defaults(func=cmd_demo_limit)
    sub.add_parser("metrics", help="before/after table for the client's six metrics").set_defaults(func=cmd_metrics)
    fixes = sub.add_parser("ai-fixes", help="AI remediation guide for every vulnerable app, then rebuild the CyberSuite data + Excel")
    fixes.add_argument("--force", action="store_true", help="ask the AI again for every app (ignore the cache)")
    fixes.add_argument("--no-ai", action="store_true", help="data-based cards only, no AI calls")
    fixes.set_defaults(func=cmd_ai_fixes)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
