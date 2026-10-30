"""Command line: python -m threat_intel <command>

  check       environment, settings present (never shows values), feed reachability
  live-test   tiny real calls to Defender, Gemini, NVD, abuse.ch, OTX
  models      list the Gemini flash-lite models your key can use
  collect     download the threat feeds
  inventory   pull devices, software and vulnerabilities from Defender
  analyse     derive + EPSS + Gemini analysis + exposure + scoring
  hunt        run hunts in Defender (+ correlate + re-score)
  report      build the Word/PDF report
  dashboard   export the portal's data (data/dashboard/*.json)
  alerts      raise alerts for high-risk threats that affect us
  metrics     print the key metrics
  run         the Threat Intel run: everything above except hunting, in order (what the scheduled task runs)
  attack-check  the Attack Check Agent: hunt in Defender for the collected warning signs, keep new signs of attack,
              AI resolution steps, alerts, portal data (waits up to 30 minutes if a Threat Intel run is busy)
  summary     short overview of what's in the database
  spotcheck   export 20 AI answers for a person to check (--score FILE reads the marks back)
  demo        the demo story with today's numbers (data/demo_notes.md)
  serve       the service the portal calls on http://127.0.0.1:8700 (this computer only): run status,
              "Run now" and the fix engine; no web pages (--port N)

Fix loop - fixes only run after an approval:
  fix-plan     rebuild the fix plan from the last inventory (and verify earlier fixes)
  fix-refresh  pull a fresh inventory from Defender, rebuild the fix plan and list the new fixes (the Vulnerability
               Agent's Fix stage; prints "Fix plan: {json}"; waits up to 15 minutes if a Threat Intel run is busy)
  fix-status   show the plan and each fix's status
  fix-probe    read-only check of the lab VMs (winget, installed versions) (--method)
  fix-approve  approve fixes: --stage 1 | --all | --ids fx_a,fx_b  [--device NAME] [--method runcommand|liveresponse]
  fix-run      run the approved fixes now (also from the portal's Fix page)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

from threat_intel import alerts, dashboard, live_test, metrics, report
from threat_intel.config import ConfigError, Settings, load_settings
from threat_intel.pipeline import Pipeline, RunLocked, lock_active, make_ai, make_defender, run_lock
from threat_intel.store import Store, utcnow

FEED_HOSTS = {
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
    "EPSS": "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
    "MITRE ATT&CK": "https://github.com/mitre-attack/attack-stix-data",
    "abuse.ch": "https://threatfox-api.abuse.ch/api/v1/",
    "AlienVault OTX": "https://otx.alienvault.com/",
    "Microsoft MSRC": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
    "NCSC-NL": "https://advisories.ncsc.nl/rss/advisories",
    "CERT-EU": "https://cert.europa.eu/publications/security-advisories-rss",
    "Defender API": "https://api.security.microsoft.com/api/advancedqueries/run",
    "Gemini API": "https://generativelanguage.googleapis.com/",
}


def setup_logging(settings: Settings, verbose: bool) -> None:
    settings.ensure_dirs()
    handlers = [logging.StreamHandler(sys.stdout),
                logging.FileHandler(settings.log_dir / f"threat_intel_{datetime.now():%Y-%m-%d}.log", encoding="utf-8")]
    handlers[0].setLevel(logging.INFO if verbose else logging.WARNING)
    handlers[1].setLevel(logging.INFO)
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "google_genai", "urllib3", "msal"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def cmd_check(settings: Settings) -> int:
    print(f"Threat Intel check\n  Python {sys.version.split()[0]}\n  Folder: {settings.data_dir.parent}\n")
    print("Settings in .env (values are never shown):")
    for name, is_set, why in settings.describe():
        print(f"  [{'set' if is_set else '---'}] {name:24s} {why}")
    if settings.ai_provider == "azure":
        print(f"  AI: Azure AI Foundry deployment {settings.azure_deployment} · {settings.azure_rpm} requests/min cap")
    else:
        print(f"  Gemini models: {', '.join(settings.gemini_models)} · {settings.gemini_rpm} requests/min cap")
    print("\nInternet reachability:")
    hosts = dict(FEED_HOSTS)
    if settings.has_azure:
        hosts["Azure AI Foundry"] = settings.azure_endpoint
    for name, url in hosts.items():
        try:
            r = requests.head(url, timeout=15, allow_redirects=True)
            print(f"  [OK  ] {name} (HTTP {r.status_code})")
        except requests.RequestException as exc:
            print(f"  [FAIL] {name}: {exc.__class__.__name__}")
    return 0


def cmd_summary(store: Store) -> int:
    q = store.query
    print("Threats by source:")
    for r in q("SELECT source, COUNT(*) n FROM threats GROUP BY 1 ORDER BY 2 DESC"):
        print(f"  {r['source']:18s} {r['n']}")
    print("Ratings:", {r["rating"]: r["n"] for r in q("SELECT rating, COUNT(*) n FROM scores GROUP BY 1")})
    print("AI status:", {r["ai_status"]: r["n"] for r in q("SELECT ai_status, COUNT(*) n FROM analysis GROUP BY 1")})
    print("Devices:", store.scalar("SELECT COUNT(*) FROM devices"),
          "· vulnerabilities:", store.scalar("SELECT COUNT(*) FROM device_vulns"))
    print("Findings:", {r["kind"]: r["n"] for r in q("SELECT kind, COUNT(*) n FROM findings GROUP BY 1")})
    print("\nTop risks:")
    for r in q("""SELECT s.rating, s.score, t.title FROM scores s JOIN threats t USING (threat_id)
                  ORDER BY s.score DESC LIMIT 10"""):
        print(f"  {r['rating']:8s} {r['score']:3d}  {r['title'][:100]}")
    return 0


def cmd_fix(settings: Settings, args) -> int:
    from threat_intel.fix import plan as fix_plan
    from threat_intel.fix.runner import FixRunner
    if args.command == "fix-status":
        v = fix_plan.view(settings)
        print(f"Remediation plan from inventory {v['inventory_at']} · default method {v['default_method']}")
        print("  " + " · ".join(f"{k} {n}" for k, n in v["totals"].items() if n))
        imp = v["impact"]
        print(f"  findings open {imp['findings_open']} · remediated {imp['findings_cleared']}\n")
        for r in v["rows"]:
            print(f"  {r['fix_id']}  {r['status']:11s} S{r['stage']} {r['device_name']:12s} {r['action']:8s} "
                  f"{(r['app'] + ' ' + r['version'])[:40]:40s} {r['findings']:5d} findings"
                  + (f"  · {r['message'][:90]}" if r.get("message") else ""))
        return 0
    if args.command == "fix-approve":
        rows = [r for r in fix_plan.view(settings)["rows"] if r["action"] != "none" and r["status"] in ("proposed", "failed", "still_there")]
        if args.device:
            rows = [r for r in rows if r["device_name"] == args.device.lower()]
        if args.ids:
            wanted = {i.strip() for i in args.ids.split(",")}
            rows = [r for r in rows if r["fix_id"] in wanted]
        elif args.stage:
            rows = [r for r in rows if r["stage"] == args.stage]
        elif not args.all:
            print("Say what to approve: --stage 1, --all or --ids fx_...,fx_...")
            return 2
        print(fix_plan.approve(settings, [r["fix_id"] for r in rows], args.method))
        return 0
    runner = FixRunner(settings, on_step=print)
    if args.command == "fix-probe":
        result = runner.probe(args.method, [args.device.lower()] if args.device else None)
        print(json.dumps(result, indent=2))
        return 0 if result and all("error" not in r for r in result.values()) else 1
    if args.command == "fix-run":
        result = runner.run_approved()
        print(result)
        return 0 if not result["failed"] else 1
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m threat_intel", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["check", "live-test", "models", "collect", "inventory", "analyse", "hunt",
                                            "report", "dashboard", "alerts", "metrics", "run", "attack-check", "summary",
                                            "spotcheck", "demo", "serve", "fix-plan", "fix-refresh", "fix-status", "fix-probe",
                                            "fix-approve", "fix-run"])
    parser.add_argument("--feeds", help="collect: comma-separated feed names (default: all enabled)")
    parser.add_argument("--score", help="spotcheck: the filled-in spot-check file to score")
    parser.add_argument("--port", type=int, default=8700, help="serve: port on 127.0.0.1 (default 8700)")
    parser.add_argument("--method", choices=["runcommand", "liveresponse"], help="fix-*: Azure Run Command or Defender Live Response")
    parser.add_argument("--stage", type=int, help="fix-approve: approve every fix in this stage (1 = urgent, 2 = end-of-life, 3 = other)")
    parser.add_argument("--ids", help="fix-approve: comma-separated fix IDs (see fix-status)")
    parser.add_argument("--device", help="fix-approve / fix-probe: only this computer")
    parser.add_argument("--all", action="store_true", help="fix-approve: approve every fixable item")
    parser.add_argument("-q", "--quiet", action="store_true", help="only warnings on screen (full log in logs/)")
    args = parser.parse_args(argv)
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Settings problem: {exc}")
        return 2
    setup_logging(settings, verbose=not args.quiet)

    if args.command == "check":
        return cmd_check(settings)
    if args.command == "live-test":
        return 0 if live_test.run(settings) else 1
    if args.command == "serve":
        from threat_intel.site import serve
        serve(settings, port=args.port)
        return 0
    if args.command == "models":
        if settings.ai_provider == "azure":
            print(f"Azure AI Foundry deployment: {settings.azure_deployment} (AI_PROVIDER={settings.ai_provider_choice})")
            return 0
        from threat_intel.ai.gemini_client import GeminiClient
        ai = GeminiClient(settings)
        for name in ai.available_models():
            if "gemini" in name:
                print(("* " if "flash-lite" in name else "  ") + name)
        print(f"\nConfigured: {', '.join(settings.gemini_models)} -> using {ai.model()}")
        return 0

    if args.command in ("fix-status", "fix-probe", "fix-approve", "fix-run"):
        return cmd_fix(settings, args)

    if args.command in ("attack-check", "fix-refresh"):
        # wait BEFORE opening the database: a busy Threat Intel run holds the DuckDB file, so opening it would fail
        waited, limit = 0, (30 if args.command == "attack-check" else 15) * 60
        while lock_active(settings) and waited < limit:              # a Threat Intel run is busy: wait for it
            if waited % 60 == 0:
                print("Waiting for the Threat Intel run to finish before "
                      + ("checking for attacks" if args.command == "attack-check" else "refreshing the fix plan"), flush=True)
            time.sleep(15)
            waited += 15

    store = Store(settings.db_path)
    try:
        if args.command == "fix-plan":
            from threat_intel.fix import plan as fix_plan
            print(fix_plan.refresh(store, settings))
            return cmd_fix(settings, argparse.Namespace(command="fix-status"))
        if args.command == "summary":
            return cmd_summary(store)
        if args.command == "spotcheck":
            from threat_intel import spotcheck
            if args.score:
                result = spotcheck.score(Path(args.score), settings)
                print(json.dumps(result, indent=2))
            else:
                path = spotcheck.export(store, settings)
                print(f"Spot-check file: {path}")
                print("Open it, mark Y/N, save, then run:")
                print(f'  .venv\\Scripts\\python.exe -m threat_intel spotcheck --score "{path}"')
            return 0
        if args.command == "demo":
            from threat_intel import demo
            print(demo.write(store, settings))
            return 0
        if args.command == "metrics":
            print(json.dumps(metrics.write(store, settings), indent=2, default=str))
            return 0
        if args.command == "dashboard":
            print(dashboard.build(store, settings))
            return 0
        if args.command == "alerts":
            print(alerts.run(store, settings))
            return 0
        if args.command == "report":
            print(report.build(store, settings, None, make_ai(settings, store)))
            return 0

        with run_lock(settings):
            if args.command == "fix-refresh":
                from threat_intel.fix import plan as fix_plan
                p = Pipeline(settings, store, defender=make_defender(settings))
                p.inventory()
                inv = p.steps["inventory"]
                result = {**fix_plan.refresh(store, settings, "vulnerability"), "inventory": inv["status"],
                          "inventory_note": inv.get("error") or inv.get("reason") or ""}
                print("Fix plan:", json.dumps(result, default=str), flush=True)
                return 0
            p = Pipeline(settings, store, defender=make_defender(settings), ai=make_ai(settings, store))
            started = utcnow()
            if args.command == "collect":
                p.collect(args.feeds.split(",") if args.feeds else None)
            elif args.command == "inventory":
                p.inventory()
            elif args.command == "analyse":
                p.enrich()
                p.analyse()
                p.score()
            elif args.command == "hunt":
                p.hunt()
                p.correlate()
                p.score("rescore")
            elif args.command == "attack-check":
                result = p.attack_check()
                print(f"\nAttack check {result['run_id']}: {result['status']}")
                for name, s in result["steps"].items():
                    detail = s.get("result") if s["status"] == "ok" else s.get("error") or s.get("reason")
                    print(f"  {name:12s} {s['status']:8s} {str(detail)[:160]}")
                return 0 if result["status"] == "ok" else 1
            elif args.command == "run":
                result = p.run_all()
                print(f"\nRun {result['run_id']}: {result['status']}")
                for name, s in result["steps"].items():
                    detail = s.get("result") if s["status"] == "ok" else s.get("error") or s.get("reason")
                    print(f"  {name:12s} {s['status']:8s} {str(detail)[:160]}")
                return 0 if result["status"] == "ok" else 1
            store.upsert("runs", [{"run_id": p.run_id, "command": args.command, "started_at": started,
                                   "finished_at": utcnow(), "status": "ok" if all(s["status"] != "error" for s in p.steps.values()) else "partial",
                                   "steps": p.steps}])
            for name, s in p.steps.items():
                detail = s.get("result") if s["status"] == "ok" else s.get("error") or s.get("reason")
                print(f"  {name:12s} {s['status']:8s} {str(detail)[:200]}")
            return 0 if all(s["status"] != "error" for s in p.steps.values()) else 1
    except RunLocked as exc:
        print(exc)
        return 3
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
