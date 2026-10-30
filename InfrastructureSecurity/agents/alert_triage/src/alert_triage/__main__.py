"""Alert Triage command line: `python -m alert_triage <command>` (run from the Alert Triage folder with its own .venv).

  check            settings present (names only), folders writable, database opens
  live-test        tiny real calls: Microsoft login, incidents, hunting, devices, AI (Azure Foundry or Gemini), threat intel
  run              ingest new/changed incidents -> triage -> (comments) -> ledger -> metrics -> export
  triage --incident ID [--no-ai]   triage one incident now (re-runs even if unchanged)
  ledger           load the lab ledger (data/inbox/ledger/*.txt) and match lab incidents
  backtest [--guide N] [--no-ai]   grade the agent on N GUIDE incidents + all matched lab incidents
  metrics          print the metrics (MEASURED / ASSUMPTION)
  serve [--port 8900]              the service the portal calls (this computer only; no web pages)
  demo             today's numbers for the demo script
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from alert_triage.config import Settings, load_settings
from alert_triage.store import Store


def setup_logging(settings: Settings, verbose: bool) -> None:
    from alert_triage.store import utcnow
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    handlers = [logging.StreamHandler(sys.stdout),
                logging.FileHandler(settings.log_dir / f"alert_triage_{utcnow():%Y-%m-%d}.log", encoding="utf-8")]
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for noisy in ("urllib3", "msal", "httpx", "google_genai", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def cmd_check(settings: Settings) -> int:
    print("Alert Triage settings check (values are never shown)\n")
    for name, is_set, why in settings.describe():
        print(f"  [{'set ' if is_set else '----'}] {name:20s} {why}")
    print(f"\n  pilot comments (TRIAGE_WRITEBACK): {'ON' if settings.writeback else 'off'}")
    print(f"  isolate stretch (TRIAGE_CONTAIN):  {'ON' if settings.contain else 'off'}  lab devices: "
          f"{', '.join(settings.lab_devices)}")
    settings.ensure_dirs()
    store = Store(settings.db_path)
    store.close()
    from alert_triage.router import load_playbooks
    from alert_triage.tools.logs import LogTools
    books = load_playbooks()
    queries = LogTools(None, settings).available()
    missing = sorted({q for b in books for q in b.get("queries", [])} - queries)
    print(f"\n  database: {settings.db_path}")
    print(f"  playbooks: {len(books)} ({', '.join(b['id'] for b in books)})")
    print(f"  search templates: {len(queries)}" + (f"  MISSING: {', '.join(missing)}" if missing else ""))
    ok = settings.has_microsoft and not missing
    print("\n" + ("Ready." if ok else "Not ready yet: fill in the missing settings in the suite .env (see .env.example at the repository root)."))
    return 0 if ok else 1


def cmd_triage(settings: Settings, incident_id: str, no_ai: bool) -> int:
    from alert_triage.packet import build
    from alert_triage.pipeline import build_clients
    from alert_triage.triage import Triage
    store = Store(settings.db_path)
    try:
        graph, defender, llm = build_clients(settings, store)
        packet = build(graph.incident(incident_id), settings.lab_devices,
                       lab_titles=settings.lab_alert_titles)
        v = Triage(settings, store, graph, defender, None if no_ai else llm).run_one(packet)
        from alert_triage.export import export_all
        export_all(store, settings)
    finally:
        store.close()
    print(json.dumps({k: v.get(k) for k in ("verdict", "confidence", "recommended_severity", "escalate",
                                            "guardrails", "summary", "ai_status")}, indent=1, default=str))
    return 0


def cmd_backtest(settings: Settings, n: int, no_ai: bool) -> int:
    from alert_triage import backtest, ledger
    from alert_triage.llm import make_llm
    store = Store(settings.db_path)
    try:
        ledger.load_inbox(store, settings)
        ledger.match_incidents(store, settings)
        print("Lab set:", backtest.grade_lab(store))
        if n:
            llm = None if no_ai else make_llm(settings, store)
            try:
                print("GUIDE set:", backtest.run_guide(settings, store, llm, n))
            except FileNotFoundError as exc:
                print(f"GUIDE skipped: {exc}")
        out = backtest.report(settings, store)
    finally:
        store.close()
    for name, ev in out["sets"].items():
        print(f"\n{name.upper()}: {ev['n']} incidents | decided {ev['decided_pct']}% | accuracy when decided "
              f"{ev['accuracy_when_decided_pct']}% | missed real attacks {ev['missed_true_positives']} | "
              f"false alarms closable {ev['false_alarms_closable_pct']}%")
    if out.get("excel"):
        print(f"\nReport: {out['excel']}")
    return 0


def cmd_metrics(settings: Settings) -> int:
    from alert_triage import metrics
    store = Store(settings.db_path)
    try:
        data = metrics.write(store, settings)
    finally:
        store.close()
    print(f"Alert Triage metrics ({data['incidents']} triaged incidents)\n")
    for m in data["metrics"]:
        v = m["value"]
        shown = (f"median {v['median']} / mean {v['mean']} (n={v['n']})" if isinstance(v, dict) else v)
        print(f"  [{m['label']:10s}] {m['name']}: {shown if shown is not None else '-'}")
    return 0


def cmd_demo(settings: Settings) -> int:
    from alert_triage import metrics
    from alert_triage.export import queue
    store = Store(settings.db_path)
    try:
        q = queue(store)
        data = metrics.compute(store, settings)
    finally:
        store.close()
    print(f"Incidents triaged: {len(q)} (lab: {sum(1 for r in q if r['is_lab'])})")
    by = {}
    for r in q:
        by[r["verdict"]] = by.get(r["verdict"], 0) + 1
    print("By verdict:", by)
    print("Escalated:", sum(1 for r in q if r["escalate"]))
    for m in data["metrics"][:4] + data["metrics"][7:9]:
        print(f"  {m['name']}: {m['value']}")
    from alert_triage.labels import label
    for r in q[:5]:
        print(f"  - {r['incident_id']}: {r['title'][:60]} -> {label(r['verdict'])} ({r['confidence']})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alert_triage", description="Alert Triage alert triage agent (recommend-only)")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "live-test", "run", "ledger", "metrics", "demo"):
        sub.add_parser(name)
    t = sub.add_parser("triage")
    t.add_argument("--incident", required=True)
    t.add_argument("--no-ai", action="store_true")
    b = sub.add_parser("backtest")
    b.add_argument("--guide", type=int, default=300, help="GUIDE incidents to sample (0 = lab set only)")
    b.add_argument("--no-ai", action="store_true", help="rules + history baseline only")
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8900)
    args = parser.parse_args(argv)

    settings = load_settings()
    setup_logging(settings, args.verbose)
    if args.command == "check":
        return cmd_check(settings)
    if args.command == "live-test":
        from alert_triage import live_test
        return 0 if live_test.run(settings) else 1
    if args.command == "run":
        from alert_triage.pipeline import RunLocked, run
        try:
            result = run(settings)
        except RunLocked as exc:
            print(exc)
            return 3
        print(json.dumps(result, indent=1, default=str))
        return 0 if result["status"] == "ok" else 2
    if args.command == "triage":
        return cmd_triage(settings, args.incident, args.no_ai)
    if args.command == "ledger":
        from alert_triage import ledger
        store = Store(settings.db_path)
        try:
            print("loaded:", ledger.load_inbox(store, settings), "| matched:", ledger.match_incidents(store, settings))
        finally:
            store.close()
        return 0
    if args.command == "backtest":
        return cmd_backtest(settings, args.guide, args.no_ai)
    if args.command == "metrics":
        return cmd_metrics(settings)
    if args.command == "demo":
        return cmd_demo(settings)
    if args.command == "serve":
        from alert_triage.site import serve
        serve(settings, args.port)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
