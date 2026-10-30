"""Command line: python -m attack_detection <command>

  check           settings present (never shows values)
  run             the Attack Detection run: hunt in Defender for the Threat Intel Agent's warning signs, connect the
                  evidence, AI resolution steps, report, publish data/out/findings.json, let Threat Intel import it
  publish         write data/out/findings.json again from the database
  report          build the Word/PDF report of the latest run
  import-history  once: copy the hunts and signs of attack from before the split out of the Threat Intel database
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime

from attack_detection import attack_report, publish
from attack_detection.config import ConfigError, Settings, load_settings
from attack_detection.pipeline import Pipeline, RunLocked, make_ai, make_defender, run_lock
from attack_detection.store import Store


def setup_logging(settings: Settings, verbose: bool) -> None:
    settings.ensure_dirs()
    handlers = [logging.StreamHandler(sys.stdout),
                logging.FileHandler(settings.log_dir / f"attack_detection_{datetime.now():%Y-%m-%d}.log", encoding="utf-8")]
    handlers[0].setLevel(logging.INFO if verbose else logging.WARNING)
    handlers[1].setLevel(logging.INFO)
    logging.basicConfig(level=logging.INFO, handlers=handlers, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "google_genai", "urllib3", "msal"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m attack_detection", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["check", "run", "publish", "report", "import-history"])
    parser.add_argument("-q", "--quiet", action="store_true", help="only warnings on screen (full log in logs/)")
    args = parser.parse_args(argv)
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Settings problem: {exc}")
        return 2
    setup_logging(settings, verbose=not args.quiet)

    if args.command == "check":
        inp = settings.threat_intel_dir / "data" / "out" / "hunt_inputs.json" if settings.threat_intel_dir else None
        print(f"Attack Detection check\n  Folder: {settings.data_dir.parent}\n  Threat Intel input: {inp} "
              f"({'found' if inp and inp.is_file() else 'not there yet'})\n")
        print("Settings in .env (values are never shown):")
        for name, is_set, why in settings.describe():
            if name.startswith(("DEFENDER_", "GEMINI_", "AZURE_FOUNDRY_")):
                print(f"  [{'set' if is_set else '---'}] {name:24s} {why}")
        return 0

    store = Store(settings.db_path)
    try:
        if args.command == "publish":
            print(publish.write(store, settings, None))
            return 0
        if args.command == "report":
            print(attack_report.build(store, settings))
            return 0
        if args.command == "import-history":
            from attack_detection import history
            print(history.copy_from_threat_intel(store, settings))
            return 0
        with run_lock(settings):
            p = Pipeline(settings, store, defender=make_defender(settings), ai=make_ai(settings, store))
            result = p.run()
            print(f"\nAttack Detection run {result['run_id']}: {result['status']}")
            for name, s in result["steps"].items():
                detail = s.get("result") if s["status"] == "ok" else s.get("error") or s.get("reason")
                print(f"  {name:12s} {s['status']:8s} {str(detail)[:160]}")
            return 0 if result["status"] == "ok" else 1
    except RunLocked as exc:
        print(exc)
        return 3
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
