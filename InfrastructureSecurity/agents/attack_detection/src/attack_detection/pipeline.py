"""The Attack Detection run (`python -m attack_detection run`):

  Search devices    inputs (the Threat Intel Agent's published threats, indicators and devices) -> hunt in Defender
  Connect evidence  correlate: hits -> findings with device, users, Defender alerts and timeline (kept from run to run)
  How to resolve    resolve: AI resolution steps per new sign of attack, checked against the evidence
  Publish           report (Word/PDF) -> publish data/out/findings.json -> threat_intel: the Threat Intel Agent imports
                    it (re-score, alerts, dashboard, scan-and-clean proposals and auto-fix)

Each step's failure is logged and the next steps continue. A lock file stops two runs from overlapping.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
import traceback
from contextlib import contextmanager
from datetime import datetime

from dotenv import dotenv_values

from attack_detection import attack_report, correlate, inputs, publish, resolve
from attack_detection.ai.azure_client import AzureFoundryClient, make_client
from attack_detection.ai.gemini_client import AIUnavailable, GeminiClient
from attack_detection.api_client import DefenderClient
from attack_detection.auth import EntraTokenProvider
from attack_detection.config import SUITE_ENV, Settings
from attack_detection.hunting.runner import HuntRunner
from attack_detection.store import Store, utcnow

log = logging.getLogger("attack_detection.pipeline")


class RunLocked(RuntimeError):
    pass


@contextmanager
def run_lock(settings: Settings):
    """One run at a time. A lock older than 3 hours is left over from a run that was killed."""
    lock = settings.data_dir / ".run.lock"
    if lock.exists() and time.time() - lock.stat().st_mtime < 3 * 3600:
        raise RunLocked(f"Another run is in progress (lock file {lock}). If none is running, delete that file.")
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(str(os.getpid()))
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def make_defender(settings: Settings) -> DefenderClient | None:
    return DefenderClient(settings.api_base, EntraTokenProvider(settings)) if settings.has_defender else None


def make_ai(settings: Settings, store: Store) -> GeminiClient | AzureFoundryClient | None:
    try:
        return make_client(settings, store)
    except AIUnavailable:
        return None


def notify_threat_intel(settings: Settings) -> dict:
    """Let the Threat Intel Agent import findings.json now (it waits if its own run is busy). Its step lines are
    copied to this run's output, so the dashboard's run page shows its re-score, alerts and fix steps too."""
    root = settings.threat_intel_dir
    python = root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python") if root else None
    if not python or not python.is_file():
        return {"imported": False, "note": f"no Threat Intel Agent at {root}"}
    ours = set(dotenv_values(SUITE_ENV))      # it reads the suite .env itself; ours would only override it
    env = {k: v for k, v in os.environ.items() if k not in ours} | {"PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run([str(python), "-m", "threat_intel", "attack-import"], cwd=root, env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=45 * 60,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    for line in proc.stdout.splitlines():
        print(line, flush=True)
    if proc.returncode != 0:
        raise RuntimeError(f"threat_intel attack-import failed ({proc.returncode}): {proc.stderr.strip()[-300:]}")
    return {"imported": True}


class Pipeline:
    def __init__(self, settings: Settings, store: Store, run_id: str | None = None,
                 defender: DefenderClient | None = None, ai: GeminiClient | None = None):
        self.settings, self.store = settings, store
        self.run_id = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.defender, self.ai = defender, ai
        self.steps: dict[str, dict] = {}

    def step(self, name: str, fn, *args, **kwargs):
        started = time.monotonic()
        try:
            result = fn(*args, **kwargs)
            self.steps[name] = {"status": "ok", "result": result, "seconds": round(time.monotonic() - started, 1)}
            log.info("Step %s ok: %s", name, result)
            return result
        except Exception as exc:  # noqa: BLE001 - keep going with the other steps
            self.steps[name] = {"status": "error", "error": str(exc).splitlines()[0][:400],
                                "seconds": round(time.monotonic() - started, 1)}
            log.error("Step %s failed: %s\n%s", name, exc, traceback.format_exc())
            return None

    def skip(self, name: str, reason: str) -> None:
        self.steps[name] = {"status": "skipped", "reason": reason}
        log.info("Step %s skipped: %s", name, reason)

    def run(self) -> dict:
        started = utcnow()
        self.store.upsert("runs", [{"run_id": self.run_id, "command": "run", "started_at": started, "status": "running",
                                    "steps": {}}])
        self.step("inputs", inputs.load, self.store, self.settings)
        if self.defender:
            runner = HuntRunner(self.store, self.defender, self.run_id, self.settings.hunt_lookback_days, self.ai)
            self.step("hunt", runner.run_all, self.settings.feed_backfill_days)
        else:
            self.skip("hunt", "Defender not configured")
        self.step("correlate", correlate.run, self.store, self.defender, self.run_id)
        self.step("resolve", resolve.run, self.store, self.settings, self.ai)
        self.step("report", attack_report.build, self.store, self.settings, self.run_id, self.steps)
        self.step("publish", publish.write, self.store, self.settings, self.run_id)
        self.step("threat_intel", notify_threat_intel, self.settings)
        failed = [k for k, v in self.steps.items() if v["status"] == "error"]
        status = "ok" if not failed else "partial"
        finished = utcnow()
        self.store.upsert("runs", [{"run_id": self.run_id, "command": "run", "started_at": started,
                                    "finished_at": finished, "status": status, "steps": self.steps}])
        (self.settings.data_dir / "last_run.json").write_text(json.dumps({
            "run_id": self.run_id, "status": status, "started_at": started.isoformat(), "finished_at": finished.isoformat(),
            "failed_steps": failed}), encoding="utf-8")
        return {"run_id": self.run_id, "status": status, "failed_steps": failed, "steps": self.steps}
