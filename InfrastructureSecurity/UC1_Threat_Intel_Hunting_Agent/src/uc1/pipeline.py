"""Two runs share this database:

- Threat Intel run (`uc1 run`): collect -> inventory -> derive -> EPSS -> analyse -> exposure -> score -> link the
  exposure to computers -> AI fix steps for the threats that affect us -> alerts -> report -> dashboard -> metrics
  -> fix (the fix plan, with the fixes that are new in this run).
- Attack check run (`uc1 attack-check`): hunt in Defender for the warning signs the Threat Intel run collected ->
  correlate (keeps earlier signs, adds new ones) -> re-score -> AI resolution steps -> alerts -> dashboard -> fix
  (a scan-and-clean response for every new sign of attack).
The fix step only PROPOSES: a person fixes or saves each new fix for later on the portal's run page (or in the Fix
Centre), and nothing on a computer changes without that approval. `python -m uc1 fix-plan` rebuilds it on its own.

Each step's failure is logged and the next steps continue with what is available. A lock file stops two runs
(e.g. a scheduled run and a manual one) from overlapping.
"""

from __future__ import annotations

import json
import logging
import os
import time
import traceback
from contextlib import contextmanager
from datetime import datetime

from uc1 import alerts, analyse, attack_report, correlate, dashboard, derive, exposure, fix_advice, inventory, metrics, report, resolve, scoring
from uc1.ai.azure_client import AzureFoundryClient, make_client
from uc1.ai.gemini_client import AIUnavailable, GeminiClient
from uc1.api_client import DefenderClient
from uc1.auth import EntraTokenProvider
from uc1.config import Settings
from uc1.feeds import collect_all, epss
from uc1.feeds.common import FeedContext
from uc1.feeds.nvd import fetch_cves
from uc1.hunting.runner import HuntRunner
from uc1.store import Store, utcnow

log = logging.getLogger("uc1.pipeline")


class RunLocked(RuntimeError):
    pass


def _pid_alive(pid: int) -> bool:
    """Is a process with this ID still running? (Never sends a signal: on Windows os.kill would terminate it.)"""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)        # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            if code.value != 259:                                 # STILL_ACTIVE
                return False
            # Windows reuses process IDs: after a killed run the number can belong to another program
            # (seen 5 Oct: conhost.exe), so only a Python process counts as "our run is still going"
            size = ctypes.c_ulong(1024)
            buf = ctypes.create_unicode_buffer(1024)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                return "python" in buf.value.lower().rsplit("\\", 1)[-1]
            return True
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def lock_active(settings: Settings) -> bool:
    """True if a run holds the lock. A lock left behind by a run that was killed (VM restart, power off) is stale:
    its process no longer exists, or it's older than 3 hours."""
    lock = settings.data_dir / ".run.lock"
    if not lock.exists():
        return False
    if time.time() - lock.stat().st_mtime >= 3 * 3600:
        return False
    try:
        pid = int(lock.read_text().strip() or 0)
    except (OSError, ValueError):
        return True                                               # unreadable: assume busy (it's young)
    return _pid_alive(pid)


@contextmanager
def run_lock(settings: Settings):
    lock = settings.data_dir / ".run.lock"
    if lock_active(settings):
        raise RunLocked(f"Another run is in progress (lock file {lock}). If none is running, delete that file.")
    if lock.exists():
        log.warning("Removing a stale run lock left by a run that was interrupted")
    lock.write_text(str(os.getpid()))
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def new_run_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def make_defender(settings: Settings) -> DefenderClient | None:
    if not settings.has_defender:
        return None
    return DefenderClient(settings.api_base, EntraTokenProvider(settings))


def make_ai(settings: Settings, store: Store) -> GeminiClient | AzureFoundryClient | None:
    try:
        return make_client(settings, store)
    except AIUnavailable:
        return None


class Pipeline:
    def __init__(self, settings: Settings, store: Store, run_id: str | None = None,
                 defender: DefenderClient | None = None, ai: GeminiClient | None = None):
        self.settings, self.store = settings, store
        self.run_id = run_id or new_run_id()
        self.defender, self.ai = defender, ai
        self.steps: dict[str, dict] = {}
        self.ctx = FeedContext(settings, store, settings.raw_dir / self.run_id)

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

    # ---------- steps ----------
    def collect(self, only=None):
        return self.step("collect", collect_all, self.ctx, only)

    def inventory(self):
        if not self.defender:
            return self.skip("inventory", "Defender not configured")
        return self.step("inventory", inventory.pull, self.store, self.defender)

    def enrich(self):
        self.step("derive", derive.run, self.store, self.settings.cve_window_days)
        missing = [r["cve_id"] for r in self.store.query("""
            SELECT DISTINCT l.value AS cve_id FROM threat_links l LEFT JOIN cves c ON c.cve_id = l.value
            WHERE l.link_type = 'cve' AND (c.cve_id IS NULL OR c.description IS NULL)
              AND l.threat_id IN (SELECT threat_id FROM threats WHERE kind IN ('advisory', 'pulse'))""")][:60]
        if missing:
            self.step("nvd_details", fetch_cves, self.ctx, missing)
        self.step("epss", epss.collect, self.ctx)
        self.step("products", exposure.products_from_cves, self.store)

    def analyse(self):
        return self.step("analyse", analyse.run, self.store, self.ai, workers=self.settings.ai_workers)

    def score(self, name="score"):
        self.step("exposure", exposure.compute, self.store)
        return self.step(name, scoring.run, self.store)

    def hunt(self):
        if not self.defender:
            return self.skip("hunt", "Defender not configured")
        runner = HuntRunner(self.store, self.defender, self.run_id, self.settings.hunt_lookback_days, self.ai)
        return self.step("hunt", runner.run_all, self.settings.feed_backfill_days)

    def correlate(self):
        return self.step("correlate", correlate.run, self.store, self.defender, self.run_id)

    def fix_advice(self):
        return self.step("fix_advice", fix_advice.run, self.store, self.settings, self.ai)   # AI fix steps per threat

    def resolve(self):
        return self.step("resolve", resolve.run, self.store, self.settings, self.ai)     # AI steps per sign of attack

    def outputs(self):
        self.step("alerts", alerts.run, self.store, self.settings)
        self.step("report", report.build, self.store, self.settings, self.run_id, self.ai, self.steps)
        self.step("dashboard", lambda: str(dashboard.build(self.store, self.settings)))
        self.step("metrics", metrics.write, self.store, self.settings)

    def fix_plan(self, source: str):
        """Last step of both runs: rebuild the fix plan and list the fixes that are new in this run (proposals only)."""
        from uc1.fix import plan as fix_plan
        return self.step("fix_plan", fix_plan.refresh, self.store, self.settings, source)

    def attack_check(self) -> dict:
        """The Attack Check Agent: search our computers for the warning signs the Threat Intel run collected."""
        started = utcnow()
        self.store.upsert("runs", [{"run_id": self.run_id, "command": "attack-check", "started_at": started,
                                    "status": "running", "steps": {}}])
        self.hunt()
        self.correlate()
        self.score("rescore")          # threats with new signs of attack get their rating raised
        self.resolve()
        self.step("alerts", alerts.run, self.store, self.settings)
        self.step("report", attack_report.build, self.store, self.settings, self.run_id, self.steps)
        self.step("dashboard", lambda: str(dashboard.build(self.store, self.settings)))
        self.fix_plan("attack_detection")
        failed = [k for k, v in self.steps.items() if v["status"] == "error"]
        status = "ok" if not failed else "partial"
        finished = utcnow()
        self.store.upsert("runs", [{"run_id": self.run_id, "command": "attack-check", "started_at": started,
                                    "finished_at": finished, "status": status, "steps": self.steps}])
        (self.settings.data_dir / "last_attack_check.json").write_text(json.dumps({
            "run_id": self.run_id, "status": status, "started_at": started.isoformat(), "finished_at": finished.isoformat(),
            "failed_steps": failed}), encoding="utf-8")
        return {"run_id": self.run_id, "status": status, "failed_steps": failed, "steps": self.steps}

    def run_all(self) -> dict:
        started = utcnow()
        self.store.upsert("runs", [{"run_id": self.run_id, "command": "run", "started_at": started, "status": "running",
                                    "steps": {}}])
        self.collect()
        self.inventory()
        self.enrich()
        self.analyse()
        self.score()
        self.correlate()               # no hunts in this run: refreshes which computers each threat affects
        self.fix_advice()
        self.outputs()
        self.fix_plan("threat_intel")
        failed = [k for k, v in self.steps.items() if v["status"] == "error"]
        feeds_failed = [k for k, v in (self.steps.get("collect", {}).get("result") or {}).items() if v.startswith("FAILED")]
        status = "ok" if not failed and not feeds_failed else "partial"
        finished = utcnow()
        self.store.upsert("runs", [{"run_id": self.run_id, "command": "run", "started_at": started,
                                    "finished_at": finished, "status": status, "steps": self.steps}])
        (self.settings.data_dir / "last_run.json").write_text(json.dumps({       # read by the website
            "run_id": self.run_id, "status": status, "started_at": started.isoformat(), "finished_at": finished.isoformat(),
            "failed_steps": failed, "failed_feeds": feeds_failed}), encoding="utf-8")
        return {"run_id": self.run_id, "status": status, "failed_steps": failed, "failed_feeds": feeds_failed,
                "steps": self.steps}

