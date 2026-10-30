"""One run: ingest changed incidents, triage each, export the website data. A PID-checked lock (Threat Intel lesson) stops a
scheduled run and a manual run from overlapping. Each step logs and the run continues with what is available.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from datetime import datetime

from alert_triage.api import DefenderClient, graph_client
from alert_triage.auth import DEFENDER_SCOPE, EntraLogin
from alert_triage.config import Settings
from alert_triage.ingest import fetch
from alert_triage.llm import make_llm
from alert_triage.store import Store, utcnow
from alert_triage.triage import Triage

log = logging.getLogger("alert_triage.pipeline")


class RunLocked(RuntimeError):
    pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        k = ctypes.windll.kernel32
        handle = k.OpenProcess(0x1000, False, pid)        # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            k.GetExitCodeProcess(handle, ctypes.byref(code))
            if code.value != 259:                          # STILL_ACTIVE
                return False
            size, buf = ctypes.c_ulong(1024), ctypes.create_unicode_buffer(1024)
            if k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                return "python" in buf.value.lower().rsplit("\\", 1)[-1]
            return True
        finally:
            k.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def lock_active(settings: Settings) -> bool:
    lock = settings.data_dir / ".run.lock"
    if not lock.exists():
        return False
    if time.time() - lock.stat().st_mtime >= 2 * 3600:
        return False
    try:
        return _pid_alive(int(lock.read_text().strip() or 0))
    except (OSError, ValueError):
        return True


@contextmanager
def run_lock(settings: Settings):
    lock = settings.data_dir / ".run.lock"
    if lock_active(settings):
        raise RunLocked(f"Another run is in progress (lock file {lock}).")
    if lock.exists():
        log.warning("Removing a stale run lock left by an interrupted run")
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    lock.write_text(str(os.getpid()))
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def build_clients(settings: Settings, store: Store):
    login = EntraLogin(settings)
    graph = graph_client(settings, login)
    defender = DefenderClient(settings.defender_base, login.provider(DEFENDER_SCOPE))
    llm = make_llm(settings, store)
    return graph, defender, llm


def _step(steps: dict, name: str, fn, *args):
    """Run one step; log and record failures, never stop the run."""
    try:
        result = fn(*args)
        steps[name] = result if isinstance(result, (str, int, dict)) else "ok"
        log.info("Step %s ok: %s", name, steps[name])
        return result
    except Exception as exc:  # noqa: BLE001
        log.error("Step %s failed: %s", name, exc)
        steps[name] = f"FAILED: {str(exc).splitlines()[0][:150]}"
        return None


def run(settings: Settings, store: Store | None = None, clients=None) -> dict:
    """One full run. `clients` = (graph, defender, llm) for tests; built from .env otherwise."""
    from alert_triage import autoresolve, backtest, feedback, ledger, metrics, report, respond, writeback
    from alert_triage.export import export_all
    close = store is None
    store = store or Store(settings.db_path)
    settings.ensure_dirs()
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    started = utcnow()
    steps, triaged, status = {}, [], "ok"
    try:
        with run_lock(settings):
            graph, defender, llm = clients or build_clients(settings, store)
            _step(steps, "feedback", feedback.import_all, store, settings)
            packets = _step(steps, "ingest", fetch, graph, store, settings)
            if packets is None:
                status = "partial"
                packets = []
            else:
                steps["ingest"] = f"{len(packets)} to triage"
            triager = Triage(settings, store, graph, defender, llm)
            for packet in packets:
                try:
                    v = triager.run_one(packet)
                    triaged.append({"incident": packet["incident_id"], "verdict": v["verdict"]})
                except Exception as exc:  # noqa: BLE001
                    status = "partial"
                    log.error("Triage of %s failed: %s", packet["incident_id"], exc)
            steps["triage"] = f"{len(triaged)} of {len(packets)} triaged"
            if settings.auto_resolve:
                _step(steps, "auto_resolve", autoresolve.run, graph, store, settings)
            if settings.respond:
                _step(steps, "respond", respond.run, defender, graph, store, settings)
            _step(steps, "defender_view", respond.collect_view, graph, defender, store, settings)
            if settings.writeback:
                _step(steps, "writeback", writeback.post_pending, graph, store, settings)
            _step(steps, "actions", feedback.import_all, store, settings)     # include this run's actions in metrics
            _step(steps, "ledger", lambda: {"loaded": ledger.load_inbox(store, settings),
                                            "matched": ledger.match_incidents(store, settings)})
            _step(steps, "accuracy", lambda: backtest.grade_lab(store) | {
                "report": bool(backtest.report(settings, store, full=False))})
            _step(steps, "metrics", lambda: metrics.write(store, settings) and "ok")
            _step(steps, "export", export_all, store, settings)
            _step(steps, "report", report.build, store, settings, run_id, started)
    except RunLocked:
        raise
    finally:
        store.upsert("runs", [{"run_id": run_id, "command": "run", "started_at": started, "finished_at": utcnow(),
                               "status": status, "steps": steps}])
        store.set_state("last_run", utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
        _write_last_run(settings, run_id, started, status, steps, triaged)
        if close:
            store.close()
    return {"run_id": run_id, "status": status, "steps": steps, "triaged": triaged}


def _write_last_run(settings: Settings, run_id, started, status, steps, triaged) -> None:
    """data/last_run.json: what the website shows as 'last run' (it never opens the database)."""
    import json
    try:
        (settings.data_dir / "last_run.json").write_text(json.dumps({
            "run_id": run_id, "started_at": str(started), "finished_at": str(utcnow()), "status": status,
            "steps": steps, "triaged": triaged}, default=str, indent=1), encoding="utf-8")
    except OSError:
        pass
