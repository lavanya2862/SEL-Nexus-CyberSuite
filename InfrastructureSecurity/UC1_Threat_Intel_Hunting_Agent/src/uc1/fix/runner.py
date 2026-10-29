"""Runs approved fixes (one computer at a time per VM, both VMs in parallel) and judges what the computer reports.

Judging uses the installed versions the script reads from Windows before and after (the "Apps & features" list):
  upgrade  ok when the old version is gone and a version is installed
  remove   ok when nothing matching the old version is left
  replace  ok when the old version is gone (a failed install of the new one is reported but doesn't undo the fix)
  setting  ok when the value the script reads back afterwards is the value the catalogue asks for
  respond  (a sign of attack) ok when the Defender scan ran and no active threat is left afterwards; until then the
           Remediation Agent (Azure AI Foundry) picks the next scan, up to 3 (without AI: quick, full, full)
"done" means fixed on the computer; it becomes "verified" when Defender's next inventory no longer lists it.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import defaultdict
from collections.abc import Callable
from contextlib import contextmanager

from uc1.config import Settings
from uc1.fix.executors import FixError, make_executor
from uc1.fix.plan import load_catalog, probe_spec, read_plan
from uc1.fix.state import FixState, event
from uc1.store import utcnow

log = logging.getLogger("uc1.fix")
OK_CODES = {0, 1641, 3010, -1978334967, -1978334966}
# a scan-and-clean is repeated until Defender lists no active threat: the same fixed script each time, a stronger scan
RESPONSE_LADDER = ("QuickScan", "FullScan", "FullScan")


class FixBusy(RuntimeError):
    pass


LOCK_MAX_AGE_S = 8 * 3600     # a fix run never takes this long; an older lock is left over (and its PID may be reused)


def fix_active(settings: Settings) -> bool:
    """Is a fix run (website or command line) in progress? PID check like the pipeline's run lock, plus an age limit."""
    import time

    from uc1.pipeline import _pid_alive
    lock = settings.fix_dir / ".fix.lock"
    try:
        if time.time() - lock.stat().st_mtime > LOCK_MAX_AGE_S:
            return False
        return _pid_alive(int(lock.read_text().strip() or 0))
    except (OSError, ValueError):
        return False


@contextmanager
def fix_lock(settings: Settings):
    lock = settings.fix_dir / ".fix.lock"
    if fix_active(settings):
        raise FixBusy("Remediations are already running. Wait for them to finish.")
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(str(os.getpid()))
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def parse_result(output: str) -> dict | None:
    for line in reversed((output or "").splitlines()):
        line = line.strip()
        if line.startswith("UC1RESULT "):
            try:
                return json.loads(line[len("UC1RESULT "):])
            except ValueError:
                return None
    return None


def _versions(entries) -> set[str]:
    return {str(e.get("version", "")) for e in (entries or []) if isinstance(e, dict)}


def _fmt(entries) -> str:
    return ", ".join(f"{e.get('name')} {e.get('version')}".strip() for e in (entries or []) if isinstance(e, dict)) or "nothing"


def judge(action: str, result: dict | None) -> tuple[str, str]:
    """(status, plain-English message)."""
    if not result:
        return "failed", "The computer did not report a result (see the output)."
    if action == "setting":
        return judge_setting(result)
    if action == "respond":
        return judge_response(result)
    before, after = result.get("before") or [], result.get("after") or []
    if isinstance(before, dict):
        before = [before]
    if isinstance(after, dict):
        after = [after]
    code = result.get("exit")
    reboot = " A restart is needed to finish." if result.get("reboot") else ""
    if result.get("not_found") or (action == "upgrade" and not before):
        # Never "done": nothing was found, so nothing was changed (and nothing new was installed).
        # A failed fix still becomes "verified" later if Defender stops listing it.
        return "failed", ("UC1 could not find this app on the computer, so it changed nothing. Either it is already "
                          "gone (Defender will clear it on its next scan), it is installed for one user only, or the "
                          "name pattern in config/fix_catalog.csv does not match it.")
    if action == "upgrade":
        old, new = _versions(before), _versions(after)
        if after and not (old & new):
            return "done", f"Updated: {_fmt(before)} -> {_fmt(after)}." + reboot
        if not after:
            return "failed", f"The app disappeared during the update (exit {code}). Before: {_fmt(before)}."
        return "failed", f"Still the old version after the update (exit {code}): {_fmt(after)}."
    if action in ("remove", "replace"):
        if int(result.get("left_count") or 0) > 0:
            return "failed", f"Could not remove everything: {_fmt(result.get('left'))} is still installed."
        if action == "remove":
            return "done", f"Removed: {_fmt(before)}." + reboot
        if code in OK_CODES:
            return "done", f"Old version removed ({_fmt(before)}); now installed: {_fmt(after)}." + reboot
        return "done", f"Old version removed ({_fmt(before)}), but installing the current one failed (exit {code}). " \
                       "The vulnerability is remediated; install the new version later if it is needed." + reboot
    return "failed", f"Unknown action {action}"


def _shown(value) -> str:
    return "not set" if value in (None, "") else str(value)


def judge_setting(result: dict) -> tuple[str, str]:
    """A setting is fixed when the computer reads back the wanted value after the change."""
    before, after, wanted = result.get("before"), result.get("after"), result.get("wanted")
    if result.get("error"):
        return "failed", f"The setting could not be changed: {result['error']}"
    if str(after) != str(wanted):
        return "failed", (f"The setting is still {_shown(after)} (wanted {wanted}). A company policy (Group Policy or "
                          "Intune) or Defender's tamper protection may be setting it back.")
    if str(before) == str(wanted):
        return "done", (f"Already set correctly on the computer ({wanted}); Defender's data was older and its next "
                        "check will clear it.")
    return "done", f"Changed from {_shown(before)} to {after}."


def judge_response(result: dict) -> tuple[str, str]:
    """Scan and clean (a sign of attack): done when the scan ran and Defender lists no active threat afterwards."""
    before, after = int(result.get("before") or 0), int(result.get("after") or 0)
    lab = result.get("lab_cleaned") or []
    also = f" Also removed the lab test's leftovers: {', '.join(lab)}." if lab else ""
    if result.get("error"):
        return "failed", f"The Defender scan could not run: {result['error']}"
    if after:
        names = ", ".join(result.get("found") or []) or "see Defender"
        return "failed", f"Scanned, but Defender still lists {after} active threat{'s' * (after != 1)} ({names}). " \
                         "Look at the computer in Defender; isolate it there if needed."
    if before:
        return "done", f"Scanned and cleaned: Defender removed {before} active threat{'s' * (before != 1)}.{also}"
    if lab:
        return "done", f"Scanned with Defender: no active threat found.{also}"
    return "done", "Scanned with Defender: no active threat found on the computer."


def _remediation_ai(settings: Settings):
    """The Remediation Agent's model: the suite's Azure AI Foundry deployment (AI_PROVIDER), or None (standard scans)."""
    from uc1.ai.azure_client import make_client
    from uc1.ai.gemini_client import AIUnavailable
    try:
        return make_client(settings)
    except AIUnavailable as exc:
        log.info("Remediation Agent without AI: %s", exc)
        return None


class FixRunner:
    def __init__(self, settings: Settings, executor_factory: Callable = make_executor, on_step: Callable[[str], None] | None = None,
                 ai=None):
        self.settings = settings
        self.ai = ai if ai is not None else _remediation_ai(settings)
        self.state = FixState(settings.fix_dir / "state.json")
        self.factory = executor_factory
        self.on_step = on_step or (lambda text: None)
        self._executors: dict[str, object] = {}
        self._lock = threading.Lock()

    def executor(self, method: str):
        with self._lock:
            if method not in self._executors:
                self._executors[method] = self.factory(method, self.settings)
            return self._executors[method]

    def _say(self, text: str, fix_id: str | None = None) -> None:
        log.info(text)
        self.on_step(text)
        with self.state.edit() as data:
            event(data, text, fix_id)

    # ---------------------------------------------------------- fixes
    def run_approved(self, ids: list[str] | None = None) -> dict:
        with fix_lock(self.settings):
            return self._run_approved(ids)

    def _run_approved(self, ids: list[str] | None) -> dict:
        with self.state.edit() as data:
            for fid, f in data["fixes"].items():            # left over from a run that was killed
                if f.get("status") in ("queued", "running"):
                    f.update(status="failed", message="Interrupted (the Threat Intel Agent stopped while this remediation was running). "
                                                      "Approve it again to retry.", finished_at=utcnow().isoformat())
            todo = [(fid, f) for fid, f in data["fixes"].items()
                    if f.get("status") == "approved" and (ids is None or fid in ids)]
            for fid, f in todo:
                f["status"] = "queued"
        if not todo:
            return {"ran": 0, "done": 0, "failed": 0}
        by_device: dict[str, list] = defaultdict(list)
        for fid, f in todo:
            by_device[f["item"]["device_name"]].append((fid, f))
        for items in by_device.values():                 # urgent first on each computer
            items.sort(key=lambda x: (x[1]["item"].get("stage", 3), -x[1]["item"].get("findings", 0)))
        results: dict[str, str] = {}
        threads = [threading.Thread(target=self._device_worker, args=(dev, items, results), daemon=True)
                   for dev, items in by_device.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        summary = {"ran": len(results), "done": sum(1 for s in results.values() if s == "done"),
                   "failed": sum(1 for s in results.values() if s == "failed")}
        self._say(f"Remediation run finished: {summary['done']} remediated, {summary['failed']} failed. "
                  "Defender confirms within a few hours (next UC1 run).")
        started = sorted({vm for ex in self._executors.values() for vm in getattr(ex, "started", set())})
        if started:
            self._say(f"The Threat Intel Agent started {', '.join(started)} for these remediations. Keep it running for about 6 "
                      "hours so Defender can scan it and verify the remediations, then stop it in the Azure portal to save cost.")
        return summary

    def _device_worker(self, device: str, items: list, results: dict) -> None:
        for fid, f in items:
            item, method = f["item"], f.get("method") or self.settings.fix_method
            # today's settings win over the ones frozen at approval time (e.g. Chocolatey switched off since)
            spec = {**f["spec"], "allow_choco": self.settings.fix_allow_choco}
            with self.state.edit() as data:
                data["fixes"][fid].update(status="running", started_at=utcnow().isoformat())
            what = f"change setting '{item['app']}'" if item["action"] == "setting" else \
                f"scan and clean after '{item['app']}'" if item["action"] == "respond" else \
                f"{item['action']} {item['app']} {item['version']}"
            self._say(f"{device}: {what} via {method}", fid)
            moves = None
            if item["action"] == "respond":
                status, message, result, output, moves = self._respond(device, fid, item, method, spec)
            else:
                status, message, result, output = self._attempt(device, fid, item, method, spec)
            with self.state.edit() as data:
                data["fixes"][fid].update(status=status, message=message[:600], finished_at=utcnow().isoformat(),
                                          result=result, output=(output or "")[-3000:],
                                          **({"agent": moves} if moves is not None else {}))
            self._say(f"{device}: {' '.join(p for p in (item['app'], item.get('version')) if p)} -> {status}: {message}", fid)
            results[fid] = status

    def _attempt(self, device: str, fid: str, item: dict, method: str, spec: dict) -> tuple[str, str, dict | None, str]:
        """Run the fixed script once on the computer and judge what it reports."""
        output, result = "", None
        try:
            output = self.executor(method).run(device, item["device_id"], spec, say=lambda t: self._say(t, fid))
            result = parse_result(output)
            status, message = judge(item["action"], result)
        except FixError as exc:
            status, message = "failed", str(exc)
        except Exception as exc:  # noqa: BLE001 - one failed fix must not stop the others
            log.exception("Remediation %s failed unexpectedly", fid)
            status, message = "failed", f"{exc.__class__.__name__}: {exc}"
        return status, message, result, output

    def _respond(self, device: str, fid: str, item: dict, method: str, spec: dict):
        """Scan and clean until Defender lists no active threat. The Remediation Agent (Azure AI Foundry) picks each
        move from the evidence and the results so far, but only from quick scan / full scan / stop: the script and
        what it does stay fixed. Without the AI (or when it fails) the moves follow RESPONSE_LADDER."""
        from uc1.ai.gemini_client import AIUnavailable
        from uc1.ai.prompts import REMEDIATE_SYSTEM, remediate_prompt
        from uc1.ai.schemas import RemediationMove
        system = REMEDIATE_SYSTEM.replace("{max_moves}", str(len(RESPONSE_LADDER)))
        evidence = "\n".join(f"{k}: {v}" for k, v in (("Device", device), ("Sign of attack", item.get("app")),
                                                       ("Type", item.get("category")), ("Evidence", item.get("note"))) if v)
        moves: list[dict] = []
        status, message, result, output, summary = "failed", "No scan ran.", None, "", ""
        while len([m for m in moves if m["action"] != "stop"]) < len(RESPONSE_LADDER):
            scans = len(moves)
            fallback = RESPONSE_LADDER[scans]
            move = None
            if self.ai is not None:
                history = "\n".join(f"{i}. {m['action']}: {m['result']}" for i, m in enumerate(moves, 1))
                try:
                    move = self.ai.json("remediate", system, remediate_prompt(evidence, history), RemediationMove, max_tokens=400)
                except AIUnavailable as exc:
                    self._say(f"{device}: Remediation Agent unavailable ({exc}); using the standard scans", fid)
                    self.ai = None
            action = move.action.strip().lower() if move else ("quick_scan" if fallback == "QuickScan" else "full_scan")
            if status == "done" or (action == "stop" and scans):    # clean (or the agent is done): only its summary is left
                if move and action == "stop":
                    summary = move.summary or move.reason
                    moves.append({"action": "stop", "reason": move.reason, "result": summary})
                break
            if action not in ("quick_scan", "full_scan"):       # anything else (or stop before any scan): the standard move
                action = "quick_scan" if fallback == "QuickScan" else "full_scan"
            reason = move.reason if move else "Standard sequence (no AI)"
            self._say(f"{device}: Remediation Agent: {action.replace('_', ' ')} ({reason})", fid)
            status, message, result, output = self._attempt(
                device, fid, item, method, {**spec, "scan": "FullScan" if action == "full_scan" else "QuickScan"})
            moves.append({"action": action, "reason": reason, "result": message, "status": status})
            with self.state.edit() as data:          # the card shows each move as it happens
                data["fixes"][fid]["agent"] = list(moves)
            if status == "done" and self.ai is None:
                break
        scans = [m for m in moves if m["action"] != "stop"]
        message = f"{summary} " if summary else ""
        message += f"After {len(scans)} scan{'s' * (len(scans) != 1)}: {scans[-1]['result'] if scans else message}"
        return status, message, result, output, moves

    # ---------------------------------------------------------- probe (read-only check)
    def probe(self, method: str | None = None, devices: list[str] | None = None) -> dict:
        with fix_lock(self.settings):
            return self._probe(method or self.settings.fix_method, devices)

    def _probe(self, method: str, devices: list[str] | None) -> dict:
        plan_items = read_plan(self.settings).get("items", [])
        targets = {i["device_name"]: i["device_id"] for i in plan_items}
        if devices:
            targets = {d: i for d, i in targets.items() if d in devices}
        spec = probe_spec(load_catalog())
        out: dict[str, dict] = {}

        def one(device: str, device_id: str) -> None:
            self._say(f"{device}: checking the device (read-only) via {method}")
            try:
                ex = self.executor(method)
                # read-only means read-only: the check never switches a VM on (fix runs may, see FIX_START_VMS)
                kwargs = {"allow_start": False} if getattr(ex, "can_start_vms", False) else {}
                text = ex.run(device, device_id, spec, say=self._say, **kwargs)
                result = parse_result(text) or {"error": "no result", "output": text[-1500:]}
            except Exception as exc:  # noqa: BLE001
                result = {"error": str(exc)}
            result.update(method=method, checked_at=utcnow().isoformat())
            out[device] = result
            with self.state.edit() as data:
                data.setdefault("probes", {})[device] = result
            self._say(f"{device}: check {'failed: ' + result['error'] if result.get('error') else 'ok'}")

        threads = [threading.Thread(target=one, args=(d, i), daemon=True) for d, i in targets.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return out
