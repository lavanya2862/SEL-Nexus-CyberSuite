"""Keep the services behind the portal running, so nobody has to switch anything on.

The portal relies on two background services: the fixing service (Threat Intel's site, Fix) and the alert-triage
service (Alert Triage's site: agree/disagree, Ask, Reopen). `python -m dashboard serve` starts a watcher thread that starts
either one when it is not answering, at start-up and then every CHECK_EVERY seconds. Each service is started with its
own Python, handed to Windows so it keeps running on its own (see _launch); 127.0.0.1 only. Switch off with PORTAL_AUTOSTART=0.

A service that holds its port but no longer answers its API (for example an old copy left running after a code
update) is stopped and started again once it has failed STRIKES checks in a row; only a `<module> serve` process
from that service's own folder is stopped, and never the fixing service while it is running remediations.
"""
from __future__ import annotations

import base64
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from dashboard import fixproxy, triageproxy

log = logging.getLogger("dashboard.services")

CHECK_EVERY = 30
STRIKES = 2          # failed API checks in a row before a stuck service is restarted
_lock = threading.Lock()
_strikes: dict[str, int] = {}


def listening(base: str, timeout: float = 1.0) -> bool:
    """Is something answering on this site's host and port?"""
    u = urlparse(base)
    try:
        with socket.create_connection((u.hostname or "127.0.0.1", u.port or 80), timeout=timeout):
            return True
    except OSError:
        return False


def _python(folder: Path) -> Path | None:
    for rel in (".venv/Scripts/python.exe", ".venv/bin/python"):
        if (folder / rel).is_file():
            return folder / rel
    return None


def _launch(cmd: list[str], cwd: Path) -> None:
    """Start a service so it outlives whoever started it.

    A plain child process dies with the portal (or with the console/job that launched the portal), so on Windows we
    ask Windows itself to start it (WMI Win32_Process.Create, the same way agent runs are started). Fallback: a
    detached child that breaks away from the job when allowed.
    """
    if sys.platform == "win32":
        q = lambda v: v.replace("'", "''")  # noqa: E731 - PowerShell single-quote escaping
        script = (
            "$si = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ShowWindow=[uint16]0};"
            f"$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine='{q(subprocess.list2cmdline(cmd))}';"
            f"CurrentDirectory='{q(str(cwd))}';ProcessStartupInformation=$si}};"
            "exit [int]$r.ReturnValue"
        )
        try:
            done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                                   base64.b64encode(script.encode("utf-16-le")).decode()],
                                  capture_output=True, timeout=30, creationflags=0x08000000)
            if done.returncode == 0:
                return
        except (OSError, subprocess.SubprocessError):
            pass
        flags = 0x00000008 | 0x00000200 | 0x08000000      # DETACHED_PROCESS | NEW_PROCESS_GROUP | NO_WINDOW
        kwargs = dict(cwd=str(cwd), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        try:
            subprocess.Popen(cmd, creationflags=flags | 0x01000000, **kwargs)   # + BREAKAWAY_FROM_JOB
        except OSError:
            subprocess.Popen(cmd, creationflags=flags, **kwargs)
    else:
        subprocess.Popen(cmd, cwd=str(cwd), start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _services(settings) -> dict:
    """name -> (site address, folder, module)."""
    return {"fixing": (settings.fix_site, settings.threat_intel_dir, "threat_intel"), "triage": (settings.triage_site, settings.alert_triage_dir, "alert_triage")}


ERRORS = {"fixing": fixproxy.FixUnavailable, "triage": triageproxy.TriageUnavailable}


def answering(name: str, base: str) -> bool:
    """Does the service answer its own API? Listening is not enough: a stuck copy can hold the port and drop requests."""
    if name == "fixing":
        try:
            fixproxy.get_fix(base)
            return True
        except fixproxy.FixUnavailable:
            return False
    return triageproxy.site_up(base)


def _port_owner(base: str) -> tuple[int, str] | None:
    """(PID, command line) of the process listening on this site's port. Windows only; None when unknown."""
    if sys.platform != "win32":
        return None
    port = urlparse(base).port or 80
    script = (
        f"$c = Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1;"
        "if ($c) { $p = Get-CimInstance Win32_Process -Filter \"ProcessId=$($c.OwningProcess)\";"
        " \"$($c.OwningProcess)`n$($p.CommandLine)\" }"
    )
    try:
        done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                               base64.b64encode(script.encode("utf-16-le")).decode()],
                              capture_output=True, text=True, timeout=30, creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError):
        return None
    pid, _, cmd = done.stdout.strip().partition("\n")
    return (int(pid), cmd.strip()) if pid.strip().isdigit() else None


def _fix_lock_pid(folder: Path) -> int | None:
    """The PID in Threat Intel's fix-run lock (data/fix/.fix.lock), if any: that process is remediating devices right now."""
    try:
        return int((folder / "data" / "fix" / ".fix.lock").read_text().strip() or 0) or None
    except (OSError, ValueError):
        return None


def _stop_stuck(name: str, base: str, folder: Path, module: str) -> bool:
    """Stop the stuck copy of this service so a fresh one can take its port. True once the port is free."""
    owner = _port_owner(base)
    if owner is None:
        log.warning("The %s service is not answering, and the process holding its port could not be found", name)
        return False
    pid, cmd = owner
    if f"-m {module} serve" not in cmd or str(folder).lower() not in cmd.lower():
        log.warning("The %s service's port is held by another program (PID %s); leaving it running", name, pid)
        return False
    if name == "fixing" and _fix_lock_pid(folder) == pid:
        log.warning("The %s service is not answering but is running remediations (PID %s); not restarting it", name, pid)
        return False
    log.warning("The %s service is not answering (PID %s); restarting it", name, pid)
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        log.warning("Could not stop the %s service (PID %s): %s", name, pid, exc)
        return False
    deadline = time.monotonic() + 5
    while listening(base) and time.monotonic() < deadline:
        time.sleep(0.2)
    return not listening(base)


def start_one(settings, name: str, wait_s: float = 15) -> bool:
    """Start one service if it isn't answering (one start at a time, so two pages can't start it twice), and restart
    one that holds its port without answering. Raises FixUnavailable / TriageUnavailable when it can't be started at all."""
    base, folder, module = _services(settings)[name]
    with _lock:
        if listening(base):
            if answering(name, base):
                _strikes.pop(name, None)
                return True
            _strikes[name] = _strikes.get(name, 0) + 1
            if _strikes[name] < STRIKES or not _stop_stuck(name, base, folder, module):
                return False
            _strikes.pop(name, None)
        python = _python(folder)
        if python is None:
            raise ERRORS[name](f"The {name} service has no Python environment in {folder}")
        _launch([str(python), "-m", module, "serve"], folder)
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            if listening(base):
                log.info("Started the %s service", name)
                return True
            time.sleep(0.5)
        log.warning("Started the %s service, but it is not answering yet", name)
        return False


def ensure(settings) -> dict[str, bool]:
    """Start whichever service is down. Returns {name: answering}. Safe to call often."""
    out = {}
    for name in _services(settings):
        try:
            out[name] = start_one(settings, name)
        except (fixproxy.FixUnavailable, triageproxy.TriageUnavailable, OSError) as exc:
            out[name] = False
            log.warning("Could not start the %s service: %s", name, exc)
    return out


def autostart_enabled() -> bool:
    return os.environ.get("PORTAL_AUTOSTART", "1").lower() not in ("0", "off", "false", "no")


def start_watcher(settings) -> threading.Thread | None:
    if not autostart_enabled():
        return None
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            try:
                ensure(settings)
            except Exception:  # noqa: BLE001 - the watcher must never take the portal down
                log.exception("Service check failed")
            stop.wait(CHECK_EVERY)

    t = threading.Thread(target=loop, name="portal-services", daemon=True)
    t.start()
    return t
