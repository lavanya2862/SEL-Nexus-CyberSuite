"""Keep the services behind the portal running, so nobody has to switch anything on.

The portal relies on two background services: the fixing service (UC1's site, Fix) and the alert-triage
service (UC4's site: agree/disagree, Ask, Reopen). `python -m portal serve` starts a watcher thread that starts
either one when it is not answering, at start-up and then every CHECK_EVERY seconds. Each service is started with its
own Python, handed to Windows so it keeps running on its own (see _launch); 127.0.0.1 only. Switch off with PORTAL_AUTOSTART=0.
"""
from __future__ import annotations

import base64
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from portal import fixproxy, uc4proxy

log = logging.getLogger("portal.services")

CHECK_EVERY = 30
_lock = threading.Lock()


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
    return {"fixing": (settings.uc1_site, settings.uc1_dir, "uc1"), "triage": (settings.uc4_site, settings.uc4_dir, "uc4")}


ERRORS = {"fixing": fixproxy.Uc1Unavailable, "triage": uc4proxy.Uc4Unavailable}


def start_one(settings, name: str, wait_s: float = 15) -> bool:
    """Start one service if it isn't answering (one start at a time, so two pages can't start it twice).
    Raises Uc1Unavailable / Uc4Unavailable when it can't be started at all."""
    base, folder, module = _services(settings)[name]
    with _lock:
        if listening(base):
            return True
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
        except (fixproxy.Uc1Unavailable, uc4proxy.Uc4Unavailable, OSError) as exc:
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
