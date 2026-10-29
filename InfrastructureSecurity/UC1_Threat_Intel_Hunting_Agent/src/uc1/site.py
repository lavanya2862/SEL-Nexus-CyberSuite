"""The Threat Intel Agent's service for the portal: `python -m uc1 serve` -> http://127.0.0.1:8700 (this computer only).

The portal is the only user interface; this service has no web pages, only the API the portal calls:
  GET  /api/status       is a run in progress (here or by the scheduled task)? which step? last run?
  POST /api/run          start a run now (same job as `uc1 run`; one at a time; needs the X-UC1 header)
  GET  /api/fix          fix engine: plan + approvals + results + what the fixer is doing
  POST /api/fix/approve | /api/fix/unapprove | /api/fix/save | /api/fix/unsave | /api/fix/run | /api/fix/probe
                         (need the header X-UC1: fix; save = "Save for later" on a new fix)

Design: every run exports its data to files (data/dashboard/*.json) and the portal reads those directly; this
service never opens the database, so it can't block the scheduled run.
Security: listens on 127.0.0.1 only; requests must name this host (blocks DNS-rebinding tricks); every POST
requires a custom header (other websites can't send it).
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from uc1.config import Settings
from uc1.store import Store

log = logging.getLogger("uc1.site")
DEFAULT_PORT = 8700
RUN_HEADER = ("X-UC1", "run")
FIX_HEADER = ("X-UC1", "fix")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_runner(settings: Settings) -> dict:
    """The same job as `uc1 run`, in this process."""
    from uc1.pipeline import Pipeline, make_ai, make_defender, run_lock
    with run_lock(settings):
        store = Store(settings.db_path)
        try:
            p = Pipeline(settings, store, defender=make_defender(settings), ai=make_ai(settings, store))
            return p.run_all()
        finally:
            store.close()


class _StepHandler(logging.Handler):
    """Shows the latest step of a run started from the website."""

    def __init__(self, server: "Site"):
        super().__init__(logging.INFO)
        self.server = server

    def emit(self, record: logging.LogRecord) -> None:
        if self.server.running and record.name.startswith("uc1."):
            self.server.step = record.getMessage()[:180]


class Site(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, settings: Settings, runner=None):
        super().__init__(address, _Handler)
        self.settings = settings
        self.runner = runner or (lambda: default_runner(settings))
        self.lock = threading.Lock()
        self.running, self.step, self.started_at, self.finished_at = False, "", None, None
        self.last_outcome, self.last_message = None, ""
        self.fix_running, self.fix_step, self.fix_task, self.fix_message = False, "", "", ""
        self._cache: tuple[float, dict] | None = None
        self._handler = _StepHandler(self)
        logging.getLogger("uc1").addHandler(self._handler)

    # ---------- runs ----------
    def other_run_active(self) -> bool:
        """A run started elsewhere (the scheduled task / a terminal) holds the lock. Stale locks don't count."""
        from uc1.pipeline import lock_active
        return not self.running and lock_active(self.settings)

    def start_run(self) -> tuple[bool, str]:
        if self.other_run_active():
            return False, "A run is already in progress (probably the scheduled task). The page updates when it's done."
        with self.lock:
            if self.running:
                return False, "A run started from this website is already in progress."
            self.running, self.started_at, self.step = True, _now(), "Starting"
        threading.Thread(target=self._run, daemon=True).start()
        return True, "Run started"

    def _run(self) -> None:
        try:
            result = self.runner()
            outcome = result.get("status", "error")
            failed = result.get("failed_steps", []) + result.get("failed_feeds", [])
            message = "Run finished: everything ok" if outcome == "ok" else f"Run finished with problems: {', '.join(failed) or outcome}"
        except Exception as exc:  # noqa: BLE001 - shown on the page; details are in the log
            log.exception("Run from the website failed")
            outcome, message = "error", str(exc).splitlines()[0][:200]
        with self.lock:
            self.running, self.finished_at, self.step = False, _now(), ""
            self.last_outcome, self.last_message = outcome, message

    def status(self) -> dict:
        last = self.settings.data_dir / "last_run.json"
        return {"running": self.running, "scheduled_running": self.other_run_active(),
                "step": self.step, "started_at": self.started_at, "finished_at": self.finished_at,
                "last_outcome": self.last_outcome, "last_message": self.last_message,
                "last_run": json.loads(last.read_text(encoding="utf-8")) if last.is_file() else None}

    # ---------- fix loop ----------
    def fix_view(self) -> dict:
        from uc1.fix.plan import view
        from uc1.fix.runner import fix_active
        v = view(self.settings)
        v["worker"] = {"running": self.fix_running, "elsewhere": not self.fix_running and fix_active(self.settings),
                       "task": self.fix_task, "step": self.fix_step, "message": self.fix_message}
        return v

    def start_fix(self, task: str, method: str | None = None, ids: list[str] | None = None) -> tuple[bool, str]:
        """Check the computers, or run the approved fixes: all of them, or only `ids` (a run page runs just its own)."""
        from uc1.fix.runner import FixRunner, fix_active
        if fix_active(self.settings) and not self.fix_running:
            return False, "Fixes are already running from the command line."
        with self.lock:
            if self.fix_running:
                return False, "The fixer is already busy."
            self.fix_running, self.fix_task, self.fix_step, self.fix_message = True, task, "Starting", ""

        def work():
            try:
                runner = FixRunner(self.settings, on_step=lambda text: setattr(self, "fix_step", text[:200]))
                if task == "probe":
                    out = runner.probe(method)
                    bad = [d for d, r in out.items() if r.get("error")]
                    msg = f"Check finished: {len(out) - len(bad)} ok" + (f", problem on {', '.join(bad)}" if bad else "")
                else:
                    r = runner.run_approved(ids or None)
                    msg = f"Remediation run finished: {r['done']} remediated, {r['failed']} failed"
            except Exception as exc:  # noqa: BLE001 - shown on the page; details in the log
                log.exception("Remediation task failed")
                msg = str(exc).splitlines()[0][:200]
            with self.lock:
                self.fix_running, self.fix_step, self.fix_message = False, "", msg

        threading.Thread(target=work, daemon=True).start()
        return True, "Started"

    def server_close(self) -> None:
        logging.getLogger("uc1").removeHandler(self._handler)
        super().server_close()


class _Handler(BaseHTTPRequestHandler):
    server: Site

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, default=str).encode(), "application/json")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        return host in ("127.0.0.1", "localhost")

    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": "forbidden host"})
        path = unquote(self.path.split("?")[0].split("#")[0])
        s = self.server
        if path == "/api/status":
            return self._json(200, s.status())
        if path == "/api/fix":
            return self._json(200, s.fix_view())
        return self._json(404, {"error": "not found"})

    def _body(self) -> dict:
        length = min(int(self.headers.get("Content-Length") or 0), 64_000)
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            return body if isinstance(body, dict) else {}
        except ValueError:
            return {}

    def _fix_post(self, path: str):
        from uc1.fix import plan
        if self.headers.get(FIX_HEADER[0]) != FIX_HEADER[1]:
            return self._json(403, {"error": "missing header"})
        s, body = self.server, self._body()
        ids = [str(i) for i in body.get("ids", []) if isinstance(i, str)][:200]
        method = body.get("method") if body.get("method") in ("runcommand", "liveresponse") else None
        by = str(body.get("by") or "").strip()[:80] or None      # the portal's signed-in person
        try:
            if path == "/api/fix/approve":
                result = plan.approve(s.settings, ids, method, by)
            elif path == "/api/fix/unapprove":
                result = plan.unapprove(s.settings, ids, by)
            elif path == "/api/fix/save":
                result = plan.save(s.settings, ids, by)
            elif path == "/api/fix/unsave":
                result = plan.unsave(s.settings, ids, by)
            elif path in ("/api/fix/run", "/api/fix/probe"):
                started, message = s.start_fix("probe" if path.endswith("probe") else "run", method, ids)
                result = {"started": started, "message": message}
            else:
                return self._json(404, {"error": "not found"})
        except (ValueError, TimeoutError) as exc:
            return self._json(400, {"error": str(exc)})
        return self._json(200, {**result, "view": s.fix_view()})

    def do_POST(self):
        if not self._host_ok():
            return self._json(403, {"error": "forbidden host"})
        path = self.path.split("?")[0]
        if path.startswith("/api/fix/"):
            return self._fix_post(path)
        if path != "/api/run":
            return self._json(404, {"error": "not found"})
        if self.headers.get(RUN_HEADER[0]) != RUN_HEADER[1]:
            return self._json(403, {"error": "missing header"})
        started, message = self.server.start_run()
        self._json(202 if started else 409, {"started": started, "message": message, **self.server.status()})


def serve(settings: Settings, port: int = DEFAULT_PORT) -> None:
    server = Site(("127.0.0.1", port), settings)
    print(f"Threat Intel Agent service on http://127.0.0.1:{server.server_address[1]}/api  (local access only). "
          "Keep this window open; press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
