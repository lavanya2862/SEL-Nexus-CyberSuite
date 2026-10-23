"""Live mode: `python -m uc3 serve` — the dashboard as a local web page with a "Refresh from Defender now" button.

  http://127.0.0.1:8600/            the latest dashboard (+ live controls)
  GET  /api/status                  is a fetch running? which step? when was the dashboard last rebuilt?
  POST /api/refresh                 start a fetch now (same job as `uc3 run`; one at a time)

The page checks /api/status every few seconds and reloads itself as soon as a newer dashboard exists — whether
the new data came from the button or from the scheduled task. The server listens on 127.0.0.1 only (this
machine); the refresh endpoint requires a custom header, so other websites can't trigger it from a browser.
"""

from __future__ import annotations

import json
import logging
import threading
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from uc3.config import Settings
from uc3.status import read_status

log = logging.getLogger("uc3.live")
DEFAULT_PORT = 8600
REFRESH_HEADER = ("X-UC3", "refresh")
NO_DASHBOARD = """<!doctype html><html><head><meta charset="utf-8"><title>Vulnerability Command Centre</title></head>
<body style="font-family:system-ui;background:#0b1120;color:#f3f5fa;padding:40px">
<h2>No dashboard yet</h2><p>Click the button to fetch data from Microsoft Defender for the first time.</p>
<div class="top"></div><script>window.D = null;</script></body></html>"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class LiveState:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.started_at: str | None = None
        self.finished_at: str | None = None
        self.step = ""
        self.last_outcome: str | None = None
        self.last_message = ""


class _StepHandler(logging.Handler):
    """Keeps the latest pipeline log message as the 'current step' shown on the page."""

    def __init__(self, state: LiveState):
        super().__init__(logging.INFO)
        self.state = state

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith("uc3") and self.state.running:
            self.state.step = record.getMessage()[:160]


class LiveServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, settings: Settings, runner=None):
        super().__init__(address, _Handler)
        from uc3.pipeline import daily_job
        self.settings = settings
        self.runner = runner or daily_job
        self.state = LiveState()
        self._step_handler = _StepHandler(self.state)
        logging.getLogger("uc3").addHandler(self._step_handler)

    @property
    def dashboard(self):
        return self.settings.data_dir / "dashboard" / "UC3_Dashboard_latest.html"

    def dashboard_mtime(self) -> float:
        return self.dashboard.stat().st_mtime if self.dashboard.is_file() else 0.0

    def start_refresh(self) -> bool:
        with self.state.lock:
            if self.state.running:
                return False
            self.state.running, self.state.started_at, self.state.step = True, _now(), "Starting"
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def _run(self) -> None:
        try:
            job = self.runner()
            outcome = job.get("outcome", "error")
            message = job.get("message") or {"published": "New data published",
                                              "quality_failed": "A quality check failed; nothing was published"}.get(outcome, "")
        except Exception as exc:   # the runner records its own errors; this is a last safety net
            log.exception("Live refresh crashed")
            outcome, message = "error", str(exc)
        with self.state.lock:
            self.state.running, self.state.finished_at = False, _now()
            self.state.last_outcome, self.state.last_message, self.state.step = outcome, message, ""

    def status(self) -> dict:
        s = self.state
        return {"running": s.running, "started_at": s.started_at, "finished_at": s.finished_at, "step": s.step,
                "last_outcome": s.last_outcome, "last_message": s.last_message,
                "dashboard_mtime": self.dashboard_mtime(), "last_run": read_status(self.settings)}

    def server_close(self) -> None:
        logging.getLogger("uc3").removeHandler(self._step_handler)
        super().server_close()


class _Handler(BaseHTTPRequestHandler):
    server: LiveServer

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self):
        path = self.path.split("?")[0].split("#")[0]
        if path in ("/", "/index.html"):
            server = self.server
            html = server.dashboard.read_text(encoding="utf-8") if server.dashboard.is_file() else NO_DASHBOARD
            flag = f"<script>window.UC3_LIVE = {{mtime: {server.dashboard_mtime()}}};</script>"
            html = html.replace("</head>", flag + "\n</head>", 1)
            if not server.dashboard.is_file():
                html = html.replace("</body>", _MINI_LIVE_SCRIPT + "</body>", 1)
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/status":
            self._json(200, self.server.status())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?")[0] != "/api/refresh":
            return self._json(404, {"error": "not found"})
        if self.headers.get(REFRESH_HEADER[0]) != REFRESH_HEADER[1]:
            return self._json(403, {"error": "missing header"})
        started = self.server.start_refresh()
        self._json(202 if started else 409, {"started": started, **self.server.status()})


# Minimal controls for the "no dashboard yet" page (the full dashboard has its own live controls in app.js).
_MINI_LIVE_SCRIPT = """<script>
const b = document.createElement('button'); b.textContent = 'Refresh from Defender now'; b.style.cssText='padding:8px 14px';
const p = document.createElement('p'); document.querySelector('.top').append(b, p);
b.onclick = () => fetch('/api/refresh', {method: 'POST', headers: {'X-UC3': 'refresh'}});
setInterval(async () => { const s = await (await fetch('/api/status')).json();
  p.textContent = s.running ? 'Fetching… ' + s.step : (s.last_message || '');
  if (s.dashboard_mtime > window.UC3_LIVE.mtime) location.reload(); }, 3000);
</script>"""


def serve(settings: Settings, port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    server = LiveServer(("127.0.0.1", port), settings)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"Live dashboard running at {url}  (this machine only). Press Ctrl+C to stop.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
