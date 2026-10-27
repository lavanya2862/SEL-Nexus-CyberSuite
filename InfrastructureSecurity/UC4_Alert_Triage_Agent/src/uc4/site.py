"""The Alert Triage Agent's service for the portal: `python -m uc4 serve` -> http://127.0.0.1:8900 (this computer only).

The portal is the only user interface; this service has no web pages, only the API the portal calls:
  GET  /api/status       run in progress? last run?
  GET  /api/queue        every triaged incident with its verdict and the latest analyst feedback
  POST /api/run          start a run now (header X-UC4: run)
  POST /api/feedback     analyst agree/disagree (header X-UC4: feedback)
  POST /api/contain      human-approved isolate/release of a LAB device (header X-UC4: contain; off unless UC4_CONTAIN=1)
  POST /api/close        close an incident in Defender (header X-UC4: close; off unless switched on)
  POST /api/reopen       reopen an automatically closed incident (header X-UC4: reopen)
  POST /api/ask          "Ask about this incident": the AI answers from the incident's saved evidence (header X-UC4: ask)

Design (as UC1): runs export files (data/export/*.json, data/verdicts/*.json, data/last_run.json) and the service only
reads those plus the feedback files it appends to. It never opens the database, so it can't block a scheduled run.
Security: listens on 127.0.0.1 only; the Host header must name this computer (blocks DNS rebinding); every POST
needs a custom header (other websites can't send it).
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from uc4 import feedback
from uc4.config import Settings
from uc4.triage import _safe

log = logging.getLogger("uc4.site")
DEFAULT_PORT = 8900
HEADER = "X-UC4"


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


class Site(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, settings: Settings, runner=None, defender_factory=None, graph_factory=None,
                 llm_factory=None):
        super().__init__(address, _Handler)
        self.settings = settings
        self.runner = runner or self._default_runner
        self.defender_factory = defender_factory or self._default_defender
        self.graph_factory = graph_factory or self._default_graph
        self._run_thread: threading.Thread | None = None
        self._run_error: str | None = None
        self._lock = threading.Lock()
        self.llm_factory = llm_factory or self._default_llm
        self._llm = None

    # ---------- data ----------
    def triage_data(self) -> dict:
        data = _read_json(self.settings.export_dir / "triage_data.json", {"queue": [], "totals": {}, "by_verdict": {}})
        latest = feedback.latest_by_incident(self.settings)      # show clicks immediately, before the next run
        for row in data.get("queue", []):
            if row["incident_id"] in latest:
                f = latest[row["incident_id"]]
                row["feedback"] = {"agree": f.get("agree"), "analyst_verdict": f.get("analyst_verdict")}
        data["status"] = self.status()
        data["flags"] = {"contain": self.settings.contain, "writeback": self.settings.writeback,
                         "close": self.settings.close, "auto_resolve": self.settings.auto_resolve}
        return data

    def incident(self, incident_id: str) -> dict | None:
        path = self.settings.verdicts_dir / f"{_safe(incident_id)}.json"
        data = _read_json(path, None)
        if data is None:
            return None
        data["feedback"] = [r for r in feedback.read_jsonl(self.settings.feedback_dir / "feedback.jsonl")
                            if r.get("incident_id") == data["packet"]["incident_id"]]
        data["actions"] = [r for r in feedback.read_jsonl(self.settings.feedback_dir / "actions.jsonl")
                           if r.get("incident_id") == data["packet"]["incident_id"]]
        from uc4.close import DETERMINATIONS
        from uc4.uc1link import fixes_for
        data["flags"] = {"contain": self.settings.contain, "close": self.settings.close,
                         "auto_resolve": self.settings.auto_resolve,
                         "lab_devices": list(self.settings.lab_devices)}
        data["determinations"] = DETERMINATIONS
        data["defender"] = _read_json(self.settings.verdicts_dir / f"{_safe(incident_id)}.defender.json", None)
        data["uc1"] = fixes_for(self.settings.uc1_dir, [d.get("name") for d in data["packet"]["entities"]["devices"]])
        from uc4.ask import history
        data["questions"] = history(self.settings, data["packet"]["incident_id"])
        data["flags"]["ask"] = self.settings.has_ai
        data["status"] = self.status()
        return data

    # ---------- runs ----------
    def status(self) -> dict:
        from uc4.pipeline import lock_active
        running_here = bool(self._run_thread and self._run_thread.is_alive())
        return {"running": running_here or lock_active(self.settings),
                "last_run": _read_json(self.settings.data_dir / "last_run.json", None),
                "error": self._run_error}

    def _default_runner(self, settings: Settings) -> dict:
        from uc4.pipeline import run
        return run(settings)

    def start_run(self) -> tuple[bool, str]:
        with self._lock:
            if self.status()["running"]:
                return False, "A run is already in progress."
            self._run_error = None
            self._run_thread = threading.Thread(target=self._run, daemon=True)
            self._run_thread.start()
        return True, "Run started."

    def _run(self) -> None:
        try:
            self.runner(self.settings)
        except Exception as exc:  # noqa: BLE001
            log.error("Run from the website failed: %s", exc)
            self._run_error = str(exc).splitlines()[0][:200]

    def ask(self, incident_id: str, question: str) -> dict:
        from uc4.ask import ask
        data = self.incident(incident_id)
        if data is None:
            from uc4.ask import AskError
            raise AskError("unknown incident")
        with self._lock:
            if self._llm is None:
                self._llm = self.llm_factory()
        return ask(self.settings, self._llm, data, question, cap=self.settings.ask_daily_cap)

    def _default_llm(self):
        from uc4.llm import make_llm
        return make_llm(self.settings)

    def _default_graph(self):
        from uc4.api import graph_client
        from uc4.auth import EntraLogin
        return graph_client(self.settings, EntraLogin(self.settings))

    def _default_defender(self):
        from uc4.api import DefenderClient
        from uc4.auth import DEFENDER_SCOPE, EntraLogin
        return DefenderClient(self.settings.defender_base, EntraLogin(self.settings).provider(DEFENDER_SCOPE))


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
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload, default=str).encode(), "application/json")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        return host in ("127.0.0.1", "localhost")

    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": "forbidden host"})
        path = unquote(self.path.split("?")[0].split("#")[0])
        s = self.server
        if path == "/api/status":
            return self._json(200, s.status())
        if path == "/api/queue":
            return self._json(200, s.triage_data())
        return self._json(404, {"error": "not found"})

    def _body(self) -> dict:
        length = min(int(self.headers.get("Content-Length") or 0), 32_000)
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            return body if isinstance(body, dict) else {}
        except ValueError:
            return {}

    def do_POST(self):
        if not self._host_ok():
            return self._json(403, {"error": "forbidden host"})
        path = self.path.split("?")[0]
        expected = {"/api/run": "run", "/api/feedback": "feedback", "/api/contain": "contain", "/api/close": "close",
                    "/api/reopen": "reopen", "/api/ask": "ask"}.get(path)
        if expected is None:
            return self._json(404, {"error": "not found"})
        if self.headers.get(HEADER) != expected:
            return self._json(403, {"error": "missing header"})
        s, body = self.server, self._body()
        if path == "/api/run":
            started, message = s.start_run()
            return self._json(202 if started else 409, {"started": started, "message": message, **s.status()})
        if path == "/api/ask":
            from uc4.ask import AskError
            try:
                row = s.ask(str(body.get("incident_id") or ""), str(body.get("question") or ""))
            except AskError as exc:
                return self._json(400, {"error": str(exc)})
            return self._json(200, {"saved": row})
        if path == "/api/feedback":
            incident_id = str(body.get("incident_id") or "")
            if not incident_id or s.incident(incident_id) is None:
                return self._json(400, {"error": "unknown incident"})
            try:
                row = feedback.add_feedback(s.settings, incident_id, bool(body.get("agree")),
                                            body.get("analyst_verdict") or None, str(body.get("reason") or ""),
                                            body.get("minutes") if body.get("minutes") not in ("", None) else None,
                                            str(body.get("mode") or "assisted"))
            except (ValueError, TypeError) as exc:
                return self._json(400, {"error": str(exc)})
            return self._json(200, {"saved": row})
        if path in ("/api/close", "/api/reopen"):
            if body.get("confirm") is not True:
                return self._json(400, {"error": "confirmation missing"})
            incident_id = str(body.get("incident_id") or "")
            if not incident_id or s.incident(incident_id) is None:
                return self._json(400, {"error": "unknown incident"})
            if path == "/api/close":
                from uc4.close import CloseError, act as close_act
                minutes = body.get("minutes")
                try:
                    result = close_act(s.settings, s.graph_factory(), incident_id, str(body.get("verdict") or ""),
                                       body.get("determination"), str(body.get("reason") or "")[:500],
                                       float(minutes) if minutes not in (None, "") else None)
                except (CloseError, ValueError, TypeError) as exc:
                    return self._json(400, {"error": str(exc)})
                return self._json(200, result)
            if not (s.settings.close or s.settings.auto_resolve):
                return self._json(400, {"error": "Writing to Defender is switched off."})
            from uc4.autoresolve import reopen
            try:
                row = reopen(s.settings, s.graph_factory(), incident_id, str(body.get("reason") or ""))
            except Exception as exc:  # noqa: BLE001
                return self._json(400, {"error": f"Defender refused: {str(exc).splitlines()[0][:200]}"})
            return self._json(200, {"action": row})
        # /api/contain
        from uc4.contain import ContainError, act
        if body.get("confirm") is not True:
            return self._json(400, {"error": "confirmation missing"})
        try:
            row = act(s.settings, s.defender_factory(), str(body.get("incident_id") or ""),
                      str(body.get("device") or ""), str(body.get("action") or ""))
        except ContainError as exc:
            return self._json(400, {"error": str(exc)})
        return self._json(200, {"action": row})


def serve(settings: Settings, port: int = DEFAULT_PORT) -> None:
    settings.ensure_dirs()
    server = Site(("127.0.0.1", port), settings)
    print(f"Alert Triage Agent service on http://127.0.0.1:{server.server_address[1]}/api (this computer only). "
          "Keep this window open; Ctrl+C stops it.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
