"""The UC1 website: `python -m uc1 serve` -> http://127.0.0.1:8700 (this computer only).

  /                      Threat Command Centre (live: "Run now" button, reloads itself when new data arrives)
  /threat/<id>           detail page per threat: rating reasons, AI extraction, CVEs, exposure, hits, queries, source text
  /reports               reports, spot-check workbooks, demo notes, alerts - ready to download
  /files/reports/<name>  download from data/reports (pdf, docx, xlsx only)
  /files/data/<name>     demo_notes.md, alerts.jsonl, metrics.json
  GET  /api/status       is a run in progress (here or by the scheduled task)? which step? last run?
  POST /api/run          start a run now (same job as `uc1 run`; one at a time; needs the X-UC1 header)
  /fix                   Fix Centre: the fix plan, approve fixes, run them on the lab VMs, see results
  GET  /api/fix          plan + approvals + results + what the fixer is doing
  POST /api/fix/approve | /api/fix/unapprove | /api/fix/run | /api/fix/probe   (need the header X-UC1: fix)

Design: every run exports the website's data to files (data/dashboard/dashboard.html + site_data.json), and the
server only reads those files. It never opens the database, so it can't block the scheduled run.
Security: listens on 127.0.0.1 only; requests must name this host (blocks DNS-rebinding tricks); the run endpoint
requires a custom header (other websites can't trigger it); downloads are limited to a fixed folder and file types;
every value is escaped before it's shown.
"""

from __future__ import annotations

import json
import logging
import threading
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from uc1.config import Settings
from uc1.report import defang
from uc1.fix_advice import for_threats
from uc1.resolve import for_findings
from uc1.store import Store, utcnow

log = logging.getLogger("uc1.site")
ASSETS = Path(__file__).parent / "site_assets"
DEFAULT_PORT = 8700
RUN_HEADER = ("X-UC1", "run")
FIX_HEADER = ("X-UC1", "fix")
REPORT_TYPES = {".pdf": "application/pdf", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
DATA_FILES = {"demo_notes.md": "text/markdown; charset=utf-8", "alerts.jsonl": "application/json; charset=utf-8",
              "metrics.json": "application/json; charset=utf-8"}


def _j(v):
    return json.loads(v) if isinstance(v, str) else (v if v is not None else [])


# ---------------------------------------------------------------- data export (called after every dashboard build)
def export_site_data(store: Store, settings: Settings) -> Path:
    """Everything the detail pages need, as one JSON file next to the dashboard."""
    q = store.query
    month = utcnow() - timedelta(days=30)
    threats = q("""
        SELECT t.threat_id, t.title, t.source, t.kind, t.url, t.published_at, t.first_seen_at, t.is_test, t.text,
               s.score, s.rating, s.factors, s.why, a.summary, a.threat_type, a.techniques AS ai_techniques,
               a.actions, a.confidence, a.ai_status, a.ai_model, a.dropped, a.analysed_at
        FROM threats t LEFT JOIN scores s USING (threat_id) LEFT JOIN analysis a USING (threat_id)
        WHERE t.first_seen_at >= ? OR t.threat_id IN (SELECT threat_id FROM findings)""", [month])
    ids = {t["threat_id"] for t in threats}
    links: dict[str, dict[str, list]] = {}
    for l in q("SELECT threat_id, link_type, value, origin FROM threat_links"):
        if l["threat_id"] in ids:
            links.setdefault(l["threat_id"], {}).setdefault(l["link_type"], []).append((l["value"], l["origin"]))
    cve_ids = sorted({v for lk in links.values() for v, _ in lk.get("cve", [])})
    cves = {}
    for i in range(0, len(cve_ids), 500):
        chunk = cve_ids[i:i + 500]
        for c in q(f"""SELECT cve_id, cvss, severity, epss, epss_percentile, kev_added, kev_due, kev_ransomware, description
                       FROM cves WHERE cve_id IN ({",".join("?" for _ in chunk)})""", chunk):
            cves[c["cve_id"]] = c
    techniques = {t["technique_id"]: t for t in q("SELECT * FROM attack_techniques")}
    exposure: dict[str, list] = {}
    for e in q("SELECT * FROM exposure ORDER BY device_name"):
        exposure.setdefault(e["threat_id"], []).append({k: e[k] for k in ("device_name", "opco", "match_type", "detail",
                                                                          "recommended_update")})
    findings: dict[str, list] = {}
    resolutions = for_findings(store)
    threat_fixes = for_threats(store)
    for f in q("SELECT * FROM findings WHERE kind <> 'exposure' ORDER BY first_hit DESC NULLS LAST"):
        findings.setdefault(f["threat_id"], []).append({
            "kind": f["kind"], "device": f["device_name"], "opco": f["opco"], "detail": f["detail"], "is_test": f["is_test"],
            "first_hit": f["first_hit"], "hunt_id": f["hunt_id"], "users": _j(f["users"]), "alerts": _j(f["alerts"]),
            "timeline": _j(f["timeline"]), "resolution": resolutions.get(f["finding_id"])})
    hunt_ids = {f["hunt_id"] for fl in findings.values() for f in fl if f["hunt_id"]}
    hunts: dict[str, list] = {}
    for h in q("SELECT * FROM hunts ORDER BY started_at DESC"):
        keys = [h["threat_id"]] if h["threat_id"] in ids else []
        if h["hunt_id"] in hunt_ids:
            keys += [f_tid for f_tid, fl in findings.items() if any(f["hunt_id"] == h["hunt_id"] for f in fl)]
        for key in dict.fromkeys(keys):
            if len(hunts.setdefault(key, [])) < 4:
                hunts[key].append({k: h[k] for k in ("name", "origin", "technique", "status", "row_count", "error",
                                                     "started_at", "query")})

    out = {}
    for t in threats:
        tid = t["threat_id"]
        lk = links.get(tid, {})
        fixes = [e["recommended_update"] for e in exposure.get(tid, []) if e["recommended_update"]]
        ai_tech = {x["id"]: x.get("reason", "") for x in _j(t["ai_techniques"])}
        out[tid] = {
            "id": tid, "title": t["title"], "source": t["source"], "kind": t["kind"], "url": t["url"],
            "published": t["published_at"], "first_seen": t["first_seen_at"], "is_test": t["is_test"],
            "text": (t["text"] or "")[:8000], "score": t["score"], "rating": t["rating"], "factors": _j(t["factors"]),
            "why": t["why"], "summary": t["summary"], "threat_type": t["threat_type"], "confidence": t["confidence"],
            "ai_status": t["ai_status"], "ai_model": t["ai_model"], "dropped": _j(t["dropped"]) or {},
            "analysed_at": t["analysed_at"],
            "actions": list(dict.fromkeys(fixes + _j(t["actions"]))),
            "cves": [{"id": v, "origin": o, **{k: cves.get(v, {}).get(k) for k in (
                "cvss", "severity", "epss", "epss_percentile", "kev_added", "kev_due", "kev_ransomware")},
                "description": (cves.get(v, {}).get("description") or "")[:400]} for v, o in lk.get("cve", [])][:80],
            "techniques": [{"id": v, "origin": o, "name": techniques.get(v, {}).get("name", ""),
                            "tactics": techniques.get(v, {}).get("tactics", ""), "url": techniques.get(v, {}).get("url", ""),
                            "reason": ai_tech.get(v, "")} for v, o in lk.get("technique", [])],
            "products": [{"value": v.replace("|", " · "), "origin": o} for v, o in lk.get("product", [])][:30],
            "ioc_count": len(lk.get("ioc", [])),
            "iocs": [{"type": v.split("|", 1)[0], "value": defang(v.split("|", 1)[1]), "origin": o}
                     for v, o in lk.get("ioc", [])[:60]],
            "exposure": exposure.get(tid, []), "findings": findings.get(tid, []), "hunts": hunts.get(tid, []),
            "fix": threat_fixes.get(tid) if exposure.get(tid) else None,
        }
    path = settings.dashboard_dir / "site_data.json"
    path.write_text(json.dumps(out, default=str, ensure_ascii=False), encoding="utf-8")
    return path


def export_clues(store: Store, settings: Settings) -> Path:
    """Every clue (IP, domain, web link, file hash) we ever collected, one row each, as data/dashboard/clues.json:
    found on our computers first, then newest first. "collected" is when we last got it (the portal's period filter uses
    it). Values are made safe (hxxp, [.]) so they can't be clicked."""
    q = store.query
    seen: dict[str, set[str]] = {}
    for f in q("SELECT device_name, detail FROM findings WHERE kind = 'ioc_hit'"):
        _, kind, value = ((f["detail"] or "") + "  ").split(" ", 2)      # "matched <type> <value>"
        seen.setdefault(f"{kind}|{value.strip()}", set()).add(f["device_name"])
    out: dict[str, dict] = {}
    for r in q("""SELECT l.value, l.threat_id, t.title, t.source, t.is_test, t.first_seen_at, i.malware, i.first_seen
                  FROM threat_links l JOIN threats t USING (threat_id)
                  LEFT JOIN iocs i ON i.ioc_type || '|' || i.value = l.value
                  WHERE l.link_type = 'ioc' ORDER BY t.first_seen_at DESC"""):   # latest sighting first
        key = r["value"]
        if key in out:
            continue
        kind, _, value = key.partition("|")
        out[key] = {"type": kind, "value": defang(value), "malware": r["malware"] or "", "source": r["source"],
                    "first_seen": str(r["first_seen"] or r["first_seen_at"])[:16],
                    "collected": str(r["first_seen_at"])[:16], "test": r["is_test"],
                    "threat_id": r["threat_id"], "threat": r["title"], "seen_on": sorted(seen.get(key, ()))}
    clues = sorted(out.values(), key=lambda c: c["first_seen"], reverse=True)
    clues.sort(key=lambda c: not c["seen_on"])      # stable: found on our computers first, each part newest first
    path = settings.dashboard_dir / "clues.json"
    path.write_text(json.dumps(clues, ensure_ascii=False), encoding="utf-8")
    return path


# ---------------------------------------------------------------- server
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

    # ---------- files ----------
    @property
    def dashboard(self) -> Path:
        return self.settings.dashboard_dir / "dashboard.html"

    def mtime(self) -> float:
        return self.dashboard.stat().st_mtime if self.dashboard.is_file() else 0.0

    def threats(self) -> dict:
        path = self.settings.dashboard_dir / "site_data.json"
        if not path.is_file():
            return {}
        mtime = path.stat().st_mtime
        if not self._cache or self._cache[0] != mtime:
            self._cache = (mtime, json.loads(path.read_text(encoding="utf-8")))
        return self._cache[1]

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
                "last_outcome": self.last_outcome, "last_message": self.last_message, "dashboard_mtime": self.mtime(),
                "last_run": json.loads(last.read_text(encoding="utf-8")) if last.is_file() else None}

    def reports(self) -> dict:
        rdir = self.settings.reports_dir
        files = []
        if rdir.is_dir():
            for p in sorted(rdir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
                if p.is_file() and p.suffix.lower() in REPORT_TYPES:
                    files.append({"name": p.name, "type": p.suffix.lower()[1:], "size": p.stat().st_size,
                                  "modified": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(timespec="minutes")})
        data = [{"name": n, "size": (self.settings.data_dir / n).stat().st_size} for n in DATA_FILES
                if (self.settings.data_dir / n).is_file()]
        return {"reports": files, "data": data}

    # ---------- fix loop ----------
    def fix_view(self) -> dict:
        from uc1.fix.plan import view
        from uc1.fix.runner import fix_active
        v = view(self.settings)
        v["worker"] = {"running": self.fix_running, "elsewhere": not self.fix_running and fix_active(self.settings),
                       "task": self.fix_task, "step": self.fix_step, "message": self.fix_message}
        return v

    def start_fix(self, task: str, method: str | None = None) -> tuple[bool, str]:
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
                    r = runner.run_approved()
                    msg = f"Fix run finished: {r['done']} fixed, {r['failed']} failed"
            except Exception as exc:  # noqa: BLE001 - shown on the page; details in the log
                log.exception("Fix task failed")
                msg = str(exc).splitlines()[0][:200]
            with self.lock:
                self.fix_running, self.fix_step, self.fix_message = False, "", msg

        threading.Thread(target=work, daemon=True).start()
        return True, "Started"

    def server_close(self) -> None:
        logging.getLogger("uc1").removeHandler(self._handler)
        super().server_close()


def _page(name: str, payload: dict | None = None) -> str:
    html = (ASSETS / name).read_text(encoding="utf-8")
    data = json.dumps(payload or {}, default=str, ensure_ascii=False).replace("</", "<\\/")
    return html.replace("/*__DATA__*/null", data)


class _Handler(BaseHTTPRequestHandler):
    server: Site

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, default=str).encode(), "application/json")

    def _html(self, html: str, status: int = 200) -> None:
        self._send(status, html.encode("utf-8"), "text/html; charset=utf-8")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        return host in ("127.0.0.1", "localhost")

    def _live_flag(self) -> str:
        return f"<script>window.UC1_LIVE = {{mtime: {self.server.mtime()}}};</script>"

    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": "forbidden host"})
        path = unquote(self.path.split("?")[0].split("#")[0])
        s = self.server
        if path in ("/", "/index.html"):
            if s.dashboard.is_file():
                html = s.dashboard.read_text(encoding="utf-8")
            else:
                html = _page("empty.html")
            html = html.replace("</head>", self._live_flag() + '\n<link rel="stylesheet" href="/assets/live.css">\n</head>', 1)
            # insert before the LAST </body>: the embedded chart library contains that text inside its code
            cut = html.rfind("</body>")
            if cut >= 0:
                html = html[:cut] + '<script src="/assets/live.js"></script>\n' + html[cut:]
            return self._html(html)
        if path.startswith("/threat/"):
            threat = s.threats().get(path[len("/threat/"):])
            if not threat:
                return self._html(_page("notfound.html"), 404)
            return self._html(_page("threat.html", threat).replace("</head>", self._live_flag() + "\n</head>", 1))
        if path == "/reports":
            return self._html(_page("reports.html", s.reports()).replace("</head>", self._live_flag() + "\n</head>", 1))
        if path.startswith("/files/reports/"):
            name = path[len("/files/reports/"):]
            file = s.settings.reports_dir / name
            if "/" in name or "\\" in name or file.suffix.lower() not in REPORT_TYPES or not file.is_file():
                return self._json(404, {"error": "not found"})
            return self._send(200, file.read_bytes(), REPORT_TYPES[file.suffix.lower()],
                              {"Content-Disposition": f'attachment; filename="{file.name}"'})
        if path.startswith("/files/data/"):
            name = path[len("/files/data/"):]
            file = s.settings.data_dir / name
            if name not in DATA_FILES or not file.is_file():
                return self._json(404, {"error": "not found"})
            return self._send(200, file.read_bytes(), DATA_FILES[name])
        if path.startswith("/assets/"):
            name = path[len("/assets/"):]
            types = {".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}
            file = ASSETS / name
            if "/" in name or "\\" in name or file.suffix not in types or not file.is_file():
                return self._json(404, {"error": "not found"})
            return self._send(200, file.read_bytes(), types[file.suffix])
        if path == "/api/status":
            return self._json(200, s.status())
        if path == "/fix":
            return self._html(_page("fix.html", s.fix_view()).replace("</head>", self._live_flag() + "\n</head>", 1))
        if path == "/api/fix":
            return self._json(200, s.fix_view())
        return self._html(_page("notfound.html"), 404)

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
        try:
            if path == "/api/fix/approve":
                result = plan.approve(s.settings, ids, method)
            elif path == "/api/fix/unapprove":
                result = plan.unapprove(s.settings, ids)
            elif path in ("/api/fix/run", "/api/fix/probe"):
                started, message = s.start_fix("probe" if path.endswith("probe") else "run", method)
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


def serve(settings: Settings, port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    server = Site(("127.0.0.1", port), settings)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"UC1 website running at {url}  (this computer only). Keep this window open; press Ctrl+C to stop.", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
