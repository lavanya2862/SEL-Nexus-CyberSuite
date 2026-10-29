"""Help chat: the two ready questions per screen, answered from today's data (no AI, instant, no quota).

Each answer is filled in from the same read-only data the page shows, every time someone clicks, so the numbers always
match the screen. The question wording here must match the fallback labels in web/src/lib/helpFaq.ts.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from urllib.parse import quote, unquote

from portal import fixproxy
from portal.sources import UC1, UC3, UC4

VERDICT_WORDS = {"likely_true_positive": "true positive", "likely_false_positive": "false positive",
                 "benign_positive": "false positive", "needs_investigation": "needs review"}
SOURCE_WORDS = {"microsoftSentinel": "Microsoft Sentinel", "microsoftDefenderForEndpoint": "Defender for Endpoint",
                "microsoftDefenderForOffice365": "Defender for Office 365", "microsoftDefenderForIdentity": "Defender for Identity",
                "microsoftDefenderForCloudApps": "Defender for Cloud Apps", "azureAdIdentityProtection": "Entra ID Protection"}
AGENTS = {"uc1": "Threat Intel Agent", "uc3": "Vulnerability Agent", "uc4": "Alert Triage Agent", "attack": "Attack Detection Agent"}


def n(value) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "?"


def plural(count, word: str, many: str | None = None) -> str:
    return f"{n(count)} {word if count == 1 else (many or word + 's')}"


def when(value) -> str:
    """'2026-10-08T02:11:52+00:00' → '8 Oct, 7:41 am' in this computer's time zone."""
    if not value:
        return "never"
    try:
        dt = datetime.fromisoformat(str(value).replace(" ", "T").replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if dt.tzinfo is not None:
        dt = dt.astimezone()
    hour = dt.hour % 12 or 12
    return f"{dt.day} {dt:%b}, {hour}:{dt:%M} {'am' if dt.hour < 12 else 'pm'}"


def day(value) -> str:
    try:
        dt = datetime.fromisoformat(str(value)[:10])
        return f"{dt.day} {dt:%b}"
    except ValueError:
        return str(value)


def listing(items: list[str]) -> str:
    items = [i for i in items if i]
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1] if items else "none"


def qa(question: str, answer: str, links: list[tuple[str, str]] | None = None) -> dict:
    return {"question": question, "answer": answer, "links": [{"label": l, "to": t} for l, t in links or []]}


# ---------------------------------------------------------------- one function per screen (two questions each)

def _home(ctx) -> list[dict]:
    t = ctx.summary["uc3"]["totals"]
    return [
        qa("How many vulnerabilities do we have right now?",
           f"{n(t.get('total'))} findings ({n(t.get('cves'))} unique CVEs) on {plural(t.get('devices'), 'device')}. "
           f"{n(t.get('p1'))} of them are P1, the highest priority.", [("Vulnerabilities", "/uc3")]),
        qa("Which device is most at risk?", _riskiest(ctx)),
    ]


def _riskiest(ctx) -> str:
    devices = sorted(ctx.summary.get("devices") or [], key=lambda d: (-(d.get("p1") or 0), -(d.get("findings") or 0)))
    if not devices:
        return "No device data yet: run the Vulnerability Agent from Agents."
    d = devices[0]
    return f"{d['name']}: {n(d.get('findings'))} findings, {n(d.get('p1'))} of them P1."


def _threats(ctx) -> list[dict]:
    t = ctx.summary["uc1"]["totals"]
    top = (ctx.summary["uc1"].get("top_threats") or [None])[0]
    second = (f"{top['title']}. Rated {top.get('rating')}, found on {top.get('devices') or 'none of our devices'}."
              if top else "There are no rated threats yet: run the Threat Intel Agent.")
    return [
        qa("How many threats apply to our devices?",
           f"{n(t.get('affecting'))} of {n(t.get('new_threats'))} new threats apply to software on our devices. "
           f"{n(t.get('urgent'))} of them are rated Critical or High."),
        qa("What is the most serious threat right now?", second,
           [("this threat", f"/uc1/threat/{quote(top['id'], safe='')}")] if top else None),
    ]


def _threat(ctx) -> list[dict]:
    m = re.match(r"^/uc1/threat/(.+)$", ctx.path)
    th = UC1(ctx.settings.uc1_dir).threat(unquote(m.group(1))) if m else None
    if not isinstance(th, dict):
        msg = "I can't find this threat in today's data."
        return [qa("Which of our devices have this?", msg), qa("How serious is it?", msg)]
    exp = th.get("exposure") or []
    devices = sorted({e.get("device_name") for e in exp if e.get("device_name")})
    first = (f"{plural(len(devices), 'device')}: {listing(devices)}. "
             + (f"Defender sees {exp[0].get('detail')}." if exp and exp[0].get("detail") else "")
             if devices else "None of our devices have the software this threat targets, so no action is needed for now.")
    second = f"Rated {th.get('rating')} ({th.get('score')}/100)."
    return [qa("Which of our devices have this?", first.strip()), qa("How serious is it?", second)]


def _hunts(ctx) -> list[dict]:
    t = ctx.summary["uc1"]["totals"]
    real, test = t.get("real_hits") or 0, t.get("test_hits") or 0
    first = (f"Yes, {plural(real, 'real hunt match', 'real hunt matches')} worth a closer look, plus {plural(test, 'match', 'matches')} from our own harmless lab tests."
             if real else f"No signs of an attacker: 0 real hunt matches. {plural(test, 'match', 'matches')} came from our own harmless lab tests.")
    devs = [d for d in ctx.summary.get("devices") or [] if d.get("hunt_hits") or d.get("test_hits")]
    second = ("; ".join(f"{d['name']}: {n(d.get('hunt_hits') or 0)} real, {n(d.get('test_hits') or 0)} test" for d in devs) + "."
              if devs else "No device had a hunt match on the last hunt.")
    return [qa("Did we find any signs of an attacker?", first), qa("Which device had hunt matches?", second)]


def _weak(ctx) -> list[dict]:
    t = ctx.summary["uc3"]["totals"]
    ops = sorted(ctx.summary["uc3"].get("opco_totals") or [], key=lambda o: -(o.get("findings") or 0))
    second = (f"{ops[0]['opco']} has the most: {n(ops[0].get('findings'))} ({n(ops[0].get('p1'))} P1)."
              + "".join(f" {o['opco']}: {n(o.get('findings'))} ({n(o.get('p1'))} P1)." for o in ops[1:])
              if ops else "No VM data yet.")
    return [
        qa("How many vulnerabilities do we have?",
           f"{n(t.get('total'))} findings on {plural(t.get('devices'), 'device')} ({n(t.get('cves'))} unique CVEs). "
           f"{n(t.get('p1'))} are P1."),
        qa("Which VM has the most?", second),
    ]


def _quality(ctx) -> list[dict]:
    checks = ctx.summary["uc3"].get("quality") or []
    c = Counter(str(q.get("status")).upper() for q in checks)
    bad = [q["check_name"] for q in checks if str(q.get("status")).upper() in ("FAIL", "ERROR")]
    warn = [q["check_name"] for q in checks if str(q.get("status")).upper() == "WARN"]
    if bad:
        first = f"Not yet: {plural(len(bad), 'check')} failed ({listing(bad)}). Run the Vulnerability Agent again from Agents."
    else:
        first = (f"Yes: {plural(c['PASS'], 'check')} passed, 0 failed"
                 + (f", {n(len(warn))} with a warning ({listing(warn)})" if warn else "")
                 + (f", {n(c['INFO'])} for information only." if c["INFO"] else "."))
    h = next((h for h in ctx.summary.get("health") or [] if h.get("key") == "uc3"), {})
    return [qa("Can I trust today's numbers?", first),
            qa("When was the data last refreshed?", f"{when(h.get('data_as_of'))}, by the Vulnerability Agent.",
               [("Agents", "/runs")])]


def _fixes(ctx) -> list[dict]:
    fixes = (UC3(ctx.settings.uc3_dir).dashboard() or {}).get("fixes") or {}
    apps = fixes.get("apps") or []
    if not apps:
        msg = "The remediation list isn't built yet. Run the Vulnerability Agent from Agents."
        return [qa("How many apps need updating?", msg), qa("Which app should I update first?", msg)]
    now = [a for a in apps if (a.get("urgency") or {}).get("level") == 1]
    top = (now or apps)[0]
    devices = listing([d.get("name") for d in top.get("devices") or []])
    return [
        qa("How many apps need updating?",
           f"{plural(len(apps), 'app')}. {n(len(now))} are marked High priority."),
        qa("Which app should I update first?",
           f"{top['app']}: {n(top.get('cves'))} CVEs"
           + (f", due {day(top['fix_by'])}" if top.get("fix_by") else "") + f". It is on {devices}.",
           [(top["app"], f"/fixes?app={quote(top['app'])}")]),
    ]


def _progress(ctx) -> list[dict]:
    try:
        rows = fixproxy.get_fix(ctx.settings.uc1_site).get("rows") or []
    except fixproxy.Uc1Unavailable:
        msg = "Remediation status is not available: automated remediation is not running. Open Remediation and enable it."
        return [qa("How many remediations are complete?", msg, [("Remediation", "/fixes")]),
                qa("Did any remediation fail?", msg)]
    c = Counter(r.get("status") for r in rows)
    first = (f"{plural(c['verified'], 'remediation')} verified by Defender"
             + (f", {n(c['done'])} complete and pending verification" if c["done"] else "")
             + (f", {n(c['queued'] + c['running'])} running now" if c["queued"] + c["running"] else "")
             + f". {n(c['proposed'] + c['approved'])} more are proposed or in the remediation queue.")
    failed = [r for r in rows if r.get("status") in ("failed", "still_there")]
    second = ("No, none failed." if not failed else
              f"Yes, {plural(len(failed), 'remediation')}: " + "; ".join(
                  f"{r.get('app')} on {r.get('device_name')}" + (f" ({r['message'][:80]})" if r.get("message") else "")
                  for r in failed[:3]) + ("…" if len(failed) > 3 else "."))
    return [qa("How many remediations are complete?", first), qa("Did any remediation fail?", second)]


def _respond(ctx) -> list[dict]:
    queue = (UC4(ctx.settings.uc4_dir).queue() or {}).get("queue") or []
    if not queue:
        msg = "No incidents have been checked yet. Press Check for new incidents."
        return [qa("How many incidents are there, and where did they come from?", msg),
                qa("How many are real attacks (true positives)?", msg)]
    src = Counter(SOURCE_WORDS.get(q.get("sources"), q.get("sources") or "unknown") for q in queue)
    # a benign positive (older verdicts) is filed as a false positive
    v = Counter("likely_false_positive" if q.get("verdict") == "benign_positive" else q.get("verdict") for q in queue)
    order = ["likely_true_positive", "likely_false_positive", "needs_investigation"]
    rest = [f"{n(v[k])} {VERDICT_WORDS[k]}" for k in order[1:] if v[k]]
    return [
        qa("How many incidents are there, and where did they come from?",
           f"{plural(len(queue), 'incident')}: " + listing([f"{n(c)} from {s}" for s, c in src.most_common()]) + "."),
        qa("How many are real attacks (true positives)?",
           f"{n(v['likely_true_positive'])} rated true positive" + (f"; {listing(rest)}." if rest else ".")),
    ]


def _case(ctx) -> list[dict]:
    m = re.match(r"^/respond/([^/?#]+)", ctx.path)
    case = UC4(ctx.settings.uc4_dir).case(unquote(m.group(1))) if m else None
    if not case:
        msg = "I can't find this incident in the saved data."
        return [qa("What happened, in one line?", msg), qa("Which device and account were involved?", msg)]
    p, v, ent = case["packet"], case.get("verdict") or {}, case["packet"].get("entities") or {}
    first = (f"#{p.get('incident_id')} {p.get('title')}: rated {VERDICT_WORDS.get(v.get('verdict'), 'not rated yet')}"
             + (f", {v.get('confidence')} confidence" if v.get("confidence") else "") + f". Severity {p.get('severity')}.")
    devs = [d.get("name") for d in ent.get("devices") or []]
    accs = [a.get("upn") or a.get("name") for a in ent.get("accounts") or []]
    ips = [i.get("value") for i in ent.get("ips") or []][:3]
    parts = [f"device {listing(devs)}" if devs else "no device", f"account {listing(accs)}" if accs else "no account"]
    second = listing(parts).capitalize() + (f". IP address {listing(ips)}." if ips else ".")
    return [qa("What happened, in one line?", first), qa("Which device and account were involved?", second)]


def _reports(ctx) -> list[dict]:
    files = [dict(f, kind="threat") for f in UC1(ctx.settings.uc1_dir).reports()] + \
            [dict(f, kind="vulnerability") for f in UC3(ctx.settings.uc3_dir).downloads()]
    if not files:
        msg = "There are no reports yet. Run an agent from Agents to make one."
        return [qa("What is the newest report?", msg), qa("Where is the full vulnerability list?", msg)]
    newest = max(files, key=lambda f: str(f.get("modified") or ""))
    stem = newest["name"].rsplit(".", 1)[0]
    kinds = sorted({f["name"].rsplit(".", 1)[-1].upper() for f in files if f["name"].rsplit(".", 1)[0] == stem})
    xlsx = [f for f in files if f["kind"] == "vulnerability" and f["name"].lower().endswith(".xlsx")]
    second = (f"{xlsx[0]['name']} (Excel, {when(xlsx[0].get('modified'))}): every vulnerability, ready to filter."
              if xlsx else "There is no Excel vulnerability list yet. Run the Vulnerability Agent.")
    return [qa("What is the newest report?", f"{stem} ({' + '.join(kinds)}), made {when(newest.get('modified'))}."),
            qa("Where is the full vulnerability list?", second)]


def _runs(ctx) -> list[dict]:
    health = {h.get("key"): h for h in ctx.summary.get("health") or []}
    first = " · ".join(f"{AGENTS[k]}: {when((health.get(k) or {}).get('last_run_at') or (health.get(k) or {}).get('data_as_of'))}"
                       for k in AGENTS if k in health) + "."
    words = {"ok": "finished OK", "stale": "finished OK, but the data is getting old", "error": "failed",
             "missing": "has not run yet"}
    bad = [k for k in AGENTS if (health.get(k) or {}).get("status") not in ("ok", None)]
    running = [AGENTS[k] for k, r in (ctx.runs or {}).items() if (r or {}).get("status") == "running"]
    second = ("Yes, all 3 finished OK." if not bad else
              "; ".join(f"{AGENTS[k]} {words.get(health[k].get('status'), health[k].get('status'))}"
                        + (f" ({health[k].get('message')})" if health[k].get("status") == "error" and health[k].get("message") else "")
                        for k in bad) + ". Press Run on that agent to try again.")
    if running:
        second += f" Running now: {listing(running)}."
    return [qa("When did each agent last run?", first), qa("Did the last runs work?", second)]


SCREENS = {"home": _home, "threats": _threats, "threat": _threat, "hunts": _hunts, "weak": _weak, "quality": _quality,
           "fixes": _fixes, "progress": _progress, "respond": _respond, "case": _case, "reports": _reports, "runs": _runs}


class _Ctx:
    def __init__(self, settings, summary, runs, path):
        self.settings, self.summary, self.runs, self.path = settings, summary, runs, path


def ready(settings, summary: dict, runs: dict, screen: str, path: str) -> list[dict]:
    """The two ready questions for this screen with today's answers (always a list of two)."""
    fn = SCREENS.get(screen, _home)
    return fn(_Ctx(settings, summary, runs, path or "/"))
