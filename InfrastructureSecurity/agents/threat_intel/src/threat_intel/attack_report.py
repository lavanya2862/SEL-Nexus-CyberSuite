"""Attack Detection Report for one attack-check run (Word + PDF): the searches it ran in Defender, every sign of attack
with its evidence and the AI's steps to resolve it, and the queries used. Built from the database only."""

from __future__ import annotations

from threat_intel import docstyle as ds
from threat_intel.config import Settings
from threat_intel.report import _j, cover_lines, run_window
from threat_intel.resolve import for_findings
from threat_intel.store import Store, utcnow

KIND_WORDS = {"ioc_hit": "Warning sign found", "behaviour_hit": "Suspicious behaviour"}


def build(store: Store, settings: Settings, run_id: str | None = None, steps: dict | None = None) -> dict:
    run_id, started, finished, stored = run_window(store, run_id, "attack-check")
    steps = steps or stored
    hunts = store.query("SELECT * FROM hunts WHERE run_id = ? ORDER BY row_count DESC, name", [run_id])
    signs = store.query("""SELECT f.*, t.title AS threat FROM findings f LEFT JOIN threats t USING (threat_id)
                           WHERE f.kind <> 'exposure' ORDER BY f.created_at DESC, f.first_hit DESC NULLS LAST""")
    new_ids = {f["finding_id"] for f in signs if f["created_at"] and started <= f["created_at"] <= finished}
    res = for_findings(store)
    devices = store.query("SELECT * FROM devices ORDER BY device_name")
    techniques = {r["technique_id"]: r for r in store.query("SELECT technique_id, name, tactics FROM attack_techniques")}
    co = (steps.get("correlate") or {}).get("result") or {}
    rs = (steps.get("resolve") or {}).get("result") or {}
    al = (steps.get("alerts") or {}).get("result") or {}
    found = [h for h in hunts if (h["row_count"] or 0) > 0]
    failed = [h for h in hunts if h["status"] != "ok"]
    real = [f for f in signs if not f["is_test"]]

    r = ds.Report("Attack Detection Report", "Attack Detection Agent",
                  cover_lines(started, finished, f"{len(hunts)} searches in Microsoft Defender (last 30 days) on "
                                                 f"{len(devices)} computers"))
    r.h1("1. Summary")
    new_steps = (rs.get("new_ai") or 0) + (rs.get("new_standard") or 0)
    r.tiles([(f"{len(hunts):,}", "Searches run", f"{len(failed)} could not run" if failed else "all ran", ds.BLUE),
             (f"{len(found):,}", "Searches with results", "something matched", ds.SERIOUS),
             (f"{co.get('new_hits', len(new_ids)):,}", "New signs of attack", "since the last run", ds.BAD),
             (f"{len(signs):,}", "Signs of attack open", f"{len(signs) - len(real)} are harmless lab tests", ds.SERIOUS),
             (f"{new_steps:,}", "Resolution steps written", "for signs of attack", ds.GOOD),
             (f"{al.get('new_alerts', 0):,}", "Alerts sent", "to the security team" if al.get("new_alerts") else
              "no one needed to be told", ds.BAD if al.get("new_alerts") else ds.INK_3)])
    r.para(f"This run ran {len(hunts)} searches in Microsoft Defender; {len(found)} found something. "
           f"{co.get('new_hits', len(new_ids))} new signs of attack were added; {len(signs)} signs are open in total "
           f"({len(signs) - len(real)} of them are harmless lab tests made on purpose to prove detection works).")
    if found:
        top = found[:12]
        r.image(ds.hbar([h["name"][:50] for h in top], [h["row_count"] for h in top], ds.SERIOUS,
                        "Rows found per search (searches with results)"))
    per_device = {dv["device_name"]: sum(f["device_id"] == dv["device_id"] for f in signs) for dv in devices}
    r.table(["Computer", "OpCo", "OS", "Signs of attack", "Last seen"],
            [[dv["device_name"], dv["opco"], f"{dv['os_platform'] or ''} {dv['os_version'] or ''}", per_device[dv["device_name"]],
              f"{dv['last_seen']:%d %b %Y %H:%M}" if dv["last_seen"] else ""] for dv in devices], [4, 3, 4, 2.5, 3.5])

    r.h1("2. Signs of attack and how to resolve them")
    if not signs:
        r.note("No signs of attack found.")
    for f in signs:
        rv = res.get(f["finding_id"]) or {}
        timeline = [f"{e['time']}  {e['what'][:220]}" for e in _j(f["timeline"])[:10]]
        users = ", ".join(u["account"] for u in _j(f["users"])[:5])
        alerts = "; ".join(f"{a['title']} ({a.get('severity', '')}, {a.get('status', '')})" for a in _j(f["alerts"])[:4])
        badge = ("NEW · " if f["finding_id"] in new_ids else "") + ("LAB TEST" if f["is_test"] else KIND_WORDS.get(f["kind"], f["kind"]))
        r.card(f"{f['device_name']}: {f['detail']}",
               f"{f['opco']} · first seen {f['first_hit']:%d %b %Y %H:%M}" if f["first_hit"] else f["opco"],
               [("Related threat", f["threat"]), ("What happened", rv.get("what_happened")),
                ("Recent users", users), ("Defender alerts", alerts), ("Timeline", timeline),
                ("How to resolve", rv.get("steps") or ["Resolution steps are written in the next run."]),
                ("Done when", rv.get("done_when")),
                ("Source", f"Steps written by AI ({rv.get('model') or 'AI'}), checked against the evidence."
                 if rv.get("source") == "ai" else "Standard steps (AI not available)." if rv else "")],
               ds.WARN if f["is_test"] else ds.BAD, badge)

    r.h1("3. Searches run in this run")
    r.table(["Search", "Made by", "Technique", "Result", "Rows", "Seconds"],
            [[h["name"], "AI (checked)" if h["origin"] == "ai" else "template",
              f"{h['technique'] or ''} {techniques.get(h['technique'] or '', {}).get('name', '')}".strip(),
              h["status"] + (f": {h['error'][:60]}" if h["error"] else ""), h["row_count"], h["duration_s"]] for h in hunts],
            [7, 2.2, 4.5, 2, 1.3, 1.5], colour_cols={3: {"ok": ds.GOOD}})

    r.h1("Appendix: queries run")
    for h in hunts:
        r.card(h["name"], f"{h['template'] or ''} · {h['row_count']} rows", [("Query", ("code", (h["query"] or "")[:2500]))], ds.BLUE)

    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    return r.save(settings.reports_dir / f"Attack_Detection_Report_{started:%Y%m%d_%H%M}.docx")
