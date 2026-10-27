"""`python -m uc1 demo`: the demo story with today's real numbers, as a cheat sheet for recording.

Writes data/demo_notes.md and prints it. It only reads the database; it changes nothing.
"""

from __future__ import annotations

from uc1 import metrics
from uc1.config import Settings
from uc1.spotcheck import latest_result
from uc1.store import Store


def notes(store: Store, settings: Settings) -> str:
    q = store.query
    m = metrics.compute(store, settings)
    feeds = q("SELECT feed, last_status FROM feed_state ORDER BY feed")
    top = q("""SELECT t.title, s.score, s.rating, s.why,
                      (SELECT string_agg(DISTINCT e.device_name, ', ') FROM exposure e WHERE e.threat_id = t.threat_id) AS devices,
                      (SELECT max(e.recommended_update) FROM exposure e WHERE e.threat_id = t.threat_id) AS fix
               FROM threats t JOIN scores s USING (threat_id)
               WHERE t.kind = 'kev' AND t.threat_id IN (SELECT threat_id FROM exposure)
               ORDER BY s.score DESC LIMIT 1""")
    contrast = q("""SELECT t.title, s.score, s.rating FROM threats t JOIN scores s USING (threat_id)
                    WHERE t.kind = 'kev' AND t.threat_id NOT IN (SELECT threat_id FROM exposure)
                    ORDER BY s.score DESC, t.published_at DESC LIMIT 1""")
    dutch = q("""SELECT t.title, a.summary FROM threats t JOIN analysis a USING (threat_id)
                 WHERE t.source = 'NCSC-NL' AND a.ai_status = 'done' ORDER BY t.published_at DESC LIMIT 1""")
    last = store.scalar("SELECT run_id FROM hunts ORDER BY started_at DESC LIMIT 1")
    hunts = q("SELECT origin, COUNT(*) n, SUM(row_count) r FROM hunts WHERE run_id = ? AND status = 'ok' GROUP BY 1", [last])
    iocs = store.scalar("SELECT COUNT(*) FROM iocs WHERE NOT is_test") or 0
    hits = q("""SELECT f.device_name, f.opco, f.detail, f.is_test, t.title FROM findings f JOIN threats t USING (threat_id)
                WHERE f.kind <> 'exposure' ORDER BY f.is_test DESC, f.first_hit DESC LIMIT 5""")
    report = store.scalar("SELECT pdf_path FROM reports ORDER BY created_at DESC LIMIT 1")
    spot = latest_result(settings)

    lines = ["# UC1 demo notes (live numbers)", "",
             "## 1. It collects real threats",
             f"- Feeds: {', '.join(f'{f['feed']} ({f['last_status']})' for f in feeds)}",
             f"- {m['new_threats']} threats in the last {m['window_days']} days; {iocs} fresh indicators (IPs, domains, URLs, hashes)", "",
             "## 2. It understands them (AI)"]
    if dutch:
        lines += [f"- Dutch advisory: \"{dutch[0]['title'][:90]}\"", f"- AI summary (English): {dutch[0]['summary']}"]
    lines += [f"- {m['pct_assessed']}% of new threats assessed · AI items corrected by the checks: {m['ai_items_corrected_by_guard']}"]
    if spot:
        lines.append(f"- AI accuracy from your spot-check: {spot['overall_pct_correct']}% ({spot['marks']} marks)")
    lines += ["", "## 3. Does it affect us? (key moment)"]
    if top:
        t = top[0]
        lines += [f"- {t['rating']} {t['score']}/100: {t['title']}", f"- On our devices: {t['devices']}",
                  f"- Why: {t['why']}", f"- Fix: {t['fix']}"]
    if contrast:
        c = contrast[0]
        lines.append(f"- Contrast: {c['title']} is {c['rating']} ({c['score']}/100) because we don't have it: monitor, not act now")
    lines += [f"- {m['proactive_threats_identified']} threats affect our devices; {m['exposed_actively_exploited']} are actively exploited", "",
              "## 4. It hunts",
              f"- Last run: " + ", ".join(f"{h['n']} {h['origin']} hunts ({h['r'] or 0} rows)" for h in hunts),
              f"- About {m['hunts_per_month_projected']} hunts per month at 6 runs a day"]
    if hits:
        for h in hits:
            title = h["title"].removeprefix("TEST: ")
            lines.append(f"- {'[TEST] ' if h['is_test'] else ''}{title} on {h['device_name']} ({h['opco']}): {h['detail']}")
    else:
        lines.append("- No hits: real indicators were not found on our devices (a real 'we're clean' result). "
                     "Run the 3 lab tests first if you want to show a positive find.")
    lines += ["", "## 5. Report and alert", f"- Latest report: {report}", "- Dashboard: the Threats page of the Unified Cyber Portal", "",
              "## 6. Metrics",
              f"- Median time to assess: {m['median_minutes_to_assess']} min · to report: {m['median_minutes_to_report']} min",
              f"- Manual effort equivalent (assumption): {m['manual_hours_equivalent (assumption)']} h", "",
              "## 7. Honest limits",
              "- 2 lab computers; free feeds; Sentinel not included; positive hunt hits come from harmless lab tests."]
    return "\n".join(lines) + "\n"


def write(store: Store, settings: Settings) -> str:
    text = notes(store, settings)
    (settings.data_dir / "demo_notes.md").write_text(text, encoding="utf-8")
    return text

