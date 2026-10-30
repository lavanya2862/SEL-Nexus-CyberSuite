"""Phase 4b: risk score from fixed, explainable rules (config/risk_policy.csv). The AI never sets the score.

Signals: EPSS, CVSS, Defender 'exploit available', NCSC-NL [H/H] rating,
devices exposed, hunt hits. Without exposure or hits the rating is capped ("monitor"): a dangerous flaw we
don't have is not our emergency.
"""

from __future__ import annotations

import re

from threat_intel.config import read_policy
from threat_intel.store import Store, utcnow

DEFAULTS = {
    "epss_high": 0.5, "epss_high_points": 15, "epss_medium": 0.1, "epss_medium_points": 8,
    "cvss_critical": 9.0, "cvss_critical_points": 15, "cvss_high": 7.0, "cvss_high_points": 10,
    "exploit_available_points": 10, "ncsc_high_high_points": 15,
    "exposed_points": 15, "possible_exposure_points": 8, "ioc_base_points": 20,
    "critical": 70, "high": 50, "medium": 30,
    "cap_not_exposed": 49, "cap_possible_only": 69, "hunt_hit_score": 95,
}
NCSC_RATING = re.compile(r"\[([HML])/([HML])\]")


def rating_for(score: int, p: dict) -> str:
    if score >= p["critical"]:
        return "Critical"
    if score >= p["high"]:
        return "High"
    if score >= p["medium"]:
        return "Medium"
    return "Low"


def score_threat(t: dict, cves: list[dict], exposure: list[dict], hits: int, exploit_available: bool, p: dict) -> dict:
    points, factors = 0, []

    def add(n, label):
        nonlocal points
        points += int(n)
        factors.append(f"{label} (+{int(n)})")

    epss = max((c.get("epss") or 0 for c in cves), default=0)
    if epss >= p["epss_high"]:
        add(p["epss_high_points"], f"EPSS {epss:.0%} chance of attack in 30 days")
    elif epss >= p["epss_medium"]:
        add(p["epss_medium_points"], f"EPSS {epss:.0%} chance of attack in 30 days")
    cvss = max((c.get("cvss") or 0 for c in cves), default=0)
    if cvss >= p["cvss_critical"]:
        add(p["cvss_critical_points"], f"CVSS {cvss:g} (critical severity)")
    elif cvss >= p["cvss_high"]:
        add(p["cvss_high_points"], f"CVSS {cvss:g} (high severity)")
    if exploit_available:
        add(p["exploit_available_points"], "Defender: public exploit available")
    m = NCSC_RATING.search(t.get("title") or "")
    if m and m.groups() == ("H", "H"):
        add(p["ncsc_high_high_points"], "NCSC-NL rates it high likelihood / high damage")
    if t["kind"] in ("ioc", "test"):
        add(p["ioc_base_points"], "fresh indicators of compromise to hunt for")

    exact = sorted({e["device_name"] for e in exposure if e["match_type"] == "cve"})
    early = sorted({e["device_name"] for e in exposure if e["match_type"] == "early"})
    possible = sorted({e["device_name"] for e in exposure if e["match_type"] in ("product", "watchlist")}) or early
    if exact:
        add(p["exposed_points"], f"{len(exact)} of our devices exposed: {', '.join(exact[:5])}")
    elif early:   # version checked against NVD, but Defender hasn't confirmed it yet: still 'possible'
        add(p["possible_exposure_points"], f"affected version installed, not in Defender yet: {', '.join(early[:5])}")
    elif possible:
        add(p["possible_exposure_points"], f"possibly exposed (product match): {', '.join(possible[:5])}")

    score = points
    if hits:
        score = max(score, int(p["hunt_hit_score"]))
        factors.append(f"hunt found activity on our devices ({hits} finding(s)) -> Critical")
    elif not exact:
        cap = p["cap_possible_only"] if possible else p["cap_not_exposed"]
        if score > cap:
            factors.append("capped: not found on our devices, so 'monitor' rather than 'act now'")
            score = int(cap)
    score = min(100, score)
    rating = rating_for(score, p)
    why = f"{rating} ({score}/100): " + "; ".join(factors) if factors else f"{rating} ({score}/100): no risk signals"
    return {"threat_id": t["threat_id"], "score": score, "rating": rating, "factors": factors, "why": why,
            "scored_at": utcnow()}


def run(store: Store) -> dict:
    p = {**DEFAULTS, **read_policy()}
    threats = store.query("SELECT * FROM threats")
    cve_rows = {}
    for r in store.query("""SELECT l.threat_id, c.* FROM threat_links l JOIN cves c ON c.cve_id = l.value
                            WHERE l.link_type = 'cve'"""):
        cve_rows.setdefault(r["threat_id"], []).append(r)
    exposure = {}
    for e in store.query("SELECT * FROM exposure"):
        exposure.setdefault(e["threat_id"], []).append(e)
    hits = {r["threat_id"]: r["n"] for r in store.query(
        "SELECT threat_id, COUNT(*) n FROM findings WHERE kind <> 'exposure' GROUP BY threat_id")}
    exploit = {r["threat_id"] for r in store.query("""
        SELECT DISTINCT l.threat_id FROM threat_links l JOIN device_vulns v ON v.cve_id = l.value
        WHERE l.link_type = 'cve' AND v.exploit_available""")}
    rows = [score_threat(t, cve_rows.get(t["threat_id"], []), exposure.get(t["threat_id"], []),
                         hits.get(t["threat_id"], 0), t["threat_id"] in exploit, p) for t in threats]
    store.execute("DELETE FROM scores")
    store.upsert("scores", rows)
    counts = {}
    for r in rows:
        counts[r["rating"]] = counts.get(r["rating"], 0) + 1
    return counts
