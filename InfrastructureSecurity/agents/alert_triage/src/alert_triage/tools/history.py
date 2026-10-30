"""History signal: how the same kind of incident, on the same device or account, was resolved before.

The strongest false-positive signal (feasibility guide). Read from our own store: past agent verdicts for the same
playbook on an overlapping device/account, and what the analyst said about them (agree/disagree + their verdict).
No external call. (For the GUIDE backtest the history comes from the dataset itself: guide.py.)

Only verdicts that existed BEFORE this incident was created count. Otherwise incidents raised together (one test
creating several alerts) would echo each other's fresh, unconfirmed verdicts as "history" (8 Oct, incident #6).
"""

from __future__ import annotations

import json
from datetime import timedelta

from alert_triage.store import Store, to_utc, utcnow


def for_incident(store: Store, packet: dict, playbook_id: str, days: int = 90) -> dict:
    devices = {d["name"] for d in packet["entities"]["devices"] if d.get("name")}
    accounts = {a["name"].lower() for a in packet["entities"]["accounts"] if a.get("name")}
    cutoff = utcnow() - timedelta(days=days)
    before = to_utc(packet.get("created_at")) or utcnow()
    rows = store.query(
        """SELECT i.incident_id, i.devices, i.accounts, v.verdict,
                  (SELECT analyst_verdict FROM feedback f WHERE f.incident_id = i.incident_id
                   ORDER BY created_at DESC LIMIT 1) AS analyst_verdict,
                  (SELECT agree FROM feedback f WHERE f.incident_id = i.incident_id
                   ORDER BY created_at DESC LIMIT 1) AS agree
           FROM verdicts v JOIN incidents i USING (incident_id)
           WHERE v.playbook = ? AND i.incident_id <> ? AND COALESCE(i.updated_at, v.triaged_at) >= ?
             AND v.triaged_at < ?""",
        [playbook_id, packet["incident_id"], cutoff, before])
    outcomes: dict[str, int] = {}
    for r in rows:
        r_devices = set(_list(r["devices"]))
        r_accounts = {a.lower() for a in _list(r["accounts"])}
        if devices and accounts and not (devices & r_devices or accounts & r_accounts):
            continue
        if devices and not accounts and not devices & r_devices:
            continue
        # the analyst's word beats the agent's: a disagreement with a verdict given counts as that verdict
        final = r["analyst_verdict"] if r["analyst_verdict"] else r["verdict"]
        if r["agree"] is False and not r["analyst_verdict"]:
            final = "disputed"
        outcomes[final] = outcomes.get(final, 0) + 1
    total = sum(outcomes.values())
    benign = outcomes.get("likely_false_positive", 0) + outcomes.get("benign_positive", 0)
    return {
        "playbook": playbook_id,
        "devices": sorted(devices),
        "accounts": sorted(accounts),
        "prior_verdicts": outcomes,
        "prior_total": total,
        "prior_benign_rate": round(benign / total, 2) if total else None,
        "note": _note(total, benign, outcomes.get("likely_true_positive", 0), days),
    }


def _note(total: int, benign: int, real: int, days: int) -> str:
    if not total:
        return f"No earlier incident of this type on these devices/accounts in the last {days} days."
    if benign / total >= 0.8:
        return (f"Same type on the same device/account was a false positive or expected activity {benign} of "
                f"{total} times in the last {days} days (strong false-positive signal).")
    if real / total >= 0.5:
        return f"Same type on the same device/account was a true positive {real} of {total} times in the last {days} days."
    return (f"Mixed history: {benign} of {total} earlier incidents of this type were a false positive or expected "
            "activity.")


def _list(v):
    if isinstance(v, list):
        return v
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []
