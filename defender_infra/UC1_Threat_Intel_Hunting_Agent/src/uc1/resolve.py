"""Resolution steps for every sign of attack (hunt hit), written by Gemini and checked by code.

- Each finding is resolved once and kept (findings are kept from run to run, so only new ones cost an AI call).
  Findings that only got standard steps because the AI was unavailable are retried on the next run.
- The evidence (command lines, file names, alert titles) may be written by an attacker: it goes to the model in a
  data block it is told not to obey, and the model gets no tools.
- Check: a step that names an IP address or a file hash that is not in the evidence is dropped. If fewer than
  two steps survive, the finding gets the standard steps instead.
"""

from __future__ import annotations

import json
import logging
import re

from uc1.ai.gemini_client import AIUnavailable, GeminiClient
from uc1.ai.prompts import RESOLVE_SYSTEM, resolve_prompt
from uc1.ai.schemas import Resolution
from uc1.config import Settings
from uc1.store import Store, dumps, utcnow

log = logging.getLogger("uc1.resolve")

MAX_AI_PER_RUN = 25
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _j(value):
    if value is None:
        return []
    return json.loads(value) if isinstance(value, str) else value


def evidence(f: dict) -> str:
    """The finding as plain text for the model (and for the check)."""
    users = ", ".join(dict.fromkeys(u["account"] for u in _j(f["users"]))) or "unknown"
    alerts = "; ".join(f"{a['title']} ({a.get('severity', '')}, {a.get('status', '')})" for a in _j(f["alerts"])[:5]) or "none"
    lines = [f"Device: {f['device_name']}", f"What our search looked for: {f['detail']}",
             f"Search type: {'known attacker indicator' if f['kind'] == 'ioc_hit' else 'attacker behaviour'}",
             f"First seen: {f['first_hit']}", f"Accounts recently logged on: {users}", f"Defender alerts: {alerts}",
             "Events:"]
    lines += [f"- {e['time']} {e['what'][:400]}" for e in _j(f["timeline"])[:12]]
    return "\n".join(lines)


def standard(f: dict) -> dict:
    """Steps that fit any sign of attack, used when the AI is unavailable or its answer fails the check."""
    user = next((u["account"] for u in _j(f["users"])), None) or "the user"
    dev = f["device_name"]
    steps = [f"Isolate {dev} in Microsoft Defender (device page, Isolate device) so it cannot reach other computers.",
             f"Ask {user} whether they recognise this activity ({f['detail']}).",
             f"Run a full antivirus scan on {dev} from Microsoft Defender and remove anything it finds."]
    if f["kind"] == "ioc_hit":
        steps.append(f"Block the indicator in Microsoft Defender (Settings, Endpoints, Indicators): {f['detail'].removeprefix('matched ')}.")
    steps += [f"If the activity was not expected, reset the password of {user} and sign them out of all sessions.",
              f"Release {dev} from isolation once the scan is clean and the activity is explained."]
    return {"what_happened": f"Our search for '{f['detail']}' found matching activity on {dev}.", "steps": steps,
            "done_when": f"The scan is clean, the cause is known or removed, and the next check finds nothing new on {dev}.",
            "source": "standard", "model": None, "dropped": []}


def checked(answer: Resolution, text: str) -> tuple[list[str], list[str]]:
    """Keep the steps whose IPs and hashes all appear in the evidence."""
    known = text.lower()
    keep, dropped = [], []
    for step in answer.steps[:6]:
        names = IP_RE.findall(step) + HASH_RE.findall(step)
        (keep if all(n.lower() in known for n in names) else dropped).append(step[:400])
    return keep, dropped


def resolve_one(f: dict, ai: GeminiClient) -> dict:
    text = evidence(f)
    answer = ai.json("resolve", RESOLVE_SYSTEM, resolve_prompt(text), Resolution, max_tokens=1200)
    steps, dropped = checked(answer, text)
    if len(steps) < 2:
        res = standard(f)
        res["dropped"] = dropped
        return res
    return {"what_happened": answer.what_happened[:400], "steps": steps, "done_when": answer.done_when[:300],
            "source": "ai", "model": ai.model(), "dropped": dropped}


def run(store: Store, settings: Settings, ai: GeminiClient | None) -> dict:
    todo = store.query("""
        SELECT f.* FROM findings f LEFT JOIN resolutions r USING (finding_id)
        WHERE f.kind <> 'exposure' AND (r.finding_id IS NULL OR r.source <> 'ai')
        ORDER BY f.first_hit DESC NULLS LAST""")
    ai_note = None if ai else "AI not configured"
    done = {"ai": 0, "standard": 0}
    for i, f in enumerate(todo):
        res = None
        if ai and not ai_note and i < MAX_AI_PER_RUN:
            try:
                res = resolve_one(f, ai)
            except AIUnavailable as exc:
                ai_note = str(exc)
                log.warning("AI resolution steps unavailable: %s", exc)
        if res is None:
            if store.scalar("SELECT 1 FROM resolutions WHERE finding_id = ?", [f["finding_id"]]):
                continue                      # already has standard steps: keep them, retry the AI next run
            res = standard(f)
        done[res["source"]] += 1
        store.upsert("resolutions", [{"finding_id": f["finding_id"], **{k: res[k] for k in ("what_happened", "done_when",
                                      "source", "model")}, "steps": dumps(res["steps"]), "dropped": dumps(res["dropped"]),
                                      "created_at": utcnow()}])
    total = store.scalar("SELECT COUNT(*) FROM findings WHERE kind <> 'exposure'") or 0
    by_ai = store.scalar("""SELECT COUNT(*) FROM resolutions r JOIN findings f USING (finding_id)
                            WHERE f.kind <> 'exposure' AND r.source = 'ai'""") or 0
    out = {"signs": total, "by_ai": by_ai, "new_ai": done["ai"], "new_standard": done["standard"]}
    if ai_note:
        out["ai_note"] = ai_note[:200]
    log.info("Resolution steps: %s", out)
    return out


def for_findings(store: Store) -> dict[str, dict]:
    """finding_id -> resolution, for the report and the dashboard."""
    return {r["finding_id"]: {"what_happened": r["what_happened"], "steps": _j(r["steps"]), "done_when": r["done_when"],
                              "source": r["source"], "model": r["model"]}
            for r in store.query("SELECT * FROM resolutions")}
