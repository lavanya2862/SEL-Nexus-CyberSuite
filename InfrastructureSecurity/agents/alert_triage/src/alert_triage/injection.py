"""Detect prompt-injection attempts in attacker-controllable text (command lines, file names, URLs, alert
descriptions, e-mail subjects) and wrap untrusted text safely for the AI prompt.

This is a signal, not a filter: when a marker is found, the guardrail holds the verdict for a human. We never try to
"clean" the text; we fence it and flag it.
"""

from __future__ import annotations

import re

# Phrases that look like instructions aimed at an AI assistant / triage system. Case-insensitive.
PATTERNS = [
    r"ignore (the )?(previous|prior|above|all) (instructions|context|prompts?)",
    r"disregard (the )?(previous|prior|above|all)",
    r"you are (now )?(an?|the) ",
    r"system prompt",
    r"\bas an ai\b", r"\bai assistant\b", r"\bai:\b", r"\bassistant:\b",
    r"(mark|classif\w*|close|treat|set) (this|it|the incident|the alert) as (a )?(false[ -]?positive|benign|safe|closed|resolved)",
    r"(this is|it'?s) (approved|authori[sz]ed|a sanctioned test|safe to close)",
    r"do not (escalate|report|flag|alert)",
    r"override (the )?(guardrail|rule|policy|verdict)",
    r"new instructions?:",
    r"</?(system|instruction|prompt|untrusted)[^>]*>",
]
COMPILED = [re.compile(p, re.IGNORECASE) for p in PATTERNS]


def scan(text: str) -> list[str]:
    """Return the injection phrases found in `text` (empty if none)."""
    if not text:
        return []
    hits = []
    for rx in COMPILED:
        m = rx.search(text)
        if m:
            hits.append(m.group(0).strip()[:80])
    return hits


def scan_packet(packet: dict) -> list[dict]:
    """Walk every untrusted field in the packet and return a list of {where, phrase} hits."""
    found = []

    def visit(where: str, value):
        for phrase in scan(str(value or "")):
            found.append({"where": where, "phrase": phrase})

    for a in packet.get("alerts", []):
        visit(f"alert '{a.get('title','')[:40]}' description", a.get("untrusted", {}).get("description"))
    ent = packet.get("entities", {})
    for p in ent.get("processes", []):
        visit(f"process {p.get('file','')}", p.get("untrusted", {}).get("command_line"))
    for f in ent.get("files", []):
        visit("file name", f.get("name"))
        visit("file path", f.get("path"))
    for u in ent.get("urls", []):
        visit("url", u.get("value"))
    for r in ent.get("registry", []):
        visit("registry value", r.get("untrusted", {}).get("value"))
    for m in ent.get("messages", []):
        visit("message subject", m.get("untrusted", {}).get("subject"))
    return found
