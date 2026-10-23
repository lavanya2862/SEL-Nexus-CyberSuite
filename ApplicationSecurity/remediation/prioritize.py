"""Risk scoring used by the Vulnerability Analysis & Prioritization Agent.

Score (0-10) = severity base x confidence, adjusted for exploitability class, corroboration
across scanners, fix availability and location (test code is de-prioritised).
"""
from __future__ import annotations

from .models import Finding

SEVERITY_BASE = {"critical": 9.0, "high": 7.0, "medium": 4.5, "low": 2.0, "info": 0.5, "unknown": 3.5}
CONFIDENCE = {"high": 1.0, "medium": 0.9, "low": 0.65}
HIGH_IMPACT = {"code-injection", "command-injection", "sql-injection", "deserialization", "template-injection",
               "path-traversal", "ssrf", "xxe", "missing-auth", "exposed_secret", "hardcoded-secret"}
MEDIUM_IMPACT = {"xss", "tls-verification", "open-redirect", "prototype-pollution", "ldap-injection", "xpath-injection"}


def score_finding(f: Finding) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = SEVERITY_BASE.get(f.severity, 3.5)
    reasons.append(f"{f.severity} severity")
    conf = CONFIDENCE.get(f.confidence, 0.9)
    if conf < 1.0:
        score *= conf
        if f.confidence == "low":
            reasons.append("low scanner confidence")
    if f.category in HIGH_IMPACT:
        score += 1.0
        reasons.append(f"high-impact class ({f.category})")
    elif f.category in MEDIUM_IMPACT:
        score += 0.4
    if f.also_reported_by:
        score += min(1.0, 0.5 * len(f.also_reported_by))
        reasons.append(f"corroborated by {', '.join(f.also_reported_by)}")
    if f.scanner == "CodeQL" or "CodeQL" in f.also_reported_by:
        score += 0.3
        reasons.append("confirmed by CodeQL data-flow analysis")
    if f.is_dependency:
        if f.fixed_version:
            score += 0.4
            reasons.append(f"patched version {f.fixed_version} available")
        else:
            score -= 0.5
            reasons.append("no upstream fix yet")
        if (f.raw or {}).get("direct") is True:
            score += 0.3
            reasons.append("direct dependency")
    if (f.raw or {}).get("vendored"):
        score *= 0.5
        reasons.append("third-party library code (update the library)")
    if (f.raw or {}).get("in_tests"):
        score *= 0.4
        reasons.append("located in test code")
    return round(max(0.0, min(10.0, score)), 1), reasons


def prioritize(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        f.priority_score, f.priority_reasons = score_finding(f)
    ranked = sorted(findings, key=lambda f: (-f.priority_score, f.file_path or "", f.line or 0))
    for idx, f in enumerate(ranked, 1):
        f.priority_rank = idx
    return ranked
