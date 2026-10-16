"""Static checks for hunt queries, especially AI-drafted ones, before they are sent to Defender.

Advanced Hunting is read-only by design, but we still require: known tables only, a time filter, a row
limit, no external data access, and a sensible size. Violations are returned as plain-language problems.
"""

from __future__ import annotations

import re

ALLOWED_TABLES = {
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceLogonEvents",
    "DeviceImageLoadEvents", "DeviceEvents", "DeviceInfo", "DeviceNetworkInfo", "DeviceFileCertificateInfo",
    "DeviceTvmSoftwareInventory", "DeviceTvmSoftwareVulnerabilities", "DeviceTvmSoftwareVulnerabilitiesKB",
}
FORBIDDEN = re.compile(r"(?i)\b(externaldata|external_table|http_request|http_request_post|evaluate\s+python|"
                       r"evaluate\s+r\b|cluster\s*\(|database\s*\()")
# Table names (not columns such as DeviceName/DeviceId): known prefixes + table-style suffixes
TABLE_TOKEN = re.compile(r"\b((?:Device|Identity|Email|Alert|Cloud|Url|Behavior)[A-Za-z]*"
                         r"(?:Events|Info|Inventory|Vulnerabilities|VulnerabilitiesKB|Assessment|Evidence|Gathering))\b")
MAX_LENGTH = 60_000


def strip_comments(query: str) -> str:
    return "\n".join(line for line in query.splitlines() if not line.strip().startswith("//"))


def validate(query: str, *, require_limit: bool = True) -> list[str]:
    problems = []
    q = strip_comments(query).strip()
    if not q:
        return ["query is empty"]
    if len(q) > MAX_LENGTH:
        problems.append(f"query is too long ({len(q)} characters)")
    if q.startswith("."):
        problems.append("management commands (starting with '.') are not allowed")
    if FORBIDDEN.search(q):
        problems.append("external data access is not allowed")
    tables = set(TABLE_TOKEN.findall(q))
    unknown = sorted(t for t in tables if t not in ALLOWED_TABLES)
    if unknown:
        problems.append(f"tables not allowed: {', '.join(unknown)}")
    if not tables & ALLOWED_TABLES:
        problems.append("no allowed table used")
    uses_events = any(t.endswith(("Events", "Info")) for t in tables & ALLOWED_TABLES)
    if uses_events and not re.search(r"(?i)Timestamp\s*(>|>=|between)\s*", q):
        problems.append("missing time filter (Timestamp > ago(Nd))")
    if require_limit and not re.search(r"(?i)\|\s*(take|limit|top|summarize|count)\b", q):
        problems.append("missing row limit (| take N)")
    return problems


def ensure_limit(query: str, n: int = 500) -> str:
    q = strip_comments(query).strip().rstrip(";")
    if not re.search(r"(?i)\|\s*(take|limit|top|summarize|count)\b", q):
        q += f"\n| take {n}"
    return q
