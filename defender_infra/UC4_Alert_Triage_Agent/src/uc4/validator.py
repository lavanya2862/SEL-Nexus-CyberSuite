"""Static checks that a hunting query is read-only before it is sent to Microsoft Graph. Adapted from UC1.

Graph runHuntingQuery is read-only by design, but we still require: known tables only, a time filter, a row limit,
no external data access. Our own KQL templates always pass; this mainly guards against a template being edited into
something unsafe, and documents the safety boundary.
"""

from __future__ import annotations

import re

ALLOWED_TABLES = {
    # Defender XDR hunting tables
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents", "DeviceLogonEvents",
    "DeviceImageLoadEvents", "DeviceEvents", "DeviceInfo", "DeviceNetworkInfo", "DeviceFileCertificateInfo",
    "DeviceTvmSoftwareInventory", "DeviceTvmSoftwareVulnerabilities",
    "AlertInfo", "AlertEvidence",
    "IdentityLogonEvents", "IdentityDirectoryEvents", "IdentityQueryEvents",
    "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo", "EmailPostDeliveryEvents", "UrlClickEvents",
    "CloudAppEvents",
    # Sentinel Training Lab custom-log tables (option C)
    "SigninLogs_CL", "AADNonInteractiveUserSignInLogs_CL", "SecurityEvent_CL", "OfficeActivity_CL", "AzureActivity_CL",
    "Cisco_Umbrella_dns_CL",
    # Sentinel standard tables (the lab VMs' Windows security events)
    "SecurityEvent",
}
FORBIDDEN = re.compile(r"(?i)\b(externaldata|external_table|http_request|http_request_post|evaluate\s+python|"
                       r"evaluate\s+r\b|cluster\s*\(|database\s*\()")
TABLE_TOKEN = re.compile(r"\b((?:Device|Identity|Email|Alert|Cloud|Url|Behavior|Signin|AAD|Security|Office|Azure)"
                         r"[A-Za-z]*(?:Events|Event|Info|Inventory|Vulnerabilities|Evidence|Logs_CL|Event_CL|Activity_CL))\b"
                         r"|\b(\w+_CL)\b")
MAX_LENGTH = 60_000


def strip_comments(query: str) -> str:
    return "\n".join(line for line in query.splitlines() if not line.strip().startswith("//"))


def validate(query: str, *, require_limit: bool = True, require_time: bool = True) -> list[str]:
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
    tables = {t for pair in TABLE_TOKEN.findall(q) for t in pair if t}     # any custom-log table must be listed too
    unknown = sorted(t for t in tables if t not in ALLOWED_TABLES)
    if unknown:
        problems.append(f"tables not allowed: {', '.join(unknown)}")
    if not tables & ALLOWED_TABLES:
        problems.append("no allowed table used")
    if require_time and not re.search(r"(?i)(Timestamp|TimeGenerated)\s*(>|>=|between)", q):
        problems.append("missing time filter")
    if require_limit and not re.search(r"(?i)\|\s*(take|limit|top|summarize|count)\b", q):
        problems.append("missing row limit (| take N)")
    return problems
