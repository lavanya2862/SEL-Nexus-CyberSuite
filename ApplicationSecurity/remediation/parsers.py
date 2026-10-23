"""Normalisation of scanner output (SARIF, Trivy JSON, Bandit JSON) into ``Finding`` objects."""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote

from .models import SEVERITY_ORDER, Finding, normalize_severity

CWE_CATEGORIES = {
    "22": "path-traversal", "23": "path-traversal", "36": "path-traversal", "73": "path-traversal",
    "77": "command-injection", "78": "command-injection", "88": "command-injection",
    "79": "xss", "80": "xss", "89": "sql-injection", "90": "ldap-injection", "643": "xpath-injection",
    "94": "code-injection", "95": "code-injection", "1336": "template-injection",
    "502": "deserialization", "611": "xxe", "776": "xxe", "918": "ssrf", "601": "open-redirect",
    "327": "weak-crypto", "328": "weak-crypto", "326": "weak-crypto", "916": "weak-crypto", "338": "weak-random",
    "295": "tls-verification", "297": "tls-verification", "798": "hardcoded-secret", "259": "hardcoded-secret",
    "377": "insecure-temp-file", "489": "debug-enabled", "215": "debug-enabled", "352": "csrf",
    "1004": "insecure-cookie", "614": "insecure-cookie", "209": "information-exposure", "200": "information-exposure",
    "117": "log-injection", "915": "mass-assignment", "1321": "prototype-pollution", "400": "resource-exhaustion",
    "1333": "redos", "730": "redos", "732": "file-permissions", "250": "privilege", "306": "missing-auth",
}


def cwes_from_tags(tags) -> list[str]:
    out = []
    for tag in tags or []:
        m = re.search(r"cwe[-/_:]?0*(\d+)", str(tag), re.I)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


# Rule-id keywords (CodeQL, Semgrep, ...) used when the CWE alone is too generic (e.g. CWE-74 "injection").
RULE_KEYWORDS = [
    ("template-injection", "template-injection"), ("sql-injection", "sql-injection"), ("sqli", "sql-injection"),
    ("command-line-injection", "command-injection"), ("command-injection", "command-injection"),
    ("shell-command", "command-injection"), ("code-injection", "code-injection"), ("path-injection", "path-traversal"),
    ("path-traversal", "path-traversal"), ("xss", "xss"), ("request-forgery", "ssrf"), ("ssrf", "ssrf"),
    ("xxe", "xxe"), ("deserialization", "deserialization"), ("open-redirect", "open-redirect"),
    ("url-redirection", "open-redirect"), ("hardcoded-credentials", "hardcoded-secret"),
    ("clear-text", "information-exposure"), ("ldap-injection", "ldap-injection"), ("xpath-injection", "xpath-injection"),
    ("redos", "redos"), ("polynomial-redos", "redos"), ("prototype-pollution", "prototype-pollution"),
]
GENERIC_TAGS = {"security", "correctness", "maintainability", "reliability", "external", "experimental"}


def category_from(cwes: list[str], fallback: str, rule_id: str | None = None) -> str:
    for cwe in cwes:
        if cwe in CWE_CATEGORIES:
            return CWE_CATEGORIES[cwe]
    rid = (rule_id or "").lower()
    for keyword, category in RULE_KEYWORDS:
        if keyword in rid:
            return category
    return fallback


def _fallback_tag(tags: list) -> str:
    for tag in tags:
        t = str(tag).lower()
        if t not in GENERIC_TAGS and not t.startswith("external/"):
            return t
    return "source-code"


def _severity_from_sarif(result: dict, rule: dict | None) -> str:
    props = result.get("properties") or {}
    rule_props = (rule or {}).get("properties") or {}
    raw = str(props.get("security-severity") or rule_props.get("security-severity")
              or result.get("level") or ((rule or {}).get("defaultConfiguration") or {}).get("level") or "unknown").lower()
    try:
        score = float(raw)
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        if score > 0:
            return "low"
        return "info"
    except ValueError:
        pass
    return normalize_severity(raw)


def _clean_uri(uri: str | None, root: Path | None) -> str | None:
    if not uri:
        return None
    uri = unquote(uri)
    if uri.startswith("file://"):
        uri = uri[7:]
        if re.match(r"^/[A-Za-z]:/", uri):
            uri = uri[1:]
    if root is not None:
        try:
            p = Path(uri)
            if p.is_absolute():
                uri = p.resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            pass
    return uri.replace("\\", "/")


def parse_sarif_data(data: dict, scanner: str = "CodeQL", root: Path | None = None) -> list[Finding]:
    findings = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool_name = scanner or driver.get("name") or "SARIF"
        rules = {r.get("id", ""): r for r in (driver.get("rules") or [])}
        for ext in run.get("tool", {}).get("extensions") or []:
            for r in ext.get("rules") or []:
                rules.setdefault(r.get("id", ""), r)
        for idx, result in enumerate(run.get("results", []), start=1):
            if result.get("suppressions"):
                continue
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or "unknown-rule"
            rule = rules.get(rule_id, {})
            locations = result.get("locations") or []
            physical = (locations[0].get("physicalLocation") or {}) if locations else {}
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            message = result.get("message") or {}
            description = message.get("text") or message.get("markdown") or ""
            tags = list((rule.get("properties") or {}).get("tags") or []) + \
                list((result.get("properties") or {}).get("tags") or [])
            cwes = cwes_from_tags(tags)
            help_uri = rule.get("helpUri")
            title = ((rule.get("shortDescription") or {}).get("text")
                     or (rule.get("name") if rule.get("name") and rule.get("name") != rule_id else None)
                     or description.split("\n")[0][:160] or rule_id)
            snippet = ((region.get("snippet") or {}).get("text") or "").strip() or None
            findings.append(Finding(
                finding_id=f"{tool_name.upper().replace(' ', '')}-{rule_id}-{idx}", scanner=tool_name,
                category=category_from(cwes, _fallback_tag(tags), rule_id),
                severity=_severity_from_sarif(result, rule), title=title, description=description,
                file_path=_clean_uri(artifact.get("uri"), root), line=region.get("startLine"),
                end_line=region.get("endLine"), snippet=snippet, rule_id=rule_id, cwe=cwes,
                remediation_type="source_code_fix", references=[help_uri] if help_uri else [], raw=result))
    return findings


def parse_codeql(path: str | Path, scanner: str = "CodeQL", root: Path | None = None) -> list[Finding]:
    return parse_sarif_data(json.loads(Path(path).read_text(encoding="utf-8")), scanner, root)


parse_sarif = parse_codeql


def _first_fixed(fixed: str | None) -> str | None:
    if not fixed:
        return None
    return fixed.split(",")[0].strip() or None


TRIVY_ECOSYSTEMS = {"pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "python-pkg": "PyPI", "npm": "npm",
                    "yarn": "npm", "pnpm": "npm", "node-pkg": "npm", "gomod": "Go", "cargo": "crates.io",
                    "bundler": "RubyGems", "gemspec": "RubyGems", "composer": "Packagist", "pom": "Maven",
                    "gradle": "Maven", "jar": "Maven", "nuget": "NuGet"}


def parse_trivy_data(data: dict) -> list[Finding]:
    findings = []
    for result_idx, result in enumerate(data.get("Results") or [], start=1):
        target = result.get("Target", "")
        ecosystem = TRIVY_ECOSYSTEMS.get(str(result.get("Type", "")).lower())
        for idx, item in enumerate(result.get("Vulnerabilities") or [], start=1):
            cwes = [c.split("-")[-1] for c in item.get("CweIDs") or []]
            findings.append(Finding(
                finding_id=f"TRIVY-VULN-{result_idx}-{idx}", scanner="Trivy",
                category="dependency_vulnerability", severity=item.get("Severity", "unknown"),
                title=item.get("Title") or item.get("VulnerabilityID") or "Dependency vulnerability",
                description=item.get("Description") or "", file_path=target, cwe=cwes,
                package_name=item.get("PkgName"), ecosystem=ecosystem,
                installed_version=item.get("InstalledVersion"), fixed_version=_first_fixed(item.get("FixedVersion")),
                advisory_id=item.get("VulnerabilityID"), aliases=list(item.get("VendorIDs") or []),
                remediation_type="dependency_upgrade", references=(item.get("References") or [])[:10],
                raw={k: item.get(k) for k in ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion",
                                              "Severity", "PrimaryURL", "CVSS")}))
        for idx, item in enumerate(result.get("Misconfigurations") or [], start=1):
            if str(item.get("Status", "FAIL")).upper() != "FAIL":
                continue
            meta = item.get("CauseMetadata") or {}
            code_lines = ((meta.get("Code") or {}).get("Lines") or [])
            snippet = "\n".join(l.get("Content", "") for l in code_lines if l.get("IsCause")) or None
            findings.append(Finding(
                finding_id=f"TRIVY-MISCONFIG-{result_idx}-{idx}", scanner="Trivy",
                category="misconfiguration", severity=item.get("Severity", "unknown"),
                title=item.get("Title") or item.get("ID") or "Misconfiguration",
                description=(item.get("Message") or item.get("Description") or "") +
                            (f"\nResolution: {item['Resolution']}" if item.get("Resolution") else ""),
                file_path=target, line=meta.get("StartLine"), end_line=meta.get("EndLine"), snippet=snippet,
                rule_id=item.get("AVDID") or item.get("ID"), remediation_type="configuration_fix",
                references=[item["PrimaryURL"]] if item.get("PrimaryURL") else [],
                raw={k: item.get(k) for k in ("ID", "AVDID", "Title", "Severity", "Resolution")}))
        for idx, item in enumerate(result.get("Secrets") or [], start=1):
            findings.append(Finding(
                finding_id=f"TRIVY-SECRET-{result_idx}-{idx}", scanner="Trivy",
                category="exposed_secret", severity=item.get("Severity", "high"),
                title=item.get("Title") or item.get("RuleID") or "Potential secret",
                description="Potential hard-coded credential (value redacted).", file_path=item.get("Target") or target,
                line=item.get("StartLine"), end_line=item.get("EndLine"), rule_id=item.get("RuleID"), cwe=["798"],
                snippet=f"{item.get('RuleID')}:{item.get('StartLine')}",
                remediation_type="secret_removal", raw={"RuleID": item.get("RuleID"), "Category": item.get("Category")}))
    return findings


def parse_trivy(path: str | Path) -> list[Finding]:
    return parse_trivy_data(json.loads(Path(path).read_text(encoding="utf-8")))


def parse_bandit_data(data: dict, root: Path | None = None) -> list[Finding]:
    findings = []
    for idx, item in enumerate(data.get("results") or [], start=1):
        cwe = str((item.get("issue_cwe") or {}).get("id") or "")
        cwes = [cwe] if cwe else []
        findings.append(Finding(
            finding_id=f"BANDIT-{item.get('test_id')}-{idx}", scanner="Bandit",
            category=category_from(cwes, item.get("test_name") or "python", item.get("test_name")),
            severity=item.get("issue_severity"),
            confidence=str(item.get("issue_confidence", "medium")).lower(),
            title=item.get("issue_text") or item.get("test_name") or "Bandit finding",
            description=item.get("issue_text") or "", file_path=_clean_uri(item.get("filename"), root),
            line=item.get("line_number"), snippet=_bandit_line(item), rule_id=item.get("test_id"), cwe=cwes,
            remediation_type="source_code_fix", references=[item["more_info"]] if item.get("more_info") else []))
    return findings


def _bandit_line(item: dict) -> str | None:
    code = item.get("code") or ""
    target = item.get("line_number")
    for line in code.splitlines():
        m = re.match(r"^(\d+)\s(.*)$", line)
        if m and int(m.group(1)) == target:
            return m.group(2).strip()
    return None


def _merge(into: Finding, other: Finding) -> None:
    into.references = list(dict.fromkeys(into.references + other.references))[:15]
    into.aliases = list(dict.fromkeys(into.aliases + [a for a in [other.advisory_id, *other.aliases] if a
                                                       and a != into.advisory_id]))
    if other.scanner != into.scanner and other.scanner not in into.also_reported_by:
        into.also_reported_by.append(other.scanner)
    if SEVERITY_ORDER.get(other.severity, 5) < SEVERITY_ORDER.get(into.severity, 5):
        into.severity = other.severity
    into.cwe = list(dict.fromkeys(into.cwe + other.cwe))
    if not into.fixed_version and other.fixed_version:
        into.fixed_version = other.fixed_version
    if not into.snippet and other.snippet:
        into.snippet = other.snippet
    if not into.ecosystem and other.ecosystem:
        into.ecosystem = other.ecosystem


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse the same issue reported by several scanners and sort by priority."""
    kept: list[Finding] = []
    code_index: dict[tuple, Finding] = {}
    dep_index: dict[tuple, Finding] = {}
    for finding in findings:
        if finding.is_dependency:
            ids = {a.upper() for a in [finding.advisory_id, *finding.aliases] if a}
            pkg = (finding.package_name or "").lower().replace("_", "-")
            match = None
            for advisory in ids:
                match = dep_index.get((pkg, finding.installed_version, advisory))
                if match:
                    break
            if match:
                _merge(match, finding)
                for advisory in ids:
                    dep_index.setdefault((pkg, finding.installed_version, advisory), match)
                continue
            for advisory in ids or {finding.title.upper()}:
                dep_index[(pkg, finding.installed_version, advisory)] = finding
            kept.append(finding)
            continue
        key = (finding.category.lower(), (finding.file_path or "").lower(), finding.line,
               "" if finding.cwe or finding.category not in ("unknown", "source-code") else finding.title.lower().strip())
        if key in code_index:
            _merge(code_index[key], finding)
        else:
            code_index[key] = finding
            kept.append(finding)
    return sorted(kept, key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), 0 if f.is_dependency else 1,
                                       f.file_path or "", f.line or 0))
