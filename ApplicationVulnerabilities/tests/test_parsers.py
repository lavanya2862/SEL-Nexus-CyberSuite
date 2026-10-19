import json
from remediation.parsers import parse_codeql, parse_trivy, deduplicate
from remediation.models import Finding

def test_parse_codeql(tmp_path):
    data = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"rules": [{"id": "py/sql-injection",
            "shortDescription": {"text": "SQL injection"},
            "properties": {"security-severity": "8.0"}}]}},
        "results": [{"ruleId": "py/sql-injection", "level": "error",
            "message": {"text": "Unsafe query"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/routes.py"},
            "region": {"startLine": 17}}}]}]}]}
    path = tmp_path / "codeql.sarif"
    path.write_text(json.dumps(data))
    findings = parse_codeql(path)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].file_path == "app/routes.py"
    assert findings[0].line == 17

def test_parse_trivy(tmp_path):
    data = {"Results": [{"Target": "requirements.txt", "Type": "pip",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "PkgName": "demo",
        "InstalledVersion": "1.0", "FixedVersion": "1.1", "Severity": "HIGH",
        "Title": "Test advisory"}],
        "Secrets": [{"RuleID": "generic-api-key", "Title": "Possible key",
        "Severity": "HIGH", "StartLine": 4}],
        "Misconfigurations": [{"ID": "DS001", "Title": "Config issue",
        "Severity": "MEDIUM", "Message": "Test"}]}]}
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(data))
    findings = parse_trivy(path)
    assert len(findings) == 3
    assert {f.category for f in findings} == {"dependency_vulnerability", "exposed_secret", "misconfiguration"}

def test_deduplicate():
    a = Finding(finding_id="a", scanner="CodeQL", category="injection", title="SQL injection", file_path="x.py", line=4)
    b = Finding(finding_id="b", scanner="Semgrep", category="injection", title="SQL injection", file_path="x.py", line=4)
    assert len(deduplicate([a, b])) == 1


def test_codeql_generic_cwe_uses_rule_id_and_merges_with_builtin():
    from remediation.parsers import parse_sarif_data
    sarif = {"runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "py/template-injection",
        "shortDescription": {"text": "Server Side Template Injection"},
        "properties": {"tags": ["security", "external/cwe/cwe-074"], "security-severity": "9.3"}}]}},
        "results": [{"ruleId": "py/template-injection", "message": {"text": "tainted template"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/app.py"},
                                                         "region": {"startLine": 114}}}]}]}]}
    codeql = parse_sarif_data(sarif, "CodeQL")[0]
    assert codeql.category == "template-injection" and codeql.severity == "critical"
    builtin = Finding(finding_id="b", scanner="Builtin-SAST", category="template-injection", title="SSTI",
                      file_path="app/app.py", line=114, cwe=["1336"])
    merged = deduplicate([codeql, builtin])
    assert len(merged) == 1 and merged[0].scanner == "CodeQL" and merged[0].also_reported_by == ["Builtin-SAST"]
