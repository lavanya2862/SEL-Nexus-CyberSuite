from remediation.cli import _gate


def test_fail_on_gate_ignores_resolved_findings():
    findings = [{"severity": "critical", "fix_status": "verified"}, {"severity": "high", "fix_status": "manual"},
                {"severity": "low", "fix_status": "skipped"}]
    assert _gate(findings, None) == 0
    assert _gate(findings, "critical") == 0
    assert _gate(findings, "high") == 2
