from remediation.models import Finding, FixRecord, RemediationReport
from remediation.pdf_reports import PDF_NAMES, _clean, render_pdf


def _report_and_findings():
    findings = [
        Finding(finding_id="f1", scanner="codeql", severity="critical", title="SQL injection → user input",
                file_path="app/db.py", line=12, code_context="q = 'SELECT ' + name\n\tcur.execute(q)",
                context_start_line=11, cwe=["89"], fix_status="fixed", references=["https://cwe.mitre.org/89"]),
        Finding(finding_id="f2", scanner="trivy", severity="high", title="pyyaml: unsafe load ✅ 日本",
                file_path="requirements.txt", package_name="pyyaml", installed_version="3.13", fixed_version="5.4",
                ecosystem="PyPI"),
    ]
    fix = FixRecord(finding_ids=["f1"], method="llm", summary="Parameterise the query", files=["app/db.py"],
                    commit="abc123def4567890", explanation="Uses a bound parameter.",
                    diff="--- a/app/db.py\n+++ b/app/db.py\n@@ -1 +1 @@\n-q = 'SELECT ' + name\n+q = 'SELECT ?'\n" * 300)
    report = RemediationReport(run_id="run-1", repo="acme/shop", repo_url="https://github.com/acme/shop",
                               findings_input=2, severity_counts={"critical": 1, "high": 1}, patches_applied=1,
                               fixes=[fix], validation_status="passed", notes=["Nothing is merged — ever."])
    return report, findings


def test_every_pdf_renders_with_unicode_and_long_diffs():
    report, findings = _report_and_findings()
    for name in PDF_NAMES:
        pdf = render_pdf(name, report, findings)
        assert pdf.startswith(b"%PDF") and len(pdf) > 2000, name


def test_pdfs_render_for_a_run_without_findings_or_fixes():
    report = RemediationReport(run_id="run-2", repo="acme/clean")
    for name in PDF_NAMES:
        assert render_pdf(name, report, []).startswith(b"%PDF")


def test_text_outside_the_pdf_fonts_is_replaced_not_dropped_silently():
    assert _clean("a → b ✅") == "a -> b "
    assert _clean("日本") == "??"
    assert _clean(None) == ""
