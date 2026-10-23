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


def test_open_findings_get_a_plain_reason_and_fixes_name_their_agent():
    from remediation.pdf_reports import _bucket, _fix_of, _made_by, _why_open
    report, findings = _report_and_findings()
    no_ai = Finding(finding_id="f3", scanner="codeql", title="XSS", fix_status="skipped",
                    fix_note="Needs an AI patch: configure an LLM in Settings to remediate this automatically.")
    assert "had no AI model" in _why_open(no_ai)
    assert _bucket(Finding(finding_id="f4", scanner="osv", title="x", fix_status="verified")).startswith("Fixed")
    assert _made_by(report.fixes[0], report).startswith("Remediation Agent, code fix")
    assert _fix_of(report)["f1"][0] == 1


def test_open_findings_get_a_concrete_suggestion():
    from remediation.advice import advise
    lib = Finding(finding_id="a", scanner="codeql", title="DOM text reinterpreted as HTML", category="xss",
                  cwe=["79"], file_path="app/static/js/materialize.js", line=10)
    assert advise(lib).action.startswith("Update the bundled library") and advise(lib).who == "A person"
    own = lib.model_copy(update={"file_path": "app/static/js/app.js"})
    assert advise(own).key == "xss"
    root = Finding(finding_id="b", scanner="trivy", title="Image user should not be 'root'", rule_id="DS-0002",
                   category="misconfiguration", file_path="Dockerfile")
    assert "USER" in advise(root).how
    weak = Finding(finding_id="c", scanner="codeql", title="weak hash", rule_id="py/weak-sensitive-data-hashing",
                   cwe=["327"], file_path="dao/user.py")
    assert advise(weak).key == "weak-hash"
