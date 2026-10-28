"""The broader rule sets: CodeQL's security-extended suite and Semgrep's default + OWASP Top 10 + CWE Top 25 packs."""
import json

from remediation import config
from remediation.scanners import external


class _Run:
    def __init__(self):
        self.calls = []

    def __call__(self, args, timeout=None, env=None):
        self.calls.append(args)
        out = next((a.split("=", 1)[1] for a in args if str(a).startswith("--output=")), None)
        if out is None and "--output" in args:
            out = args[args.index("--output") + 1]
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                json.dump({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x", "rules": []}}, "results": []}]}, fh)

        class R:
            ok, returncode, stdout, stderr = True, 0, "", ""
        return R()


def test_semgrep_runs_every_configured_pack(tmp_path, monkeypatch):
    run = _Run()
    monkeypatch.setattr(external, "run_cmd", run)
    monkeypatch.setattr(external, "local_tool", lambda name: "semgrep")
    external.SemgrepScanner().scan(tmp_path, tmp_path / "w")
    args = run.calls[0]
    packs = [args[i + 1] for i, a in enumerate(args) if a == "--config"]
    assert packs == ["p/default", "p/owasp-top-ten", "p/cwe-top-25"]

    monkeypatch.setenv("SEMGREP_CONFIG", " p/default , ,p/python ")
    config.reset_settings_cache()
    external.SemgrepScanner().scan(tmp_path, tmp_path / "w2")
    args = run.calls[1]
    assert [args[i + 1] for i, a in enumerate(args) if a == "--config"] == ["p/default", "p/python"]


def test_codeql_runs_the_security_extended_suite(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    run = _Run()
    monkeypatch.setattr(external, "run_cmd", run)
    monkeypatch.setattr(external, "codeql_binary", lambda: "codeql")
    external.CodeQLScanner().scan(tmp_path, tmp_path / "w")
    analyze = next(c for c in run.calls if "analyze" in c)
    assert analyze[-1] == "codeql/python-queries:codeql-suites/python-security-extended.qls"

    monkeypatch.setenv("CODEQL_SUITE", "code-scanning")
    config.reset_settings_cache()
    external.CodeQLScanner().scan(tmp_path, tmp_path / "w2")
    analyze = [c for c in run.calls if "analyze" in c][-1]
    assert analyze[-1] == "codeql/python-queries:codeql-suites/python-code-scanning.qls"
