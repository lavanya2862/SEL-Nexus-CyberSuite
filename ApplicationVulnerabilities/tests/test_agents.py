import subprocess

from remediation.agents.validation import diff_guard, issue_key
from remediation.fixers import ensure_python_import, fix_secret_to_env, fix_with_rule
from remediation.gitops import apply_mbox, commit_all, create_branch, format_patch, head_sha
from remediation.models import Finding
from remediation.prioritize import prioritize
from remediation.scanners.builtin_sast import BuiltinSastScanner
from tests.conftest import make_git_repo


def _diff(added=(), removed=(), file="app.py"):
    lines = [f"diff --git a/{file} b/{file}", f"--- a/{file}", f"+++ b/{file}", "@@ -1,2 +1,2 @@"]
    return "\n".join(lines + [f"-{r}" for r in removed] + [f"+{a}" for a in added])


def test_diff_guard_flags_weakening_patches():
    assert diff_guard(_diff(added=["x = run(cmd)  # nosec"]))
    assert diff_guard(_diff(added=["requests.get(url, verify=False)"]))
    assert diff_guard(_diff(added=["@pytest.mark.skip"], file="tests/test_a.py"))
    assert diff_guard(_diff(removed=["@login_required"], added=["def view():"]))
    assert diff_guard(_diff(removed=["    assert resp.status == 403"], file="tests/test_auth.py"))
    assert diff_guard("diff --git a/tests/test_x.py b/tests/test_x.py\ndeleted file mode 100644\n")


def test_diff_guard_accepts_genuine_fixes():
    assert diff_guard(_diff(removed=["data = yaml.load(raw)"], added=["data = yaml.safe_load(raw)"])) == []
    assert diff_guard(_diff(removed=["requests.get(u, verify=False)"], added=["requests.get(u, verify=True)"])) == []
    # modifying a line that already contained a control is not a removal of that control
    assert diff_guard(_diff(removed=["user = authenticate(request, pw)"],
                            added=["user = authenticate(request, pw, strict=True)"])) == []


def test_issue_key_ignores_dependency_version():
    old = Finding(finding_id="a", scanner="OSV", title="t", package_name="PyJWT", installed_version="1.5.2",
                  advisory_id="GHSA-x", aliases=["CVE-1"], remediation_type="dependency_upgrade")
    new = old.model_copy(update={"installed_version": "2.14.0"})
    assert old.fingerprint() != new.fingerprint() and issue_key(old) == issue_key(new)


def test_ensure_python_import_placement():
    lines = ['"""Doc."""\n', "from __future__ import annotations\n", "import sys\n", "x = 1\n"]
    assert ensure_python_import(lines, "os") == 1 and lines[2] == "import os\n"
    assert ensure_python_import(lines, "os") == 0
    lines = ["import os, sys\n"]
    assert ensure_python_import(lines, "sys") == 0


def test_secret_moved_to_environment(tmp_path):
    repo = make_git_repo(tmp_path / "r", {
        "settings.py": 'DEBUG = False\nSECRET_KEY = "s3cr3t-value-123"  # prod\n',
        "web/config.js": "const apiKey = 'sk_live_abcdefghijklmnop';\nmodule.exports = {apiKey};\n"})
    py = Finding(finding_id="s1", scanner="Trivy", title="secret", file_path="settings.py", line=2,
                 category="exposed_secret", remediation_type="secret_removal")
    attempt = fix_secret_to_env(repo, py)
    assert attempt.ok and "ROTATE" in attempt.detail
    assert (repo / "settings.py").read_text() == ('import os\nDEBUG = False\n'
                                                  'SECRET_KEY = os.environ.get("SECRET_KEY", "")  # prod\n')
    js = py.model_copy(update={"file_path": "web/config.js", "line": 1})
    assert fix_secret_to_env(repo, js).ok
    assert (repo / "web/config.js").read_text().startswith('const apiKey = process.env.API_KEY || "";')


def test_flask_debug_rewrite_adds_import(tmp_path):
    repo = make_git_repo(tmp_path / "r", {"app.py": "from flask import Flask\napp = Flask(__name__)\n"
                                                    "app.run(host='127.0.0.1', debug=True)\n"})
    f = Finding(finding_id="d", scanner="Builtin-SAST", title="debug", file_path="app.py", line=3,
                category="debug-enabled", rule_id="PY-FLASK-DEBUG")
    assert fix_with_rule(repo, f).ok
    text = (repo / "app.py").read_text()
    assert text.startswith("import os\nfrom flask import Flask") and 'debug=os.environ.get("FLASK_DEBUG") == "1"' in text


def test_minified_files_are_not_pattern_scanned(tmp_path):
    (tmp_path / "vendor.js").write_text("var a=1;" * 400 + "eval(x);\n", encoding="utf-8")
    (tmp_path / "app.js").write_text("function run(x) {\n  return eval(x);\n}\n", encoding="utf-8")
    found = BuiltinSastScanner().scan(tmp_path, tmp_path / "w")
    assert [f.file_path for f in found] == ["app.js"]


def test_prioritisation_ranks_exploitable_and_corroborated_first():
    a = Finding(finding_id="a", scanner="Builtin-SAST", title="weak hash", severity="low", category="weak-crypto")
    b = Finding(finding_id="b", scanner="CodeQL", title="sqli", severity="high", category="sql-injection",
                also_reported_by=["Semgrep"])
    c = Finding(finding_id="c", scanner="Builtin-SAST", title="sqli in test", severity="high", category="sql-injection",
                raw={"in_tests": True})
    ranked = prioritize([a, c, b])
    assert [f.finding_id for f in ranked] == ["b", "c", "a"]
    assert ranked[0].priority_rank == 1 and "confirmed by CodeQL data-flow analysis" in ranked[0].priority_reasons


def test_mbox_round_trip_preserves_per_fix_commits(tmp_path):
    origin = make_git_repo(tmp_path / "o", {"a.txt": "one\n", "b.txt": "two\n"})
    base = head_sha(origin)
    create_branch(origin, "ai-remediation/x")
    (origin / "a.txt").write_bytes((origin / "a.txt").read_bytes().replace(b"one", b"ONE"))
    commit_all(origin, "fix(security): first", ["a.txt"])
    (origin / "b.txt").write_bytes((origin / "b.txt").read_bytes().replace(b"two", b"TWO"))
    commit_all(origin, "fix(security): second", ["b.txt"])
    mbox = format_patch(origin, base)
    replay = tmp_path / "replay"
    subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "-q", "-c", "core.autocrlf=false", str(origin), str(replay)], check=True, capture_output=True)
    subprocess.run(["git", "checkout", "-q", base], cwd=replay, check=True, capture_output=True)
    ok, msg = apply_mbox(replay, mbox)
    assert ok, msg
    log = subprocess.run(["git", "log", "--format=%s", f"{base}..HEAD"], cwd=replay, capture_output=True, text=True).stdout
    assert log.split("\n")[:2] == ["fix(security): second", "fix(security): first"]
    assert (replay / "b.txt").read_bytes().strip() == b"TWO"


def test_diff_guard_flags_fast_password_hashes():
    weak = _diff(removed=["hash_pass = hashlib.md5(password).hexdigest()"],
                 added=["hash_pass = hashlib.sha256(password.encode('utf-8')).hexdigest()"])
    assert any("fast unsalted digest" in p for p in diff_guard(weak))
    good = _diff(removed=["hash_pass = hashlib.md5(password).hexdigest()"],
                 added=["hash_pass = generate_password_hash(password)"])
    assert diff_guard(good) == []
    assert diff_guard(_diff(added=["etag = hashlib.sha256(body).hexdigest()"])) == []  # non-password use is fine
