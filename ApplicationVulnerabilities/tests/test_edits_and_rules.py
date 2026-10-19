import pytest

from remediation.edits import Edit, EditError, apply_edits
from remediation.fixers import fix_with_rule
from remediation.llm import extract_json
from remediation.models import Finding
from remediation.scanners.builtin_sast import BuiltinSastScanner
from remediation.scanners.builtin_secrets import BuiltinSecretsScanner, redact
from tests.conftest import make_git_repo


def test_apply_edits_exact_and_tolerant(tmp_path):
    f = tmp_path / "app.py"
    f.write_bytes(b"import os\r\n\r\ndef run(cmd):\r\n    os.system(cmd)\r\n    return 0\r\n")
    # The model mis-indents its search block (8 spaces instead of 4): tolerant matching re-indents the replacement.
    changed = apply_edits(tmp_path, [Edit("app.py", "import os\n", "import os\nimport subprocess\n"),
                                     Edit("app.py", "        os.system(cmd)\n        return 0",
                                          "        subprocess.run([cmd], check=True)\n        return 0")])
    assert changed == ["app.py"]
    assert f.read_bytes() == (b"import os\r\nimport subprocess\r\n\r\ndef run(cmd):\r\n"
                              b"    subprocess.run([cmd], check=True)\r\n    return 0\r\n")


def test_apply_edits_is_atomic_and_safe(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(EditError):
        apply_edits(tmp_path, [Edit("a.py", "x = 1", "x = 2"), Edit("a.py", "missing", "y")])
    assert (tmp_path / "a.py").read_text(encoding="utf-8") == "x = 1\n"
    for bad in ("../outside.py", "a/../../outside.py", "C:/Windows/x", ".git/config", ".github/workflows/ci.yml"):
        with pytest.raises(EditError):
            apply_edits(tmp_path, [Edit(bad, "", "boom")])
    # A leading slash is interpreted relative to the repository root, never the filesystem root.
    assert apply_edits(tmp_path, [Edit("/new/file.py", "", "x = 1\n")]) == ["new/file.py"]
    (tmp_path / "dup.py").write_text("a\na\n", encoding="utf-8")
    with pytest.raises(EditError, match="multiple"):
        apply_edits(tmp_path, [Edit("dup.py", "a", "b")])


def test_extract_json_from_noisy_reply():
    reply = 'Sure!\n```json\n{"status": "fixed", "edits": [{"file": "a", "search": "{x}", "replace": "}"}]}\n```'
    assert extract_json(reply)["status"] == "fixed"
    assert extract_json('prefix {"a": "b \\" }"} suffix') == {"a": 'b " }'}


def test_builtin_sast_detects_and_downgrades_tests(tmp_path):
    (tmp_path / "app.py").write_text("import yaml, subprocess\nd = yaml.load(s)\nsafe = yaml.load(s, Loader=yaml.SafeLoader)\n"
                                     "subprocess.call(cmd, shell=True)\n# eval(x) in a comment\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("eval(user)\n", encoding="utf-8")
    found = BuiltinSastScanner().scan(tmp_path, tmp_path / "w")
    rules = sorted((f.rule_id, f.line, f.severity) for f in found)
    assert rules == [("PY-EVAL", 1, "low"), ("PY-SUBPROCESS-SHELL", 4, "high"), ("PY-YAML-LOAD", 2, "high")]


def test_rule_autofix_rewrites_yaml_load(tmp_path):
    repo = make_git_repo(tmp_path / "r", {"app.py": "import yaml\ncfg = yaml.load(raw, Loader=yaml.FullLoader)\n"})
    finding = Finding(finding_id="x", scanner="Builtin-SAST", category="deserialization", title="t",
                      file_path="app.py", line=2, rule_id="PY-YAML-LOAD")
    attempt = fix_with_rule(repo, finding)
    assert attempt and attempt.ok
    assert (repo / "app.py").read_text(encoding="utf-8") == "import yaml\ncfg = yaml.safe_load(raw)\n"


def test_secrets_detection_and_redaction(tmp_path):
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    (tmp_path / "settings.py").write_text(f'AWS_KEY = "{key}"\npassword = "changeme"\n'
                                          f'db_password = "Xk9#mQ2$vL7pZ"\n', encoding="utf-8")
    found = BuiltinSecretsScanner().scan(tmp_path, tmp_path / "w")
    assert sorted(f.rule_id for f in found) == ["aws-access-key-id", "generic-credential"]
    assert key not in redact(f'k = "{key}"') and "Xk9#mQ2$vL7pZ" not in redact('db_password = "Xk9#mQ2$vL7pZ"')
    assert all(key not in (f.snippet or "") + f.description for f in found)
