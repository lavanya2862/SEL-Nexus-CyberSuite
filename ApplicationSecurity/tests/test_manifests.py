import json

from remediation.manifests import (best_fixed_version, bump_dependency, bump_go_mod, bump_package_json, bump_pom,
                                   bump_requirements, compare_versions, discover_packages, is_major_upgrade,
                                   parse_go_mod, parse_package_lock, parse_requirements, parse_yarn_lock, stable_version)


def test_parse_requirements_handles_extras_markers_comments():
    text = "flask==2.0.1  # web\nrequests[socks]==2.25.0 ; python_version>'3'\n-r other.txt\nloose>=1.0\nDjango===3.2\n"
    pkgs = {(p.name, p.version, p.line) for p in parse_requirements(text, "requirements.txt")}
    assert pkgs == {("flask", "2.0.1", 1), ("requests", "2.25.0", 2), ("Django", "3.2", 5)}


def test_parse_package_lock_v3_and_v1():
    v3 = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "^4.17.0"}},
                                             "node_modules/lodash": {"version": "4.17.15"},
                                             "node_modules/a/node_modules/minimist": {"version": "0.0.8"}}}
    pkgs = {(p.name, p.version, p.direct) for p in parse_package_lock(json.dumps(v3), "package-lock.json")}
    assert pkgs == {("lodash", "4.17.15", True), ("minimist", "0.0.8", False)}
    v1 = {"lockfileVersion": 1, "dependencies": {"express": {"version": "4.16.0",
                                                             "dependencies": {"qs": {"version": "6.5.1"}}}}}
    assert {(p.name, p.version) for p in parse_package_lock(json.dumps(v1), "x")} == {("express", "4.16.0"), ("qs", "6.5.1")}


def test_parse_yarn_and_go():
    yarn = '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.1.2"\n\nlodash@^4.0.0:\n  version "4.17.4"\n'
    assert {(p.name, p.version) for p in parse_yarn_lock(yarn, "yarn.lock")} == {("@babel/core", "7.1.2"), ("lodash", "4.17.4")}
    gomod = "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n\tgolang.org/x/net v0.0.1 // indirect\n)\nrequire github.com/a/b v1.0.0\n"
    got = {(p.name, p.version, p.direct) for p in parse_go_mod(gomod, "go.mod")}
    assert got == {("github.com/gin-gonic/gin", "v1.6.0", True), ("golang.org/x/net", "v0.0.1", False),
                   ("github.com/a/b", "v1.0.0", True)}


def test_versions():
    assert compare_versions("1.10.0", "1.9.9", "PyPI") > 0
    assert compare_versions("2.0.0-rc.1", "2.0.0", "npm") < 0
    assert best_fixed_version("1.1.11", ["1.3.0b3", "1.2.19"], "PyPI") == "1.2.19"
    assert best_fixed_version("4.17.4", ["4.17.21", "5.0.0"], "npm") == "4.17.21"
    assert best_fixed_version("2.0", ["1.0"], "PyPI") is None
    assert stable_version("1.3.0b3", "PyPI") == "1.3.0"
    assert is_major_upgrade("0.12.2", "3.1.3") and not is_major_upgrade("2.1.0", "2.4.0")


def test_bumps_preserve_formatting():
    req = bump_requirements("Flask==0.12.2  # pinned\nflask-login==0.4\n", "flask", "2.3.3")
    assert req.new_text == "Flask==2.3.3  # pinned\nflask-login==0.4\n"
    pkg = bump_package_json('{\n  "dependencies": {\n    "lodash": "^4.17.4"\n  }\n}\n', "lodash", "4.17.21")
    assert '"lodash": "^4.17.21"' in pkg.new_text
    go = bump_go_mod("require (\n\tgithub.com/x/y v1.0.0\n)\n", "github.com/x/y", "1.2.0")
    assert "github.com/x/y v1.2.0" in go.new_text
    pom = bump_pom("<project><dependencies><dependency><groupId>org.a</groupId><artifactId>b</artifactId>"
                   "<version>1.0</version></dependency></dependencies></project>", "org.a:b", "1.5")
    assert "<version>1.5</version>" in pom.new_text


def test_bump_dependency_redirects_lockfile_to_manifest(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.4"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    files, message = bump_dependency(tmp_path, "package-lock.json", "lodash", "4.17.21")
    assert files == ["package.json"]
    assert "npm install --package-lock-only" in message


def test_discover_skips_vendor_dirs(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==2.0\n", encoding="utf-8")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text('{"dependencies":{"a":"1.0.0"}}', encoding="utf-8")
    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "package-lock.json").write_text("{not json", encoding="utf-8")
    pkgs, warnings = discover_packages(tmp_path)
    assert [(p.name, p.version) for p in pkgs] == [("django", "2.0")]
    assert len(warnings) == 1
