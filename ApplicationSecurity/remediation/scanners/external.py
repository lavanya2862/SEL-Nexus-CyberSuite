"""Wrappers around optional third-party scanners. Each is used only if installed."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from ..config import get_settings, scrubbed_env
from ..gitops import run_cmd
from ..models import Finding
from ..parsers import parse_bandit_data, parse_sarif_data, parse_trivy_data
from .base import Scanner, ScannerUnavailable

SKIP = ["node_modules", "vendor", ".venv", "venv", "dist", "build", "target", ".git"]


def _ensure(workdir: Path) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    return workdir


def local_tool(name: str) -> str | None:
    """A Python scanner installed with this app: in its own environment under tools/<name> (Semgrep, whose
    dependencies clash with the app's), next to the app's own Python (Bandit), or else anywhere on PATH."""
    exe = name + (".exe" if os.name == "nt" else "")
    scripts = "Scripts" if os.name == "nt" else "bin"
    for path in (Path(__file__).resolve().parents[2] / "tools" / name / scripts / exe, Path(sys.executable).parent / exe):
        if path.is_file():
            return str(path)
    return shutil.which(name)


class TrivyScanner(Scanner):
    name, kind, binary, setting = "trivy", "sca+secrets+iac", "trivy", "enable_trivy"
    description = "Aqua Trivy — complementary scanner: dependency CVEs, exposed secrets, IaC/Dockerfile misconfigurations"
    primary = True

    def scan(self, root: Path, workdir: Path) -> list[Finding]:
        s = get_settings()
        out = _ensure(workdir) / "trivy.json"
        cache = s.trivy_cache_dir or (s.cache_dir / "trivy")
        args = ["trivy", "fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "--output", str(out),
                "--quiet", "--cache-dir", str(cache), "--timeout", f"{max(60, s.scanner_timeout_seconds - 30)}s"]
        for d in SKIP:
            args += ["--skip-dirs", f"**/{d}"]
        res = run_cmd(args + [str(root)], timeout=s.scanner_timeout_seconds)
        if not out.exists():
            raise RuntimeError(f"trivy exited {res.returncode}: {(res.stderr or res.stdout)[-600:]}")
        return parse_trivy_data(json.loads(out.read_text(encoding="utf-8")))


class SemgrepScanner(Scanner):
    name, kind, binary, setting = "semgrep", "sast", "semgrep", "enable_semgrep"
    description = "Semgrep OSS rules (multi-language SAST)"

    def available(self) -> bool:
        return local_tool("semgrep") is not None

    def scan(self, root: Path, workdir: Path) -> list[Finding]:
        s = get_settings()
        out = _ensure(workdir) / "semgrep.sarif"
        packs = [c.strip() for c in s.semgrep_config.split(",") if c.strip()] or ["p/default"]
        args = [local_tool("semgrep") or "semgrep", "scan", *[a for c in packs for a in ("--config", c)], "--sarif",
                "--output", str(out), "--metrics", "off", "--quiet", "--timeout", "30", "--max-target-bytes", "1000000",
                "--disable-version-check"]
        for d in SKIP:
            args += ["--exclude", d]
        # UTF-8 mode: on Windows Semgrep otherwise writes the SARIF in the ANSI code page and fails on emoji in it
        res = run_cmd(args + [str(root)], timeout=s.scanner_timeout_seconds, env=scrubbed_env({"PYTHONUTF8": "1"}))
        if not out.exists():
            raise RuntimeError(f"semgrep exited {res.returncode}: {(res.stderr or res.stdout)[-600:]}")
        return parse_sarif_data(json.loads(out.read_text(encoding="utf-8")), "Semgrep", root)


class BanditScanner(Scanner):
    name, kind, binary, setting = "bandit", "sast", "bandit", "enable_bandit"
    description = "Bandit (Python SAST)"
    languages = {"python"}

    def available(self) -> bool:
        return local_tool("bandit") is not None

    def scan(self, root: Path, workdir: Path) -> list[Finding]:
        s = get_settings()
        out = _ensure(workdir) / "bandit.json"
        excludes = ",".join(str(root / d) for d in SKIP)
        res = run_cmd([local_tool("bandit") or "bandit", "-r", str(root), "-f", "json", "-o", str(out), "-q", "-x", excludes],
                      timeout=s.scanner_timeout_seconds)
        if not out.exists():
            raise RuntimeError(f"bandit exited {res.returncode}: {(res.stderr or res.stdout)[-600:]}")
        return parse_bandit_data(json.loads(out.read_text(encoding="utf-8")), root)


CODEQL_LANGS = {"python": ("python", "none"), "javascript": ("javascript-typescript", "none"),
                "typescript": ("javascript-typescript", "none"), "ruby": ("ruby", "none"),
                "java": ("java-kotlin", "none"), "kotlin": ("java-kotlin", "none"), "csharp": ("csharp", "none"),
                "go": ("go", "autobuild")}
CODEQL_PACKS = {"python": "python", "javascript-typescript": "javascript", "ruby": "ruby", "java-kotlin": "java",
                "csharp": "csharp", "go": "go"}


def codeql_binary() -> str | None:
    configured = get_settings().codeql_path
    if configured and Path(configured).is_file():
        return configured
    local = Path(__file__).resolve().parents[2] / "tools" / "codeql" / ("codeql.exe" if os.name == "nt" else "codeql")
    if local.is_file():
        return str(local)
    return shutil.which("codeql")


class CodeQLScanner(Scanner):
    name, kind, binary, setting = "codeql", "sast", "codeql", "enable_codeql"
    description = "GitHub CodeQL — primary SAST engine (deep semantic data-flow analysis)"
    languages = set(CODEQL_LANGS)
    primary = True

    def available(self) -> bool:
        return codeql_binary() is not None

    def scan(self, root: Path, workdir: Path) -> list[Finding]:
        from ..detect import detect_project
        s = get_settings()
        workdir = _ensure(workdir)
        langs = {CODEQL_LANGS[l] for l in detect_project(root).languages if l in CODEQL_LANGS}
        if not langs:
            raise ScannerUnavailable("no CodeQL-supported languages")
        findings: list[Finding] = []
        errors = []
        for lang, mode in sorted(langs):
            db = workdir / f"db-{lang}"
            out = workdir / f"{lang}.sarif"
            exe = codeql_binary() or "codeql"
            create = run_cmd([exe, "database", "create", str(db), f"--language={lang}", f"--source-root={root}",
                              f"--build-mode={mode}", "--overwrite", "--threads=0"], timeout=s.scanner_timeout_seconds)
            if not create.ok:
                errors.append(f"{lang}: database create failed: {create.stderr[-300:]}")
                continue
            pack = CODEQL_PACKS[lang]
            analyze = run_cmd([exe, "database", "analyze", str(db), "--format=sarif-latest", f"--output={out}",
                               "--download", "--threads=0",
                               f"codeql/{pack}-queries:codeql-suites/{pack}-{s.codeql_suite}.qls"],
                              timeout=s.scanner_timeout_seconds)
            if analyze.ok and out.exists():
                findings.extend(parse_sarif_data(json.loads(out.read_text(encoding="utf-8")), "CodeQL", root))
            else:
                errors.append(f"{lang}: analyze failed: {analyze.stderr[-300:]}")
        if errors and not findings:
            raise RuntimeError("; ".join(errors))
        self.last_message = "; ".join(errors)
        return findings
