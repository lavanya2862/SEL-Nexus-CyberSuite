"""Validation of changes: static syntax checks (never execute repo code) and sandboxed commands."""
from __future__ import annotations

import ast
import json
import shutil
import subprocess
import tomllib
from pathlib import Path

from .config import scrubbed_env
from .models import ValidationResult


def static_check(root: Path, files: list[str]) -> tuple[bool, str]:
    """Parse-only checks for edited files. Returns (ok, message)."""
    problems = []
    for rel in files:
        path = root / rel
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            problems.append(f"{rel}: not valid UTF-8 after edit")
            continue
        try:
            if suffix == ".py":
                ast.parse(text, filename=rel)
            elif suffix == ".json" or path.name.endswith(".json"):
                json.loads(text)
            elif suffix == ".toml" or path.name in ("Cargo.lock", "poetry.lock"):
                tomllib.loads(text)
            elif suffix in (".yml", ".yaml"):
                try:
                    import yaml
                    list(yaml.safe_load_all(text))
                except ImportError:
                    pass
            elif suffix in (".js", ".mjs", ".cjs") and shutil.which("node"):
                proc = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True, timeout=60,
                                      env=scrubbed_env())
                if proc.returncode:
                    problems.append(f"{rel}: {proc.stderr.strip()[-400:]}")
        except SyntaxError as exc:
            problems.append(f"{rel}:{exc.lineno}: syntax error: {exc.msg}")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{rel}: {type(exc).__name__}: {exc}")
    return (not problems), "; ".join(problems)


def run_validation(worktree: Path, commands: list[tuple[str, str]]) -> list[ValidationResult]:
    """Legacy API: run trusted commands on the host (used by the local-path CLI)."""
    import time
    results = []
    for name, command in commands:
        start = time.monotonic()
        try:
            proc = subprocess.run(command, cwd=worktree, shell=True, text=True, capture_output=True, timeout=900,
                                  check=False, env=scrubbed_env())
            results.append(ValidationResult(name=name, command=command, exit_code=proc.returncode,
                                            passed=proc.returncode == 0, stdout=proc.stdout[-12000:],
                                            stderr=proc.stderr[-12000:], duration_seconds=round(time.monotonic() - start, 2)))
        except subprocess.TimeoutExpired as exc:
            results.append(ValidationResult(name=name, command=command, exit_code=124, passed=False,
                                            stdout=str(exc.stdout or "")[-12000:], stderr="Timed out after 900 seconds."))
    return results
