"""Execution of repository code (install/test commands).

Running a stranger's test suite is running a stranger's code, so this is disabled by
default. ``SANDBOX_MODE=docker`` runs each command in a throw-away container with no
network (configurable), CPU/memory/PID limits and no service credentials;
``SANDBOX_MODE=local`` runs directly on the host and is only for trusted repositories.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from .config import get_settings, scrubbed_env
from .models import ValidationResult


def sandbox_available() -> tuple[bool, str]:
    s = get_settings()
    if s.sandbox_mode == "disabled":
        return False, "SANDBOX_MODE=disabled"
    if s.sandbox_mode == "docker" and not shutil.which("docker"):
        return False, "docker CLI not found"
    return True, s.sandbox_mode


def run_in_sandbox(name: str, command: str, workdir: Path, image: str, timeout: int | None = None,
                   network: str | None = None) -> ValidationResult:
    s = get_settings()
    timeout = timeout or s.test_timeout_seconds
    ok, why = sandbox_available()
    if not ok:
        return ValidationResult(name=name, command=command, exit_code=0, passed=True, skipped=True,
                                stderr=f"Skipped: {why}")
    start = time.monotonic()
    if s.sandbox_mode == "docker":
        args = ["docker", "run", "--rm", "--network", network or s.sandbox_network, "--cpus", s.sandbox_cpus,
                "--memory", s.sandbox_memory, "--pids-limit", "512", "--security-opt", "no-new-privileges",
                "--cap-drop", "ALL", "-e", "CI=true", "-e", "HOME=/tmp", "-v", f"{workdir.resolve()}:/workspace",
                "-w", "/workspace", image, "sh", "-c", command]
        shell = False
    else:
        args, shell = command, True
    try:
        proc = subprocess.run(args, cwd=str(workdir), shell=shell, text=True, capture_output=True, timeout=timeout,
                              check=False, env=scrubbed_env({"CI": "true"}), encoding="utf-8", errors="replace")
        return ValidationResult(name=name, command=command, exit_code=proc.returncode, passed=proc.returncode == 0,
                                stdout=(proc.stdout or "")[-12000:], stderr=(proc.stderr or "")[-12000:],
                                duration_seconds=round(time.monotonic() - start, 2))
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return ValidationResult(name=name, command=command, exit_code=124, passed=False, stdout=out[-12000:],
                                stderr=f"Timed out after {timeout} seconds.",
                                duration_seconds=round(time.monotonic() - start, 2))


__all__ = ["run_in_sandbox", "sandbox_available"]
