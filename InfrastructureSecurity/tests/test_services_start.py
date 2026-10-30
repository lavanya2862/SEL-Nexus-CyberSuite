"""The dashboard and the two agent services really start and answer, the way the Start script runs them.

Each one gets a free port, so this runs next to a module that is already running.
"""
from __future__ import annotations

import os
import socket
import subprocess
import time
import urllib.request

import pytest

from layout import PARTS, part_dir, python

# part -> the path that answers once it is up
SERVICES = {"dashboard": "/api/health", "threat_intel": "/api/status", "alert_triage": "/api/status"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.parametrize("part", sorted(SERVICES))
def test_service_starts_and_answers(part, tmp_path):
    py = python(part)
    if not py.exists():
        pytest.skip(f"{part} has no .venv yet")
    port = _free_port()
    log = tmp_path / "out.log"
    with log.open("w", encoding="utf-8") as out:
        proc = subprocess.Popen([str(py), "-m", PARTS[part]["package"], "serve", "--port", str(port)], cwd=part_dir(part),
                                stdout=out, stderr=subprocess.STDOUT, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        try:
            deadline, status = time.time() + 30, None
            while time.time() < deadline and proc.poll() is None and status is None:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}{SERVICES[part]}", timeout=2) as r:
                        status = r.status
                except OSError:
                    time.sleep(0.5)
        finally:
            proc.kill()
            proc.wait(10)
    assert status == 200, log.read_text(encoding="utf-8", errors="replace")[-3000:]
