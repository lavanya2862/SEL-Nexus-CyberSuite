"""Settings by agent name; the names from before the restructure keep working."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from layout import PARTS, ROOT, part_dir, python

sys.path.insert(0, str(ROOT / "shared" / "infra_core" / "src"))
from infra_core.settings import env  # noqa: E402


@pytest.mark.parametrize("part", sorted(p for p in PARTS if p != "dashboard"))
def test_agent_reads_the_suite_env_file(part):
    """Every agent reads the one .env at the repository root (moving a folder deeper must not lose it)."""
    py = python(part)
    if not py.exists():
        pytest.skip(f"{part} has no .venv yet")
    pkg = PARTS[part]["package"]
    done = subprocess.run([str(py), "-c", f"from {pkg}.config import SUITE_ENV; print(SUITE_ENV)"], cwd=part_dir(part),
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert Path(done.stdout.strip()) == ROOT.parent / ".env"


def test_new_name_wins(monkeypatch):
    monkeypatch.setenv("TRIAGE_CLOSE", "1")
    monkeypatch.setenv("UC4_CLOSE", "0")
    assert env("TRIAGE_CLOSE", "UC4_CLOSE") == "1"


def test_old_name_still_works_and_says_so(monkeypatch, caplog):
    monkeypatch.delenv("TRIAGE_LOOKBACK_DAYS", raising=False)
    monkeypatch.setenv("UC4_LOOKBACK_DAYS", " 14 ")
    with caplog.at_level("WARNING", logger="infra_core.settings"):
        assert env("TRIAGE_LOOKBACK_DAYS", "UC4_LOOKBACK_DAYS") == "14"
    assert "rename it to TRIAGE_LOOKBACK_DAYS" in caplog.text


def test_empty_is_not_set(monkeypatch):
    monkeypatch.setenv("VULN_FIX_STAGE", "  ")
    monkeypatch.delenv("UC3_FIX_STAGE", raising=False)
    assert env("VULN_FIX_STAGE", "UC3_FIX_STAGE") is None
